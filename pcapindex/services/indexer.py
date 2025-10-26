"""Async services that build database indices from pcap files."""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone as dt_timezone
from pathlib import Path
from typing import Iterable

from asgiref.sync import sync_to_async
from django.conf import settings

from pcapindex.models import PacketIndex, PcapFile

from .files import ResolvedPath, resolve_pcap_path

logger = logging.getLogger(__name__)


class TsharkError(RuntimeError):
    """Raised when tshark fails during indexing."""


@dataclass(slots=True)
class IndexingStats:
    """Statistics generated while indexing a pcap file."""

    packets_indexed: int
    batches_written: int
    errors: int


async def index_pcap_file(
    pcap_path: str | Path,
    *,
    reindex: bool = False,
    extra_tshark_args: Iterable[str] | None = None,
    batch_size: int | None = None,
) -> IndexingStats:
    """Index a pcap file and persist packet offsets.

    Parameters
    ----------
    pcap_path:
        Path to the pcap file, relative or absolute.
    reindex:
        When ``True`` existing indices for the file will be removed prior to
        inserting the new ones.
    extra_tshark_args:
        Additional command line arguments passed to tshark.
    batch_size:
        Number of packets to accumulate before persisting.
    """

    resolved = resolve_pcap_path(pcap_path)
    stat_result = resolved.absolute.stat()
    file_timestamp = datetime.fromtimestamp(stat_result.st_mtime, tz=dt_timezone.utc)

    pcap_file = await _persist_pcap_file(
        resolved, file_timestamp=file_timestamp, size_bytes=stat_result.st_size
    )

    if reindex:
        await _delete_packet_indices(pcap_file)

    process = await _spawn_tshark(resolved, extra_tshark_args)
    stats = IndexingStats(packets_indexed=0, batches_written=0, errors=0)

    packets: list[PacketIndex] = []
    configured_batch = batch_size or settings.PCAP_INDEX_BATCH_SIZE

    async for packet in _stream_packets(process):
        if packet is None:
            stats.errors += 1
            continue

        packets.append(
            PacketIndex(
                pcap_file=pcap_file,
                packet_id=packet.packet_id,
                packet_timestamp=packet.timestamp,
                offset=packet.offset,
                metadata=packet.metadata,
            )
        )

        if len(packets) >= configured_batch:
            await _bulk_create_packet_indices(packets)
            stats.packets_indexed += len(packets)
            stats.batches_written += 1
            packets = []

    if packets:
        await _bulk_create_packet_indices(packets)
        stats.packets_indexed += len(packets)
        stats.batches_written += 1

    await _ensure_process_success(process)
    return stats


@dataclass(slots=True)
class _Packet:
    packet_id: int
    timestamp: datetime
    offset: int
    metadata: dict


async def _spawn_tshark(
    resolved: ResolvedPath, extra_args: Iterable[str] | None
) -> asyncio.subprocess.Process:
    args = [
        settings.PCAP_TSHARK_PATH,
        "-l",  # incremental output
        "-r",
        str(resolved.absolute),
        "-T",
        "ek",
    ]

    if extra_args:
        args.extend(extra_args)

    logger.debug("Launching tshark: %s", " ".join(args))

    try:
        return await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:  # pragma: no cover - depends on runtime env
        raise TsharkError("tshark executable was not found") from exc


async def _stream_packets(process: asyncio.subprocess.Process):
    if process.stdout is None:
        raise TsharkError("tshark process has no stdout pipe configured")

    while True:
        line = await process.stdout.readline()
        if not line:
            break
        line = line.decode("utf-8", errors="ignore").strip()
        if not line:
            continue
        try:
            packet_json = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("Failed to decode tshark output: %s", line)
            yield None
            continue
        parsed = _parse_packet(packet_json)
        if parsed is None:
            yield None
        else:
            yield parsed


def _parse_packet(packet_json: dict | list | str | int | float | None) -> _Packet | None:
    if not isinstance(packet_json, dict):
        return None

    source = packet_json.get("_source")
    if not isinstance(source, dict):
        return None

    layers = source.get("layers")
    if not isinstance(layers, dict):
        return None

    frame = layers.get("frame")
    if isinstance(frame, list) and frame:
        frame_data = frame[0]
    elif isinstance(frame, dict):
        frame_data = frame
    else:
        return None

    def _first_value(key: str) -> str | None:
        value = frame_data.get(key)
        if isinstance(value, list) and value:
            return value[0]
        if isinstance(value, str):
            return value
        return None

    packet_id_raw = _first_value("frame.number")
    timestamp_raw = _first_value("frame.time_epoch")
    offset_raw = _first_value("frame.file_off")

    if packet_id_raw is None or timestamp_raw is None:
        return None

    try:
        packet_id = int(packet_id_raw)
    except (TypeError, ValueError):
        return None

    try:
        ts_float = float(timestamp_raw)
    except (TypeError, ValueError):
        return None

    timestamp = datetime.fromtimestamp(ts_float, tz=dt_timezone.utc)

    try:
        offset = int(offset_raw) if offset_raw is not None else 0
    except (TypeError, ValueError):
        offset = 0

    metadata = {"layers": layers}

    return _Packet(packet_id=packet_id, timestamp=timestamp, offset=offset, metadata=metadata)


async def _bulk_create_packet_indices(packets: list[PacketIndex]) -> None:
    if not packets:
        return

    await sync_to_async(PacketIndex.objects.bulk_create, thread_sensitive=True)(
        packets, ignore_conflicts=True
    )


async def _delete_packet_indices(pcap_file: PcapFile) -> None:
    await sync_to_async(PacketIndex.objects.filter(pcap_file=pcap_file).delete, thread_sensitive=True)()


async def _persist_pcap_file(
    resolved: ResolvedPath, *, file_timestamp: datetime, size_bytes: int
) -> PcapFile:
    defaults = {"file_timestamp": file_timestamp, "size_bytes": size_bytes}

    def _update() -> PcapFile:
        obj, _ = PcapFile.objects.update_or_create(
            path=str(resolved.absolute), defaults=defaults
        )
        return obj

    return await sync_to_async(_update, thread_sensitive=True)()


async def _ensure_process_success(process: asyncio.subprocess.Process) -> None:
    stderr = b""
    if process.stderr is not None:
        stderr = await process.stderr.read()
    return_code = await process.wait()
    if return_code != 0:
        message = stderr.decode("utf-8", errors="ignore")
        raise TsharkError(f"tshark exited with code {return_code}: {message}")


__all__ = [
    "index_pcap_file",
    "IndexingStats",
    "TsharkError",
]
