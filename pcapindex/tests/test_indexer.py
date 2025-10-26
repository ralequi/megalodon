import asyncio
from datetime import datetime, timezone
from pathlib import Path

import pytest

from pcapindex.models import PcapFile
from pcapindex.services.indexer import _Packet, index_pcap_file

@pytest.mark.asyncio
async def test_index_pcap_file_persists_packets(monkeypatch, settings, tmp_path):
    settings.PCAP_ALLOWED_DIRECTORIES = [str(tmp_path)]
    settings.PCAP_REQUIRE_WITHIN_ALLOWED = True
    settings.PCAP_ENFORCE_READABLE = False

    pcap_path = tmp_path / "capture.pcap"
    pcap_path.write_bytes(b"pcap-data")

    events: dict[str, object] = {}

    class DummyProcess:
        pass

    async def fake_spawn(resolved, extra_args):
        events["resolved"] = resolved
        return DummyProcess()

    async def fake_stream(process):
        yield _Packet(
            packet_id=1,
            timestamp=datetime.now(timezone.utc),
            offset=0,
            metadata={"layers": {}},
        )
        yield None
        yield _Packet(
            packet_id=2,
            timestamp=datetime.now(timezone.utc),
            offset=42,
            metadata={"layers": {"frame": "data"}},
        )

    async def fake_ensure(process):
        events["ensured"] = True

    async def fake_persist(resolved, *, file_timestamp, size_bytes):
        events["persist"] = (resolved, file_timestamp, size_bytes)
        return PcapFile(
            path=str(resolved.absolute),
            file_timestamp=file_timestamp,
            size_bytes=size_bytes,
        )

    packets_written: list[list[int]] = []

    async def fake_bulk(packets):
        packets_written.append([packet.packet_id for packet in packets])

    monkeypatch.setattr("pcapindex.services.indexer._spawn_tshark", fake_spawn)
    monkeypatch.setattr("pcapindex.services.indexer._stream_packets", fake_stream)
    monkeypatch.setattr("pcapindex.services.indexer._ensure_process_success", fake_ensure)
    monkeypatch.setattr("pcapindex.services.indexer._persist_pcap_file", fake_persist)
    monkeypatch.setattr("pcapindex.services.indexer._bulk_create_packet_indices", fake_bulk)

    stats = await index_pcap_file(pcap_path)

    assert stats.packets_indexed == 2
    assert stats.batches_written == 1
    assert stats.errors == 1
    assert packets_written == [[1, 2]]
    assert events["resolved"].absolute == pcap_path.resolve()
    assert events.get("ensured") is True


@pytest.mark.asyncio
async def test_index_pcap_file_deletes_existing_packets_on_reindex(
    monkeypatch, settings, tmp_path
):
    settings.PCAP_ALLOWED_DIRECTORIES = [str(tmp_path)]
    settings.PCAP_REQUIRE_WITHIN_ALLOWED = True
    settings.PCAP_ENFORCE_READABLE = False

    pcap_path = tmp_path / "existing.pcap"
    pcap_path.write_bytes(b"data")

    async def fake_spawn(resolved, extra_args):
        return object()

    async def fake_stream(process):
        if False:
            yield None

    async def fake_ensure(process):
        return None

    async def fake_persist(resolved, *, file_timestamp, size_bytes):
        return PcapFile(
            path=str(resolved.absolute),
            file_timestamp=file_timestamp,
            size_bytes=size_bytes,
        )

    deleted = {}

    async def fake_delete(pcap_file):
        deleted["pcap"] = pcap_file

    monkeypatch.setattr("pcapindex.services.indexer._spawn_tshark", fake_spawn)
    monkeypatch.setattr("pcapindex.services.indexer._stream_packets", fake_stream)
    monkeypatch.setattr("pcapindex.services.indexer._ensure_process_success", fake_ensure)
    monkeypatch.setattr("pcapindex.services.indexer._persist_pcap_file", fake_persist)
    monkeypatch.setattr("pcapindex.services.indexer._delete_packet_indices", fake_delete)
    monkeypatch.setattr(
        "pcapindex.services.indexer._bulk_create_packet_indices",
        lambda packets: asyncio.sleep(0),
    )

    stats = await index_pcap_file(pcap_path, reindex=True)

    assert stats.packets_indexed == 0
    assert stats.batches_written == 0
    assert deleted["pcap"].path == str(pcap_path.resolve())
