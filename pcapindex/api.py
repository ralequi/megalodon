"""REST API views for PCAP indexing and packet inspection."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import asdict, dataclass
from typing import Any

from asgiref.sync import sync_to_async
from django.conf import settings
from rest_framework import permissions, status
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import PacketIndex, PcapFile
from .serializers import (
    IndexLaunchSerializer,
    PacketDetailQuerySerializer,
    PacketIndexSerializer,
    PacketSearchSerializer,
    PcapFileSerializer,
    PcapUploadSerializer,
)
from .services.files import FileAccessError, resolve_pcap_path, store_uploaded_file
from .services.indexer import IndexingStats, index_pcap_file

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class _TaskState:
    """Represents a background indexing job."""

    id: str
    path: str
    requested_by: str
    status: str
    result: dict[str, Any] | None = None
    error: str | None = None

    def as_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        return payload


_INDEX_TASKS: dict[str, _TaskState] = {}


def _register_task(path: str, username: str, coroutine) -> _TaskState:
    task_id = str(uuid.uuid4())
    state = _TaskState(id=task_id, path=path, requested_by=username, status="pending")
    _INDEX_TASKS[task_id] = state

    async def _runner():
        state.status = "running"
        try:
            stats: IndexingStats = await coroutine
        except Exception as exc:  # pragma: no cover - defensive guard
            logger.exception("Indexing task %s failed", task_id)
            state.status = "failed"
            state.error = str(exc)
        else:
            state.status = "completed"
            state.result = {
                "packets_indexed": stats.packets_indexed,
                "batches_written": stats.batches_written,
                "errors": stats.errors,
            }

    loop = asyncio.get_running_loop()
    loop.create_task(_runner())
    return state


class IndexLaunchView(APIView):
    """Start asynchronous indexing jobs for PCAP files."""

    permission_classes = [permissions.IsAuthenticated]

    async def post(self, request, *args, **kwargs):
        if not request.user.has_perm("pcapindex.add_packetindex"):
            return Response(status=status.HTTP_403_FORBIDDEN)

        serializer = IndexLaunchSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        path = serializer.validated_data["path"]
        reindex = serializer.validated_data.get("reindex", False)

        try:
            resolved = await sync_to_async(resolve_pcap_path)(path)
        except FileAccessError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        coroutine = index_pcap_file(resolved.absolute, reindex=reindex)
        state = _register_task(str(resolved.absolute), request.user.get_username(), coroutine)

        return Response({"task_id": state.id, "status": state.status}, status=status.HTTP_202_ACCEPTED)

    async def get(self, request, *args, **kwargs):
        """Return the status for in-flight or completed indexing jobs."""

        if not request.user.has_perm("pcapindex.view_packetindex"):
            return Response(status=status.HTTP_403_FORBIDDEN)

        payload = [task.as_payload() for task in _INDEX_TASKS.values()]
        return Response(payload)


class PacketDetailView(APIView):
    """Return details for an indexed packet using tshark output."""

    permission_classes = [permissions.IsAuthenticated]

    async def get(self, request, pk: int, *args, **kwargs):
        query_serializer = PacketDetailQuerySerializer(data=request.query_params)
        query_serializer.is_valid(raise_exception=True)
        display_filter = query_serializer.validated_data.get("filter") or ""

        if not request.user.has_perm("pcapindex.view_packetindex"):
            return Response(status=status.HTTP_403_FORBIDDEN)

        try:
            packet: PacketIndex = await sync_to_async(
                PacketIndex.objects.select_related("pcap_file").get
            )(pk=pk)
        except PacketIndex.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

        try:
            resolved = await sync_to_async(resolve_pcap_path)(packet.pcap_file.path)
        except FileAccessError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        combined_filter = f"frame.number == {packet.packet_id}"
        if display_filter:
            combined_filter = f"({combined_filter}) && ({display_filter})"

        args = [
            settings.PCAP_TSHARK_PATH,
            "-r",
            str(resolved.absolute),
            "-T",
            "ek",
            "-c",
            "1",
            "-Y",
            combined_filter,
        ]

        if packet.offset:
            args.extend(["-o", f"uat:readfile.seek,{packet.offset}"])

        try:
            process = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:  # pragma: no cover - environment dependent
            return Response(
                {"detail": "tshark executable was not found"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            logger.error("tshark exited with %s: %s", process.returncode, stderr.decode("utf-8"))
            return Response(
                {"detail": "Failed to retrieve packet details", "stderr": stderr.decode("utf-8")},
                status=status.HTTP_502_BAD_GATEWAY,
            )

        payload = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                payload.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        metadata_serializer = PacketIndexSerializer(packet)
        return Response({
            "packet": metadata_serializer.data,
            "tshark_output": payload,
        })


class PacketSearchView(APIView):
    """Run Wireshark style searches against stored PCAP files."""

    permission_classes = [permissions.IsAuthenticated]

    async def get(self, request, *args, **kwargs):
        serializer = PacketSearchSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)
        pcap: PcapFile = serializer.validated_data["pcap"]
        display_filter = serializer.validated_data.get("query") or ""
        limit = serializer.validated_data["limit"]

        if not request.user.has_perm("pcapindex.view_packetindex"):
            return Response(status=status.HTTP_403_FORBIDDEN)

        try:
            resolved = await sync_to_async(resolve_pcap_path)(pcap.path)
        except FileAccessError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        args = [
            settings.PCAP_TSHARK_PATH,
            "-r",
            str(resolved.absolute),
            "-T",
            "ek",
            "-c",
            str(limit),
        ]
        if display_filter:
            args.extend(["-Y", display_filter])

        try:
            process = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:  # pragma: no cover - environment dependent
            return Response(
                {"detail": "tshark executable was not found"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            logger.error("tshark search failure (%s): %s", process.returncode, stderr.decode("utf-8"))
            return Response(
                {"detail": "Search failed", "stderr": stderr.decode("utf-8")},
                status=status.HTTP_502_BAD_GATEWAY,
            )

        packets: list[dict[str, Any]] = []
        packet_numbers: list[int] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            packets.append(entry)
            frame_number = _extract_frame_number(entry)
            if frame_number is not None:
                packet_numbers.append(frame_number)

        indices: list[PacketIndex] = []
        if packet_numbers:
            indices = await sync_to_async(
                lambda: list(
                    PacketIndex.objects.filter(
                        pcap_file=pcap, packet_id__in=packet_numbers
                    ).order_by("packet_id")
                )
            )()

        serialized_indices = PacketIndexSerializer(indices, many=True)

        return Response(
            {
                "pcap": PcapFileSerializer(pcap).data,
                "packets": packets,
                "indices": serialized_indices.data,
            }
        )


def _extract_frame_number(entry: dict[str, Any]) -> int | None:
    """Helper that extracts the frame number from tshark ek output."""

    source = entry.get("_source")
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

    value = frame_data.get("frame.number")
    if isinstance(value, list) and value:
        value = value[0]

    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    if isinstance(value, (int, float)):
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    return None


class PcapUploadView(APIView):
    """Handle PCAP uploads, storing them on disk once validated."""

    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    async def post(self, request, *args, **kwargs):
        if not request.user.has_perm("pcapindex.add_pcapfile"):
            return Response(status=status.HTTP_403_FORBIDDEN)

        serializer = PcapUploadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        uploaded = serializer.validated_data["file"]
        content = await sync_to_async(uploaded.read)()

        try:
            resolved = await sync_to_async(store_uploaded_file)(uploaded.name, content)
        except FileAccessError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        return Response(
            {
                "detail": "Upload successful",
                "path": str(resolved.absolute),
            },
            status=status.HTTP_201_CREATED,
        )


class PcapListView(APIView):
    """List the PCAP files that are known to the system."""

    permission_classes = [permissions.IsAuthenticated]

    async def get(self, request, *args, **kwargs):
        if not request.user.has_perm("pcapindex.view_pcapfile"):
            return Response(status=status.HTTP_403_FORBIDDEN)

        queryset = await sync_to_async(lambda: list(PcapFile.objects.all().order_by("path")))()
        serializer = PcapFileSerializer(queryset, many=True)
        return Response(serializer.data)
