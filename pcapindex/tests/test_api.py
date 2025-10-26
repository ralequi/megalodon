import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from rest_framework.test import APIRequestFactory, force_authenticate

from pcapindex.api import IndexLaunchView, PacketSearchView
from pcapindex.services.files import ResolvedPath


class UserStub:
    """Minimal user stub exposing the authentication hooks used by the API views."""

    def __init__(self, *perms):
        self._perms = set(perms)
        self.is_authenticated = True

    def has_perm(self, perm: str) -> bool:
        return perm in self._perms

    def get_username(self) -> str:
        return "stub-user"


@pytest.mark.asyncio
async def test_index_launch_requires_permission():
    factory = APIRequestFactory()
    raw_request = factory.post("/api/index/", {"path": "/tmp/foo.pcap"}, format="json")
    force_authenticate(raw_request, user=UserStub())

    view = IndexLaunchView()
    request = view.initialize_request(raw_request)

    response = await view.post(request)

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_index_launch_returns_task_payload(monkeypatch):
    captured: dict[str, object] = {}

    def fake_resolve(path):
        captured["path"] = path
        return ResolvedPath(original=path, absolute=Path("/captures/test.pcap"))

    async def fake_index(*args, **kwargs):  # pragma: no cover - coroutine returned, not awaited
        return None

    def fake_register(resolved_path, username, coroutine):
        captured["registered"] = {
            "path": resolved_path,
            "username": username,
            "is_coroutine": asyncio.iscoroutine(coroutine),
        }
        asyncio.get_running_loop().create_task(coroutine)

        class DummyState:
            id = "task-123"
            status = "pending"

        return DummyState()

    monkeypatch.setattr("pcapindex.api.resolve_pcap_path", fake_resolve)
    monkeypatch.setattr("pcapindex.api.index_pcap_file", fake_index)
    monkeypatch.setattr("pcapindex.api._register_task", fake_register)

    factory = APIRequestFactory()
    raw_request = factory.post(
        "/api/index/",
        {"path": "/captures/test.pcap", "reindex": True},
        format="json",
    )
    force_authenticate(raw_request, user=UserStub("pcapindex.add_packetindex"))

    view = IndexLaunchView()
    request = view.initialize_request(raw_request)

    response = await view.post(request)

    assert response.status_code == 202
    payload = response.data
    assert payload["task_id"] == "task-123"
    assert captured["path"] == "/captures/test.pcap"
    assert captured["registered"]["username"] == "stub-user"
    assert captured["registered"]["is_coroutine"] is True


@pytest.mark.asyncio
async def test_packet_search_requires_permission(monkeypatch):
    dummy_pcap = SimpleNamespace(path="/tmp/dummy.pcap")

    class DummySerializer:
        def __init__(self, data=None):
            self.data = data
            self.validated_data = {"pcap": dummy_pcap, "limit": 5, "query": ""}

        def is_valid(self, raise_exception=False):
            return True

    monkeypatch.setattr("pcapindex.api.PacketSearchSerializer", DummySerializer)

    factory = APIRequestFactory()
    raw_request = factory.get("/api/packets/search/", {"pcap": 1, "limit": 5})
    force_authenticate(raw_request, user=UserStub())

    view = PacketSearchView()
    request = view.initialize_request(raw_request)

    response = await view.get(request)

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_packet_search_returns_index_data(monkeypatch):
    dummy_pcap = SimpleNamespace(
        id=1,
        path="/tmp/searchable.pcap",
        file_timestamp=datetime.now(timezone.utc),
        size_bytes=123,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )

    class DummySerializer:
        def __init__(self, data=None):
            self.data = data
            self.validated_data = {"pcap": dummy_pcap, "limit": 5, "query": ""}

        def is_valid(self, raise_exception=False):
            return True

    class DummyPcapSerializer:
        def __init__(self, instance):
            self.data = {"id": instance.id, "path": instance.path}

    packet_indices = [SimpleNamespace(packet_id=7, packet_timestamp=datetime.now(timezone.utc), offset=128, metadata={"layers": {}})]

    class DummyPacketIndexSerializer:
        def __init__(self, instances, many=False):
            if many:
                self.data = [
                    {"packet_id": obj.packet_id, "offset": obj.offset, "metadata": obj.metadata}
                    for obj in instances
                ]
            else:
                self.data = {"packet_id": instances.packet_id}

    class DummyQueryset(list):
        def order_by(self, field):
            return self

    class DummyManager:
        def filter(self, **kwargs):
            return DummyQueryset(packet_indices)

    class DummyPacketIndex:
        objects = DummyManager()

    class DummyProcess:
        returncode = 0

        def __init__(self, stdout):
            self._stdout = stdout

        async def communicate(self):
            return self._stdout, b""

    async def fake_exec(*args, **kwargs):
        stdout = json.dumps({"_source": {"layers": {"frame": {"frame.number": "7"}}}}).encode("utf-8") + b"\n"
        return DummyProcess(stdout)

    def immediate_sync(func, **kwargs):
        async def runner(*args, **kw):
            return func(*args, **kw)

        return runner

    monkeypatch.setattr("pcapindex.api.PacketSearchSerializer", DummySerializer)
    monkeypatch.setattr("pcapindex.api.PcapFileSerializer", DummyPcapSerializer)
    monkeypatch.setattr("pcapindex.api.PacketIndexSerializer", DummyPacketIndexSerializer)
    monkeypatch.setattr("pcapindex.api.PacketIndex", DummyPacketIndex)
    monkeypatch.setattr("pcapindex.api.asyncio.create_subprocess_exec", fake_exec)
    monkeypatch.setattr("pcapindex.api.resolve_pcap_path", lambda path: ResolvedPath(original=path, absolute=Path(path)))
    monkeypatch.setattr("pcapindex.api.sync_to_async", immediate_sync)

    factory = APIRequestFactory()
    raw_request = factory.get(
        "/api/packets/search/",
        {"pcap": dummy_pcap.id, "limit": 5},
    )
    force_authenticate(raw_request, user=UserStub("pcapindex.view_packetindex", "pcapindex.view_pcapfile"))

    view = PacketSearchView()
    request = view.initialize_request(raw_request)

    response = await view.get(request)

    assert response.status_code == 200
    body = response.data
    assert body["pcap"]["id"] == dummy_pcap.id
    assert body["indices"][0]["packet_id"] == 7
    assert body["packets"][0]["_source"]["layers"]["frame"]["frame.number"] == "7"
