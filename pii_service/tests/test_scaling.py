"""Shared-store idempotency rules required when requests reach different pods."""

import asyncio
import uuid

from fastapi.testclient import TestClient

from app.main import _storage_key, app
from app.store import Cipher, InMemoryStore


def test_store_first_writer_wins_under_concurrency():
    async def scenario():
        store = InMemoryStore(Cipher(), ttl=3600)
        results = await asyncio.gather(
            store.set_if_absent("same-key", "first", "*****"),
            store.set_if_absent("same-key", "second", "******"),
        )
        assert results.count(True) == 1
        assert await store.get("same-key") in (("first", "*****"), ("second", "******"))

    asyncio.run(scenario())


def test_payload_id_is_scoped_to_system():
    assert _storage_key("default", "id") != _storage_key("crm", "id")
    assert "id" not in _storage_key("default", "id")


def test_reused_id_with_new_payload_is_conflict():
    payload_id = str(uuid.uuid4())
    with TestClient(app) as client:
        first = client.post("/process", json={"payload": "email: demo@example.com", "payload_id": payload_id})
        same = client.post("/process", json={"payload": "email: demo@example.com", "payload_id": payload_id})
        changed = client.post("/process", json={"payload": "email: other@example.com", "payload_id": payload_id})
    assert first.status_code == same.status_code == 200
    assert first.json()["result"] == same.json()["result"]
    assert changed.status_code == 409
