"""API-контракт POST /process, mask→demask и отсутствие ПД в логах/метриках."""
import logging
import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app

PII = "Клиент Иванов Иван Иванович, тел +7 912 345 67 89, email ivan@example.com, паспорт 45 06 123456"
RAW_FRAGMENTS = ("Иванов", "345 67", "ivan@example.com", "123456")


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_mask_demask_roundtrip(client):
    pid = str(uuid.uuid4())
    r = client.post("/process", json={"payload": PII, "payload_id": pid})
    assert r.status_code == 200
    masked = r.json()["result"]
    assert r.json()["direction"] == "mask"
    assert r.json()["types"]
    assert isinstance(r.json()["elapsed_ms"], int)
    assert all(f not in masked for f in RAW_FRAGMENTS)
    r2 = client.post("/process", json={"payload": masked, "payload_id": pid})
    assert r2.json()["result"] == PII
    assert r2.json()["direction"] == "demask"


def test_idempotent_remask_same_id(client):
    pid = str(uuid.uuid4())
    a = client.post("/process", json={"payload": PII, "payload_id": pid}).json()["result"]
    b = client.post("/process", json={"payload": PII, "payload_id": pid}).json()["result"]
    assert a == b


def test_public_text_untouched(client):
    text = "Поэт Александр Пушкин. Отделение банка: г. Москва, ул. Тверская, д. 5. Горячая линия 8 800 555 35 35"
    r = client.post("/process", json={"payload": text, "payload_id": str(uuid.uuid4())})
    assert r.json()["result"] == text


def test_contract_validation(client):
    assert client.post("/process", json={"payload": "x"}).status_code == 422
    r = client.post("/process", json={"payload": "x", "payload_id": "1"}, headers={"X-System-Id": "nope"})
    assert r.status_code == 403


def test_no_pii_in_logs_and_metrics(client, caplog):
    caplog.set_level(logging.DEBUG)
    client.post("/process", json={"payload": PII, "payload_id": "secret-id-1"})
    logs = caplog.text
    assert all(f not in logs for f in RAW_FRAGMENTS)
    assert "secret-id-1" not in logs
    metrics = client.get("/metrics").text
    assert all(f not in metrics for f in RAW_FRAGMENTS)


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_frontend_routes(client):
    assert client.get("/").status_code == 200
    assert "PII Security Module" in client.get("/").text
    assert client.get("/static/app.js").status_code == 200
    systems = client.get("/systems")
    assert systems.status_code == 200
    assert systems.json()["default"]["demask"] is True
