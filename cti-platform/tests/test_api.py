"""اختبارات نقاط REST API والاستضافة الساكنة."""

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="module")
def client() -> TestClient:
    return TestClient(app)


def test_health(client):
    d = client.get("/health").json()
    assert d["status"] == "ok"
    assert d["model"] == "trained"


def test_eval_pipeline_present(client):
    d = client.get("/api/eval").json()
    assert d["token_level"]["macro_avg"]["f1"] >= 0.0
    assert d["pipeline"]["ALL"]["f1"] > 0.9
    assert d["train_records"] > 0 and d["n_test_records"] > 0
    assert "per_type" in d["pipeline"]


def test_entity_catalog(client):
    d = client.get("/api/entities").json()
    assert "MALWARE" in d["types"]
    assert all(d["colors"].get(k) for k in d["types"])


def test_sample_and_extract(client):
    sample = client.get("/api/sample").json()["text"]
    r = client.post("/api/extract", json={"text": sample, "enrich": True})
    assert r.status_code == 200
    d = r.json()
    assert d["entities"]
    assert d["summary"]["risk_level"] in {"low", "medium", "high", "critical"}
    assert d["stix"]["type"] == "bundle"
    assert d["graph"]["nodes"]
    assert d["summary"]["mitre_techniques"]


def test_extract_simple_cve(client):
    r = client.post("/api/extract", json={"text": "استُغلّت CVE-2021-44228", "enrich": False})
    types = {e["type"] for e in r.json()["entities"]}
    assert "CVE" in types


def test_mitre_search(client):
    d = client.get("/api/mitre/techniques", params={"q": "injection", "limit": 10}).json()
    assert d["count"] >= 1
    assert any("injection" in r["name"].lower() or "Injection" in r["name"] for r in d["results"])


def test_mitre_detail(client):
    d = client.get("/api/mitre/technique/T1055").json()
    assert d["id"] == "T1055"
    assert d["name"]
    assert d.get("tactics")


def test_reputation_offline(client):
    r = client.post("/api/enrichment/reputation",
                    json={"type": "IP", "value": "185.130.5.85"})
    assert r.status_code == 200
    providers = {p["provider"] for p in r.json()["providers"]}
    assert "Offline Intelligence DB" in providers


def test_analyze_txt_file(client):
    r = client.post("/api/analyze/file",
                    files={"file": ("report.txt", b"malware Emotet from 185.130.5.85 CVE-2021-44228", "text/plain")},
                    data={"enrich": "false"})
    assert r.status_code == 200
    d = r.json()
    types = {e["type"] for e in d["entities"]}
    assert "MALWARE" in types and "CVE" in types


def test_analyze_empty_file_rejected(client):
    r = client.post("/api/analyze/file",
                    files={"file": ("empty.txt", b"", "text/plain")})
    assert r.status_code in (400, 422)


def test_static_web_served(client):
    assert client.get("/").status_code == 200
    assert "text/html" in client.get("/").headers["content-type"]
    assert client.get("/assets/app.js").status_code == 200
    assert client.get("/assets/styles.css").status_code == 200


def test_enrichment_providers_status(client):
    d = client.get("/api/enrichment/providers").json()
    assert "providers" in d and "mode" in d