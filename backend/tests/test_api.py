from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_end_to_end_telemetry_pipeline():
    res_reset = client.delete("/api/v1/reset")
    assert res_reset.status_code == 200

    res_nmap = client.post("/api/v1/ingest/nmap")
    assert res_nmap.status_code == 200
    assert res_nmap.json()["hosts_processed"] >= 1

    res_wazuh = client.post("/api/v1/ingest/wazuh")
    assert res_wazuh.status_code == 200
    assert res_wazuh.json()["packages_imported"] >= 1

    res_risk = client.get("/api/v1/risk/dashboard")
    assert res_risk.status_code == 200
    data = res_risk.json()
    assert data["assets_evaluated"] >= 1
    assert data["prioritized_remediation_list"][0]["severity"] in ["HIGH", "CRITICAL"]
