from types import SimpleNamespace
from unittest.mock import patch
import pytest
from app.scanner import LiveScanner
from app.risk_engine import RiskEngine


def test_scanner_blocks_command_injection():
    assert LiveScanner.validate_target("192.168.1.0/24") == "192.168.1.0/24"
    with pytest.raises(ValueError):
        LiveScanner.validate_target("127.0.0.1; rm -rf /")


@patch("app.risk_engine.ThreatIntel.lookup_package_cves")
def test_risk_engine_escalates_on_cve(mock_cves):
    mock_cves.return_value = ({"id": "CVE-2024-9999", "summary": "Critical RCE"},)
    asset = SimpleNamespace(
        services=[SimpleNamespace(port=22, protocol="tcp", service_name="ssh")],
        endpoint_security=SimpleNamespace(failed_checks=2),
        packages=[SimpleNamespace(name="openssl", version="1.1.1")],
    )
    result = RiskEngine.calculate_asset_risk(asset)
    assert result["severity"] == "CRITICAL"
    assert result["risk_score"] == 77
    assert any("CVE-2024-9999" in f for f in result["risk_factors"])
