from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from typing import Optional
from app.database import engine, Base, get_db
from app.models import Scan, Asset, Service, SoftwarePackage, EndpointSecurity
from app.parsers.nmap_parser import NmapParser
from app.parsers.wazuh_parser import WazuhParser
from app.risk_engine import RiskEngine
from app.scanner import LiveScanner
from app.notifier import WebhookNotifier
import os

Base.metadata.create_all(bind=engine)

app = FastAPI(title="NetScope API", version="0.2.0")


def _persist_nmap_hosts(db: Session, parsed_hosts: list[dict], source_file: str, scan_type: str = "nmap_discovery") -> tuple[Scan, list[Asset]]:
    scan_record = Scan(scan_type=scan_type, source_file=source_file)
    db.add(scan_record)
    db.commit()
    db.refresh(scan_record)

    created_assets = []
    for host_data in parsed_hosts:
        asset = Asset(
            scan_id=scan_record.id,
            ip_address=host_data["ip_address"],
            mac_address=host_data["mac_address"],
            vendor=host_data["vendor"],
            hostname=host_data["hostname"],
            os_estimate=host_data["os_estimate"]
        )
        db.add(asset)
        db.commit()
        db.refresh(asset)

        for serv in host_data["services"]:
            service = Service(
                asset_id=asset.id,
                port=serv["port"],
                protocol=serv["protocol"],
                state=serv["state"],
                service_name=serv["service_name"],
                product=serv["product"],
                version=serv["version"]
            )
            db.add(service)
        db.commit()
        db.refresh(asset)
        created_assets.append(asset)

    return scan_record, created_assets


def _compute_scan_drift(db: Session) -> dict:
    scans = db.query(Scan).order_by(Scan.id.desc()).limit(2).all()
    if len(scans) < 2:
        return {
            "has_baseline": False,
            "message": "Need at least 2 completed scans in the database to perform a comparison.",
            "total_scans_found": len(scans),
            "new_devices_detected": [],
            "devices_disappeared": [],
            "service_changes_on_existing_devices": []
        }

    current_scan = scans[0]
    previous_scan = scans[1]

    def get_host_map(scan_obj):
        mapping = {}
        for asset in scan_obj.assets:
            services_set = {(s.port, s.protocol, s.service_name) for s in asset.services}
            mapping[asset.ip_address] = {
                "hostname": asset.hostname,
                "mac": asset.mac_address,
                "services": services_set
            }
        return mapping

    current_hosts = get_host_map(current_scan)
    previous_hosts = get_host_map(previous_scan)

    current_ips = set(current_hosts.keys())
    previous_ips = set(previous_hosts.keys())

    new_ips = list(current_ips - previous_ips)
    disappeared_ips = list(previous_ips - current_ips)
    common_ips = current_ips.intersection(previous_ips)

    service_changes = []
    for ip in common_ips:
        curr_srvs = current_hosts[ip]["services"]
        prev_srvs = previous_hosts[ip]["services"]

        new_services = curr_srvs - prev_srvs
        removed_services = prev_srvs - curr_srvs

        if new_services or removed_services:
            service_changes.append({
                "ip_address": ip,
                "hostname": current_hosts[ip]["hostname"],
                "new_services": [{"port": p, "protocol": pr, "service": s} for p, pr, s in new_services],
                "removed_services": [{"port": p, "protocol": pr, "service": s} for p, pr, s in removed_services]
            })

    return {
        "has_baseline": True,
        "previous_scan_id": previous_scan.id,
        "current_scan_id": current_scan.id,
        "new_devices_detected": new_ips,
        "devices_disappeared": disappeared_ips,
        "service_changes_on_existing_devices": service_changes
    }


@app.get("/")
def read_root():
    return {"status": "online", "project": "NetScope Network Risk Mapper", "version": "0.2.0"}


@app.get("/dashboard")
def serve_dashboard():
    return FileResponse("app/static/index.html")


@app.post("/api/v1/ingest/nmap")
def ingest_nmap(file_path: str = "../scans/sample_scan.xml", db: Session = Depends(get_db)):
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail=f"Scan file not found at {file_path}")

    try:
        parsed_hosts = NmapParser.parse_file(file_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    scan_record, created_assets = _persist_nmap_hosts(db, parsed_hosts, file_path, scan_type="nmap_fixture")

    return {
        "message": "Nmap scan ingested successfully",
        "scan_id": scan_record.id,
        "hosts_processed": len(created_assets)
    }


@app.post("/api/v1/scan/live")
def run_live_scan(
    target: str = "127.0.0.1",
    webhook_url: Optional[str] = None,
    notify_always: bool = False,
    db: Session = Depends(get_db)
):
    try:
        output_path, parsed_hosts = LiveScanner.run_nmap(target=target)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))

    scan_record, created_assets = _persist_nmap_hosts(db, parsed_hosts, output_path, scan_type="nmap_live")
    drift = _compute_scan_drift(db)

    risky_assets = []
    for asset in created_assets:
        risk = RiskEngine.calculate_asset_risk(asset)
        if risk["severity"] in ["HIGH", "CRITICAL"]:
            risky_assets.append({
                "asset_id": asset.id,
                "ip_address": asset.ip_address,
                "hostname": asset.hostname,
                "risk_score": risk["risk_score"],
                "severity": risk["severity"],
                "risk_factors": risk["risk_factors"]
            })

    has_drift = bool(
        drift.get("new_devices_detected")
        or drift.get("devices_disappeared")
        or drift.get("service_changes_on_existing_devices")
    )

    if notify_always or has_drift or risky_assets:
        alert_status = WebhookNotifier.send_alert(
            webhook_url=webhook_url,
            target=target,
            hosts_count=len(created_assets),
            drift_summary=drift,
            risky_assets=risky_assets
        )
    else:
        alert_status = {"sent": False, "reason": "No network drift or high/critical risks detected"}

    return {
        "message": f"Live Nmap scan completed for {target}",
        "scan_id": scan_record.id,
        "output_file": output_path,
        "hosts_discovered": len(created_assets),
        "drift_detected": has_drift,
        "drift_summary": drift,
        "webhook_alert": alert_status
    }


@app.post("/api/v1/ingest/wazuh")
def ingest_wazuh(file_path: str = "../scans/sample_wazuh_agent.json", db: Session = Depends(get_db)):
    paths_to_try = [file_path, "../scans/sample_wazuh_agent.json", "scans/sample_wazuh_agent.json", "../../scans/sample_wazuh_agent.json"]
    valid_path = None
    for p in paths_to_try:
        if os.path.exists(p):
            valid_path = p
            break

    if not valid_path:
        raise HTTPException(status_code=404, detail=f"Wazuh file not found. Tried: {paths_to_try}")

    try:
        wazuh_data = WazuhParser.parse_file(valid_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    ip = wazuh_data.get("ip_address")
    hostname = wazuh_data.get("hostname")

    asset = db.query(Asset).filter(
        (Asset.ip_address == ip) | (Asset.hostname == hostname)
    ).order_by(Asset.id.desc()).first()

    if not asset:
        raise HTTPException(
            status_code=404,
            detail=f"No matching network asset found for IP {ip} or Hostname {hostname}. Run an Nmap scan first!"
        )

    db.query(SoftwarePackage).filter(SoftwarePackage.asset_id == asset.id).delete()
    db.query(EndpointSecurity).filter(EndpointSecurity.asset_id == asset.id).delete()

    for pkg in wazuh_data.get("packages", []):
        software = SoftwarePackage(
            asset_id=asset.id,
            name=pkg["name"],
            version=pkg["version"],
            architecture=pkg.get("architecture")
        )
        db.add(software)

    conf = wazuh_data.get("configuration_assessments", {})
    sec = EndpointSecurity(
        asset_id=asset.id,
        wazuh_agent_id=wazuh_data.get("agent_id"),
        status=wazuh_data.get("status"),
        total_checks=conf.get("total_checks", 0),
        passed_checks=conf.get("passed", 0),
        failed_checks=conf.get("failed", 0)
    )
    db.add(sec)
    db.commit()

    return {
        "message": "Wazuh telemetry successfully correlated with Nmap asset",
        "asset_id": asset.id,
        "matched_ip": ip,
        "matched_hostname": hostname,
        "packages_imported": len(wazuh_data.get("packages", []))
    }


@app.get("/api/v1/assets")
def get_assets(db: Session = Depends(get_db)):
    assets = db.query(Asset).all()
    result = []
    for a in assets:
        services = [{
            "port": s.port,
            "protocol": s.protocol,
            "service": s.service_name,
            "product": s.product,
            "version": s.version
        } for s in a.services]

        packages = [{
            "name": p.name,
            "version": p.version,
            "arch": p.architecture
        } for p in a.packages]

        endpoint_sec = {
            "agent_id": a.endpoint_security.wazuh_agent_id,
            "status": a.endpoint_security.status,
            "total_checks": a.endpoint_security.total_checks,
            "passed": a.endpoint_security.passed_checks,
            "failed": a.endpoint_security.failed_checks
        } if a.endpoint_security else None

        result.append({
            "id": a.id,
            "ip": a.ip_address,
            "mac": a.mac_address,
            "vendor": a.vendor,
            "hostname": a.hostname,
            "os": a.os_estimate,
            "services": services,
            "wazuh_packages_count": len(packages),
            "endpoint_security": endpoint_sec
        })
    return result


@app.get("/api/v1/assets/{asset_id}")
def get_asset_detail(asset_id: int, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    services = [{
        "port": s.port,
        "protocol": s.protocol,
        "service": s.service_name,
        "product": s.product,
        "version": s.version
    } for s in asset.services]

    packages = [{
        "name": p.name,
        "version": p.version,
        "arch": p.architecture
    } for p in asset.packages]

    endpoint_sec = {
        "agent_id": asset.endpoint_security.wazuh_agent_id,
        "status": asset.endpoint_security.status,
        "total_checks": asset.endpoint_security.total_checks,
        "passed": asset.endpoint_security.passed_checks,
        "failed": asset.endpoint_security.failed_checks
    } if asset.endpoint_security else None

    return {
        "id": asset.id,
        "scan_id": asset.scan_id,
        "ip_address": asset.ip_address,
        "mac_address": asset.mac_address,
        "vendor": asset.vendor,
        "hostname": asset.hostname,
        "os_estimate": asset.os_estimate,
        "first_seen": asset.first_seen,
        "last_seen": asset.last_seen,
        "services": services,
        "wazuh_packages": packages,
        "endpoint_security": endpoint_sec
    }


@app.get("/api/v1/scans")
def list_scans(db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(Scan.id.desc()).all()
    return [{"scan_id": s.id, "scan_type": s.scan_type, "timestamp": s.timestamp, "source_file": s.source_file} for s in scans]


@app.get("/api/v1/scans/compare-latest")
def compare_latest_scans(db: Session = Depends(get_db)):
    drift = _compute_scan_drift(db)
    if not drift.get("has_baseline"):
        return {
            "message": drift["message"],
            "total_scans_found": drift["total_scans_found"]
        }
    return {
        "comparison": {
            "previous_scan_id": drift["previous_scan_id"],
            "current_scan_id": drift["current_scan_id"],
            "new_devices_detected": drift["new_devices_detected"],
            "devices_disappeared": drift["devices_disappeared"],
            "service_changes_on_existing_devices": drift["service_changes_on_existing_devices"]
        }
    }


@app.get("/api/v1/risk/dashboard")
def get_risk_dashboard(db: Session = Depends(get_db)):
    assets = db.query(Asset).all()

    asset_risks = []
    total_network_risk = 0

    for asset in assets:
        risk_data = RiskEngine.calculate_asset_risk(asset)
        total_network_risk += risk_data["risk_score"]

        asset_risks.append({
            "asset_id": asset.id,
            "ip_address": asset.ip_address,
            "hostname": asset.hostname,
            "risk_score": risk_data["risk_score"],
            "severity": risk_data["severity"],
            "risk_factors": risk_data["risk_factors"]
        })

    asset_risks.sort(key=lambda x: x["risk_score"], reverse=True)

    return {
        "global_network_risk_score": total_network_risk,
        "assets_evaluated": len(assets),
        "prioritized_remediation_list": asset_risks
    }


@app.delete("/api/v1/reset")
def reset_database(db: Session = Depends(get_db)):
    try:
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)
        return {"message": "Database successfully reset. All scan history and assets cleared."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to reset database: {e}")
