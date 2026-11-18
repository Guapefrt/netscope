import urllib.request
import json
import sys

BASE_URL = "http://127.0.0.1:8000"

def fetch(endpoint):
    try:
        req = urllib.request.Request(f"{BASE_URL}{endpoint}")
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode())
    except Exception as e:
        print(f"[!] Error connecting to NetScope API at {BASE_URL}: {e}")
        sys.exit(1)

def print_banner():
    print("=" * 65)
    print("   NETSCOPE CLI - Network & Endpoint Security Dashboard")
    print("=" * 65)

def cmd_status():
    data = fetch("/")
    print(f"\n[*] API Status: {data.get('status')} | Project: {data.get('project')}")

def cmd_assets():
    assets = fetch("/api/v1/assets")
    print(f"\n[+] Discovered Assets Inventory ({len(assets)} hosts found):")
    print("-" * 65)
    for a in assets:
        print(f"  • ID: {a['id']} | IP: {a['ip']} | Hostname: {a['hostname'] or 'N/A'}")
        print(f"    MAC: {a['mac'] or 'N/A'} ({a['vendor'] or 'Unknown Vendor'})")
        print(f"    OS Estimate: {a['os']}")
        print(f"    Open Services:")
        for s in a['services']:
            print(f"      - Port {s['port']}/{s['protocol']}: {s['service']} ({s['product']} {s['version']})")
        
        if a.get('endpoint_security'):
            sec = a['endpoint_security']
            print(f"    Wazuh Endpoint Telemetry:")
            print(f"      - Agent ID: {sec['agent_id']} | Status: {sec['status']}")
            print(f"      - SCA Checks: {sec['passed']}/{sec['total_checks']} passed ({sec['failed']} failed)")
        else:
            print(f"    Wazuh Endpoint Telemetry: Not Correlated")
        print("-" * 65)

def cmd_scans():
    scans = fetch("/api/v1/scans")
    print(f"\n[+] Scan History ({len(scans)} total scans):")
    print("-" * 65)
    for s in scans:
        print(f"  • Scan ID: {s['scan_id']} | Type: {s['scan_type']} | Time: {s['timestamp']}")
        print(f"    Source: {s['source_file']}")
    print("-" * 65)

def cmd_diff():
    result = fetch("/api/v1/scans/compare-latest")
    if "message" in result:
        print(f"\n[!] {result['message']} (Found: {result.get('total_scans_found', 0)})")
        return
    
    comp = result.get("comparison", {})
    print(f"\n[+] Scan Drift Comparison (Previous ID: {comp.get('previous_scan_id')} -> Current ID: {comp.get('current_scan_id')})")
    print("-" * 65)
    
    new_devs = comp.get("new_devices_detected", [])
    dis_devs = comp.get("devices_disappeared", [])
    changes = comp.get("service_changes_on_existing_devices", [])
    
    print(f"  • New Devices Detected: {new_devs if new_devs else 'None'}")
    print(f"  • Disappeared Devices: {dis_devs if dis_devs else 'None'}")
    print(f"  • Service Changes on Existing Devices: {len(changes)}")
    for ch in changes:
        print(f"    - IP: {ch['ip_address']} ({ch['hostname']})")
        print(f"      New Services: {ch['new_services']}")
        print(f"      Removed Services: {ch['removed_services']}")
    print("-" * 65)

def cmd_risk():
    data = fetch("/api/v1/risk/dashboard")
    print(f"\n[+] NetScope Executive Risk & Prioritization Dashboard")
    print(f"    Global Network Risk Score: {data.get('global_network_risk_score')} points")
    print(f"    Total Assets Evaluated: {data.get('assets_evaluated')}")
    print("-" * 65)
    
    for item in data.get('prioritized_remediation_list', []):
        print(f"  • Asset ID: {item['asset_id']} | IP: {item['ip_address']} ({item['hostname'] or 'N/A'})")
        print(f"    Risk Score: {item['risk_score']} | Severity: [{item['severity']}]")
        print(f"    Identified Risk Factors:")
        if item['risk_factors']:
            for factor in item['risk_factors']:
                print(f"      - {factor}")
        else:
            print(f"      - No immediate risk factors detected.")
        print("-" * 65)

def cmd_reset():
    try:
        req = urllib.request.Request(f"{BASE_URL}/api/v1/reset", method="DELETE")
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            print(f"\n[+] {data.get('message')}")
    except Exception as e:
        print(f"[!] Error resetting database: {e}")
        sys.exit(1)

if __name__ == "__main__":
    print_banner()
    if len(sys.argv) < 2:
        print("\nUsage: python netscope_cli.py [status | assets | scans | diff | risk | reset]")
        sys.exit(1)
    
    command = sys.argv[1].lower()
    if command == "status":
        cmd_status()
    elif command == "assets":
        cmd_assets()
    elif command == "scans":
        cmd_scans()
    elif command == "diff":
        cmd_diff()
    elif command == "risk":
        cmd_risk()
    elif command == "reset":
        cmd_reset()
    else:
        print(f"Unknown command: {command}. Use status, assets, scans, diff, risk, or reset.")
