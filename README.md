# 🛡️ NetScope: Network & Endpoint Risk Mapper

![NetScope Risk & Topology Console](netscope_dashboard.png)

**NetScope** is a modular security posture and telemetry platform designed to bridge the gap between network discovery and endpoint compliance. Built as a home lab project simulating enterprise security engineering workflows, NetScope ingests multi-source telemetry, executes live network scans, enriches software inventory with real CVE threat intelligence, and triggers automated webhook alerts on network drift or critical exposure.

---

## 🏗️ Architecture & Core Components

* **Backend API (`FastAPI`):** RESTful API with Pydantic validation and **SQLite** persistence via **SQLAlchemy ORM**.
* **Live Scanner & Hybrid Parsers (`scanner.py`, `parsers/`):** Runs validated on-demand Nmap discovery (`-sT -sV`) and parses Nmap XML + Wazuh JSON telemetry (packages & SCA checks).
* **Threat Intelligence & Risk Engine (`threat_intel.py`, `risk_engine.py`):** Queries **OSV.dev** for package CVEs and scores exposure (`CRITICAL` to `LOW`).
* **Webhook Alerting (`notifier.py`):** Sends alerts to **Discord** or **Slack** on network drift or high-risk hosts.
* **Web Console (`/dashboard`) & CLI (`netscope_cli.py`):** Interactive **Cytoscape.js** topology UI and terminal dashboard.

---

## 📂 Project Structure

    netscope/
    ├── backend/
    │   ├── app/
    │   │   ├── parsers/ (nmap_parser.py, wazuh_parser.py)
    │   │   ├── static/index.html
    │   │   ├── database.py, models.py, main.py
    │   │   └── notifier.py, risk_engine.py, scanner.py, threat_intel.py
    │   └── netscope_cli.py
    ├── scans/ (sample_scan.xml, sample_wazuh_agent.json)
    ├── netscope_dashboard.png
    └── README.md

---

## ⚙️ Quickstart & Usage

    cd ~/Projects/programming-labs/python/netscope/backend
    python -m venv venv && source venv/bin/activate
    pip install fastapi uvicorn sqlalchemy pydantic
    PYTHONPATH=. python -m uvicorn app.main:app --reload --port 8000

In a second terminal (`backend/` with `venv` active):

    python netscope_cli.py reset
    curl -X POST "http://127.0.0.1:8000/api/v1/ingest/nmap"
    curl -X POST "http://127.0.0.1:8000/api/v1/ingest/wazuh"
    python netscope_cli.py scan 127.0.0.1
    python netscope_cli.py risk

---

## 💡 Sales Engineering Value

* **Unified Visibility:** Connects network discovery, endpoint posture, and OSV.dev CVE intelligence.
* **Actionable Prioritization:** Ranks exposure (`CRITICAL` to `LOW`) to guide remediation.
* **Operational Integration:** Fits SOC/MSP workflows via REST APIs and Discord/Slack webhooks.
