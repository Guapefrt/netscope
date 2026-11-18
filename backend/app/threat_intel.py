import json
import urllib.request
from functools import lru_cache


class ThreatIntel:
    OSV_API_URL = "https://api.osv.dev/v1/query"

    @staticmethod
    @lru_cache(maxsize=256)
    def lookup_package_cves(package_name: str, version: str) -> tuple[dict, ...]:
        if not package_name or not version:
            return ()

        clean_name = package_name.strip().lower()
        clean_version = version.strip()

        queries = [
            {"version": clean_version, "package": {"purl": f"pkg:generic/{clean_name}"}},
            {"version": clean_version, "package": {"name": clean_name, "ecosystem": "Linux"}},
        ]

        found_cves = {}
        for query_payload in queries:
            try:
                req = urllib.request.Request(
                    ThreatIntel.OSV_API_URL,
                    data=json.dumps(query_payload).encode("utf-8"),
                    headers={"Content-Type": "application/json", "User-Agent": "NetScope-ThreatIntel/1.0"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=6) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
            except Exception:
                continue

            for vuln in data.get("vulns", []):
                aliases = vuln.get("aliases", [])
                cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln.get("id", "UNKNOWN-ID"))
                if cve_id in found_cves:
                    continue
                summary = (vuln.get("summary") or vuln.get("details") or "Known vulnerability").strip()
                if len(summary) > 95:
                    summary = summary[:92] + "..."
                found_cves[cve_id] = {"id": cve_id, "summary": summary}
                if len(found_cves) >= 3:
                    break

            if found_cves:
                break

        return tuple(found_cves.values())
