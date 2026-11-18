import json
import os
import urllib.request
from typing import Optional


class WebhookNotifier:
    @staticmethod
    def send_alert(
        webhook_url: Optional[str],
        target: str,
        hosts_count: int,
        drift_summary: dict,
        risky_assets: list[dict],
    ) -> dict:
        url = webhook_url or os.getenv("NETSCOPE_WEBHOOK_URL")
        if not url:
            return {"sent": False, "reason": "No webhook URL configured (set NETSCOPE_WEBHOOK_URL or pass webhook_url)"}

        new_devs = drift_summary.get("new_devices_detected", [])
        disappeared = drift_summary.get("devices_disappeared", [])
        svc_changes = drift_summary.get("service_changes_on_existing_devices", [])

        lines = [
            f"**NetScope Live Scan Alert** (`{target}`)",
            f"• **Hosts Discovered:** {hosts_count}",
            f"• **New Devices (Drift):** {', '.join(new_devs) if new_devs else 'None'}",
            f"• **Offline Devices:** {', '.join(disappeared) if disappeared else 'None'}",
            f"• **Service Changes:** {len(svc_changes)}",
        ]

        if risky_assets:
            lines.append("• **High / Critical Risk Hosts:**")
            for asset in risky_assets:
                lines.append(
                    f"  - `{asset['ip_address']}` ({asset.get('hostname') or 'N/A'}) -> "
                    f"**{asset['severity']}** ({asset['risk_score']} pts)"
                )

        message = "\n".join(lines)

        if "discord.com" in url or "discordapp.com" in url:
            payload = {"username": "NetScope Security Bot", "content": message}
        else:
            payload = {"text": message.replace("**", "*")}

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "NetScope-Bot/1.0"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return {"sent": True, "status_code": resp.status}
        except Exception as exc:
            return {"sent": False, "reason": str(exc)}
