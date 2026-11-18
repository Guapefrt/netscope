from app.threat_intel import ThreatIntel


class RiskEngine:
    @staticmethod
    def calculate_asset_risk(asset) -> dict:
        score = 0
        factors = []

        for service in asset.services:
            if service.port in [22, 21, 3389]:
                score += 25
                factors.append(f"Sensitive admin port open: {service.port}/{service.protocol} ({service.service_name})")
            elif service.port in [80, 8080]:
                score += 10
                factors.append(f"Unencrypted web service: {service.port}")
            else:
                score += 5

        if asset.endpoint_security and asset.endpoint_security.failed_checks > 0:
            score += (asset.endpoint_security.failed_checks * 15)
            factors.append(f"Wazuh SCA: {asset.endpoint_security.failed_checks} configuration compliance failures")

        if len(asset.packages) > 0:
            score += min(len(asset.packages) * 2, 20)
            for pkg in asset.packages:
                cves = ThreatIntel.lookup_package_cves(pkg.name, pkg.version)
                for cve in cves:
                    score += 20
                    factors.append(f"CVE Detected ({cve['id']}) in {pkg.name} {pkg.version}: {cve['summary']}")

        if score >= 60:
            severity = "CRITICAL"
        elif score >= 35:
            severity = "HIGH"
        elif score >= 15:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return {
            "risk_score": score,
            "severity": severity,
            "risk_factors": factors
        }
