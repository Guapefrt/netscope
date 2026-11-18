import ipaddress
import os
import subprocess
from datetime import datetime
from app.parsers.nmap_parser import NmapParser


class LiveScanner:
    @staticmethod
    def validate_target(target: str) -> str:
        cleaned = target.strip()
        try:
            ipaddress.ip_network(cleaned, strict=False)
            return cleaned
        except ValueError:
            raise ValueError(f"Invalid IP address or CIDR range: {target}")

    @staticmethod
    def run_nmap(target: str, output_dir: str = "../scans") -> tuple[str, list[dict]]:
        valid_target = LiveScanner.validate_target(target)
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(output_dir, f"live_scan_{timestamp}.xml")

        cmd = [
            "nmap",
            "-sT",
            "-sV",
            "--top-ports",
            "100",
            "-T4",
            "-oX",
            output_path,
            valid_target,
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        except FileNotFoundError:
            raise RuntimeError("Nmap binary not found. Install it with: sudo pacman -S nmap")
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Nmap scan timed out after 120s for target {valid_target}")

        if result.returncode != 0:
            raise RuntimeError(f"Nmap execution failed: {result.stderr.strip()}")

        parsed_hosts = NmapParser.parse_file(output_path)
        return output_path, parsed_hosts
