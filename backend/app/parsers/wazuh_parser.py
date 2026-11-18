import json
from typing import Dict, Any

class WazuhParser:
    """
    Parses Wazuh agent JSON telemetry reports for NetScope correlation.
    """
    
    @staticmethod
    def parse_file(file_path: str) -> Dict[str, Any]:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return data
        except Exception as e:
            raise ValueError(f"Failed to parse Wazuh JSON file {file_path}: {e}")
