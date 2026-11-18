from app.parsers.nmap_parser import NmapParser
import json

if __name__ == "__main__":
    results = NmapParser.parse_file("../scans/sample_scan.xml")
    print(json.dumps(results, indent=2))
