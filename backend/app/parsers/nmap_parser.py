import xml.etree.ElementTree as ET
from typing import List, Dict, Any

class NmapParser:
    """
    Parses Nmap XML output files into structured, normalized dictionaries
    for NetScope ingestion.
    """
    
    @staticmethod
    def parse_file(file_path: str) -> List[Dict[str, Any]]:
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
        except Exception as e:
            raise ValueError(f"Failed to parse Nmap XML file {file_path}: {e}")

        hosts_data = []

        for host in root.findall('host'):
            status_elem = host.find('status')
            state = status_elem.get('state') if status_elem is not None else 'unknown'
            if state != 'up':
                continue

            ip_address = None
            mac_address = None
            vendor = None

            for addr in host.findall('address'):
                addr_type = addr.get('addrtype')
                if addr_type == 'ipv4':
                    ip_address = addr.get('addr')
                elif addr_type == 'mac':
                    mac_address = addr.get('addr')
                    vendor = addr.get('vendor')

            hostname = None
            hostnames_elem = host.find('hostnames')
            if hostnames_elem is not None:
                hn_elem = hostnames_elem.find('hostname')
                if hn_elem is not None:
                    hostname = hn_elem.get('name')

            os_name = "Unknown"
            os_elem = host.find('os')
            if os_elem is not None:
                match_elem = os_elem.find('osmatch')
                if match_elem is not None:
                    os_name = match_elem.get('name')

            services = []
            ports_elem = host.find('ports')
            if ports_elem is not None:
                for port in ports_elem.findall('port'):
                    port_id = int(port.get('portid'))
                    protocol = port.get('protocol')
                    
                    state_elem = port.find('state')
                    port_state = state_elem.get('state') if state_elem is not None else 'unknown'
                    
                    if port_state != 'open':
                        continue

                    service_name = "unknown"
                    product = ""
                    version = ""

                    serv_elem = port.find('service')
                    if serv_elem is not None:
                        service_name = serv_elem.get('name', 'unknown')
                        product = serv_elem.get('product', '')
                        version = serv_elem.get('version', '')

                    services.append({
                        "port": port_id,
                        "protocol": protocol,
                        "state": port_state,
                        "service_name": service_name,
                        "product": product,
                        "version": version
                    })

            hosts_data.append({
                "ip_address": ip_address,
                "mac_address": mac_address,
                "vendor": vendor,
                "hostname": hostname,
                "os_estimate": os_name,
                "services": services
            })

        return hosts_data
