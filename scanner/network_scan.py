import nmap
import socket
import netifaces
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.scan_results = {
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'hosts': []
        }
    
    def get_local_subnet(self):
        """
        Automatically detect the local subnet
        """
        try:
            # Get default gateway interface
            gateways = netifaces.gateways()
            default_interface = gateways['default'][netifaces.AF_INET][1]
            
            # Get IP address and netmask for the interface
            addrs = netifaces.ifaddresses(default_interface)
            ip_info = addrs[netifaces.AF_INET][0]
            
            ip = ip_info['addr']
            netmask = ip_info['netmask']
            
            # Calculate subnet (simple approach for /24 networks)
            ip_parts = ip.split('.')
            subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            
            logger.info(f"Detected local subnet: {subnet}")
            return subnet
        except Exception as e:
            logger.error(f"Error detecting subnet: {e}")
            # Fallback to common subnet
            return "192.168.1.0/24"
    
    def discover_hosts(self, target=None):
        """
        Discover live hosts on the network using ping scan
        """
        if target is None:
            target = self.get_local_subnet()
        
        logger.info(f"Starting host discovery on {target}...")
        
        try:
            # Ping scan to find live hosts (-sn = no port scan, just ping)
            self.nm.scan(hosts=target, arguments='-sn')
            
            live_hosts = []
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    hostname = self.nm[host].hostname() or 'Unknown'
                    live_hosts.append({
                        'ip': host,
                        'hostname': hostname,
                        'state': 'up'
                    })
                    logger.info(f"Found live host: {host} ({hostname})")
            
            logger.info(f"Discovery complete. Found {len(live_hosts)} live hosts.")
            return live_hosts
        
        except Exception as e:
            logger.error(f"Error during host discovery: {e}")
            return []
    
    def scan_ports(self, host, port_range='1-1000'):
        """
        Scan ports on a specific host
        """
        logger.info(f"Scanning ports on {host}...")
        
        try:
            # SYN scan with service version detection
            # -sV = version detection, -sS = SYN scan, -O = OS detection
            self.nm.scan(hosts=host, ports=port_range, arguments='-sV -sS')
            
            open_ports = []
            
            if host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    
                    for port in ports:
                        port_info = self.nm[host][proto][port]
                        
                        if port_info['state'] == 'open':
                            service_info = {
                                'port': port,
                                'protocol': proto,
                                'state': port_info['state'],
                                'service': port_info.get('name', 'unknown'),
                                'product': port_info.get('product', ''),
                                'version': port_info.get('version', ''),
                                'extrainfo': port_info.get('extrainfo', '')
                            }
                            open_ports.append(service_info)
                            logger.info(f"  Port {port}/{proto}: {service_info['service']} {service_info['product']} {service_info['version']}")
            
            return open_ports
        
        except Exception as e:
            logger.error(f"Error scanning ports on {host}: {e}")
            return []
    
    def detect_os(self, host):
        """
        Attempt OS detection on a host
        """
        logger.info(f"Attempting OS detection on {host}...")
        
        try:
            self.nm.scan(hosts=host, arguments='-O')
            
            if host in self.nm.all_hosts():
                if 'osmatch' in self.nm[host]:
                    os_matches = self.nm[host]['osmatch']
                    if os_matches:
                        best_match = os_matches[0]
                        logger.info(f"  OS: {best_match['name']} (accuracy: {best_match['accuracy']}%)")
                        return {
                            'name': best_match['name'],
                            'accuracy': best_match['accuracy']
                        }
            
            return {'name': 'Unknown', 'accuracy': 0}
        
        except Exception as e:
            logger.error(f"Error detecting OS on {host}: {e}")
            return {'name': 'Unknown', 'accuracy': 0}
    
    def full_scan(self, target=None, port_range='1-1000', skip_os_detection=False):
        """
        Perform a complete scan: discover hosts, scan ports, detect OS
        """
        logger.info("=" * 60)
        logger.info("Starting Full Network Scan")
        logger.info("=" * 60)
        
        # Discover hosts
        live_hosts = self.discover_hosts(target)
        
        # Scan each host
        for host_info in live_hosts:
            host_ip = host_info['ip']
            
            logger.info(f"\n{'=' * 60}")
            logger.info(f"Scanning {host_ip} ({host_info['hostname']})")
            logger.info(f"{'=' * 60}")
            
            # Port scan
            open_ports = self.scan_ports(host_ip, port_range)
            
            # OS detection (optional, can be slow)
            os_info = {'name': 'Unknown', 'accuracy': 0}
            if not skip_os_detection and open_ports:
                os_info = self.detect_os(host_ip)
            
            # Store results
            self.scan_results['hosts'].append({
                'ip': host_ip,
                'hostname': host_info['hostname'],
                'state': host_info['state'],
                'os': os_info,
                'open_ports': open_ports
            })
        
        logger.info("\n" + "=" * 60)
        logger.info("Scan Complete!")
        logger.info("=" * 60)
        logger.info(f"Total hosts scanned: {len(self.scan_results['hosts'])}")
        
        total_open_ports = sum(len(host['open_ports']) for host in self.scan_results['hosts'])
        logger.info(f"Total open ports found: {total_open_ports}")
        
        return self.scan_results
    
    def get_results(self):
        """
        Return the scan results
        """
        return self.scan_results
