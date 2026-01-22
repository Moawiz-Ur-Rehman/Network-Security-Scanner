import json
import logging
import time
import socket
from ftplib import FTP
import paramiko

# Try to import telnetlib (removed in Python 3.13+)
try:
    from telnetlib import Telnet
    TELNET_AVAILABLE = True
except ImportError:
    TELNET_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.warning("telnetlib not available (Python 3.13+) - Telnet testing will be skipped")

logger = logging.getLogger(__name__)

class CredentialsChecker:
    def __init__(self, creds_file='config/default_creds.json'):
        self.credentials = self.load_credentials(creds_file)
        self.findings = []
        self.timeout = 5  # Connection timeout in seconds
        self.delay = 1  # Delay between attempts to avoid overwhelming services
        
    def load_credentials(self, creds_file):
        """
        Load default credentials database from JSON file
        """
        try:
            with open(creds_file, 'r') as f:
                creds = json.load(f)
                total = sum(len(c['combos']) for c in creds.get('credentials', []))
                logger.info(f"Loaded {len(creds.get('credentials', []))} credential sets ({total} total combinations)")
                return creds.get('credentials', [])
        except FileNotFoundError:
            logger.error(f"Credentials file not found: {creds_file}")
            return []
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing credentials file: {e}")
            return []
    
    def test_ssh(self, host, port, username, password):
        """
        Test SSH authentication
        """
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            client.connect(
                host,
                port=port,
                username=username,
                password=password,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False
            )
            
            client.close()
            return True
            
        except paramiko.AuthenticationException:
            return False
        except Exception as e:
            logger.debug(f"SSH test error for {host}:{port} - {e}")
            return False
    
    def test_ftp(self, host, port, username, password):
        """
        Test FTP authentication
        """
        try:
            ftp = FTP(timeout=self.timeout)
            ftp.connect(host, port)
            ftp.login(username, password)
            ftp.quit()
            return True
            
        except Exception as e:
            logger.debug(f"FTP test error for {host}:{port} - {e}")
            return False
    
    def test_telnet(self, host, port, username, password):
        """
        Test Telnet authentication
        """
        if not TELNET_AVAILABLE:
            logger.debug("Telnet testing skipped - telnetlib not available")
            return None
            
        try:
            tn = Telnet(host, port, timeout=self.timeout)
            
            # Wait for login prompt
            tn.read_until(b"login: ", timeout=self.timeout)
            tn.write(username.encode('ascii') + b"\n")
            
            # Wait for password prompt
            tn.read_until(b"Password: ", timeout=self.timeout)
            tn.write(password.encode('ascii') + b"\n")
            
            # Check if login was successful
            response = tn.read_some()
            tn.close()
            
            # Simple check - if we don't see error messages, assume success
            error_indicators = [b"Login incorrect", b"Authentication failed", b"Access denied"]
            if not any(err in response for err in error_indicators):
                return True
            return False
            
        except Exception as e:
            logger.debug(f"Telnet test error for {host}:{port} - {e}")
            return False
    
    def test_mysql(self, host, port, username, password):
        """
        Test MySQL authentication
        Requires pymysql library
        """
        try:
            import pymysql
            
            connection = pymysql.connect(
                host=host,
                port=port,
                user=username,
                password=password,
                connect_timeout=self.timeout
            )
            connection.close()
            return True
            
        except ImportError:
            logger.warning("pymysql not installed - skipping MySQL credential tests")
            return None
        except Exception as e:
            logger.debug(f"MySQL test error for {host}:{port} - {e}")
            return False
    
    def test_credentials_for_service(self, host, port, service):
        """
        Test default credentials for a specific service
        """
        # Find credential set for this service
        cred_set = None
        for creds in self.credentials:
            if creds['service'].lower() == service.lower() and creds['port'] == port:
                cred_set = creds
                break
        
        if not cred_set:
            logger.debug(f"No credential set found for {service} on port {port}")
            return []
        
        logger.info(f"Testing {len(cred_set['combos'])} credential combinations for {service} on {host}:{port}")
        
        successful_logins = []
        
        for combo in cred_set['combos']:
            username = combo['username']
            password = combo['password']
            
            logger.debug(f"Testing {host}:{port} - {username}:{password}")
            
            # Select appropriate test function
            test_func = None
            if service.lower() == 'ssh':
                test_func = self.test_ssh
            elif service.lower() == 'ftp':
                test_func = self.test_ftp
            elif service.lower() == 'telnet':
                test_func = self.test_telnet
            elif service.lower() == 'mysql':
                test_func = self.test_mysql
            
            if test_func is None:
                logger.warning(f"No test function available for service: {service}")
                break
            
            # Test the credentials
            result = test_func(host, port, username, password)
            
            if result is True:
                logger.warning(f"✓ SUCCESS! Default credentials found: {username}:{password}")
                successful_logins.append({
                    'username': username,
                    'password': password
                })
            elif result is None:
                # Library not available
                break
            
            # Rate limiting - be nice to the target
            time.sleep(self.delay)
        
        return successful_logins
    
    def check_host(self, host_data):
        """
        Check a host for default credentials on all open ports
        """
        host_ip = host_data['ip']
        open_ports = host_data.get('open_ports', [])
        
        logger.info(f"Checking default credentials for {host_ip}...")
        
        findings = []
        
        for port_info in open_ports:
            port = port_info['port']
            service = port_info['service'].lower()
            
            # Map service names to our credential database names
            service_map = {
                'ssh': 'ssh',
                'ftp': 'ftp',
                'telnet': 'telnet',
                'mysql': 'mysql',
                'postgresql': 'postgres',
                'microsoft-ds': 'smb'
            }
            
            mapped_service = service_map.get(service)
            
            if not mapped_service:
                continue
            
            logger.info(f"Testing {mapped_service} on {host_ip}:{port}")
            
            try:
                successful = self.test_credentials_for_service(host_ip, port, mapped_service)
                
                if successful:
                    finding = {
                        'host': host_ip,
                        'port': port,
                        'service': service,
                        'type': 'DEFAULT_CREDENTIALS',
                        'severity': 'CRITICAL',
                        'credentials': successful,
                        'message': f'Default credentials found on {service.upper()}',
                        'details': f'{len(successful)} default credential combination(s) work on port {port}'
                    }
                    findings.append(finding)
                    self.findings.append(finding)
                    
            except Exception as e:
                logger.error(f"Error testing {mapped_service} on {host_ip}:{port} - {e}")
        
        return findings
    
    def check_all_hosts(self, scan_results):
        """
        Check all hosts in scan results for default credentials
        """
        logger.info("=" * 60)
        logger.info("Starting Default Credentials Check")
        logger.info("=" * 60)
        
        self.findings = []
        
        for host in scan_results.get('hosts', []):
            cred_findings = self.check_host(host)
            
            # Add to host's vulnerabilities
            if 'vulnerabilities' not in host:
                host['vulnerabilities'] = []
            host['vulnerabilities'].extend(cred_findings)
        
        logger.info("=" * 60)
        logger.info("Default Credentials Check Complete")
        logger.info("=" * 60)
        logger.info(f"Total default credentials found: {len(self.findings)}")
        
        return scan_results
    
    def get_findings(self):
        """
        Get all default credential findings
        """
        return self.findings
    
    def generate_report(self):
        """
        Generate a report of default credential findings
        """
        report = []
        report.append("=" * 80)
        report.append("DEFAULT CREDENTIALS REPORT")
        report.append("=" * 80)
        report.append("")
        
        if not self.findings:
            report.append("✓ No default credentials found")
            return "\n".join(report)
        
        report.append(f"🔴 CRITICAL: {len(self.findings)} service(s) using default credentials!")
        report.append("")
        
        for finding in self.findings:
            report.append("-" * 80)
            report.append(f"Host: {finding['host']}")
            report.append(f"Port: {finding['port']} ({finding['service'].upper()})")
            report.append(f"Message: {finding['message']}")
            report.append("")
            report.append("Working Credentials:")
            for cred in finding['credentials']:
                report.append(f"  • Username: {cred['username']}")
                report.append(f"    Password: {cred['password']}")
            report.append("")
        
        report.append("=" * 80)
        report.append("RECOMMENDATIONS:")
        report.append("=" * 80)
        report.append("1. Change ALL default passwords immediately")
        report.append("2. Implement strong password policies")
        report.append("3. Use SSH keys instead of passwords where possible")
        report.append("4. Enable multi-factor authentication")
        report.append("5. Disable unused services")
        
        return "\n".join(report)
