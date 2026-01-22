import json
import re
import logging

logger = logging.getLogger(__name__)

class RulesEngine:
    def __init__(self, rules_file='config/rules.json'):
        self.rules = self.load_rules(rules_file)
        self.vulnerabilities = []
        
    def load_rules(self, rules_file):
        """
        Load vulnerability rules from JSON file
        """
        try:
            with open(rules_file, 'r') as f:
                rules = json.load(f)
                logger.info(f"Loaded {len(rules.get('port_rules', []))} port rules")
                logger.info(f"Loaded {len(rules.get('version_rules', []))} version rules")
                return rules
        except FileNotFoundError:
            logger.error(f"Rules file not found: {rules_file}")
            return {'port_rules': [], 'version_rules': []}
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing rules file: {e}")
            return {'port_rules': [], 'version_rules': []}
    
    def check_port_vulnerabilities(self, host_ip, open_ports):
        """
        Check if any open ports match vulnerability rules
        """
        findings = []
        
        for port_info in open_ports:
            port_number = port_info['port']
            
            # Check against port rules
            for rule in self.rules.get('port_rules', []):
                if rule['port'] == port_number:
                    vulnerability = {
                        'host': host_ip,
                        'type': 'DANGEROUS_PORT',
                        'severity': rule['severity'],
                        'port': port_number,
                        'service': port_info['service'],
                        'message': rule['message'],
                        'details': f"Port {port_number}/{port_info['protocol']} ({port_info['service']}) is open"
                    }
                    findings.append(vulnerability)
                    logger.warning(f"[{rule['severity']}] {host_ip}:{port_number} - {rule['message']}")
        
        return findings
    
    def check_version_vulnerabilities(self, host_ip, open_ports):
        """
        Check if any service versions match vulnerability rules
        """
        findings = []
        
        for port_info in open_ports:
            service_name = port_info.get('product', '').lower()
            version = port_info.get('version', '')
            
            if not service_name or not version:
                continue
            
            # Check against version rules
            for rule in self.rules.get('version_rules', []):
                rule_service = rule['service'].lower()
                
                # Check if service name matches
                if rule_service in service_name or service_name in rule_service:
                    
                    # Check vulnerable versions list
                    if 'vulnerable_versions' in rule:
                        if version in rule['vulnerable_versions']:
                            vulnerability = {
                                'host': host_ip,
                                'type': 'VULNERABLE_VERSION',
                                'severity': rule['severity'],
                                'port': port_info['port'],
                                'service': service_name,
                                'version': version,
                                'message': rule['message'],
                                'details': f"{service_name} {version} on port {port_info['port']}"
                            }
                            findings.append(vulnerability)
                            logger.warning(f"[{rule['severity']}] {host_ip} - {service_name} {version}: {rule['message']}")
                    
                    # Check version pattern (regex)
                    elif 'version_pattern' in rule:
                        pattern = rule['version_pattern']
                        if re.match(pattern, version):
                            vulnerability = {
                                'host': host_ip,
                                'type': 'VULNERABLE_VERSION',
                                'severity': rule['severity'],
                                'port': port_info['port'],
                                'service': service_name,
                                'version': version,
                                'message': rule['message'],
                                'details': f"{service_name} {version} on port {port_info['port']}"
                            }
                            findings.append(vulnerability)
                            logger.warning(f"[{rule['severity']}] {host_ip} - {service_name} {version}: {rule['message']}")
        
        return findings
    
    def check_default_credentials_risk(self, host_ip, open_ports):
        """
        Flag services that commonly have default credentials
        """
        findings = []
        
        # Services that commonly have default credentials
        risky_services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            6379: 'Redis',
            27017: 'MongoDB',
            3389: 'RDP',
            8080: 'Web Admin'
        }
        
        for port_info in open_ports:
            port_number = port_info['port']
            
            if port_number in risky_services:
                vulnerability = {
                    'host': host_ip,
                    'type': 'DEFAULT_CREDENTIALS_RISK',
                    'severity': 'MEDIUM',
                    'port': port_number,
                    'service': port_info['service'],
                    'message': f'{risky_services[port_number]} may be using default credentials',
                    'details': f'Service on port {port_number} should be tested for default credentials'
                }
                findings.append(vulnerability)
        
        return findings
    
    def analyze_host(self, host_data):
        """
        Perform complete vulnerability analysis on a host
        """
        host_ip = host_data['ip']
        open_ports = host_data.get('open_ports', [])
        
        logger.info(f"Analyzing vulnerabilities for {host_ip}...")
        
        # Run all checks
        port_vulns = self.check_port_vulnerabilities(host_ip, open_ports)
        version_vulns = self.check_version_vulnerabilities(host_ip, open_ports)
        cred_risks = self.check_default_credentials_risk(host_ip, open_ports)
        
        # Combine all findings
        all_findings = port_vulns + version_vulns + cred_risks
        
        # Add to global vulnerabilities list
        self.vulnerabilities.extend(all_findings)
        
        return all_findings
    
    def analyze_scan_results(self, scan_results):
        """
        Analyze complete scan results for all hosts
        """
        logger.info("=" * 60)
        logger.info("Starting Vulnerability Analysis")
        logger.info("=" * 60)
        
        self.vulnerabilities = []
        
        for host in scan_results.get('hosts', []):
            findings = self.analyze_host(host)
            host['vulnerabilities'] = findings
        
        # Generate summary
        summary = self.generate_summary()
        scan_results['vulnerability_summary'] = summary
        
        logger.info("=" * 60)
        logger.info("Vulnerability Analysis Complete")
        logger.info("=" * 60)
        logger.info(f"Total vulnerabilities found: {len(self.vulnerabilities)}")
        logger.info(f"Critical: {summary['critical']}")
        logger.info(f"High: {summary['high']}")
        logger.info(f"Medium: {summary['medium']}")
        logger.info(f"Low: {summary['low']}")
        
        return scan_results
    
    def generate_summary(self):
        """
        Generate vulnerability summary statistics
        """
        summary = {
            'total': len(self.vulnerabilities),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'by_type': {}
        }
        
        for vuln in self.vulnerabilities:
            severity = vuln['severity'].upper()
            vuln_type = vuln['type']
            
            # Count by severity
            if severity == 'CRITICAL':
                summary['critical'] += 1
            elif severity == 'HIGH':
                summary['high'] += 1
            elif severity == 'MEDIUM':
                summary['medium'] += 1
            elif severity == 'LOW':
                summary['low'] += 1
            
            # Count by type
            if vuln_type not in summary['by_type']:
                summary['by_type'][vuln_type] = 0
            summary['by_type'][vuln_type] += 1
        
        return summary
    
    def get_vulnerabilities(self, severity=None, host=None):
        """
        Get vulnerabilities filtered by severity and/or host
        """
        filtered = self.vulnerabilities
        
        if severity:
            filtered = [v for v in filtered if v['severity'].upper() == severity.upper()]
        
        if host:
            filtered = [v for v in filtered if v['host'] == host]
        
        return filtered
    
    def generate_report(self):
        """
        Generate a detailed vulnerability report
        """
        report = []
        report.append("=" * 80)
        report.append("VULNERABILITY REPORT")
        report.append("=" * 80)
        report.append("")
        
        summary = self.generate_summary()
        report.append(f"Total Vulnerabilities: {summary['total']}")
        report.append(f"  Critical: {summary['critical']}")
        report.append(f"  High: {summary['high']}")
        report.append(f"  Medium: {summary['medium']}")
        report.append(f"  Low: {summary['low']}")
        report.append("")
        
        # Group by severity
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            vulns = self.get_vulnerabilities(severity=severity)
            
            if vulns:
                report.append("=" * 80)
                report.append(f"{severity} SEVERITY FINDINGS ({len(vulns)})")
                report.append("=" * 80)
                
                for vuln in vulns:
                    report.append(f"\nHost: {vuln['host']}")
                    report.append(f"Type: {vuln['type']}")
                    report.append(f"Port: {vuln['port']} ({vuln['service']})")
                    report.append(f"Message: {vuln['message']}")
                    report.append(f"Details: {vuln['details']}")
                    report.append("-" * 80)
        
        return "\n".join(report)
