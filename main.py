#!/usr/bin/env python3
"""
Network Security Scanner with Vulnerability Detection
Phase 3 - Rules Engine Integration
"""

import sys
import os
from scanner.network_scan import NetworkScanner
from scanner.rules_engine import RulesEngine
from scanner.credentials import CredentialsChecker
from reports.html_report import HTMLReportGenerator
from reports.pdf_report import PDFReportGenerator
import json

def print_banner():
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║          Network Security Scanner v1.0                       ║
    ║          Scan • Detect • Analyze                             ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def print_vulnerability_summary(summary):
    """
    Print a color-coded vulnerability summary
    """
    print("\n" + "=" * 70)
    print("VULNERABILITY SUMMARY")
    print("=" * 70)
    
    total = summary['total']
    critical = summary['critical']
    high = summary['high']
    medium = summary['medium']
    low = summary['low']
    
    print(f"\n📊 Total Vulnerabilities Found: {total}")
    print(f"   🔴 Critical: {critical}")
    print(f"   🟠 High: {high}")
    print(f"   🟡 Medium: {medium}")
    print(f"   🟢 Low: {low}")
    
    if summary['by_type']:
        print("\n📋 By Type:")
        for vuln_type, count in summary['by_type'].items():
            print(f"   • {vuln_type}: {count}")

def print_host_vulnerabilities(host):
    """
    Print vulnerabilities for a specific host
    """
    vulns = host.get('vulnerabilities', [])
    
    if not vulns:
        return
    
    print(f"\n⚠️  Vulnerabilities for {host['ip']} ({host['hostname']}):")
    print("-" * 70)
    
    # Sort by severity
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    sorted_vulns = sorted(vulns, key=lambda x: severity_order.get(x['severity'], 4))
    
    for vuln in sorted_vulns:
        severity_icon = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢'
        }.get(vuln['severity'], '⚪')
        
        print(f"\n{severity_icon} [{vuln['severity']}] {vuln['type']}")
        print(f"   Port: {vuln['port']} ({vuln['service']})")
        print(f"   Message: {vuln['message']}")
        if 'version' in vuln:
            print(f"   Version: {vuln['version']}")

def main():
    print_banner()
    
    # Check if running as root
    if os.geteuid() != 0:
        print("⚠️  Warning: This script requires root privileges for full functionality")
        print("   Please run with: sudo venv/bin/python main.py")
        response = input("\nContinue anyway? (y/n): ")
        if response.lower() != 'y':
            sys.exit(1)
    
    # Menu
    print("\n📋 Scan Options:")
    print("1. Auto-detect and scan local subnet")
    print("2. Scan specific target")
    print("3. Quick scan (ports 1-100)")
    print("4. Full scan (ports 1-1000)")
    print("5. Comprehensive scan (ports 1-5000)")
    
    choice = input("\nSelect option (1-5): ").strip()
    
    target = None
    port_range = '1-1000'
    
    if choice == '2':
        target = input("Enter target (IP or subnet, e.g., 192.168.1.0/24): ").strip()
    elif choice == '3':
        port_range = '1-100'
    elif choice == '5':
        port_range = '1-5000'
    
    skip_os = input("\nSkip OS detection? (faster) (y/n): ").strip().lower() == 'y'
    
    # Ask about credential testing
    print("\n⚠️  DEFAULT CREDENTIALS TESTING")
    print("   This will actively attempt to login to services with common credentials.")
    print("   Only proceed if you own this network or have explicit permission!")
    test_creds = input("\nTest for default credentials? (y/n): ").strip().lower() == 'y'
    
    print("\n" + "=" * 70)
    print("PHASE 1: Network Scanning")
    print("=" * 70)
    
    try:
        # Initialize scanner
        scanner = NetworkScanner()
        
        # Perform scan
        print("\n🔍 Starting network scan...")
        scan_results = scanner.full_scan(
            target=target,
            port_range=port_range,
            skip_os_detection=skip_os
        )
        
        print("\n" + "=" * 70)
        print("PHASE 2: Vulnerability Analysis")
        print("=" * 70)
        
        # Initialize rules engine
        print("\n🔎 Loading vulnerability rules...")
        rules_engine = RulesEngine()
        
        # Analyze results
        print("🔎 Analyzing scan results for vulnerabilities...")
        analyzed_results = rules_engine.analyze_scan_results(scan_results)
        
        # Phase 3: Default Credentials Testing (if enabled)
        if test_creds:
            print("\n" + "=" * 70)
            print("PHASE 3: Default Credentials Testing")
            print("=" * 70)
            
            print("\n🔐 Initializing credentials checker...")
            cred_checker = CredentialsChecker()
            
            print("🔐 Testing for default credentials...")
            print("   (This may take a few minutes depending on services found)")
            analyzed_results = cred_checker.check_all_hosts(analyzed_results)
            
            # Update vulnerability summary to include credential findings
            cred_findings = len(cred_checker.get_findings())
            if cred_findings > 0:
                analyzed_results['vulnerability_summary']['total'] += cred_findings
                analyzed_results['vulnerability_summary']['critical'] += cred_findings
        else:
            cred_checker = None
        
        # Display results
        print("\n" + "=" * 70)
        print("SCAN RESULTS")
        print("=" * 70)
        print(f"\n📅 Scan Time: {analyzed_results['scan_time']}")
        print(f"🖥️  Total Hosts Found: {len(analyzed_results['hosts'])}")
        
        total_ports = sum(len(host['open_ports']) for host in analyzed_results['hosts'])
        print(f"🔌 Total Open Ports: {total_ports}")
        
        # Display vulnerability summary
        print_vulnerability_summary(analyzed_results['vulnerability_summary'])
        
        # Display detailed findings per host
        print("\n" + "=" * 70)
        print("DETAILED FINDINGS")
        print("=" * 70)
        
        for host in analyzed_results['hosts']:
            print(f"\n{'=' * 70}")
            print(f"Host: {host['ip']} ({host['hostname']})")
            print(f"OS: {host['os']['name']} (Accuracy: {host['os']['accuracy']}%)")
            print(f"Open Ports: {len(host['open_ports'])}")
            print(f"{'=' * 70}")
            
            # Show open ports
            if host['open_ports']:
                print("\n🔌 Open Ports:")
                for port in host['open_ports']:
                    service_str = f"{port['service']}"
                    if port['product']:
                        service_str += f" - {port['product']}"
                    if port['version']:
                        service_str += f" {port['version']}"
                    print(f"   • {port['port']}/{port['protocol']}: {service_str}")
            
            # Show vulnerabilities
            print_host_vulnerabilities(host)
        
        # Generate detailed report
        print("\n" + "=" * 70)
        print("GENERATING REPORTS")
        print("=" * 70)
        
        # Save JSON results
        output_dir = 'output'
        os.makedirs(output_dir, exist_ok=True)
        
        from datetime import datetime
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        json_file = os.path.join(output_dir, f'scan_results_{timestamp}.json')
        with open(json_file, 'w') as f:
            json.dump(analyzed_results, f, indent=2)
        print(f"\n✓ JSON results saved to: {json_file}")
        
        # Save text report
        text_report = rules_engine.generate_report()
        report_file = os.path.join(output_dir, f'vulnerability_report_{timestamp}.txt')
        with open(report_file, 'w') as f:
            f.write(text_report)
        print(f"✓ Text report saved to: {report_file}")
        
        # Generate HTML report
        print("\n📄 Generating HTML report...")
        html_gen = HTMLReportGenerator()
        html_file = os.path.join(output_dir, f'scan_report_{timestamp}.html')
        html_gen.generate_report(analyzed_results, html_file)
        print(f"✓ HTML report saved to: {html_file}")
        
        # Generate PDF report
        print("📄 Generating PDF report...")
        try:
            pdf_gen = PDFReportGenerator()
            pdf_file = os.path.join(output_dir, f'scan_report_{timestamp}.pdf')
            pdf_gen.generate_report(analyzed_results, pdf_file)
            print(f"✓ PDF report saved to: {pdf_file}")
        except Exception as e:
            print(f"⚠️  PDF generation failed: {e}")
            print("   (HTML report is still available)")
        
        # Save credentials report if tested
        if test_creds and cred_checker:
            cred_report = cred_checker.generate_report()
            cred_report_file = os.path.join(output_dir, f'credentials_report_{timestamp}.txt')
            with open(cred_report_file, 'w') as f:
                f.write(cred_report)
            print(f"✓ Credentials report saved to: {cred_report_file}")
            
            # Show critical findings
            if cred_checker.get_findings():
                print("\n🔴 CRITICAL: Default credentials found!")
                for finding in cred_checker.get_findings():
                    print(f"   • {finding['host']}:{finding['port']} ({finding['service']}) - {len(finding['credentials'])} working credential(s)")
        
        print("\n" + "=" * 70)
        print("✅ SCAN COMPLETE!")
        print("=" * 70)
        
        # Show recommendations
        if analyzed_results['vulnerability_summary']['total'] > 0:
            print("\n💡 RECOMMENDATIONS:")
            
            # Priority 1: Default credentials
            if test_creds and cred_checker and cred_checker.get_findings():
                print("   🔴 URGENT - DEFAULT CREDENTIALS DETECTED:")
                print("      → Change ALL default passwords immediately!")
                print("      → These systems can be accessed by anyone!")
            
            print("   1. Review all CRITICAL and HIGH severity findings immediately")
            print("   2. Update outdated software versions")
            print("   3. Disable unnecessary services")
            print("   4. Change default credentials on all services")
            print("   5. Use firewalls to restrict access to sensitive ports")
            print("   6. Implement strong authentication (SSH keys, MFA)")
        else:
            print("\n✅ No vulnerabilities detected! Your network looks secure.")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error during scan: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
