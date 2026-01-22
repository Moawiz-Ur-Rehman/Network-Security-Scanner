from jinja2 import Template
from datetime import datetime
import os

class HTMLReportGenerator:
    def __init__(self):
        self.template = self.get_template()
    
    def get_template(self):
        """
        HTML template with modern styling
        """
        template_str = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Security Scan Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header p {
            font-size: 1.2em;
            opacity: 0.9;
        }
        
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }
        
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }
        
        .stat-card h3 {
            color: #666;
            font-size: 0.9em;
            margin-bottom: 10px;
            text-transform: uppercase;
        }
        
        .stat-card .number {
            font-size: 2.5em;
            font-weight: bold;
            color: #2a5298;
        }
        
        .severity-summary {
            padding: 30px;
        }
        
        .severity-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }
        
        .severity-card {
            padding: 15px;
            border-radius: 8px;
            text-align: center;
            color: white;
        }
        
        .severity-critical {
            background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
        }
        
        .severity-high {
            background: linear-gradient(135deg, #e67e22 0%, #d35400 100%);
        }
        
        .severity-medium {
            background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%);
        }
        
        .severity-low {
            background: linear-gradient(135deg, #3498db 0%, #2980b9 100%);
        }
        
        .severity-card h4 {
            font-size: 0.9em;
            margin-bottom: 5px;
        }
        
        .severity-card .count {
            font-size: 2em;
            font-weight: bold;
        }
        
        .section {
            padding: 30px;
            border-top: 2px solid #f0f0f0;
        }
        
        .section h2 {
            color: #2a5298;
            margin-bottom: 20px;
            font-size: 1.8em;
        }
        
        .host-card {
            background: #f8f9fa;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            border-left: 4px solid #2a5298;
        }
        
        .host-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .host-header h3 {
            color: #2a5298;
            font-size: 1.3em;
        }
        
        .badge {
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
        }
        
        .badge-up {
            background: #27ae60;
            color: white;
        }
        
        .ports-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 10px;
            margin-top: 15px;
        }
        
        .port-item {
            background: white;
            padding: 10px;
            border-radius: 5px;
            border-left: 3px solid #3498db;
        }
        
        .port-item strong {
            color: #2a5298;
        }
        
        .vulnerability {
            background: white;
            padding: 15px;
            border-radius: 8px;
            margin-top: 10px;
            border-left: 4px solid;
        }
        
        .vuln-critical {
            border-color: #e74c3c;
            background: #fee;
        }
        
        .vuln-high {
            border-color: #e67e22;
            background: #fef5e7;
        }
        
        .vuln-medium {
            border-color: #f39c12;
            background: #fef9e7;
        }
        
        .vuln-low {
            border-color: #3498db;
            background: #ebf5fb;
        }
        
        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        
        .vuln-title {
            font-weight: bold;
            font-size: 1.1em;
        }
        
        .severity-badge {
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
            color: white;
        }
        
        .footer {
            background: #2c3e50;
            color: white;
            padding: 20px;
            text-align: center;
        }
        
        .recommendations {
            background: #e8f8f5;
            padding: 20px;
            border-radius: 10px;
            margin-top: 20px;
            border-left: 4px solid #27ae60;
        }
        
        .recommendations h3 {
            color: #27ae60;
            margin-bottom: 15px;
        }
        
        .recommendations ul {
            list-style-position: inside;
            line-height: 1.8;
        }
        
        @media print {
            body {
                background: white;
                padding: 0;
            }
            
            .container {
                box-shadow: none;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>🔒 Network Security Scan Report</h1>
            <p>Generated on {{ scan_time }}</p>
        </div>
        
        <!-- Summary Statistics -->
        <div class="summary">
            <div class="stat-card">
                <h3>Total Hosts</h3>
                <div class="number">{{ total_hosts }}</div>
            </div>
            <div class="stat-card">
                <h3>Open Ports</h3>
                <div class="number">{{ total_ports }}</div>
            </div>
            <div class="stat-card">
                <h3>Vulnerabilities</h3>
                <div class="number">{{ total_vulns }}</div>
            </div>
            <div class="stat-card">
                <h3>Critical Issues</h3>
                <div class="number" style="color: #e74c3c;">{{ critical_count }}</div>
            </div>
        </div>
        
        <!-- Severity Summary -->
        <div class="severity-summary">
            <h2>Vulnerability Breakdown</h2>
            <div class="severity-grid">
                <div class="severity-card severity-critical">
                    <h4>CRITICAL</h4>
                    <div class="count">{{ critical_count }}</div>
                </div>
                <div class="severity-card severity-high">
                    <h4>HIGH</h4>
                    <div class="count">{{ high_count }}</div>
                </div>
                <div class="severity-card severity-medium">
                    <h4>MEDIUM</h4>
                    <div class="count">{{ medium_count }}</div>
                </div>
                <div class="severity-card severity-low">
                    <h4>LOW</h4>
                    <div class="count">{{ low_count }}</div>
                </div>
            </div>
        </div>
        
        <!-- Detailed Findings -->
        <div class="section">
            <h2>Detailed Findings</h2>
            
            {% for host in hosts %}
            <div class="host-card">
                <div class="host-header">
                    <h3>{{ host.ip }} {% if host.hostname %}({{ host.hostname }}){% endif %}</h3>
                    <span class="badge badge-up">{{ host.state|upper }}</span>
                </div>
                
                <p><strong>Operating System:</strong> {{ host.os.name }} ({{ host.os.accuracy }}% confidence)</p>
                
                {% if host.open_ports %}
                <h4 style="margin-top: 15px; color: #2a5298;">Open Ports ({{ host.open_ports|length }})</h4>
                <div class="ports-grid">
                    {% for port in host.open_ports %}
                    <div class="port-item">
                        <strong>{{ port.port }}/{{ port.protocol }}</strong><br>
                        {{ port.service }}
                        {% if port.product %}
                        <br><small>{{ port.product }} {% if port.version %}{{ port.version }}{% endif %}</small>
                        {% endif %}
                    </div>
                    {% endfor %}
                </div>
                {% endif %}
                
                {% if host.vulnerabilities %}
                <h4 style="margin-top: 20px; color: #e74c3c;">⚠️ Vulnerabilities ({{ host.vulnerabilities|length }})</h4>
                {% for vuln in host.vulnerabilities %}
                <div class="vulnerability vuln-{{ vuln.severity|lower }}">
                    <div class="vuln-header">
                        <div class="vuln-title">{{ vuln.type|replace('_', ' ') }}</div>
                        <span class="severity-badge" style="background: {% if vuln.severity == 'CRITICAL' %}#e74c3c{% elif vuln.severity == 'HIGH' %}#e67e22{% elif vuln.severity == 'MEDIUM' %}#f39c12{% else %}#3498db{% endif %}">
                            {{ vuln.severity }}
                        </span>
                    </div>
                    <p><strong>Port:</strong> {{ vuln.port }} ({{ vuln.service }})</p>
                    <p><strong>Message:</strong> {{ vuln.message }}</p>
                    <p><strong>Details:</strong> {{ vuln.details }}</p>
                    {% if vuln.credentials %}
                    <p style="color: #e74c3c; font-weight: bold; margin-top: 10px;">
                        🔓 Default Credentials Found:
                        {% for cred in vuln.credentials %}
                        <br>• {{ cred.username }} : {{ cred.password }}
                        {% endfor %}
                    </p>
                    {% endif %}
                </div>
                {% endfor %}
                {% endif %}
            </div>
            {% endfor %}
        </div>
        
        <!-- Recommendations -->
        {% if total_vulns > 0 %}
        <div class="section">
            <div class="recommendations">
                <h3>💡 Recommendations</h3>
                <ul>
                    <li>Immediately address all CRITICAL severity vulnerabilities</li>
                    <li>Update all outdated software to the latest versions</li>
                    <li>Change all default credentials immediately</li>
                    <li>Disable unnecessary services and close unused ports</li>
                    <li>Implement network segmentation and firewall rules</li>
                    <li>Enable multi-factor authentication where possible</li>
                    <li>Schedule regular security scans</li>
                </ul>
            </div>
        </div>
        {% endif %}
        
        <!-- Footer -->
        <div class="footer">
            <p>Network Security Scanner v1.0 | Report generated automatically</p>
            <p style="font-size: 0.9em; margin-top: 10px;">For internal use only - Contains sensitive security information</p>
        </div>
    </div>
</body>
</html>
        """
        return Template(template_str)
    
    def generate_report(self, scan_results, output_file):
        """
        Generate HTML report from scan results
        """
        # Calculate statistics
        hosts = scan_results.get('hosts', [])
        vuln_summary = scan_results.get('vulnerability_summary', {})
        
        total_hosts = len(hosts)
        total_ports = sum(len(h.get('open_ports', [])) for h in hosts)
        total_vulns = vuln_summary.get('total', 0)
        
        # Render template
        html_content = self.template.render(
            scan_time=scan_results.get('scan_time', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            total_hosts=total_hosts,
            total_ports=total_ports,
            total_vulns=total_vulns,
            critical_count=vuln_summary.get('critical', 0),
            high_count=vuln_summary.get('high', 0),
            medium_count=vuln_summary.get('medium', 0),
            low_count=vuln_summary.get('low', 0),
            hosts=hosts
        )
        
        # Write to file
        with open(output_file, 'w') as f:
            f.write(html_content)
        
        return output_file
