# 🛡️ Network Security Scanner

A comprehensive network security scanning tool built with Python that discovers hosts, detects open ports, identifies vulnerabilities, and tests for default credentials.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey)

## ✨ Features

- 🔍 **Network Discovery** - Automatically detects and scans local subnet
- 🔌 **Port Scanning** - Customizable port ranges (Quick, Common, Extended, Full)
- 🔎 **Service Detection** - Identifies services and versions running on open ports
- 💻 **OS Fingerprinting** - Attempts to detect operating system
- ⚠️ **Vulnerability Detection** - Rules-based engine to identify security issues
- 🔐 **Default Credentials Testing** - Tests common username/password combinations
- 📊 **Beautiful Reports** - Generates HTML, PDF, and JSON reports
- 🎨 **Modern GUI** - Dark-themed professional interface
- 📈 **Real-time Progress** - Live statistics and color-coded output

## 🎯 Vulnerability Detection

The scanner checks for:

- **Dangerous Open Ports** (Telnet, FTP, Redis, MongoDB, etc.)
- **Outdated Software Versions** (Apache, Nginx, PHP, MySQL, etc.)
- **Default Credentials** (SSH, FTP, MySQL, Telnet)
- **Misconfigured Services**
- **Known CVEs**

## 📋 Requirements

- Linux (Kali Linux recommended)
- Python 3.8+
- Root/sudo privileges
- Nmap

## 🚀 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/network-security-scanner.git
cd network-security-scanner
```

### 2. Install System Dependencies
```bash
sudo apt update
sudo apt install python3-venv nmap python3-tk libpango-1.0-0 -y
```

### 3. Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### 4. Install Python Dependencies
```bash
pip install -r requirements.txt
```

## 💻 Usage

### Command Line Interface
```bash
sudo venv/bin/python main.py
```

**Options:**
1. Auto-detect and scan local subnet
2. Scan specific target
3. Quick scan (ports 1-100)
4. Full scan (ports 1-1000)
5. Comprehensive scan (ports 1-5000)

### Modern GUI (Recommended)
```bash
sudo venv/bin/python gui_modern.py
```

**Features:**
- Visual configuration panel
- Real-time scan output
- Live statistics dashboard
- One-click report export

### Old GUI
```bash
sudo venv/bin/python gui_scanner.py
```

## 📊 Report Formats

After each scan, reports are generated in the `output/` directory:

- **JSON** - Raw scan data for further processing
- **HTML** - Interactive web-based report with modern styling
- **PDF** - Professional printable report
- **TXT** - Plain text vulnerability and credentials reports

## 🛠️ Configuration

### Port Rules (`config/rules.json`)

Add custom port-based vulnerability rules:
```json
{
  "port": 22,
  "service": "SSH",
  "severity": "MEDIUM",
  "message": "SSH service exposed"
}
```

### Version Rules

Add version-specific vulnerability checks:
```json
{
  "service": "apache",
  "vulnerable_versions": ["2.4.49"],
  "severity": "CRITICAL",
  "message": "Apache vulnerable to CVE-2021-41773"
}
```

### Default Credentials (`config/default_creds.json`)

Customize credential testing (use responsibly):
```json
{
  "service": "ssh",
  "port": 22,
  "combos": [
    {"username": "admin", "password": "admin"}
  ]
}
```

## 🔒 Legal & Ethical Use

⚠️ **IMPORTANT**: This tool is for authorized security testing only.

- ✅ Only scan networks you own or have explicit written permission to test
- ✅ Use for security audits, penetration testing, and compliance checks
- ❌ Never scan networks without authorization
- ❌ Unauthorized access attempts are illegal (Computer Fraud and Abuse Act, etc.)

**The developers assume no liability for misuse of this tool.**

## 📸 Screenshots

### Modern GUI
<img width="1707" height="857" alt="image" src="https://github.com/user-attachments/assets/3190d317-e660-4e52-9253-2356ed502ca8" />


### HTML Report
<img width="1260" height="714" alt="image" src="https://github.com/user-attachments/assets/f8bb0c58-3745-44d9-8da5-72770376b368" />


## 🏗️ Project Structure
```
network-scanner/
├── scanner/
│   ├── network_scan.py      # Core scanning engine
│   ├── rules_engine.py      # Vulnerability detection
│   └── credentials.py       # Default credentials checker
├── reports/
│   ├── html_report.py       # HTML report generator
│   └── pdf_report.py        # PDF report generator
├── config/
│   ├── rules.json           # Vulnerability rules
│   └── default_creds.json   # Default credentials database
├── main.py                  # CLI interface
├── gui_modern.py           # Modern GUI interface
└── gui_scanner.py          # Original GUI interface
```

## 🧪 Testing

Test on your local network:
```bash
# Quick test (ports 1-100)
sudo venv/bin/python main.py
# Select option 3

# Full GUI test
sudo venv/bin/python gui_modern.py
```

## 🐛 Troubleshooting

### Permission Errors
```bash
# Always run with sudo
sudo venv/bin/python main.py
```

### Module Not Found
```bash
# Activate virtual environment
source venv/bin/activate
pip install -r requirements.txt
```

### GUI Won't Start
```bash
sudo apt install python3-tk -y
```

### PDF Generation Fails
```bash
sudo apt install libpango-1.0-0 libpangocairo-1.0-0 -y
pip install weasyprint
```

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 TODO / Future Enhancements

- [ ] Add more service credential testers (RDP, PostgreSQL, MongoDB)
- [ ] Implement CVE database integration
- [ ] Add email notifications for critical findings
- [ ] Create web-based dashboard
- [ ] Add scheduled scanning capabilities
- [ ] Implement network segmentation analysis
- [ ] Add custom exploit modules

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

Moawiz-Ur-Rehman - [GitHub Profile](https://github.com/Moawiz-Ur-Rehman)

## 🙏 Acknowledgments

- Built with Python and Nmap
- GUI uses Tkinter
- Reports generated with Jinja2 and WeasyPrint
- Inspired by professional penetration testing tools

## ⚠️ Disclaimer

This tool is provided for educational and authorized security testing purposes only. Users are responsible for complying with all applicable laws and regulations. Unauthorized network scanning and access attempts are illegal and unethical.

---

**Star ⭐ this repository if you found it helpful!**
