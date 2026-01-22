#!/usr/bin/env python3
"""
Network Security Scanner - Modern GUI
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import json
import os
from datetime import datetime
from scanner.network_scan import NetworkScanner
from scanner.rules_engine import RulesEngine
from scanner.credentials import CredentialsChecker
from reports.html_report import HTMLReportGenerator
from reports.pdf_report import PDFReportGenerator

class ModernButton(tk.Canvas):
    """Custom modern button with hover effects"""
    def __init__(self, parent, text, command, bg_color, hover_color, width=200, height=45):
        super().__init__(parent, width=width, height=height, bg='#1a1a2e', highlightthickness=0)
        
        self.bg_color = bg_color
        self.hover_color = hover_color
        self.command = command
        
        # Draw button
        self.rect = self.create_rectangle(
            0, 0, width, height,
            fill=bg_color, outline='', width=0
        )
        
        self.text = self.create_text(
            width//2, height//2,
            text=text, fill='white',
            font=('Arial', 12, 'bold')
        )
        
        # Bind events
        self.bind('<Enter>', self.on_enter)
        self.bind('<Leave>', self.on_leave)
        self.bind('<Button-1>', self.on_click)
        
    def on_enter(self, e):
        self.itemconfig(self.rect, fill=self.hover_color)
        
    def on_leave(self, e):
        self.itemconfig(self.rect, fill=self.bg_color)
        
    def on_click(self, e):
        if self.command:
            self.command()

class ScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Security Scanner Pro")
        self.root.geometry("1400x900")
        self.root.configure(bg='#0f0f1e')
        
        # Modern color scheme
        self.colors = {
            'bg_dark': '#0f0f1e',
            'bg_medium': '#1a1a2e',
            'bg_light': '#16213e',
            'accent': '#e94560',
            'accent_hover': '#ff6b85',
            'success': '#06ffa5',
            'warning': '#ffd93d',
            'text': '#ffffff',
            'text_dim': '#a8a8a8'
        }
        
        self.scanner = None
        self.scan_thread = None
        self.is_scanning = False
        self.scan_results = None
        
        self.setup_ui()
        
    def setup_ui(self):
        # Main container
        main_frame = tk.Frame(self.root, bg=self.colors['bg_dark'])
        main_frame.pack(fill='both', expand=True)
        
        # ===== LEFT SIDEBAR =====
        sidebar = tk.Frame(main_frame, bg=self.colors['bg_medium'], width=350)
        sidebar.pack(side='left', fill='y', padx=0, pady=0)
        sidebar.pack_propagate(False)
        
        # Logo/Title
        title_frame = tk.Frame(sidebar, bg=self.colors['bg_medium'], height=100)
        title_frame.pack(fill='x', pady=(20, 30))
        
        tk.Label(
            title_frame,
            text="🛡️",
            font=('Arial', 40),
            bg=self.colors['bg_medium'],
            fg=self.colors['accent']
        ).pack()
        
        tk.Label(
            title_frame,
            text="Security Scanner",
            font=('Arial', 18, 'bold'),
            bg=self.colors['bg_medium'],
            fg=self.colors['text']
        ).pack()
        
        tk.Label(
            title_frame,
            text="Network Vulnerability Analyzer",
            font=('Arial', 9),
            bg=self.colors['bg_medium'],
            fg=self.colors['text_dim']
        ).pack()
        
        # Configuration Section
        config_frame = tk.Frame(sidebar, bg=self.colors['bg_medium'])
        config_frame.pack(fill='both', expand=True, padx=20)
        
        # Target Configuration
        self.create_section_header(config_frame, "TARGET CONFIGURATION")
        
        self.auto_detect_var = tk.BooleanVar(value=True)
        self.create_checkbox(
            config_frame,
            "Auto-detect local network",
            self.auto_detect_var,
            self.toggle_target_entry
        )
        
        tk.Label(
            config_frame,
            text="Custom Target:",
            bg=self.colors['bg_medium'],
            fg=self.colors['text_dim'],
            font=('Arial', 9)
        ).pack(anchor='w', pady=(10, 5))
        
        self.target_entry = tk.Entry(
            config_frame,
            bg=self.colors['bg_light'],
            fg=self.colors['text'],
            insertbackground=self.colors['accent'],
            font=('Arial', 10),
            relief='flat',
            state='disabled'
        )
        self.target_entry.pack(fill='x', ipady=8)
        
        # Port Range
        self.create_section_header(config_frame, "PORT RANGE")
        
        self.port_var = tk.StringVar(value="1-1000")
        port_frame = tk.Frame(config_frame, bg=self.colors['bg_medium'])
        port_frame.pack(fill='x', pady=5)
        
        ports = [("Quick\n1-100", "1-100"), ("Common\n1-1000", "1-1000"), 
                 ("Extended\n1-5000", "1-5000"), ("Full\n1-65535", "1-65535")]
        
        for i, (text, value) in enumerate(ports):
            btn = tk.Radiobutton(
                port_frame,
                text=text,
                variable=self.port_var,
                value=value,
                bg=self.colors['bg_light'],
                fg=self.colors['text'],
                selectcolor=self.colors['bg_dark'],
                activebackground=self.colors['bg_light'],
                activeforeground=self.colors['accent'],
                font=('Arial', 8),
                indicatoron=0,
                width=8,
                height=3,
                relief='flat',
                borderwidth=0
            )
            btn.grid(row=0, column=i, padx=2)
        
        # Scan Options
        self.create_section_header(config_frame, "SCAN OPTIONS")
        
        self.skip_os_var = tk.BooleanVar(value=True)
        self.create_checkbox(config_frame, "Skip OS Detection (Faster)", self.skip_os_var)
        
        self.test_creds_var = tk.BooleanVar(value=False)
        self.create_checkbox(config_frame, "Test Default Credentials", self.test_creds_var)
        
        # Action Buttons
        buttons_frame = tk.Frame(sidebar, bg=self.colors['bg_medium'])
        buttons_frame.pack(side='bottom', fill='x', padx=20, pady=20)
        
        self.start_btn = ModernButton(
            buttons_frame,
            "▶ START SCAN",
            self.start_scan,
            self.colors['accent'],
            self.colors['accent_hover'],
            width=310,
            height=50
        )
        self.start_btn.pack(pady=5)
        
        self.stop_btn = ModernButton(
            buttons_frame,
            "⬛ STOP SCAN",
            self.stop_scan,
            '#555',
            '#666',
            width=310,
            height=40
        )
        self.stop_btn.pack(pady=5)
        
        self.export_btn = ModernButton(
            buttons_frame,
            "💾 EXPORT REPORTS",
            self.export_results,
            '#4a5899',
            '#5a68a9',
            width=310,
            height=40
        )
        self.export_btn.pack(pady=5)
        
        # ===== RIGHT MAIN AREA =====
        right_frame = tk.Frame(main_frame, bg=self.colors['bg_dark'])
        right_frame.pack(side='right', fill='both', expand=True)
        
        # Top Stats Bar
        stats_frame = tk.Frame(right_frame, bg=self.colors['bg_light'], height=120)
        stats_frame.pack(fill='x', padx=20, pady=20)
        stats_frame.pack_propagate(False)
        
        # Stats cards
        stats_container = tk.Frame(stats_frame, bg=self.colors['bg_light'])
        stats_container.pack(expand=True)
        
        self.stat_hosts = self.create_stat_card(stats_container, "HOSTS FOUND", "0", 0)
        self.stat_ports = self.create_stat_card(stats_container, "OPEN PORTS", "0", 1)
        self.stat_vulns = self.create_stat_card(stats_container, "VULNERABILITIES", "0", 2)
        self.stat_critical = self.create_stat_card(stats_container, "CRITICAL", "0", 3, self.colors['accent'])
        
        # Output Area
        output_frame = tk.Frame(right_frame, bg=self.colors['bg_dark'])
        output_frame.pack(fill='both', expand=True, padx=20, pady=(0, 20))
        
        # Tab-like header
        tab_header = tk.Frame(output_frame, bg=self.colors['bg_dark'], height=40)
        tab_header.pack(fill='x')
        
        tk.Label(
            tab_header,
            text="📊 SCAN OUTPUT",
            bg=self.colors['bg_dark'],
            fg=self.colors['text'],
            font=('Arial', 12, 'bold')
        ).pack(side='left', pady=10)
        
        self.status_label = tk.Label(
            tab_header,
            text="● Ready",
            bg=self.colors['bg_dark'],
            fg=self.colors['success'],
            font=('Arial', 10, 'bold')
        )
        self.status_label.pack(side='right', pady=10, padx=20)
        
        # Console output
        console_frame = tk.Frame(output_frame, bg=self.colors['bg_light'])
        console_frame.pack(fill='both', expand=True)
        
        self.output_text = scrolledtext.ScrolledText(
            console_frame,
            bg='#0a0a15',
            fg=self.colors['success'],
            font=('Consolas', 10),
            insertbackground=self.colors['accent'],
            wrap='word',
            relief='flat',
            padx=15,
            pady=15
        )
        self.output_text.pack(fill='both', expand=True, padx=2, pady=2)
        
        # Configure text tags for colored output
        self.output_text.tag_config('info', foreground='#06ffa5')
        self.output_text.tag_config('warning', foreground='#ffd93d')
        self.output_text.tag_config('error', foreground='#e94560')
        self.output_text.tag_config('success', foreground='#00d4ff')
        
        # Progress bar
        progress_frame = tk.Frame(right_frame, bg=self.colors['bg_dark'], height=30)
        progress_frame.pack(fill='x', padx=20, pady=(0, 20))
        
        self.progress = ttk.Progressbar(
            progress_frame,
            mode='indeterminate',
            style='Custom.Horizontal.TProgressbar'
        )
        self.progress.pack(fill='x')
        
        # Style the progress bar
        style = ttk.Style()
        style.theme_use('clam')
        style.configure(
            'Custom.Horizontal.TProgressbar',
            background=self.colors['accent'],
            troughcolor=self.colors['bg_light'],
            borderwidth=0,
            thickness=6
        )
        
        # Welcome message
        self.log_output("=" * 80, 'info')
        self.log_output("  NETWORK SECURITY SCANNER PRO v1.0", 'success')
        self.log_output("  Advanced Vulnerability Detection System", 'info')
        self.log_output("=" * 80, 'info')
        self.log_output("\n✓ System initialized and ready", 'success')
        self.log_output("✓ Configure your scan settings and click START SCAN\n", 'info')
        
    def create_section_header(self, parent, text):
        """Create a styled section header"""
        header = tk.Label(
            parent,
            text=text,
            bg=self.colors['bg_medium'],
            fg=self.colors['text_dim'],
            font=('Arial', 9, 'bold')
        )
        header.pack(anchor='w', pady=(20, 10))
        
    def create_checkbox(self, parent, text, variable, command=None):
        """Create a styled checkbox"""
        cb = tk.Checkbutton(
            parent,
            text=text,
            variable=variable,
            command=command,
            bg=self.colors['bg_medium'],
            fg=self.colors['text'],
            selectcolor=self.colors['bg_dark'],
            activebackground=self.colors['bg_medium'],
            activeforeground=self.colors['accent'],
            font=('Arial', 10),
            cursor='hand2'
        )
        cb.pack(anchor='w', pady=5)
        
    def create_stat_card(self, parent, label, value, column, color=None):
        """Create a statistics card"""
        card = tk.Frame(parent, bg=self.colors['bg_medium'])
        card.grid(row=0, column=column, padx=10, pady=10)
        
        tk.Label(
            card,
            text=label,
            bg=self.colors['bg_medium'],
            fg=self.colors['text_dim'],
            font=('Arial', 9)
        ).pack()
        
        value_label = tk.Label(
            card,
            text=value,
            bg=self.colors['bg_medium'],
            fg=color or self.colors['success'],
            font=('Arial', 24, 'bold')
        )
        value_label.pack(pady=(5, 0))
        
        return value_label
        
    def toggle_target_entry(self):
        """Toggle custom target entry"""
        if self.auto_detect_var.get():
            self.target_entry.config(state='disabled')
        else:
            self.target_entry.config(state='normal')
    
    def log_output(self, message, tag='info'):
        """Add message to output console with color"""
        self.output_text.insert('end', message + '\n', tag)
        self.output_text.see('end')
        self.root.update()
    
    def update_status(self, message, color=None):
        """Update status label"""
        self.status_label.config(
            text=f"● {message}",
            fg=color or self.colors['success']
        )
    
    def update_stats(self, hosts=0, ports=0, vulns=0, critical=0):
        """Update statistics display"""
        self.stat_hosts.config(text=str(hosts))
        self.stat_ports.config(text=str(ports))
        self.stat_vulns.config(text=str(vulns))
        self.stat_critical.config(text=str(critical))
    
    def start_scan(self):
        """Start the security scan"""
        if self.is_scanning:
            messagebox.showwarning("Scan in Progress", "A scan is already running!")
            return
        
        # Check root privileges
        if os.geteuid() != 0:
            messagebox.showerror(
                "Root Required",
                "This scanner requires root privileges.\n\nPlease run with:\nsudo venv/bin/python gui_modern.py"
            )
            return
        
        # Clear previous output
        self.output_text.delete('1.0', 'end')
        self.update_stats(0, 0, 0, 0)
        
        # Get configuration
        target = None if self.auto_detect_var.get() else self.target_entry.get()
        port_range = self.port_var.get()
        skip_os = self.skip_os_var.get()
        test_creds = self.test_creds_var.get()
        
        # Update UI
        self.is_scanning = True
        self.progress.start(10)
        self.update_status("Scanning...", self.colors['warning'])
        
        # Start scan in separate thread
        self.scan_thread = threading.Thread(
            target=self.run_scan,
            args=(target, port_range, skip_os, test_creds),
            daemon=True
        )
        self.scan_thread.start()
    
    def run_scan(self, target, port_range, skip_os, test_creds):
        """Run the complete scan process"""
        try:
            self.log_output("\n" + "=" * 80, 'success')
            self.log_output("  PHASE 1: NETWORK SCANNING", 'success')
            self.log_output("=" * 80 + "\n", 'success')
            
            # Initialize scanner
            self.scanner = NetworkScanner()
            
            # Setup logging redirect
            import logging
            class GUIHandler(logging.Handler):
                def __init__(self, gui):
                    super().__init__()
                    self.gui = gui
                
                def emit(self, record):
                    msg = self.format(record)
                    tag = 'info'
                    if record.levelname == 'WARNING':
                        tag = 'warning'
                    elif record.levelname == 'ERROR':
                        tag = 'error'
                    self.gui.log_output(msg, tag)
            
            logger = logging.getLogger('scanner.network_scan')
            gui_handler = GUIHandler(self)
            gui_handler.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))
            logger.addHandler(gui_handler)
            
            # Run scan
            results = self.scanner.full_scan(
                target=target,
                port_range=port_range,
                skip_os_detection=skip_os
            )
            
            # Update stats
            total_hosts = len(results['hosts'])
            total_ports = sum(len(h['open_ports']) for h in results['hosts'])
            self.update_stats(hosts=total_hosts, ports=total_ports)
            
            # Phase 2: Vulnerability Analysis
            self.log_output("\n" + "=" * 80, 'success')
            self.log_output("  PHASE 2: VULNERABILITY ANALYSIS", 'success')
            self.log_output("=" * 80 + "\n", 'success')
            
            rules_engine = RulesEngine()
            results = rules_engine.analyze_scan_results(results)
            
            # Phase 3: Credentials Testing
            cred_checker = None
            if test_creds:
                self.log_output("\n" + "=" * 80, 'success')
                self.log_output("  PHASE 3: CREDENTIALS TESTING", 'success')
                self.log_output("=" * 80 + "\n", 'success')
                
                cred_checker = CredentialsChecker()
                results = cred_checker.check_all_hosts(results)
            
            # Update final stats
            vuln_summary = results.get('vulnerability_summary', {})
            total_vulns = vuln_summary.get('total', 0)
            critical = vuln_summary.get('critical', 0)
            self.update_stats(
                hosts=total_hosts,
                ports=total_ports,
                vulns=total_vulns,
                critical=critical
            )
            
            # Store results
            self.scan_results = results
            
            # Display summary
            self.log_output("\n" + "=" * 80, 'success')
            self.log_output("  SCAN COMPLETE", 'success')
            self.log_output("=" * 80, 'success')
            self.log_output(f"\n✓ Hosts Scanned: {total_hosts}", 'info')
            self.log_output(f"✓ Open Ports Found: {total_ports}", 'info')
            self.log_output(f"✓ Total Vulnerabilities: {total_vulns}", 'warning' if total_vulns > 0 else 'success')
            
            if critical > 0:
                self.log_output(f"\n⚠️  CRITICAL: {critical} critical vulnerabilities detected!", 'error')
            
            # Generate reports
            self.log_output("\n" + "=" * 80, 'success')
            self.log_output("  GENERATING REPORTS", 'success')
            self.log_output("=" * 80 + "\n", 'success')
            
            self.generate_reports(results, test_creds, cred_checker)
            
            self.update_status("Scan Complete", self.colors['success'])
            self.log_output("\n✓ All reports generated successfully!", 'success')
            
        except Exception as e:
            self.log_output(f"\n❌ ERROR: {str(e)}", 'error')
            self.update_status("Scan Failed", self.colors['accent'])
            import traceback
            self.log_output(traceback.format_exc(), 'error')
        
        finally:
            self.is_scanning = False
            self.progress.stop()
    
    def generate_reports(self, results, test_creds, cred_checker):
        """Generate all report formats"""
        output_dir = 'output'
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # JSON
        json_file = os.path.join(output_dir, f'scan_{timestamp}.json')
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2)
        self.log_output(f"✓ JSON: {json_file}", 'info')
        
        # HTML
        html_gen = HTMLReportGenerator()
        html_file = os.path.join(output_dir, f'report_{timestamp}.html')
        html_gen.generate_report(results, html_file)
        self.log_output(f"✓ HTML: {html_file}", 'info')
        
        # PDF
        try:
            pdf_gen = PDFReportGenerator()
            pdf_file = os.path.join(output_dir, f'report_{timestamp}.pdf')
            pdf_gen.generate_report(results, pdf_file)
            self.log_output(f"✓ PDF: {pdf_file}", 'info')
        except Exception as e:
            self.log_output(f"⚠️  PDF generation skipped: {str(e)}", 'warning')
        
        # Credentials report
        if test_creds and cred_checker:
            cred_file = os.path.join(output_dir, f'credentials_{timestamp}.txt')
            with open(cred_file, 'w') as f:
                f.write(cred_checker.generate_report())
            self.log_output(f"✓ Credentials: {cred_file}", 'info')
    
    def stop_scan(self):
        """Stop the running scan"""
        if messagebox.askyesno("Stop Scan", "Are you sure you want to stop the scan?"):
            self.is_scanning = False
            self.log_output("\n⚠️  Scan stopped by user", 'warning')
            self.update_status("Stopped", self.colors['accent'])
            self.progress.stop()
    
    def export_results(self):
        """Export the most recent scan results"""
        if not self.scan_results:
            # Find most recent file
            output_dir = 'output'
            if not os.path.exists(output_dir):
                messagebox.showwarning("No Results", "No scan results available!")
                return
            
            files = [f for f in os.listdir(output_dir) if f.endswith('.html')]
            if not files:
                messagebox.showwarning("No Results", "No scan results available!")
                return
            
            latest = max([os.path.join(output_dir, f) for f in files], key=os.path.getctime)
        else:
            latest = 'output'
        
        # Open file dialog
        import subprocess
        subprocess.Popen(['xdg-open', 'output'])
        messagebox.showinfo("Reports", f"Opening reports folder:\n{os.path.abspath('output')}")

def main():
    # Check root
    if os.geteuid() != 0:
        print("⚠️  Warning: This scanner requires root privileges")
        print("Please run with: sudo venv/bin/python gui_modern.py")
        response = input("\nContinue anyway? (limited functionality) (y/n): ")
        if response.lower() != 'y':
            return
    
    root = tk.Tk()
    app = ScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
