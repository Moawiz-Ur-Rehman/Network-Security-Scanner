#!/usr/bin/env python3
"""
Network Security Scanner - GUI Version
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import json
import os
from datetime import datetime
from scanner.network_scan import NetworkScanner

class ScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Security Scanner")
        self.root.geometry("1000x700")
        self.root.configure(bg='#1e1e1e')
        
        self.scanner = None
        self.scan_thread = None
        self.is_scanning = False
        
        self.setup_ui()
        
    def setup_ui(self):
        # Title
        title_frame = tk.Frame(self.root, bg='#2d2d2d', height=60)
        title_frame.pack(fill='x', padx=10, pady=10)
        
        title_label = tk.Label(
            title_frame,
            text="🔍 Network Security Scanner",
            font=('Arial', 20, 'bold'),
            bg='#2d2d2d',
            fg='#00ff00'
        )
        title_label.pack(pady=10)
        
        # Main container
        main_frame = tk.Frame(self.root, bg='#1e1e1e')
        main_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Left panel - Configuration
        left_frame = tk.Frame(main_frame, bg='#2d2d2d', width=300)
        left_frame.pack(side='left', fill='both', padx=(0, 5))
        
        # Configuration section
        config_label = tk.Label(
            left_frame,
            text="Scan Configuration",
            font=('Arial', 14, 'bold'),
            bg='#2d2d2d',
            fg='#ffffff'
        )
        config_label.pack(pady=10)
        
        # Target selection
        target_frame = tk.LabelFrame(
            left_frame,
            text="Target",
            bg='#2d2d2d',
            fg='#ffffff',
            font=('Arial', 10, 'bold')
        )
        target_frame.pack(fill='x', padx=10, pady=5)
        
        self.auto_detect_var = tk.BooleanVar(value=True)
        auto_check = tk.Checkbutton(
            target_frame,
            text="Auto-detect local subnet",
            variable=self.auto_detect_var,
            command=self.toggle_target_entry,
            bg='#2d2d2d',
            fg='#ffffff',
            selectcolor='#1e1e1e',
            activebackground='#2d2d2d',
            activeforeground='#ffffff'
        )
        auto_check.pack(anchor='w', padx=5, pady=5)
        
        tk.Label(
            target_frame,
            text="Custom Target:",
            bg='#2d2d2d',
            fg='#ffffff'
        ).pack(anchor='w', padx=5)
        
        self.target_entry = tk.Entry(
            target_frame,
            bg='#3d3d3d',
            fg='#ffffff',
            insertbackground='#ffffff',
            state='disabled'
        )
        self.target_entry.pack(fill='x', padx=5, pady=5)
        
        # Port range
        port_frame = tk.LabelFrame(
            left_frame,
            text="Port Range",
            bg='#2d2d2d',
            fg='#ffffff',
            font=('Arial', 10, 'bold')
        )
        port_frame.pack(fill='x', padx=10, pady=5)
        
        self.port_var = tk.StringVar(value="1-1000")
        
        port_options = [
            ("Quick (1-100)", "1-100"),
            ("Common (1-1000)", "1-1000"),
            ("Extended (1-5000)", "1-5000"),
            ("All (1-65535)", "1-65535")
        ]
        
        for text, value in port_options:
            tk.Radiobutton(
                port_frame,
                text=text,
                variable=self.port_var,
                value=value,
                bg='#2d2d2d',
                fg='#ffffff',
                selectcolor='#1e1e1e',
                activebackground='#2d2d2d',
                activeforeground='#ffffff'
            ).pack(anchor='w', padx=5)
        
        # Options
        options_frame = tk.LabelFrame(
            left_frame,
            text="Options",
            bg='#2d2d2d',
            fg='#ffffff',
            font=('Arial', 10, 'bold')
        )
        options_frame.pack(fill='x', padx=10, pady=5)
        
        self.skip_os_var = tk.BooleanVar(value=True)
        tk.Checkbutton(
            options_frame,
            text="Skip OS detection (faster)",
            variable=self.skip_os_var,
            bg='#2d2d2d',
            fg='#ffffff',
            selectcolor='#1e1e1e',
            activebackground='#2d2d2d',
            activeforeground='#ffffff'
        ).pack(anchor='w', padx=5, pady=5)
        
        # Buttons
        button_frame = tk.Frame(left_frame, bg='#2d2d2d')
        button_frame.pack(fill='x', padx=10, pady=20)
        
        self.start_btn = tk.Button(
            button_frame,
            text="▶ Start Scan",
            command=self.start_scan,
            bg='#00aa00',
            fg='#ffffff',
            font=('Arial', 12, 'bold'),
            relief='flat',
            cursor='hand2',
            height=2
        )
        self.start_btn.pack(fill='x', pady=5)
        
        self.stop_btn = tk.Button(
            button_frame,
            text="⬛ Stop Scan",
            command=self.stop_scan,
            bg='#aa0000',
            fg='#ffffff',
            font=('Arial', 12, 'bold'),
            relief='flat',
            cursor='hand2',
            height=2,
            state='disabled'
        )
        self.stop_btn.pack(fill='x', pady=5)
        
        self.export_btn = tk.Button(
            button_frame,
            text="💾 Export Results",
            command=self.export_results,
            bg='#0066cc',
            fg='#ffffff',
            font=('Arial', 12, 'bold'),
            relief='flat',
            cursor='hand2',
            height=2
        )
        self.export_btn.pack(fill='x', pady=5)
        
        # Right panel - Results
        right_frame = tk.Frame(main_frame, bg='#2d2d2d')
        right_frame.pack(side='right', fill='both', expand=True)
        
        results_label = tk.Label(
            right_frame,
            text="Scan Output",
            font=('Arial', 14, 'bold'),
            bg='#2d2d2d',
            fg='#ffffff'
        )
        results_label.pack(pady=10)
        
        # Output text area
        self.output_text = scrolledtext.ScrolledText(
            right_frame,
            bg='#1e1e1e',
            fg='#00ff00',
            font=('Courier', 10),
            insertbackground='#00ff00',
            wrap='word'
        )
        self.output_text.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Status bar
        status_frame = tk.Frame(self.root, bg='#2d2d2d', height=30)
        status_frame.pack(fill='x', side='bottom')
        
        self.status_label = tk.Label(
            status_frame,
            text="Ready",
            bg='#2d2d2d',
            fg='#00ff00',
            font=('Arial', 10),
            anchor='w'
        )
        self.status_label.pack(side='left', padx=10)
        
        self.progress = ttk.Progressbar(
            status_frame,
            mode='indeterminate',
            length=200
        )
        self.progress.pack(side='right', padx=10)
        
    def toggle_target_entry(self):
        if self.auto_detect_var.get():
            self.target_entry.config(state='disabled')
        else:
            self.target_entry.config(state='normal')
    
    def log_output(self, message):
        self.output_text.insert('end', message + '\n')
        self.output_text.see('end')
        self.root.update()
    
    def update_status(self, message, color='#00ff00'):
        self.status_label.config(text=message, fg=color)
    
    def start_scan(self):
        if self.is_scanning:
            messagebox.showwarning("Scan in Progress", "A scan is already running!")
            return
        
        # Check root privileges
        if os.geteuid() != 0:
            messagebox.showerror(
                "Root Required",
                "This scanner requires root privileges.\nPlease run with: sudo venv/bin/python gui_scanner.py"
            )
            return
        
        # Clear previous output
        self.output_text.delete('1.0', 'end')
        
        # Get configuration
        target = None if self.auto_detect_var.get() else self.target_entry.get()
        port_range = self.port_var.get()
        skip_os = self.skip_os_var.get()
        
        # Update UI
        self.is_scanning = True
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.progress.start()
        self.update_status("Scanning...", '#ffaa00')
        
        # Start scan in separate thread
        self.scan_thread = threading.Thread(
            target=self.run_scan,
            args=(target, port_range, skip_os),
            daemon=True
        )
        self.scan_thread.start()
    
    def run_scan(self, target, port_range, skip_os):
        try:
            self.log_output("=" * 70)
            self.log_output("Network Security Scanner - Starting Scan")
            self.log_output("=" * 70)
            self.log_output("")
            
            # Initialize scanner
            self.scanner = NetworkScanner()
            
            # Redirect logging to GUI
            import logging
            
            class GUIHandler(logging.Handler):
                def __init__(self, gui):
                    super().__init__()
                    self.gui = gui
                
                def emit(self, record):
                    msg = self.format(record)
                    self.gui.log_output(msg)
            
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
            
            # Display summary
            self.log_output("\n" + "=" * 70)
            self.log_output("SCAN COMPLETE - SUMMARY")
            self.log_output("=" * 70)
            self.log_output(f"Scan Time: {results['scan_time']}")
            self.log_output(f"Total Hosts: {len(results['hosts'])}")
            
            total_ports = sum(len(h['open_ports']) for h in results['hosts'])
            self.log_output(f"Total Open Ports: {total_ports}")
            self.log_output("")
            
            for host in results['hosts']:
                self.log_output(f"Host: {host['ip']} ({host['hostname']})")
                self.log_output(f"  OS: {host['os']['name']}")
                self.log_output(f"  Open Ports: {len(host['open_ports'])}")
                
                for port in host['open_ports']:
                    service = f"{port['service']}"
                    if port['product']:
                        service += f" - {port['product']}"
                    if port['version']:
                        service += f" {port['version']}"
                    self.log_output(f"    • {port['port']}/{port['protocol']}: {service}")
                self.log_output("")
            
            # Save results
            os.makedirs('output', exist_ok=True)
            output_file = f"output/scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            self.log_output(f"✓ Results saved to: {output_file}")
            self.update_status("Scan complete!", '#00ff00')
            
        except Exception as e:
            self.log_output(f"\n❌ Error: {str(e)}")
            self.update_status("Scan failed!", '#ff0000')
        
        finally:
            self.is_scanning = False
            self.start_btn.config(state='normal')
            self.stop_btn.config(state='disabled')
            self.progress.stop()
    
    def stop_scan(self):
        if messagebox.askyesno("Stop Scan", "Are you sure you want to stop the scan?"):
            self.is_scanning = False
            self.log_output("\n⚠️  Scan stopped by user")
            self.update_status("Scan stopped", '#ff0000')
            self.start_btn.config(state='normal')
            self.stop_btn.config(state='disabled')
            self.progress.stop()
    
    def export_results(self):
        # Find the most recent scan file
        output_dir = 'output'
        if not os.path.exists(output_dir):
            messagebox.showwarning("No Results", "No scan results found!")
            return
        
        files = [f for f in os.listdir(output_dir) if f.startswith('scan_') and f.endswith('.json')]
        if not files:
            messagebox.showwarning("No Results", "No scan results found!")
            return
        
        latest_file = max([os.path.join(output_dir, f) for f in files], key=os.path.getctime)
        
        # Ask user where to save
        save_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=os.path.basename(latest_file)
        )
        
        if save_path:
            import shutil
            shutil.copy(latest_file, save_path)
            messagebox.showinfo("Export Complete", f"Results exported to:\n{save_path}")

def main():
    # Check root
    if os.geteuid() != 0:
        print("⚠️  Warning: This scanner requires root privileges")
        print("Please run with: sudo venv/bin/python gui_scanner.py")
        response = input("\nContinue anyway? (limited functionality) (y/n): ")
        if response.lower() != 'y':
            return
    
    root = tk.Tk()
    app = ScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
