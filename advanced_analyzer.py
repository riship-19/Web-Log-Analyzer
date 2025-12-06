import re
import pandas as pd
import matplotlib.pyplot as plt
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import os
from datetime import datetime

# --- Configuration ---
LOG_FILE = "sample_logs/access.log"
REPORT_DIR = "reports"
os.makedirs(REPORT_DIR, exist_ok=True)


class LogAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Web Log Analyzer")
        self.root.geometry("800x600")

        self.df = None

        # UI Elements
        self.create_widgets()

    def create_widgets(self):
        # Header
        header = tk.Label(self.root, text="Web Log Analyzer Dashboard", font=("Arial", 16, "bold"))
        header.pack(pady=10)

        # Control Frame
        control_frame = tk.Frame(self.root)
        control_frame.pack(pady=5)

        btn_analyze = tk.Button(control_frame, text="1. Load & Analyze Logs", command=self.analyze_logs, bg="#dddddd")
        btn_analyze.pack(side=tk.LEFT, padx=10)

        btn_graphs = tk.Button(control_frame, text="2. Generate Graphs", command=self.show_graphs, bg="#dddddd")
        btn_graphs.pack(side=tk.LEFT, padx=10)

        btn_report = tk.Button(control_frame, text="3. Export HTML Report", command=self.generate_html_report,
                               bg="#dddddd")
        btn_report.pack(side=tk.LEFT, padx=10)

        # Log Output Area
        self.log_text = scrolledtext.ScrolledText(self.root, width=90, height=25)
        self.log_text.pack(pady=20)

        self.log_message("Welcome. Click 'Load & Analyze Logs' to start.")

    def log_message(self, message):
        self.log_text.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n")
        self.log_text.see(tk.END)

    def analyze_logs(self):
        if not os.path.exists(LOG_FILE):
            messagebox.showerror("Error", f"Log file not found: {LOG_FILE}")
            return

        self.log_message(f"Reading {LOG_FILE}...")

        # Regex Pattern for Parsing
        pattern = re.compile(
            r'(?P<ip>\S+) - - \[(?P<time>.*?)\] "(?P<method>\S+) (?P<path>.*?) HTTP/1.1" (?P<status>\d+) (?P<size>\d+) "-" "(?P<ua>.*?)"'
        )

        records = []
        try:
            with open(LOG_FILE, 'r') as f:
                for line in f:
                    m = pattern.match(line)
                    if m:
                        records.append(m.groupdict())

            if not records:
                self.log_message("No valid records found in log file.")
                return

            self.df = pd.DataFrame(records)
            self.df['status'] = self.df['status'].astype(int)

            # --- Enhanced Attack Detection Signatures ---
            self.df['attack_type'] = "Normal"

            # 1. SQL Injection (Expanded)
            sqli_pattern = r"OR '1'='1|UNION SELECT|SELECT.*FROM|SLEEP\(|BENCHMARK\(|--"
            self.df.loc[
                self.df['path'].str.contains(sqli_pattern, case=False, regex=True), 'attack_type'] = "SQL Injection"

            # 2. XSS (Cross-Site Scripting)
            xss_pattern = r"<script>|javascript:|onerror=|onload=|alert\("
            self.df.loc[self.df['path'].str.contains(xss_pattern, case=False, regex=True), 'attack_type'] = "XSS"

            # 3. Directory Traversal
            trav_pattern = r"\.\./|\.\.\\|/etc/passwd|c:\\boot.ini"
            self.df.loc[self.df['path'].str.contains(trav_pattern, case=False,
                                                     regex=True), 'attack_type'] = "Directory Traversal"

            # 4. Command Injection
            cmd_pattern = r";\s*ls|;\s*cat|\|\s*ls|\|\s*cat|\$\(.*\)"
            self.df.loc[
                self.df['path'].str.contains(cmd_pattern, case=False, regex=True), 'attack_type'] = "Command Injection"

            # 5. Scanners (User-Agent based)
            ua_pattern = r"sqlmap|nikto|nmap|masscan|gobuster"
            self.df.loc[self.df['ua'].str.contains(ua_pattern, case=False, regex=True) & (
                        self.df['attack_type'] == "Normal"), 'attack_type'] = "Automated Scanner"

            # Summary stats
            total_reqs = len(self.df)
            total_attacks = len(self.df[self.df['attack_type'] != "Normal"])

            self.log_message(f"Analysis Complete.")
            self.log_message(f"Total Requests: {total_reqs}")
            self.log_message(f"Attacks Detected: {total_attacks}")
            self.log_message("-" * 30)
            self.log_message(
                "Top Attackers:\n" + str(self.df[self.df['attack_type'] != 'Normal']['ip'].value_counts().head()))

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def show_graphs(self):
        if self.df is None:
            messagebox.showwarning("Warning", "Please analyze logs first.")
            return

        self.log_message("Generating graphs...")

        # Filter only attacks for visualization
        attack_df = self.df[self.df['attack_type'] != "Normal"]

        if attack_df.empty:
            messagebox.showinfo("Info", "No attacks found to plot.")
            return

        # Setup plots
        fig, axes = plt.subplots(1, 2, figsize=(12, 5))

        # Graph 1: Attacks by Type
        attack_counts = attack_df['attack_type'].value_counts()
        attack_counts.plot(kind='bar', ax=axes[0], color='salmon')
        axes[0].set_title('Distribution of Attack Types')
        axes[0].set_ylabel('Count')
        axes[0].tick_params(axis='x', rotation=45)

        # Graph 2: Top Attacking IPs
        ip_counts = attack_df['ip'].value_counts().head(5)
        ip_counts.plot(kind='pie', ax=axes[1], autopct='%1.1f%%', startangle=90)
        axes[1].set_title('Top 5 Attacking IPs')
        axes[1].set_ylabel('')

        plt.tight_layout()
        plt.show()  # Opens the matplotlib window
        self.log_message("Graphs displayed.")

    def generate_html_report(self):
        if self.df is None:
            messagebox.showwarning("Warning", "Please analyze logs first.")
            return

        self.log_message("Generating HTML report...")

        # Save plots to file for HTML inclusion
        attack_df = self.df[self.df['attack_type'] != "Normal"]
        img_path = os.path.join(REPORT_DIR, "attack_summary.png")

        if not attack_df.empty:
            plt.figure(figsize=(10, 6))
            attack_df['attack_type'].value_counts().plot(kind='barh', color='skyblue')
            plt.title("Attack Summary")
            plt.xlabel("Count")
            plt.savefig(img_path)
            plt.close()

        # Create HTML Content
        html_content = f"""
        <html>
        <head>
            <title>Security Analysis Report</title>
            <style>
                body {{ font-family: sans-serif; margin: 20px; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .danger {{ color: red; font-weight: bold; }}
            </style>
        </head>
        <body>
            <h1>Web Log Security Report</h1>
            <p><strong>Date Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

            <h2>Executive Summary</h2>
            <ul>
                <li>Total Requests: {len(self.df)}</li>
                <li class="danger">Malicious Requests: {len(attack_df)}</li>
            </ul>

            <h2>Visual Analysis</h2>
            <img src="attack_summary.png" alt="Attack Graph" style="border:1px solid #ccc;">

            <h2>Detailed Attack Log (Top 20)</h2>
            {attack_df[['time', 'ip', 'attack_type', 'method', 'path']].head(20).to_html(index=False, classes='table')}
        </body>
        </html>
        """

        report_file = os.path.join(REPORT_DIR, "report.html")
        with open(report_file, "w") as f:
            f.write(html_content)

        self.log_message(f"Report saved to: {os.path.abspath(report_file)}")
        messagebox.showinfo("Success", f"Report generated:\n{report_file}")


if __name__ == "__main__":
    root = tk.Tk()
    app = LogAnalyzerApp(root)
    root.mainloop()