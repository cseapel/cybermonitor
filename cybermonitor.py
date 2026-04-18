import json
import os
import re
import sys
import csv
import time
import queue
import shutil
import smtplib
import tempfile
import threading
import subprocess
import tkinter as tk
import ipaddress
from collections import deque
from email.message import EmailMessage
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText

APP_TITLE = "Cyber System Monitor"
WINDOW_SIZE = "1600x980"
REFRESH_MS = 3000
LOG_LINES = 300
MAX_TEXT = 180000
TOP_N = 15
CONFIG_PATH = Path.home() / ".cyber_monitor_config.json"
CHART_POINTS = 30
GEO_CACHE_LIMIT = 256

try:
    import psutil
except Exception:
    psutil = None

try:
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
    MATPLOTLIB_AVAILABLE = True
except Exception:
    MATPLOTLIB_AVAILABLE = False


def detect_platform() -> str:
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


class CyberMonitorApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry(WINDOW_SIZE)
        self.platform = detect_platform()
        self.queue: queue.Queue = queue.Queue()
        self.refresh_job = None
        self.worker = None
        self.last_logs = ""
        self.last_events = ""
        self.last_failed_login_count = 0
        self.last_cpu_rows = []
        self.last_storage_rows = []
        self.last_network_rows = []
        self.last_net_counters = None
        self.last_net_time = None
        self.cpu_history = deque(maxlen=CHART_POINTS)
        self.mem_history = deque(maxlen=CHART_POINTS)
        self.net_sent_history = deque(maxlen=CHART_POINTS)
        self.net_recv_history = deque(maxlen=CHART_POINTS)
        self.current_net_severity = "LOW"
        self.geo_cache = {}
        self.geo_status = "Geo/IP lookup idle"
        self.load_config()
        self.selected_path = tk.StringVar(value=self.config.get("scan_path", self.default_scan_path()))
        self.status = tk.StringVar(value=f"Ready on {self.platform}")
        self.auto_refresh = tk.BooleanVar(value=True)
        self.filter_text = tk.StringVar(value="")
        self.build_ui()
        self.refresh_all()

    def default_config(self):
        return {
            "scan_path": self.default_scan_path(),
            "email_enabled": False,
            "smtp_server": "smtp.gmail.com",
            "smtp_port": 587,
            "smtp_username": "",
            "smtp_password": "",
            "sender_email": "",
            "recipient_emails": "",
            "use_tls": True,
            "cpu_process_names": "python.exe, python, chrome.exe, chrome",
            "cpu_threshold": 40.0,
            "memory_threshold_mb": 500.0,
            "storage_threshold_gb": 5.0,
            "failed_login_threshold": 5,
            "network_bytes_per_sec_threshold": 5000000,
            "suspicious_ports": "21,22,23,3389,4444,5555,8080",
            "cooldown_minutes": 20,
            "attach_report_files": True,
            "attachment_log_paths": self.default_attachment_paths(),
            "last_alerts": {}
        }

    def default_attachment_paths(self):
        if self.platform == "linux":
            return "/var/log/auth.log,/var/log/syslog"
        if self.platform == "macos":
            return "/var/log/system.log"
        return ""

    def load_config(self):
        self.config = self.default_config()
        if CONFIG_PATH.exists():
            try:
                loaded = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
                self.config.update(loaded)
            except Exception:
                pass

    def save_config(self):
        self.config["scan_path"] = self.selected_path.get()
        try:
            CONFIG_PATH.write_text(json.dumps(self.config, indent=2), encoding="utf-8")
            self.status.set(f"Settings saved to {CONFIG_PATH}")
        except Exception as exc:
            messagebox.showerror(APP_TITLE, f"Could not save settings: {exc}")

    def build_ui(self):
        outer = ttk.Frame(self.root, padding=10)
        outer.pack(fill="both", expand=True)

        toolbar = ttk.Frame(outer)
        toolbar.pack(fill="x", pady=(0, 8))
        ttk.Label(toolbar, text="Folder scan path:").pack(side="left")
        ttk.Entry(toolbar, textvariable=self.selected_path, width=42).pack(side="left", padx=(8, 6))
        ttk.Button(toolbar, text="Browse", command=self.choose_folder).pack(side="left")
        ttk.Button(toolbar, text="Refresh now", command=self.refresh_all).pack(side="left", padx=(10, 0))
        ttk.Button(toolbar, text="Email current report", command=self.email_current_report).pack(side="left", padx=(10, 0))
        ttk.Button(toolbar, text="Export CSV", command=self.export_csv_report).pack(side="left", padx=(10, 0))
        ttk.Checkbutton(toolbar, text="Auto refresh", variable=self.auto_refresh, command=self.toggle_auto_refresh).pack(side="left", padx=(12, 0))
        ttk.Label(toolbar, text="Filter logs/events:").pack(side="left", padx=(16, 4))
        filter_entry = ttk.Entry(toolbar, textvariable=self.filter_text, width=22)
        filter_entry.pack(side="left")
        filter_entry.bind("<KeyRelease>", lambda e: self.apply_filters())

  
     
   
      

        self.notebook = ttk.Notebook(outer)
        self.notebook.pack(fill="both", expand=True)

        self.dashboard_tab = ttk.Frame(self.notebook)
        self.logs_tab = ttk.Frame(self.notebook)
        self.events_tab = ttk.Frame(self.notebook)
        self.cpu_tab = ttk.Frame(self.notebook)
        self.storage_tab = ttk.Frame(self.notebook)
        self.network_tab = ttk.Frame(self.notebook)
        self.alerts_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_tab, text="Dashboard")
        self.notebook.add(self.logs_tab, text="System Logs")
        self.notebook.add(self.events_tab, text="Login / Shutdown Events")
        self.notebook.add(self.cpu_tab, text="CPU / Processes")
        self.notebook.add(self.storage_tab, text="Storage Hotspots")
        self.notebook.add(self.network_tab, text="Network Traffic")
        self.notebook.add(self.alerts_tab, text="Alert Settings")

        self.build_dashboard_tab()

        self.logs_text = ScrolledText(self.logs_tab, wrap="none", font=("Courier New", 10))
        self.logs_text.pack(fill="both", expand=True)
        self.logs_text.configure(state="disabled")

        events_frame = ttk.Frame(self.events_tab, padding=6)
        events_frame.pack(fill="both", expand=True)

        event_columns = ("time", "type", "details", "user")
        self.events_table = ttk.Treeview(events_frame, columns=event_columns, show="headings", height=20)
        for col, width in [("time", 190), ("type", 170), ("details", 760), ("user", 180)]:
            self.events_table.heading(col, text=col.upper())
            self.events_table.column(col, width=width, anchor="w")
        self.events_table.pack(fill="both", expand=True, side="left")

        events_scroll = ttk.Scrollbar(events_frame, orient="vertical", command=self.events_table.yview)
        events_scroll.pack(side="right", fill="y")
        self.events_table.configure(yscrollcommand=events_scroll.set)

        self.events_table.tag_configure("HIGH", background="#ffd6d6")
        self.events_table.tag_configure("MEDIUM", background="#fff2cc")
        self.events_table.tag_configure("LOW", background="#e7f4ff")

        cpu_frame = ttk.Frame(self.cpu_tab, padding=6)
        cpu_frame.pack(fill="both", expand=True)
        columns = ("severity", "pid", "name", "cpu", "memory", "user")
        self.cpu_table = ttk.Treeview(cpu_frame, columns=columns, show="headings", height=20)
        for col, width in [("severity", 90), ("pid", 80), ("name", 320), ("cpu", 100), ("memory", 120), ("user", 220)]:
            self.cpu_table.heading(col, text=col.upper())
            self.cpu_table.column(col, width=width, anchor="w")
        self.cpu_table.pack(fill="both", expand=True)

        storage_frame = ttk.Frame(self.storage_tab, padding=6)
        storage_frame.pack(fill="both", expand=True)
        s_cols = ("severity", "folder", "size", "files")
        self.storage_table = ttk.Treeview(storage_frame, columns=s_cols, show="headings", height=18)
        for col, width in [("severity", 90), ("folder", 700), ("size", 180), ("files", 120)]:
            self.storage_table.heading(col, text=col.upper())
            self.storage_table.column(col, width=width, anchor="w")
        self.storage_table.pack(fill="both", expand=True)

        network_frame = ttk.Frame(self.network_tab, padding=6)
        network_frame.pack(fill="both", expand=True)
        top_net = ttk.Frame(network_frame)
        top_net.pack(fill="x", pady=(0, 6))
        self.network_rate_label = ttk.Label(top_net, text="Traffic rates: waiting for baseline...")
        self.network_rate_label.pack(anchor="w")
        self.geo_label = ttk.Label(top_net, text="Geo/IP lookup idle")
        self.geo_label.pack(anchor="w")
        n_cols = ("severity", "proto", "local", "remote", "geo", "status", "pid", "process")
        self.network_table = ttk.Treeview(network_frame, columns=n_cols, show="headings", height=20)
        for col, width in [("severity", 90), ("proto", 70), ("local", 210), ("remote", 210), ("geo", 250), ("status", 120), ("pid", 80), ("process", 180)]:
            self.network_table.heading(col, text=col.upper())
            self.network_table.column(col, width=width, anchor="w")
        self.network_table.pack(fill="both", expand=True)

        self.build_alerts_tab()

        bottom = ttk.Frame(outer)
        bottom.pack(fill="x", pady=(8, 0))
        ttk.Label(bottom, textvariable=self.status).pack(side="left")

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def build_dashboard_tab(self):
        container = ttk.Frame(self.dashboard_tab, padding=8)
        container.pack(fill="both", expand=True)
        self.dashboard_cards = ttk.Frame(container)
        self.dashboard_cards.pack(fill="x", pady=(0, 8))

        self.card_vars = {
            "cpu": tk.StringVar(value="CPU\n--"),
            "memory": tk.StringVar(value="Memory\n--"),
            "failed": tk.StringVar(value="Failed Logins\n--"),
            "network": tk.StringVar(value="Network Severity\n--"),
        }
        for key in ["cpu", "memory", "failed", "network"]:
            card = ttk.LabelFrame(self.dashboard_cards, text=key.upper(), padding=12)
            card.pack(side="left", fill="both", expand=True, padx=4)
            ttk.Label(card, textvariable=self.card_vars[key], justify="center", font=("Arial", 12, "bold")).pack(fill="both", expand=True)

        if MATPLOTLIB_AVAILABLE:
            self.figure = Figure(figsize=(11, 5), dpi=100)
            self.ax1 = self.figure.add_subplot(121)
            self.ax2 = self.figure.add_subplot(122)
            self.chart_canvas = FigureCanvasTkAgg(self.figure, master=container)
            self.chart_canvas.get_tk_widget().pack(fill="both", expand=True)
        else:
            self.chart_fallback = ScrolledText(container, wrap="word", height=20)
            self.chart_fallback.pack(fill="both", expand=True)
            self.chart_fallback.insert("1.0", "Install matplotlib to see live visual dashboards.\nThis area will summarize CPU, memory, and network trends in text form.")
            self.chart_fallback.configure(state="disabled")

    def build_alerts_tab(self):
        frame = ttk.Frame(self.alerts_tab, padding=10)
        frame.pack(fill="both", expand=True)

        left = ttk.LabelFrame(frame, text="Email settings", padding=10)
        left.pack(side="left", fill="both", expand=True, padx=(0, 8))

        self.email_enabled_var = tk.BooleanVar(value=bool(self.config.get("email_enabled", False)))
        self.use_tls_var = tk.BooleanVar(value=bool(self.config.get("use_tls", True)))
        self.attach_files_var = tk.BooleanVar(value=bool(self.config.get("attach_report_files", True)))
        self.smtp_server_var = tk.StringVar(value=str(self.config.get("smtp_server", "smtp.gmail.com")))
        self.smtp_port_var = tk.StringVar(value=str(self.config.get("smtp_port", 587)))
        self.smtp_username_var = tk.StringVar(value=str(self.config.get("smtp_username", "")))
        self.smtp_password_var = tk.StringVar(value=str(self.config.get("smtp_password", "")))
        self.sender_email_var = tk.StringVar(value=str(self.config.get("sender_email", "")))
        self.recipient_emails_var = tk.StringVar(value=str(self.config.get("recipient_emails", "")))
        self.attachment_paths_var = tk.StringVar(value=str(self.config.get("attachment_log_paths", "")))

        self.cpu_process_names_var = tk.StringVar(value=str(self.config.get("cpu_process_names", "")))
        self.cpu_threshold_var = tk.StringVar(value=str(self.config.get("cpu_threshold", 40.0)))
        self.memory_threshold_var = tk.StringVar(value=str(self.config.get("memory_threshold_mb", 500.0)))
        self.storage_threshold_var = tk.StringVar(value=str(self.config.get("storage_threshold_gb", 5.0)))
        self.failed_login_threshold_var = tk.StringVar(value=str(self.config.get("failed_login_threshold", 5)))
        self.network_threshold_var = tk.StringVar(value=str(self.config.get("network_bytes_per_sec_threshold", 5000000)))
        self.suspicious_ports_var = tk.StringVar(value=str(self.config.get("suspicious_ports", "")))
        self.cooldown_var = tk.StringVar(value=str(self.config.get("cooldown_minutes", 20)))

        fields = [
            ("SMTP server", self.smtp_server_var, False),
            ("SMTP port", self.smtp_port_var, False),
            ("SMTP username", self.smtp_username_var, False),
            ("SMTP password", self.smtp_password_var, True),
            ("Sender email", self.sender_email_var, False),
            ("Recipient emails (comma separated)", self.recipient_emails_var, False),
            ("Attach file paths (comma separated)", self.attachment_paths_var, False),
        ]
        ttk.Checkbutton(left, text="Enable automatic email alerts", variable=self.email_enabled_var).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        for idx, (label, var, masked) in enumerate(fields, start=1):
            ttk.Label(left, text=label).grid(row=idx, column=0, sticky="w", pady=4)
            ttk.Entry(left, textvariable=var, width=42, show="*" if masked else "").grid(row=idx, column=1, sticky="ew", pady=4)
        ttk.Checkbutton(left, text="Use STARTTLS", variable=self.use_tls_var).grid(row=len(fields)+1, column=0, columnspan=2, sticky="w", pady=(8, 4))
        ttk.Checkbutton(left, text="Attach generated report files", variable=self.attach_files_var).grid(row=len(fields)+2, column=0, columnspan=2, sticky="w", pady=(0, 8))
        ttk.Button(left, text="Save settings", command=self.save_settings_from_form).grid(row=len(fields)+3, column=0, pady=(8, 0), sticky="w")
        ttk.Button(left, text="Send test email", command=self.send_test_email).grid(row=len(fields)+3, column=1, pady=(8, 0), sticky="e")
        left.columnconfigure(1, weight=1)

        right = ttk.LabelFrame(frame, text="Admin thresholds", padding=10)
        right.pack(side="left", fill="both", expand=True)
        threshold_fields = [
            ("Watch process names (comma separated)", self.cpu_process_names_var),
            ("CPU threshold %", self.cpu_threshold_var),
            ("Memory threshold MB", self.memory_threshold_var),
            ("Folder size threshold GB", self.storage_threshold_var),
            ("Failed login threshold", self.failed_login_threshold_var),
            ("Network bytes/sec threshold", self.network_threshold_var),
            ("Suspicious ports (comma separated)", self.suspicious_ports_var),
            ("Alert cooldown minutes", self.cooldown_var),
        ]
        for idx, (label, var) in enumerate(threshold_fields):
            ttk.Label(right, text=label).grid(row=idx, column=0, sticky="w", pady=5)
            ttk.Entry(right, textvariable=var, width=40).grid(row=idx, column=1, sticky="ew", pady=5)
        help_text = (
            "Admin chooses process, storage, login, and network thresholds.\n"
            "Severity is LOW, MEDIUM, or HIGH based on how far a metric exceeds its threshold.\n"
            "Live dashboard shows CPU, memory, and network trends plus risky connections."
        )
        ttk.Label(right, text=help_text, justify="left").grid(row=len(threshold_fields), column=0, columnspan=2, sticky="w", pady=(12, 0))
        right.columnconfigure(1, weight=1)

    def default_scan_path(self) -> str:
        return str(Path.home())

    def choose_folder(self):
        chosen = filedialog.askdirectory(initialdir=self.selected_path.get() or self.default_scan_path())
        if chosen:
            self.selected_path.set(chosen)
            self.refresh_all()

    def save_settings_from_form(self):
        self.config["email_enabled"] = bool(self.email_enabled_var.get())
        self.config["use_tls"] = bool(self.use_tls_var.get())
        self.config["attach_report_files"] = bool(self.attach_files_var.get())
        self.config["smtp_server"] = self.smtp_server_var.get().strip()
        self.config["smtp_port"] = int(self.smtp_port_var.get().strip() or "587")
        self.config["smtp_username"] = self.smtp_username_var.get().strip()
        self.config["smtp_password"] = self.smtp_password_var.get()
        self.config["sender_email"] = self.sender_email_var.get().strip()
        self.config["recipient_emails"] = self.recipient_emails_var.get().strip()
        self.config["attachment_log_paths"] = self.attachment_paths_var.get().strip()
        self.config["cpu_process_names"] = self.cpu_process_names_var.get().strip()
        self.config["cpu_threshold"] = float(self.cpu_threshold_var.get().strip() or "40")
        self.config["memory_threshold_mb"] = float(self.memory_threshold_var.get().strip() or "500")
        self.config["storage_threshold_gb"] = float(self.storage_threshold_var.get().strip() or "5")
        self.config["failed_login_threshold"] = int(self.failed_login_threshold_var.get().strip() or "5")
        self.config["network_bytes_per_sec_threshold"] = int(float(self.network_threshold_var.get().strip() or "5000000"))
        self.config["suspicious_ports"] = self.suspicious_ports_var.get().strip()
        self.config["cooldown_minutes"] = int(self.cooldown_var.get().strip() or "20")
        self.save_config()

    def toggle_auto_refresh(self):
        if self.auto_refresh.get():
            self.schedule_refresh()
        elif self.refresh_job is not None:
            self.root.after_cancel(self.refresh_job)
            self.refresh_job = None

    def schedule_refresh(self):
        if not self.auto_refresh.get():
            return
        if self.refresh_job is not None:
            self.root.after_cancel(self.refresh_job)
        self.refresh_job = self.root.after(REFRESH_MS, self.refresh_all)

    def refresh_all(self):
        if self.worker and self.worker.is_alive():
            self.schedule_refresh()
            return
        self.status.set("Refreshing system data...")
        self.worker = threading.Thread(target=self.collect_data, daemon=True)
        self.worker.start()
        self.root.after(150, self.check_queue)

    def collect_data(self):
        try:
            logs = self.fetch_system_logs()
            events = self.fetch_security_events()
            processes = self.fetch_processes()
            storage = self.fetch_storage_usage(self.selected_path.get())
            network_rows, sent_rate, recv_rate, net_severity = self.fetch_network_activity()
            failed_logins = self.count_failed_logins(events)
            payload = {
                "summary": self.build_summary(failed_logins, sent_rate, recv_rate, net_severity),
                "logs": logs,
                "events": events,
                "cpu": processes,
                "storage": storage,
                "network": network_rows,
                "net_sent_rate": sent_rate,
                "net_recv_rate": recv_rate,
                "net_severity": net_severity,
                "failed_logins": failed_logins,
            }
            self.queue.put(("ok", payload))
        except Exception as exc:
            self.queue.put(("error", str(exc)))

    def check_queue(self):
        try:
            state, payload = self.queue.get_nowait()
        except queue.Empty:
            self.root.after(150, self.check_queue)
            return

        if state == "error":
            self.status.set(f"Failed: {payload}")
            messagebox.showerror(APP_TITLE, payload)
            self.schedule_refresh()
            return

        self.last_logs = payload["logs"]
        self.last_events = payload["events"]
        self.last_cpu_rows = payload["cpu"]
        self.last_storage_rows = payload["storage"]
        self.last_network_rows = payload["network"]
        self.last_failed_login_count = payload["failed_logins"]
        self.current_net_severity = payload["net_severity"]
        self.summary_label.config(text=payload["summary"])
        self.apply_filters()
        self.populate_cpu(payload["cpu"])
        self.populate_storage(payload["storage"])
        self.populate_network(payload["network"], payload["net_sent_rate"], payload["net_recv_rate"])
        self.update_dashboard(payload)
        self.check_and_send_alerts(payload["cpu"], payload["storage"], payload["network"], payload["failed_logins"], payload["net_sent_rate"], payload["net_recv_rate"], payload["net_severity"])
        self.status.set(f"Updated at {time.strftime('%Y-%m-%d %H:%M:%S')} | Path: {self.selected_path.get()}")
        self.schedule_refresh()

    def apply_filters(self):
        term = self.filter_text.get().strip().lower()
        logs = self.last_logs
        events = self.last_events
        if term:
            logs = "".join(line for line in self.last_logs.splitlines() if term in line.lower())
            events = "".join(line for line in self.last_events.splitlines() if term in line.lower())
        self.set_text(self.logs_text, logs)
        self.populate_events_table(events)

    def classify_event(self, details: str, event_id: str = ""):
        text = f"{event_id} {details}".lower()
        if any(k in text for k in ["4625", "failed password", "authentication failure", "invalid user", "failed login"]):
            return "FAILED LOGIN", "HIGH"
        if any(k in text for k in ["shutdown", "power off"]):
            return "SHUTDOWN", "MEDIUM"
        if any(k in text for k in ["restart", "reboot", "1074", "6006", "6008"]):
            return "RESTART", "MEDIUM"
        if any(k in text for k in ["4624", "login", "logon", "session opened", "accepted password"]):
            return "LOGIN", "LOW"
        return "OTHER", "LOW"

    def extract_user_from_text(self, details: str) -> str:
        patterns = [
            r"user\s+([^\s,;]+)",
            r"for user\s+'?([^\s,;']+)",
            r"on behalf of user\s+([^\s,;]+)",
            r"account name:\s*([^\s,;]+)",
        ]
        for pattern in patterns:
            match = re.search(pattern, details, flags=re.IGNORECASE)
            if match:
                return match.group(1)
        if "nt authority\\system" in details.lower():
            return "NT AUTHORITY\\SYSTEM"
        return "system"

    def parse_windows_event_records(self, text: str):
        records = []
        current = {}
        message_lines = []
        capture_message = False

        for raw_line in text.splitlines():
            line = raw_line.rstrip()
            stripped = line.strip()

            if stripped.startswith("====="):
                continue

            if stripped.startswith("TimeCreated"):
                if current:
                    current["Message"] = " ".join(message_lines).strip() or current.get("Message", "")
                    records.append(current)
                    current = {}
                    message_lines = []
                    capture_message = False
                current["TimeCreated"] = stripped.split(":", 1)[1].strip() if ":" in stripped else stripped
                continue

            if not stripped:
                if current and (message_lines or current.get("Message")):
                    current["Message"] = " ".join(message_lines).strip() or current.get("Message", "")
                    records.append(current)
                    current = {}
                    message_lines = []
                    capture_message = False
                continue

            if ":" in stripped and not capture_message:
                key, value = stripped.split(":", 1)
                key = key.strip()
                value = value.strip()
                current[key] = value
                capture_message = (key == "Message")
                if capture_message and value:
                    message_lines.append(value)
            elif capture_message:
                message_lines.append(stripped)

        if current:
            current["Message"] = " ".join(message_lines).strip() or current.get("Message", "")
            records.append(current)

        return records

    def parse_events_for_table(self, text: str):
        rows = []
        if self.platform == "windows" and "TimeCreated" in text:
            for record in self.parse_windows_event_records(text):
                details = record.get("Message") or record.get("ProviderName") or "Event"
                event_type, severity = self.classify_event(details, str(record.get("Id", "")))
                rows.append((
                    record.get("TimeCreated", "-"),
                    event_type,
                    details,
                    self.extract_user_from_text(details),
                    severity,
                ))
            return rows

        current_section = ""
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("====="):
                current_section = line.strip("= ").upper()
                continue

            time_value = "-"
            details = line

            match = re.match(r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})(.*)$", line)
            if match:
                time_value = match.group(1)
                details = match.group(2).strip(" -") or line
            elif re.match(r"^[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}", line):
                time_value = "System Event"

            event_type, severity = self.classify_event(f"{current_section} {details}")
            if current_section and event_type == "OTHER":
                event_type = current_section.replace("RECENT ", "")
            rows.append((time_value, event_type, details, self.extract_user_from_text(details), severity))

        return rows

    def populate_events_table(self, text: str):
        for item in self.events_table.get_children():
            self.events_table.delete(item)

        rows = self.parse_events_for_table(text)
        if not rows:
            self.events_table.insert("", tk.END, values=("-", "OTHER", "No matching events found.", "-"), tags=("LOW",))
            return

        for time_value, event_type, details, user, severity in rows:
            self.events_table.insert("", tk.END, values=(time_value, event_type, details, user), tags=(severity,))

    def set_text(self, widget: ScrolledText, text: str):
        if len(text) > MAX_TEXT:
            text = text[-MAX_TEXT:]
        widget.configure(state="normal")
        widget.delete("1.0", tk.END)
        widget.insert(tk.END, text)
        widget.configure(state="disabled")
        widget.see(tk.END)

    def populate_cpu(self, rows):
        for item in self.cpu_table.get_children():
            self.cpu_table.delete(item)
        for row in rows:
            self.cpu_table.insert("", tk.END, values=(row["severity"], row["pid"], row["name"], f"{row['cpu']:.1f}%", self.human_size(row["memory"]), row["user"]))

    def populate_storage(self, rows):
        for item in self.storage_table.get_children():
            self.storage_table.delete(item)
        for row in rows:
            self.storage_table.insert("", tk.END, values=(row["severity"], row["folder"], self.human_size(row["size"]), row["files"]))

    def populate_network(self, rows, sent_rate, recv_rate):
        for item in self.network_table.get_children():
            self.network_table.delete(item)
        for row in rows:
            self.network_table.insert("", tk.END, values=(row["severity"], row["proto"], row["local"], row["remote"], row.get("geo", "-"), row["status"], row["pid"], row["process"]))
        self.network_rate_label.config(text=f"Traffic rates: upload {self.human_size(int(sent_rate))}/s | download {self.human_size(int(recv_rate))}/s")
        self.geo_label.config(text=self.geo_status)

    def update_dashboard(self, payload):
        cpu_now = 0.0
        mem_now = 0.0
        if psutil is not None:
            try:
                cpu_now = psutil.cpu_percent(interval=0.1)
                mem_now = psutil.virtual_memory().percent
            except Exception:
                pass
        self.cpu_history.append(cpu_now)
        self.mem_history.append(mem_now)
        self.net_sent_history.append(payload["net_sent_rate"])
        self.net_recv_history.append(payload["net_recv_rate"])

        self.card_vars["cpu"].set(f"CPU\n{cpu_now:.1f}%")
        self.card_vars["memory"].set(f"Memory\n{mem_now:.1f}%")
        self.card_vars["failed"].set(f"Failed Logins\n{payload['failed_logins']}")
        self.card_vars["network"].set(f"Network Severity\n{payload['net_severity']}")

        if MATPLOTLIB_AVAILABLE:
            self.ax1.clear()
            self.ax2.clear()
            self.ax1.plot(list(self.cpu_history), label="CPU %")
            self.ax1.plot(list(self.mem_history), label="Memory %")
            self.ax1.set_title("CPU / Memory Trend")
            self.ax1.legend()
            self.ax1.set_ylim(bottom=0)
            self.ax2.plot(list(self.net_sent_history), label="Upload B/s")
            self.ax2.plot(list(self.net_recv_history), label="Download B/s")
            self.ax2.set_title("Network Throughput Trend")
            self.ax2.legend()
            self.ax2.set_ylim(bottom=0)
            self.figure.tight_layout()
            self.chart_canvas.draw()
        else:
            summary = (
                f"CPU history: {list(self.cpu_history)}\n\n"
                f"Memory history: {list(self.mem_history)}\n\n"
                f"Upload B/s history: {list(self.net_sent_history)}\n\n"
                f"Download B/s history: {list(self.net_recv_history)}"
            )
            self.chart_fallback.configure(state="normal")
            self.chart_fallback.delete("1.0", tk.END)
            self.chart_fallback.insert("1.0", summary)
            self.chart_fallback.configure(state="disabled")

    def run_command(self, command):
        result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
        if result.returncode != 0:
            err = result.stderr.strip() or result.stdout.strip() or "Command failed"
            raise RuntimeError(err)
        return result.stdout.strip()

    def build_summary(self, failed_logins: int, sent_rate: float, recv_rate: float, net_severity: str) -> str:
        hostname = os.environ.get("COMPUTERNAME") or os.environ.get("HOSTNAME") or "unknown-host"
        scan_target = self.selected_path.get()
        if not os.path.exists(scan_target):
            scan_target = str(Path.home())
        total, used, free = shutil.disk_usage(scan_target)
        summary = [
            f"Host: {hostname}",
            f"Platform: {self.platform}",
            f"Scan path: {scan_target}",
            f"Disk used: {self.human_size(used)} / {self.human_size(total)} | Free: {self.human_size(free)}",
            f"Failed logins observed in current event window: {failed_logins}",
            f"Network upload rate: {self.human_size(int(sent_rate))}/s | download rate: {self.human_size(int(recv_rate))}/s | network severity: {net_severity}",
        ]
        if psutil is not None:
            try:
                cpu = psutil.cpu_percent(interval=0.2)
                mem = psutil.virtual_memory()
                boot_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(psutil.boot_time()))
                summary.append(f"CPU load: {cpu:.1f}% | Memory used: {mem.percent:.1f}%")
                summary.append(f"Boot time: {boot_time}")
            except Exception:
                pass
        else:
            summary.append("Install psutil for richer CPU, memory, process, and network monitoring.")
        return "\n".join(summary)

    def fetch_system_logs(self) -> str:
        if self.platform == "linux":
            candidates = [
                ["journalctl", "-n", str(LOG_LINES), "--no-pager", "-o", "short-iso"],
                ["sh", "-c", f"tail -n {LOG_LINES} /var/log/syslog"],
                ["sh", "-c", f"tail -n {LOG_LINES} /var/log/messages"],
            ]
        elif self.platform == "macos":
            candidates = [["log", "show", "--style", "syslog", "--last", "20m"]]
        else:
            ps = (
                "Get-WinEvent -LogName System -MaxEvents 300 | "
                "Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message | Format-List"
            )
            candidates = [["powershell", "-NoProfile", "-Command", ps]]
        errors = []
        for cmd in candidates:
            try:
                return self.run_command(cmd)
            except Exception as exc:
                errors.append(str(exc))
        return "Unable to fetch system logs.\n" + "\n".join(errors)

    def fetch_security_events(self) -> str:
        if self.platform == "linux":
            parts = []
            try:
                cmd = ["journalctl", "-n", "160", "--no-pager", "-u", "systemd-logind", "-o", "short-iso"]
                parts.append("===== Recent login events =====\n" + self.run_command(cmd))
            except Exception as exc:
                parts.append(f"===== Recent login events =====\nUnavailable: {exc}")
            try:
                cmd = ["sh", "-c", "grep -iE 'session opened|session closed|failed password|accepted password|authentication failure|invalid user' /var/log/auth.log | tail -n 160"]
                parts.append("===== Authentication events =====\n" + self.run_command(cmd))
            except Exception as exc:
                parts.append(f"===== Authentication events =====\nUnavailable: {exc}")
            try:
                boot = self.run_command(["journalctl", "-n", "220", "--no-pager", "-o", "short-iso"])
                filtered = [line for line in boot.splitlines() if any(k in line.lower() for k in ["shutdown", "reboot", "starting", "stopping", "power off"])]
                parts.append("===== Shutdown and boot =====\n" + "\n".join(filtered[-140:]))
            except Exception as exc:
                parts.append(f"===== Shutdown and boot =====\nUnavailable: {exc}")
            return "\n\n".join(parts)
        if self.platform == "macos":
            parts = []
            try:
                login_cmd = ["log", "show", "--style", "syslog", "--last", "1d", "--predicate", 'eventMessage CONTAINS[c] "login" OR process == "loginwindow"']
                parts.append("===== Login-related events =====\n" + self.run_command(login_cmd))
            except Exception as exc:
                parts.append(f"===== Login-related events =====\nUnavailable: {exc}")
            try:
                power_cmd = ["log", "show", "--style", "syslog", "--last", "1d", "--predicate", 'eventMessage CONTAINS[c] "shutdown" OR eventMessage CONTAINS[c] "restart"']
                parts.append("===== Shutdown / restart =====\n" + self.run_command(power_cmd))
            except Exception as exc:
                parts.append(f"===== Shutdown / restart =====\nUnavailable: {exc}")
            return "\n\n".join(parts)
        login_ps = (
            "$a = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625} -MaxEvents 120 -ErrorAction SilentlyContinue;"
            "$b = Get-WinEvent -FilterHashtable @{LogName='System'; Id=1074,6005,6006,6008} -MaxEvents 120 -ErrorAction SilentlyContinue;"
            "$a | Select-Object TimeCreated,Id,ProviderName,Message | Format-List;"
            "'===== Shutdown / startup =====';"
            "$b | Select-Object TimeCreated,Id,ProviderName,Message | Format-List"
        )
        try:
            return self.run_command(["powershell", "-NoProfile", "-Command", login_ps])
        except Exception as exc:
            return f"Unable to fetch security events: {exc}"

    def count_failed_logins(self, events_text: str) -> int:
        patterns = [r"failed password", r"authentication failure", r"4625", r"invalid user", r"failure"]
        count = 0
        lower = events_text.lower()
        for pattern in patterns:
            count += len(re.findall(pattern, lower))
        return count

    def severity_from_ratio(self, ratio: float) -> str:
        if ratio >= 1.5:
            return "HIGH"
        if ratio >= 1.0:
            return "MEDIUM"
        return "LOW"

    def fetch_processes(self):
        cpu_limit = float(self.config.get("cpu_threshold", 40.0))
        mem_limit_bytes = float(self.config.get("memory_threshold_mb", 500.0)) * 1024 * 1024
        watched_names = [x.strip().lower() for x in str(self.config.get("cpu_process_names", "")).split(",") if x.strip()]
        if psutil is None:
            return [{"severity": "LOW", "pid": "-", "name": "Install psutil for detailed process monitoring", "cpu": 0.0, "memory": 0, "user": "-", "watched": False}]
        try:
            for proc in psutil.process_iter(["pid", "name", "username", "memory_info"]):
                try:
                    proc.cpu_percent(None)
                except Exception:
                    continue
            time.sleep(0.2)
            items = []
            for proc in psutil.process_iter(["pid", "name", "username", "memory_info"]):
                try:
                    cpu = float(proc.cpu_percent(None))
                    mem = int(proc.info["memory_info"].rss) if proc.info.get("memory_info") else 0
                    name = proc.info.get("name") or "unknown"
                    watched = (not watched_names) or (name.lower() in watched_names)
                    ratio = max(cpu / max(cpu_limit, 0.1), mem / max(mem_limit_bytes, 1)) if watched else 0.0
                    items.append({
                        "severity": self.severity_from_ratio(ratio),
                        "pid": proc.info.get("pid"),
                        "name": name,
                        "cpu": cpu,
                        "memory": mem,
                        "user": proc.info.get("username") or "unknown",
                        "watched": watched,
                    })
                except Exception:
                    continue
            items.sort(key=lambda x: (0 if x["severity"] == "HIGH" else 1 if x["severity"] == "MEDIUM" else 2, -x["cpu"]))
            return items[:TOP_N]
        except Exception as exc:
            return [{"severity": "LOW", "pid": "-", "name": f"Process read error: {exc}", "cpu": 0.0, "memory": 0, "user": "-", "watched": False}]

    def fetch_storage_usage(self, path: str):
        base = Path(path)
        threshold_bytes = float(self.config.get("storage_threshold_gb", 5.0)) * 1024 * 1024 * 1024
        if not base.exists():
            return [{"severity": "LOW", "folder": "Invalid path", "size": 0, "files": 0}]
        try:
            candidates = [entry for entry in base.iterdir() if entry.is_dir()]
        except Exception as exc:
            return [{"severity": "LOW", "folder": f"Cannot list path: {exc}", "size": 0, "files": 0}]
        rows = []
        for folder in candidates:
            total = 0
            files = 0
            try:
                for root_dir, _, filenames in os.walk(folder, onerror=lambda e: None):
                    for filename in filenames:
                        fp = os.path.join(root_dir, filename)
                        try:
                            total += os.path.getsize(fp)
                            files += 1
                        except Exception:
                            continue
            except Exception:
                continue
            ratio = total / max(threshold_bytes, 1)
            rows.append({"severity": self.severity_from_ratio(ratio), "folder": str(folder), "size": total, "files": files})
        rows.sort(key=lambda x: (0 if x["severity"] == "HIGH" else 1 if x["severity"] == "MEDIUM" else 2, -x["size"]))
        return rows[:TOP_N]

    def is_private_ip(self, ip_text: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip_text)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved
        except Exception:
            return True

    def lookup_ip_info(self, ip_text):
        if not ip_text:
            return "-"
        if self.is_private_ip(ip_text):
            return "Private/Local"
        if ip_text in self.geo_cache:
            return self.geo_cache[ip_text]
        info = "Lookup unavailable"
        try:
            req = Request(
                f"http://ip-api.com/json/{ip_text}?fields=status,country,regionName,city,isp,query",
                headers={"User-Agent": "CyberMonitor/1.0"},
            )
            with urlopen(req, timeout=2.5) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
            if data.get("status") == "success":
                parts = [data.get("country"), data.get("regionName"), data.get("city"), data.get("isp")]
                info = " / ".join([p for p in parts if p]) or ip_text
        except (URLError, HTTPError, TimeoutError, ValueError, json.JSONDecodeError):
            info = "Lookup unavailable"
        self.geo_cache[ip_text] = info
        if len(self.geo_cache) > GEO_CACHE_LIMIT:
            first_key = next(iter(self.geo_cache))
            self.geo_cache.pop(first_key, None)
        return info

    def fetch_network_activity(self):
        if psutil is None:
            return ([{"severity": "LOW", "proto": "-", "local": "Install psutil", "remote": "-", "geo": "-", "status": "-", "pid": "-", "process": "-"}], 0.0, 0.0, "LOW")

        suspicious_ports = {int(p.strip()) for p in str(self.config.get("suspicious_ports", "")).split(",") if p.strip().isdigit()}
        threshold = float(self.config.get("network_bytes_per_sec_threshold", 5000000))
        now = time.time()
        sent_rate = 0.0
        recv_rate = 0.0
        counters = psutil.net_io_counters()
        if self.last_net_counters is not None and self.last_net_time is not None:
            elapsed = max(now - self.last_net_time, 0.1)
            sent_rate = max((counters.bytes_sent - self.last_net_counters.bytes_sent) / elapsed, 0.0)
            recv_rate = max((counters.bytes_recv - self.last_net_counters.bytes_recv) / elapsed, 0.0)
        self.last_net_counters = counters
        self.last_net_time = now

        rows = []
        high_found = False
        looked_up = 0
        try:
            for conn in psutil.net_connections(kind="inet"):
                local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "-"
                remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "-"
                remote_ip = conn.raddr.ip if conn.raddr else None
                proto = "TCP" if conn.type == 1 else "UDP"
                status = conn.status or "-"
                pid = conn.pid or "-"
                process = "unknown"
                try:
                    if conn.pid:
                        process = psutil.Process(conn.pid).name()
                except Exception:
                    pass
                ratio = max(sent_rate / max(threshold, 1.0), recv_rate / max(threshold, 1.0))
                severity = self.severity_from_ratio(ratio)
                port_flag = False
                if conn.laddr and conn.laddr.port in suspicious_ports:
                    port_flag = True
                if conn.raddr and conn.raddr.port in suspicious_ports:
                    port_flag = True
                geo = self.lookup_ip_info(remote_ip)
                if remote_ip and geo not in ("Private/Local", "Lookup unavailable", "-"):
                    looked_up += 1
                if port_flag:
                    severity = "HIGH"
                if remote_ip and self.is_private_ip(remote_ip):
                    geo = "Private/Local"
                if severity == "HIGH":
                    high_found = True
                rows.append({
                    "severity": severity,
                    "proto": proto,
                    "local": local,
                    "remote": remote,
                    "geo": geo,
                    "status": status,
                    "pid": pid,
                    "process": process,
                })
        except Exception as exc:
            rows.append({"severity": "LOW", "proto": "-", "local": f"Network read error: {exc}", "remote": "-", "geo": "-", "status": "-", "pid": "-", "process": "-"})

        self.geo_status = f"Geo/IP lookup: {looked_up} public remote address(es) enriched"
        rows.sort(key=lambda x: (0 if x["severity"] == "HIGH" else 1 if x["severity"] == "MEDIUM" else 2, str(x["process"])))
        net_severity = "HIGH" if high_found else self.severity_from_ratio(max(sent_rate, recv_rate) / max(threshold, 1.0))
        return rows[:TOP_N], sent_rate, recv_rate, net_severity

    def check_and_send_alerts(self, processes, storage_rows, network_rows, failed_logins, sent_rate, recv_rate, net_severity):
        if not self.config.get("email_enabled"):
            return
        watched_names = [x.strip().lower() for x in str(self.config.get("cpu_process_names", "")).split(",") if x.strip()]
        cpu_limit = float(self.config.get("cpu_threshold", 40.0))
        mem_limit_bytes = float(self.config.get("memory_threshold_mb", 500.0)) * 1024 * 1024
        storage_limit_bytes = float(self.config.get("storage_threshold_gb", 5.0)) * 1024 * 1024 * 1024
        failed_limit = int(self.config.get("failed_login_threshold", 5))
        network_limit = float(self.config.get("network_bytes_per_sec_threshold", 5000000))
        findings = []

        for proc in processes:
            name = str(proc.get("name", ""))
            lowered = name.lower()
            watch_match = (not watched_names) or lowered in watched_names
            if watch_match and (float(proc.get("cpu", 0.0)) >= cpu_limit or int(proc.get("memory", 0)) >= mem_limit_bytes):
                findings.append(f"[{proc.get('severity','MEDIUM')}] Process alert: {name} (PID {proc.get('pid')}) CPU {float(proc.get('cpu', 0.0)):.1f}% | Memory {self.human_size(int(proc.get('memory', 0)))} | User {proc.get('user')}")

        for row in storage_rows:
            if int(row.get("size", 0)) >= storage_limit_bytes:
                findings.append(f"[{row.get('severity','MEDIUM')}] Storage alert: {row.get('folder')} size {self.human_size(int(row.get('size', 0)))} with {row.get('files')} files")

        if failed_logins >= failed_limit:
            severity = self.severity_from_ratio(failed_logins / max(failed_limit, 1))
            findings.append(f"[{severity}] Failed login alert: observed {failed_logins} failed login indicators in the current event window")

        if max(sent_rate, recv_rate) >= network_limit:
            findings.append(f"[{net_severity}] Network traffic alert: upload {self.human_size(int(sent_rate))}/s | download {self.human_size(int(recv_rate))}/s")
        for row in network_rows:
            if row.get("severity") == "HIGH":
                findings.append(f"[HIGH] Suspicious connection: {row.get('proto')} {row.get('local')} -> {row.get('remote')} | {row.get('geo','-')} | {row.get('status')} | PID {row.get('pid')} | {row.get('process')}")

        if not findings:
            return

        key = "|".join(findings)
        now = time.time()
        cooldown_seconds = int(self.config.get("cooldown_minutes", 20)) * 60
        last_alerts = self.config.setdefault("last_alerts", {})
        last_sent = float(last_alerts.get(key, 0))
        if now - last_sent < cooldown_seconds:
            return

        subject = f"Cyber Monitor Alert - {os.environ.get('COMPUTERNAME') or os.environ.get('HOSTNAME') or 'host'}"
        body = self.build_alert_email_body(findings, sent_rate, recv_rate, net_severity)
        attachments = self.generate_report_attachments() if self.config.get("attach_report_files") else []
        self.send_email(subject, body, attachments)
        last_alerts[key] = now
        self.save_config()

    def build_alert_email_body(self, findings, sent_rate=0.0, recv_rate=0.0, net_severity="LOW"):
        lines = [
            "Automatic alert from Cyber Monitor",
            "",
            f"Host: {os.environ.get('COMPUTERNAME') or os.environ.get('HOSTNAME') or 'unknown-host'}",
            f"Platform: {self.platform}",
            f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Monitored path: {self.selected_path.get()}",
            f"Failed logins in window: {self.last_failed_login_count}",
            f"Network upload rate: {self.human_size(int(sent_rate))}/s | download rate: {self.human_size(int(recv_rate))}/s | network severity: {net_severity}",
            "",
            "Triggered conditions:",
        ]
        lines.extend(f"- {item}" for item in findings)
        lines.extend([
            "",
            "Recent login/shutdown events:",
            self.last_events[:5000] if self.last_events else "No cached event text yet.",
            "",
            "Recent system logs:",
            self.last_logs[:5000] if self.last_logs else "No cached log text yet.",
        ])
        return "\n".join(lines)

    def parse_recipients(self):
        recipients = [x.strip() for x in str(self.config.get("recipient_emails", "")).split(",") if x.strip()]
        if not recipients:
            raise ValueError("At least one recipient email is required.")
        return recipients

    def send_test_email(self):
        try:
            self.save_settings_from_form()
            subject = "Cyber Monitor Test Email"
            body = self.build_alert_email_body(["Test message from admin"], 0.0, 0.0, "LOW")
            attachments = self.generate_report_attachments() if self.config.get("attach_report_files") else []
            self.send_email(subject, body, attachments)
            messagebox.showinfo(APP_TITLE, "Test email sent successfully.")
        except Exception as exc:
            messagebox.showerror(APP_TITLE, f"Test email failed: {exc}")

    def email_current_report(self):
        try:
            self.save_settings_from_form()
            subject = f"Cyber Monitor Manual Report - {os.environ.get('COMPUTERNAME') or os.environ.get('HOSTNAME') or 'host'}"
            body = self.build_alert_email_body(
                ["Manual report requested by admin"],
                self.net_sent_history[-1] if self.net_sent_history else 0.0,
                self.net_recv_history[-1] if self.net_recv_history else 0.0,
                self.current_net_severity,
            )
            attachments = self.generate_report_attachments() if self.config.get("attach_report_files") else []
            self.send_email(subject, body, attachments)
            messagebox.showinfo(APP_TITLE, "Current report emailed successfully.")
        except Exception as exc:
            messagebox.showerror(APP_TITLE, f"Could not email current report: {exc}")

    def generate_report_attachments(self):
        attachments = []
        temp_dir = Path(tempfile.gettempdir()) / "cyber_monitor_reports"
        temp_dir.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d_%H%M%S")

        summary_path = temp_dir / f"cyber_monitor_summary_{stamp}.txt"
        summary_text = self.summary_label.cget("text") + "\n\n" + self.build_alert_email_body(["Attached report bundle"])
        summary_path.write_text(summary_text, encoding="utf-8", errors="replace")
        attachments.append(summary_path)

        cpu_csv = temp_dir / f"cyber_monitor_processes_{stamp}.csv"
        with cpu_csv.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["severity", "pid", "name", "cpu_percent", "memory_bytes", "user"])
            for row in self.last_cpu_rows:
                writer.writerow([row.get("severity"), row.get("pid"), row.get("name"), row.get("cpu"), row.get("memory"), row.get("user")])
        attachments.append(cpu_csv)

        storage_csv = temp_dir / f"cyber_monitor_storage_{stamp}.csv"
        with storage_csv.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["severity", "folder", "size_bytes", "files"])
            for row in self.last_storage_rows:
                writer.writerow([row.get("severity"), row.get("folder"), row.get("size"), row.get("files")])
        attachments.append(storage_csv)

        network_csv = temp_dir / f"cyber_monitor_network_{stamp}.csv"
        with network_csv.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["severity", "proto", "local", "remote", "geo", "status", "pid", "process"])
            for row in self.last_network_rows:
                writer.writerow([row.get("severity"), row.get("proto"), row.get("local"), row.get("remote"), row.get("geo"), row.get("status"), row.get("pid"), row.get("process")])
        attachments.append(network_csv)

        logs_txt = temp_dir / f"cyber_monitor_logs_{stamp}.txt"
        logs_txt.write_text(self.last_logs or "No logs captured.", encoding="utf-8", errors="replace")
        attachments.append(logs_txt)

        events_txt = temp_dir / f"cyber_monitor_events_{stamp}.txt"
        events_txt.write_text(self.last_events or "No events captured.", encoding="utf-8", errors="replace")
        attachments.append(events_txt)

        for raw_path in [x.strip() for x in str(self.config.get("attachment_log_paths", "")).split(",") if x.strip()]:
            path = Path(raw_path)
            if path.exists() and path.is_file():
                attachments.append(path)
        return attachments

    def export_csv_report(self):
        try:
            target = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")], title="Save security report")
            if not target:
                return
            with open(target, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["section", "severity", "identifier", "name_or_folder", "metric1", "metric2", "user_or_files"])
                for row in self.last_cpu_rows:
                    writer.writerow(["process", row.get("severity"), row.get("pid"), row.get("name"), row.get("cpu"), row.get("memory"), row.get("user")])
                for row in self.last_storage_rows:
                    writer.writerow(["storage", row.get("severity"), "", row.get("folder"), row.get("size"), "", row.get("files")])
                for row in self.last_network_rows:
                    writer.writerow(["network", row.get("severity"), row.get("pid"), row.get("process"), row.get("local"), row.get("remote") + " | " + str(row.get("geo", "-")), row.get("status")])
            messagebox.showinfo(APP_TITLE, "CSV report exported successfully.")
        except Exception as exc:
            messagebox.showerror(APP_TITLE, f"Could not export CSV report: {exc}")

    def send_email(self, subject, body, attachments=None):
        smtp_server = str(self.config.get("smtp_server", "")).strip()
        smtp_port = int(self.config.get("smtp_port", 587))
        smtp_username = str(self.config.get("smtp_username", "")).strip()
        smtp_password = str(self.config.get("smtp_password", ""))
        sender_email = str(self.config.get("sender_email", "")).strip()
        recipients = self.parse_recipients()
        use_tls = bool(self.config.get("use_tls", True))
        if not smtp_server or not sender_email:
            raise ValueError("SMTP server and sender email are required.")

        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = sender_email
        msg["To"] = ", ".join(recipients)
        msg.set_content(body)

        for attachment in attachments or []:
            try:
                data = Path(attachment).read_bytes()
                msg.add_attachment(data, maintype="application", subtype="octet-stream", filename=Path(attachment).name)
            except Exception:
                continue

        with smtplib.SMTP(smtp_server, smtp_port, timeout=25) as server:
            server.ehlo()
            if use_tls:
                server.starttls()
                server.ehlo()
            if smtp_username:
                server.login(smtp_username, smtp_password)
            server.send_message(msg)

    def human_size(self, size: int) -> str:
        value = float(size)
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if value < 1024 or unit == "TB":
                return f"{value:.1f} {unit}"
            value /= 1024
        return f"{value:.1f} TB"

    def on_close(self):
        if self.refresh_job is not None:
            self.root.after_cancel(self.refresh_job)
        self.root.destroy()


def main():
    root = tk.Tk()
    if sys.platform.startswith("win"):
        root.state("zoomed")
    else:
        try:
            root.attributes("-zoomed", True)
        except Exception:
            pass
    ttk.Style().theme_use("clam")
    CyberMonitorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
