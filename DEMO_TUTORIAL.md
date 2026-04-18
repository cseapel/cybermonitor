# Demo & Tutorial

This file explains how to demonstrate **Cyber Monitor** for GitHub, class presentation, or project submission.

## Quick Start

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the project:

```bash
python cybermonitor.py
```

The app opens in a maximized window for better visibility.

---

## Demo Flow

Follow this order during your demo for the strongest impression.

### 1. Launch the Application
Open the application and briefly explain that Cyber Monitor is a desktop cybersecurity monitoring tool designed to provide visibility into logs, processes, storage, network activity, and alerting in one interface.

### 2. Show the Dashboard
Open the **Dashboard** tab and explain:
- CPU trend
- Memory trend
- Network throughput trend
- Security severity cards

Say:
> This acts like a mini SOC-style overview panel, helping the user quickly identify abnormal system behavior.

### 3. Show System Logs
Open **System Logs** and explain:
- live log viewing
- keyword filtering
- usefulness for identifying errors and suspicious activity

Suggested demo keywords:
- `error`
- `failed`
- `warning`

### 4. Show Login / Shutdown Events
Open **Login / Shutdown Events** and explain:
- failed login attempts
- session activity
- boot, restart, and shutdown visibility

Say:
> This helps identify authentication anomalies and unusual system access behavior.

### 5. Show CPU / Processes
Open **CPU / Processes** and explain:
- top CPU-consuming processes
- memory-heavy applications
- severity levels based on thresholds

Good demo idea:
Open a browser with many tabs or run a heavy app so usage rises visibly.

### 6. Show Storage Hotspots
Open **Storage Hotspots** and explain:
- large folders
- abnormal disk usage
- simple visibility into storage-heavy locations

Say:
> This can help identify suspicious growth, large dumps, or unusual folder expansion.

### 7. Show Network Traffic
Open **Network Traffic** and explain:
- active connections
- local and remote addresses
- process ownership
- protocol and status
- Geo/IP enrichment

This is one of the strongest parts of the project.

Say:
> The tool enriches public remote IPs with location and ISP data, helping the analyst understand where connections are coming from.

### 8. Show Alert Settings
Open **Alert Settings** and explain:
- CPU threshold
- memory threshold
- storage threshold
- failed login threshold
- network traffic threshold
- suspicious ports
- SMTP email configuration

Say:
> Admin-defined thresholds allow the system to automatically notify a supervisor or administrator when suspicious conditions are detected.

### 9. Show Email Alerting
Click **Send Test Email** and explain:
- email reporting
- attached logs and CSV exports
- use for incident notification

If email is configured, mention that the app can automatically notify the boss/admin when thresholds are exceeded.

### 10. Show CSV Export
Click **Export CSV** and explain:
- process data export
- storage data export
- network data export
- useful for documentation and reporting

---

## Best Demo Order

For a short demo, use this sequence:

1. Dashboard  
2. Network Traffic  
3. Geo/IP details  
4. Login / Shutdown Events  
5. Alert Settings  
6. Send Test Email  

This order gives the strongest cybersecurity impression.

---

## What to Say During the Demo

### Problem
> Traditional monitoring tools often separate logs, processes, storage, and network information. This makes security visibility slower and less efficient.

### Solution
> Cyber Monitor combines these monitoring areas into one desktop dashboard with severity classification, alerting, and reporting.

### Value
> It helps simulate a mini Security Operations Center dashboard suitable for small-scale monitoring and academic demonstration.

---

## Suggested Screenshots for GitHub

Add these screenshots into the `screenshots/` folder:

- `dashboard.png`
- `network-traffic.png`
- `logs-events.png`
- `alert-settings.png`

Optional:
- `email-demo.png`
- `csv-export.png`

---

## Suggested Demo Video

A short 1 to 2 minute screen recording can improve your GitHub project a lot.

Recommended structure:
1. Launch app
2. Show dashboard
3. Open network tab
4. Show geo/IP details
5. Open alert settings
6. Send test email

---

## Notes

- Some logs require administrator or root privileges
- Geo/IP lookup requires internet access
- Private/local addresses are shown as `Private/Local`
- This is a project-grade monitoring tool, not a full enterprise IDS/IPS

---

