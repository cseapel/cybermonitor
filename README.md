## ⚠️ Disclaimer

This software is developed for educational and demonstration purposes only.  
It is not intended for production or enterprise-level security use.

The application provides system monitoring features such as logs, process activity, 
and network connections for learning and analysis purposes only.

Users are responsible for how they use this software. The author is not liable for 
any misuse or damage caused.

---

## 🔐 Security & Privacy Notice

- This application does **not collect or transmit personal data** without user configuration.
- Email alerts require manual SMTP setup by the user.
- No credentials are stored externally.
- Geo/IP lookup uses a public API and only queries external IP addresses.

---

## 📜 License

This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**.

You are free to:
- Use
- Modify
- Distribute

Under the condition that:
- Modified versions must also be open-source under the same license

See the `LICENSE` file for full details.

---

## 👤 Author

**Apel Mahmud**  
Cybersecurity Student Project  

GitHub: https://github.com/cseapel/cybermonitor

---

## 🚀 Release Notes (v1.0.0)

### Features
- Real-time system log monitoring  
- Login and shutdown event tracking  
- CPU and memory process monitoring  
- Storage hotspot detection  
- Network traffic analysis with Geo/IP lookup  
- Severity-based alert classification  
- Email alerting system  
- CSV report export  

### Notes
- Requires Python 3.10+  
- Internet required for Geo/IP enrichment  
- Administrator privileges may be needed for full system visibility  
- Windows Defender may show warnings for unsigned `.exe`

---

# Cyber Monitor

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-success)
![License](https://img.shields.io/badge/License-GNU%20GPLv3-green)

A lightweight cybersecurity desktop monitoring tool.

🔗 Repository: https://github.com/cseapel/cybermonitor

## Run
```bash
pip install -r requirements.txt
python cybermonitor.py
```

## Screenshots
![Dashboard](screenshots/dashboard.png)
![Network](screenshots/network-traffic.png)
![Logs](screenshots/logs-events.png)
![Alerts](screenshots/alert-settings.png)

## Structure
```
cybermonitor/
├── cybermonitor.py
├── requirements.txt
├── README.md
├── LICENSE
└── screenshots/
```

## License
GNU GPLv3

## Demo & Tutorial

See [DEMO_TUTORIAL.md](DEMO_TUTORIAL.md) for a full walkthrough, demo flow, and presentation guide.
