# SentinelX

SentinelX is a modular cybersecurity platform for real-time threat detection, host and network monitoring, alert management, and reporting. Its extensible Python architecture enables security teams to monitor, analyze, and respond to threats efficiently with a user-friendly GUI.

## Features
- Real-time threat detection and scoring
- Host and network monitoring
- Centralized alert dashboard
- Automated reporting
- Extensible, modular design

## Getting Started
1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Run: `python -m sentinelx.main`

## License
MIT License# 🛡️ SentinelX – Windows Defensive Cybersecurity Monitoring Suite

**Version 1.0.0** | Python 3.11+ | Windows 10/11

---

## 📌 Overview

SentinelX is a scalable, modular, Windows-based defensive cybersecurity application with a professional PySide6 GUI. It acts as a lightweight **Endpoint Detection & Response (EDR)** and **Network Intrusion Detection System (NIDS)** for small to medium environments.

### Core Capabilities

| Module | Functionality |
|--------|--------------|
| **Network Monitor** | Packet capture, port scan detection, SYN flood, ARP spoofing, DNS tunneling |
| **Event Log Monitor** | Windows Security log analysis – failed logins, privilege escalation, PowerShell abuse |
| **File Integrity Monitor** | SHA256 baseline, real-time change detection, ransomware behavior alerting |
| **Process Monitor** | Suspicious process chains, reverse shell patterns, high CPU anomaly detection |
| **Detection Engine** | Rule-based evaluation with configurable thresholds and time windows |
| **Threat Scoring** | Per-entity risk score aggregation with severity mapping |
| **GUI Dashboard** | Real-time stats, alert management, threat exploration, settings configuration |
| **Reporting** | PDF & CSV security reports with charts and timelines |

---

## 🏗️ Architecture

```
sentinelx/
├── core/
│   ├── engine.py              # Detection engine (rule evaluation, alert generation)
│   ├── rules.py               # Rule definitions (15+ built-in rules)
│   └── threat_scoring.py      # Per-entity threat score aggregation
├── network/
│   ├── sniffer.py             # Scapy packet capture
│   └── network_analyzer.py    # Traffic analysis & anomaly detection
├── host/
│   ├── event_log_monitor.py   # Windows Security event log monitoring
│   ├── file_integrity.py      # File integrity monitoring with watchdog
│   └── process_monitor.py     # Process behavior analysis with psutil
├── database/
│   ├── models.py              # SQLAlchemy ORM models
│   └── db_manager.py          # CRUD operations & statistics
├── gui/
│   ├── main_window.py         # Main window with sidebar navigation
│   ├── dashboard.py           # Real-time dashboard with charts
│   ├── alerts_view.py         # Alert table with filtering & export
│   ├── reports_view.py        # Report generation UI
│   └── settings_view.py       # Module configuration panel
├── auth/
│   └── auth_manager.py        # bcrypt authentication & role management
├── reporting/
│   └── report_generator.py    # PDF/CSV report generation
├── utils/
│   ├── config.py              # Encrypted configuration management
│   ├── logger.py              # Tamper-resistant logging system
│   └── updater.py             # Version checking & license validation
├── main.py                    # GUI application entry point
└── service.py                 # Windows Service entry point
```

---

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Run the Application

```bash
# Run with GUI (requires Administrator for full functionality)
python -m sentinelx.main
```

### 3. Default Login

| Username | Password | Role |
|----------|----------|------|
| `admin`  | `admin`  | Admin |

> ⚠️ **Change the default admin password immediately after first login.**

---

## 🖥️ Running as Windows Service

```bash
# Install the service
python sentinelx/service.py install

# Start the service
python sentinelx/service.py start

# Stop the service
python sentinelx/service.py stop

# Remove the service
python sentinelx/service.py remove
```

---

## 📦 Building an Executable

```bash
pip install pyinstaller
pyinstaller sentinelx.spec
```

The executable will be created in the `dist/` directory with UAC admin manifest.

---

## 🔍 Detection Rules (Built-in)

| Rule | Severity | Threshold | Window |
|------|----------|-----------|--------|
| Port Scan Detected | High | 10 ports | 10 sec |
| SYN Flood Attempt | Critical | 100 SYN packets | 5 sec |
| ARP Spoofing | Critical | 1 MAC change | 30 sec |
| Excessive DNS Requests | Medium | 50 queries | 10 sec |
| Brute Force Login | High | 5 failed logins | 60 sec |
| Suspicious User Created | High | 1 event | 300 sec |
| Admin Privilege Escalation | High | 1 event | 60 sec |
| Suspicious PowerShell | High | 1 event | 60 sec |
| Ransomware Behavior | Critical | 50 file changes | 30 sec |
| High CPU Sustained | Medium | 80% for 30 sec | 30 sec |
| Suspicious Process Chain | High | 1 match | 60 sec |
| Reverse Shell Pattern | Critical | 1 match | 60 sec |

All thresholds are configurable via the Settings GUI.

---

## 🎚️ Threat Scoring

| Severity | Score | Aggregate Risk Level |
|----------|-------|---------------------|
| Low | 10 | < 40: Low |
| Medium | 30 | 40–99: Medium |
| High | 70 | 100–199: High |
| Critical | 100 | ≥ 200: Critical |

Scores aggregate per IP/entity over a 24-hour rolling window (capped at 1000).

---

## 🔐 Security Features

- **Role-based access control** – Admin (full) and Viewer (read-only)
- **bcrypt password hashing** – Secure local authentication
- **Encrypted configuration** – Fernet encryption for config files
- **Log tamper resistance** – HMAC integrity hashes on log entries

---

## 💼 Licensing

| Feature | Free | Pro |
|---------|------|-----|
| All monitoring modules | ✅ | ✅ |
| Real-time dashboard | ✅ | ✅ |
| Alert management | ✅ | ✅ |
| CSV export | ✅ | ✅ |
| PDF reports | ❌ | ✅ |
| Threat intelligence | ❌ | ✅ |
| Remote agents | ❌ | ✅ |
| API access | ❌ | ✅ |

---

## 🧪 Running Tests

```bash
python -m pytest tests/ -v
```

---

## 📊 Tech Stack

| Component | Technology |
|-----------|-----------|
| GUI | PySide6 |
| Network Capture | scapy |
| Process Monitoring | psutil |
| Event Logs | pywin32 |
| File Monitoring | watchdog |
| Database | SQLite + SQLAlchemy |
| Password Hashing | bcrypt |
| Config Encryption | cryptography (Fernet) |
| Charts | matplotlib |
| PDF Reports | reportlab |

---

## 📜 License

Proprietary. See LICENSE file for details.
