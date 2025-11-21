# 🛡 Project JANUS
### *ARP Spoofing Man-in-the-Middle Attack & Network Intelligence Toolkit*
by **@uptouplaksh**

---

## 🚀 Overview
**Project JANUS** is a cybersecurity research tool designed to demonstrate **ARP-based Man-in-the-Middle (MITM) attacks** and real-time packet intelligence extraction inside local networks.

It enables:
- 🔍 Automatic host discovery through passive packet sniffing
- 🕵 Real-time DNS interception & intelligence logging
- ⚔ Full ARP Spoof MITM lifecycle (start, active monitoring, restore state)
- 📦 Session logging & packet storage with PostgreSQL + SQLAlchemy ORM
- 🎛 Clean interactive command-line interface

JANUS acts like a **network telescope**, revealing communication happening in LAN environments.

---

## 🎯 Core Features

| Feature | Status | Description |
|--------|--------|-------------|
| Passive network sniffing | ✅ | Discovers hosts on the network & logs packets |
| ARP-Spoof MITM attack engine | ✅ | Hijacks gateway communication securely |
| DNS query analysis | ✅ | Human-readable domain intelligence |
| Auto interface detection | ✅ | No need to type complex `wlo1`/`eth0` manually |
| Auto attacker IP/MAC detection | ✅ | Instantly identifies your system on network |
| MITM session manager | ✅ | Start / stop / list attack sessions |
| DB-backed packet logging | ✅ | Persistent storage for auditing |
| Real-time output display | ⚡ | Domain names shown live while session runs |

---

## 🧠 High-Level Architecture

```text
+-------------------+         +-----------------------+
|      CLI UI       | <-----> | Attack Session Manager|
+-------------------+         +-----------------------+
           |                               |
           v                               v
+-----------------------+       +----------------------+
| Packet Sniffer        |       | ARP Handler (Spoof)  |
| (Scapy interception)  |       | + restore ARP tables |
+-----------------------+       +----------------------+
                 \             /
                  \           /
                 +-------------------------------+
                 | Database Layer (SQLAlchemy)   |
                 | + Host + ARP + Packet logs    |
                 +-------------------------------+

```
---

## 📂 Project Structure

```text
project_janus/
│
├── README.md
├── requirements.txt
├── .env.example
│
├── janus_core/
│ ├── init.py
│ └── main.py
│
├── janus_network/
│ ├── init.py
│ ├── sniffer.py
│ ├── ip_forwarder.py 
│ └── arp_handler.py 
│
├── janus_data/
│ ├── init.py
│ ├── database.py 
│ ├── models.py 
│ └── db_utils.py 
│
├── janus_attack_manager/
│ ├── init.py
│ └── session_manager.py 
│
├── janus_ui/
│ ├── init.py
│ ├── menu.py 
│ ├── network_select.py 
│ ├── host_select.py 
│ ├── sniff_commands.py
│ ├── mitm_commands.py 
│ ├── db_commands.py 
│ └── analysis_commands.py 
│
├── janus_utils/
│ ├── init.py
│ ├── netinfo.py
│ └── banner.py
│
└── docs/
   ├── diagrams/
   │   ├── class-diagram.png
   │   ├── use-case-diagram.png
   │   ├── component-diagram.png
   │   ├── activity-launch-mitm.png
   │   ├── activity-restore-network.png
   │   ├── activity-packet-logging.png
   │   ├── sequence-mitm-flow.png
   │   └── er-diagram.png
   │
   └── screenshots/
       ├── cli-main-menu.png
       ├── mitm-started.png
       ├── dns-analysis-output.png
       └── sessions-list.png
```

---

## 🧪 Demo Output Example

```yaml
[+] MITM attack session started successfully!
    Session ID : 3
    Victim IP  : 172.30.137.86
    Gateway IP : 172.30.137.236

--- DNS Query Analysis ---
[2025-11-21 23:48:35] 172.30.137.86 → Query for youtube.com
[2025-11-21 23:48:39] 172.30.137.86 → Query for fonts.gstatic.com

[+] Total DNS queries: 12
```
---

## 🧩 Prerequisites & System Setup

This project requires the following dependencies and environment configuration before running.

### System Requirements
- Linux OS (Ubuntu / Debian recommended)
- Python 3.13+
- sudo/root access
- PostgreSQL running locally
- Basic networking utilities installed (`tcpdump`, `iproute2`, etc.)

### Install Required System Packages

```bash
sudo apt update
sudo apt install postgresql postgresql-contrib
sudo apt install tcpdump
sudo apt install net-tools
```
### Setup PostgreSQL Database
```bash
sudo systemctl enable postgresql
sudo systemctl start postgresql
sudo -u postgres psql
```
### Inside the PostgreSQL shell:
```bash
CREATE DATABASE janus_db;
CREATE USER janus_user WITH ENCRYPTED PASSWORD 'janus_password';
GRANT ALL PRIVILEGES ON DATABASE janus_db TO janus_user;
```
### Create Virtual Environment & Install Requirements
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```
### Create .env file (based on template)
```bash
cp .env.example .env
```
### Inside .env, edit the values to match your DB credentials:
```env
DB_HOST=localhost
DB_PORT=5432
DB_NAME=janus_db
DB_USER=janus_user
DB_PASS=janus_password
```
### Run the JANUS CLI
```bash
sudo .venv/bin/python -m janus_core.main
```
### (Optional) Monitor Live Traffic with tcpdump
Open a second terminal and run:
```bash
sudo tcpdump -i wlo1 host <victim-ip>
```
---
## 🧪 Usage Flow
- Run passive sniffing to detect hosts
- Start MITM: select victim + gateway from menu
- Analyze DNS queries and traffic summaries via CLI
- Stop session & restore ARP tables safely

---

## ⚠ Legal & Ethical Usage
Project JANUS is a cybersecurity research tool for educational and authorized testing environments only. Performing ARP spoofing or MITM attacks on networks without explicit written permission is illegal. Use responsibly.

---

## 🧊 Future Plans
- Full interactive GUI dashboard
- PCAP export + Wireshark integration
- Web app monitoring + real time charts

---

## 🌟 Credits
Developed by **@uptouplaksh**
Conceptualized and engineered with a strong focus on real-world cybersecurity applications and academic research excellence.

---

## 🤝 Contributors

| Name | Role | GitHub |
|-------|--------|--------|
| Uplaksh | Lead Developer & Researcher | https://github.com/uptouplaksh |
| Open for contributions | Security Research / UI / Testing | (Submit PRs or reach out) |
