# Vigilon - System Monitor Dashboard

A premium, enterprise-grade, **single-file** Linux system monitoring dashboard built with Flask and psutil. No build step, no frontend framework, no database server to set up — just one `monitor.py` file that runs a full real-time monitoring web app.

![Theme](https://img.shields.io/badge/theme-Navy%20%26%20Gold-0B1F3A) ![Python](https://img.shields.io/badge/python-3.9%2B-blue) ![License](https://img.shields.io/badge/license-MIT-green)

---

## ✨ Features

**Core monitoring**
- Live CPU, memory, disk, and network stats (2-second refresh, AJAX + optional WebSocket push)
- Per-core CPU usage, load average, temperature (where available)
- Disk partitions, usage, and I/O counters
- Network interfaces, gateway, DNS, live upload/download speed
- Active connections (TCP/UDP, IPv4/IPv6) with search & filter
- Running processes with CPU/Mem/threads/status, kill / suspend / resume / priority controls
- Listening ports table
- Logged-in users, systemd services (ssh, docker, NetworkManager, cron, etc.)
- Security overview: firewall detection (ufw/nftables/iptables), failed SSH attempts, suspicious high-CPU processes
- Recent logs via `journalctl`, with search
- Hardware info (CPU model, RAM, motherboard/BIOS/serial where permissions allow)
- Wi-Fi details (SSID, signal, channel, security) or graceful "no wireless interface" message

**Extended tooling**
- Packet Monitor (Scapy-based live capture, with graceful fallback if Scapy/root isn't available)
- Bandwidth per process
- Network tools: ping, traceroute, DNS/reverse-DNS lookup, whois, port scanner, subnet/CIDR calculator, ARP table
- Visual network topology map
- USB, PCI, Bluetooth, GPU (NVIDIA/AMD/Intel) detection
- Docker containers & images overview
- Virtual machine / container environment detection (VirtualBox, VMware, KVM/QEMU, Hyper-V, LXC, Docker)
- Cron jobs, kernel modules, installed packages, environment variables
- Built-in filesystem browser (permissions, owner, size, modified date)
- Embedded terminal (admin-token protected)
- System power controls: lock, sleep, hibernate, logout, restart, shutdown (admin-token protected, confirmation required)
- Export to JSON, CSV, HTML report, and PDF
- Persistent history in SQLite, with a `/api/history-db` endpoint for time-ranged queries

**Design**
- Premium "enterprise dashboard" theme — cream background, navy navbar, gold accents
- Fully responsive: collapsible sidebar with backdrop on mobile, stacked cards, scrollable tables
- Chart.js powered resource history and network speed graphs
- Toast notifications, skeleton-style loading, status badges, progress bars

---

## 🔒 Security model

This dashboard exposes real system internals over HTTP. By design:

- **Read-only data endpoints** (`/api/system`, `/api/cpu`, `/api/processes`, etc.) require no authentication — treat these the way you'd treat any monitoring tool's read access.
- **Dangerous actions** — killing/suspending a process, the embedded terminal, and power controls (shutdown/restart/lock/etc.) — require an **admin token**.
  - The token is randomly generated **every time you start `monitor.py`** and printed once to the console.
  - You must paste it into the dashboard's **Settings** or **Terminal** page (stored only in your browser's `localStorage`) to use protected features.
- All shell-invoking network tools (ping, traceroute, whois, etc.) validate their input against a strict allowlist regex to prevent command injection.
- Port scans are capped to 200 ports per request to avoid accidental abuse.

> ⚠️ **Do not expose this dashboard to the public internet or an untrusted network.** Anyone with the admin token has the equivalent of a remote shell on the host. Run it on a trusted LAN, behind a VPN, or behind an authenticating reverse proxy (e.g. Nginx with basic auth or OAuth2 Proxy) if remote access is required.

---

## 📦 Requirements

- Linux (Debian/Ubuntu or Fedora/RHEL family — see `install.sh`)
- Python 3.9+
- Root/sudo access for full hardware detail and some security features (the app degrades gracefully without it)

---

## 🚀 Installation

### Option 1 — Automated installer (recommended)

```bash
git clone https://github.com/psvineet/vigilon.git
cd vigilon
chmod +x install.sh
./install.sh
```

`install.sh` will:
1. Detect whether you're on a Debian/Ubuntu or Fedora/RHEL based system.
2. Install required system packages (`python3`, `python3-venv`/`pip`, `iproute2`/`iproute`, `net-tools`, `dnsutils`/`bind-utils`, `whois`, `traceroute`, `usbutils`, `pciutils`, `lsof`).
3. Create an isolated Python virtual environment in `./venv` (avoids the "externally-managed-environment" pip error on modern distros).
4. Install Python dependencies (`Flask`, `psutil`, `flask-sock`, and best-effort `scapy` / `reportlab`).
5. Create a `run.sh` launcher script.
6. Optionally install and enable a `systemd` service so the dashboard starts on boot.

Flags:
```bash
./install.sh --service      # install + enable systemd service non-interactively
./install.sh --no-service   # skip the systemd prompt entirely
```

### Option 2 — Manual install

```bash
# Debian/Ubuntu
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip iproute2 net-tools dnsutils whois traceroute usbutils pciutils lsof

# Fedora/RHEL
sudo dnf install -y python3 python3-pip iproute net-tools bind-utils whois traceroute usbutils pciutils lsof

# Then, on either distro:
python3 -m venv venv
source venv/bin/activate
pip install Flask psutil flask-sock
python3 monitor.py
```

`monitor.py` will also attempt to auto-install any missing Python packages (`Flask`, `psutil`) the moment you run it, so a bare `python3 monitor.py` works in a pinch — though using the installer/venv is recommended for a clean, reproducible setup.

---

## ▶️ Running

```bash
./run.sh
```

or directly:

```bash
source venv/bin/activate
python3 monitor.py
```

Then open:

```
http://localhost:1110
```

On first start, note the **admin token** printed in the console — you'll need it for process control, the terminal, and power actions.

### Running as a systemd service

If you chose to install the service (or want to do it later):

```bash
sudo systemctl status system-monitor-dashboard
sudo systemctl restart system-monitor-dashboard
journalctl -u system-monitor-dashboard -f
```

---

## 🌐 REST API

All data is also available as JSON, for scripting or integration:

| Endpoint | Description |
|---|---|
| `/api/system` | Hostname, OS, kernel, uptime, etc. |
| `/api/cpu` | CPU usage, per-core, frequency, load average |
| `/api/memory` | RAM and swap usage |
| `/api/disk` | Partitions and I/O counters |
| `/api/network` | Interfaces, speed, gateway, DNS |
| `/api/connections` | Active TCP/UDP connections |
| `/api/ports` | Listening ports |
| `/api/processes` | Running processes |
| `/api/users` | Logged-in users |
| `/api/services` | Watched systemd services |
| `/api/security` | Firewall, failed SSH attempts, suspicious processes |
| `/api/logs?q=` | Recent `journalctl` entries, optional search |
| `/api/wifi` | Wireless interface details |
| `/api/hardware` | CPU/RAM/motherboard/BIOS info |
| `/api/history` / `/api/history-db?minutes=` | In-memory or persisted (SQLite) resource history |
| `/api/bandwidth` | Per-process I/O |
| `/api/usb`, `/api/pci`, `/api/bluetooth`, `/api/gpu` | Hardware peripherals |
| `/api/docker` | Containers and images |
| `/api/vm` | Virtualization/container detection |
| `/api/cron`, `/api/kernel-modules`, `/api/packages`, `/api/environment` | System configuration data |
| `/api/filesystem?path=` | Directory listing |
| `/api/tools/ping`, `/dns`, `/rdns`, `/whois`, `/portscan`, `/subnet`, `/mac`, `/arp` | Network diagnostic tools |
| `/api/packets`, `/api/packets/start`, `/stop`, `/clear` | Packet monitor (Scapy) |
| `/api/process/<pid>/kill`, `/suspend`, `/resume`, `/priority`, `/details` | Process control *(admin token required for kill/suspend/resume/priority)* |
| `/api/terminal` *(POST)* | Execute a shell command *(admin token required)* |
| `/api/system/action` *(POST)* | Power controls *(admin token required, `confirm: true` required)* |
| `/api/export/json`, `/csv`, `/html`, `/pdf` | Export current snapshot |
| `/ws/live` | WebSocket live feed (falls back to AJAX automatically if unavailable) |

---

## ⚙️ Configuration

There's no config file — everything lives in `monitor.py`:

- **Port / host**: change the `app.run(host="0.0.0.0", port=1110, ...)` call at the bottom of the file.
- **Refresh interval**: adjustable live from the dashboard's Settings page (client-side, no restart needed).
- **Service watchlist**: edit `SERVICE_WATCHLIST` to monitor different systemd units.
- **History retention**: edit `MAX_HISTORY` (in-memory) or query `/api/history-db` for longer SQLite-backed history.

---

## 🩹 Troubleshooting

- **"externally-managed-environment" pip error** → use `install.sh`, which creates a virtualenv specifically to avoid this (PEP 668 on newer Debian/Fedora).
- **Packet Monitor says "unavailable"** → Scapy needs to be installed *and* the process typically needs root privileges for raw sockets. Try `sudo venv/bin/python3 monitor.py`.
- **Hardware page shows "N/A (requires root)"** → BIOS/motherboard/serial data is only readable as root on most distros.
- **PDF export fails** → `reportlab` wasn't installed; run `venv/bin/pip install reportlab`.
- **Nothing loads on a page** → check the browser console; data endpoints return JSON errors rather than crashing, so a 401 usually just means you need to paste the admin token into Settings.

---

## 📁 Project structure

```
.
├── monitor.py     # The entire application (Flask backend + embedded HTML/CSS/JS frontend)
├── install.sh     # Cross-distro installer (Debian/Ubuntu + Fedora/RHEL)
├── run.sh         # Generated by install.sh — convenience launcher
└── README.md      # This file
```

---

## 📝 License

MIT — use it, fork it, adapt it for your own homelab or internal tooling.

---

## ⭐ Acknowledgements

Built with [Flask](https://flask.palletsprojects.com/), [psutil](https://github.com/giampaolo/psutil), [Chart.js](https://www.chartjs.org/), [Bootstrap 5](https://getbootstrap.com/), and [Bootstrap Icons](https://icons.getbootstrap.com/).
