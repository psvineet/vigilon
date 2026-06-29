#!/usr/bin/env python3
"""
Vigilon - Premium System Monitoring Dashboard
A premium, enterprise-grade single-file system monitoring application.
Run: python3 monitor.py  -> http://localhost:1110
"""

import sys
import subprocess
import importlib
import os

# ============================================================
# DEPENDENCY BOOTSTRAP
# ============================================================

def _ensure(pkg_import: str, pip_name: str = None):
    pip_name = pip_name or pkg_import
    try:
        importlib.import_module(pkg_import)
        return  # already installed
    except ImportError:
        pass
    print(f"  -> Installing missing dependency: {pip_name} ...")
    # Try with --break-system-packages first (needed on modern Debian/Ubuntu/macOS)
    for extra_flags in [["--break-system-packages"], ["--user"], []]:
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--quiet", pip_name] + extra_flags,
                stderr=subprocess.DEVNULL,
            )
            # Verify it's now importable
            importlib.import_module(pkg_import)
            return
        except Exception:
            continue
    print(f"  !! Could not install {pip_name}. Run manually: pip install {pip_name}")

print("=" * 50)
print("Vigilon - System Monitor")
print("=" * 50)
print("Checking dependencies...")

_ensure("flask", "Flask")
_ensure("psutil", "psutil")
_ensure("flask_sock", "flask-sock")

from flask import Flask, render_template_string, jsonify, request, Response, g
import sqlite3
import secrets
import signal as signal_mod

try:
    from flask_sock import Sock
except Exception:
    Sock = None

try:
    import psutil
except Exception:
    psutil = None

import socket
import platform
import getpass
import time
import datetime
import shutil
import json
import csv
import io
import threading
import subprocess as sp

# ============================================================
# APP SETUP
# ============================================================

app = Flask(__name__)
sock = Sock(app) if Sock else None

# Admin token for dangerous actions (kill process, terminal, power controls).
# Generated fresh each launch and printed to console -- pass it back via
# X-Admin-Token header or ?token= query param to use protected endpoints.
ADMIN_TOKEN = secrets.token_hex(16)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "monitor_history.db")
_db_lock = threading.Lock()


def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    return conn


def init_db():
    with _db_lock:
        conn = get_db()
        conn.execute("""CREATE TABLE IF NOT EXISTS history(
            ts REAL, cpu REAL, memory REAL, disk REAL, net_up REAL, net_down REAL)""")
        conn.commit()
        conn.close()


def require_admin(fn):
    """Decorator: require a valid admin token for dangerous endpoints."""
    def wrapper(*args, **kwargs):
        token = request.headers.get("X-Admin-Token") or request.args.get("token")
        if token != ADMIN_TOKEN:
            return jsonify({"error": "Unauthorized. Valid admin token required."}), 401
        return fn(*args, **kwargs)
    wrapper.__name__ = fn.__name__
    return wrapper


START_TIME = time.time()
_cache = {}
_cache_lock = threading.Lock()
CACHE_TTL = 1.5  # seconds, avoid hammering expensive syscalls


def cached(key, ttl=CACHE_TTL):
    """Decorator-like helper: cache function result for ttl seconds."""
    def wrapper(fn):
        def inner(*args, **kwargs):
            now = time.time()
            with _cache_lock:
                entry = _cache.get(key)
                if entry and (now - entry[0]) < ttl:
                    return entry[1]
            result = fn(*args, **kwargs)
            with _cache_lock:
                _cache[key] = (now, result)
            return result
        return inner
    return wrapper


def safe(fn, default=None):
    """Run fn() and swallow any exception, returning default instead."""
    try:
        return fn()
    except Exception:
        return default


def run_cmd(cmd, timeout=2):
    """Run a shell command safely, return stdout text or '' on failure."""
    try:
        out = sp.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return out.stdout.strip()
    except Exception:
        return ""


def bytes_fmt(n):
    try:
        n = float(n)
    except Exception:
        return "N/A"
    for unit in ["B", "KB", "MB", "GB", "TB", "PB"]:
        if n < 1024.0:
            return f"{n:.2f} {unit}"
        n /= 1024.0
    return f"{n:.2f} EB"


def uptime_str(seconds):
    seconds = int(seconds)
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    parts = []
    if d:
        parts.append(f"{d}d")
    if h:
        parts.append(f"{h}h")
    if m:
        parts.append(f"{m}m")
    parts.append(f"{s}s")
    return " ".join(parts)


# ============================================================
# DATA COLLECTORS
# ============================================================

@cached("system_info", ttl=5)
def get_system_info():
    uname = platform.uname()
    boot_ts = safe(lambda: psutil.boot_time(), time.time())
    info = {
        "hostname": safe(lambda: socket.gethostname(), "unknown"),
        "username": safe(lambda: getpass.getuser(), "unknown"),
        "os": f"{uname.system} {uname.release}",
        "kernel": uname.release,
        "architecture": uname.machine,
        "python_version": platform.python_version(),
        "machine": uname.machine,
        "processor": (
            run_cmd("lscpu 2>/dev/null | grep -m1 'Model name' | sed 's/.*: *//'")
            or uname.processor or platform.processor() or "Unknown"
        ).strip(),
        "boot_time": datetime.datetime.fromtimestamp(boot_ts).strftime("%Y-%m-%d %H:%M:%S"),
        "uptime": uptime_str(time.time() - boot_ts),
        "timezone": safe(lambda: str(datetime.datetime.now().astimezone().tzinfo), "Unknown"),
    }
    return info


@cached("cpu_info", ttl=1)
def get_cpu_info():
    try:
        per_core = psutil.cpu_percent(percpu=True, interval=0.1)
        overall = psutil.cpu_percent(interval=None)
    except Exception:
        per_core, overall = [], 0
    freq = safe(lambda: psutil.cpu_freq(), None)
    load_avg = safe(lambda: os.getloadavg(), (0, 0, 0))
    temps = safe(lambda: psutil.sensors_temperatures(), {}) or {}
    temp_val = None
    for name, entries in temps.items():
        if entries:
            temp_val = entries[0].current
            break
    stats = safe(lambda: psutil.cpu_stats(), None)
    return {
        "usage": overall,
        "per_core": per_core,
        "core_count_logical": psutil.cpu_count(logical=True),
        "core_count_physical": psutil.cpu_count(logical=False),
        "frequency_current": round(freq.current, 1) if freq else None,
        "frequency_max": round(freq.max, 1) if freq else None,
        "temperature": round(temp_val, 1) if temp_val else None,
        "load_avg": [round(x, 2) for x in load_avg],
        "context_switches": stats.ctx_switches if stats else None,
        "interrupts": stats.interrupts if stats else None,
    }


@cached("memory_info", ttl=1)
def get_memory_info():
    vm = psutil.virtual_memory()
    sm = psutil.swap_memory()
    return {
        "total": bytes_fmt(vm.total),
        "used": bytes_fmt(vm.used),
        "available": bytes_fmt(vm.available),
        "free": bytes_fmt(vm.free),
        "cached": bytes_fmt(getattr(vm, "cached", 0)),
        "buffers": bytes_fmt(getattr(vm, "buffers", 0)),
        "percent": vm.percent,
        "swap_total": bytes_fmt(sm.total),
        "swap_used": bytes_fmt(sm.used),
        "swap_percent": sm.percent,
    }


@cached("disk_info", ttl=3)
def get_disk_info():
    partitions = []
    for part in safe(lambda: psutil.disk_partitions(all=False), []):
        usage = safe(lambda: psutil.disk_usage(part.mountpoint), None)
        if usage is None:
            continue
        partitions.append({
            "device": part.device,
            "mountpoint": part.mountpoint,
            "fstype": part.fstype,
            "total": bytes_fmt(usage.total),
            "used": bytes_fmt(usage.used),
            "free": bytes_fmt(usage.free),
            "percent": usage.percent,
        })
    io_counters = safe(lambda: psutil.disk_io_counters(), None)
    io_data = {
        "read_bytes": bytes_fmt(io_counters.read_bytes) if io_counters else "N/A",
        "write_bytes": bytes_fmt(io_counters.write_bytes) if io_counters else "N/A",
        "read_count": io_counters.read_count if io_counters else 0,
        "write_count": io_counters.write_count if io_counters else 0,
    }
    return {"partitions": partitions, "io": io_data}


_net_last = {"t": time.time(), "sent": 0, "recv": 0}


@cached("network_info", ttl=1)
def get_network_info():
    interfaces = []
    addrs = safe(lambda: psutil.net_if_addrs(), {})
    stats = safe(lambda: psutil.net_if_stats(), {})
    for name, addr_list in addrs.items():
        ipv4 = ipv6 = mac = None
        for a in addr_list:
            if a.family == socket.AF_INET:
                ipv4 = a.address
            elif a.family == socket.AF_INET6:
                ipv6 = a.address
            elif a.family == psutil.AF_LINK:
                mac = a.address
        st = stats.get(name)
        interfaces.append({
            "name": name,
            "ipv4": ipv4 or "N/A",
            "ipv6": ipv6 or "N/A",
            "mac": mac or "N/A",
            "mtu": st.mtu if st else "N/A",
            "speed": f"{st.speed} Mbps" if st and st.speed else "N/A",
            "duplex": str(st.duplex) if st else "N/A",
            "status": "UP" if (st and st.isup) else "DOWN",
        })

    io = safe(lambda: psutil.net_io_counters(), None)
    now = time.time()
    up_speed = down_speed = 0
    if io:
        dt = max(now - _net_last["t"], 0.001)
        up_speed = max((io.bytes_sent - _net_last["sent"]) / dt, 0)
        down_speed = max((io.bytes_recv - _net_last["recv"]) / dt, 0)
        _net_last.update({"t": now, "sent": io.bytes_sent, "recv": io.bytes_recv})

    gateway = run_cmd("ip route | grep default | awk '{print $3}'") or "N/A"
    dns = run_cmd("cat /etc/resolv.conf 2>/dev/null | grep nameserver | awk '{print $2}'") or "N/A"

    return {
        "interfaces": interfaces,
        "upload_total": bytes_fmt(io.bytes_sent) if io else "N/A",
        "download_total": bytes_fmt(io.bytes_recv) if io else "N/A",
        "upload_speed": bytes_fmt(up_speed) + "/s",
        "download_speed": bytes_fmt(down_speed) + "/s",
        "upload_speed_raw": round(up_speed, 2),
        "download_speed_raw": round(down_speed, 2),
        "gateway": gateway,
        "dns": dns.replace("\n", ", ") if dns else "N/A",
    }


@cached("connections_info", ttl=2)
def get_connections():
    conns = []
    for c in safe(lambda: psutil.net_connections(kind="inet"), []):
        try:
            pname = "N/A"
            user = "N/A"
            if c.pid:
                p = safe(lambda: psutil.Process(c.pid), None)
                if p:
                    pname = safe(lambda: p.name(), "N/A")
                    user = safe(lambda: p.username(), "N/A")
            conns.append({
                "proto": "TCP" if c.type == socket.SOCK_STREAM else "UDP",
                "family": "IPv6" if c.family == socket.AF_INET6 else "IPv4",
                "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "N/A",
                "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "N/A",
                "status": c.status,
                "pid": c.pid or "N/A",
                "process": pname,
                "user": user,
            })
        except Exception:
            continue
    return conns[:500]


@cached("listening_ports", ttl=2)
def get_listening_ports():
    ports = []
    for c in safe(lambda: psutil.net_connections(kind="inet"), []):
        if c.status == "LISTEN" and c.laddr:
            pname = "N/A"
            if c.pid:
                p = safe(lambda: psutil.Process(c.pid), None)
                if p:
                    pname = safe(lambda: p.name(), "N/A")
            ports.append({
                "port": c.laddr.port,
                "address": c.laddr.ip,
                "program": pname,
                "pid": c.pid or "N/A",
                "protocol": "TCP" if c.type == socket.SOCK_STREAM else "UDP",
            })
    seen = set()
    unique = []
    for p in ports:
        key = (p["port"], p["protocol"])
        if key not in seen:
            seen.add(key)
            unique.append(p)
    return sorted(unique, key=lambda x: x["port"])


@cached("processes_info", ttl=2)
def get_processes():
    procs = []
    for p in safe(lambda: psutil.process_iter(
            ["pid", "name", "exe", "cpu_percent", "memory_percent",
             "num_threads", "status", "username", "create_time"]), []):
        try:
            info = p.info
            procs.append({
                "pid": info.get("pid"),
                "name": info.get("name") or "N/A",
                "exe": info.get("exe") or "N/A",
                "cpu": round(info.get("cpu_percent") or 0, 1),
                "memory": round(info.get("memory_percent") or 0, 2),
                "threads": info.get("num_threads") or 0,
                "status": info.get("status") or "N/A",
                "user": info.get("username") or "N/A",
                "created": datetime.datetime.fromtimestamp(
                    info.get("create_time", time.time())).strftime("%Y-%m-%d %H:%M:%S"),
            })
        except Exception:
            continue
    return sorted(procs, key=lambda x: x["cpu"], reverse=True)[:300]


@cached("logged_users", ttl=3)
def get_logged_users():
    users = []
    for u in safe(lambda: psutil.users(), []):
        users.append({
            "name": u.name,
            "terminal": u.terminal or "N/A",
            "host": u.host or "N/A",
            "started": datetime.datetime.fromtimestamp(u.started).strftime("%Y-%m-%d %H:%M:%S"),
        })
    return users


SERVICE_WATCHLIST = ["ssh", "sshd", "docker", "NetworkManager", "systemd-resolved", "cron", "crond"]


@cached("services_info", ttl=4)
def get_services():
    services = []
    for svc in SERVICE_WATCHLIST:
        out = run_cmd(f"systemctl is-active {svc} 2>/dev/null")
        if not out:
            continue
        state = out.strip()
        services.append({"name": svc, "state": state})
    return services


@cached("security_info", ttl=5)
def get_security_info():
    firewall = "Not detected"
    if run_cmd("which ufw"):
        ufw_status = run_cmd("ufw status 2>/dev/null")
        firewall = f"ufw: {ufw_status.splitlines()[0] if ufw_status else 'inactive'}"
    elif run_cmd("which nft"):
        firewall = "nftables detected"
    elif run_cmd("which iptables"):
        firewall = "iptables detected"

    failed_ssh = run_cmd(
        "journalctl -u ssh -u sshd --no-pager -n 50 2>/dev/null | grep -i 'failed' | tail -n 20"
    ) or run_cmd("grep -i 'failed password' /var/log/auth.log 2>/dev/null | tail -n 20")

    auth_logs = run_cmd("journalctl -n 30 --no-pager 2>/dev/null") or "No log access."

    suspicious = []
    for p in safe(lambda: psutil.process_iter(["pid", "name", "cpu_percent"]), []):
        try:
            if (p.info.get("cpu_percent") or 0) > 80:
                suspicious.append(f"{p.info.get('name')} (PID {p.info.get('pid')}) high CPU")
        except Exception:
            continue

    return {
        "firewall": firewall,
        "failed_ssh": failed_ssh.splitlines()[-20:] if failed_ssh else ["No failed login data available."],
        "auth_logs": auth_logs.splitlines()[-20:] if auth_logs else ["No log access."],
        "suspicious": suspicious or ["None detected."],
    }


@cached("logs_info", ttl=3)
def get_logs(filter_text=""):
    out = run_cmd("journalctl -n 100 --no-pager 2>/dev/null")
    if not out:
        out = "journalctl unavailable on this system."
    lines = out.splitlines()
    if filter_text:
        lines = [l for l in lines if filter_text.lower() in l.lower()]
    return lines[-100:]


@cached("wifi_info", ttl=5)
def get_wifi_info():
    iw_out = run_cmd("iwconfig 2>/dev/null") or run_cmd("nmcli -t -f active,ssid,signal,freq,chan,security,rate dev wifi 2>/dev/null")
    if not iw_out:
        return {"available": False, "message": "No wireless interface detected."}
    # Use pipe separator to avoid breaking on SSIDs with colons
    nmcli_out = run_cmd("nmcli --terse --fields active,ssid,signal,freq,chan,security,rate dev wifi 2>/dev/null")
    if nmcli_out:
        for line in nmcli_out.splitlines():
            # nmcli --terse uses colon but escapes embedded colons as \:
            # Split on unescaped colons only
            import re as _re2
            parts = _re2.split(r'(?<!\\):', line)
            parts = [p.replace('\\:', ':') for p in parts]
            if len(parts) >= 7 and parts[0].lower() in ('yes', 'true', '*'):
                return {
                    "available": True,
                    "ssid": parts[1] or "(hidden)",
                    "signal": parts[2] + "%",
                    "frequency": parts[3],
                    "channel": parts[4],
                    "security": parts[5] or "Open",
                    "bitrate": parts[6],
                }
    # fallback: try iw
    iw_ssid = run_cmd("iw dev 2>/dev/null | awk '/Interface/{iface=$2} /ssid/{print iface\":\"+$2}'") or ""
    if iw_ssid:
        return {"available": True, "message": "Connected", "raw": iw_out[:800]}
    return {"available": True, "message": "Wireless interface present; nmcli/iw details unavailable.", "raw": iw_out[:500]}


@cached("hardware_info", ttl=10)
def get_hardware_info():
    cpu_model = run_cmd("lscpu 2>/dev/null | grep 'Model name' | cut -d':' -f2") or platform.processor() or "Unknown"
    mobo = run_cmd("cat /sys/devices/virtual/dmi/id/board_name 2>/dev/null") or "N/A (requires root)"
    bios = run_cmd("cat /sys/devices/virtual/dmi/id/bios_version 2>/dev/null") or "N/A (requires root)"
    serial = run_cmd("cat /sys/devices/virtual/dmi/id/product_serial 2>/dev/null") or "N/A (requires root)"
    storage = []
    for part in safe(lambda: psutil.disk_partitions(), []):
        storage.append(part.device)
    return {
        "cpu_model": cpu_model.strip(),
        "ram_total": bytes_fmt(psutil.virtual_memory().total),
        "motherboard": mobo.strip(),
        "bios": bios.strip(),
        "serial": serial.strip(),
        "storage_devices": storage,
    }


def get_history_point():
    return {
        "time": datetime.datetime.now().strftime("%H:%M:%S"),
        "cpu": safe(lambda: psutil.cpu_percent(interval=None), 0),
        "memory": safe(lambda: psutil.virtual_memory().percent, 0),
        "disk": safe(lambda: psutil.disk_usage("/").percent, 0),
    }


HISTORY = []
HISTORY_LOCK = threading.Lock()
MAX_HISTORY = 60

init_db()


def history_collector():
    while True:
        point = get_history_point()
        net = safe(get_network_info, {})
        point["net_up"] = net.get("upload_speed_raw", 0) if isinstance(net, dict) else 0
        point["net_down"] = net.get("download_speed_raw", 0) if isinstance(net, dict) else 0
        with HISTORY_LOCK:
            HISTORY.append(point)
            if len(HISTORY) > MAX_HISTORY:
                HISTORY.pop(0)
        try:
            with _db_lock:
                conn = get_db()
                conn.execute(
                    "INSERT INTO history VALUES (?,?,?,?,?,?)",
                    (time.time(), point["cpu"], point["memory"], point["disk"],
                     point["net_up"], point["net_down"]))
                conn.commit()
                conn.close()
        except Exception:
            pass
        time.sleep(2)


threading.Thread(target=history_collector, daemon=True).start()


# ---------------- Extended collectors ----------------

@cached("bandwidth_per_proc", ttl=2)
def get_bandwidth_per_process():
    """Approximate per-process bandwidth using io_counters where supported."""
    rows = []
    for p in safe(lambda: psutil.process_iter(["pid", "name"]), []):
        try:
            io = p.io_counters() if hasattr(p, "io_counters") else None
            if io:
                rows.append({
                    "pid": p.info["pid"], "name": p.info["name"],
                    "read_bytes": bytes_fmt(io.read_bytes),
                    "write_bytes": bytes_fmt(io.write_bytes),
                })
        except Exception:
            continue
    return sorted(rows, key=lambda r: r["pid"])[:200]


@cached("usb_devices", ttl=10)
def get_usb_devices():
    out = run_cmd("lsusb 2>/dev/null")
    if not out:
        return [{"info": "lsusb not available or no permission."}]
    devices = []
    for line in out.splitlines():
        devices.append({"info": line.strip()})
    return devices


@cached("pci_devices", ttl=10)
def get_pci_devices():
    out = run_cmd("lspci 2>/dev/null")
    if not out:
        return [{"info": "lspci not available or no permission."}]
    return [{"info": l.strip()} for l in out.splitlines()]


@cached("bluetooth_devices", ttl=10)
def get_bluetooth_devices():
    out = run_cmd("bluetoothctl devices 2>/dev/null")
    if not out:
        return [{"info": "No bluetooth controller detected, or bluetoothctl unavailable."}]
    devices = []
    for line in out.splitlines():
        parts = line.split(" ", 2)
        if len(parts) >= 3:
            devices.append({"mac": parts[1], "name": parts[2]})
    return devices or [{"info": "No paired devices found."}]


@cached("gpu_info", ttl=5)
def get_gpu_info():
    nvidia = run_cmd("nvidia-smi --query-gpu=name,temperature.gpu,memory.used,memory.total,utilization.gpu "
                      "--format=csv,noheader 2>/dev/null")
    if nvidia:
        gpus = []
        for line in nvidia.splitlines():
            parts = [x.strip() for x in line.split(",")]
            if len(parts) >= 5:
                gpus.append({
                    "vendor": "NVIDIA", "name": parts[0], "temperature": parts[1],
                    "vram_used": parts[2], "vram_total": parts[3], "usage": parts[4],
                })
        return gpus
    lspci_gpu = run_cmd("lspci 2>/dev/null | grep -i 'vga\\|3d\\|display'")
    if lspci_gpu:
        return [{"vendor": "Detected", "name": l.strip(), "temperature": "N/A",
                  "vram_used": "N/A", "vram_total": "N/A", "usage": "N/A"} for l in lspci_gpu.splitlines()]
    return [{"info": "No GPU detected."}]


@cached("docker_info", ttl=5)
def get_docker_info():
    if not run_cmd("which docker"):
        return {"available": False, "message": "Docker not installed."}
    containers_raw = run_cmd("docker ps -a --format '{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}' 2>/dev/null")
    images_raw = run_cmd("docker images --format '{{.Repository}}|{{.Tag}}|{{.Size}}' 2>/dev/null")
    containers = []
    for line in containers_raw.splitlines():
        parts = line.split("|")
        if len(parts) >= 5:
            containers.append({"id": parts[0], "name": parts[1], "image": parts[2],
                                "status": parts[3], "ports": parts[4]})
    images = []
    for line in images_raw.splitlines():
        parts = line.split("|")
        if len(parts) >= 3:
            images.append({"repo": parts[0], "tag": parts[1], "size": parts[2]})
    return {"available": True, "containers": containers, "images": images}


VM_INDICATORS = {
    "VirtualBox": "virtualbox",
    "VMware": "vmware",
    "KVM/QEMU": "qemu",
    "Hyper-V": "hyperv",
    "LXC": "lxc",
    "Docker": "docker",
}


@cached("vm_detection", ttl=10)
def get_vm_detection():
    detected = []
    sysvendor = run_cmd("cat /sys/class/dmi/id/sys_vendor 2>/dev/null").lower()
    product = run_cmd("cat /sys/class/dmi/id/product_name 2>/dev/null").lower()
    cgroup = run_cmd("cat /proc/1/cgroup 2>/dev/null").lower()
    combined = sysvendor + " " + product + " " + cgroup
    for label, marker in VM_INDICATORS.items():
        if marker in combined:
            detected.append(label)
    if os.path.exists("/.dockerenv"):
        detected.append("Docker")
    return {"detected": detected or ["Bare metal / not detected"], "raw_vendor": sysvendor or "unknown"}


@cached("cron_jobs", ttl=10)
def get_cron_jobs():
    user_cron = run_cmd("crontab -l 2>/dev/null")
    system_cron = run_cmd("cat /etc/crontab 2>/dev/null")
    return {
        "user": user_cron.splitlines() if user_cron else ["No user crontab."],
        "system": system_cron.splitlines() if system_cron else ["No system crontab access."],
    }


@cached("kernel_modules", ttl=10)
def get_kernel_modules():
    out = run_cmd("lsmod 2>/dev/null")
    if not out:
        return [{"info": "lsmod unavailable."}]
    lines = out.splitlines()[1:]
    return [{"info": l.strip()} for l in lines[:200]]


@cached("installed_packages", ttl=20)
def get_installed_packages():
    out = run_cmd("dpkg -l 2>/dev/null | tail -n +6") or run_cmd("rpm -qa 2>/dev/null")
    if not out:
        return [{"info": "No supported package manager detected (dpkg/rpm)."}]
    return [{"info": l.strip()} for l in out.splitlines()[:500]]


@cached("environment_vars", ttl=30)
def get_environment_vars():
    return [{"key": k, "value": v} for k, v in sorted(os.environ.items())]


def safe_filesystem_listing(path):
    """List a directory's entries with permission/owner/size/modified info."""
    path = os.path.abspath(path or "/")
    entries = []
    try:
        for name in sorted(os.listdir(path)):
            full = os.path.join(path, name)
            try:
                st = os.stat(full)
                entries.append({
                    "name": name,
                    "is_dir": os.path.isdir(full),
                    "size": bytes_fmt(st.st_size) if not os.path.isdir(full) else "-",
                    "permissions": oct(st.st_mode)[-3:],
                    "owner": safe(lambda: __import__("pwd").getpwuid(st.st_uid).pw_name, str(st.st_uid)),
                    "modified": datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                })
            except Exception:
                continue
    except Exception as e:
        return {"path": path, "error": str(e), "entries": []}
    return {"path": path, "entries": entries}


# ---------------- Network tools (input-validated, shell-injection safe) ----------------

import re as _re
IP_RE = _re.compile(r"^[a-zA-Z0-9.\-:]+$")  # hostnames / IPv4 / IPv6, no shell metacharacters


def _valid_target(target: str) -> bool:
    return bool(target) and len(target) < 256 and bool(IP_RE.match(target))


def tool_ping(target):
    if not _valid_target(target):
        return "Invalid target."
    return run_cmd(f"ping -c 4 -W 2 {target}", timeout=10) or "No response / ping unavailable."


def tool_traceroute(target):
    if not _valid_target(target):
        return "Invalid target."
    out = run_cmd(f"traceroute -m 15 {target}", timeout=20)
    return out or run_cmd(f"tracepath {target}", timeout=20) or "traceroute unavailable."


def tool_dns_lookup(target):
    if not _valid_target(target):
        return "Invalid target."
    return run_cmd(f"nslookup {target}", timeout=10) or run_cmd(f"getent hosts {target}", timeout=10) or "DNS lookup failed."


def tool_reverse_dns(target):
    if not _valid_target(target):
        return "Invalid target."
    return run_cmd(f"nslookup {target}", timeout=10) or "Reverse DNS lookup failed."


def tool_whois(target):
    if not _valid_target(target):
        return "Invalid target."
    return run_cmd(f"whois {target}", timeout=10) or "whois not installed or no response."


def tool_port_scan(target, ports="20-1024"):
    if not _valid_target(target):
        return ["Invalid target."]
    if not _re.match(r"^[0-9,\-]+$", ports):
        ports = "20-1024"
    results = []
    try:
        start, end = (ports.split("-") + [ports])[:2]
        start, end = int(start), int(min(int(end), int(start) + 200))  # cap scan size
        for port in range(start, end + 1):
            sock_ = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_.settimeout(0.2)
            result = sock_.connect_ex((target, port))
            if result == 0:
                results.append({"port": port, "state": "open"})
            sock_.close()
    except Exception as e:
        return [{"error": str(e)}]
    return results or [{"info": "No open ports found in range."}]


def tool_subnet_calc(cidr):
    import ipaddress
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return {
            "network": str(net.network_address),
            "broadcast": str(net.broadcast_address) if net.version == 4 else "N/A",
            "netmask": str(net.netmask) if net.version == 4 else "N/A",
            "num_addresses": net.num_addresses,
            "first_host": str(list(net.hosts())[0]) if net.num_addresses > 2 else "N/A",
            "last_host": str(list(net.hosts())[-1]) if net.num_addresses > 2 else "N/A",
            "version": net.version,
        }
    except Exception as e:
        return {"error": str(e)}


def tool_mac_lookup(mac):
    if not _re.match(r"^[0-9A-Fa-f:.\-]{6,17}$", mac or ""):
        return {"error": "Invalid MAC format."}
    prefix = mac.upper().replace("-", ":")[:8]
    return {"mac": mac, "oui_prefix": prefix, "note": "Offline OUI database not bundled; cross-check vendor via IEEE registry."}


def tool_arp_table():
    out = run_cmd("ip neigh 2>/dev/null") or run_cmd("arp -a 2>/dev/null")
    return out.splitlines() if out else ["ARP table unavailable."]


# ---------------- Packet monitor (Scapy, optional) ----------------

PACKET_BUFFER = []
PACKET_LOCK = threading.Lock()
PACKET_CAPTURE_ACTIVE = {"on": False}
_scapy_available = False
try:
    _ensure("scapy", "scapy")
    from scapy.all import sniff, IP, TCP, UDP, ARP, ICMP  # noqa
    _scapy_available = True
except Exception:
    _scapy_available = False


def _packet_callback(pkt):
    if not PACKET_CAPTURE_ACTIVE["on"]:
        return
    try:
        proto, src, dst, length, info = "OTHER", "N/A", "N/A", len(pkt), ""
        if pkt.haslayer(IP):
            src, dst = pkt[IP].src, pkt[IP].dst
            if pkt.haslayer(TCP):
                proto = "TCP"
                info = f"{pkt[TCP].sport} -> {pkt[TCP].dport}"
            elif pkt.haslayer(UDP):
                proto = "UDP"
                info = f"{pkt[UDP].sport} -> {pkt[UDP].dport}"
                if pkt[UDP].dport == 53 or pkt[UDP].sport == 53:
                    proto = "DNS"
            elif pkt.haslayer(ICMP):
                proto = "ICMP"
        elif pkt.haslayer(ARP):
            proto = "ARP"
            src, dst = pkt[ARP].psrc, pkt[ARP].pdst
        with PACKET_LOCK:
            PACKET_BUFFER.append({
                "time": datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3],
                "proto": proto, "src": src, "dst": dst, "length": length, "info": info,
            })
            if len(PACKET_BUFFER) > 300:
                PACKET_BUFFER.pop(0)
    except Exception:
        pass


def _packet_sniff_loop():
    if not _scapy_available:
        return
    try:
        sniff(prn=_packet_callback, store=False,
              stop_filter=lambda x: not PACKET_CAPTURE_ACTIVE["on"], timeout=300)
    except Exception:
        PACKET_CAPTURE_ACTIVE["on"] = False


# ---------------- System power tools ----------------

def system_action(action):
    actions = {
        "lock": "loginctl lock-session 2>/dev/null || xdg-screensaver lock 2>/dev/null",
        "logout": "loginctl terminate-session $XDG_SESSION_ID 2>/dev/null",
        "sleep": "systemctl suspend 2>/dev/null",
        "hibernate": "systemctl hibernate 2>/dev/null",
        "restart": "systemctl reboot 2>/dev/null",
        "shutdown": "systemctl poweroff 2>/dev/null",
    }
    cmd = actions.get(action)
    if not cmd:
        return {"error": "Unknown action."}
    run_cmd(cmd, timeout=3)
    return {"status": f"'{action}' command issued. (Requires sufficient privileges to take effect.)"}


# ============================================================
# API ROUTES
# ============================================================

@app.route("/api/system")
def api_system():
    return jsonify(get_system_info())


@app.route("/api/cpu")
def api_cpu():
    return jsonify(get_cpu_info())


@app.route("/api/memory")
def api_memory():
    return jsonify(get_memory_info())


@app.route("/api/disk")
def api_disk():
    return jsonify(get_disk_info())


@app.route("/api/network")
def api_network():
    return jsonify(get_network_info())


@app.route("/api/connections")
def api_connections():
    return jsonify(get_connections())


@app.route("/api/ports")
def api_ports():
    return jsonify(get_listening_ports())


@app.route("/api/processes")
def api_processes():
    return jsonify(get_processes())


@app.route("/api/users")
def api_users():
    return jsonify(get_logged_users())


@app.route("/api/services")
def api_services():
    return jsonify(get_services())


@app.route("/api/security")
def api_security():
    return jsonify(get_security_info())


@app.route("/api/logs")
def api_logs():
    q = request.args.get("q", "")
    return jsonify(get_logs(q))


@app.route("/api/wifi")
def api_wifi():
    return jsonify(get_wifi_info())


@app.route("/api/hardware")
def api_hardware():
    return jsonify(get_hardware_info())


@app.route("/api/history")
def api_history():
    with HISTORY_LOCK:
        return jsonify(HISTORY)


@app.route("/api/all")
def api_all():
    """Aggregate endpoint used by the dashboard for efficient polling."""
    return jsonify({
        "system": get_system_info(),
        "cpu": get_cpu_info(),
        "memory": get_memory_info(),
        "disk": get_disk_info(),
        "network": get_network_info(),
    })


@app.route("/api/bandwidth")
def api_bandwidth():
    return jsonify(get_bandwidth_per_process())


@app.route("/api/usb")
def api_usb():
    return jsonify(get_usb_devices())


@app.route("/api/pci")
def api_pci():
    return jsonify(get_pci_devices())


@app.route("/api/bluetooth")
def api_bluetooth():
    return jsonify(get_bluetooth_devices())


@app.route("/api/gpu")
def api_gpu():
    return jsonify(get_gpu_info())


@app.route("/api/docker")
def api_docker():
    return jsonify(get_docker_info())


@app.route("/api/vm")
def api_vm():
    return jsonify(get_vm_detection())


@app.route("/api/cron")
def api_cron():
    return jsonify(get_cron_jobs())


@app.route("/api/kernel-modules")
def api_kernel_modules():
    return jsonify(get_kernel_modules())


@app.route("/api/packages")
def api_packages():
    return jsonify(get_installed_packages())


@app.route("/api/environment")
def api_environment():
    return jsonify(get_environment_vars())


@app.route("/api/filesystem")
def api_filesystem():
    path = request.args.get("path", "/")
    return jsonify(safe_filesystem_listing(path))


@app.route("/api/history-db")
def api_history_db():
    """Returns persisted history from SQLite for a given range in minutes."""
    minutes = int(request.args.get("minutes", 60))
    cutoff = time.time() - minutes * 60
    try:
        with _db_lock:
            conn = get_db()
            rows = conn.execute(
                "SELECT ts,cpu,memory,disk,net_up,net_down FROM history WHERE ts >= ? ORDER BY ts ASC",
                (cutoff,)).fetchall()
            conn.close()
        return jsonify([
            {"time": datetime.datetime.fromtimestamp(r[0]).strftime("%H:%M:%S"),
             "cpu": r[1], "memory": r[2], "disk": r[3], "net_up": r[4], "net_down": r[5]}
            for r in rows
        ])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---- Network tools endpoints (read-only, input-validated) ----

@app.route("/api/tools/ping")
def api_tool_ping():
    return jsonify({"result": tool_ping(request.args.get("target", ""))})


@app.route("/api/tools/traceroute")
def api_tool_traceroute():
    return jsonify({"result": tool_traceroute(request.args.get("target", ""))})


@app.route("/api/tools/dns")
def api_tool_dns():
    return jsonify({"result": tool_dns_lookup(request.args.get("target", ""))})


@app.route("/api/tools/rdns")
def api_tool_rdns():
    return jsonify({"result": tool_reverse_dns(request.args.get("target", ""))})


@app.route("/api/tools/whois")
def api_tool_whois():
    return jsonify({"result": tool_whois(request.args.get("target", ""))})


@app.route("/api/tools/portscan")
def api_tool_portscan():
    target = request.args.get("target", "")
    ports = request.args.get("ports", "20-1024")
    return jsonify(tool_port_scan(target, ports))


@app.route("/api/tools/subnet")
def api_tool_subnet():
    return jsonify(tool_subnet_calc(request.args.get("cidr", "192.168.1.0/24")))


@app.route("/api/tools/mac")
def api_tool_mac():
    return jsonify(tool_mac_lookup(request.args.get("mac", "")))


@app.route("/api/tools/arp")
def api_tool_arp():
    return jsonify({"result": tool_arp_table()})


# ---- Packet monitor endpoints ----

@app.route("/api/packets/start")
@require_admin
def api_packets_start():
    if not _scapy_available:
        return jsonify({"error": "Scapy not available or insufficient privileges (requires root)."}), 400
    if not PACKET_CAPTURE_ACTIVE["on"]:
        PACKET_CAPTURE_ACTIVE["on"] = True
        threading.Thread(target=_packet_sniff_loop, daemon=True).start()
    return jsonify({"status": "started"})


@app.route("/api/packets/stop")
@require_admin
def api_packets_stop():
    PACKET_CAPTURE_ACTIVE["on"] = False
    return jsonify({"status": "stopped"})


@app.route("/api/packets/clear")
@require_admin
def api_packets_clear():
    with PACKET_LOCK:
        PACKET_BUFFER.clear()
    return jsonify({"status": "cleared"})


@app.route("/api/packets")
def api_packets():
    proto_filter = request.args.get("proto", "").upper()
    with PACKET_LOCK:
        data = list(PACKET_BUFFER)
    if proto_filter:
        data = [p for p in data if p["proto"] == proto_filter]
    return jsonify({"active": PACKET_CAPTURE_ACTIVE["on"], "available": _scapy_available, "packets": data[-200:]})


# ---- Process management endpoints (admin-protected) ----

@app.route("/api/process/<int:pid>/kill")
@require_admin
def api_process_kill(pid):
    try:
        psutil.Process(pid).terminate()
        return jsonify({"status": f"Terminate signal sent to PID {pid}."})
    except psutil.NoSuchProcess:
        return jsonify({"error": "No such process."}), 404
    except psutil.AccessDenied:
        return jsonify({"error": "Access denied. Insufficient privileges."}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/process/<int:pid>/suspend")
@require_admin
def api_process_suspend(pid):
    try:
        psutil.Process(pid).suspend()
        return jsonify({"status": f"PID {pid} suspended."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/process/<int:pid>/resume")
@require_admin
def api_process_resume(pid):
    try:
        psutil.Process(pid).resume()
        return jsonify({"status": f"PID {pid} resumed."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/process/<int:pid>/priority", methods=["POST"])
@require_admin
def api_process_priority(pid):
    try:
        nice = int(request.json.get("nice", 0)) if request.is_json else int(request.form.get("nice", 0))
        nice = max(-20, min(19, nice))
        psutil.Process(pid).nice(nice)
        return jsonify({"status": f"PID {pid} priority set to {nice}."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/process/<int:pid>/details")
def api_process_details(pid):
    try:
        p = psutil.Process(pid)
        children = [c.pid for c in safe(lambda: p.children(recursive=False), [])]
        files = []
        for f in safe(lambda: p.open_files(), [])[:50]:
            files.append(f.path)
        return jsonify({
            "pid": pid, "name": safe(lambda: p.name(), "N/A"),
            "parent_pid": safe(lambda: p.ppid(), "N/A"),
            "children": children,
            "open_files": files,
            "nice": safe(lambda: p.nice(), "N/A"),
            "cmdline": safe(lambda: " ".join(p.cmdline()), "N/A"),
        })
    except psutil.NoSuchProcess:
        return jsonify({"error": "No such process."}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---- Terminal endpoint (admin-protected, restricted to a safe allowlist-free shell) ----

TERMINAL_BLOCKLIST = ["rm -rf /", ":(){:|:&};:", "mkfs", "dd if=/dev/zero", "> /dev/sda"]


@app.route("/api/terminal", methods=["POST"])
@require_admin
def api_terminal():
    """
    Executes a shell command and returns output. Protected by admin token.
    NOTE: this grants full shell access to whoever holds the admin token --
    only share the token with people you'd trust with a real terminal.
    """
    data = request.get_json(silent=True) or {}
    command = (data.get("command") or "").strip()
    if not command:
        return jsonify({"error": "Empty command."}), 400
    if any(b in command for b in TERMINAL_BLOCKLIST):
        return jsonify({"error": "Command blocked for safety."}), 403
    output = run_cmd(command, timeout=15)
    return jsonify({"output": output or "(no output)"})


# ---- System power controls (admin-protected, require confirm flag) ----

@app.route("/api/system/action", methods=["POST"])
@require_admin
def api_system_action():
    data = request.get_json(silent=True) or {}
    action = data.get("action", "")
    confirmed = bool(data.get("confirm"))
    if not confirmed:
        return jsonify({"error": "Action requires confirm=true."}), 400
    return jsonify(system_action(action))


@app.route("/api/admin-token-check")
def api_admin_token_check():
    """Lets the frontend verify a token without performing any action."""
    token = request.headers.get("X-Admin-Token") or request.args.get("token")
    return jsonify({"valid": token == ADMIN_TOKEN})


@app.route("/api/export/<fmt>")
def api_export(fmt):
    data = {
        "system": get_system_info(),
        "cpu": get_cpu_info(),
        "memory": get_memory_info(),
        "disk": get_disk_info(),
        "network": get_network_info(),
        "processes": get_processes(),
    }
    if fmt == "json":
        return Response(json.dumps(data, indent=2), mimetype="application/json",
                         headers={"Content-Disposition": "attachment;filename=export.json"})
    elif fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["PID", "Name", "CPU%", "Memory%", "Status", "User"])
        for p in data["processes"]:
            writer.writerow([p["pid"], p["name"], p["cpu"], p["memory"], p["status"], p["user"]])
        return Response(buf.getvalue(), mimetype="text/csv",
                         headers={"Content-Disposition": "attachment;filename=processes.csv"})
    elif fmt == "html":
        rows_html = "".join(
            f"<tr><td>{p['pid']}</td><td>{p['name']}</td><td>{p['cpu']}%</td>"
            f"<td>{p['memory']}%</td><td>{p['status']}</td></tr>" for p in data["processes"][:100])
        html = f"""<html><head><title>Vigilon Report</title>
        <style>body{{font-family:Arial;background:#F8F6F0;color:#2b2b2b;padding:20px;}}
        h1{{color:#0B1F3A;}} table{{width:100%;border-collapse:collapse;}}
        th{{background:#0B1F3A;color:white;padding:8px;}} td{{padding:6px;border-bottom:1px solid #ddd;}}
        .gold{{color:#D4AF37;}}</style></head><body>
        <h1>System Monitor <span class="gold">Report</span></h1>
        <p>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <h2>System</h2><pre>{json.dumps(data['system'], indent=2)}</pre>
        <h2>CPU</h2><pre>{json.dumps(data['cpu'], indent=2)}</pre>
        <h2>Memory</h2><pre>{json.dumps(data['memory'], indent=2)}</pre>
        <h2>Top Processes</h2>
        <table><tr><th>PID</th><th>Name</th><th>CPU</th><th>Mem</th><th>Status</th></tr>{rows_html}</table>
        </body></html>"""
        return Response(html, mimetype="text/html",
                         headers={"Content-Disposition": "attachment;filename=report.html"})
    elif fmt == "pdf":
        try:
            _ensure("reportlab", "reportlab")
            from reportlab.pdfgen import canvas as pdf_canvas
            from reportlab.lib.pagesizes import letter
            buf = io.BytesIO()
            c = pdf_canvas.Canvas(buf, pagesize=letter)
            c.setFont("Helvetica-Bold", 16)
            c.drawString(50, 750, "System Monitor Report")
            c.setFont("Helvetica", 9)
            y = 720
            for line in (json.dumps(data["system"], indent=2) + "\n" +
                         json.dumps(data["cpu"], indent=2)).splitlines():
                c.drawString(50, y, line[:110])
                y -= 12
                if y < 50:
                    c.showPage()
                    y = 750
            c.save()
            buf.seek(0)
            return Response(buf.read(), mimetype="application/pdf",
                             headers={"Content-Disposition": "attachment;filename=report.pdf"})
        except Exception as e:
            return jsonify({"error": f"PDF export unavailable: {e}"}), 500
    return jsonify({"error": "Unsupported format"}), 400


# ============================================================
# WEBSOCKET (real-time push, graceful AJAX fallback in frontend)
# ============================================================

if sock:
    @sock.route("/ws/live")
    def ws_live(ws):
        try:
            while True:
                payload = {
                    "system": get_system_info(),
                    "cpu": get_cpu_info(),
                    "memory": get_memory_info(),
                    "disk": get_disk_info(),
                    "network": get_network_info(),
                }
                ws.send(json.dumps(payload))
                time.sleep(2)
        except Exception:
            pass


# ============================================================
# FRONTEND TEMPLATE
# ============================================================

PAGE_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vigilon | System Monitor</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"></script>
<style>
:root{
  --navy:#0B1F3A;
  --navy-light:#142b4f;
  --gold:#D4AF37;
  --gold-soft:#e6c75c;
  --cream:#F8F6F0;
  --charcoal:#2b2b2b;
  --border:#e7e3da;
  --white:#ffffff;
}
*{box-sizing:border-box;}
body{
  font-family:'Inter',sans-serif;
  background:var(--cream);
  color:var(--charcoal);
  margin:0;
  overflow-x:hidden;
  display:flex;
  flex-direction:column;
  min-height:100vh;
}
body > .d-flex{flex:1 1 auto;min-height:0;overflow:hidden;}
.navbar{
  background:var(--navy);
  position:sticky;
  top:0;
  z-index:1000;
  box-shadow:0 2px 12px rgba(0,0,0,.15);
  padding:.4rem 1.25rem;
}
.navbar .brand{
  color:var(--white);
  font-weight:800;
  font-size:1.25rem;
  letter-spacing:.3px;
}
.navbar .brand i{color:var(--gold);margin-right:.5rem;}
#globalSearch{
  border-radius:24px;
  border:1px solid rgba(255,255,255,.2);
  background:rgba(255,255,255,.08);
  color:#fff;
  padding:.4rem 1rem;
}
#globalSearch::placeholder{color:rgba(255,255,255,.6);}
.sidebar{
  position:sticky;
  top:52px;
  height:calc(100vh - 52px);
  overflow-y:auto;
  overflow-x:hidden;
  background:var(--white);
  border-right:1px solid var(--border);
  padding:1rem .6rem;
  flex-shrink:0;
  transition:transform .25s ease;
}
.admin-token-bar{
  display:flex;align-items:center;gap:.4rem;background:rgba(255,255,255,.08);
  border:1px solid rgba(255,255,255,.18);border-radius:24px;padding:.25rem .5rem .25rem .75rem;
}
.admin-token-bar input{
  background:transparent;border:none;color:#fff;font-size:.82rem;width:110px;outline:none;
}
.admin-token-bar input::placeholder{color:rgba(255,255,255,.55);}
.admin-token-bar .btn{padding:.2rem .5rem;border-radius:50%;}
.admin-token-bar .badge-status{margin-left:.2rem;}
.badge-running.pulse{box-shadow:0 0 0 0 rgba(28,138,75,.5);animation:pulseGlow 1.6s infinite;}
@keyframes pulseGlow{0%{box-shadow:0 0 0 0 rgba(28,138,75,.5);}70%{box-shadow:0 0 0 6px rgba(28,138,75,0);}100%{box-shadow:0 0 0 0 rgba(28,138,75,0);}}
.nav-group-label{
  font-size:.7rem;text-transform:uppercase;letter-spacing:.08em;color:#9a9a9a;
  font-weight:700;padding:.9rem .8rem .3rem;
}
.sidebar .nav-link{
  color:var(--charcoal);
  border-radius:10px;
  font-weight:500;
  padding:.55rem .8rem;
  margin-bottom:.15rem;
  display:flex;
  align-items:center;
  gap:.6rem;
  font-size:.92rem;
}
.sidebar .nav-link i{color:var(--navy);width:18px;text-align:center;}
.sidebar .nav-link:hover{background:#f3efe2;}
.sidebar .nav-link.active{
  background:var(--navy);
  color:var(--white);
}
.sidebar .nav-link.active i{color:var(--gold);}
.main-content{padding:1.5rem;overflow-y:auto;min-width:0;}
.card{
  border:1px solid var(--border);
  border-radius:16px;
  box-shadow:0 2px 10px rgba(0,0,0,.04);
  background:var(--white);
  transition:.2s ease;
}
.card:hover{box-shadow:0 6px 18px rgba(0,0,0,.08);}
.stat-card{padding:1.25rem;}
.stat-card .label{font-size:.78rem;color:#7a7a7a;font-weight:600;text-transform:uppercase;letter-spacing:.5px;}
.stat-card .value{font-size:1.8rem;font-weight:800;color:var(--navy);}
.stat-card .icon-wrap{
  width:46px;height:46px;border-radius:12px;
  background:linear-gradient(135deg,var(--navy),var(--navy-light));
  display:flex;align-items:center;justify-content:center;color:var(--gold);font-size:1.2rem;
}
.section-title{
  font-weight:800;color:var(--navy);margin-bottom:1rem;font-size:1.15rem;
  display:flex;align-items:center;gap:.5rem;
}
.section-title i{color:var(--gold);}
.btn-navy{background:var(--navy);border:none;color:#fff;font-weight:600;border-radius:10px;}
.btn-navy:hover{background:var(--navy-light);color:var(--gold);}
.badge-status{padding:.35rem .7rem;border-radius:20px;font-weight:600;font-size:.72rem;}
.badge-running{background:#e3f6e8;color:#1c8a4b;}
.badge-stopped{background:#fdeaea;color:#c0392b;}
.badge-warn{background:#fdf3da;color:#a9791f;}
table.modern{width:100%;border-collapse:separate;border-spacing:0;}
table.modern thead th{
  background:var(--navy);color:#fff;font-weight:600;font-size:.78rem;
  text-transform:uppercase;letter-spacing:.4px;padding:.65rem .8rem;position:sticky;top:0;
}
table.modern tbody tr:nth-child(odd){background:#fbf9f4;}
table.modern tbody tr:hover{background:#f3ecd8;}
table.modern td{padding:.55rem .8rem;font-size:.85rem;border-bottom:1px solid var(--border);}
.table-wrap{max-height:480px;overflow:auto;border-radius:12px;border:1px solid var(--border);}
.progress{height:8px;border-radius:10px;background:#eee;}
.progress-bar{background:linear-gradient(90deg,var(--navy),var(--gold));}
.page-section{display:none;}
.page-section.active{display:block;animation:fadeIn .3s ease;}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px);}to{opacity:1;transform:translateY(0);}}
.skeleton{
  background:linear-gradient(90deg,#eee 25%,#f5f5f5 50%,#eee 75%);
  background-size:200% 100%;
  animation:shimmer 1.4s infinite;
  border-radius:8px;height:14px;
}
@keyframes shimmer{0%{background-position:200% 0;}100%{background-position:-200% 0;}}
.toast-container{z-index:2000;}
footer{
  position:sticky;bottom:0;left:0;width:100%;z-index:500;
  background:var(--navy);color:rgba(255,255,255,.7);padding:.55rem 1rem;
  text-align:center;font-size:.78rem;
}
footer a.gold{color:var(--gold);text-decoration:none;font-weight:600;}
footer a.gold:hover{text-decoration:underline;}
.search-bar{border-radius:10px;border:1px solid var(--border);}
@media (max-width:991px){
  .sidebar{
    position:fixed;left:0;top:52px;width:260px;transform:translateX(-100%);
    z-index:1050;background:#fff;box-shadow:4px 0 18px rgba(0,0,0,.15);
  }
  .sidebar.show{transform:translateX(0);}
  .sidebar-backdrop{
    position:fixed;inset:52px 0 0 0;background:rgba(0,0,0,.35);z-index:1040;display:none;
  }
  .sidebar-backdrop.show{display:block;}
  #globalSearch{max-width:140px;}
  .navbar .brand{font-size:1rem;}
  .navbar .brand span.brand-sub{display:none;}
  .admin-token-bar input{width:70px;}
}
@media (max-width:767px){
  .main-content{padding:.85rem;}
  .stat-card .value{font-size:1.4rem;}
  .stat-card{padding:1rem;}
  .section-title{font-size:1rem;}
  table.modern thead th, table.modern td{padding:.45rem .5rem;font-size:.78rem;}
  .navbar{padding:.6rem .75rem;}
  #globalSearch{display:none;}
  .d-flex.gap-2.flex-wrap .btn{flex:1 1 45%;}
}
@media (max-width:480px){
  .row.g-3 > [class^="col-"]{flex:0 0 100%;max-width:100%;}
}
.spinner-border-sm-gold{color:var(--gold);}
code.small-code{font-size:.75rem;background:#f3efe2;padding:.1rem .4rem;border-radius:6px;}
</style>
</head>
<body>

<nav class="navbar d-flex align-items-center justify-content-between flex-wrap">
  <div class="d-flex align-items-center gap-3">
    <button class="btn btn-sm btn-outline-light d-lg-none" onclick="document.querySelector('.sidebar').classList.toggle('show'); document.getElementById('sidebarBackdrop').classList.toggle('show');">
      <i class="bi bi-list"></i>
    </button>
    <span class="brand"><i class="bi bi-hexagon-fill"></i>Vigilon</span>
  </div>
  <div class="flex-grow-1 mx-3" style="max-width:360px;">
    <input id="globalSearch" class="form-control" placeholder="Search current page..." oninput="globalSearch(this.value)">
  </div>
  <div class="d-flex align-items-center gap-2">
    <div class="admin-token-bar">
      <i class="bi bi-key-fill" style="color:#D4AF37;"></i>
      <input id="navTokenInput" type="password" placeholder="Admin token" autocomplete="off">
      <button class="btn btn-sm btn-navy" onclick="submitAdminToken()" title="Save &amp; verify token"><i class="bi bi-check2"></i></button>
      <span id="adminStatusPill" class="badge-status badge-stopped">Locked</span>
    </div>
    <span class="text-white-50 small d-none d-md-inline" id="clock"></span>
    <span class="badge bg-success"><i class="bi bi-circle-fill" style="font-size:.5rem;"></i> Live</span>
  </div>
</nav>

<div class="sidebar-backdrop" id="sidebarBackdrop" onclick="document.querySelector('.sidebar').classList.remove('show'); this.classList.remove('show');"></div>
<div class="d-flex">
  <div class="sidebar">
    <ul class="nav flex-column" id="sideNav">
      <li class="nav-group-label">Overview</li>
      <li><a class="nav-link active" data-page="dashboard" href="#"><i class="bi bi-speedometer2"></i>Dashboard</a></li>
      <li><a class="nav-link" data-page="system" href="#"><i class="bi bi-pc-display"></i>System</a></li>

      <li class="nav-group-label">Performance</li>
      <li><a class="nav-link" data-page="cpu" href="#"><i class="bi bi-cpu"></i>CPU</a></li>
      <li><a class="nav-link" data-page="memory" href="#"><i class="bi bi-memory"></i>Memory</a></li>
      <li><a class="nav-link" data-page="disk" href="#"><i class="bi bi-hdd"></i>Disk</a></li>
      <li><a class="nav-link" data-page="processes" href="#"><i class="bi bi-list-task"></i>Processes</a></li>
      <li><a class="nav-link" data-page="bandwidth" href="#"><i class="bi bi-speedometer"></i>Bandwidth</a></li>

      <li class="nav-group-label">Network</li>
      <li><a class="nav-link" data-page="network" href="#"><i class="bi bi-ethernet"></i>Network</a></li>
      <li><a class="nav-link" data-page="connections" href="#"><i class="bi bi-diagram-3"></i>Connections</a></li>
      <li><a class="nav-link" data-page="ports" href="#"><i class="bi bi-plug"></i>Ports</a></li>
      <li><a class="nav-link" data-page="packets" href="#"><i class="bi bi-broadcast-pin"></i>Packet Monitor</a></li>
      <li><a class="nav-link" data-page="nettools" href="#"><i class="bi bi-tools"></i>Network Tools</a></li>
      <li><a class="nav-link" data-page="netmap" href="#"><i class="bi bi-diagram-2"></i>Network Map</a></li>
      <li><a class="nav-link" data-page="wifi" href="#"><i class="bi bi-wifi"></i>WiFi</a></li>

      <li class="nav-group-label">Security &amp; Logs</li>
      <li><a class="nav-link" data-page="security" href="#"><i class="bi bi-shield-lock"></i>Security</a></li>
      <li><a class="nav-link" data-page="logs" href="#"><i class="bi bi-journal-text"></i>Logs</a></li>
      <li><a class="nav-link" data-page="services" href="#"><i class="bi bi-gear"></i>Services</a></li>
      <li><a class="nav-link" data-page="cron" href="#"><i class="bi bi-alarm"></i>Cron Jobs</a></li>

      <li class="nav-group-label">Hardware &amp; Devices</li>
      <li><a class="nav-link" data-page="hardware" href="#"><i class="bi bi-motherboard"></i>Hardware</a></li>
      <li><a class="nav-link" data-page="usb" href="#"><i class="bi bi-usb-symbol"></i>USB</a></li>
      <li><a class="nav-link" data-page="pci" href="#"><i class="bi bi-cpu-fill"></i>PCI</a></li>
      <li><a class="nav-link" data-page="bluetooth" href="#"><i class="bi bi-bluetooth"></i>Bluetooth</a></li>
      <li><a class="nav-link" data-page="gpu" href="#"><i class="bi bi-gpu-card"></i>GPU</a></li>

      <li class="nav-group-label">Platform</li>
      <li><a class="nav-link" data-page="docker" href="#"><i class="bi bi-box-seam"></i>Docker</a></li>
      <li><a class="nav-link" data-page="vm" href="#"><i class="bi bi-display"></i>Virtual Machines</a></li>
      <li><a class="nav-link" data-page="environment" href="#"><i class="bi bi-braces"></i>Environment</a></li>
      <li><a class="nav-link" data-page="kernel" href="#"><i class="bi bi-layers"></i>Kernel Modules</a></li>
      <li><a class="nav-link" data-page="packagesPage" href="#"><i class="bi bi-archive"></i>Installed Packages</a></li>
      <li><a class="nav-link" data-page="filesystem" href="#"><i class="bi bi-folder2-open"></i>Filesystem</a></li>

      <li class="nav-group-label">Admin Tools <i class="bi bi-lock-fill"></i></li>
      <li><a class="nav-link" data-page="terminal" href="#"><i class="bi bi-terminal"></i>Terminal</a></li>
      <li><a class="nav-link" data-page="systools" href="#"><i class="bi bi-power"></i>System Tools</a></li>

      <li class="nav-group-label">App</li>
      <li><a class="nav-link" data-page="export" href="#"><i class="bi bi-download"></i>Export</a></li>
      <li><a class="nav-link" data-page="settings" href="#"><i class="bi bi-sliders"></i>Settings</a></li>
    </ul>
  </div>

  <div class="main-content flex-grow-1">

    <!-- DASHBOARD -->
    <div class="page-section active" id="page-dashboard">
      <div class="section-title"><i class="bi bi-speedometer2"></i>Overview</div>
      <div class="row g-3 mb-3">
        <div class="col-md-3"><div class="card stat-card d-flex flex-row align-items-center justify-content-between">
          <div><div class="label">CPU Usage</div><div class="value" id="d-cpu">--%</div></div>
          <div class="icon-wrap"><i class="bi bi-cpu"></i></div>
        </div></div>
        <div class="col-md-3"><div class="card stat-card d-flex flex-row align-items-center justify-content-between">
          <div><div class="label">Memory Usage</div><div class="value" id="d-mem">--%</div></div>
          <div class="icon-wrap"><i class="bi bi-memory"></i></div>
        </div></div>
        <div class="col-md-3"><div class="card stat-card d-flex flex-row align-items-center justify-content-between">
          <div><div class="label">Disk Usage</div><div class="value" id="d-disk">--%</div></div>
          <div class="icon-wrap"><i class="bi bi-hdd"></i></div>
        </div></div>
        <div class="col-md-3"><div class="card stat-card d-flex flex-row align-items-center justify-content-between">
          <div><div class="label">Uptime</div><div class="value" style="font-size:1.1rem;" id="d-uptime">--</div></div>
          <div class="icon-wrap"><i class="bi bi-clock-history"></i></div>
        </div></div>
      </div>
      <div class="row g-3">
        <div class="col-lg-8"><div class="card p-3">
          <div class="section-title"><i class="bi bi-graph-up"></i>Resource History</div>
          <canvas id="historyChart" height="110"></canvas>
        </div></div>
        <div class="col-lg-4"><div class="card p-3">
          <div class="section-title"><i class="bi bi-router"></i>Network Speed</div>
          <div class="d-flex justify-content-between mb-2"><span><i class="bi bi-arrow-up text-success"></i> Upload</span><strong id="d-up">--</strong></div>
          <div class="d-flex justify-content-between mb-3"><span><i class="bi bi-arrow-down text-primary"></i> Download</span><strong id="d-down">--</strong></div>
          <canvas id="netChart" height="120"></canvas>
        </div></div>
      </div>
    </div>

    <!-- SYSTEM -->
    <div class="page-section" id="page-system">
      <div class="section-title"><i class="bi bi-pc-display"></i>System Information</div>
      <div class="card p-3"><div class="table-wrap"><table class="modern" id="systemTable"><tbody></tbody></table></div></div>
    </div>

    <!-- CPU -->
    <div class="page-section" id="page-cpu">
      <div class="section-title"><i class="bi bi-cpu"></i>CPU Details</div>
      <div class="row g-3 mb-3" id="cpuStats"></div>
      <div class="card p-3 mb-3">
        <div class="section-title"><i class="bi bi-bar-chart"></i>Per-Core Usage</div>
        <div id="coreBars"></div>
      </div>
    </div>

    <!-- MEMORY -->
    <div class="page-section" id="page-memory">
      <div class="section-title"><i class="bi bi-memory"></i>Memory Details</div>
      <div class="row g-3" id="memStats"></div>
    </div>

    <!-- DISK -->
    <div class="page-section" id="page-disk">
      <div class="section-title"><i class="bi bi-hdd"></i>Disk Partitions</div>
      <div class="card p-3"><div class="table-wrap"><table class="modern">
        <thead><tr><th>Device</th><th>Mount</th><th>FS</th><th>Used</th><th>Total</th><th>Usage</th></tr></thead>
        <tbody id="diskTable"></tbody></table></div></div>
      <div class="card p-3 mt-3" id="diskIO"></div>
    </div>

    <!-- NETWORK -->
    <div class="page-section" id="page-network">
      <div class="section-title"><i class="bi bi-ethernet"></i>Network Interfaces</div>
      <div class="card p-3 mb-3"><div class="table-wrap"><table class="modern">
        <thead><tr><th>Interface</th><th>IPv4</th><th>IPv6</th><th>MAC</th><th>MTU</th><th>Speed</th><th>Status</th></tr></thead>
        <tbody id="netTable"></tbody></table></div></div>
      <div class="card p-3" id="netExtra"></div>
    </div>

    <!-- CONNECTIONS -->
    <div class="page-section" id="page-connections">
      <div class="section-title"><i class="bi bi-diagram-3"></i>Active Connections</div>
      <input class="form-control search-bar mb-2" placeholder="Filter connections..." oninput="filterTable('connTable', this.value)">
      <div class="card p-3"><div class="table-wrap"><table class="modern">
        <thead><tr><th>Proto</th><th>Family</th><th>Local</th><th>Remote</th><th>Status</th><th>PID</th><th>Process</th><th>User</th></tr></thead>
        <tbody id="connTable"></tbody></table></div></div>
    </div>

    <!-- PROCESSES -->
    <div class="page-section" id="page-processes">
      <div class="section-title"><i class="bi bi-list-task"></i>Running Processes</div>
      <input class="form-control search-bar mb-2" placeholder="Filter processes..." oninput="filterTable('procTable', this.value)">
      <div class="card p-3"><div class="table-wrap"><table class="modern">
        <thead><tr><th>PID</th><th>Name</th><th>CPU%</th><th>Mem%</th><th>Threads</th><th>Status</th><th>User</th><th>Created</th><th>Actions</th></tr></thead>
        <tbody id="procTable"></tbody></table></div></div>
    </div>

    <!-- PORTS -->
    <div class="page-section" id="page-ports">
      <div class="section-title"><i class="bi bi-plug"></i>Listening Ports</div>
      <div class="card p-3"><div class="table-wrap"><table class="modern">
        <thead><tr><th>Port</th><th>Protocol</th><th>Address</th><th>Program</th><th>PID</th></tr></thead>
        <tbody id="portsTable"></tbody></table></div></div>
    </div>

    <!-- LOGS -->
    <div class="page-section" id="page-logs">
      <div class="section-title"><i class="bi bi-journal-text"></i>Recent Logs</div>
      <input class="form-control search-bar mb-2" id="logFilter" placeholder="Search logs..." onkeyup="if(event.key==='Enter') loadLogs()">
      <div class="card p-3"><pre id="logsBox" style="max-height:480px;overflow:auto;white-space:pre-wrap;font-size:.78rem;"></pre></div>
    </div>

    <!-- SERVICES -->
    <div class="page-section" id="page-services">
      <div class="section-title"><i class="bi bi-gear"></i>Services</div>
      <div class="card p-3"><div class="table-wrap"><table class="modern">
        <thead><tr><th>Service</th><th>State</th></tr></thead><tbody id="svcTable"></tbody></table></div></div>
      <div class="section-title mt-4"><i class="bi bi-person-check"></i>Logged In Users</div>
      <div class="card p-3"><div class="table-wrap"><table class="modern">
        <thead><tr><th>User</th><th>Terminal</th><th>Host</th><th>Started</th></tr></thead><tbody id="usersTable"></tbody></table></div></div>
    </div>

    <!-- SECURITY -->
    <div class="page-section" id="page-security">
      <div class="section-title"><i class="bi bi-shield-lock"></i>Security Overview</div>
      <div class="row g-3">
        <div class="col-md-12"><div class="card p-3" id="secFirewall"></div></div>
        <div class="col-md-6"><div class="card p-3"><strong>Failed SSH Attempts</strong><pre id="secSSH" style="font-size:.75rem;max-height:260px;overflow:auto;"></pre></div></div>
        <div class="col-md-6"><div class="card p-3"><strong>Suspicious Processes</strong><pre id="secSuspicious" style="font-size:.78rem;"></pre></div></div>
      </div>
    </div>

    <!-- HARDWARE -->
    <div class="page-section" id="page-hardware">
      <div class="section-title"><i class="bi bi-motherboard"></i>Hardware Information</div>
      <div class="card p-3"><div class="table-wrap"><table class="modern" id="hwTable"><tbody></tbody></table></div></div>
    </div>

    <!-- PACKET MONITOR -->
    <div class="page-section" id="page-packets">
      <div class="section-title"><i class="bi bi-broadcast-pin"></i>Packet Monitor</div>
      <div class="card p-2 mb-2" id="packetAvailabilityNotice" style="display:none;background:#fdf3da;color:#a9791f;font-size:.82rem;"></div>
      <div class="card p-3 mb-3 d-flex flex-row gap-2 align-items-center flex-wrap">
        <button class="btn btn-navy btn-sm" id="packetStartBtn" onclick="packetStart()"><i class="bi bi-play-fill"></i> Start</button>
        <button class="btn btn-outline-secondary btn-sm" onclick="packetStop()"><i class="bi bi-stop-fill"></i> Stop</button>
        <button class="btn btn-outline-secondary btn-sm" onclick="packetClear()"><i class="bi bi-trash"></i> Clear</button>
        <select class="form-select form-select-sm" style="width:160px;" id="packetFilter" onchange="loadPackets()">
          <option value="">All Protocols</option>
          <option value="TCP">TCP</option><option value="UDP">UDP</option>
          <option value="DNS">DNS</option><option value="ARP">ARP</option><option value="ICMP">ICMP</option>
        </select>
        <span class="badge bg-secondary small" id="packetStatus">checking...</span>
      </div>
      <div class="card p-3"><div class="table-wrap"><table class="modern">
        <thead><tr><th>Time</th><th>Protocol</th><th>Source</th><th>Destination</th><th>Length</th><th>Info</th></tr></thead>
        <tbody id="packetsTable"></tbody></table></div></div>
    </div>

    <!-- BANDWIDTH -->
    <div class="page-section" id="page-bandwidth">
      <div class="section-title"><i class="bi bi-speedometer"></i>Bandwidth Per Process</div>
      <div class="card p-3"><div class="table-wrap"><table class="modern">
        <thead><tr><th>PID</th><th>Name</th><th>Read</th><th>Write</th></tr></thead>
        <tbody id="bwTable"></tbody></table></div></div>
    </div>

    <!-- NETWORK TOOLS -->
    <div class="page-section" id="page-nettools">
      <div class="section-title"><i class="bi bi-tools"></i>Network Tools</div>
      <div class="row g-3">
        <div class="col-md-6"><div class="card p-3">
          <label class="form-label fw-bold">Target (host/IP)</label>
          <input class="form-control mb-2" id="toolTarget" placeholder="example.com">
          <div class="d-flex gap-2 flex-wrap">
            <button class="btn btn-navy btn-sm" onclick="runTool('ping')">Ping</button>
            <button class="btn btn-navy btn-sm" onclick="runTool('traceroute')">Traceroute</button>
            <button class="btn btn-navy btn-sm" onclick="runTool('dns')">DNS Lookup</button>
            <button class="btn btn-navy btn-sm" onclick="runTool('rdns')">Reverse DNS</button>
            <button class="btn btn-navy btn-sm" onclick="runTool('whois')">Whois</button>
          </div>
        </div></div>
        <div class="col-md-6"><div class="card p-3">
          <label class="form-label fw-bold">Port Scan (cap 200 ports/scan)</label>
          <input class="form-control mb-2" id="scanRange" placeholder="20-1024" value="20-1024">
          <button class="btn btn-navy btn-sm" onclick="runPortScan()">Scan</button>
        </div></div>
        <div class="col-md-6"><div class="card p-3">
          <label class="form-label fw-bold">Subnet / CIDR Calculator</label>
          <input class="form-control mb-2" id="cidrInput" placeholder="192.168.1.0/24" value="192.168.1.0/24">
          <button class="btn btn-navy btn-sm" onclick="runSubnet()">Calculate</button>
        </div></div>
        <div class="col-md-6"><div class="card p-3">
          <label class="form-label fw-bold">ARP Table</label>
          <button class="btn btn-navy btn-sm" onclick="runArp()">Show ARP Table</button>
        </div></div>
      </div>
      <div class="card p-3 mt-3"><pre id="toolOutput" style="white-space:pre-wrap;font-size:.8rem;max-height:340px;overflow:auto;">Results will appear here.</pre></div>
    </div>

    <!-- NETWORK MAP -->
    <div class="page-section" id="page-netmap">
      <div class="section-title"><i class="bi bi-diagram-2"></i>Network Topology</div>
      <div class="card p-4 text-center" id="netmapBox">
        <div class="mb-3"><i class="bi bi-cloud" style="font-size:2rem;color:#0B1F3A;"></i><div>Internet</div></div>
        <div>&darr;</div>
        <div class="mb-3 mt-2"><i class="bi bi-router" style="font-size:2rem;color:#D4AF37;"></i><div id="mapGateway">Gateway</div></div>
        <div>&darr;</div>
        <div class="mb-3 mt-2"><i class="bi bi-pc-display" style="font-size:2rem;color:#0B1F3A;"></i><div id="mapLocal">Local Machine</div></div>
        <div>&darr;</div>
        <div id="mapDevices" class="small text-muted">Connected devices appear here based on ARP table.</div>
      </div>
    </div>

    <!-- USB -->
    <div class="page-section" id="page-usb">
      <div class="section-title"><i class="bi bi-usb-symbol"></i>USB Devices</div>
      <div class="card p-3"><pre id="usbBox" style="white-space:pre-wrap;font-size:.82rem;"></pre></div>
    </div>

    <!-- PCI -->
    <div class="page-section" id="page-pci">
      <div class="section-title"><i class="bi bi-cpu-fill"></i>PCI Devices</div>
      <div class="card p-3"><pre id="pciBox" style="white-space:pre-wrap;font-size:.82rem;max-height:480px;overflow:auto;"></pre></div>
    </div>

    <!-- BLUETOOTH -->
    <div class="page-section" id="page-bluetooth">
      <div class="section-title"><i class="bi bi-bluetooth"></i>Bluetooth Devices</div>
      <div class="card p-3"><div class="table-wrap"><table class="modern">
        <thead><tr><th>MAC</th><th>Name</th></tr></thead><tbody id="btTable"></tbody></table></div></div>
    </div>

    <!-- GPU -->
    <div class="page-section" id="page-gpu">
      <div class="section-title"><i class="bi bi-gpu-card"></i>GPU Information</div>
      <div class="row g-3" id="gpuCards"></div>
    </div>

    <!-- DOCKER -->
    <div class="page-section" id="page-docker">
      <div class="section-title"><i class="bi bi-box-seam"></i>Docker</div>
      <div class="card p-3 mb-3"><div class="table-wrap"><table class="modern">
        <thead><tr><th>ID</th><th>Name</th><th>Image</th><th>Status</th><th>Ports</th></tr></thead>
        <tbody id="dockerContainers"></tbody></table></div></div>
      <div class="section-title"><i class="bi bi-images"></i>Images</div>
      <div class="card p-3"><div class="table-wrap"><table class="modern">
        <thead><tr><th>Repo</th><th>Tag</th><th>Size</th></tr></thead><tbody id="dockerImages"></tbody></table></div></div>
    </div>

    <!-- VM -->
    <div class="page-section" id="page-vm">
      <div class="section-title"><i class="bi bi-display"></i>Virtual Machine Detection</div>
      <div class="card p-3" id="vmBox"></div>
    </div>

    <!-- ENVIRONMENT -->
    <div class="page-section" id="page-environment">
      <div class="section-title"><i class="bi bi-braces"></i>Environment Variables</div>
      <input class="form-control search-bar mb-2" placeholder="Filter..." oninput="filterTable('envTable', this.value)">
      <div class="card p-3"><div class="table-wrap"><table class="modern">
        <thead><tr><th>Key</th><th>Value</th></tr></thead><tbody id="envTable"></tbody></table></div></div>
    </div>

    <!-- CRON -->
    <div class="page-section" id="page-cron">
      <div class="section-title"><i class="bi bi-alarm"></i>Cron Jobs</div>
      <div class="row g-3">
        <div class="col-md-6"><div class="card p-3"><strong>User Crontab</strong><pre id="cronUser" style="font-size:.8rem;"></pre></div></div>
        <div class="col-md-6"><div class="card p-3"><strong>System Crontab</strong><pre id="cronSystem" style="font-size:.8rem;"></pre></div></div>
      </div>
    </div>

    <!-- KERNEL MODULES -->
    <div class="page-section" id="page-kernel">
      <div class="section-title"><i class="bi bi-layers"></i>Kernel Modules</div>
      <input class="form-control search-bar mb-2" placeholder="Filter..." oninput="filterTable('kernelTable', this.value)">
      <div class="card p-3"><div class="table-wrap"><table class="modern"><tbody id="kernelTable"></tbody></table></div></div>
    </div>

    <!-- INSTALLED PACKAGES -->
    <div class="page-section" id="page-packagesPage">
      <div class="section-title"><i class="bi bi-archive"></i>Installed Packages</div>
      <input class="form-control search-bar mb-2" placeholder="Filter..." oninput="filterTable('pkgTable', this.value)">
      <div class="card p-3"><div class="table-wrap"><table class="modern"><tbody id="pkgTable"></tbody></table></div></div>
    </div>

    <!-- FILESYSTEM -->
    <div class="page-section" id="page-filesystem">
      <div class="section-title"><i class="bi bi-folder2-open"></i>Filesystem Browser</div>
      <div class="d-flex gap-2 mb-2">
        <input class="form-control" id="fsPath" value="/" placeholder="/path/to/dir">
        <button class="btn btn-navy" onclick="loadFilesystem()">Go</button>
      </div>
      <div class="card p-3"><div class="table-wrap"><table class="modern">
        <thead><tr><th>Name</th><th>Type</th><th>Size</th><th>Permissions</th><th>Owner</th><th>Modified</th></tr></thead>
        <tbody id="fsTable"></tbody></table></div></div>
    </div>

    <!-- TERMINAL -->
    <div class="page-section" id="page-terminal">
      <div class="section-title"><i class="bi bi-terminal"></i>Embedded Terminal</div>
      <div class="card p-2 mb-2">
        <div class="d-flex gap-2">
          <input class="form-control" id="adminTokenInput" placeholder="Paste admin token shown in server console...">
          <button class="btn btn-navy" onclick="document.getElementById('navTokenInput').value=document.getElementById('adminTokenInput').value; submitAdminToken();"><i class="bi bi-check2"></i> Save &amp; Verify</button>
        </div>
        <div class="small text-muted mt-1">Required for terminal, process kill, and power actions. Token is printed in your <strong>server console</strong> on startup. Status: <span id="terminalTokenStatus">check navbar pill</span></div>
      </div>
      <div class="card p-3" style="background:#0B1F3A;color:#e9e6da;border-radius:14px;">
        <pre id="terminalOutput" style="height:320px;overflow:auto;font-size:.82rem;margin:0;"></pre>
        <div class="d-flex gap-2 mt-2">
          <span style="color:#D4AF37;">$</span>
          <input class="form-control bg-transparent text-white border-0" id="terminalInput" style="outline:none;box-shadow:none;" onkeyup="if(event.key==='Enter') runTerminal()">
        </div>
      </div>
    </div>

    <!-- SYSTEM TOOLS -->
    <div class="page-section" id="page-systools">
      <div class="section-title"><i class="bi bi-power"></i>System Power Controls</div>
      <div class="card p-4 d-flex gap-2 flex-wrap">
        <button class="btn btn-outline-secondary" onclick="systemAction('lock')"><i class="bi bi-lock"></i> Lock</button>
        <button class="btn btn-outline-secondary" onclick="systemAction('sleep')"><i class="bi bi-moon"></i> Sleep</button>
        <button class="btn btn-outline-secondary" onclick="systemAction('hibernate')"><i class="bi bi-snow"></i> Hibernate</button>
        <button class="btn btn-outline-secondary" onclick="systemAction('logout')"><i class="bi bi-box-arrow-right"></i> Logout</button>
        <button class="btn btn-outline-danger" onclick="systemAction('restart')"><i class="bi bi-arrow-clockwise"></i> Restart</button>
        <button class="btn btn-outline-danger" onclick="systemAction('shutdown')"><i class="bi bi-power"></i> Shutdown</button>
      </div>
      <p class="small text-muted mt-2">Requires admin token (Settings/Terminal) and a confirmation dialog. Actions require sufficient OS-level privileges to actually take effect.</p>
    </div>

    <!-- WIFI -->
    <div class="page-section" id="page-wifi">
      <div class="section-title"><i class="bi bi-wifi"></i>Wireless Network</div>
      <div class="card p-3" id="wifiBox"></div>
    </div>

    <!-- EXPORT -->
    <div class="page-section" id="page-export">
      <div class="section-title"><i class="bi bi-download"></i>Export Data</div>
      <div class="card p-4 d-flex gap-3 flex-wrap">
        <a class="btn btn-navy" href="/api/export/json"><i class="bi bi-filetype-json"></i> Export JSON</a>
        <a class="btn btn-navy" href="/api/export/csv"><i class="bi bi-filetype-csv"></i> Export CSV</a>
        <a class="btn btn-navy" href="/api/export/html"><i class="bi bi-filetype-html"></i> Export HTML Report</a>
        <a class="btn btn-navy" href="/api/export/pdf"><i class="bi bi-filetype-pdf"></i> Export PDF</a>
      </div>
    </div>

    <!-- SETTINGS -->
    <div class="page-section" id="page-settings">
      <div class="section-title"><i class="bi bi-sliders"></i>Settings</div>
      <div class="card p-4">
        <label class="form-label fw-bold">Refresh Interval (seconds)</label>
        <input type="range" min="1" max="10" value="2" class="form-range" id="refreshRange" oninput="setRefresh(this.value)">
        <div class="small text-muted mb-3">Current: <span id="refreshVal">2</span>s</div>
        <label class="form-label fw-bold">Admin Token</label>
        <div class="d-flex gap-2 mb-1">
          <input class="form-control" id="settingsTokenInput" placeholder="Paste admin token from server console">
          <button class="btn btn-navy" onclick="document.getElementById('navTokenInput').value=document.getElementById('settingsTokenInput').value; submitAdminToken();"><i class="bi bi-check2"></i> Save &amp; Verify</button>
        </div>
        <div class="small text-muted mb-3">Status is shown as a pill next to the search bar in the top navbar.</div>
        <div class="form-check form-switch mb-3">
          <input class="form-check-input" type="checkbox" id="notifToggle" checked onchange="saveSetting('notif', this.checked)">
          <label class="form-check-label" for="notifToggle">Enable alert notifications (CPU/RAM/Disk thresholds)</label>
        </div>
        <hr>
        <p class="small text-muted mb-0"><strong>About:</strong> Vigilon &mdash; a single-file Flask + psutil monitoring tool with optional WebSocket live feed, SQLite history, packet capture, network tools, and admin-protected controls. Built for enterprise-grade visibility into Linux systems.</p>
      </div>
    </div>

  </div>
</div>

<footer>Built by <a href="https://admin.xo.je" target="_blank" rel="noopener" class="gold">Vineet Pratap Singh</a> &copy; <span id="year"></span></footer>

<div class="toast-container position-fixed bottom-0 end-0 p-3">
  <div id="liveToast" class="toast align-items-center text-bg-dark" role="alert">
    <div class="d-flex">
      <div class="toast-body" id="toastBody">Updated</div>
      <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
    </div>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script>
const _yearEl = document.getElementById('year');
if (_yearEl) _yearEl.textContent = new Date().getFullYear();
let REFRESH_MS = 2000;
let refreshTimer = null;

function setRefresh(v){
  REFRESH_MS = parseInt(v) * 1000;
  document.getElementById('refreshVal').textContent = v;
  clearInterval(refreshTimer);
  refreshTimer = setInterval(tick, REFRESH_MS);
}

function tickClock(){
  document.getElementById('clock').textContent = new Date().toLocaleString();
}
setInterval(tickClock, 1000); tickClock();

// Navigation
document.querySelectorAll('#sideNav .nav-link').forEach(link => {
  link.addEventListener('click', e => {
    e.preventDefault();
    document.querySelectorAll('#sideNav .nav-link').forEach(l => l.classList.remove('active'));
    link.classList.add('active');
    document.querySelectorAll('.page-section').forEach(p => p.classList.remove('active'));
    document.getElementById('page-' + link.dataset.page).classList.add('active');
    document.querySelector('.sidebar').classList.remove('show');
    document.getElementById('sidebarBackdrop').classList.remove('show');
    loadPageData(link.dataset.page);
  });
});

function escapeHtml(s){
  if (s === null || s === undefined) return 'N/A';
  return String(s).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
}

let historyChart, netChart;
function initCharts(){
  const ctx1 = document.getElementById('historyChart').getContext('2d');
  historyChart = new Chart(ctx1, {
    type: 'line',
    data: { labels: [], datasets: [
      {label:'CPU %', data: [], borderColor:'#0B1F3A', backgroundColor:'rgba(11,31,58,.08)', tension:.35, fill:true},
      {label:'Memory %', data: [], borderColor:'#D4AF37', backgroundColor:'rgba(212,175,55,.12)', tension:.35, fill:true},
      {label:'Disk %', data: [], borderColor:'#8a8a8a', tension:.35}
    ]},
    options: { responsive:true, animation:{duration:400}, scales:{y:{min:0,max:100}}, plugins:{legend:{position:'bottom'}} }
  });
  const ctx2 = document.getElementById('netChart').getContext('2d');
  netChart = new Chart(ctx2, {
    type:'bar',
    data:{labels:['Up','Down'], datasets:[{label:'KB/s', data:[0,0], backgroundColor:['#1c8a4b','#0B1F3A']}]},
    options:{responsive:true, plugins:{legend:{display:false}}}
  });
}

async function fetchJSON(url){
  try{
    const r = await fetch(url);
    return await r.json();
  }catch(e){ return null; }
}

function badge(state){
  const s = (state||'').toLowerCase();
  if (s.includes('active') || s.includes('running')) return `<span class="badge-status badge-running">${escapeHtml(state)}</span>`;
  if (s.includes('fail')) return `<span class="badge-status badge-stopped">${escapeHtml(state)}</span>`;
  return `<span class="badge-status badge-warn">${escapeHtml(state)}</span>`;
}

async function loadDashboard(){
  const all = await fetchJSON('/api/all');
  if (!all) return;
  document.getElementById('d-cpu').textContent = all.cpu.usage.toFixed(1) + '%';
  document.getElementById('d-mem').textContent = all.memory.percent.toFixed(1) + '%';
  const diskPct = all.disk.partitions.find(p=>p.mountpoint==='/') || all.disk.partitions[0];
  document.getElementById('d-disk').textContent = diskPct ? diskPct.percent.toFixed(1) + '%' : 'N/A';
  document.getElementById('d-uptime').textContent = all.system.uptime;
  document.getElementById('d-up').textContent = all.network.upload_speed;
  document.getElementById('d-down').textContent = all.network.download_speed;

  if (netChart){
    netChart.data.datasets[0].data = [
      (all.network.upload_speed_raw/1024).toFixed(1),
      (all.network.download_speed_raw/1024).toFixed(1)
    ];
    netChart.update();
  }

  const hist = await fetchJSON('/api/history');
  if (hist && historyChart){
    historyChart.data.labels = hist.map(h=>h.time);
    historyChart.data.datasets[0].data = hist.map(h=>h.cpu);
    historyChart.data.datasets[1].data = hist.map(h=>h.memory);
    historyChart.data.datasets[2].data = hist.map(h=>h.disk);
    historyChart.update();
  }
}

async function loadSystem(){
  const d = await fetchJSON('/api/system');
  if (!d) return;
  const rows = Object.entries(d).map(([k,v]) =>
    `<tr><td style="width:220px;font-weight:600;color:#0B1F3A;">${escapeHtml(k.replace(/_/g,' ').toUpperCase())}</td><td>${escapeHtml(v)}</td></tr>`).join('');
  document.querySelector('#systemTable tbody').innerHTML = rows;
}

async function loadCpu(){
  const d = await fetchJSON('/api/cpu');
  if (!d) return;
  document.getElementById('cpuStats').innerHTML = `
    <div class="col-md-3"><div class="card stat-card"><div class="label">Usage</div><div class="value">${d.usage.toFixed(1)}%</div></div></div>
    <div class="col-md-3"><div class="card stat-card"><div class="label">Logical Cores</div><div class="value">${d.core_count_logical}</div></div></div>
    <div class="col-md-3"><div class="card stat-card"><div class="label">Frequency</div><div class="value" style="font-size:1.3rem;">${d.frequency_current ?? 'N/A'} MHz</div></div></div>
    <div class="col-md-3"><div class="card stat-card"><div class="label">Load Avg</div><div class="value" style="font-size:1.1rem;">${d.load_avg.join(' / ')}</div></div></div>
  `;
  document.getElementById('coreBars').innerHTML = d.per_core.map((v,i)=>`
    <div class="mb-2">
      <div class="d-flex justify-content-between small mb-1"><span>Core ${i}</span><span>${v.toFixed(1)}%</span></div>
      <div class="progress"><div class="progress-bar" style="width:${v}%"></div></div>
    </div>`).join('');
}

async function loadMemory(){
  const d = await fetchJSON('/api/memory');
  if (!d) return;
  document.getElementById('memStats').innerHTML = `
    <div class="col-md-4"><div class="card stat-card"><div class="label">RAM Used</div><div class="value">${d.percent}%</div>
      <div class="progress mt-2"><div class="progress-bar" style="width:${d.percent}%"></div></div>
      <div class="small text-muted mt-1">${d.used} / ${d.total}</div></div></div>
    <div class="col-md-4"><div class="card stat-card"><div class="label">Available</div><div class="value" style="font-size:1.4rem;">${d.available}</div></div></div>
    <div class="col-md-4"><div class="card stat-card"><div class="label">Swap</div><div class="value">${d.swap_percent}%</div>
      <div class="small text-muted mt-1">${d.swap_used} / ${d.swap_total}</div></div></div>
    <div class="col-md-4"><div class="card stat-card"><div class="label">Cached</div><div class="value" style="font-size:1.4rem;">${d.cached}</div></div></div>
    <div class="col-md-4"><div class="card stat-card"><div class="label">Buffers</div><div class="value" style="font-size:1.4rem;">${d.buffers}</div></div></div>
    <div class="col-md-4"><div class="card stat-card"><div class="label">Free</div><div class="value" style="font-size:1.4rem;">${d.free}</div></div></div>
  `;
}

async function loadDisk(){
  const d = await fetchJSON('/api/disk');
  if (!d) return;
  document.getElementById('diskTable').innerHTML = d.partitions.map(p=>`
    <tr><td>${escapeHtml(p.device)}</td><td>${escapeHtml(p.mountpoint)}</td><td>${escapeHtml(p.fstype)}</td>
    <td>${escapeHtml(p.used)}</td><td>${escapeHtml(p.total)}</td>
    <td><div class="progress"><div class="progress-bar" style="width:${p.percent}%"></div></div><span class="small">${p.percent}%</span></td></tr>
  `).join('');
  document.getElementById('diskIO').innerHTML = `
    <div class="section-title"><i class="bi bi-arrow-down-up"></i>Disk I/O</div>
    <div class="row"><div class="col-md-3">Read: <strong>${d.io.read_bytes}</strong></div>
    <div class="col-md-3">Write: <strong>${d.io.write_bytes}</strong></div>
    <div class="col-md-3">Read Ops: <strong>${d.io.read_count}</strong></div>
    <div class="col-md-3">Write Ops: <strong>${d.io.write_count}</strong></div></div>`;
}

async function loadNetwork(){
  const d = await fetchJSON('/api/network');
  if (!d) return;
  document.getElementById('netTable').innerHTML = d.interfaces.map(i=>`
    <tr><td>${escapeHtml(i.name)}</td><td>${escapeHtml(i.ipv4)}</td><td>${escapeHtml(i.ipv6)}</td>
    <td>${escapeHtml(i.mac)}</td><td>${escapeHtml(i.mtu)}</td><td>${escapeHtml(i.speed)}</td>
    <td>${badge(i.status)}</td></tr>`).join('');
  document.getElementById('netExtra').innerHTML = `
    <div class="row">
      <div class="col-md-3">Gateway: <strong>${escapeHtml(d.gateway)}</strong></div>
      <div class="col-md-3">DNS: <strong>${escapeHtml(d.dns)}</strong></div>
      <div class="col-md-3">Upload Total: <strong>${escapeHtml(d.upload_total)}</strong></div>
      <div class="col-md-3">Download Total: <strong>${escapeHtml(d.download_total)}</strong></div>
    </div>`;
}

async function loadConnections(){
  const d = await fetchJSON('/api/connections');
  if (!d) return;
  document.getElementById('connTable').innerHTML = d.map(c=>`
    <tr><td>${escapeHtml(c.proto)}</td><td>${escapeHtml(c.family)}</td><td>${escapeHtml(c.laddr)}</td>
    <td>${escapeHtml(c.raddr)}</td><td>${badge(c.status)}</td><td>${escapeHtml(c.pid)}</td>
    <td>${escapeHtml(c.process)}</td><td>${escapeHtml(c.user)}</td></tr>`).join('');
}

async function loadProcesses(){
  const d = await fetchJSON('/api/processes');
  if (!d) return;
  document.getElementById('procTable').innerHTML = d.map(p=>`
    <tr><td>${escapeHtml(p.pid)}</td><td>${escapeHtml(p.name)}</td><td>${p.cpu}%</td><td>${p.memory}%</td>
    <td>${escapeHtml(p.threads)}</td><td>${badge(p.status)}</td><td>${escapeHtml(p.user)}</td><td>${escapeHtml(p.created)}</td>
    <td class="d-flex gap-1">
      <button class="btn btn-sm btn-outline-danger" title="Kill" onclick="processAction(${p.pid},'kill')"><i class="bi bi-x-lg"></i></button>
      <button class="btn btn-sm btn-outline-secondary" title="Suspend" onclick="processAction(${p.pid},'suspend')"><i class="bi bi-pause-fill"></i></button>
      <button class="btn btn-sm btn-outline-secondary" title="Resume" onclick="processAction(${p.pid},'resume')"><i class="bi bi-play-fill"></i></button>
    </td></tr>`).join('');
}

async function processAction(pid, action){
  if (!getAdminToken()){
    showToast('Admin token required. Enter it in the navbar to manage processes.');
    return;
  }
  if (action === 'kill' && !confirm(`Kill process ${pid}? This cannot be undone.`)) return;
  const r = await adminFetch(`/api/process/${pid}/${action}`);
  showToast(r.status || r.error || 'Done.');
  loadProcesses();
}

async function loadPorts(){
  const d = await fetchJSON('/api/ports');
  if (!d) return;
  document.getElementById('portsTable').innerHTML = d.map(p=>`
    <tr><td><strong>${escapeHtml(p.port)}</strong></td><td>${escapeHtml(p.protocol)}</td><td>${escapeHtml(p.address)}</td>
    <td>${escapeHtml(p.program)}</td><td>${escapeHtml(p.pid)}</td></tr>`).join('');
}

async function loadLogs(){
  const q = document.getElementById('logFilter').value;
  const d = await fetchJSON('/api/logs?q=' + encodeURIComponent(q));
  if (!d) return;
  document.getElementById('logsBox').textContent = d.join('\n') || 'No logs available.';
}

async function loadServices(){
  const d = await fetchJSON('/api/services');
  const u = await fetchJSON('/api/users');
  if (d) document.getElementById('svcTable').innerHTML = d.map(s=>`
    <tr><td>${escapeHtml(s.name)}</td><td>${badge(s.state)}</td></tr>`).join('') || '<tr><td colspan="2">No watched services found.</td></tr>';
  if (u) document.getElementById('usersTable').innerHTML = u.map(x=>`
    <tr><td>${escapeHtml(x.name)}</td><td>${escapeHtml(x.terminal)}</td><td>${escapeHtml(x.host)}</td><td>${escapeHtml(x.started)}</td></tr>`).join('') || '<tr><td colspan="4">No active sessions.</td></tr>';
}

async function loadSecurity(){
  const d = await fetchJSON('/api/security');
  if (!d) return;
  document.getElementById('secFirewall').innerHTML = `<strong>Firewall Status:</strong> ${escapeHtml(d.firewall)}`;
  document.getElementById('secSSH').textContent = d.failed_ssh.join('\n');
  document.getElementById('secSuspicious').textContent = d.suspicious.join('\n');
}

async function loadHardware(){
  const d = await fetchJSON('/api/hardware');
  if (!d) return;
  const rows = Object.entries(d).map(([k,v])=>{
    const val = Array.isArray(v) ? v.join(', ') : v;
    return `<tr><td style="width:220px;font-weight:600;color:#0B1F3A;">${escapeHtml(k.replace(/_/g,' ').toUpperCase())}</td><td>${escapeHtml(val)}</td></tr>`;
  }).join('');
  document.querySelector('#hwTable tbody').innerHTML = rows;
}

async function loadWifi(){
  const d = await fetchJSON('/api/wifi');
  if (!d) return;
  if (!d.available){
    document.getElementById('wifiBox').innerHTML = `<p class="text-muted">No wireless interface detected.</p>`;
    return;
  }
  if (d.ssid){
    document.getElementById('wifiBox').innerHTML = `
      <table class="modern"><tbody>
      <tr><td><strong>SSID</strong></td><td>${escapeHtml(d.ssid)}</td></tr>
      <tr><td><strong>Signal</strong></td><td>${escapeHtml(d.signal)}</td></tr>
      <tr><td><strong>Frequency</strong></td><td>${escapeHtml(d.frequency)}</td></tr>
      <tr><td><strong>Channel</strong></td><td>${escapeHtml(d.channel)}</td></tr>
      <tr><td><strong>Security</strong></td><td>${escapeHtml(d.security)}</td></tr>
      <tr><td><strong>Bitrate</strong></td><td>${escapeHtml(d.bitrate)}</td></tr>
      </tbody></table>`;
  } else {
    document.getElementById('wifiBox').innerHTML = `<p>${escapeHtml(d.message || 'Wireless interface present.')}</p>`;
  }
}

function showToast(msg){
  const el = document.getElementById('liveToast');
  document.getElementById('toastBody').textContent = msg;
  new bootstrap.Toast(el).show();
}

function getAdminToken(){
  try { return localStorage.getItem('admin_token') || sessionStorage.getItem('admin_token') || ''; } catch(e){ return sessionStorage.getItem('admin_token') || ''; }
}

function syncTokenFields(v){
  ['navTokenInput', 'adminTokenInput', 'settingsTokenInput'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = v;
  });
}

function setAdminStatusPill(valid){
  const pill = document.getElementById('adminStatusPill');
  if (!pill) return;
  if (valid){
    pill.textContent = 'Unlocked';
    pill.className = 'badge-status badge-running pulse';
  } else {
    pill.textContent = 'Locked';
    pill.className = 'badge-status badge-stopped';
  }
}

async function submitAdminToken(){
  const v = (document.getElementById('navTokenInput').value
    || document.getElementById('adminTokenInput')?.value
    || document.getElementById('settingsTokenInput')?.value || '').trim();
  if (!v){
    showToast('Enter the admin token printed in the server console first.');
    return;
  }
  try { localStorage.setItem('admin_token', v); } catch(e){} try { sessionStorage.setItem('admin_token', v); } catch(e){}
  syncTokenFields(v);
  try{
    const r = await fetch('/api/admin-token-check', {headers:{'X-Admin-Token': v}});
    const data = await r.json();
    setAdminStatusPill(data.valid);
    showToast(data.valid ? 'Admin token verified — protected actions unlocked.' : 'Token saved, but it does not match the server. Check the console output.');
  }catch(e){
    showToast('Could not reach the server to verify the token.');
  }
}

function saveAdminToken(v){
  // Legacy hook kept for the Settings/Terminal inline inputs; routes to the same submit flow.
  document.getElementById('navTokenInput').value = v;
}

function saveSetting(key, val){
  localStorage.setItem('setting_' + key, JSON.stringify(val));
}
function getSetting(key, def){
  const v = localStorage.getItem('setting_' + key);
  return v === null ? def : JSON.parse(v);
}

async function verifyStoredToken(){
  const t = getAdminToken();
  if (!t){ setAdminStatusPill(false); return; }
  syncTokenFields(t);
  try{
    const r = await fetch('/api/admin-token-check', {headers:{'X-Admin-Token': t}});
    const data = await r.json();
    setAdminStatusPill(data.valid);
  }catch(e){
    setAdminStatusPill(false);
  }
}

window.addEventListener('load', verifyStoredToken);

document.addEventListener('keydown', e => {
  if (e.key === 'Enter' && e.target && e.target.id === 'navTokenInput') submitAdminToken();
});

async function adminFetch(url, opts={}){
  opts.headers = Object.assign({}, opts.headers, {'X-Admin-Token': getAdminToken()});
  const r = await fetch(url, opts);
  let data;
  try { data = await r.json(); } catch(e){ data = {error: 'Invalid response from server.'}; }
  if (r.status === 401) showToast('Unauthorized — paste a valid admin token in the navbar first.');
  return data;
}

// ---- Packet monitor ----
let packetPolling = null;
async function packetStart(){
  if (!getAdminToken()){
    showToast('Admin token required. Paste it in the navbar first.');
    return;
  }
  const r = await adminFetch('/api/packets/start');
  if (r.error){
    showToast(r.error);
    document.getElementById('packetAvailabilityNotice').style.display = 'block';
    document.getElementById('packetAvailabilityNotice').textContent =
      '⚠ ' + r.error + ' Install Scapy (pip install scapy) and run the server as root to enable live packet capture.';
    return;
  }
  document.getElementById('packetStatus').textContent = 'capturing';
  clearInterval(packetPolling);
  packetPolling = setInterval(loadPackets, 1500);
}
async function packetStop(){
  await adminFetch('/api/packets/stop');
  document.getElementById('packetStatus').textContent = 'stopped';
  clearInterval(packetPolling);
}
async function packetClear(){
  await adminFetch('/api/packets/clear');
  document.getElementById('packetsTable').innerHTML = '';
}
async function loadPackets(){
  const proto = document.getElementById('packetFilter').value;
  const d = await fetchJSON('/api/packets?proto=' + encodeURIComponent(proto));
  if (!d) return;
  const notice = document.getElementById('packetAvailabilityNotice');
  const startBtn = document.getElementById('packetStartBtn');
  if (!d.available){
    document.getElementById('packetStatus').textContent = 'unavailable';
    notice.style.display = 'block';
    notice.textContent = '⚠ Scapy is not installed or this server is not running as root. Packet capture needs raw-socket access. Install with "pip install scapy" and restart with sudo.';
    startBtn.disabled = true;
  } else {
    notice.style.display = 'none';
    startBtn.disabled = false;
    document.getElementById('packetStatus').textContent = d.active ? 'capturing' : 'stopped';
  }
  document.getElementById('packetsTable').innerHTML = d.packets.length ? d.packets.map(p=>`
    <tr><td>${escapeHtml(p.time)}</td><td>${escapeHtml(p.proto)}</td><td>${escapeHtml(p.src)}</td>
    <td>${escapeHtml(p.dst)}</td><td>${escapeHtml(p.length)}</td><td>${escapeHtml(p.info)}</td></tr>`).join('')
    : '<tr><td colspan="6" class="text-muted">No packets captured yet. Click Start to begin.</td></tr>';
}

// ---- Bandwidth ----
async function loadBandwidth(){
  const d = await fetchJSON('/api/bandwidth');
  if (!d) return;
  document.getElementById('bwTable').innerHTML = d.map(p=>`
    <tr><td>${escapeHtml(p.pid)}</td><td>${escapeHtml(p.name)}</td><td>${escapeHtml(p.read_bytes)}</td><td>${escapeHtml(p.write_bytes)}</td></tr>`).join('')
    || '<tr><td colspan="4">No per-process IO data available on this platform.</td></tr>';
}

// ---- Network tools ----
async function runTool(kind){
  const target = document.getElementById('toolTarget').value.trim();
  document.getElementById('toolOutput').textContent = 'Running...';
  const d = await fetchJSON('/api/tools/' + kind + '?target=' + encodeURIComponent(target));
  document.getElementById('toolOutput').textContent = d ? (d.result || JSON.stringify(d)) : 'Request failed.';
}
async function runPortScan(){
  const target = document.getElementById('toolTarget').value.trim();
  const ports = document.getElementById('scanRange').value.trim();
  document.getElementById('toolOutput').textContent = 'Scanning...';
  const d = await fetchJSON('/api/tools/portscan?target=' + encodeURIComponent(target) + '&ports=' + encodeURIComponent(ports));
  document.getElementById('toolOutput').textContent = JSON.stringify(d, null, 2);
}
async function runSubnet(){
  const cidr = document.getElementById('cidrInput').value.trim();
  const d = await fetchJSON('/api/tools/subnet?cidr=' + encodeURIComponent(cidr));
  document.getElementById('toolOutput').textContent = JSON.stringify(d, null, 2);
}
async function runArp(){
  const d = await fetchJSON('/api/tools/arp');
  document.getElementById('toolOutput').textContent = d ? d.result.join('\n') : 'Request failed.';
  loadNetmapDevices();
}

async function loadNetmap(){
  const net = await fetchJSON('/api/network');
  if (net){
    document.getElementById('mapGateway').textContent = 'Gateway: ' + net.gateway;
    document.getElementById('mapLocal').textContent = 'Local Machine (' + (net.interfaces[0]?.ipv4 || 'N/A') + ')';
  }
  loadNetmapDevices();
}
async function loadNetmapDevices(){
  const d = await fetchJSON('/api/tools/arp');
  if (d) document.getElementById('mapDevices').innerHTML = (d.result || []).map(l=>escapeHtml(l)).join('<br>');
}

// ---- Hardware extras ----
async function loadUsb(){
  const d = await fetchJSON('/api/usb');
  document.getElementById('usbBox').textContent = (d||[]).map(x=>x.info).join('\n');
}
async function loadPci(){
  const d = await fetchJSON('/api/pci');
  document.getElementById('pciBox').textContent = (d||[]).map(x=>x.info).join('\n');
}
async function loadBluetooth(){
  const d = await fetchJSON('/api/bluetooth');
  document.getElementById('btTable').innerHTML = (d||[]).map(x=>
    x.mac ? `<tr><td>${escapeHtml(x.mac)}</td><td>${escapeHtml(x.name)}</td></tr>` : `<tr><td colspan="2">${escapeHtml(x.info)}</td></tr>`
  ).join('');
}
async function loadGpu(){
  const d = await fetchJSON('/api/gpu');
  document.getElementById('gpuCards').innerHTML = (d||[]).map(g => g.info ? `
    <div class="col-12"><div class="card p-3">${escapeHtml(g.info)}</div></div>` : `
    <div class="col-md-4"><div class="card stat-card">
      <div class="label">${escapeHtml(g.vendor)}</div>
      <div class="value" style="font-size:1.1rem;">${escapeHtml(g.name)}</div>
      <div class="small text-muted mt-2">Temp: ${escapeHtml(g.temperature)} | Usage: ${escapeHtml(g.usage)}</div>
      <div class="small text-muted">VRAM: ${escapeHtml(g.vram_used)} / ${escapeHtml(g.vram_total)}</div>
    </div></div>`).join('');
}
async function loadDocker(){
  const d = await fetchJSON('/api/docker');
  if (!d || !d.available){
    document.getElementById('dockerContainers').innerHTML = `<tr><td colspan="5">${escapeHtml(d?.message || 'Docker unavailable.')}</td></tr>`;
    return;
  }
  document.getElementById('dockerContainers').innerHTML = d.containers.map(c=>`
    <tr><td>${escapeHtml(c.id)}</td><td>${escapeHtml(c.name)}</td><td>${escapeHtml(c.image)}</td><td>${badge(c.status)}</td><td>${escapeHtml(c.ports)}</td></tr>`).join('') || '<tr><td colspan="5">No containers.</td></tr>';
  document.getElementById('dockerImages').innerHTML = d.images.map(i=>`
    <tr><td>${escapeHtml(i.repo)}</td><td>${escapeHtml(i.tag)}</td><td>${escapeHtml(i.size)}</td></tr>`).join('') || '<tr><td colspan="3">No images.</td></tr>';
}
async function loadVm(){
  const d = await fetchJSON('/api/vm');
  if (!d) return;
  document.getElementById('vmBox').innerHTML = `<strong>Detected:</strong> ${d.detected.map(escapeHtml).join(', ')}<br><span class="small text-muted">DMI Vendor: ${escapeHtml(d.raw_vendor)}</span>`;
}
async function loadEnvironment(){
  const d = await fetchJSON('/api/environment');
  document.getElementById('envTable').innerHTML = (d||[]).map(e=>`
    <tr><td style="width:280px;font-weight:600;">${escapeHtml(e.key)}</td><td>${escapeHtml(e.value)}</td></tr>`).join('');
}
async function loadCron(){
  const d = await fetchJSON('/api/cron');
  if (!d) return;
  document.getElementById('cronUser').textContent = d.user.join('\n');
  document.getElementById('cronSystem').textContent = d.system.join('\n');
}
async function loadKernel(){
  const d = await fetchJSON('/api/kernel-modules');
  document.getElementById('kernelTable').innerHTML = (d||[]).map(x=>`<tr><td>${escapeHtml(x.info)}</td></tr>`).join('');
}
async function loadPackagesPage(){
  const d = await fetchJSON('/api/packages');
  document.getElementById('pkgTable').innerHTML = (d||[]).map(x=>`<tr><td>${escapeHtml(x.info)}</td></tr>`).join('');
}
async function loadFilesystem(){
  const path = document.getElementById('fsPath').value || '/';
  const d = await fetchJSON('/api/filesystem?path=' + encodeURIComponent(path));
  if (!d || d.error){
    document.getElementById('fsTable').innerHTML = `<tr><td colspan="6">${escapeHtml(d?.error || 'Unable to read path.')}</td></tr>`;
    return;
  }
  document.getElementById('fsPath').value = d.path;
  document.getElementById('fsTable').innerHTML = d.entries.map(e=>`
    <tr class="fs-row" data-name="${escapeHtml(e.name)}" data-isdir="${e.is_dir}" style="cursor:${e.is_dir ? 'pointer':'default'};">
    <td><i class="bi bi-${e.is_dir ? 'folder-fill text-warning' : 'file-earmark'}"></i> ${escapeHtml(e.name)}</td>
    <td>${e.is_dir ? 'Directory' : 'File'}</td><td>${escapeHtml(e.size)}</td>
    <td><code class="small-code">${escapeHtml(e.permissions)}</code></td><td>${escapeHtml(e.owner)}</td><td>${escapeHtml(e.modified)}</td></tr>`).join('');
}
document.addEventListener('click', e => {
  const row = e.target.closest('.fs-row');
  if (!row) return;
  if (row.dataset.isdir !== 'true') return;
  const base = document.getElementById('fsPath').value.replace(/\/+$/, '');
  document.getElementById('fsPath').value = (base || '') + '/' + row.dataset.name;
  loadFilesystem();
});
async function loadFilesystemDefault(){ loadFilesystem(); }

// ---- Terminal ----
async function runTerminal(){
  const input = document.getElementById('terminalInput');
  const cmd = input.value;
  if (!cmd.trim()) return;
  if (!getAdminToken()){
    showToast('Admin token required. Paste it in the navbar (top right) and click the check button first.');
    return;
  }
  const box = document.getElementById('terminalOutput');
  box.textContent += `\n$ ${cmd}\n`;
  input.value = '';
  const r = await adminFetch('/api/terminal', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({command: cmd})});
  box.textContent += (r.output || r.error || '');
  box.scrollTop = box.scrollHeight;
}

// ---- System power ----
async function systemAction(action){
  if (!getAdminToken()){
    showToast('Admin token required. Paste it in the navbar (top right) and click the check button first.');
    return;
  }
  if (!confirm(`Are you sure you want to ${action} this system? This action requires admin privileges.`)) return;
  const r = await adminFetch('/api/system/action', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({action, confirm:true})});
  showToast(r.status || r.error || 'Action sent.');
}

// ---- Threshold alerts ----
let lastAlertTime = {};
function maybeAlert(key, condition, message){
  if (!getSetting('notif', true)) return;
  const now = Date.now();
  if (condition && (!lastAlertTime[key] || now - lastAlertTime[key] > 30000)){
    showToast(message);
    lastAlertTime[key] = now;
  }
}

function filterTable(tbodyId, query){
  const rows = document.querySelectorAll('#' + tbodyId + ' tr');
  query = query.toLowerCase();
  rows.forEach(r => {
    r.style.display = r.textContent.toLowerCase().includes(query) ? '' : 'none';
  });
}

function globalSearch(query){
  const active = document.querySelector('.page-section.active');
  if (!active) return;
  const tbody = active.querySelector('tbody');
  if (tbody) filterTable(tbody.id, query);
}

const loaders = {
  dashboard: loadDashboard,
  system: loadSystem,
  cpu: loadCpu,
  memory: loadMemory,
  disk: loadDisk,
  network: loadNetwork,
  connections: loadConnections,
  processes: loadProcesses,
  ports: loadPorts,
  packets: loadPackets,
  bandwidth: loadBandwidth,
  nettools: () => {},
  netmap: loadNetmap,
  logs: loadLogs,
  services: loadServices,
  security: loadSecurity,
  hardware: loadHardware,
  usb: loadUsb,
  pci: loadPci,
  bluetooth: loadBluetooth,
  gpu: loadGpu,
  docker: loadDocker,
  vm: loadVm,
  environment: loadEnvironment,
  cron: loadCron,
  kernel: loadKernel,
  packagesPage: loadPackagesPage,
  filesystem: loadFilesystemDefault,
  terminal: () => {},
  systools: () => {},
  wifi: loadWifi,
};

function loadPageData(page){
  if (loaders[page]) loaders[page]();
}

function tick(){
  const activeLink = document.querySelector('#sideNav .nav-link.active');
  if (activeLink) loadPageData(activeLink.dataset.page);
}

window.addEventListener('load', () => {
  initCharts();
  loadDashboard();
  refreshTimer = setInterval(tick, REFRESH_MS);
});
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(PAGE_TEMPLATE)


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error", "detail": str(e)}), 500


# ============================================================
# ENTRYPOINT
# ============================================================

if __name__ == "__main__":
    print("Checking permissions...")
    if os.geteuid() != 0 if hasattr(os, "geteuid") else False:
        print("  -> Running without root: some hardware/security data may be limited.")
    print("Starting server...")
    print("=" * 50)
    print("Dashboard:")
    print("http://localhost:1110")
    print("-" * 50)
    print(f"Admin Token (required for kill/terminal/power actions): {ADMIN_TOKEN}")
    print("Pass via header 'X-Admin-Token' or ?token= query param.")
    print(f"WebSocket live feed: {'enabled at /ws/live' if sock else 'unavailable, using AJAX fallback'}")
    print(f"Packet monitor (Scapy): {'available' if _scapy_available else 'unavailable (install scapy / run as root)'}")
    print("=" * 50)
    try:
        app.run(host="0.0.0.0", port=1110, debug=False, threaded=True)
    except Exception as e:
        print(f"Failed to start server: {e}")
        sys.exit(1)
