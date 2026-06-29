#!/usr/bin/env bash
#
# install.sh — Installer for System Monitor Dashboard (monitor.py)
# Supports: Debian/Ubuntu (apt) and Fedora/RHEL (dnf)
#
# What this does:
#   1. Detects your distro family.
#   2. Installs Python 3, pip, and venv support via the system package manager.
#   3. Creates an isolated virtualenv in ./venv (keeps your system Python clean,
#      and avoids the "externally-managed-environment" pip error on modern
#      Debian/Fedora releases).
#   4. Installs Python dependencies (Flask, psutil, flask-sock, etc.) into the venv.
#   5. Optionally installs a systemd service so the dashboard starts on boot.
#
# Usage:
#   chmod +x install.sh
#   ./install.sh                # interactive install
#   ./install.sh --service      # also install + enable a systemd service
#   ./install.sh --no-service   # skip the systemd prompt entirely
#
set -euo pipefail

# ----------------------------------------------------------------------------
# Colors / helpers
# ----------------------------------------------------------------------------
BOLD="\033[1m"; GREEN="\033[0;32m"; YELLOW="\033[0;33m"; RED="\033[0;31m"; RESET="\033[0m"

info()  { echo -e "${GREEN}[+]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $*"; }
error() { echo -e "${RED}[x]${RESET} $*" >&2; }

INSTALL_SERVICE="ask"
for arg in "$@"; do
  case "$arg" in
    --service)    INSTALL_SERVICE="yes" ;;
    --no-service) INSTALL_SERVICE="no" ;;
    -h|--help)
      echo "Usage: ./install.sh [--service|--no-service]"
      exit 0
      ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=================================================="
echo " System Monitor Dashboard — Installer"
echo "=================================================="

if [[ ! -f "monitor.py" ]]; then
  error "monitor.py not found in $SCRIPT_DIR. Place install.sh next to monitor.py and re-run."
  exit 1
fi

# ----------------------------------------------------------------------------
# 1. Detect distro family
# ----------------------------------------------------------------------------
DISTRO_FAMILY="unknown"
PKG_MANAGER=""

if [[ -f /etc/os-release ]]; then
  # shellcheck disable=SC1091
  source /etc/os-release
  ID_LIKE="${ID_LIKE:-}"
  case "${ID:-}" in
    fedora|rhel|centos|rocky|almalinux)
      DISTRO_FAMILY="fedora"
      ;;
    debian|ubuntu|linuxmint|pop|raspbian|kali)
      DISTRO_FAMILY="debian"
      ;;
    *)
      if [[ "$ID_LIKE" == *"fedora"* || "$ID_LIKE" == *"rhel"* ]]; then
        DISTRO_FAMILY="fedora"
      elif [[ "$ID_LIKE" == *"debian"* ]]; then
        DISTRO_FAMILY="debian"
      fi
      ;;
  esac
fi

if command -v dnf >/dev/null 2>&1 && [[ "$DISTRO_FAMILY" != "debian" ]]; then
  DISTRO_FAMILY="fedora"; PKG_MANAGER="dnf"
elif command -v apt-get >/dev/null 2>&1 && [[ "$DISTRO_FAMILY" != "fedora" ]]; then
  DISTRO_FAMILY="debian"; PKG_MANAGER="apt-get"
fi

if [[ "$DISTRO_FAMILY" == "unknown" || -z "$PKG_MANAGER" ]]; then
  error "Could not detect a supported package manager (apt-get or dnf)."
  error "This installer supports Debian/Ubuntu and Fedora/RHEL family distros only."
  exit 1
fi

info "Detected distro family: ${BOLD}${DISTRO_FAMILY}${RESET} (using ${PKG_MANAGER})"

# ----------------------------------------------------------------------------
# 2. Root / sudo handling for system package installs
# ----------------------------------------------------------------------------
SUDO=""
if [[ "$(id -u)" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    warn "Not running as root and 'sudo' was not found."
    warn "System package installation may fail. Continuing anyway..."
  fi
fi

# ----------------------------------------------------------------------------
# 3. Install system packages (Python, pip, venv, optional extras)
# ----------------------------------------------------------------------------
info "Installing system dependencies (this may ask for your password)..."

if [[ "$DISTRO_FAMILY" == "debian" ]]; then
  $SUDO apt-get update -y
  $SUDO apt-get install -y \
    python3 \
    python3-venv \
    python3-pip \
    iproute2 \
    net-tools \
    dnsutils \
    whois \
    traceroute \
    usbutils \
    pciutils \
    lsof
elif [[ "$DISTRO_FAMILY" == "fedora" ]]; then
  $SUDO dnf install -y \
    python3 \
    python3-pip \
    iproute \
    net-tools \
    bind-utils \
    whois \
    traceroute \
    usbutils \
    pciutils \
    lsof
fi

info "System dependencies installed."

# ----------------------------------------------------------------------------
# 4. Create a virtual environment and install Python dependencies
# ----------------------------------------------------------------------------
VENV_DIR="$SCRIPT_DIR/venv"

if [[ ! -d "$VENV_DIR" ]]; then
  info "Creating Python virtual environment at $VENV_DIR ..."
  python3 -m venv "$VENV_DIR"
else
  info "Virtual environment already exists, reusing it."
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

info "Upgrading pip..."
pip install --upgrade pip --quiet

info "Installing Python dependencies (Flask, psutil, flask-sock)..."
pip install --quiet Flask psutil flask-sock

# Optional, best-effort extras. Never fail the install if these can't build.
info "Attempting optional extras (scapy for packet capture, reportlab for PDF export)..."
pip install --quiet reportlab 2>/dev/null || warn "reportlab not installed — PDF export will be unavailable until you install it manually."
pip install --quiet scapy 2>/dev/null || warn "scapy not installed — Packet Monitor will be unavailable until you install it manually (may also require running as root)."

deactivate

info "Python environment ready."

# ----------------------------------------------------------------------------
# 5. Create a convenience launcher script
# ----------------------------------------------------------------------------
cat > "$SCRIPT_DIR/run.sh" <<EOF
#!/usr/bin/env bash
# Convenience launcher — activates the venv and runs monitor.py
cd "\$(dirname "\${BASH_SOURCE[0]}")"
source venv/bin/activate
exec python3 monitor.py
EOF
chmod +x "$SCRIPT_DIR/run.sh"
info "Created run.sh launcher."

# ----------------------------------------------------------------------------
# 6. Optional systemd service
# ----------------------------------------------------------------------------
install_service() {
  local user_name
  user_name="$(whoami)"
  local service_path="/etc/systemd/system/system-monitor-dashboard.service"

  info "Installing systemd service to $service_path ..."

  $SUDO bash -c "cat > '$service_path'" <<EOF
[Unit]
Description=System Monitor Dashboard
After=network.target

[Service]
Type=simple
User=${user_name}
WorkingDirectory=${SCRIPT_DIR}
ExecStart=${VENV_DIR}/bin/python3 ${SCRIPT_DIR}/monitor.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

  $SUDO systemctl daemon-reload
  $SUDO systemctl enable system-monitor-dashboard.service
  $SUDO systemctl restart system-monitor-dashboard.service

  info "Service installed and started."
  info "Check status with: ${BOLD}systemctl status system-monitor-dashboard${RESET}"
  info "View logs with:    ${BOLD}journalctl -u system-monitor-dashboard -f${RESET}"
}

if [[ "$INSTALL_SERVICE" == "ask" ]]; then
  echo
  read -r -p "Install as a systemd service so it auto-starts on boot? [y/N]: " answer
  case "$answer" in
    [yY]|[yY][eE][sS]) INSTALL_SERVICE="yes" ;;
    *) INSTALL_SERVICE="no" ;;
  esac
fi

if [[ "$INSTALL_SERVICE" == "yes" ]]; then
  if command -v systemctl >/dev/null 2>&1; then
    install_service
  else
    warn "systemctl not found — skipping service installation."
    INSTALL_SERVICE="no"
  fi
fi

# ----------------------------------------------------------------------------
# 7. Done
# ----------------------------------------------------------------------------
echo
echo "=================================================="
echo -e " ${BOLD}Installation complete!${RESET}"
echo "=================================================="
if [[ "$INSTALL_SERVICE" == "yes" ]]; then
  echo " The dashboard is running as a systemd service."
  echo " Dashboard: http://localhost:1110"
else
  echo " Start the dashboard with:"
  echo -e "   ${BOLD}./run.sh${RESET}"
  echo " Then open: http://localhost:1110"
fi
echo
echo " The admin token (needed for process kill / terminal / power controls)"
echo " is printed to the console each time monitor.py starts."
echo " Do not expose this dashboard to an untrusted network."
echo "=================================================="
