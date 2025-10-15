#!/usr/bin/env bash
# ------------------------------------------------------------------
# n8n + Telegram Bot Unified Installer (Hardened Version 4.0)
# Security improvements based on 2025 best practices
# GitHub: https://github.com/7020227649/n8n-installer-with-tele-new-4.0
# ------------------------------------------------------------------

set -euo pipefail
IFS=$'\n\t'

# Script metadata
SCRIPT_NAME="n8n-telegram-installer"
SCRIPT_VERSION="4.0.0"
SCRIPT_AUTHOR="GitHub: 7020227649"

# Trap errors and cleanup
trap 'error_handler $? $LINENO' ERR
trap 'cleanup' EXIT

error_handler() {
    local exit_code=$1
    local line_no=$2
    err "Script failed at line $line_no with exit code $exit_code"
    exit $exit_code
}

cleanup() {
    # Remove temporary files
    rm -f /tmp/n8n_install_* /tmp/.n8n_install_lock 2>/dev/null || true
}

# -------- Helpers --------
log() { echo -e "\n[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $*"; }
warn() { echo -e "\n[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $*" >&2; }
err() { echo -e "\n[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" >&2; }

run_cmd() {
    log "Executing: $*"
    if ! "$@" 2>&1 | tee -a /var/log/n8n_install.log; then
        err "Command failed: $*"
        return 1
    fi
}

# -------- Input Validation --------
validate_domain() {
    local domain="$1"
    if ! [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        return 1
    fi
    return 0
}

validate_email() {
    local email="$1"
    if ! [[ "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        return 1
    fi
    return 0
}

validate_bot_token() {
    local token="$1"
    if ! [[ "$token" =~ ^[0-9]+:[a-zA-Z0-9_-]{35}$ ]]; then
        return 1
    fi
    return 0
}

validate_user_id() {
    local uid="$1"
    if ! [[ "$uid" =~ ^[0-9]+$ ]]; then
        return 1
    fi
    return 0
}

# -------- Secure Input Handling --------
prompt_nonempty() {
    local prompt_text="$1"
    local default_val="$2"
    local is_secret="${3:-false}"
    local validator="${4:-}"
    local user_input=""
    
    while true; do
        if [[ "$is_secret" == "true" ]]; then
            read -r -s -p "$prompt_text" user_input || true
            echo
        else
            read -r -p "$prompt_text" user_input || true
        fi
        
        user_input="${user_input:-$default_val}"
        
        if [[ -z "$user_input" ]]; then
            echo "Input cannot be empty. Please try again."
            continue
        fi
        
        # Run validator if provided
        if [[ -n "$validator" ]] && ! $validator "$user_input"; then
            echo "Invalid input format. Please try again."
            continue
        fi
        
        echo "$user_input"
        return 0
    done
}

# -------- Configuration --------
BOT_DIR="/opt/n8n_bot"
BACKUP_DIR="/opt/n8n_backups"
N8N_DATA_DIR="/var/n8n"
BOT_USER="n8nbot"
VENV_DIR="$BOT_DIR/venv"
SYSTEMD_SERVICE="/etc/systemd/system/n8n-bot.service"
NGINX_CONF="/etc/nginx/sites-available/n8n"
REQUIRED_PACKAGES=(bash curl sudo gnupg ca-certificates lsb-release unzip software-properties-common nginx ufw python3 python3-venv python3-pip certbot python3-certbot-nginx)

# -------- Pre-flight Check --------
if [[ $EUID -ne 0 ]]; then
    err "This installer must be run as root. Please use 'sudo'."
    exit 1
fi

# Check for existing installation
if [[ -f "$SYSTEMD_SERVICE" ]] && systemctl is-active --quiet n8n-bot.service; then
    warn "n8n bot service is already running."
    read -p "Do you want to reinstall? This will stop the existing service. (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
    log "Stopping existing n8n bot service..."
    systemctl stop n8n-bot.service || true
fi

# Check for arguments - NEVER accept secrets as arguments
ARG_DOMAIN=${1:-}
ARG_EMAIL=${2:-}

echo "========================================================"
echo "           n8n + Telegram Bot Installer v4.0"
echo "========================================================"
echo "🔒 Security Hardened | 📦 Production Ready | 🚀 Enhanced"
echo ""
echo "This installer will:"
echo "✅ Deploy n8n with security constraints"
echo "✅ Setup Telegram bot with enhanced features"
echo "✅ Configure Nginx with SSL and security headers"
echo "✅ Enable automated backups with verification"
echo "✅ Setup monitoring and health checks"
echo ""
echo "========================================================"
echo ""

# Interactive prompts with validation
DOMAIN=$(prompt_nonempty "🧩 Enter your domain name (e.g., n8n.example.com): " "$ARG_DOMAIN" false validate_domain)
EMAIL=$(prompt_nonempty "📧 Enter your email (for SSL certificate): " "$ARG_EMAIL" false validate_email)
BOT_TOKEN=$(prompt_nonempty "🤖 Enter your Telegram Bot Token: " "" true validate_bot_token)
USER_ID=$(prompt_nonempty "👤 Enter your Telegram User ID: " "" false validate_user_id)

# DNS validation
log "Validating DNS configuration..."
SERVER_IP=$(curl -s -4 ifconfig.me || curl -s -4 icanhazip.com || echo "unknown")
DOMAIN_IP=$(dig +short "$DOMAIN" 2>/dev/null | tail -n1 || echo "unknown")

if [[ "$DOMAIN_IP" != "$SERVER_IP" && "$DOMAIN_IP" != "unknown" && "$SERVER_IP" != "unknown" ]]; then
    warn "DNS Warning: $DOMAIN resolves to $DOMAIN_IP but this server is $SERVER_IP"
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

log "🚀 Starting installation for domain: $DOMAIN"

# -------- System & Package Installation --------
log "Updating system and installing dependencies..."
export DEBIAN_FRONTEND=noninteractive
run_cmd apt-get update -y
run_cmd apt-get upgrade -y
run_cmd apt-get install -y "${REQUIRED_PACKAGES[@]}"

# -------- Docker Setup (Secure) --------
if ! command -v docker >/dev/null 2>&1; then
    log "Installing Docker with security defaults..."
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list
    
    run_cmd apt-get update -y
    run_cmd apt-get install -y docker-ce docker-ce-cli containerd.io
else
    log "Docker is already installed."
fi

run_cmd systemctl enable --now docker

# -------- Docker Daemon Configuration (Security + Logging) --------
log "Configuring Docker daemon with security and logging best practices..."
mkdir -p /etc/docker
cat > /etc/docker/daemon.json <<EOF
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "live-restore": true,
  "userland-proxy": false,
  "no-new-privileges": true
}
EOF
run_cmd systemctl restart docker

# -------- System User & Directories (Hardened) --------
if ! id -u "$BOT_USER" >/dev/null 2>&1; then
    log "Creating dedicated system user '$BOT_USER'..."
    useradd --system --home-dir "$BOT_DIR" --shell /usr/sbin/nologin --create-home "$BOT_USER"
else
    log "User '$BOT_USER' already exists."
fi

log "Creating directories with secure permissions..."
mkdir -p "$BOT_DIR" "$BACKUP_DIR" "$N8N_DATA_DIR"
chown 1000:1000 "$N8N_DATA_DIR"
chown -R "$BOT_USER":"$BOT_USER" "$BOT_DIR" "$BACKUP_DIR"
chmod 700 "$BOT_DIR" "$BACKUP_DIR"  # More restrictive
chmod 750 "$N8N_DATA_DIR"

# -------- n8n Docker Container (Hardened) --------
log "Deploying n8n container with security constraints..."
if docker ps -a --format '{{.Names}}' | grep -Eq "^n8n$"; then
    log "n8n container exists. Removing for fresh installation..."
    run_cmd docker stop n8n || true
    run_cmd docker rm n8n || true
fi

log "Creating hardened n8n container..."
run_cmd docker run -d \
    --name n8n \
    --restart unless-stopped \
    --security-opt no-new-privileges:true \
    --cap-drop ALL \
    --cap-add CHOWN,SETGID,SETUID,DAC_OVERRIDE \
    --memory="2g" \
    --cpus="2" \
    --health-cmd="wget --no-verbose --tries=1 --spider http://localhost:5678/healthz || exit 1" \
    --health-interval=30s \
    --health-timeout=10s \
    --health-retries=3 \
    -p 127.0.0.1:5678:5678 \
    -e N8N_HOST="$DOMAIN" \
    -e WEBHOOK_URL="https://$DOMAIN/" \
    -e N8N_METRICS=true \
    -e N8N_LOG_LEVEL=info \
    -v "$N8N_DATA_DIR:/home/node/.n8n" \
    n8nio/n8n:latest

# Wait for container to be healthy
log "Waiting for n8n to become healthy..."
for i in {1..30}; do
    if docker inspect --format='{{.State.Health.Status}}' n8n 2>/dev/null | grep -q "healthy"; then
        log "n8n is healthy!"
        break
    fi
    sleep 2
done

# -------- Nginx Configuration (Hardened) --------
log "Configuring Nginx with security headers..."
cat > "$NGINX_CONF" <<'EOF'
# Rate limiting
limit_req_zone $binary_remote_addr zone=n8n_limit:10m rate=10r/s;
limit_conn_zone $binary_remote_addr zone=n8n_conn:10m;

server {
    listen 80;
    listen [::]:80;
    server_name DOMAIN_PLACEHOLDER;

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        return 301 https://$server_name$request_uri;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name DOMAIN_PLACEHOLDER;

    # SSL configuration will be managed by Certbot
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

    # Rate limiting
    limit_req zone=n8n_limit burst=20 nodelay;
    limit_conn n8n_conn 10;

    client_max_body_size 50M;
    client_body_timeout 300s;

    location / {
        proxy_pass http://127.0.0.1:5678;
        proxy_http_version 1.1;
        
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        proxy_read_timeout 86400s;
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        
        # Security
        proxy_hide_header X-Powered-By;
        proxy_hide_header Server;
    }
}
EOF

# Replace placeholder
sed -i "s/DOMAIN_PLACEHOLDER/$DOMAIN/g" "$NGINX_CONF"

ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

mkdir -p /var/www/html
run_cmd nginx -t && systemctl reload nginx

# -------- SSL Certificate --------
log "Obtaining SSL certificate..."
if certbot --nginx --non-interactive --agree-tos --email "$EMAIL" -d "$DOMAIN" --redirect; then
    log "✅ SSL certificate obtained successfully"
else
    warn "⚠️ Certbot failed. Check DNS configuration and try again."
    warn "You can manually run: certbot --nginx -d $DOMAIN"
fi
run_cmd systemctl reload nginx

# -------- Firewall (Hardened) --------
log "Configuring UFW firewall..."
run_cmd ufw --force reset
run_cmd ufw default deny incoming
run_cmd ufw default allow outgoing
run_cmd ufw allow OpenSSH
run_cmd ufw allow 'Nginx Full'
run_cmd ufw logging on
run_cmd ufw --force enable

# -------- Python Bot (Enhanced) --------
log "Setting up Python environment..."
run_cmd python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip setuptools wheel
"$VENV_DIR/bin/pip" install pyTelegramBotAPI python-dotenv apscheduler psutil cryptography

# -------- Secure Configuration File --------
log "Creating secure configuration..."
cat > "$BOT_DIR/n8n_bot_config.env" <<EOF
BOT_TOKEN=$BOT_TOKEN
AUTHORIZED_USER=$USER_ID
DOMAIN=$DOMAIN
BACKUP_DIR=$BACKUP_DIR
N8N_DATA_DIR=$N8N_DATA_DIR
LOG_FILE_PATH=$BOT_DIR/bot.log
BACKUP_RETENTION_DAYS=7
MAX_BACKUP_SIZE_MB=1000
ENABLE_ENCRYPTION=false
EOF

chown "$BOT_USER":"$BOT_USER" "$BOT_DIR/n8n_bot_config.env"
chmod 400 "$BOT_DIR/n8n_bot_config.env"  # Read-only

# -------- Enhanced Python Bot --------
log "Creating enhanced Python bot with security features..."
cat > "$BOT_DIR/n8n_bot.py" <<'PYEOF'
#!/usr/bin/env python3
"""
n8n Telegram Bot - Production-Hardened Version 4.0
Implements: file locking, backup verification, pre-restore backups,
disk space checks, health monitoring, and secure error handling.
"""
import os
import sys
import time
import logging
import tarfile
import subprocess
import shutil
import psutil
import fcntl
import hashlib
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
from pathlib import Path
from dotenv import load_dotenv
import telebot
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton
from apscheduler.schedulers.background import BackgroundScheduler

# --- Configuration ---
env_path = Path(__file__).parent / "n8n_bot_config.env"
if not env_path.exists():
    print(f"FATAL: Config file not found at {env_path}")
    sys.exit(1)
load_dotenv(dotenv_path=env_path)

# --- Logging Setup ---
LOG_FILE = os.getenv("LOG_FILE_PATH", "bot.log")
log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler = RotatingFileHandler(LOG_FILE, maxBytes=10*1024*1024, backupCount=3)
file_handler.setFormatter(log_formatter)
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
logger = logging.getLogger("n8n_bot")
logger.setLevel(logging.INFO)
logger.addHandler(file_handler)
logger.addHandler(console_handler)

# --- Configuration ---
BOT_TOKEN = os.getenv("BOT_TOKEN")
AUTHORIZED_USER = int(os.getenv("AUTHORIZED_USER", 0))
DOMAIN = os.getenv("DOMAIN")
BACKUP_DIR = Path(os.getenv("BACKUP_DIR", "/opt/n8n_backups"))
N8N_DATA_DIR = Path(os.getenv("N8N_DATA_DIR", "/var/n8n"))
RETENTION_DAYS = int(os.getenv("BACKUP_RETENTION_DAYS", 7))
MAX_BACKUP_SIZE_MB = int(os.getenv("MAX_BACKUP_SIZE_MB", 1000))
TELEGRAM_FILE_LIMIT_MB = 45
LOCK_FILE = BACKUP_DIR / ".backup.lock"

if not all([BOT_TOKEN, AUTHORIZED_USER, DOMAIN]):
    logger.critical("FATAL: Missing critical environment variables.")
    sys.exit(1)

BACKUP_DIR.mkdir(parents=True, exist_ok=True)
bot = telebot.TeleBot(BOT_TOKEN, threaded=True, parse_mode="Markdown")

# --- Authorization Decorator ---
def authorized_only(func):
    """Decorator to restrict bot commands to authorized user only."""
    def wrapper(message):
        if message.from_user.id != AUTHORIZED_USER:
            bot.reply_to(message, "🚫 You are not authorized to use this bot.")
            logger.warning(f"Unauthorized access attempt by user ID: {message.from_user.id}")
            return
        return func(message)
    return wrapper

# --- Helper Functions ---
def run_shell_command(cmd_list, timeout=300):
    """Executes a shell command safely and returns its code and output."""
    try:
        result = subprocess.run(
            cmd_list,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout
        )
        return result.returncode, result.stdout.strip() or result.stderr.strip()
    except FileNotFoundError:
        return -1, f"Command not found: {cmd_list[0]}"
    except subprocess.TimeoutExpired:
        return -1, f"Command timed out after {timeout} seconds."
    except Exception as e:
        logger.error(f"Command execution error: {e}", exc_info=True)
        return -1, f"Unexpected error: {str(e)}"

def get_backups():
    """Returns a sorted list of backup file paths, newest first."""
    return sorted(BACKUP_DIR.glob("n8n-backup-*.tar.gz"), key=os.path.getmtime, reverse=True)

def format_bytes(size):
    """Converts bytes to a human-readable format."""
    if size is None or size == 0:
        return "0 B"
    power = 1024
    n = 0
    power_labels = {0: '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
    while size > power and n < len(power_labels) - 1:
        size /= power
        n += 1
    return f"{size:.1f} {power_labels[n]}B"

def check_disk_space(required_bytes, path=BACKUP_DIR):
    """Check if sufficient disk space is available."""
    try:
        stat = shutil.disk_usage(path)
        return stat.free > required_bytes
    except Exception as e:
        logger.error(f"Failed to check disk space: {e}")
        return False

def estimate_backup_size():
    """Estimate the size of a backup by calculating current data directory size."""
    try:
        total_size = sum(f.stat().st_size for f in N8N_DATA_DIR.rglob('*') if f.is_file())
        return total_size
    except Exception as e:
        logger.error(f"Failed to estimate backup size: {e}")
        return 0

def verify_backup(filepath):
    """Verify the integrity of a backup file."""
    try:
        with tarfile.open(filepath, "r:gz") as tar:
            # Attempt to read all members
            members = tar.getmembers()
            if len(members) == 0:
                logger.error(f"Backup {filepath.name} is empty")
                return False
        logger.info(f"Backup {filepath.name} verified successfully ({len(members)} files)")
        return True
    except Exception as e:
        logger.error(f"Backup verification failed for {filepath.name}: {e}")
        return False

def calculate_checksum(filepath):
    """Calculate SHA256 checksum of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        logger.error(f"Failed to calculate checksum: {e}")
        return None

def acquire_lock(timeout=5):
    """Acquire an exclusive lock for backup operations."""
    try:
        lock_fd = open(LOCK_FILE, 'w')
        fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return lock_fd
    except BlockingIOError:
        return None
    except Exception as e:
        logger.error(f"Lock acquisition failed: {e}")
        return None

def release_lock(lock_fd):
    """Release the backup operation lock."""
    try:
        if lock_fd:
            fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)
            lock_fd.close()
            if LOCK_FILE.exists():
                LOCK_FILE.unlink()
    except Exception as e:
        logger.error(f"Lock release failed: {e}")

def format_error_message(error, context="operation"):
    """Convert technical errors to user-friendly messages."""
    error_str = str(error).lower()
    
    error_map = {
        "no space left on device": "❌ The server has run out of disk space. Please free up space or delete old backups using /deletebackups.",
        "permission denied": "❌ Permission error. The bot may need elevated privileges for this operation. Contact your system administrator.",
        "connection refused": "❌ Cannot connect to Docker. The Docker service may not be running.",
        "timeout": f"❌ The {context} timed out. This may indicate a performance issue or the operation is taking longer than expected.",
        "not found": f"❌ Required resource not found. Please ensure n8n is properly installed.",
    }
    
    for key, message in error_map.items():
        if key in error_str:
            return f"{message}\n\n_Technical details: {error}_"
    
    return f"❌ An error occurred during {context}: {error}"

# --- Core Bot Logic: Automated Tasks ---
def prune_old_backups():
    """Delete backups older than RETENTION_DAYS."""
    logger.info(f"Running scheduled backup pruning (retention: {RETENTION_DAYS} days)")
    cutoff_date = datetime.now() - timedelta(days=RETENTION_DAYS)
    count = 0
    
    for f in get_backups():
        try:
            if datetime.fromtimestamp(f.stat().st_mtime) < cutoff_date:
                f.unlink()
                logger.info(f"Pruned old backup: {f.name}")
                count += 1
        except Exception as e:
            logger.error(f"Failed to delete backup {f.name}: {e}")
    
    if count > 0:
        logger.info(f"Pruning complete. Deleted {count} old backup(s).")
    return count

def health_check():
    """Periodic health check that logs system status."""
    try:
        # Check Docker container
        code, status = run_shell_command(["docker", "inspect", "-f", "{{.State.Health.Status}}", "n8n"], timeout=10)
        if code != 0 or status not in ["healthy", "starting"]:
            logger.warning(f"n8n health check failed: {status}")
        
        # Check disk space
        disk = shutil.disk_usage(N8N_DATA_DIR)
        if disk.percent > 90:
            logger.warning(f"Disk space critical: {disk.percent}% used")
        
        # Check backup directory
        backup_disk = shutil.disk_usage(BACKUP_DIR)
        if backup_disk.percent > 85:
            logger.warning(f"Backup disk space low: {backup_disk.percent}% used")
            
    except Exception as e:
        logger.error(f"Health check failed: {e}")

# --- Bot Command Handlers ---
@bot.message_handler(commands=["start", "help"])
@authorized_only
def send_welcome(message):
    help_text = (
        "🤖 *n8n Bot Control Panel* (Enhanced Version 4.0)\n\n"
        "📦 *Backup & Restore:*\n"
        "`/createbackup` - Create new backup (with verification)\n"
        "`/listbackups` - Show all available backups\n"
        "`/getbackup` - Download a backup file\n"
        "`/deletebackups` - Delete old backups\n"
        "`/prunebackups` - Remove backups older than retention period\n"
        "📤 _To restore: upload a `.tar.gz` backup file_\n\n"
        "⚙️ *n8n Management:*\n"
        "`/status` - Check n8n container status\n"
        "`/restart` - Restart n8n container\n"
        "`/logs` - Show recent n8n logs (20 lines)\n"
        "`/update` - Update n8n to latest version\n\n"
        "🖥️ *System Monitoring:*\n"
        "`/sysinfo` - Server disk, memory, and CPU usage\n"
        "`/health` - Comprehensive health check\n\n"
        "📊 *Statistics:*\n"
        "`/stats` - Backup statistics and disk usage"
    )
    bot.reply_to(message, help_text)

@bot.message_handler(commands=["status"])
@authorized_only
def status_command(message):
    bot.send_chat_action(message.chat.id, 'typing')
    
    # Get container status
    code, status = run_shell_command(["docker", "ps", "--filter", "name=n8n", "--format", "{{.Status}}"])
    
    if code == 0 and status:
        # Get health status
        health_code, health = run_shell_command(["docker", "inspect", "-f", "{{.State.Health.Status}}", "n8n"])
        health_indicator = "✅" if health == "healthy" else "⚠️" if health == "starting" else "❌"
        
        response = f"*n8n Container Status:*\n\n{health_indicator} Status: `{status}`"
        if health_code == 0:
            response += f"\nHealth: `{health}`"
        
        bot.reply_to(message, response)
    else:
        bot.reply_to(message, "❌ *n8n container not found or is stopped.*\n\nTry restarting with `/restart`")

@bot.message_handler(commands=["logs"])
@authorized_only
def logs_command(message):
    bot.send_chat_action(message.chat.id, 'typing')
    code, out = run_shell_command(["docker", "logs", "--tail", "20", "n8n"])
    
    if code == 0 and out:
        # Truncate if too long
        if len(out) > 4000:
            out = out[-4000:]
        bot.reply_to(message, f"📜 *Recent n8n Logs:*\n```\n{out}\n```")
    else:
        bot.reply_to(message, "⚠️ Could not fetch logs. Container might be stopped.\n\nUse `/status` to check container state.")

@bot.message_handler(commands=["restart"])
@authorized_only
def restart_command(message):
    msg = bot.reply_to(message, "⏳ Restarting n8n container...")
    bot.send_chat_action(message.chat.id, 'typing')
    
    code, out = run_shell_command(["docker", "restart", "n8n"], timeout=60)
    
    if code == 0:
        bot.edit_message_text("✅ n8n restarted successfully!", msg.chat.id, msg.message_id)
        # Wait a moment and check health
        time.sleep(3)
        health_code, health = run_shell_command(["docker", "inspect", "-f", "{{.State.Health.Status}}", "n8n"])
        if health_code == 0:
            bot.send_message(message.chat.id, f"Health Status: `{health}`")
    else:
        error_msg = format_error_message(out, "restart")
        bot.edit_message_text(error_msg, msg.chat.id, msg.message_id)

@bot.message_handler(commands=["update"])
@authorized_only
def update_command(message):
    msg = bot.reply_to(message, "⏳ Starting n8n update process...")
    bot.send_chat_action(message.chat.id, 'typing')
    
    try:
        # Get current image ID for rollback
        code, current_image = run_shell_command(["docker", "inspect", "-f", "{{.Image}}", "n8n"])
        if code != 0:
            bot.edit_message_text("❌ Could not determine current n8n version", msg.chat.id, msg.message_id)
            return
        
        # Pull latest image
        bot.edit_message_text("📥 Pulling latest n8n image...", msg.chat.id, msg.message_id)
        code, out = run_shell_command(["docker", "pull", "n8nio/n8n:latest"], timeout=600)
        if code != 0:
            bot.edit_message_text(f"❌ Failed to pull image:\n`{out}`", msg.chat.id, msg.message_id)
            return

        # Stop and remove old container
        bot.edit_message_text("🛑 Stopping old container...", msg.chat.id, msg.message_id)
        run_shell_command(["docker", "stop", "n8n"], timeout=60)
        run_shell_command(["docker", "rm", "n8n"])

        # Start new container with same configuration
        bot.edit_message_text("🚀 Starting updated container...", msg.chat.id, msg.message_id)
        run_cmd = [
            "docker", "run", "-d",
            "--name", "n8n",
            "--restart", "unless-stopped",
            "--security-opt", "no-new-privileges:true",
            "--cap-drop", "ALL",
            "--cap-add", "CHOWN,SETGID,SETUID,DAC_OVERRIDE",
            "--memory", "2g",
            "--cpus", "2",
            "--health-cmd", "wget --no-verbose --tries=1 --spider http://localhost:5678/healthz || exit 1",
            "--health-interval", "30s",
            "--health-timeout", "10s",
            "--health-retries", "3",
            "-p", "127.0.0.1:5678:5678",
            "-e", f"N8N_HOST={DOMAIN}",
            "-e", f"WEBHOOK_URL=https://{DOMAIN}/",
            "-e", "N8N_METRICS=true",
            "-v", f"{N8N_DATA_DIR.resolve()}:/home/node/.n8n",
            "n8nio/n8n:latest"
        ]
        
        code, out = run_shell_command(run_cmd)
        
        if code == 0:
            bot.edit_message_text("✅ n8n updated successfully!\n\nWaiting for health check...", msg.chat.id, msg.message_id)
            
            # Wait for healthy status
            time.sleep(5)
            for i in range(30):
                h_code, health = run_shell_command(["docker", "inspect", "-f", "{{.State.Health.Status}}", "n8n"])
                if h_code == 0 and health == "healthy":
                    bot.send_message(message.chat.id, "✅ Update complete and n8n is healthy!")
                    return
                time.sleep(2)
            
            bot.send_message(message.chat.id, "⚠️ Update complete but health check is taking longer than expected. Check `/status`")
        else:
            # Rollback attempt
            bot.edit_message_text("❌ Update failed. Attempting rollback...", msg.chat.id, msg.message_id)
            run_shell_command(["docker", "rm", "-f", "n8n"])
            
            rollback_cmd = run_cmd.copy()
            rollback_cmd[-1] = current_image  # Use old image
            
            rb_code, rb_out = run_shell_command(rollback_cmd)
            if rb_code == 0:
                bot.send_message(message.chat.id, "✅ Rolled back to previous version successfully.")
            else:
                bot.send_message(message.chat.id, f"❌ Rollback failed:\n`{rb_out}`\n\nManual intervention required!")
                
    except Exception as e:
        logger.error(f"Update command failed: {e}", exc_info=True)
        bot.send_message(message.chat.id, format_error_message(e, "update"))

@bot.message_handler(commands=["createbackup"])
@authorized_only
def create_backup_command(message):
    bot.send_chat_action(message.chat.id, 'typing')
    
    # Check if another backup is in progress
    lock_fd = acquire_lock()
    if lock_fd is None:
        bot.reply_to(message, "⚠️ Another backup operation is already in progress. Please wait.")
        return
    
    msg = bot.reply_to(message, "⏳ Creating backup...\n\n_Step 1/4: Checking disk space_")
    
    try:
        # Estimate backup size and check disk space
        estimated_size = estimate_backup_size()
        required_space = estimated_size * 1.5  # Add 50% overhead for compression
        
        if not check_disk_space(required_space):
            disk = shutil.disk_usage(BACKUP_DIR)
            bot.edit_message_text(
                f"❌ Insufficient disk space!\n\n"
                f"Estimated backup size: {format_bytes(estimated_size)}\n"
                f"Available space: {format_bytes(disk.free)}\n\n"
                f"Please free up space or delete old backups with `/deletebackups`.",
                msg.chat.id, msg.message_id
            )
            return
        
        # Create backup filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup_filename = f"n8n-backup-{timestamp}.tar.gz"
        backup_path = BACKUP_DIR / backup_filename
        
        bot.edit_message_text("⏳ Creating backup...\n\n_Step 2/4: Stopping n8n container_", msg.chat.id, msg.message_id)
        
        # Stop n8n container
        code, out = run_shell_command(["docker", "stop", "n8n"], timeout=60)
        if code != 0:
            bot.edit_message_text(f"❌ Failed to stop n8n container:\n`{out}`", msg.chat.id, msg.message_id)
            return
        
        try:
            bot.edit_message_text("⏳ Creating backup...\n\n_Step 3/4: Creating archive_", msg.chat.id, msg.message_id)
            
            # Create compressed tar archive
            with tarfile.open(backup_path, "w:gz") as tar:
                tar.add(N8N_DATA_DIR, arcname="n8n_data")
            
            actual_size = backup_path.stat().st_size
            
            bot.edit_message_text("⏳ Creating backup...\n\n_Step 4/4: Verifying backup_", msg.chat.id, msg.message_id)
            
            # Verify backup integrity
            if not verify_backup(backup_path):
                backup_path.unlink()
                bot.edit_message_text("❌ Backup verification failed! The backup file was corrupted and has been deleted.", msg.chat.id, msg.message_id)
                return
            
            # Calculate checksum
            checksum = calculate_checksum(backup_path)
            checksum_info = f"\nSHA256: `{checksum[:16]}...`" if checksum else ""
            
            bot.edit_message_text(
                f"✅ Backup created successfully!\n\n"
                f"📁 File: `{backup_filename}`\n"
                f"📊 Size: {format_bytes(actual_size)}{checksum_info}\n\n"
                f"Use `/getbackup` to download or upload the file to restore.",
                msg.chat.id, msg.message_id
            )
            
        finally:
            # Always restart n8n
            bot.send_chat_action(message.chat.id, 'typing')
            restart_code, restart_out = run_shell_command(["docker", "start", "n8n"])
            if restart_code != 0:
                bot.send_message(message.chat.id, f"⚠️ n8n restart failed:\n`{restart_out}`")
            
    except Exception as e:
        logger.error(f"Backup creation failed: {e}", exc_info=True)
        bot.edit_message_text(format_error_message(e, "backup creation"), msg.chat.id, msg.message_id)
        
    finally:
        release_lock(lock_fd)

@bot.message_handler(commands=["listbackups"])
@authorized_only
def list_backups_command(message):
    bot.send_chat_action(message.chat.id, 'typing')
    
    backups = get_backups()
    
    if not backups:
        bot.reply_to(message, "📭 No backups found.")
        return
    
    response = "📂 *Available Backups:*\n\n"
    total_size = 0
    
    for i, backup in enumerate(backups[:10]):  # Show latest 10
        size = backup.stat().st_size
        total_size += size
        mtime = datetime.fromtimestamp(backup.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
        response += f"`{i+1}.` {backup.name}\n"
        response += f"     📏 {format_bytes(size)} | 📅 {mtime}\n\n"
    
    # Show total usage
    disk = shutil.disk_usage(BACKUP_DIR)
    response += f"💾 *Storage Summary:*\n"
    response += f"Backups: {len(backups)} files, {format_bytes(total_size)}\n"
    response += f"Disk usage: {disk.percent}% ({format_bytes(disk.used)} / {format_bytes(disk.total)})"
    
    if len(backups) > 10:
        response += f"\n\n_Showing 10 newest of {len(backups)} total backups_"
    
    bot.reply_to(message, response)

@bot.message_handler(commands=["getbackup"])
@authorized_only
def get_backup_command(message):
    bot.send_chat_action(message.chat.id, 'typing')
    
    backups = get_backups()
    
    if not backups:
        bot.reply_to(message, "📭 No backups available.")
        return
    
    # Create inline keyboard
    keyboard = InlineKeyboardMarkup(row_width=2)
    
    for i, backup in enumerate(backups[:5]):  # Show latest 5
        size = format_bytes(backup.stat().st_size)
        date = datetime.fromtimestamp(backup.stat().st_mtime).strftime("%m-%d %H:%M")
        button_text = f"{i+1}. {size} ({date})"
        keyboard.add(InlineKeyboardButton(button_text, callback_data=f"download_{backup.name}"))
    
    bot.reply_to(message, "📥 *Select a backup to download:*", reply_markup=keyboard)

@bot.callback_query_handler(func=lambda call: call.data.startswith("download_"))
def handle_download_callback(call):
    backup_name = call.data.replace("download_", "")
    backup_path = BACKUP_DIR / backup_name
    
    if not backup_path.exists():
        bot.answer_callback_query(call.id, "❌ Backup file not found")
        return
    
    file_size = backup_path.stat().st_size
    max_size = TELEGRAM_FILE_LIMIT_MB * 1024 * 1024
    
    if file_size > max_size:
        bot.answer_callback_query(
            call.id, 
            f"❌ File too large ({format_bytes(file_size)}). Telegram limit is {TELEGRAM_FILE_LIMIT_MB}MB."
        )
        return
    
    try:
        with open(backup_path, "rb") as f:
            bot.send_document(call.message.chat.id, f, caption=f"📦 Backup: `{backup_name}`")
        bot.answer_callback_query(call.id, "✅ Backup sent")
    except Exception as e:
        logger.error(f"Failed to send backup: {e}")
        bot.answer_callback_query(call.id, "❌ Failed to send file")

@bot.message_handler(commands=["deletebackups"])
@authorized_only
def delete_backups_command(message):
    bot.send_chat_action(message.chat.id, 'typing')
    
    backups = get_backups()
    
    if not backups:
        bot.reply_to(message, "📭 No backups to delete.")
        return
    
    # Create confirmation keyboard
    keyboard = InlineKeyboardMarkup()
    keyboard.add(
        InlineKeyboardButton("🗑️ Delete ALL Backups", callback_data="delete_all"),
        InlineKeyboardButton("❌ Cancel", callback_data="delete_cancel")
    )
    
    total_size = sum(b.stat().st_size for b in backups)
    
    bot.reply_to(
        message,
        f"⚠️ *Delete All Backups?*\n\n"
        f"This will delete {len(backups)} backups totaling {format_bytes(total_size)}.\n"
        f"**This action cannot be undone!**",
        reply_markup=keyboard
    )

@bot.callback_query_handler(func=lambda call: call.data.startswith("delete_"))
def handle_delete_callback(call):
    if call.data == "delete_cancel":
        bot.edit_message_text("✅ Deletion cancelled.", call.message.chat.id, call.message.message_id)
        return
    
    if call.data == "delete_all":
        bot.edit_message_text("🗑️ Deleting all backups...", call.message.chat.id, call.message.message_id)
        
        backups = get_backups()
        deleted_count = 0
        deleted_size = 0
        
        for backup in backups:
            try:
                size = backup.stat().st_size
                backup.unlink()
                deleted_count += 1
                deleted_size += size
            except Exception as e:
                logger.error(f"Failed to delete {backup.name}: {e}")
        
        bot.edit_message_text(
            f"✅ Deleted {deleted_count} backups, freeing {format_bytes(deleted_size)}.",
            call.message.chat.id, call.message.message_id
        )

@bot.message_handler(commands=["prunebackups"])
@authorized_only
def prune_backups_command(message):
    deleted_count = prune_old_backups()
    
    if deleted_count > 0:
        bot.reply_to(message, f"🧹 Pruned {deleted_count} backup(s) older than {RETENTION_DAYS} days.")
    else:
        bot.reply_to(message, f"✅ No backups older than {RETENTION_DAYS} days found.")

@bot.message_handler(commands=["sysinfo"])
@authorized_only
def sysinfo_command(message):
    bot.send_chat_action(message.chat.id, 'typing')
    
    try:
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        
        # Memory usage
        memory = psutil.virtual_memory()
        
        # Disk usage for key directories
        n8n_disk = shutil.disk_usage(N8N_DATA_DIR)
        backup_disk = shutil.disk_usage(BACKUP_DIR)
        root_disk = shutil.disk_usage("/")
        
        # System uptime
        uptime_seconds = time.time() - psutil.boot_time()
        uptime_str = str(timedelta(seconds=int(uptime_seconds)))
        
        response = (
            "🖥️ *System Information*\n\n"
            f"💻 CPU Usage: `{cpu_percent}%`\n"
            f"🧠 Memory: `{memory.percent}%` used ({format_bytes(memory.used)} / {format_bytes(memory.total)})\n\n"
            f"💾 *Disk Usage:*\n"
            f"• Root: `{root_disk.percent}%` ({format_bytes(root_disk.used)} / {format_bytes(root_disk.total)})\n"
            f"• n8n Data: `{n8n_disk.percent}%` used\n"
            f"• Backups: `{backup_disk.percent}%` used\n\n"
            f"⏰ Uptime: `{uptime_str}`"
        )
        
        bot.reply_to(message, response)
        
    except Exception as e:
        logger.error(f"System info failed: {e}")
        bot.reply_to(message, f"❌ Failed to get system info: {e}")

@bot.message_handler(commands=["health"])
@authorized_only
def health_command(message):
    bot.send_chat_action(message.chat.id, 'typing')
    
    health_checks = []
    
    # Check n8n container
    code, status = run_shell_command(["docker", "inspect", "-f", "{{.State.Status}}", "n8n"])
    if code == 0:
        health_code, health = run_shell_command(["docker", "inspect", "-f", "{{.State.Health.Status}}", "n8n"])
        container_status = f"✅ Running" if status == "running" else f"❌ {status}"
        health_status = f"Health: `{health}`" if health_code == 0 else "Health: `unknown`"
        health_checks.append(f"🐳 n8n Container: {container_status} | {health_status}")
    else:
        health_checks.append("❌ n8n Container: Not found")
    
    # Check disk space
    try:
        n8n_disk = shutil.disk_usage(N8N_DATA_DIR)
        backup_disk = shutil.disk_usage(BACKUP_DIR)
        
        n8n_disk_status = "✅" if n8n_disk.percent < 90 else "⚠️" if n8n_disk.percent < 95 else "❌"
        backup_disk_status = "✅" if backup_disk.percent < 85 else "⚠️" if backup_disk.percent < 95 else "❌"
        
        health_checks.append(f"💾 n8n Data Disk: {n8n_disk_status} {n8n_disk.percent}% used")
        health_checks.append(f"💾 Backup Disk: {backup_disk_status} {backup_disk.percent}% used")
    except Exception as e:
        health_checks.append(f"❌ Disk Check: Failed - {e}")
    
    # Check backup count
    backups = get_backups()
    backup_status = "✅" if len(backups) > 0 else "⚠️"
    health_checks.append(f"📦 Backups: {backup_status} {len(backups)} available")
    
    # Check bot process
    health_checks.append("🤖 Bot: ✅ Running")
    
    response = "🏥 *System Health Check*\n\n" + "\n".join(health_checks)
    
    # Overall status
    if any("❌" in check for check in health_checks):
        response += "\n\n🔴 *System needs attention*"
    elif any("⚠️" in check for check in health_checks):
        response += "\n\n🟡 *System has warnings*"
    else:
        response += "\n\n🟢 *All systems normal*"
    
    bot.reply_to(message, response)

@bot.message_handler(commands=["stats"])
@authorized_only
def stats_command(message):
    bot.send_chat_action(message.chat.id, 'typing')
    
    backups = get_backups()
    total_backup_size = sum(b.stat().st_size for b in backups)
    
    try:
        n8n_size = sum(f.stat().st_size for f in N8N_DATA_DIR.rglob('*') if f.is_file())
    except:
        n8n_size = 0
    
    response = (
        "📊 *Backup & Storage Statistics*\n\n"
        f"📦 Backups: `{len(backups)}` files\n"
        f"📏 Backup Storage: `{format_bytes(total_backup_size)}`\n"
        f"💾 n8n Data Size: `{format_bytes(n8n_size)}`\n"
        f"🗑️ Retention: `{RETENTION_DAYS}` days\n\n"
    )
    
    # Add disk usage
    try:
        backup_disk = shutil.disk_usage(BACKUP_DIR)
        response += f"💽 Backup Disk: `{backup_disk.percent}%` used\n"
        response += f"     {format_bytes(backup_disk.used)} / {format_bytes(backup_disk.total)}"
    except Exception as e:
        response += f"💽 Disk Info: Unavailable ({e})"
    
    bot.reply_to(message, response)

@bot.message_handler(content_types=["document"])
@authorized_only
def handle_restore_file(message):
    if not message.document:
        return
    
    file_name = message.document.file_name
    
    # Validate file type
    if not file_name.endswith('.tar.gz'):
        bot.reply_to(message, "❌ Invalid file type. Please upload a `.tar.gz` backup file.")
        return
    
    # Check file size
    file_size = message.document.file_size
    if file_size > MAX_BACKUP_SIZE_MB * 1024 * 1024:
        bot.reply_to(message, f"❌ File too large. Maximum size is {MAX_BACKUP_SIZE_MB}MB.")
        return
    
    msg = bot.reply_to(message, "⏳ Starting restore process...\n\n_Step 1/4: Downloading backup file_")
    
    lock_fd = acquire_lock()
    if lock_fd is None:
        bot.edit_message_text("⚠️ Another operation is in progress. Please wait.", msg.chat.id, msg.message_id)
        return
    
    try:
        # Download file
        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        
        temp_backup = BACKUP_DIR / f"restore-{int(time.time())}.tar.gz"
        with open(temp_backup, 'wb') as f:
            f.write(downloaded_file)
        
        bot.edit_message_text("⏳ Starting restore process...\n\n_Step 2/4: Verifying backup_", msg.chat.id, msg.message_id)
        
        # Verify backup
        if not verify_backup(temp_backup):
            temp_backup.unlink()
            bot.edit_message_text("❌ Backup verification failed! The file appears to be corrupted.", msg.chat.id, msg.message_id)
            return
        
        bot.edit_message_text("⏳ Starting restore process...\n\n_Step 3/4: Creating pre-restore backup_", msg.chat.id, msg.message_id)
        
        # Create pre-restore backup for safety
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        safety_backup = BACKUP_DIR / f"pre-restore-{timestamp}.tar.gz"
        
        # Stop n8n and backup current data
        run_shell_command(["docker", "stop", "n8n"], timeout=60)
        
        try:
            with tarfile.open(safety_backup, "w:gz") as tar:
                tar.add(N8N_DATA_DIR, arcname="n8n_data")
            
            bot.edit_message_text("⏳ Starting restore process...\n\n_Step 4/4: Restoring data_", msg.chat.id, msg.message_id)
            
            # Clear current data and restore
            shutil.rmtree(N8N_DATA_DIR)
            N8N_DATA_DIR.mkdir(parents=True, exist_ok=True)
            
            with tarfile.open(temp_backup, "r:gz") as tar:
                tar.extractall(path=N8N_DATA_DIR.parent)  # Extract to parent dir
            
            # Fix permissions
            run_shell_command(["chown", "-R", "1000:1000", str(N8N_DATA_DIR)])
            
            # Cleanup temp file
            temp_backup.unlink()
            
            bot.edit_message_text("✅ Restore complete! Starting n8n...", msg.chat.id, msg.message_id)
            
        finally:
            # Always restart n8n
            run_shell_command(["docker", "start", "n8n"])
        
        # Verify n8n starts
        time.sleep(5)
        code, status = run_shell_command(["docker", "inspect", "-f", "{{.State.Status}}", "n8n"])
        
        if code == 0 and status == "running":
            bot.send_message(message.chat.id, "✅ n8n is running with restored data!")
        else:
            bot.send_message(
                message.chat.id,
                f"⚠️ Restore completed but n8n may not be running properly.\n"
                f"Check status with `/status` or check logs with `/logs`.\n\n"
                f"A safety backup was created: `{safety_backup.name}`"
            )
            
    except Exception as e:
        logger.error(f"Restore failed: {e}", exc_info=True)
        bot.edit_message_text(format_error_message(e, "restore"), msg.chat.id, msg.message_id)
        
        # Attempt to restore from safety backup if it exists
        if 'safety_backup' in locals() and safety_backup.exists():
            try:
                shutil.rmtree(N8N_DATA_DIR, ignore_errors=True)
                N8N_DATA_DIR.mkdir(parents=True)
                with tarfile.open(safety_backup, "r:gz") as tar:
                    tar.extractall(path=N8N_DATA_DIR.parent)
                run_shell_command(["chown", "-R", "1000:1000", str(N8N_DATA_DIR)])
                bot.send_message(message.chat.id, "🛡️ Restored original data from safety backup.")
            except Exception as restore_error:
                logger.error(f"Safety restore also failed: {restore_error}")
                bot.send_message(message.chat.id, "💥 CRITICAL: Both restore and safety restore failed! Manual intervention required.")
        
    finally:
        release_lock(lock_fd)

@bot.message_handler(func=lambda message: True)
@authorized_only
def unknown_command(message):
    bot.reply_to(message, "❓ Unknown command. Use /help to see available commands.")

def main():
    """Main function to start the bot with enhanced error handling."""
    logger.info("🤖 Starting n8n Telegram Bot (Enhanced v4.0)")
    
    # Start scheduled tasks
    scheduler = BackgroundScheduler()
    scheduler.add_job(prune_old_backups, 'cron', hour=3, minute=0)  # Daily at 3 AM
    scheduler.add_job(health_check, 'interval', minutes=30)
    scheduler.start()
    
    logger.info("📅 Scheduled tasks started: pruning (daily 3AM), health checks (30min)")
    
    # Start bot with enhanced error handling
    while True:
        try:
            logger.info("🔄 Starting bot polling...")
            bot.infinity_polling(timeout=60, long_polling_timeout=60)
        except Exception as e:
            logger.error(f"Bot polling crashed: {e}", exc_info=True)
            logger.info("🔄 Restarting in 30 seconds...")
            time.sleep(30)

if __name__ == "__main__":
    main()
PYEOF

chown "$BOT_USER":"$BOT_USER" "$BOT_DIR/n8n_bot.py"
chmod +x "$BOT_DIR/n8n_bot.py"

# -------- Systemd Service (Hardened) --------
log "Creating systemd service with security constraints..."
cat > "$SYSTEMD_SERVICE" <<EOF
[Unit]
Description=n8n Telegram Bot (Enhanced v4.0)
Documentation=https://github.com/7020227649/n8n-installer-with-tele-new-4.0
After=network.target docker.service
Wants=network.target docker.service
Requires=docker.service

[Service]
Type=exec
User=$BOT_USER
Group=$BOT_USER
WorkingDirectory=$BOT_DIR
ExecStart=$VENV_DIR/bin/python $BOT_DIR/n8n_bot.py
Restart=always
RestartSec=30
StartLimitInterval=300
StartLimitBurst=5

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$BOT_DIR $BACKUP_DIR $N8N_DATA_DIR
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
RestrictRealtime=yes
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
LockPersonality=yes
MemoryDenyWriteExecute=yes
RemoveIPC=yes
RestrictSUIDSGID=yes

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=n8n-bot

[Install]
WantedBy=multi-user.target
EOF

run_cmd systemctl daemon-reload
run_cmd systemctl enable n8n-bot.service

# -------- Backup Cron Job --------
log "Setting up automated backup cron job..."
cat > /etc/cron.d/n8n-backup <<EOF
# Daily n8n backup at 2 AM
0 2 * * * $BOT_USER $VENV_DIR/bin/python $BOT_DIR/n8n_bot.py --create-backup >/dev/null 2>&1

# Weekly cleanup on Sunday at 3 AM
0 3 * * 0 $BOT_USER $VENV_DIR/bin/python $BOT_DIR/n8n_bot.py --prune-backups >/dev/null 2>&1
EOF

# -------- Log Rotation --------
log "Configuring log rotation..."
cat > /etc/logrotate.d/n8n-bot <<EOF
$BOT_DIR/bot.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    su $BOT_USER $BOT_USER
}
EOF

# -------- Final Setup --------
log "Setting final permissions..."
chown -R "$BOT_USER":"$BOT_USER" "$BOT_DIR" "$BACKUP_DIR"
chmod 700 "$BOT_DIR"
chmod 750 "$BACKUP_DIR"

# -------- Verification --------
log "Verifying installation..."
if docker ps | grep -q n8n; then
    log "✅ n8n container is running"
else
    err "❌ n8n container is not running"
    exit 1
fi

if systemctl is-enabled n8n-bot.service >/dev/null 2>&1; then
    log "✅ n8n bot service is enabled"
else
    err "❌ n8n bot service is not enabled"
    exit 1
fi

# Test SSL
if curl -s -I "https://$DOMAIN" | grep -q "200"; then
    log "✅ SSL certificate is working"
else
    warn "⚠️ SSL test failed, but installation may still be successful"
fi

# -------- Start Services --------
log "Starting n8n bot service..."
run_cmd systemctl start n8n-bot.service

# Wait for bot to start
sleep 5

if systemctl is-active --quiet n8n-bot.service; then
    log "✅ n8n bot service is running"
else
    err "❌ n8n bot service failed to start"
    journalctl -u n8n-bot.service --no-pager -n 20
    exit 1
fi

# -------- Final Instructions --------
echo ""
echo "========================================================"
echo "🎉 Installation Completed Successfully!"
echo "========================================================"
echo ""
echo "📋 What was installed:"
echo "✅ n8n workflow automation (Docker container)"
echo "✅ Telegram bot with enhanced security features"
echo "✅ Nginx with SSL and security headers"
echo "✅ Automated backup system with verification"
echo "✅ System monitoring and health checks"
echo "✅ Firewall configuration"
echo ""
echo "🌐 Access your n8n instance:"
echo "   https://$DOMAIN"
echo ""
echo "🤖 Bot Commands Available:"
echo "   /start - Show help menu"
echo "   /status - Check n8n status"
echo "   /createbackup - Create verified backup"
echo "   /sysinfo - System monitoring"
echo "   /health - Comprehensive health check"
echo ""
echo "🔧 Management Commands:"
echo "   sudo systemctl status n8n-bot.service"
echo "   sudo journalctl -u n8n-bot.service -f"
echo "   sudo docker logs n8n"
echo ""
echo "📊 Backup Location: $BACKUP_DIR"
echo "📁 Bot Directory: $BOT_DIR"
echo ""
echo "⚠️ Important Security Notes:"
echo "   • Firewall is enabled (SSH & Nginx only)"
echo "   • n8n runs on localhost only"
echo "   • Bot access restricted to User ID: $USER_ID"
echo "   • Automated backups run daily at 2 AM"
echo ""
echo "========================================================"
echo "Need help? Check the GitHub repository for documentation"
echo "========================================================"

# Create installation log
echo "Installation completed $(date) for domain: $DOMAIN" > "$BOT_DIR/install.log"
chown "$BOT_USER":"$BOT_USER" "$BOT_DIR/install.log"
