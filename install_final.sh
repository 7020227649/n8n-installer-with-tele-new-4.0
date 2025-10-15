#!/usr/bin/env bash
# ------------------------------------------------------------------
# n8n + Telegram Bot Unified Installer (Improved Version)
#
# - Addresses critical flaws from the original script.
# - Adds full backup management: list, delete, auto-pruning.
# - Implements safe, confirmation-based restore.
# - Handles large backup files gracefully to prevent crashes.
# - Adds system health monitoring and automatic log rotation.
# - Uses interactive keyboards in Telegram for a better UX.
#
# Usage (as root):
#   curl -fsSL <URL_TO_THIS_SCRIPT> | sudo bash
# Or with arguments to skip prompts:
#   sudo bash install_improved.sh your.domain.com your@email.com YOUR_BOT_TOKEN YOUR_USER_ID
# ------------------------------------------------------------------

set -euo pipefail
IFS=$'\n\t'

# -------- Helpers --------
log() { echo -e "\n[INFO] $*"; }
warn() { echo -e "\n[WARN] $*" >&2; }
err() { echo -e "\n[ERROR] $*" >&2; }
# A function to run a command and log its output, or log an error if it fails.
run_cmd() {
    log "Executing: $*"
    if ! "$@"; then
        err "Command failed: $*"
        return 1
    fi
}

# -------- Input handling (args or interactive) --------
ARG_DOMAIN=${1:-}
ARG_EMAIL=${2:-}
ARG_BOT_TOKEN=${3:-}
ARG_USER_ID=${4:-}

# Function to prompt for non-empty input, with an option for hidden (secret) input.
prompt_nonempty() {
  local prompt_text="$1"
  local default_val="$2"
  local is_secret="${3:-false}"
  local user_input=""
  while true; do
    if [[ "$is_secret" == "true" ]]; then
      read -r -s -p "$prompt_text" user_input || true
      echo # Move to the next line after secret input
    else
      read -r -p "$prompt_text" user_input || true
    fi
    # Use default if user input is empty
    user_input="${user_input:-$default_val}"
    if [[ -n "$user_input" ]]; then
      echo "$user_input"
      return 0
    else
      echo "Input cannot be empty. Please try again."
    fi
  done
}

# Determine inputs: use arguments if provided, otherwise switch to interactive prompts.
if [[ -n "$ARG_DOMAIN" && -n "$ARG_EMAIL" && -n "$ARG_BOT_TOKEN" && -n "$ARG_USER_ID" ]]; then
  DOMAIN="$ARG_DOMAIN"
  EMAIL="$ARG_EMAIL"
  BOT_TOKEN="$ARG_BOT_TOKEN"
  USER_ID="$ARG_USER_ID"
else
  echo "--- Interactive Setup ---"
  DOMAIN=$(prompt_nonempty "🧩 Enter your domain name (e.g., n8n.example.com): " "$ARG_DOMAIN" false)
  EMAIL=$(prompt_nonempty "📧 Enter your email (for SSL certificate): " "$ARG_EMAIL" false)
  BOT_TOKEN=$(prompt_nonempty "🤖 Enter your Telegram Bot Token (input hidden): " "$ARG_BOT_TOKEN" true)
  USER_ID=$(prompt_nonempty "👤 Enter your numeric Telegram User ID: " "$ARG_USER_ID" false)
fi

# Validate that the User ID is numeric.
if ! [[ "$USER_ID" =~ ^[0-9]+$ ]]; then
  err "AUTHORIZED USER ID must be a numeric Telegram user ID."
  exit 1
fi

# -------- Configuration --------
BOT_DIR="/opt/n8n_bot"
BACKUP_DIR="/opt/n8n_backups"
N8N_DATA_DIR="/var/n8n"
BOT_USER="n8nbot"
VENV_DIR="$BOT_DIR/venv"
SYSTEMD_SERVICE="/etc/systemd/system/n8n-bot.service"
NGINX_CONF="/etc/nginx/sites-available/n8n"
REQUIRED_PACKAGES=(bash curl sudo gnupg ca-certificates lsb-release unzip software-properties-common nginx ufw python3 python3-venv python3-pip)

# -------- Pre-flight Check --------
if [[ $EUID -ne 0 ]]; then
  err "This installer must be run as root. Please use 'sudo'."
  exit 1
fi

log "🚀 Starting n8n and Telegram Bot installation for domain: $DOMAIN"

# -------- System & Package Installation --------
log "Updating package lists and installing dependencies..."
export DEBIAN_FRONTEND=noninteractive
run_cmd apt-get update -y
run_cmd apt-get install -y "${REQUIRED_PACKAGES[@]}"

# -------- Docker Setup (Idempotent) --------
if ! command -v docker >/dev/null 2>&1; then
  log "Installing Docker..."
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

# -------- NEW: Configure Docker for Automatic Log Rotation --------
log "Configuring Docker daemon for automatic log rotation..."
mkdir -p /etc/docker
cat > /etc/docker/daemon.json <<EOF
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
EOF
run_cmd systemctl restart docker

# -------- System User & Directories --------
if ! id -u "$BOT_USER" >/dev/null 2>&1; then
  log "Creating dedicated system user '$BOT_USER'..."
  useradd --system --home-dir "$BOT_DIR" --shell /usr/sbin/nologin --create-home "$BOT_USER"
else
  log "User '$BOT_USER' already exists."
fi

log "Creating required directories..."
mkdir -p "$BOT_DIR" "$BACKUP_DIR" "$N8N_DATA_DIR"
# The n8n container user (node) has UID 1000.
chown 1000:1000 "$N8N_DATA_DIR"
chown -R "$BOT_USER":"$BOT_USER" "$BOT_DIR" "$BACKUP_DIR"
chmod 750 "$BOT_DIR" "$BACKUP_DIR"

# -------- n8n Docker Container --------
log "Ensuring n8n Docker container is running..."
if docker ps -a --format '{{.Names}}' | grep -Eq "^n8n$"; then
  log "n8n container already exists. Ensuring it is started."
  run_cmd docker start n8n
else
  log "Creating and starting new n8n container."
  run_cmd docker run -d --restart unless-stopped --name n8n \
    -p 127.0.0.1:5678:5678 \
    -e N8N_HOST="$DOMAIN" \
    -e WEBHOOK_URL="https://$DOMAIN/" \
    -v "$N8N_DATA_DIR:/home/node/.n8n" \
    n8nio/n8n:latest
fi

# -------- Nginx & SSL Configuration --------
log "Configuring Nginx reverse proxy..."
cat > "$NGINX_CONF" <<EOF
server {
    listen 80;
    server_name $DOMAIN;

    # Forward validation requests to Certbot
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    server_name $DOMAIN;

    # SSL settings will be added by Certbot here
    # ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    # ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    # include /etc/letsencrypt/options-ssl-nginx.conf;
    # ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    client_max_body_size 200M; # For large webhook payloads

    location / {
        proxy_pass http://127.0.0.1:5678;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade"; # Required for WebSockets
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400s; # Long timeout for long-running workflows
    }
}
EOF
ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Create dummy webroot for Certbot
mkdir -p /var/www/html
run_cmd nginx -t && systemctl reload nginx

log "Obtaining/renewing SSL certificate with Certbot..."
# Use --nginx flag to automatically configure Nginx for SSL
if ! certbot --nginx --non-interactive --agree-tos -m "$EMAIL" -d "$DOMAIN"; then
    warn "Certbot failed. This can happen if your domain is not pointing to this server's IP address."
    warn "Please check your DNS records and re-run the script."
    exit 1
fi
run_cmd systemctl reload nginx

# -------- Firewall Setup --------
log "Configuring UFW firewall..."
run_cmd ufw allow OpenSSH
run_cmd ufw allow 'Nginx Full'
run_cmd ufw --force enable

# -------- Python Bot Setup --------
log "Setting up Python virtual environment..."
run_cmd python3 -m venv "$VENV_DIR"
PIP="$VENV_DIR/bin/pip"
run_cmd "$PIP" install --upgrade pip
# NEW: Added apscheduler for automated tasks and psutil for system info
run_cmd "$PIP" install pyTelegramBotAPI python-dotenv apscheduler psutil

log "Writing bot configuration file..."
cat > "$BOT_DIR/n8n_bot_config.env" <<EOF
BOT_TOKEN=$BOT_TOKEN
AUTHORIZED_USER=$USER_ID
DOMAIN=$DOMAIN
BACKUP_DIR=$BACKUP_DIR
N8N_DATA_DIR=$N8N_DATA_DIR
LOG_FILE_PATH=$BOT_DIR/bot.log
# NEW: Configurable backup retention policy
BACKUP_RETENTION_DAYS=7
EOF
chown "$BOT_USER":"$BOT_USER" "$BOT_DIR/n8n_bot_config.env"
chmod 600 "$BOT_DIR/n8n_bot_config.env" # More secure permissions

log "Embedding Python bot script..."
# This heredoc contains the entire, improved Python bot logic.
cat > "$BOT_DIR/n8n_bot.py" <<'PYEOF'
#!/usr/bin/env python3
"""
n8n Telegram Bot - Improved & Hardened Version
"""
import os
import sys
import time
import logging
import tarfile
import subprocess
import shutil
import psutil
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta, date
from glob import glob
from pathlib import Path
from dotenv import load_dotenv
import telebot
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton
from apscheduler.schedulers.background import BackgroundScheduler

# --- Initial Configuration ---
# Load environment variables from the config file.
env_path = Path(__file__).parent / "n8n_bot_config.env"
if not env_path.exists():
    # Use print for early errors before logging is configured.
    print(f"FATAL: Config file not found at {env_path}")
    sys.exit(1)
load_dotenv(dotenv_path=env_path)

# --- Logging Setup ---
LOG_FILE = os.getenv("LOG_FILE_PATH", "bot.log")
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
# Use a rotating file handler to prevent log files from growing indefinitely.
file_handler = RotatingFileHandler(LOG_FILE, maxBytes=5*1024*1024, backupCount=2)
file_handler.setFormatter(log_formatter)
# Also log to console for systemd logs.
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(file_handler)
logger.addHandler(console_handler)

# --- Bot & App Configuration ---
BOT_TOKEN = os.getenv("BOT_TOKEN")
AUTHORIZED_USER = int(os.getenv("AUTHORIZED_USER", 0))
DOMAIN = os.getenv("DOMAIN")
BACKUP_DIR = Path(os.getenv("BACKUP_DIR", "/opt/n8n_backups"))
N8N_DATA_DIR = Path(os.getenv("N8N_DATA_DIR", "/var/n8n"))
RETENTION_DAYS = int(os.getenv("BACKUP_RETENTION_DAYS", 7))
TELEGRAM_FILE_LIMIT_MB = 45 # Safer limit than 50MB

if not all([BOT_TOKEN, AUTHORIZED_USER, DOMAIN]):
    logger.critical("FATAL: Missing critical environment variables (BOT_TOKEN, AUTHORIZED_USER, DOMAIN).")
    sys.exit(1)

# Ensure directories exist.
BACKUP_DIR.mkdir(parents=True, exist_ok=True)
bot = telebot.TeleBot(BOT_TOKEN, threaded=True, parse_mode="Markdown")

# --- Authorization Decorator ---
# A clean way to protect all bot handlers.
def authorized_only(func):
    def wrapper(message):
        if message.from_user.id != AUTHORIZED_USER:
            bot.reply_to(message, "🚫 You are not authorized to use this bot.")
            logger.warning(f"Unauthorized access attempt by user ID: {message.from_user.id}")
            return
        return func(message)
    return wrapper

# --- Helper Functions ---
def run_shell_command(cmd_list):
    """Executes a shell command safely and returns its code and output."""
    try:
        result = subprocess.run(
            cmd_list,
            capture_output=True,
            text=True,
            check=False,  # Don't raise exception on non-zero exit codes
            timeout=300 # 5 minute timeout for long operations
        )
        return result.returncode, result.stdout.strip() or result.stderr.strip()
    except FileNotFoundError:
        return -1, f"Command not found: {cmd_list[0]}"
    except subprocess.TimeoutExpired:
        return -1, "Command timed out."
    except Exception as e:
        return -1, f"An unexpected error occurred: {str(e)}"

def get_backups():
    """Returns a sorted list of backup file paths, newest first."""
    return sorted(BACKUP_DIR.glob("n8n-backup-*.tar.gz"), key=os.path.getmtime, reverse=True)

def format_bytes(size):
    """Converts bytes to a human-readable format (KB, MB, GB)."""
    if size is None: return "0 B"
    power = 1024
    n = 0
    power_labels = {0: '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
    while size > power and n < len(power_labels):
        size /= power
        n += 1
    return f"{size:.1f} {power_labels[n]}B"

# --- Core Bot Logic: Automated Tasks ---
def prune_old_backups():
    """Deletes backups older than RETENTION_DAYS."""
    logger.info(f"Running scheduled backup pruning. Retaining backups from the last {RETENTION_DAYS} days.")
    cutoff_date = datetime.now() - timedelta(days=RETENTION_DAYS)
    count = 0
    for f in get_backups():
        if datetime.fromtimestamp(f.stat().st_mtime) < cutoff_date:
            try:
                f.unlink()
                logger.info(f"Pruned old backup: {f.name}")
                count += 1
            except Exception as e:
                logger.error(f"Failed to delete backup {f.name}: {e}")
    if count > 0:
        logger.info(f"Pruning complete. Deleted {count} old backup(s).")
    return count

# --- Bot Command Handlers ---
@bot.message_handler(commands=["start", "help"])
@authorized_only
def send_welcome(message):
    help_text = (
        "🤖 *n8n Bot Control Panel*\n\n"
        "Here are the available commands:\n\n"
        "📦 *Backup & Restore:*\n"
        "`/createbackup` - Create a new backup of n8n data.\n"
        "`/listbackups` - Show all available backups.\n"
        "`/getbackup` - Show a menu to download a backup file.\n"
        "`/deletebackups` - Show a menu to delete backups.\n"
        "`/prunebackups` - Manually delete backups older than retention period.\n"
        "📤 _To restore, simply upload a `.tar.gz` backup file to this chat._\n\n"
        "⚙️ *n8n Management:*\n"
        "`/status` - Check if the n8n container is running.\n"
        "`/restart` - Restart the n8n container.\n"
        "`/logs` - Show the 20 most recent n8n container logs.\n"
        "`/update` - Pull the latest n8n image and recreate the container.\n\n"
        "🖥️ *System:*\n"
        "`/sysinfo` - Show server disk, memory, and CPU usage."
    )
    bot.reply_to(message, help_text)

@bot.message_handler(commands=["status"])
@authorized_only
def status_command(message):
    code, out = run_shell_command(["docker", "ps", "--filter", "name=n8n", "--format", "{{.Status}}"])
    if code == 0 and out:
        bot.reply_to(message, f"✅ *n8n Status:*\n`{out}`")
    else:
        bot.reply_to(message, f"❌ *n8n container not found or is stopped.*\n`{out}`")

@bot.message_handler(commands=["logs"])
@authorized_only
def logs_command(message):
    bot.send_chat_action(message.chat.id, 'typing')
    code, out = run_shell_command(["docker", "logs", "--tail", "20", "n8n"])
    if code == 0 and out:
        # Split message if too long for Telegram
        if len(out) > 4000:
            out = out[-4000:]
        bot.reply_to(message, f"📜 *Recent n8n Logs:*\n```\n{out}\n```")
    else:
        bot.reply_to(message, f"⚠️ Could not fetch logs. Container might be stopped.\n`{out}`")

@bot.message_handler(commands=["restart"])
@authorized_only
def restart_command(message):
    bot.reply_to(message, "⏳ Restarting n8n container...")
    bot.send_chat_action(message.chat.id, 'typing')
    code, out = run_shell_command(["docker", "restart", "n8n"])
    if code == 0:
        bot.send_message(message.chat.id, "✅ n8n restarted successfully!")
    else:
        bot.send_message(message.chat.id, f"❌ Failed to restart n8n:\n`{out}`")

@bot.message_handler(commands=["update"])
@authorized_only
def update_command(message):
    msg = bot.reply_to(message, "⏳ Pulling latest n8n image... this may take a moment.")
    bot.send_chat_action(message.chat.id, 'typing')
    code, out = run_shell_command(["docker", "pull", "n8nio/n8n:latest"])
    if code != 0:
        bot.edit_message_text(f"❌ Failed to pull image:\n`{out}`", msg.chat.id, msg.message_id)
        return

    bot.edit_message_text("🛑 Stopping and removing old container...", msg.chat.id, msg.message_id)
    run_shell_command(["docker", "stop", "n8n"])
    run_shell_command(["docker", "rm", "n8n"])

    bot.edit_message_text("🚀 Starting new container...", msg.chat.id, msg.message_id)
    run_cmd = [
        "docker", "run", "-d", "--restart", "unless-stopped", "--name", "n8n",
        "-p", "127.0.0.1:5678:5678",
        "-e", f"N8N_HOST={DOMAIN}",
        "-e", f"WEBHOOK_URL=https://{DOMAIN}/",
        "-v", f"{N8N_DATA_DIR.resolve()}:/home/node/.n8n",
        "n8nio/n8n:latest"
    ]
    code, out = run_shell_command(run_cmd)
    if code == 0:
        bot.edit_message_text("✅ n8n updated and restarted successfully!", msg.chat.id, msg.message_id)
    else:
        bot.edit_message_text(f"❌ Update failed during container creation:\n`{out}`", msg.chat.id, msg.message_id)

@bot.message_handler(commands=["createbackup"])
@authorized_only
def create_backup_command(message):
    bot.reply_to(message, "⏳ Creating backup... this might take a while for large instances.")
    bot.send_chat_action(message.chat.id, 'typing')
    
    filename = f"n8n-backup-{date.today().isoformat()}-{int(time.time())}.tar.gz"
    filepath = BACKUP_DIR / filename
    
    try:
        with tarfile.open(filepath, "w:gz") as tar:
            tar.add(N8N_DATA_DIR, arcname=N8N_DATA_DIR.name)
        
        file_size = format_bytes(filepath.stat().st_size)
        prune_old_backups() # Prune after creating a new one
        bot.send_message(message.chat.id, f"✅ Backup created successfully!\n\n`{filename}` ({file_size})")
    except Exception as e:
        logger.error(f"Backup creation failed: {e}")
        bot.send_message(message.chat.id, f"❌ Backup failed: {str(e)}")

@bot.message_handler(commands=["listbackups"])
@authorized_only
def list_backups_command(message):
    bot.send_chat_action(message.chat.id, 'typing')
    backups = get_backups()
    if not backups:
        bot.reply_to(message, "No backups found.")
        return
    
    response = "*Available Backups (newest first):*\n\n"
    for bf in backups[:20]: # Show max 20
        stat = bf.stat()
        response += f"`{bf.name}`\n"
        response += f"_{format_bytes(stat.st_size)} - {datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M')}_\n\n"
    
    if len(backups) > 20:
        response += f"...and {len(backups) - 20} more."
        
    bot.reply_to(message, response)

@bot.message_handler(commands=["sysinfo"])
@authorized_only
def sysinfo_command(message):
    try:
        disk = shutil.disk_usage("/")
        mem = psutil.virtual_memory()
        cpu = psutil.cpu_percent(interval=1)
        
        info = (
            f"🖥️ *System Information*\n\n"
            f"💾 *Disk Usage:*\n"
            f"Total: {format_bytes(disk.total)}\n"
            f"Used: {format_bytes(disk.used)} ({disk.percent}%)\n"
            f"Free: {format_bytes(disk.free)}\n\n"
            f"🧠 *Memory Usage:*\n"
            f"Total: {format_bytes(mem.total)}\n"
            f"Used: {format_bytes(mem.used)} ({mem.percent}%)\n\n"
            f"⚙️ *CPU Load:* {cpu}%"
        )
        bot.reply_to(message, info)
    except Exception as e:
        logger.error(f"Could not retrieve system info: {e}")
        bot.reply_to(message, f"❌ Failed to get system info: {e}")
        
@bot.message_handler(commands=["prunebackups"])
@authorized_only
def prune_command(message):
    bot.reply_to(message, "⏳ Manually running backup pruning...")
    count = prune_old_backups()
    bot.send_message(message.chat.id, f"✅ Pruning complete. Deleted {count} old backup(s).")

# --- Interactive Menu Handlers ---

def build_backup_menu(action_prefix):
    """Builds an inline keyboard menu for backups."""
    markup = InlineKeyboardMarkup()
    markup.row_width = 1
    backups = get_backups()
    if not backups:
        return None
    for bf in backups[:10]: # Limit menu size
        callback_data = f"{action_prefix}:{bf.name}"
        # Truncate filename if too long for button
        display_name = (bf.name[:40] + '..') if len(bf.name) > 42 else bf.name
        markup.add(InlineKeyboardButton(display_name, callback_data=callback_data))
    markup.add(InlineKeyboardButton("Cancel", callback_data=f"{action_prefix}:cancel"))
    return markup

@bot.message_handler(commands=["deletebackups"])
@authorized_only
def delete_backups_menu(message):
    markup = build_backup_menu("delete")
    if markup:
        bot.reply_to(message, "🗑️ Select a backup to delete:", reply_markup=markup)
    else:
        bot.reply_to(message, "No backups available to delete.")

@bot.message_handler(commands=["getbackup"])
@authorized_only
def get_backup_menu(message):
    markup = build_backup_menu("get")
    if markup:
        bot.reply_to(message, "💾 Select a backup to download:", reply_markup=markup)
    else:
        bot.reply_to(message, "No backups available to download.")

@bot.callback_query_handler(func=lambda call: call.data.startswith("delete:"))
def handle_delete_callback(call):
    filename = call.data.split(":", 1)[1]
    if filename == 'cancel':
        bot.edit_message_text("Cancelled.", call.message.chat.id, call.message.message_id)
        return

    filepath = BACKUP_DIR / filename
    if filepath.exists():
        try:
            filepath.unlink()
            bot.answer_callback_query(call.id, f"Deleted {filename}")
            bot.edit_message_text(f"✅ Deleted `{filename}`.", call.message.chat.id, call.message.message_id)
        except Exception as e:
            bot.answer_callback_query(call.id, f"Error: {e}")
    else:
        bot.answer_callback_query(call.id, "File not found.")

@bot.callback_query_handler(func=lambda call: call.data.startswith("get:"))
def handle_get_callback(call):
    filename = call.data.split(":", 1)[1]
    if filename == 'cancel':
        bot.edit_message_text("Cancelled.", call.message.chat.id, call.message.message_id)
        return

    filepath = BACKUP_DIR / filename
    if not filepath.exists():
        bot.answer_callback_query(call.id, "File not found.")
        return

    file_size_mb = filepath.stat().st_size / (1024 * 1024)
    if file_size_mb > TELEGRAM_FILE_LIMIT_MB:
        bot.answer_callback_query(call.id, "File is too large!")
        bot.send_message(call.message.chat.id, f"⚠️ The backup `{filename}` is {file_size_mb:.1f} MB, which is too large to send via Telegram. Please retrieve it directly from the server at `{filepath.resolve()}`.")
        return
    
    bot.answer_callback_query(call.id, "Sending file...")
    bot.send_chat_action(call.message.chat.id, 'upload_document')
    try:
        with open(filepath, "rb") as doc:
            bot.send_document(call.message.chat.id, doc)
    except Exception as e:
        logger.error(f"Failed to send document {filename}: {e}")
        bot.send_message(call.message.chat.id, f"❌ Failed to send file: {e}")


# --- Restore from Upload ---
@bot.message_handler(content_types=["document"])
@authorized_only
def handle_document_upload(message):
    doc = message.document
    if not doc.file_name.lower().endswith(".tar.gz"):
        bot.reply_to(message, "⚠️ This is not a valid backup file. Only `.tar.gz` files are accepted.")
        return

    try:
        bot.reply_to(message, "⏳ Downloading uploaded file...")
        file_info = bot.get_file(doc.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        
        # Save to a temporary path for confirmation
        temp_path = BACKUP_DIR / f"restore-upload-{int(time.time())}.tar.gz"
        with open(temp_path, "wb") as f:
            f.write(downloaded_file)
            
        if not tarfile.is_tarfile(temp_path):
            temp_path.unlink()
            bot.send_message(message.chat.id, "❌ The uploaded file is corrupted or not a valid tar archive.")
            return

        markup = InlineKeyboardMarkup()
        markup.add(
            InlineKeyboardButton("✅ Yes, Restore Now", callback_data=f"confirm_restore:{temp_path.name}"),
            InlineKeyboardButton("❌ Cancel", callback_data=f"cancel_restore:{temp_path.name}")
        )
        bot.send_message(message.chat.id, 
            f"‼️ *CONFIRM RESTORE*\n\nYou are about to restore from `{doc.file_name}`. This will overwrite all current n8n data. Are you sure?",
            reply_markup=markup)

    except Exception as e:
        logger.error(f"Error handling document upload: {e}")
        bot.reply_to(message, f"❌ An error occurred during file processing: {str(e)}")

@bot.callback_query_handler(func=lambda call: call.data.startswith(("confirm_restore:", "cancel_restore:")))
def handle_restore_confirmation(call):
    action, filename = call.data.split(":", 1)
    filepath = BACKUP_DIR / filename
    
    if not filepath.exists():
        bot.edit_message_text("Restore file not found. It might have expired or been deleted.", call.message.chat.id, call.message.message_id)
        return

    if action == "cancel_restore":
        filepath.unlink() # Clean up the temp file
        bot.edit_message_text("❌ Restore cancelled.", call.message.chat.id, call.message.message_id)
        return

    # --- Restore is confirmed ---
    bot.edit_message_text("⏳ Restoring data... n8n will be restarted.", call.message.chat.id, call.message.message_id)
    bot.send_chat_action(call.message.chat.id, 'typing')
    
    try:
        # Stop n8n to prevent data corruption
        run_shell_command(["docker", "stop", "n8n"])

        # Clean the existing data directory
        for item in N8N_DATA_DIR.iterdir():
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()

        # Extract the backup
        with tarfile.open(filepath, "r:gz") as tar:
            # Important: extract contents into the target dir, not the dir itself
            tar.extractall(path=N8N_DATA_DIR.parent)

        # Clean up the uploaded file
        filepath.unlink()
        
        # Restart n8n
        run_shell_command(["docker", "start", "n8n"])

        bot.send_message(call.message.chat.id, "✅ Restore complete! n8n has been restarted.")
    except Exception as e:
        logger.error(f"Restore process failed: {e}")
        bot.send_message(call.message.chat.id, f"❌ Restore failed: {str(e)}")
        # Try to restart n8n anyway
        run_shell_command(["docker", "start", "n8n"])


# --- Main Application Loop ---
if __name__ == "__main__":
    try:
        logger.info("Starting n8n Telegram bot...")
        
        # --- Setup and start the scheduler for automated tasks ---
        scheduler = BackgroundScheduler(timezone="UTC")
        # Run prune job once at startup, then every 24 hours
        scheduler.add_job(prune_old_backups, 'interval', hours=24, next_run_time=datetime.now())
        scheduler.start()
        
        logger.info("Bot is polling for messages...")
        bot.infinity_polling(timeout=60, long_polling_timeout=30)
        
    except Exception as e:
        logger.critical(f"Bot polling loop crashed: {e}")
    finally:
        if 'scheduler' in locals() and scheduler.running:
            scheduler.shutdown()
        logger.info("Bot has shut down.")

PYEOF

# -------- Systemd Service Setup --------
# Ensure the Python script is executable
chmod +x "$BOT_DIR/n8n_bot.py"
chown -R "$BOT_USER":"$BOT_USER" "$BOT_DIR"

log "Writing systemd service file..."
cat > "$SYSTEMD_SERVICE" <<EOF
[Unit]
Description=n8n Telegram Management Bot
After=network.target docker.service
Wants=docker.service

[Service]
Type=simple
User=$BOT_USER
Group=$BOT_USER
WorkingDirectory=$BOT_DIR
ExecStart=$VENV_DIR/bin/python $BOT_DIR/n8n_bot.py
Restart=always
RestartSec=10
EnvironmentFile=$BOT_DIR/n8n_bot_config.env
# Security Hardening
PrivateTmp=true
ProtectSystem=full
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

log "Enabling and starting the n8n-bot service..."
run_cmd systemctl daemon-reload
run_cmd systemctl enable --now n8n-bot.service

log "✅ Installation complete!"
echo "-----------------------------------------------------"
echo "Your n8n instance is available at: https://$DOMAIN"
echo "Your Telegram bot is now running."
echo ""
echo "To view bot logs, run:"
echo "sudo journalctl -u n8n-bot.service -f"
echo ""
echo "Or check the log file:"
echo "sudo tail -f $BOT_DIR/bot.log"
echo "-----------------------------------------------------"
