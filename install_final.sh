#!/usr/bin/env bash
# ------------------------------------------------------------------
# n8n + Telegram Bot Unified Installer (Interactive)
# - Secure, idempotent, production-ready
# - Prompts for required info if not supplied as arguments
# - Installs Docker, n8n container, nginx, certbot, UFW
# - Creates dedicated n8nbot user, venv, systemd service
# - Embeds Python bot via heredoc
# Usage (interactive):
#   curl -fsSL https://example.com/install_final.sh | sudo bash
# Or pass args to skip prompts:
#   sudo bash install_final.sh domain.com you@example.com BOT_TOKEN USER_ID
# ------------------------------------------------------------------

set -euo pipefail
IFS=$'\n\t'

# -------- Helpers --------
log() { echo -e "\n[INFO] $*"; }
warn() { echo -e "\n[WARN] $*" >&2; }
err() { echo -e "\n[ERROR] $*" >&2; }

# -------- Input handling (args or interactive) --------
ARG_DOMAIN=${1:-}
ARG_EMAIL=${2:-}
ARG_BOT_TOKEN=${3:-}
ARG_USER_ID=${4:-}

# function to prompt with default
prompt_nonempty() {
  local prompt_text="$1"
  local default="$2"
  local secret="${3:-false}"
  local val=""
  while true; do
    if [[ "$secret" == "true" ]]; then
      # -s may not work in some non-interactive contexts but that's acceptable
      read -r -s -p "$prompt_text" val || true
      echo
    else
      read -r -p "$prompt_text" val || true
    fi
    # If user entered nothing, use default if provided
    if [[ -z "$val" && -n "$default" ]]; then
      val="$default"
    fi
    if [[ -n "$val" ]]; then
      echo "$val"
      return 0
    else
      echo "Input cannot be empty. Please try again."
    fi
  done
}

# Determine inputs (use args if provided, otherwise prompt)
if [[ -n "$ARG_DOMAIN" && -n "$ARG_EMAIL" && -n "$ARG_BOT_TOKEN" && -n "$ARG_USER_ID" ]]; then
  DOMAIN="$ARG_DOMAIN"
  EMAIL="$ARG_EMAIL"
  BOT_TOKEN="$ARG_BOT_TOKEN"
  USER_ID="$ARG_USER_ID"
else
  # Interactive prompts (hide token input)
  echo "This installer will prompt for required information."
  DOMAIN=$(prompt_nonempty "🧩 Enter your domain name (e.g., example.com): " "$ARG_DOMAIN" false)
  EMAIL=$(prompt_nonempty "🧩 Enter your email (for Let's Encrypt): " "$ARG_EMAIL" false)
  BOT_TOKEN=$(prompt_nonempty "🧩 Enter your Telegram Bot Token (input hidden): " "$ARG_BOT_TOKEN" true)
  USER_ID=$(prompt_nonempty "🧩 Enter your Telegram numeric User ID: " "$ARG_USER_ID" false)
fi

# Basic validation
if ! [[ "$USER_ID" =~ ^[0-9]+$ ]]; then
  err "AUTHORIZED USER ID must be a numeric Telegram user id."
  exit 1
fi

# -------- Config --------
BOT_DIR="/opt/n8n_bot"
BACKUP_DIR="/opt/n8n_backups"
BOT_USER="n8nbot"
VENV_DIR="$BOT_DIR/venv"
SYSTEMD_SERVICE="/etc/systemd/system/n8n-bot.service"
NGINX_CONF="/etc/nginx/sites-available/n8n"
REQUIRED_PACKAGES=(bash curl sudo gnupg2 ca-certificates lsb-release unzip software-properties-common nginx ufw python3 python3-venv python3-pip)

# -------- Ensure running as root --------
if [[ $EUID -ne 0 ]]; then
  err "This installer must be run as root. Use sudo."
  exit 1
fi

log "Starting installation for domain: $DOMAIN"

# -------- Install base packages --------
log "Updating package lists and installing required packages..."
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y "${REQUIRED_PACKAGES[@]}" || { warn "APT install had issues, continuing..."; }

# -------- Docker install (idempotent) --------
if ! command -v docker >/dev/null 2>&1; then
  log "Installing Docker..."
  curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" \
    | tee /etc/apt/sources.list.d/docker.list > /dev/null
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y docker-ce docker-ce-cli containerd.io
  systemctl enable --now docker || true
else
  log "Docker is already installed."
  systemctl enable --now docker || true
fi

# -------- Create dedicated system user --------
if ! id -u "$BOT_USER" >/dev/null 2>&1; then
  log "Creating dedicated system user '$BOT_USER'..."
  useradd --system --home "$BOT_DIR" --shell /usr/sbin/nologin --create-home "$BOT_USER" || true
else
  log "User $BOT_USER already exists."
fi

# -------- Directories & permissions --------
log "Creating directories..."
mkdir -p "$BOT_DIR" "$BACKUP_DIR" /var/n8n
chown -R "$BOT_USER":"$BOT_USER" "$BOT_DIR" "$BACKUP_DIR" /var/n8n || true
chmod 750 "$BOT_DIR" "$BACKUP_DIR" || true
# Ensure /var/n8n is owned by uid 1000 (n8n container user)
chown 1000:1000 /var/n8n || true

# -------- n8n container management --------
log "Ensuring n8n Docker container is present and running..."
if docker ps -a --format '{{.Names}}' | grep -xq "n8n"; then
  if ! docker ps --format '{{.Names}}' | grep -xq "n8n"; then
    docker start n8n || true
  fi
else
  docker run -d --restart unless-stopped --name n8n -p 5678:5678 \
    -e N8N_HOST="$DOMAIN" \
    -e WEBHOOK_URL="https://$DOMAIN/" \
    -e WEBHOOK_TUNNEL_URL="https://$DOMAIN/" \
    -v /var/n8n:/home/node/.n8n \
    n8nio/n8n:latest
fi

# -------- Nginx configuration --------
log "Writing Nginx config..."
cat > "$NGINX_CONF" <<EOF
server {
    listen 80;
    server_name $DOMAIN;

    client_max_body_size 200M;

    location / {
        proxy_pass http://127.0.0.1:5678;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_buffering off;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
}
EOF

ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/n8n
rm -f /etc/nginx/sites-enabled/default || true
nginx -t && systemctl reload nginx || warn "nginx test/reload failed; check config."

# -------- Certbot (Let's Encrypt) --------
log "Obtaining/renewing SSL certificate for $DOMAIN with certbot..."
if ! certbot certificates -d "$DOMAIN" >/dev/null 2>&1; then
  certbot --non-interactive --agree-tos --nginx -m "$EMAIL" -d "$DOMAIN" || warn "Certbot failed. Ensure domain points to this server and ports 80/443 are reachable."
else
  log "Certificate already exists for $DOMAIN."
fi

# -------- UFW firewall --------
log "Configuring UFW..."
ufw allow OpenSSH || true
ufw allow 'Nginx Full' || true
ufw --force enable || true

# -------- Python environment and dependencies --------
log "Setting up Python virtual environment..."
if [[ ! -d "$VENV_DIR" ]]; then
  python3 -m venv "$VENV_DIR"
fi
PIP="$VENV_DIR/bin/pip"
PY="$VENV_DIR/bin/python"
"$PIP" install --upgrade pip setuptools wheel
"$PIP" install pyTelegramBotAPI python-dotenv || { warn "Python package install may have issues."; }

# -------- Bot config file --------
log "Writing bot configuration file..."
cat > "$BOT_DIR/n8n_bot_config.env" <<EOF
BOT_TOKEN=$BOT_TOKEN
AUTHORIZED_USER=$USER_ID
DOMAIN=$DOMAIN
BACKUP_DIR=$BACKUP_DIR
EOF
chown "$BOT_USER":"$BOT_USER" "$BOT_DIR/n8n_bot_config.env" || true
chmod 640 "$BOT_DIR/n8n_bot_config.env" || true

# -------- Embed Python bot (heredoc) --------
log "Embedding Python bot into $BOT_DIR/n8n_bot.py ..."
cat > "$BOT_DIR/n8n_bot.py" <<'PYEOF'
#!/usr/bin/env python3
"""
n8n Telegram Bot - Embedded version
Safe, robust, uses pyTelegramBotAPI and python-dotenv
"""
import os
import sys
import time
import logging
import tarfile
from datetime import date
from glob import glob
from pathlib import Path
from dotenv import load_dotenv
import telebot
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

ENV_PATH = "/opt/n8n_bot/n8n_bot_config.env"
if not os.path.exists(ENV_PATH):
    logging.error("Config file not found: %s", ENV_PATH)
    sys.exit(1)
load_dotenv(ENV_PATH)

BOT_TOKEN = os.getenv("BOT_TOKEN")
if not BOT_TOKEN:
    logging.error("BOT_TOKEN not set in env")
    sys.exit(1)
try:
    AUTHORIZED_USER = int(os.getenv("AUTHORIZED_USER", "0"))
except ValueError:
    logging.error("AUTHORIZED_USER must be an integer")
    sys.exit(1)

DOMAIN = os.getenv("DOMAIN", "")
BACKUP_DIR = os.getenv("BACKUP_DIR", "/opt/n8n_backups")
VAR_N8N_DIR = "/var/n8n"

Path(BACKUP_DIR).mkdir(parents=True, exist_ok=True)

bot = telebot.TeleBot(BOT_TOKEN, threaded=True)

def is_authorized(message_or_user):
    try:
        uid = message_or_user.from_user.id
    except Exception:
        uid = int(message_or_user)
    return uid == AUTHORIZED_USER

def safe_run(cmd_list):
    import subprocess
    try:
        out = subprocess.check_output(cmd_list, stderr=subprocess.STDOUT, text=True)
        return 0, out
    except subprocess.CalledProcessError as e:
        return e.returncode, e.output

@bot.message_handler(commands=["help", "start"])
def help_cmd(message):
    if not is_authorized(message): return
    bot.reply_to(message, (
        "🤖 *n8n Bot Control Panel*\n\n"
        "📦 Backup Commands:\n"
        "/createbackup – Save a new backup\n"
        "/showbackup – Send latest backup with Restore button\n"
        "📤 Upload a backup file (.tar.gz) to restore it automatically\n\n"
        "⚙️ Management:\n"
        "/status – Check if container is running\n"
        "/logs – Show recent logs\n"
        "/restart – Restart n8n\n"
        "/update – Update n8n to latest\n"
        "/restore – Restore last saved backup\n\n"
        "/help – Show this message again"
    ), parse_mode="Markdown")

@bot.message_handler(commands=["status"])
def status(message):
    if not is_authorized(message): return
    code, out = safe_run(["docker", "ps", "--filter", "name=n8n", "--format", "table {{.Names}}\t{{.Status}}"])
    if code == 0 and out.strip():
        bot.reply_to(message, f"📦 *n8n Status:*\n```\n{out}\n```", parse_mode="Markdown")
    else:
        bot.reply_to(message, "⚠️ n8n container not found or docker error.")

@bot.message_handler(commands=["logs"])
def logs(message):
    if not is_authorized(message): return
    code, out = safe_run(["docker", "logs", "--tail", "200", "n8n"])
    if code == 0:
        bot.reply_to(message, f"📄 *n8n Logs:*\n```\n{out}\n```", parse_mode="Markdown")
    else:
        bot.reply_to(message, "⚠️ Failed to fetch logs or container not running.")

@bot.message_handler(commands=["restart"])
def restart(message):
    if not is_authorized(message): return
    code, _ = safe_run(["docker", "restart", "n8n"])
    if code == 0:
        bot.reply_to(message, "🔁 n8n restarted!")
    else:
        bot.reply_to(message, "❌ Failed to restart n8n.")

@bot.message_handler(commands=["update"])
def update(message):
    if not is_authorized(message): return
    bot.reply_to(message, "⏳ Updating n8n image and restarting container...")
    safe_run(["docker", "pull", "n8nio/n8n:latest"])
    safe_run(["docker", "rm", "-f", "n8n"])
    run_cmd = [
        "docker", "run", "-d", "--restart", "unless-stopped", "--name", "n8n",
        "-p", "5678:5678",
        "-e", f"N8N_HOST={DOMAIN}",
        "-e", f"WEBHOOK_URL=https://{DOMAIN}/",
        "-e", f"WEBHOOK_TUNNEL_URL=https://{DOMAIN}/",
        "-v", f"{VAR_N8N_DIR}:/home/node/.n8n",
        "n8nio/n8n:latest"
    ]
    code, out = safe_run(run_cmd)
    if code == 0:
        bot.reply_to(message, "✅ n8n updated and restarted!")
    else:
        bot.reply_to(message, f"❌ Update failed:\n```\n{out}\n```", parse_mode="Markdown")

def latest_backup_path():
    files = sorted(glob(os.path.join(BACKUP_DIR, "n8n-backup-*.tar.gz")), reverse=True)
    return files[0] if files else None

@bot.message_handler(commands=["createbackup"])
def create_backup(message):
    if not is_authorized(message): return
    today = date.today().isoformat()
    name = f"n8n-backup-{today}.tar.gz"
    dst = os.path.join(BACKUP_DIR, name)
    try:
        with tarfile.open(dst, "w:gz") as tar:
            tar.add(VAR_N8N_DIR, arcname=os.path.basename(VAR_N8N_DIR))
        bot.reply_to(message, f"📦 Backup created:\n`{dst}`", parse_mode="Markdown")
    except Exception as e:
        bot.reply_to(message, f"❌ Backup failed: {str(e)}")

@bot.message_handler(commands=["showbackup"])
def show_backup(message):
    if not is_authorized(message): return
    latest = latest_backup_path()
    if latest and os.path.exists(latest):
        try:
            with open(latest, "rb") as fh:
                bot.send_document(message.chat.id, fh)
            markup = InlineKeyboardMarkup()
            markup.add(InlineKeyboardButton("🔁 Restore this Backup", callback_data="restore_backup"))
            bot.send_message(message.chat.id, "📂 Tap below to restore the above backup:", reply_markup=markup)
        except Exception as e:
            bot.reply_to(message, f"❌ Failed to send backup: {str(e)}")
    else:
        bot.reply_to(message, "⚠️ No backup found.")

@bot.message_handler(commands=["restore"])
def manual_restore(message):
    if not is_authorized(message): return
    latest = latest_backup_path()
    if not latest:
        bot.reply_to(message, "⚠️ No backup found.")
        return
    try:
        with tarfile.open(latest, "r:gz") as tar:
            tar.extractall(path="/")
        safe_run(["docker", "restart", "n8n"])
        bot.reply_to(message, "✅ Restored from latest backup.")
    except Exception as e:
        bot.reply_to(message, f"❌ Restore failed: {str(e)}")

@bot.callback_query_handler(func=lambda call: call.data == "restore_backup")
def restore_button(call):
    if call.from_user.id != AUTHORIZED_USER:
        bot.answer_callback_query(call.id, "❌ Unauthorized")
        return
    latest = latest_backup_path()
    if not latest:
        bot.send_message(call.message.chat.id, "⚠️ No backup to restore.")
        bot.answer_callback_query(call.id, "❌ No backup found.")
        return
    try:
        with tarfile.open(latest, "r:gz") as tar:
            tar.extractall(path="/")
        safe_run(["docker", "restart", "n8n"])
        bot.send_message(call.message.chat.id, "✅ Backup restored successfully.")
        bot.answer_callback_query(call.id, "✅ Restored!")
    except Exception as e:
        bot.send_message(call.message.chat.id, f"❌ Restore failed: {str(e)}")
        bot.answer_callback_query(call.id, "❌ Restore failed")

@bot.message_handler(content_types=["document"])
def upload_backup(message):
    if not is_authorized(message): return
    doc = message.document
    if not doc.file_name.lower().endswith(".tar.gz"):
        bot.reply_to(message, "⚠️ Only .tar.gz backup files are supported.")
        return
    try:
        file_info = bot.get_file(doc.file_id)
        downloaded = bot.download_file(file_info.file_path)
        path = os.path.join(BACKUP_DIR, doc.file_name)
        with open(path, "wb") as f:
            f.write(downloaded)
        if tarfile.is_tarfile(path):
            with tarfile.open(path, "r:gz") as tar:
                tar.extractall(path="/")
            safe_run(["docker", "restart", "n8n"])
            bot.reply_to(message, f"✅ Backup `{doc.file_name}` restored and n8n restarted!", parse_mode="Markdown")
        else:
            os.remove(path)
            bot.reply_to(message, "❌ Uploaded file is not a valid tar.gz archive.")
    except Exception as e:
        bot.reply_to(message, f"❌ Restore failed: {str(e)}")

def main_poll_loop():
    backoff = 1
    while True:
        try:
            bot.infinity_polling(timeout=60, long_polling_timeout=60)
        except Exception:
            time.sleep(backoff)
            backoff = min(300, backoff * 2)

if __name__ == "__main__":
    try:
        logging.info("Starting n8n Telegram bot...")
        main_poll_loop()
    except KeyboardInterrupt:
        logging.info("Shutting down bot...")
PYEOF

# -------- LICENSE (MIT) --------
cat > "$BOT_DIR/LICENSE" <<'LIC_EOF'
MIT License

Copyright (c) 2025 webclasher

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
LIC_EOF

# Ensure ownership and permissions for bot files
chown -R "$BOT_USER":"$BOT_USER" "$BOT_DIR" "$BACKUP_DIR" || true
chmod 750 "$BOT_DIR" || true
chmod 640 "$BOT_DIR/n8n_bot_config.env" || true
chmod 750 "$BOT_DIR/n8n_bot.py" || true

# Write systemd service file
cat > "$SYSTEMD_SERVICE" <<EOF
[Unit]
Description=n8n Telegram Bot
After=network.target docker.service
Wants=docker.service

[Service]
Type=simple
User=$BOT_USER
Group=$BOT_USER
WorkingDirectory=$BOT_DIR
ExecStart=$VENV_DIR/bin/python $BOT_DIR/n8n_bot.py
Restart=always
RestartSec=5
EnvironmentFile=$BOT_DIR/n8n_bot_config.env
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload || true
systemctl enable --now n8n-bot.service || warn "Failed to enable/start n8n-bot.service immediately. Check 'systemctl status n8n-bot.service'."

log "Installation complete!"
echo "-----------------------------------------"
echo "Site: https://$DOMAIN"
echo "Bot dir: $BOT_DIR"
echo "Backups: $BACKUP_DIR"
echo "To view bot logs: sudo journalctl -u n8n-bot.service -f"
echo "-----------------------------------------"
