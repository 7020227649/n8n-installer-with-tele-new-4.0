#!/bin/bash
# n8n + Telegram Bot Installer (Pro)
# For FRESH VPS – installs Docker, n8n, and Telegram bot in one go
# GitHub: https://github.com/7020227649/n8n-installer-with-tele-new-4.0

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1" >&2; exit 1; }

# === 1. SYSTEM UPDATE ===
log "🔄 Updating system..."
apt-get update -qq
apt-get install -y curl wget gnupg lsb-release apt-transport-https ca-certificates

# === 2. INSTALL DOCKER ===
if ! command -v docker &> /dev/null; then
  log "🐳 Installing Docker..."
  curl -fsSL https://get.docker.com | sh
  usermod -aG docker root
fi

# === 3. TELEGRAM & DOMAIN INPUT ===
read -rp "$(echo -e ${YELLOW}"[?] Telegram Bot Token (from @BotFather): "${NC})" BOT_TOKEN
[[ -n "$BOT_TOKEN" ]] || error "Bot token required."

read -rp "$(echo -e ${YELLOW}"[?] Your Telegram Chat ID (from @userinfobot): "${NC})" CHAT_ID
[[ "$CHAT_ID" =~ ^-?[0-9]+$ ]] || error "Chat ID must be numeric."

read -rp "$(echo -e ${YELLOW}"[?] Domain for SSL (leave blank to skip): "${NC})" DOMAIN

# === 4. LAUNCH n8n CONTAINER ===
log "🚀 Starting n8n..."
mkdir -p /root/n8n-data
docker run -d \
  --name n8n \
  -p 5678:5678 \
  -v /root/n8n-data:/home/node/.n8n \
  -e N8N_BASIC_AUTH_ACTIVE=true \
  -e N8N_BASIC_AUTH_USER=admin \
  -e N8N_BASIC_AUTH_PASSWORD=secure_password \
  --restart unless-stopped \
  n8nio/n8n

N8N_CONTAINER="n8n"
N8N_PORT="5678"

# === 5. INSTALL BOT DEPENDENCIES ===
log "📦 Installing Python & Telegram bot..."
apt-get install -y python3 python3-pip gzip nginx certbot python3-certbot-nginx cron >/dev/null
pip3 install -q python-telegram-bot==20.7

# === 6. BACKUP SCRIPT (WORKFLOWS + CREDENTIALS) ===
cat > /root/backup_n8n.sh << 'EOF'
#!/bin/bash
set -e
BACKUP_DIR="/root/n8n-backups"
mkdir -p "$BACKUP_DIR"
TS=$(date +"%Y%m%d_%H%M%S")
cd "$BACKUP_DIR"
docker exec n8n n8n export:workflow --all --output="workflows_$TS.json" --pretty
docker exec n8n n8n export:credentials --all --output="credentials_$TS.json" --pretty
tar -czf "n8n_full_$TS.tar.gz" "workflows_$TS.json" "credentials_$TS.json"
rm -f "workflows_$TS.json" "credentials_$TS.json"
EOF
chmod +x /root/backup_n8n.sh

# === 7. TELEGRAM BOT (FULL) ===
cat > /root/telegram_bot.py << 'EOF'
import os, logging, subprocess
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters

logging.basicConfig(level=logging.INFO)
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
AUTHORIZED_CHAT_ID = int(os.getenv("TELEGRAM_CHAT_ID"))
BACKUP_DIR = "/root/n8n-backups"
os.makedirs(BACKUP_DIR, exist_ok=True)

def is_auth(u): return u.effective_chat.id == AUTHORIZED_CHAT_ID
async def unauth(u): await u.message.reply_text("🔒 Unauthorized.")

def cleanup(k=5):
    files = [f for f in os.listdir(BACKUP_DIR) if f.endswith('.tar.gz')]
    files.sort(key=lambda f: os.path.getctime(os.path.join(BACKUP_DIR, f)), reverse=True)
    for f in files[k:]: os.remove(os.path.join(BACKUP_DIR, f))

async def start(u, c):
    if not is_auth(u): return await unauth(u)
    await u.message.reply_text(
        "👋 **n8n Telegram Bot (Pro)**\\n\\n"
        "🔐 Secure • 💾 Full Backup • 🧹 Auto-cleaned\\n\\n"
        "**Commands:**\\n"
        "• /backup – Full backup\\n"
        "• /export-creds – Credentials only\\n"
        "• /list – Manage backups\\n"
        "• /status – System health\\n"
        "• /logs – n8n logs\\n"
        "• /restart – Restart n8n\\n"
        "• /upgrade – Update n8n\\n"
        "• /auto-backup on/off – Daily backup\\n\\n"
        "📤 Send a .tar.gz to restore!"
    )

async def backup_cmd(u, c):
    if not is_auth(u): return await unauth(u)
    await u.message.reply_text("⏳ Creating backup...")
    try:
        subprocess.run(["/root/backup_n8n.sh"], check=True)
        files = [f for f in os.listdir(BACKUP_DIR) if f.endswith('.tar.gz')]
        if not files: return await u.message.reply_text("❌ Backup failed.")
        latest = max(files, key=lambda f: os.path.getctime(os.path.join(BACKUP_DIR, f)))
        fp = os.path.join(BACKUP_DIR, latest)
        if os.path.getsize(fp) > 49 * 1024 * 1024:
            await u.message.reply_text("⚠️ Backup >50 MB – too large for Telegram.")
        else:
            with open(fp, 'rb') as f: await u.message.reply_document(f, filename=latest)
        cleanup()
        await u.message.reply_text("✅ Backup completed!")
    except Exception as e:
        logging.exception("Backup error")
        await u.message.reply_text("💥 Backup failed.")

async def export_creds(u, c):
    if not is_auth(u): return await unauth(u)
    await u.message.reply_text("⏳ Exporting credentials...")
    try:
        ts = subprocess.run(["date", "+%Y%m%d_%H%M%S"], capture_output=True, text=True).stdout.strip()
        cred_file = f"credentials_only_{ts}.json"
        fp = os.path.join(BACKUP_DIR, cred_file)
        subprocess.run(["docker", "exec", "n8n", "n8n", "export:credentials", "--all", f"--output=/tmp/{cred_file}"], check=True)
        subprocess.run(["docker", "cp", f"n8n:/tmp/{cred_file}", fp], check=True)
        with open(fp, 'rb') as f: await u.message.reply_document(f, filename=cred_file)
        os.remove(fp)
        await u.message.reply_text("✅ Credentials exported!")
    except Exception as e:
        logging.exception("Creds export error")
        await u.message.reply_text("💥 Failed.")

async def list_cmd(u, c):
    if not is_auth(u): return await unauth(u)
    files = sorted([f for f in os.listdir(BACKUP_DIR) if f.endswith('.tar.gz')], reverse=True)
    if not files: return await u.message.reply_text("📭 No backups.")
    for f in files[:10]:
        k = [[InlineKeyboardButton("🗑️ Delete", callback_data=f"del:{f}")]]
        await u.message.reply_text(f"📦 `{f}`", reply_markup=InlineKeyboardMarkup(k), parse_mode='Markdown')

async def status_cmd(u, c):
    if not is_auth(u): return await unauth(u)
    try:
        ver = subprocess.run(["docker", "exec", "n8n", "n8n", "--version"], capture_output=True, text=True).stdout.strip()
        disk = subprocess.run(["df", "-h", "/"], capture_output=True, text=True).stdout.split('\n')[1]
        used, total = disk.split()[2], disk.split()[1]
        ram = subprocess.run(["free", "-m"], capture_output=True, text=True).stdout.split('\n')[1]
        ram_used, ram_total = ram.split()[2], ram.split()[1]
        bcount = len([f for f in os.listdir(BACKUP_DIR) if f.endswith('.tar.gz')])
        await u.message.reply_text(
            f"🟢 **n8n Status**\\n"
            f"• Version: {ver}\\n"
            f"• Disk: {used}/{total} used\\n"
            f"• RAM: {ram_used}M/{ram_total}M\\n"
            f"• Backups: {bcount}"
        )
    except Exception as e:
        await u.message.reply_text("❌ Status failed.")

async def logs_cmd(u, c):
    if not is_auth(u): return await unauth(u)
    try:
        logs = subprocess.run(["docker", "logs", "--tail", "20", "n8n"], capture_output=True, text=True).stdout
        if len(logs) > 4000: logs = logs[-4000:]
        await u.message.reply_text(f"```\n{logs}\n```", parse_mode='MarkdownV2')
    except Exception as e:
        await u.message.reply_text("❌ Logs failed.")

async def restart_cmd(u, c):
    if not is_auth(u): return await unauth(u)
    k = [[InlineKeyboardButton("✅ Restart n8n", callback_data="confirm_restart")]]
    await u.message.reply_text("⚠️ Restart n8n?", reply_markup=InlineKeyboardMarkup(k))

async def upgrade_cmd(u, c):
    if not is_auth(u): return await unauth(u)
    k = [[InlineKeyboardButton("🆙 Upgrade n8n", callback_data="confirm_upgrade")]]
    await u.message.reply_text("⚠️ Pull latest n8n and restart?", reply_markup=InlineKeyboardMarkup(k))

async def auto_backup_cmd(u, c):
    if not is_auth(u): return await unauth(u)
    arg = c.args[0].lower() if c.args else ""
    cron_file = "/etc/cron.d/n8n-auto-backup"
    if arg == "on":
        with open(cron_file, "w") as f:
            f.write("0 2 * * * root /root/backup_n8n.sh > /dev/null 2>&1\n")
        subprocess.run(["systemctl", "reload", "cron"])
        await u.message.reply_text("✅ Auto-backup enabled.")
    elif arg == "off":
        if os.path.exists(cron_file):
            os.remove(cron_file)
            subprocess.run(["systemctl", "reload", "cron"])
        await u.message.reply_text("📴 Auto-backup disabled.")
    else:
        await u.message.reply_text("Usage: /auto-backup on|off")

async def handle_doc(u, c):
    if not is_auth(u): return await unauth(u)
    doc = u.message.document
    if not (doc and doc.file_name and doc.file_name.endswith('.tar.gz')):
        return await u.message.reply_text("❌ Send a .tar.gz backup file.")
    await u.message.reply_text("🔄 Restoring...")
    try:
        file = await c.bot.get_file(doc.file_id)
        gz = os.path.join(BACKUP_DIR, doc.file_name)
        await file.download_to_drive(gz)
        subprocess.run(["tar", "-xzf", gz, "-C", "/tmp"], check=True)
        wf = [f for f in os.listdir("/tmp") if f.startswith("workflows_")][0]
        cred = [f for f in os.listdir("/tmp") if f.startswith("credentials_")][0]
        subprocess.run(["docker", "cp", f"/tmp/{wf}", "n8n:/tmp/wf.json"], check=True)
        subprocess.run(["docker", "exec", "n8n", "n8n", "import:workflow", "--input=/tmp/wf.json", "--userId=1"], check=True)
        subprocess.run(["docker", "cp", f"/tmp/{cred}", "n8n:/tmp/cred.json"], check=True)
        subprocess.run(["docker", "exec", "n8n", "n8n", "import:credentials", "--input=/tmp/cred.json"], check=True)
        for f in [gz, f"/tmp/{wf}", f"/tmp/{cred}"]: os.remove(f)
        await u.message.reply_text("✅ Full restore completed!")
    except Exception as e:
        logging.exception("Restore error")
        await u.message.reply_text("💥 Restore failed.")

async def cb_handler(u, c):
    q = u.callback_query
    await q.answer()
    data = q.data
    if data == "confirm_restart":
        subprocess.run(["docker", "restart", "n8n"])
        await q.edit_message_text("✅ n8n restarted.")
    elif data == "confirm_upgrade":
        subprocess.run(["docker", "pull", "n8nio/n8n"])
        subprocess.run(["docker", "stop", "n8n"])
        subprocess.run(["docker", "rm", "n8n"])
        subprocess.run(["docker", "run", "-d", "--name", "n8n", "-p", "5678:5678", "-v", "/root/n8n-data:/home/node/.n8n", "-e", "N8N_BASIC_AUTH_ACTIVE=true", "-e", "N8N_BASIC_AUTH_USER=admin", "-e", "N8N_BASIC_AUTH_PASSWORD=secure_password", "--restart", "unless-stopped", "n8nio/n8n"])
        await q.edit_message_text("✅ n8n upgraded and restarted.")
    elif data.startswith("del:"):
        f = data.split(":",1)[1]
        fp = os.path.join(BACKUP_DIR, f)
        if os.path.exists(fp): os.remove(fp)
        await q.edit_message_text("✅ Deleted.")

def main():
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("backup", backup_cmd))
    app.add_handler(CommandHandler("export-creds", export_creds))
    app.add_handler(CommandHandler("list", list_cmd))
    app.add_handler(CommandHandler("status", status_cmd))
    app.add_handler(CommandHandler("logs", logs_cmd))
    app.add_handler(CommandHandler("restart", restart_cmd))
    app.add_handler(CommandHandler("upgrade", upgrade_cmd))
    app.add_handler(CommandHandler("auto-backup", auto_backup_cmd))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_doc))
    app.add_handler(CallbackQueryHandler(cb_handler))
    app.run_polling()

if __name__ == "__main__": main()
EOF

# === 8. SYSTEMD SERVICE ===
cat > /etc/systemd/system/n8n-telegram-bot.service << EOF
[Unit]
Description=n8n Telegram Bot (Pro)
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=root
WorkingDirectory=/root
Environment=TELEGRAM_BOT_TOKEN=$BOT_TOKEN
Environment=TELEGRAM_CHAT_ID=$CHAT_ID
ExecStart=/usr/bin/python3 /root/telegram_bot.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now n8n-telegram-bot

# === 9. NGINX + SSL (IF DOMAIN PROVIDED) ===
if [[ -n "$DOMAIN" ]]; then
  log "🔒 Setting up Nginx + SSL for $DOMAIN..."
  cat > /etc/nginx/sites-available/n8n << EOF
server {
    listen 80;
    server_name $DOMAIN;
    location / {
        proxy_pass http://127.0.0.1:5678;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF
  ln -sf /etc/nginx/sites-available/n8n /etc/nginx/sites-enabled/
  rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
  systemctl reload nginx
  certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email >/dev/null
  WEB_URL="https://$DOMAIN"
else
  WEB_URL="http://$(curl -s ifconfig.me):5678"
  warn "No domain provided. Access n8n at: $WEB_URL"
fi

# === 10. DONE ===
log "✅ Installation complete!"
echo -e "${GREEN}n8n is running!${NC}"
echo -e "🌐 Web UI: ${YELLOW}$WEB_URL${NC}"
echo -e "🤖 Telegram: Send /start to your bot"
echo -e "🔑 Default login: admin / secure_password (change it!)"
echo -e "📜 Logs: journalctl -u n8n-telegram-bot -f"
