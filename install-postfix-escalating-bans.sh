#!/bin/bash
# Postfix SASL Escalating Ban System Installer
# Installs progressive ban system: 48h -> 8 days -> 32 days

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
FAIL2BAN_DIR="/etc/fail2ban"
FILTER_DIR="$FAIL2BAN_DIR/filter.d"
JAIL_DIR="$FAIL2BAN_DIR/jail.d"
BACKUP_DIR="/root/fail2ban-backup-$(date +%Y%m%d-%H%M%S)"

echo -e "${BLUE}=== POSTFIX SASL ESCALATING BAN SYSTEM INSTALLER ===${NC}"
echo "This will install a progressive ban system:"
echo "  🥊 Strike 1: 48 hours"
echo "  ⚡ Strike 2: 8 days" 
echo "  💀 Strike 3: 32 days"
echo

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Check if fail2ban is installed
if ! command -v fail2ban-client &> /dev/null; then
    echo -e "${RED}fail2ban is not installed. Please install it first.${NC}"
    exit 1
fi

# Prompt for email address (optional)
echo -e "${YELLOW}Enter your email address for ban notifications (press Enter to skip):${NC}"
read -p "Email: " EMAIL_ADDRESS

# Set email configuration based on input
if [[ -z "$EMAIL_ADDRESS" ]]; then
    echo -e "${BLUE}No email provided - notifications will be disabled${NC}"
    EMAIL_CONFIG_FIRST="#         sendmail-whois[name=postfix-sasl-1st, dest=admin@example.com]"
    EMAIL_CONFIG_SECOND="#         sendmail-whois[name=postfix-sasl-2nd, dest=admin@example.com, subject=\"Second Strike Ban - 8 Days\"]"
    EMAIL_CONFIG_THIRD="#         sendmail-whois[name=postfix-sasl-3rd, dest=admin@example.com, subject=\"Third Strike Ban - 32 Days\"]"
else
    echo -e "${GREEN}Email notifications will be sent to: $EMAIL_ADDRESS${NC}"
    EMAIL_CONFIG_FIRST="         sendmail-whois[name=postfix-sasl-1st, dest=$EMAIL_ADDRESS]"
    EMAIL_CONFIG_SECOND="         sendmail-whois[name=postfix-sasl-2nd, dest=$EMAIL_ADDRESS, subject=\"Second Strike Ban - 8 Days\"]"
    EMAIL_CONFIG_THIRD="         sendmail-whois[name=postfix-sasl-3rd, dest=$EMAIL_ADDRESS, subject=\"Third Strike Ban - 32 Days\"]"
fi

# Create backup directory
echo -e "${BLUE}Creating backup...${NC}"
mkdir -p "$BACKUP_DIR"
cp -r "$FAIL2BAN_DIR"/* "$BACKUP_DIR/" 2>/dev/null || true
echo "Backup created at: $BACKUP_DIR"

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Copy filter files
echo -e "${BLUE}Installing filter files...${NC}"
if [[ -d "$SCRIPT_DIR/filter.d" ]]; then
    cp "$SCRIPT_DIR/filter.d/postfix-sasl-strict.conf" "$FILTER_DIR/"
    echo "  ✓ Installed postfix-sasl-strict.conf"
else
    echo -e "${RED}Error: filter.d directory not found in $SCRIPT_DIR${NC}"
    exit 1
fi

# Copy second strike filter
cp "$SCRIPT_DIR/filter.d/postfix-sasl-recidive.conf" "$FILTER_DIR/"
echo "  ✓ Installed postfix-sasl-recidive.conf"

# Copy third strike filter
cp "$SCRIPT_DIR/filter.d/postfix-sasl-recidive-third.conf" "$FILTER_DIR/"
echo "  ✓ Installed postfix-sasl-recidive-third.conf"

# Backup existing jail config if it exists
if [[ -f "$JAIL_DIR/postfix-sasl-strict.conf" ]]; then
    echo -e "${YELLOW}Backing up existing jail config...${NC}"
    mv "$JAIL_DIR/postfix-sasl-strict.conf" "$JAIL_DIR/postfix-sasl-strict.conf.backup-$(date +%Y%m%d-%H%M%S)"
fi

# Copy jail configuration
echo -e "${BLUE}Installing jail configuration...${NC}"
if [[ -d "$SCRIPT_DIR/jail.d" ]]; then
    # Read the template jail config and substitute email variables
    JAIL_CONTENT=$(cat "$SCRIPT_DIR/jail.d/postfix-sasl-escalating.conf")
    
    # Replace email placeholders with actual configuration
    JAIL_CONTENT="${JAIL_CONTENT//\#         sendmail-whois\[name=postfix-sasl-1st, dest=admin@example.com\]/$EMAIL_CONFIG_FIRST}"
    JAIL_CONTENT="${JAIL_CONTENT//\#         sendmail-whois\[name=postfix-sasl-2nd, dest=admin@example.com, subject=\"Second Strike Ban - 8 Days\"\]/$EMAIL_CONFIG_SECOND}"
    JAIL_CONTENT="${JAIL_CONTENT//\#         sendmail-whois\[name=postfix-sasl-3rd, dest=admin@example.com, subject=\"Third Strike Ban - 32 Days\"\]/$EMAIL_CONFIG_THIRD}"
    
    # Write the processed content
    echo "$JAIL_CONTENT" > "$JAIL_DIR/postfix-sasl-escalating.conf"
    echo "  ✓ Installed postfix-sasl-escalating.conf"
else
    echo -e "${RED}Error: jail.d directory not found in $SCRIPT_DIR${NC}"
    exit 1
fi

# Copy monitoring script
echo -e "${BLUE}Installing monitoring script...${NC}"
if [[ -f "$SCRIPT_DIR/monitor-postfix-bans.sh" ]]; then
    cp "$SCRIPT_DIR/monitor-postfix-bans.sh" "/usr/local/bin/"
    chmod +x "/usr/local/bin/monitor-postfix-bans.sh"
    echo "  ✓ Installed monitor-postfix-bans.sh"
else
    echo -e "${RED}Error: monitor-postfix-bans.sh not found in $SCRIPT_DIR${NC}"
    exit 1
fi

# Test configuration
echo -e "${BLUE}Testing configuration...${NC}"
if fail2ban-client -t; then
    echo -e "${GREEN}Configuration test passed!${NC}"
else
    echo -e "${RED}Configuration test failed!${NC}"
    echo "Restoring backup..."
    cp -r "$BACKUP_DIR"/* "$FAIL2BAN_DIR/"
    exit 1
fi

# Restart fail2ban
echo -e "${BLUE}Restarting fail2ban...${NC}"
systemctl restart fail2ban

# Wait for startup
sleep 3

# Verify jails are running
echo -e "${BLUE}Verifying installation...${NC}"
ACTIVE_JAILS=$(fail2ban-client status | grep "Jail list" | cut -d: -f2 | tr ',' '\n' | grep -c "postfix-sasl" || echo "0")

if [[ $ACTIVE_JAILS -eq 3 ]]; then
    echo -e "${GREEN}✅ All 3 escalating jails are active!${NC}"
else
    echo -e "${YELLOW}⚠️  Only $ACTIVE_JAILS jails are active${NC}"
fi

# Create systemd service for monitoring (optional)
echo -e "${BLUE}Creating monitoring service...${NC}"
cat > "/etc/systemd/system/postfix-ban-monitor.service" << 'EOF'
[Unit]
Description=Postfix Ban Monitor
After=fail2ban.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/monitor-postfix-bans.sh
User=root

[Install]
WantedBy=multi-user.target
EOF

cat > "/etc/systemd/system/postfix-ban-monitor.timer" << 'EOF'
[Unit]
Description=Run Postfix Ban Monitor every hour
Requires=postfix-ban-monitor.service

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable postfix-ban-monitor.timer
systemctl start postfix-ban-monitor.timer

# Final status report
echo
echo -e "${GREEN}=== INSTALLATION COMPLETE ===${NC}"
echo
if [[ -z "$EMAIL_ADDRESS" ]]; then
    echo "📧 Email notifications: DISABLED"
else
    echo "📧 Email notifications: $EMAIL_ADDRESS"
fi
echo "📁 Backup location: $BACKUP_DIR"
echo "🎯 Monitor command: monitor-postfix-bans.sh"
echo
echo -e "${BLUE}Current system status:${NC}"
fail2ban-client status

echo
echo -e "${YELLOW}Commands you can use:${NC}"
echo "  monitor-postfix-bans.sh           # Check ban status"
echo "  fail2ban-client status            # List all jails"
echo "  journalctl -u postfix-ban-monitor # Check monitoring logs"
echo
echo -e "${GREEN}Your mail server now has escalating ban protection!${NC}"
echo "  🥊 Strike 1: 48 hours"
echo "  ⚡ Strike 2: 8 days"
echo "  💀 Strike 3: 32 days"
