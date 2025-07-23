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

# Create main SASL filter (using your proven working configuration)
echo -e "${BLUE}Installing main SASL filter...${NC}"
cat > "$FILTER_DIR/postfix-sasl-strict.conf" << 'EOF'
# /etc/fail2ban/filter.d/postfix-sasl-strict.conf
# Filter for Postfix SASL authentication failures - Latest Version
# Blocks after 1 failed attempt for 48 hours

[Definition]
# Match SASL authentication failures - handles all SASL methods including CRAM-MD5
failregex = .*\[<HOST>\]: SASL [\w-]+ authentication failed

# Let fail2ban auto-detect the date format
datepattern = {^LN-BEG}

# Ignore successful authentications
ignoreregex =
EOF

# Create second strike recidive filter
echo -e "${BLUE}Installing second strike filter...${NC}"
cat > "$FILTER_DIR/postfix-sasl-recidive.conf" << 'EOF'
# /etc/fail2ban/filter.d/postfix-sasl-recidive.conf
# Catches IPs banned by the first-strike jail for 8-day escalation

[Definition]
# Match when someone gets banned by the first strike jail
failregex = .*\[postfix-sasl-first\] Ban <HOST>

# Use fail2ban's standard date format for its own logs  
datepattern = ^%%Y-%%m-%%d %%H:%%M:%%S,%%f

ignoreregex =
EOF

# Create third strike recidive filter
echo -e "${BLUE}Installing third strike filter...${NC}"
cat > "$FILTER_DIR/postfix-sasl-recidive-third.conf" << 'EOF'
# /etc/fail2ban/filter.d/postfix-sasl-recidive-third.conf  
# Catches IPs banned by the second-strike jail for 32-day escalation

[Definition]
# Match when someone gets banned by the second strike jail
failregex = .*\[postfix-sasl-second\] Ban <HOST>

# Use fail2ban's standard date format for its own logs
datepattern = ^%%Y-%%m-%%d %%H:%%M:%%S,%%f

ignoreregex =
EOF

# Backup existing jail config if it exists
if [[ -f "$JAIL_DIR/postfix-sasl-strict.conf" ]]; then
    echo -e "${YELLOW}Backing up existing jail config...${NC}"
    mv "$JAIL_DIR/postfix-sasl-strict.conf" "$JAIL_DIR/postfix-sasl-strict.conf.backup-$(date +%Y%m%d-%H%M%S)"
fi

# Create escalating jail configuration
echo -e "${BLUE}Installing escalating jail configuration...${NC}"
cat > "$JAIL_DIR/postfix-sasl-escalating.conf" << EOF
# /etc/fail2ban/jail.d/postfix-sasl-escalating.conf
# Progressive ban system: 48h -> 8 days -> 32 days

# First Strike: 48 hours (current system)
[postfix-sasl-first]
enabled = true
port = smtp,465,587,submission,smtps
logpath = /var/log/mail.log
          /var/log/postfix.log
          /var/log/maillog
backend = auto
maxretry = 1
findtime = 86400
bantime = 172800
filter = postfix-sasl-strict
action = iptables-multiport[name=postfix-sasl-1st, port="25,465,587", protocol=tcp]
$EMAIL_CONFIG_FIRST
ignoreip = 127.0.0.1/8 ::1 192.168.1.0/24 10.0.0.0/8 172.16.0.0/12

# Second Strike: 8 days (recidive catches repeat offenders)
[postfix-sasl-second]
enabled = true
port = smtp,465,587,submission,smtps
logpath = /var/log/fail2ban.log
backend = auto
maxretry = 1
findtime = 1209600
bantime = 691200
filter = postfix-sasl-recidive
action = iptables-multiport[name=postfix-sasl-2nd, port="25,465,587", protocol=tcp]
$EMAIL_CONFIG_SECOND
ignoreip = 127.0.0.1/8 ::1 192.168.1.0/24 10.0.0.0/8 172.16.0.0/12

# Third Strike: 32 days (catches third-time offenders)
[postfix-sasl-third]
enabled = true
port = smtp,465,587,submission,smtps
logpath = /var/log/fail2ban.log
backend = auto
maxretry = 1
findtime = 2764800
bantime = 2764800
filter = postfix-sasl-recidive-third
action = iptables-multiport[name=postfix-sasl-3rd, port="25,465,587", protocol=tcp]
$EMAIL_CONFIG_THIRD
ignoreip = 127.0.0.1/8 ::1 192.168.1.0/24 10.0.0.0/8 172.16.0.0/12
EOF

# Create monitoring script
echo -e "${BLUE}Installing monitoring script...${NC}"
cat > "/usr/local/bin/monitor-postfix-bans.sh" << 'EOF'
#!/bin/bash
# Monitor escalating ban system status

echo "=== POSTFIX SASL ESCALATING BAN SYSTEM ==="
echo "$(date)"
echo

echo "🥊 FIRST STRIKE (48 hours):"
sudo fail2ban-client status postfix-sasl-first 2>/dev/null | grep -E "(Currently banned|Total banned)" || echo "  Jail not active"
echo

echo "⚡ SECOND STRIKE (8 days):"  
sudo fail2ban-client status postfix-sasl-second 2>/dev/null | grep -E "(Currently banned|Total banned)" || echo "  Jail not active"
echo

echo "💀 THIRD STRIKE (32 days):"
sudo fail2ban-client status postfix-sasl-third 2>/dev/null | grep -E "(Currently banned|Total banned)" || echo "  Jail not active"
echo

echo "📊 SUMMARY:"
FIRST=$(sudo fail2ban-client get postfix-sasl-first banip 2>/dev/null | wc -w)
SECOND=$(sudo fail2ban-client get postfix-sasl-second banip 2>/dev/null | wc -w)  
THIRD=$(sudo fail2ban-client get postfix-sasl-third banip 2>/dev/null | wc -w)
TOTAL=$((FIRST + SECOND + THIRD))

echo "  First Strike Bans:  $FIRST"
echo "  Second Strike Bans: $SECOND" 
echo "  Third Strike Bans:  $THIRD"
echo "  Total Active Bans:  $TOTAL"
echo

echo "🔍 RECENT ESCALATIONS (last 24h):"
sudo grep -E "\[(postfix-sasl-(second|third))\] Ban" /var/log/fail2ban.log | tail -10 2>/dev/null || echo "  No recent escalations"

echo
echo "📜 RECENT FIRST STRIKES (last 10):"
sudo grep "\[postfix-sasl-first\] Ban" /var/log/fail2ban.log | tail -10 2>/dev/null || echo "  No recent first strikes"
EOF

chmod +x "/usr/local/bin/monitor-postfix-bans.sh"

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
