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

# Prompt for notification configuration
echo -e "${YELLOW}Configure email notifications:${NC}"
echo "1) None - No email notifications"
echo "2) Smart - Single email per IP (waits up to 5 min for escalation)"
echo "3) Immediate - Email for every ban (current behavior)"
echo "4) Daily - Daily summary only"
echo "5) Weekly - Weekly summary only"
echo
read -p "Select notification mode [1-5] (default: 2): " NOTIF_MODE

# Default to smart notifications
NOTIF_MODE=${NOTIF_MODE:-2}

# Set tracking and email configuration based on mode
ENABLE_TRACKING="true"
case "$NOTIF_MODE" in
    1)
        echo -e "${BLUE}Notifications disabled - bans will be tracked only${NC}"
        EMAIL_ADDRESS="none"
        NOTIFICATION_EMAIL="none"
        EMAIL_CONFIG_FIRST=""
        EMAIL_CONFIG_SECOND=""
        EMAIL_CONFIG_THIRD=""
        ;;
    2)
        echo -e "${YELLOW}Enter your email address for smart notifications:${NC}"
        read -p "Email: " EMAIL_ADDRESS
        if [[ -z "$EMAIL_ADDRESS" ]]; then
            echo -e "${RED}Email required for smart notifications${NC}"
            exit 1
        fi
        echo -e "${GREEN}Smart notifications will be sent to: $EMAIL_ADDRESS${NC}"
        NOTIFICATION_EMAIL="$EMAIL_ADDRESS"
        EMAIL_CONFIG_FIRST=""
        EMAIL_CONFIG_SECOND=""
        EMAIL_CONFIG_THIRD=""
        ;;
    3)
        echo -e "${YELLOW}Enter your email address for immediate notifications:${NC}"
        read -p "Email: " EMAIL_ADDRESS
        if [[ -z "$EMAIL_ADDRESS" ]]; then
            echo -e "${RED}Email required for immediate notifications${NC}"
            exit 1
        fi
        echo -e "${GREEN}Immediate notifications will be sent to: $EMAIL_ADDRESS${NC}"
        NOTIFICATION_EMAIL="$EMAIL_ADDRESS"
        EMAIL_CONFIG_FIRST="         sendmail-whois[name=postfix-sasl-1st, dest=$EMAIL_ADDRESS]"
        EMAIL_CONFIG_SECOND="         sendmail-whois[name=postfix-sasl-2nd, dest=$EMAIL_ADDRESS, subject=\"Second Strike Ban - 8 Days\"]"
        EMAIL_CONFIG_THIRD="         sendmail-whois[name=postfix-sasl-3rd, dest=$EMAIL_ADDRESS, subject=\"Third Strike Ban - 32 Days\"]"
        ;;
    4)
        echo -e "${YELLOW}Enter your email address for daily summaries:${NC}"
        read -p "Email: " EMAIL_ADDRESS
        if [[ -z "$EMAIL_ADDRESS" ]]; then
            echo -e "${RED}Email required for daily summaries${NC}"
            exit 1
        fi
        echo -e "${GREEN}Daily summaries will be sent to: $EMAIL_ADDRESS${NC}"
        echo -e "${YELLOW}Set up a cron job for daily summaries? (y/n):${NC}"
        read -p "Answer: " SETUP_CRON
        NOTIFICATION_EMAIL="$EMAIL_ADDRESS"
        CRON_SCHEDULE="daily"
        EMAIL_CONFIG_FIRST=""
        EMAIL_CONFIG_SECOND=""
        EMAIL_CONFIG_THIRD=""
        ;;
    5)
        echo -e "${YELLOW}Enter your email address for weekly summaries:${NC}"
        read -p "Email: " EMAIL_ADDRESS
        if [[ -z "$EMAIL_ADDRESS" ]]; then
            echo -e "${RED}Email required for weekly summaries${NC}"
            exit 1
        fi
        echo -e "${GREEN}Weekly summaries will be sent to: $EMAIL_ADDRESS${NC}"
        echo -e "${YELLOW}Set up a cron job for weekly summaries? (y/n):${NC}"
        read -p "Answer: " SETUP_CRON
        NOTIFICATION_EMAIL="$EMAIL_ADDRESS"
        CRON_SCHEDULE="weekly"
        EMAIL_CONFIG_FIRST=""
        EMAIL_CONFIG_SECOND=""
        EMAIL_CONFIG_THIRD=""
        ;;
    *)
        echo -e "${RED}Invalid selection${NC}"
        exit 1
        ;;
esac

# Prompt for ignored IP ranges (optional)
echo
echo -e "${YELLOW}Configure ignored IP ranges:${NC}"
echo "Current default in jail.local [DEFAULT]: $(grep -E '^\s*ignoreip\s*=' /etc/fail2ban/jail.local 2>/dev/null | head -1 || echo 'Not configured')"
echo
echo "Press Enter to inherit from [DEFAULT], or enter custom IP ranges"
echo "Example: 127.0.0.1/8 ::1 192.168.0.0/16 10.0.0.0/8"
read -p "Ignored IPs: " IGNORE_IP_RANGES

# Set ignoreip configuration
if [[ -z "$IGNORE_IP_RANGES" ]]; then
    echo -e "${BLUE}Will inherit ignoreip from [DEFAULT] section${NC}"
    IGNOREIP_LINE=""
else
    echo -e "${GREEN}Custom ignored IPs: $IGNORE_IP_RANGES${NC}"
    IGNOREIP_LINE="ignoreip = $IGNORE_IP_RANGES"
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

# Install ban tracking system if enabled
if [[ "$ENABLE_TRACKING" == "true" ]]; then
    echo -e "${BLUE}Installing ban tracking system...${NC}"
    
    # Copy ban tracker script
    cp "$SCRIPT_DIR/ban-tracker.sh" "/usr/local/bin/"
    chmod +x "/usr/local/bin/ban-tracker.sh"
    echo "  ✓ Installed ban-tracker.sh"
    
    # Copy ban tracker action
    if [[ -d "$SCRIPT_DIR/action.d" ]]; then
        cp "$SCRIPT_DIR/action.d/ban-tracker.conf" "$FAIL2BAN_DIR/action.d/"
        echo "  ✓ Installed ban-tracker action"
    fi
    
    # Create tracking directory
    mkdir -p "/var/lib/saslfail"
    echo "  ✓ Created tracking directory"
    
    # Set up summary cron if requested
    if [[ "$SETUP_CRON" == "y" ]] || [[ "$SETUP_CRON" == "Y" ]]; then
        if [[ "$CRON_SCHEDULE" == "daily" ]]; then
            CRON_LINE="0 0 * * * /usr/local/bin/ban-tracker.sh daily-summary $EMAIL_ADDRESS"
            (crontab -l 2>/dev/null | grep -v "ban-tracker.sh daily-summary" ; echo "$CRON_LINE") | crontab -
            echo "  ✓ Added daily summary cron job"
        elif [[ "$CRON_SCHEDULE" == "weekly" ]]; then
            # Run weekly summary on Mondays at midnight (covers previous week)
            CRON_LINE="0 0 * * 1 /usr/local/bin/ban-tracker.sh weekly-summary $EMAIL_ADDRESS"
            (crontab -l 2>/dev/null | grep -v "ban-tracker.sh weekly-summary" ; echo "$CRON_LINE") | crontab -
            echo "  ✓ Added weekly summary cron job (runs Mondays)"
        fi
    fi
fi

# Backup existing jail config if it exists
if [[ -f "$JAIL_DIR/postfix-sasl-strict.conf" ]]; then
    echo -e "${YELLOW}Backing up existing jail config...${NC}"
    mv "$JAIL_DIR/postfix-sasl-strict.conf" "$JAIL_DIR/postfix-sasl-strict.conf.backup-$(date +%Y%m%d-%H%M%S)"
fi

# Copy jail configuration
echo -e "${BLUE}Installing jail configuration...${NC}"
if [[ -d "$SCRIPT_DIR/jail.d" ]]; then
    # Choose template based on tracking
    if [[ "$ENABLE_TRACKING" == "true" ]]; then
        TEMPLATE_FILE="$SCRIPT_DIR/jail.d/postfix-sasl-escalating-tracker.conf"
    else
        TEMPLATE_FILE="$SCRIPT_DIR/jail.d/postfix-sasl-escalating.conf"
    fi
    
    # Read the template jail config and substitute variables
    JAIL_CONTENT=$(cat "$TEMPLATE_FILE")
    
    # Set notification_email variable
    JAIL_CONTENT=$(echo "$JAIL_CONTENT" | sed "s/%(notification_email)s/$NOTIFICATION_EMAIL/g")
    
    # Handle optional immediate email actions
    if [[ -n "$EMAIL_CONFIG_FIRST" ]]; then
        JAIL_CONTENT=$(echo "$JAIL_CONTENT" | sed "s/%(optional_immediate_email)s/$EMAIL_CONFIG_FIRST/g")
    else
        JAIL_CONTENT=$(echo "$JAIL_CONTENT" | sed "/%(optional_immediate_email)s/d")
    fi
    
    # Replace email placeholders with actual configuration
    JAIL_CONTENT="${JAIL_CONTENT//\#         sendmail-whois\[name=postfix-sasl-1st, dest=admin@example.com\]/$EMAIL_CONFIG_FIRST}"
    JAIL_CONTENT="${JAIL_CONTENT//\#         sendmail-whois\[name=postfix-sasl-2nd, dest=admin@example.com, subject=\"Second Strike Ban - 8 Days\"\]/$EMAIL_CONFIG_SECOND}"
    JAIL_CONTENT="${JAIL_CONTENT//\#         sendmail-whois\[name=postfix-sasl-3rd, dest=admin@example.com, subject=\"Third Strike Ban - 32 Days\"\]/$EMAIL_CONFIG_THIRD}"
    
    # Handle ignoreip configuration
    if [[ -z "$IGNOREIP_LINE" ]]; then
        # Remove all ignoreip lines to inherit from DEFAULT
        JAIL_CONTENT=$(echo "$JAIL_CONTENT" | grep -v "^ignoreip = ")
    else
        # Replace all ignoreip lines with custom configuration
        JAIL_CONTENT=$(echo "$JAIL_CONTENT" | sed "s/^ignoreip = .*/$IGNOREIP_LINE/g")
    fi
    
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

# Note: Automated monitoring timer removed to prevent journal spam
# Users can run monitor-postfix-bans.sh manually when needed
# Or use ban-tracker.sh for scheduled summaries

# Final status report
echo
echo -e "${GREEN}=== INSTALLATION COMPLETE ===${NC}"
echo
case "$NOTIF_MODE" in
    1) echo "📧 Notifications: Disabled (tracking only)" ;;
    2) echo "📧 Notifications: Smart mode to $EMAIL_ADDRESS" ;;
    3) echo "📧 Notifications: Immediate mode to $EMAIL_ADDRESS" ;;
    4) echo "📧 Notifications: Daily summary to $EMAIL_ADDRESS" ;;
    5) echo "📧 Notifications: Weekly summary to $EMAIL_ADDRESS" ;;
esac

if [[ "$ENABLE_TRACKING" == "true" ]]; then
    echo "📊 Ban tracking: Enabled (/var/lib/saslfail/bans.db)"
    echo "📈 Reports: ban-tracker.sh report {--by-date|--by-ip|--summary}"
fi

if [[ -z "$IGNORE_IP_RANGES" ]]; then
    echo "🛡️  Ignored IPs: Inheriting from [DEFAULT]"
else
    echo "🛡️  Ignored IPs: $IGNORE_IP_RANGES"
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
