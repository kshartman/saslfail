#!/bin/bash
# Uninstaller for Postfix SASL Escalating Ban System

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== POSTFIX SASL ESCALATING BAN SYSTEM UNINSTALLER ===${NC}"
echo

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Find backup directory
BACKUP_DIR=$(ls -1d /root/fail2ban-backup-* 2>/dev/null | tail -1)

if [[ -z "$BACKUP_DIR" ]]; then
    echo -e "${YELLOW}No backup found. Proceeding with manual cleanup...${NC}"
    MANUAL_CLEANUP=true
else
    echo -e "${GREEN}Found backup: $BACKUP_DIR${NC}"
    MANUAL_CLEANUP=false
fi

# Stop fail2ban
echo -e "${BLUE}Stopping fail2ban...${NC}"
systemctl stop fail2ban

# Remove escalating ban files
echo -e "${BLUE}Removing escalating ban configuration...${NC}"

# Remove jail configuration
rm -f /etc/fail2ban/jail.d/postfix-sasl-escalating.conf

# Remove filters
rm -f /etc/fail2ban/filter.d/postfix-sasl-recidive.conf
rm -f /etc/fail2ban/filter.d/postfix-sasl-recidive-third.conf

# Remove monitoring script
rm -f /usr/local/bin/monitor-postfix-bans.sh

# Remove ban tracker script
rm -f /usr/local/bin/ban-tracker.sh

# Remove ban tracker action
rm -f /etc/fail2ban/action.d/ban-tracker.conf

# Remove ban tracker data
rm -rf /var/lib/saslfail

# Remove systemd services
systemctl stop postfix-ban-monitor.timer 2>/dev/null || true
systemctl disable postfix-ban-monitor.timer 2>/dev/null || true
rm -f /etc/systemd/system/postfix-ban-monitor.service
rm -f /etc/systemd/system/postfix-ban-monitor.timer
systemctl daemon-reload

if [[ "$MANUAL_CLEANUP" == "false" ]]; then
    echo -e "${BLUE}Restoring original configuration from backup...${NC}"
    # Don't restore everything, just the jail config if it existed
    if [[ -f "$BACKUP_DIR/jail.d/postfix-sasl-strict.conf" ]]; then
        cp "$BACKUP_DIR/jail.d/postfix-sasl-strict.conf" /etc/fail2ban/jail.d/
        echo -e "${GREEN}Restored original jail configuration${NC}"
    fi
fi

# Clear fail2ban database to remove persistent bans
echo -e "${BLUE}Clearing fail2ban database...${NC}"
rm -f /var/lib/fail2ban/fail2ban.sqlite3

# Start fail2ban
echo -e "${BLUE}Starting fail2ban...${NC}"
systemctl start fail2ban

sleep 3

echo
echo -e "${GREEN}=== UNINSTALLATION COMPLETE ===${NC}"
echo
echo -e "${BLUE}Current fail2ban status:${NC}"
fail2ban-client status

echo
echo -e "${YELLOW}Note: All existing bans have been cleared.${NC}"
if [[ "$MANUAL_CLEANUP" == "false" ]]; then
    echo -e "${YELLOW}Original configuration restored from: $BACKUP_DIR${NC}"
fi
echo -e "${GREEN}Escalating ban system has been removed.${NC}"
