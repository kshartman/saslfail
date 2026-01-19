#!/bin/bash
# Upgrade saslfail from v1 to v2
# v2 fixes: proper escalation logic, no instant cascade, correct strike counts

set -e

VERSION_FILE="/var/lib/saslfail/db_version"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="/root/saslfail-upgrade-$(date +%Y%m%d-%H%M%S)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

get_version() {
    if [[ -f "$VERSION_FILE" ]]; then
        cat "$VERSION_FILE"
    else
        echo "1"
    fi
}

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Upgrade saslfail from v1 to v2.

v2 changes:
- Fixes instant cascade bug (all 3 strikes fired on every offense)
- Fixes recidive ghost bans (Strike 2/3 fired without actual new offenses)
- Proper escalation: offense #1→Strike 1, #2→Strike 2, #3+→Strike 3
- Strike 2/3 jails no longer have filters (populated by ban-tracker.sh)

Options:
  --dry-run     Show what would be done without making changes
  --force       Run even if already at target version
  -h, --help    Show this help message

EOF
    exit 0
}

DRY_RUN=false
FORCE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            ;;
    esac
done

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
    exit 1
fi

# Check if saslfail is installed
if [[ ! -d "/var/lib/saslfail" ]]; then
    log_error "saslfail not installed (/var/lib/saslfail not found)"
    log_info "Run install-postfix-escalating-bans.sh first"
    exit 1
fi

if [[ ! -f "/etc/fail2ban/jail.d/postfix-sasl-escalating.conf" ]]; then
    log_error "saslfail jail config not found"
    exit 1
fi

# Check version
CURRENT_VERSION=$(get_version)
TARGET_VERSION=2

echo "=== SASLFAIL UPGRADE ==="
echo "Current version: $CURRENT_VERSION"
echo "Target version:  $TARGET_VERSION"
echo

if [[ "$CURRENT_VERSION" -ge "$TARGET_VERSION" ]] && [[ "$FORCE" == "false" ]]; then
    log_info "Already at version $CURRENT_VERSION, no upgrade needed"
    log_info "Use --force to run anyway"
    exit 0
fi

if [[ "$DRY_RUN" == "true" ]]; then
    log_warn "DRY RUN - no changes will be made"
    echo
fi

# Step 1: Create backup
log_info "Step 1: Creating backup..."
if [[ "$DRY_RUN" == "false" ]]; then
    mkdir -p "$BACKUP_DIR"
    cp -r /etc/fail2ban/jail.d/postfix-sasl*.conf "$BACKUP_DIR/" 2>/dev/null || true
    cp -r /etc/fail2ban/filter.d/postfix-sasl*.conf "$BACKUP_DIR/" 2>/dev/null || true
    cp /usr/local/bin/ban-tracker.sh "$BACKUP_DIR/" 2>/dev/null || true
    cp /var/lib/saslfail/bans.db "$BACKUP_DIR/" 2>/dev/null || true
    log_info "Backup created: $BACKUP_DIR"
else
    log_info "Would create backup at: $BACKUP_DIR"
fi

# Step 2: Install dummy filter for Strike 2/3 jails
log_info "Step 2: Installing dummy filter..."
DUMMY_FILTER='# Dummy filter that never matches anything
# Used for jails that are only populated manually via fail2ban-client

[Definition]
# This regex will never match any real log line
failregex = ^SASLFAIL_DUMMY_NEVER_MATCH_THIS_STRING <HOST>$

ignoreregex =

journalmatch ='

if [[ "$DRY_RUN" == "false" ]]; then
    echo "$DUMMY_FILTER" > /etc/fail2ban/filter.d/postfix-sasl-dummy.conf
    log_info "Installed: /etc/fail2ban/filter.d/postfix-sasl-dummy.conf"
else
    log_info "Would install dummy filter"
fi

# Step 3: Update jail config
log_info "Step 3: Updating jail configuration..."
if [[ "$DRY_RUN" == "false" ]]; then
    # Read current config to preserve customizations
    CURRENT_JAIL="/etc/fail2ban/jail.d/postfix-sasl-escalating.conf"

    # Extract ignoreip if customized
    IGNOREIP=$(grep "^ignoreip" "$CURRENT_JAIL" | head -1 | sed 's/ignoreip = //')
    if [[ -z "$IGNOREIP" ]]; then
        IGNOREIP="127.0.0.1/8 ::1 192.168.0.0/16 10.0.0.0/8 172.16.0.0/12"
    fi

    # Extract email settings
    BAN_EMAIL=$(grep "ban_notification_email" "$CURRENT_JAIL" | head -1 | grep -oP '(?<=email=)[^]]+' || echo "none")

    # Write new jail config
    cat > "$CURRENT_JAIL" << JAILEOF
# /etc/fail2ban/jail.d/postfix-sasl-escalating.conf
# Progressive ban system v2: 48h -> 8 days -> 32 days
# Escalation handled by ban-tracker.sh, not recidive filters

# First Strike: 48 hours (watches mail.log for SASL failures)
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
         ban-tracker[name=postfix-sasl-first, email=none]
ignoreip = $IGNOREIP

# Second Strike: 8 days (NO FILTER - populated by ban-tracker.sh)
[postfix-sasl-second]
enabled = true
port = smtp,465,587,submission,smtps
logpath = /var/log/fail2ban.log
backend = auto
maxretry = 999999
findtime = 1
bantime = 691200
filter = postfix-sasl-dummy
action = iptables-multiport[name=postfix-sasl-2nd, port="25,465,587", protocol=tcp]
ignoreip = $IGNOREIP

# Third Strike: 32 days (NO FILTER - populated by ban-tracker.sh)
[postfix-sasl-third]
enabled = true
port = smtp,465,587,submission,smtps
logpath = /var/log/fail2ban.log
backend = auto
maxretry = 999999
findtime = 1
bantime = 2764800
filter = postfix-sasl-dummy
action = iptables-multiport[name=postfix-sasl-3rd, port="25,465,587", protocol=tcp]
ignoreip = $IGNOREIP
JAILEOF
    log_info "Updated jail config"
else
    log_info "Would update jail config with dummy filters for Strike 2/3"
fi

# Step 4: Update ban-tracker.sh
log_info "Step 4: Updating ban-tracker.sh..."
if [[ "$DRY_RUN" == "false" ]]; then
    cp "$SCRIPT_DIR/ban-tracker.sh" /usr/local/bin/ban-tracker.sh
    chmod +x /usr/local/bin/ban-tracker.sh
    log_info "Updated: /usr/local/bin/ban-tracker.sh"
else
    log_info "Would update ban-tracker.sh"
fi

# Step 5: Install fix-historical-bans.sh
log_info "Step 5: Installing fix-historical-bans.sh..."
if [[ "$DRY_RUN" == "false" ]]; then
    cp "$SCRIPT_DIR/fix-historical-bans.sh" /usr/local/bin/fix-historical-bans.sh
    chmod +x /usr/local/bin/fix-historical-bans.sh
    log_info "Installed: /usr/local/bin/fix-historical-bans.sh"
else
    log_info "Would install fix-historical-bans.sh"
fi

# Step 6: Test fail2ban config
log_info "Step 6: Testing fail2ban configuration..."
if [[ "$DRY_RUN" == "false" ]]; then
    if ! fail2ban-client -t 2>&1; then
        log_error "Fail2ban config test failed!"
        log_info "Restoring backup..."
        cp "$BACKUP_DIR"/*.conf /etc/fail2ban/jail.d/ 2>/dev/null || true
        cp "$BACKUP_DIR"/postfix-sasl*.conf /etc/fail2ban/filter.d/ 2>/dev/null || true
        exit 1
    fi
    log_info "Config test passed"
else
    log_info "Would test fail2ban config"
fi

# Step 7: Restart fail2ban
log_info "Step 7: Restarting fail2ban..."
if [[ "$DRY_RUN" == "false" ]]; then
    systemctl restart fail2ban
    sleep 2
    if systemctl is-active fail2ban >/dev/null 2>&1; then
        log_info "Fail2ban restarted successfully"
    else
        log_error "Fail2ban failed to start!"
        exit 1
    fi
else
    log_info "Would restart fail2ban"
fi

# Step 8: Fix historical database
log_info "Step 8: Fixing historical ban database..."
if [[ "$DRY_RUN" == "false" ]]; then
    /usr/local/bin/fix-historical-bans.sh
else
    log_info "Would run fix-historical-bans.sh"
fi

# Step 9: Remove old recidive filter files (optional cleanup)
log_info "Step 9: Cleaning up old recidive filters..."
if [[ "$DRY_RUN" == "false" ]]; then
    rm -f /etc/fail2ban/filter.d/postfix-sasl-recidive.conf
    rm -f /etc/fail2ban/filter.d/postfix-sasl-recidive-third.conf
    log_info "Removed old recidive filters"
else
    log_info "Would remove postfix-sasl-recidive*.conf"
fi

echo
echo "=== UPGRADE COMPLETE ==="
echo
log_info "saslfail upgraded to version 2"
log_info "Backup saved: $BACKUP_DIR"
echo
echo "Changes:"
echo "  - Strike 2/3 jails now use dummy filter (no log watching)"
echo "  - ban-tracker.sh handles escalation based on offense count"
echo "  - Historical database fixed with correct strike counts"
echo
echo "Verify with:"
echo "  fail2ban-client status"
echo "  ban-tracker.sh report --summary"
