#!/bin/bash
# Ban tracking system for fail2ban postfix-sasl jails
# Records ban events persistently and manages smart notifications

TRACK_DIR="/var/lib/saslfail"
BAN_DB="$TRACK_DIR/bans.db"
NOTIFICATION_STATE="$TRACK_DIR/notification_state"
LOG_FILE="$TRACK_DIR/tracker.log"

# Ensure tracking directory exists
mkdir -p "$TRACK_DIR"

# Initialize database if it doesn't exist
if [[ ! -f "$BAN_DB" ]]; then
    echo "timestamp|ip|jail|action|strike_level|notified" > "$BAN_DB"
fi

# Initialize notification state file if it doesn't exist
if [[ ! -f "$NOTIFICATION_STATE" ]]; then
    echo "# IP|first_ban_time|last_strike|notification_sent" > "$NOTIFICATION_STATE"
fi

# Function to log messages
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Function to get strike level from jail name
get_strike_level() {
    local jail="$1"
    case "$jail" in
        postfix-sasl-first) echo 1 ;;
        postfix-sasl-second) echo 2 ;;
        postfix-sasl-third) echo 3 ;;
        *) echo 0 ;;
    esac
}

# Function to record a ban event
record_ban() {
    local ip="$1"
    local jail="$2"
    local email="$3"
    local action="ban"
    local strike_level=$(get_strike_level "$jail")
    local current_time=$(date '+%Y-%m-%d %H:%M:%S')
    local epoch_time=$(date +%s)
    
    # Record in database
    echo "$current_time|$ip|$jail|$action|$strike_level|0" >> "$BAN_DB"
    log_message "Recorded ban: IP=$ip, Jail=$jail, Strike=$strike_level"
    
    # Update notification state
    local state_entry=$(grep "^$ip|" "$NOTIFICATION_STATE" 2>/dev/null)
    
    if [[ -z "$state_entry" ]]; then
        # First ban for this IP
        echo "$ip|$epoch_time|$strike_level|0" >> "$NOTIFICATION_STATE"
        log_message "First ban for $ip, starting 5-minute window"
        
        # If strike 3, send immediate notification
        if [[ $strike_level -eq 3 ]]; then
            send_notification "$ip" "$strike_level" "$email" "immediate"
            sed -i "s/^$ip|.*|0$/$ip|$epoch_time|$strike_level|1/" "$NOTIFICATION_STATE"
        fi
    else
        # Update existing entry
        local first_ban_time=$(echo "$state_entry" | cut -d'|' -f2)
        local last_strike=$(echo "$state_entry" | cut -d'|' -f3)
        local notif_sent=$(echo "$state_entry" | cut -d'|' -f4)
        
        # Update strike level
        sed -i "s/^$ip|$first_ban_time|$last_strike|/$ip|$first_ban_time|$strike_level|/" "$NOTIFICATION_STATE"
        
        # Check if we should send notification
        local time_diff=$((epoch_time - first_ban_time))
        
        if [[ $strike_level -eq 3 ]] && [[ $notif_sent -eq 0 ]]; then
            # Strike 3 reached, send notification
            send_notification "$ip" "$strike_level" "$email" "escalated"
            sed -i "s/^$ip|.*|0$/$ip|$first_ban_time|$strike_level|1/" "$NOTIFICATION_STATE"
        elif [[ $time_diff -ge 300 ]] && [[ $notif_sent -eq 0 ]]; then
            # 5 minutes passed, send notification for current level
            send_notification "$ip" "$strike_level" "$email" "delayed"
            sed -i "s/^$ip|.*|0$/$ip|$first_ban_time|$strike_level|1/" "$NOTIFICATION_STATE"
        fi
    fi
}

# Function to send notification
send_notification() {
    local ip="$1"
    local strike="$2"
    local email="$3"
    local type="$4"  # immediate, escalated, delayed
    
    if [[ -z "$email" ]] || [[ "$email" == "none" ]]; then
        log_message "No email configured, skipping notification for $ip"
        return
    fi
    
    local subject
    local ban_duration
    case "$strike" in
        1) subject="[SASLFAIL] First Strike Ban: $ip"; ban_duration="48 hours" ;;
        2) subject="[SASLFAIL] Second Strike Ban: $ip"; ban_duration="8 days" ;;
        3) subject="[SASLFAIL] Third Strike Ban: $ip"; ban_duration="32 days" ;;
    esac
    
    # Get ban history for this IP
    local history=$(grep "|$ip|" "$BAN_DB" | tail -10)
    
    # Get whois info
    local whois_info=$(whois "$ip" 2>/dev/null | grep -E "(OrgName|org-name|descr|country|Country)" | head -5)
    
    # Create email body
    cat <<EOF | mail -s "$subject" "$email"
SASL Authentication Failure Ban Notification

IP Address: $ip
Strike Level: $strike
Ban Duration: $ban_duration
Notification Type: $type
Timestamp: $(date)

IP Information:
$whois_info

Recent Ban History:
$history

$(if [[ "$type" == "escalated" ]]; then
    echo "NOTE: This IP rapidly escalated through multiple strike levels."
elif [[ "$type" == "delayed" ]]; then
    echo "NOTE: This IP has not escalated beyond strike $strike in the past 5 minutes."
fi)
EOF
    
    log_message "Sent $type notification for $ip at strike level $strike"
}

# Function to process pending notifications (called periodically if using cron)
process_pending() {
    local email="$1"
    local current_time=$(date +%s)
    
    while IFS='|' read -r ip first_ban last_strike notif_sent; do
        # Skip comments and already notified
        [[ "$ip" =~ ^# ]] && continue
        [[ "$notif_sent" == "1" ]] && continue
        
        local time_diff=$((current_time - first_ban))
        
        if [[ $time_diff -ge 300 ]]; then
            # 5 minutes passed, send notification
            send_notification "$ip" "$last_strike" "$email" "delayed"
            sed -i "s/^$ip|$first_ban|$last_strike|0$/$ip|$first_ban|$last_strike|1/" "$NOTIFICATION_STATE"
        fi
    done < "$NOTIFICATION_STATE"
}

# Function to generate daily summary
daily_summary() {
    local email="$1"
    local date="${2:-$(date '+%Y-%m-%d')}"
    
    # Count events by strike level for specified date
    local first_strike=$(grep "^$date" "$BAN_DB" | grep "|1|" | wc -l)
    local second_strike=$(grep "^$date" "$BAN_DB" | grep "|2|" | wc -l)
    local third_strike=$(grep "^$date" "$BAN_DB" | grep "|3|" | wc -l)
    
    # Get unique IPs banned on date
    local unique_ips=$(grep "^$date" "$BAN_DB" | cut -d'|' -f2 | sort -u)
    local unique_count=$(echo "$unique_ips" | grep -c .)
    
    # Get top offending IPs
    local top_ips=$(grep "^$date" "$BAN_DB" | cut -d'|' -f2 | sort | uniq -c | sort -rn | head -10)
    
    # Create summary content
    local summary_content="SASL Authentication Failure - Daily Summary
Date: $date

Ban Statistics:
- First Strike Bans: $first_strike
- Second Strike Bans: $second_strike  
- Third Strike Bans: $third_strike
- Unique IPs Banned: $unique_count

Top 10 Offending IPs:
$top_ips

Currently Active Bans:
$(monitor-postfix-bans.sh 2>/dev/null | grep -A 100 "CURRENTLY BANNED IPs:" || echo "Unable to fetch current bans")

Database Location: $BAN_DB"
    
    if [[ -z "$email" ]] || [[ "$email" == "none" ]]; then
        # Output to console
        echo "=== [SASLFAIL] Daily Ban Summary - $date ==="
        echo
        echo "$summary_content"
        echo
        log_message "Displayed daily summary on console for $date"
    else
        # Send email
        echo "$summary_content" | mail -s "[SASLFAIL] Daily Ban Summary - $date" "$email"
        log_message "Sent daily summary to $email for $date"
    fi
}

# Function to generate weekly summary
weekly_summary() {
    local email="$1"
    local end_date="${2:-$(date '+%Y-%m-%d')}"
    local start_date=$(date -d "$end_date -6 days" '+%Y-%m-%d')
    
    # Count events by strike level for the week
    local first_strike=0
    local second_strike=0
    local third_strike=0
    local daily_stats=""
    
    for i in {6..0}; do
        local check_date=$(date -d "$end_date -$i days" '+%Y-%m-%d')
        local day_first=$(grep "^$check_date" "$BAN_DB" | grep "|1|" | wc -l)
        local day_second=$(grep "^$check_date" "$BAN_DB" | grep "|2|" | wc -l)
        local day_third=$(grep "^$check_date" "$BAN_DB" | grep "|3|" | wc -l)
        
        first_strike=$((first_strike + day_first))
        second_strike=$((second_strike + day_second))
        third_strike=$((third_strike + day_third))
        
        daily_stats="${daily_stats}$check_date: Strike1=$day_first, Strike2=$day_second, Strike3=$day_third\n"
    done
    
    # Get unique IPs banned during the week
    local unique_ips=$(awk -F'|' -v start="$start_date" -v end="$end_date 23:59:59" \
        '$1 >= start && $1 <= end {print $2}' "$BAN_DB" | sort -u)
    local unique_count=$(echo "$unique_ips" | grep -c .)
    
    # Get top offending IPs for the week
    local top_ips=$(awk -F'|' -v start="$start_date" -v end="$end_date 23:59:59" \
        '$1 >= start && $1 <= end {print $2}' "$BAN_DB" | sort | uniq -c | sort -rn | head -20)
    
    # Create summary content
    local summary_content="SASL Authentication Failure - Weekly Summary
Period: $start_date to $end_date

Weekly Ban Statistics:
- First Strike Bans: $first_strike
- Second Strike Bans: $second_strike  
- Third Strike Bans: $third_strike
- Unique IPs Banned: $unique_count

Daily Breakdown:
$(echo -e "$daily_stats")

Top 20 Offending IPs This Week:
$top_ips

Currently Active Bans:
$(monitor-postfix-bans.sh 2>/dev/null | grep -A 100 "CURRENTLY BANNED IPs:" || echo "Unable to fetch current bans")

Database Location: $BAN_DB"
    
    if [[ -z "$email" ]] || [[ "$email" == "none" ]]; then
        # Output to console
        echo "=== [SASLFAIL] Weekly Ban Summary - $start_date to $end_date ==="
        echo
        echo "$summary_content"
        echo
        log_message "Displayed weekly summary on console for $start_date to $end_date"
    else
        # Send email
        echo "$summary_content" | mail -s "[SASLFAIL] Weekly Ban Summary - $start_date to $end_date" "$email"
        log_message "Sent weekly summary to $email for $start_date to $end_date"
    fi
}

# Reporting functions
report_by_date() {
    echo "=== Ban Report - Sorted by Date (Newest First) ==="
    echo
    printf "%-20s | %-15s | %-8s | %-20s\n" "Timestamp" "IP Address" "Strike" "Jail"
    echo "--------------------------------------------------------------------------------"
    tail -n +2 "$BAN_DB" | sort -r | while IFS='|' read -r timestamp ip jail action strike notified; do
        [[ "$action" == "ban" ]] && printf "%-20s | %-15s | %-8s | %-20s\n" "$timestamp" "$ip" "$strike" "$jail"
    done
}

report_by_ip() {
    echo "=== Ban Report - Grouped by IP ==="
    echo
    
    # Get unique IPs
    local ips=$(tail -n +2 "$BAN_DB" | cut -d'|' -f2 | sort -u)
    
    while read -r ip; do
        [[ -z "$ip" ]] && continue
        
        local ban_count=$(grep "|$ip|" "$BAN_DB" | grep "|ban|" | wc -l)
        echo "$ip ($ban_count bans):"
        
        grep "|$ip|" "$BAN_DB" | grep "|ban|" | while IFS='|' read -r timestamp ip_check jail action strike notified; do
            printf "  %-20s | Strike %s | %-20s\n" "$timestamp" "$strike" "$jail"
        done
        echo
    done <<< "$ips"
}

report_summary() {
    echo "=== Ban Tracking Statistics ==="
    echo
    echo "Database: $BAN_DB"
    echo "Total recorded bans: $(tail -n +2 "$BAN_DB" | grep "|ban|" | wc -l)"
    echo "Unique IPs: $(tail -n +2 "$BAN_DB" | cut -d'|' -f2 | sort -u | wc -l)"
    echo
    echo "Bans by strike level:"
    echo "  Strike 1: $(grep "|ban|1|" "$BAN_DB" | wc -l)"
    echo "  Strike 2: $(grep "|ban|2|" "$BAN_DB" | wc -l)"
    echo "  Strike 3: $(grep "|ban|3|" "$BAN_DB" | wc -l)"
    echo
    echo "Recent activity (last 24h):"
    local yesterday=$(date -d '24 hours ago' '+%Y-%m-%d %H:%M:%S')
    local recent_count=$(awk -F'|' -v date="$yesterday" '$1 > date && $4 == "ban"' "$BAN_DB" | wc -l)
    echo "  Bans in last 24h: $recent_count"
}

# Function to show help
show_help() {
    cat << 'EOF'
Ban Tracker for Postfix SASL Escalating Ban System

USAGE:
    ban-tracker.sh [COMMAND] [OPTIONS]

COMMANDS:
    record-ban <ip> <jail> [email]
        Record a ban event (called by fail2ban action)
        
    report --by-date
        Show all bans sorted by date (newest first)
        
    report --by-ip
        Show all bans grouped by IP address
        
    report --summary
        Show ban statistics summary
        
    daily-summary [email] [date]
        Generate daily summary report
        - If no email: outputs to console
        - If no date: uses today
        
    weekly-summary [email] [date]
        Generate weekly summary report (7 days ending on date)
        - If no email: outputs to console
        - If no date: uses today as end date
        
    process-pending [email]
        Process pending notifications (for smart notification mode)
        
    cleanup
        Remove old notification states (> 7 days)
        
    --help, -h
        Show this help message

EXAMPLES:
    # View all bans ever recorded
    ban-tracker.sh report --by-date
    
    # View bans grouped by IP
    ban-tracker.sh report --by-ip
    
    # Get summary statistics
    ban-tracker.sh report --summary
    
    # Generate daily report to console
    ban-tracker.sh daily-summary
    
    # Send weekly summary via email
    ban-tracker.sh weekly-summary admin@example.com
    
    # View bans for specific date
    ban-tracker.sh daily-summary "" 2025-07-24

FILES:
    /var/lib/saslfail/bans.db           - Ban history database
    /var/lib/saslfail/notification_state - Notification tracking
    /var/lib/saslfail/tracker.log       - Ban tracker log

EOF
}

# Main command processing
case "$1" in
    --help|-h)
        show_help
        exit 0
        ;;
    record-ban)
        if [[ $# -lt 3 ]]; then
            echo "Usage: $0 record-ban <ip> <jail> [email]"
            exit 1
        fi
        record_ban "$2" "$3" "${4:-}"
        ;;
    process-pending)
        process_pending "${2:-}"
        ;;
    daily-summary)
        daily_summary "${2:-}" "${3:-}"
        ;;
    weekly-summary)
        weekly_summary "${2:-}" "${3:-}"
        ;;
    report)
        case "$2" in
            --by-date) report_by_date ;;
            --by-ip) report_by_ip ;;
            --summary) report_summary ;;
            *)
                echo "Usage: $0 report {--by-date|--by-ip|--summary}"
                exit 1
                ;;
        esac
        ;;
    cleanup)
        # Clean up old notification states (older than 7 days)
        local week_ago=$(date -d '7 days ago' +%s)
        local temp_file="$NOTIFICATION_STATE.tmp"
        echo "# IP|first_ban_time|last_strike|notification_sent" > "$temp_file"
        
        while IFS='|' read -r ip first_ban last_strike notif_sent; do
            [[ "$ip" =~ ^# ]] && continue
            if [[ $first_ban -gt $week_ago ]]; then
                echo "$ip|$first_ban|$last_strike|$notif_sent" >> "$temp_file"
            fi
        done < "$NOTIFICATION_STATE"
        
        mv "$temp_file" "$NOTIFICATION_STATE"
        log_message "Cleaned up old notification states"
        ;;
    *)
        echo "Usage: $0 [COMMAND] [OPTIONS]"
        echo
        echo "Use '$0 --help' for detailed command information"
        exit 1
        ;;
esac