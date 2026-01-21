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

# Function to count previous offenses for an IP
count_offenses() {
    local ip="$1"
    # Count real ban entries only (exclude restore-ban)
    grep "|$ip|.*|ban|" "$BAN_DB" 2>/dev/null | grep -v "|restore-ban|" | wc -l
}

# Function to record a ban event
record_ban() {
    local ip="$1"
    local jail="$2"
    local email="$3"
    local current_time=$(date '+%Y-%m-%d %H:%M:%S')
    local epoch_time=$(date +%s)

    # Only process Strike 1 detections (the actual SASL failure detector)
    # Strike 2/3 jails have no filters - we populate them via escalation
    if [[ "$jail" != "postfix-sasl-first" ]]; then
        log_message "Ignoring non-Strike1 ban call: IP=$ip, Jail=$jail"
        return
    fi

    # Check if there's an unexpired ban (indicates restart/restore)
    local last_ban=$(grep "|$ip|.*|ban|" "$BAN_DB" 2>/dev/null | tail -1)
    if [[ -n "$last_ban" ]]; then
        local last_ban_time=$(echo "$last_ban" | cut -d'|' -f1)
        local last_strike=$(echo "$last_ban" | cut -d'|' -f5)
        local last_epoch=$(date -d "$last_ban_time" +%s 2>/dev/null || echo 0)
        local time_since_ban=$((epoch_time - last_epoch))
        local ban_duration=$(get_ban_duration "$last_strike")

        # If previous ban hasn't expired, this is a restore
        if [[ $time_since_ban -lt $ban_duration ]]; then
            echo "$current_time|$ip|$jail|restore-ban|1|0" >> "$BAN_DB"
            log_message "Recorded restore-ban: IP=$ip (previous Strike $last_strike ban still active)"
            return
        fi
    fi

    # Count previous offenses to determine strike level
    local prev_offenses=$(count_offenses "$ip")
    local offense_num=$((prev_offenses + 1))
    local strike_level
    local target_jail

    if [[ $offense_num -eq 1 ]]; then
        strike_level=1
        target_jail="postfix-sasl-first"
    elif [[ $offense_num -eq 2 ]]; then
        strike_level=2
        target_jail="postfix-sasl-second"
    else
        strike_level=3
        target_jail="postfix-sasl-third"
    fi

    log_message "Offense #$offense_num for $ip → Strike $strike_level"

    # Record in database (only the target strike level, no cascade)
    echo "$current_time|$ip|$target_jail|ban|$strike_level|0" >> "$BAN_DB"
    log_message "Recorded ban: IP=$ip, Strike=$strike_level"

    # Escalate if needed (move to higher strike jail)
    if [[ $strike_level -gt 1 ]]; then
        # Add to target jail
        fail2ban-client set "$target_jail" banip "$ip" 2>/dev/null
        log_message "Escalated $ip to $target_jail"

        # Remove from Strike 1 jail (they're now in a higher jail)
        fail2ban-client set postfix-sasl-first unbanip "$ip" 2>/dev/null
        log_message "Removed $ip from postfix-sasl-first"
    fi

    # Handle notifications
    if [[ -n "$email" ]] && [[ "$email" != "none" ]]; then
        if [[ $strike_level -eq 3 ]]; then
            send_notification "$ip" "$strike_level" "$email" "immediate"
        else
            # Update notification state for delayed notification
            local state_entry=$(grep "^$ip|" "$NOTIFICATION_STATE" 2>/dev/null)
            if [[ -z "$state_entry" ]]; then
                echo "$ip|$epoch_time|$strike_level|0" >> "$NOTIFICATION_STATE"
            else
                local first_ban_time=$(echo "$state_entry" | cut -d'|' -f2)
                sed -i "s/^$ip|.*/$ip|$first_ban_time|$strike_level|0/" "$NOTIFICATION_STATE"
            fi
        fi
    fi
}

# Function to get ban duration in seconds for a strike level
get_ban_duration() {
    local strike="$1"
    case $strike in
        1) echo 172800 ;;   # 48 hours
        2) echo 691200 ;;   # 8 days
        3) echo 2764800 ;;  # 32 days
        *) echo 172800 ;;
    esac
}

# Function to record an unban event
record_unban() {
    local ip="$1"
    local jail="$2"
    local current_time=$(date '+%Y-%m-%d %H:%M:%S')
    local epoch_time=$(date +%s)
    local strike_level=$(get_strike_level "$jail")
    local ban_duration=$(get_ban_duration "$strike_level")

    # Find the last ban for this IP+jail
    local last_ban=$(grep "|$ip|$jail|ban|" "$BAN_DB" 2>/dev/null | tail -1)
    local action="unban"

    if [[ -n "$last_ban" ]]; then
        local last_ban_time=$(echo "$last_ban" | cut -d'|' -f1)
        local last_epoch=$(date -d "$last_ban_time" +%s 2>/dev/null || echo 0)
        local time_since_ban=$((epoch_time - last_epoch))

        # If ban duration hasn't elapsed, this is a restart unban
        if [[ $time_since_ban -lt $ban_duration ]]; then
            action="restore-unban"
            log_message "Restart unban: IP=$ip, Strike=$strike_level (${time_since_ban}s < ${ban_duration}s)"
        fi
    fi

    # Record in database
    echo "$current_time|$ip|$jail|$action|$strike_level|0" >> "$BAN_DB"
    log_message "Recorded $action: IP=$ip, Jail=$jail, Strike=$strike_level"

    # Only clear notification state on real unbans
    if [[ "$action" == "unban" ]]; then
        sed -i "/^$ip|/d" "$NOTIFICATION_STATE"
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
    
    # Check if fail2ban is running
    local f2b_status=""
    if systemctl is-active fail2ban >/dev/null 2>&1; then
        f2b_status="Fail2ban is ACTIVE"
    else
        f2b_status="WARNING: FAIL2BAN IS NOT RUNNING! No bans are being enforced!"
    fi
    
    # Count NEW bans that occurred on specified date (exclude restore-ban)
    local new_first_strike=$(grep "^$date" "$BAN_DB" | grep "|ban|1|" | grep -cv "|restore-ban|")
    local new_second_strike=$(grep "^$date" "$BAN_DB" | grep "|ban|2|" | grep -cv "|restore-ban|")
    local new_third_strike=$(grep "^$date" "$BAN_DB" | grep "|ban|3|" | grep -cv "|restore-ban|")

    # Get unique IPs that received NEW bans on date (exclude restore-ban)
    local new_banned_ips=$(grep "^$date" "$BAN_DB" | grep "|ban|" | grep -v "|restore-ban|" | cut -d'|' -f2 | sort -u)
    local new_banned_count=$(echo "$new_banned_ips" | grep -c . 2>/dev/null || echo 0)
    
    # Get CURRENTLY ACTIVE bans (banned but not unbanned or banned after last unban)
    local active_bans=""
    local active_first=0
    local active_second=0
    local active_third=0
    local active_ips=""
    
    # Get all unique IPs from database
    local all_ips=$(tail -n +2 "$BAN_DB" | cut -d'|' -f2 | sort -u)
    
    while read -r ip; do
        [[ -z "$ip" ]] && continue
        
        # Check each jail for this IP
        for jail in postfix-sasl-first postfix-sasl-second postfix-sasl-third; do
            local strike_level
            case "$jail" in
                postfix-sasl-first) strike_level=1 ;;
                postfix-sasl-second) strike_level=2 ;;
                postfix-sasl-third) strike_level=3 ;;
            esac
            
            # Get last real ban and unban for this IP/jail combo (exclude restore events)
            local last_ban=$(grep "|$ip|$jail|ban|" "$BAN_DB" | grep -v "|restore-ban|" | tail -1)
            local last_unban=$(grep "|$ip|$jail|unban|" "$BAN_DB" | grep -v "|restore-unban|" | tail -1)
            
            if [[ -n "$last_ban" ]]; then
                local ban_time=$(echo "$last_ban" | cut -d'|' -f1)
                
                if [[ -n "$last_unban" ]]; then
                    local unban_time=$(echo "$last_unban" | cut -d'|' -f1)
                    # If ban is after unban, IP is currently banned in this jail
                    if [[ "$ban_time" > "$unban_time" ]]; then
                        case $strike_level in
                            1) ((active_first++)) ;;
                            2) ((active_second++)) ;;
                            3) ((active_third++)) ;;
                        esac
                        active_ips="${active_ips}${ip}:${strike_level}\n"
                    fi
                else
                    # No unban record means IP is still banned
                    case $strike_level in
                        1) ((active_first++)) ;;
                        2) ((active_second++)) ;;
                        3) ((active_third++)) ;;
                    esac
                    active_ips="${active_ips}${ip}:${strike_level}\n"
                fi
            fi
        done
    done <<< "$all_ips"
    
    # Get unique actively banned IPs (taking highest strike level)
    local unique_active_ips=$(echo -e "$active_ips" | cut -d':' -f1 | sort -u)
    local active_count=$(echo "$unique_active_ips" | grep -c . 2>/dev/null || echo 0)
    
    # Get top offending IPs from last 7 days (exclude restore-ban)
    local week_ago=$(date -d '7 days ago' '+%Y-%m-%d')
    local top_ips=$(grep -v "|restore-ban|" "$BAN_DB" | awk -F'|' -v start="$week_ago" '$1 >= start && $4 == "ban" {print $2}' | \
                    sort | uniq -c | sort -rn | head -10)
    
    # Format currently active bans by strike level
    local active_by_strike=""
    if [[ $active_count -gt 0 ]]; then
        # Get IPs at each strike level (highest strike only per IP)
        local strike3_ips=""
        local strike2_ips=""
        local strike1_ips=""
        
        while read -r ip; do
            [[ -z "$ip" ]] && continue
            # Find highest active strike for this IP
            local highest_strike=0
            for strike in 3 2 1; do
                if echo -e "$active_ips" | grep -q "^${ip}:${strike}$"; then
                    highest_strike=$strike
                    break
                fi
            done
            
            case $highest_strike in
                3) strike3_ips="${strike3_ips}  ${ip}\n" ;;
                2) strike2_ips="${strike2_ips}  ${ip}\n" ;;
                1) strike1_ips="${strike1_ips}  ${ip}\n" ;;
            esac
        done <<< "$unique_active_ips"
        
        active_by_strike="=== CURRENTLY ACTIVE BANS (from database):

[STRIKE 3] Third Strike (32 days):
$(if [[ -n "$strike3_ips" ]]; then echo -e "$strike3_ips" | head -n -1; else echo "  None"; fi)

[STRIKE 2] Second Strike (8 days):
$(if [[ -n "$strike2_ips" ]]; then echo -e "$strike2_ips" | head -n -1; else echo "  None"; fi)

[STRIKE 1] First Strike (48 hours):
$(if [[ -n "$strike1_ips" ]]; then echo -e "$strike1_ips" | head -n -1; else echo "  None"; fi)"
    else
        active_by_strike="=== CURRENTLY ACTIVE BANS:
  No active bans in database"
    fi
    
    # Get recent ban activity (last 24h, exclude restore-ban)
    local yesterday=$(date -d '24 hours ago' '+%Y-%m-%d %H:%M:%S')
    local recent_bans=$(grep -v "|restore-ban|" "$BAN_DB" | awk -F'|' -v date="$yesterday" '$1 > date && $4 == "ban"' | tail -10)
    
    # Create summary content
    local summary_content="SASL Authentication Failure - Daily Summary
Date: $date

=== FAIL2BAN STATUS: $f2b_status

=== NEW BANS TODAY:
- First Strike Bans: $new_first_strike
- Second Strike Bans: $new_second_strike  
- Third Strike Bans: $new_third_strike
- Unique IPs Banned Today: $new_banned_count

=== CURRENTLY ACTIVE BANS (Total):
- Active First Strike: $active_first
- Active Second Strike: $active_second
- Active Third Strike: $active_third
- Total Unique IPs Currently Banned: $active_count

=== TOP OFFENDING IPs (Last 7 Days):
$(if [[ -n "$top_ips" ]]; then echo "$top_ips"; else echo "  No bans in last 7 days"; fi)

$active_by_strike

=== RECENT BAN ACTIVITY (Last 24h):
$(if [[ -n "$recent_bans" ]]; then echo "$recent_bans" | while IFS='|' read -r ts ip jail action strike notified; do
    printf "  %s | %-15s | Strike %s | %s\n" "$ts" "$ip" "$strike" "$jail"
done; else echo "  No ban activity in last 24 hours"; fi)

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
    
    # Check if fail2ban is running
    local f2b_status=""
    if systemctl is-active fail2ban >/dev/null 2>&1; then
        f2b_status="Fail2ban is ACTIVE"
    else
        f2b_status="WARNING: FAIL2BAN IS NOT RUNNING! No bans are being enforced!"
    fi
    
    # Count events by strike level for the week
    local first_strike=0
    local second_strike=0
    local third_strike=0
    local daily_stats=""
    
    for i in {6..0}; do
        local check_date=$(date -d "$end_date -$i days" '+%Y-%m-%d')
        local day_first=$(grep "^$check_date" "$BAN_DB" | grep "|ban|1|" | grep -cv "|restore-ban|")
        local day_second=$(grep "^$check_date" "$BAN_DB" | grep "|ban|2|" | grep -cv "|restore-ban|")
        local day_third=$(grep "^$check_date" "$BAN_DB" | grep "|ban|3|" | grep -cv "|restore-ban|")

        first_strike=$((first_strike + day_first))
        second_strike=$((second_strike + day_second))
        third_strike=$((third_strike + day_third))

        daily_stats="${daily_stats}$check_date: Strike1=$day_first, Strike2=$day_second, Strike3=$day_third\n"
    done

    # Get unique IPs banned during the week (exclude restore-ban)
    local unique_ips=$(grep -v "|restore-ban|" "$BAN_DB" | awk -F'|' -v start="$start_date" -v end="$end_date 23:59:59" \
        '$1 >= start && $1 <= end && $4 == "ban" {print $2}' | sort -u)
    local unique_count=$(echo "$unique_ips" | grep -c . 2>/dev/null || echo 0)

    # Get top offending IPs for the week (exclude restore-ban)
    local top_ips=$(grep -v "|restore-ban|" "$BAN_DB" | awk -F'|' -v start="$start_date" -v end="$end_date 23:59:59" \
        '$1 >= start && $1 <= end && $4 == "ban" {print $2}' | sort | uniq -c | sort -rn | head -20)
    
    # Create summary content
    local summary_content="SASL Authentication Failure - Weekly Summary
Period: $start_date to $end_date

=== FAIL2BAN STATUS: $f2b_status

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
    printf "%-20s | %-15s | %-6s | %-8s | %-20s\n" "Timestamp" "IP Address" "Action" "Strike" "Jail"
    echo "------------------------------------------------------------------------------------------"
    tail -n +2 "$BAN_DB" | sort -r | while IFS='|' read -r timestamp ip jail action strike notified; do
        printf "%-20s | %-15s | %-6s | %-8s | %-20s\n" "$timestamp" "$ip" "$action" "$strike" "$jail"
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
        local unban_count=$(grep "|$ip|" "$BAN_DB" | grep "|unban|" | wc -l)
        echo "$ip ($ban_count bans, $unban_count unbans):"
        
        grep "|$ip|" "$BAN_DB" | while IFS='|' read -r timestamp ip_check jail action strike notified; do
            printf "  %-20s | %-6s | Strike %s | %-20s\n" "$timestamp" "$action" "$strike" "$jail"
        done
        echo
    done <<< "$ips"
}

report_current_bans() {
    echo "=== Currently Banned IPs ==="
    echo
    printf "%-15s | %-8s | %-20s | %-20s | %-10s\n" "IP Address" "Strike" "Jail" "Banned Since" "Duration"
    echo "----------------------------------------------------------------------------------------"
    
    # Get unique IPs
    local ips=$(tail -n +2 "$BAN_DB" | cut -d'|' -f2 | sort -u)
    
    while read -r ip; do
        [[ -z "$ip" ]] && continue
        
        # Get last ban and unban for each jail
        local first_ban=$(grep "|$ip|postfix-sasl-first|ban|" "$BAN_DB" | tail -1)
        local first_unban=$(grep "|$ip|postfix-sasl-first|unban|" "$BAN_DB" | tail -1)
        local second_ban=$(grep "|$ip|postfix-sasl-second|ban|" "$BAN_DB" | tail -1)
        local second_unban=$(grep "|$ip|postfix-sasl-second|unban|" "$BAN_DB" | tail -1)
        local third_ban=$(grep "|$ip|postfix-sasl-third|ban|" "$BAN_DB" | tail -1)
        local third_unban=$(grep "|$ip|postfix-sasl-third|unban|" "$BAN_DB" | tail -1)
        
        # Check each strike level
        if [[ -n "$third_ban" ]]; then
            local ban_time=$(echo "$third_ban" | cut -d'|' -f1)
            if [[ -n "$third_unban" ]]; then
                local unban_time=$(echo "$third_unban" | cut -d'|' -f1)
                if [[ "$ban_time" > "$unban_time" ]]; then
                    # Currently banned - find the original ban (first ban after last real unban or first ever)
                    local original_ban=$(grep "|$ip|postfix-sasl-third|ban|" "$BAN_DB" | head -1 | cut -d'|' -f1)
                    printf "%-15s | %-8s | %-20s | %-20s | %-10s\n" "$ip" "3" "postfix-sasl-third" "$original_ban" "32 days"
                    continue
                fi
            else
                # No unban record - use first ban time
                local original_ban=$(grep "|$ip|postfix-sasl-third|ban|" "$BAN_DB" | head -1 | cut -d'|' -f1)
                printf "%-15s | %-8s | %-20s | %-20s | %-10s\n" "$ip" "3" "postfix-sasl-third" "$original_ban" "32 days"
                continue
            fi
        fi
        
        if [[ -n "$second_ban" ]]; then
            local ban_time=$(echo "$second_ban" | cut -d'|' -f1)
            if [[ -n "$second_unban" ]]; then
                local unban_time=$(echo "$second_unban" | cut -d'|' -f1)
                if [[ "$ban_time" > "$unban_time" ]]; then
                    # Currently banned - find the original ban
                    local original_ban=$(grep "|$ip|postfix-sasl-second|ban|" "$BAN_DB" | head -1 | cut -d'|' -f1)
                    printf "%-15s | %-8s | %-20s | %-20s | %-10s\n" "$ip" "2" "postfix-sasl-second" "$original_ban" "8 days"
                    continue
                fi
            else
                # No unban record - use first ban time
                local original_ban=$(grep "|$ip|postfix-sasl-second|ban|" "$BAN_DB" | head -1 | cut -d'|' -f1)
                printf "%-15s | %-8s | %-20s | %-20s | %-10s\n" "$ip" "2" "postfix-sasl-second" "$original_ban" "8 days"
                continue
            fi
        fi
        
        if [[ -n "$first_ban" ]]; then
            local ban_time=$(echo "$first_ban" | cut -d'|' -f1)
            if [[ -n "$first_unban" ]]; then
                local unban_time=$(echo "$first_unban" | cut -d'|' -f1)
                if [[ "$ban_time" > "$unban_time" ]]; then
                    # Currently banned - find the original ban
                    local original_ban=$(grep "|$ip|postfix-sasl-first|ban|" "$BAN_DB" | head -1 | cut -d'|' -f1)
                    printf "%-15s | %-8s | %-20s | %-20s | %-10s\n" "$ip" "1" "postfix-sasl-first" "$original_ban" "48 hours"
                fi
            else
                # No unban record - use first ban time
                local original_ban=$(grep "|$ip|postfix-sasl-first|ban|" "$BAN_DB" | head -1 | cut -d'|' -f1)
                printf "%-15s | %-8s | %-20s | %-20s | %-10s\n" "$ip" "1" "postfix-sasl-first" "$original_ban" "48 hours"
            fi
        fi
    done <<< "$ips"
    
    echo
    echo "Note: Shows highest strike level for each IP currently banned"
}

report_active_bans() {
    if [[ "$HAS_SQLITE" != "true" ]]; then
        echo "Error: SQLite not available or fail2ban database not readable"
        echo "Falling back to tracker-based current report..."
        echo
        report_current_bans
        return
    fi
    
    echo "=== Active Bans from Fail2Ban Database ==="
    echo
    
    # Query fail2ban's authoritative ban data
    sqlite3 -header -column "$F2B_DB" <<EOF
SELECT 
    ip as 'IP Address',
    CASE 
        WHEN jail LIKE '%third%' THEN '3'
        WHEN jail LIKE '%second%' THEN '2'
        WHEN jail LIKE '%first%' THEN '1'
        ELSE '?'
    END as 'Strike',
    jail as 'Jail',
    datetime(timeofban,'unixepoch','localtime') as 'Banned Since',
    datetime(timeofban+bantime,'unixepoch','localtime') as 'Expires',
    CAST((bantime / 86400.0) AS INTEGER) || ' days' as 'Duration'
FROM bips 
WHERE datetime(timeofban+bantime,'unixepoch','localtime') > datetime('now','localtime')
ORDER BY 
    CASE 
        WHEN jail LIKE '%third%' THEN 1
        WHEN jail LIKE '%second%' THEN 2
        WHEN jail LIKE '%first%' THEN 3
        ELSE 4
    END,
    timeofban DESC;
EOF
    
    echo
    echo "Source: fail2ban SQLite database (authoritative)"
}

report_summary() {
    echo "=== Ban Tracking Statistics ==="
    echo
    echo "Database: $BAN_DB"
    echo "Total recorded bans: $(grep "|ban|" "$BAN_DB" | grep -v "|restore-ban|" | wc -l)"
    echo "Total recorded unbans: $(grep "|unban|" "$BAN_DB" | grep -v "|restore-unban|" | wc -l)"
    echo "Unique IPs: $(tail -n +2 "$BAN_DB" | cut -d'|' -f2 | sort -u | wc -l)"
    echo
    echo "Bans by strike level:"
    echo "  Strike 1: $(grep "|ban|1|" "$BAN_DB" | grep -v "|restore-ban|" | wc -l)"
    echo "  Strike 2: $(grep "|ban|2|" "$BAN_DB" | grep -v "|restore-ban|" | wc -l)"
    echo "  Strike 3: $(grep "|ban|3|" "$BAN_DB" | grep -v "|restore-ban|" | wc -l)"
    echo
    echo "Unbans by strike level:"
    echo "  Strike 1: $(grep "|unban|1|" "$BAN_DB" | grep -v "|restore-unban|" | wc -l)"
    echo "  Strike 2: $(grep "|unban|2|" "$BAN_DB" | grep -v "|restore-unban|" | wc -l)"
    echo "  Strike 3: $(grep "|unban|3|" "$BAN_DB" | grep -v "|restore-unban|" | wc -l)"
    echo
    echo "Restart events (excluded from counts above):"
    echo "  Restore-bans: $(grep "|restore-ban|" "$BAN_DB" | wc -l)"
    echo "  Restore-unbans: $(grep "|restore-unban|" "$BAN_DB" | wc -l)"
    echo
    echo "Recent activity (last 24h):"
    local yesterday=$(date -d '24 hours ago' '+%Y-%m-%d %H:%M:%S')
    local recent_bans=$(awk -F'|' -v date="$yesterday" '$1 > date && $4 == "ban"' "$BAN_DB" | wc -l)
    local recent_unbans=$(awk -F'|' -v date="$yesterday" '$1 > date && $4 == "unban"' "$BAN_DB" | wc -l)
    echo "  Bans in last 24h: $recent_bans"
    echo "  Unbans in last 24h: $recent_unbans"
    
    # Add fail2ban database stats if available
    if [[ "$HAS_SQLITE" == "true" ]]; then
        echo
        echo "Fail2Ban Database Statistics:"
        local f2b_active=$(sqlite3 "$F2B_DB" "SELECT COUNT(*) FROM bips WHERE jail LIKE 'postfix-sasl%' AND datetime(timeofban+bantime,'unixepoch','localtime') > datetime('now','localtime');")
        local f2b_total=$(sqlite3 "$F2B_DB" "SELECT COUNT(*) FROM bips WHERE jail LIKE 'postfix-sasl%';")
        echo "  Currently banned IPs: $f2b_active"
        echo "  Total persistent bans: $f2b_total"
    fi
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
        
    record-unban <ip> <jail>
        Record an unban event (called by fail2ban action)
        
    report --by-date
        Show all bans sorted by date (newest first)
        
    report --by-ip
        Show all bans grouped by IP address
        
    report --summary
        Show ban statistics summary
        
    report --current
        Show currently banned IPs from tracker database
        
    report --active
        Show active bans from fail2ban SQLite database (if available)
        Shows authoritative ban data directly from fail2ban
        
    daily-summary [--yesterday] [email] [date]
        Generate daily summary report
        - If no email: outputs to console
        - If no date: uses today
        - Use --yesterday for cron jobs that run at midnight
        
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

# Check if fail2ban SQLite database is available
F2B_DB="/var/lib/fail2ban/fail2ban.sqlite3"
HAS_SQLITE=false
if command -v sqlite3 >/dev/null 2>&1 && [[ -r "$F2B_DB" ]]; then
    HAS_SQLITE=true
fi

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
    record-unban)
        if [[ $# -lt 3 ]]; then
            echo "Usage: $0 record-unban <ip> <jail>"
            exit 1
        fi
        record_unban "$2" "$3"
        ;;
    process-pending)
        process_pending "${2:-}"
        ;;
    daily-summary)
        # Handle --yesterday flag for cron jobs that run at midnight
        if [[ "$2" == "--yesterday" ]]; then
            daily_summary "${3:-}" "$(date -d 'yesterday' '+%Y-%m-%d')"
        else
            daily_summary "${2:-}" "${3:-}"
        fi
        ;;
    weekly-summary)
        weekly_summary "${2:-}" "${3:-}"
        ;;
    report)
        case "$2" in
            --by-date) report_by_date ;;
            --by-ip) report_by_ip ;;
            --summary) report_summary ;;
            --current) report_current_bans ;;
            --active) report_active_bans ;;
            *)
                echo "Report options:"
                echo "  report --by-date    Show all bans sorted by date (newest first)"
                echo "  report --by-ip      Show all bans grouped by IP address"
                echo "  report --summary    Show ban statistics summary"
                echo "  report --current    Show currently banned IPs (from tracker)"
                if [[ "$HAS_SQLITE" == "true" ]]; then
                    echo "  report --active     Show active bans from fail2ban database"
                fi
                echo
                echo "Example: $0 report --current"
                echo
                echo "Use '$0 --help' for full documentation"
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