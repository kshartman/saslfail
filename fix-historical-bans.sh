#!/bin/bash
# Fix historical ban database to have correct strike counts
# Removes bogus Strike 2/3 entries caused by instant cascade and recidive bugs

BAN_DB="/var/lib/saslfail/bans.db"
BACKUP_DIR="/var/lib/saslfail/backups"
VERSION_FILE="/var/lib/saslfail/db_version"
TARGET_VERSION=2

# Get current version (default to 1 if no version file)
get_version() {
    if [[ -f "$VERSION_FILE" ]]; then
        cat "$VERSION_FILE"
    else
        echo "1"
    fi
}

set_version() {
    echo "$1" > "$VERSION_FILE"
}

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Fix the saslfail ban database to correct strike counts.

The old system had bugs:
- Instant cascade: All 3 strikes fired on every offense
- Recidive ghost: Strike 2/3 fired without actual new offenses
- Restart duplicates: fail2ban restarts created duplicate entries

This script:
1. Identifies REAL offenses (Strike 1 not preceded by unban within 60s)
2. Deletes ALL Strike 2/3 entries (all are bogus)
3. Re-assigns strike levels based on offense number:
   - Offense #1 → Strike 1
   - Offense #2 → Strike 2
   - Offense #3+ → Strike 3
4. Removes orphaned unbans (unbans with no matching ban for IP+strike)
5. Tags early unbans as restore-unban (restart events, not real expirations)

The script is idempotent - it tracks database version and only runs once.
Version 1 (or missing) = unfixed, Version 2 = fixed.

Options:
  --dry-run     Show what would be done without making changes
  --ip IP       Fix only specified IP (for testing)
  -h, --help    Show this help message

Examples:
  $(basename "$0") --dry-run              # Preview changes
  $(basename "$0") --dry-run --ip 1.2.3.4 # Preview for one IP
  $(basename "$0")                        # Apply fixes
EOF
    exit 0
}

DRY_RUN=false
SINGLE_IP=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --ip)
            SINGLE_IP="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            ;;
    esac
done

if [[ ! -f "$BAN_DB" ]]; then
    echo "Error: Database not found: $BAN_DB" >&2
    exit 1
fi

# Check version
CURRENT_VERSION=$(get_version)
if [[ "$CURRENT_VERSION" -ge "$TARGET_VERSION" ]]; then
    echo "Database already at version $CURRENT_VERSION (target: $TARGET_VERSION)"
    echo "No fix needed."
    exit 0
fi

echo "Database version: $CURRENT_VERSION → $TARGET_VERSION"
echo

# Create backup
if [[ "$DRY_RUN" == "false" ]]; then
    mkdir -p "$BACKUP_DIR"
    BACKUP_FILE="$BACKUP_DIR/bans.db.$(date +%Y%m%d-%H%M%S)"
    cp "$BAN_DB" "$BACKUP_FILE"
    echo "Backup created: $BACKUP_FILE"
    echo
fi

# Get list of IPs to process
if [[ -n "$SINGLE_IP" ]]; then
    IPS="$SINGLE_IP"
else
    IPS=$(awk -F'|' 'NR>1 {print $2}' "$BAN_DB" | sort -u)
fi

# Temporary file for new database
TEMP_DB=$(mktemp)
echo "timestamp|ip|jail|action|strike_level|notified" > "$TEMP_DB"

# Stats
total_ips=0
total_before_entries=0
total_after_entries=0
total_real_offenses=0
total_before_unbans=0
total_after_unbans=0

echo "=== Processing IPs ==="
echo

while read -r ip; do
    [[ -z "$ip" ]] && continue
    ((total_ips++))

    # Get all entries for this IP
    ip_entries=$(grep "|$ip|" "$BAN_DB")
    before_count=$(echo "$ip_entries" | grep -c "|ban|" || echo 0)
    ((total_before_entries += before_count))

    # Get all Strike 1 bans for this IP (sorted by time)
    strike1_bans=$(echo "$ip_entries" | grep "|postfix-sasl-first|ban|" | sort)

    # Get all unbans for Strike 1
    strike1_unbans=$(echo "$ip_entries" | grep "|postfix-sasl-first|unban|" | sort)

    # Find REAL offenses (Strike 1 ban NOT preceded by unban within 60 seconds)
    real_offenses=()

    while read -r banline; do
        [[ -z "$banline" ]] && continue
        ban_ts=$(echo "$banline" | cut -d"|" -f1)
        ban_epoch=$(date -d "$ban_ts" +%s 2>/dev/null) || continue

        # Check if there was an unban within 60 seconds before this ban
        is_restart=false
        while read -r uline; do
            [[ -z "$uline" ]] && continue
            u_ts=$(echo "$uline" | cut -d"|" -f1)
            u_epoch=$(date -d "$u_ts" +%s 2>/dev/null) || continue
            diff=$((ban_epoch - u_epoch))
            if [[ $diff -ge 0 && $diff -le 60 ]]; then
                is_restart=true
                break
            fi
        done <<< "$strike1_unbans"

        if [[ "$is_restart" == "false" ]]; then
            real_offenses+=("$banline")
        fi
    done <<< "$strike1_bans"

    offense_count=${#real_offenses[@]}
    ((total_real_offenses += offense_count))

    # Calculate new strike counts
    if [[ $offense_count -eq 0 ]]; then
        new_s1=0; new_s2=0; new_s3=0
    elif [[ $offense_count -eq 1 ]]; then
        new_s1=1; new_s2=0; new_s3=0
    elif [[ $offense_count -eq 2 ]]; then
        new_s1=1; new_s2=1; new_s3=0
    else
        new_s1=1; new_s2=1; new_s3=$((offense_count - 2))
    fi

    new_total=$((new_s1 + new_s2 + new_s3))
    ((total_after_entries += new_total))

    # Get old counts for comparison
    old_s1=$(echo "$ip_entries" | grep -c "|postfix-sasl-first|ban|" || echo 0)
    old_s2=$(echo "$ip_entries" | grep -c "|postfix-sasl-second|ban|" || echo 0)
    old_s3=$(echo "$ip_entries" | grep -c "|postfix-sasl-third|ban|" || echo 0)

    # Only show if there's a change
    if [[ "$old_s1" != "$new_s1" || "$old_s2" != "$new_s2" || "$old_s3" != "$new_s3" ]]; then
        printf "%-15s: offenses=%d  S1: %2d→%2d  S2: %2d→%2d  S3: %2d→%2d\n" \
            "$ip" "$offense_count" "$old_s1" "$new_s1" "$old_s2" "$new_s2" "$old_s3" "$new_s3"
    fi

    # Write corrected entries to temp database
    if [[ "$DRY_RUN" == "false" ]]; then
        offense_num=0
        for banline in "${real_offenses[@]}"; do
            ((offense_num++))
            ban_ts=$(echo "$banline" | cut -d"|" -f1)
            notified=$(echo "$banline" | cut -d"|" -f6)

            if [[ $offense_num -eq 1 ]]; then
                # First offense → Strike 1
                echo "$ban_ts|$ip|postfix-sasl-first|ban|1|$notified" >> "$TEMP_DB"
            elif [[ $offense_num -eq 2 ]]; then
                # Second offense → Strike 2
                echo "$ban_ts|$ip|postfix-sasl-second|ban|2|$notified" >> "$TEMP_DB"
            else
                # Third+ offense → Strike 3
                echo "$ban_ts|$ip|postfix-sasl-third|ban|3|$notified" >> "$TEMP_DB"
            fi
        done

        # Keep only unbans that have a matching ban, and tag as restore-unban if early
        # Ban durations: Strike 1=48h, Strike 2=8d, Strike 3=32d
        declare -A ban_durations=([1]=172800 [2]=691200 [3]=2764800)

        for strike in 1 2 3; do
            case $strike in
                1) jail="postfix-sasl-first" ;;
                2) jail="postfix-sasl-second" ;;
                3) jail="postfix-sasl-third" ;;
            esac

            # Only process unbans if we wrote a ban for this strike level
            ban_line=$(grep "|$ip|$jail|ban|" "$TEMP_DB" 2>/dev/null | tail -1)
            if [[ -n "$ban_line" ]]; then
                ban_ts_check=$(echo "$ban_line" | cut -d"|" -f1)
                ban_epoch_check=$(date -d "$ban_ts_check" +%s 2>/dev/null || echo 0)
                duration=${ban_durations[$strike]}

                # Process each unban for this IP+jail
                echo "$ip_entries" | grep "|$jail|unban|" | while read -r uline; do
                    [[ -z "$uline" ]] && continue
                    u_ts=$(echo "$uline" | cut -d"|" -f1)
                    u_epoch=$(date -d "$u_ts" +%s 2>/dev/null || echo 0)
                    u_notified=$(echo "$uline" | cut -d"|" -f6)
                    time_since_ban=$((u_epoch - ban_epoch_check))

                    # Tag as restore-unban if it occurred before ban expired
                    if [[ $time_since_ban -lt $duration ]] && [[ $time_since_ban -ge 0 ]]; then
                        echo "$u_ts|$ip|$jail|restore-unban|$strike|$u_notified" >> "$TEMP_DB"
                    elif [[ $u_epoch -gt $ban_epoch_check ]]; then
                        echo "$u_ts|$ip|$jail|unban|$strike|$u_notified" >> "$TEMP_DB"
                    fi
                done
            fi
        done
    fi

done <<< "$IPS"

echo
echo "=== Summary ==="
echo "IPs processed: $total_ips"
echo "Real offenses found: $total_real_offenses"
echo "Ban entries: $total_before_entries -> $total_after_entries"
total_before_unbans=$(grep -c "|unban|" "$BAN_DB" 2>/dev/null || echo 0)
if [[ "$DRY_RUN" == "false" ]]; then
    total_after_unbans=$(grep "|unban|" "$TEMP_DB" 2>/dev/null | grep -cv "|restore-unban|" || echo 0)
    total_restore_unbans=$(grep -c "|restore-unban|" "$TEMP_DB" 2>/dev/null || echo 0)
    echo "Unban entries: $total_before_unbans -> $total_after_unbans real + $total_restore_unbans restore"
fi
echo

if [[ "$DRY_RUN" == "true" ]]; then
    echo "(Dry run - no changes made)"
    rm -f "$TEMP_DB"
else
    # Sort by timestamp and replace original
    sort -t'|' -k1 "$TEMP_DB" > "$BAN_DB.new"

    # Add header back
    echo "timestamp|ip|jail|action|strike_level|notified" > "$BAN_DB"
    tail -n +2 "$BAN_DB.new" >> "$BAN_DB"

    rm -f "$TEMP_DB" "$BAN_DB.new"

    # Update version
    set_version "$TARGET_VERSION"

    echo "Database updated: $BAN_DB"
    echo "Version updated: $TARGET_VERSION"
    echo "Backup saved: $BACKUP_FILE"
fi
