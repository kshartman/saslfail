#!/bin/bash
# Script to remove duplicate ban entries from fail2ban restarts

DB_FILE="/var/lib/saslfail/bans.db"
BACKUP_FILE="/var/lib/saslfail/bans.db.backup-$(date +%Y%m%d-%H%M%S)"
TEMP_FILE="/var/lib/saslfail/bans.db.temp"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Check if database exists
if [[ ! -f "$DB_FILE" ]]; then
    echo "Database file not found: $DB_FILE"
    exit 1
fi

echo "Creating backup at: $BACKUP_FILE"
cp "$DB_FILE" "$BACKUP_FILE"

# Create header
head -1 "$DB_FILE" > "$TEMP_FILE"

# Process entries to remove duplicates within 60-second windows
echo "Processing entries to remove duplicates..."

# Use a simple approach that preserves the original format
declare -A last_seen
removed=0

tail -n +2 "$DB_FILE" | while IFS= read -r line; do
    # Parse the line
    timestamp=$(echo "$line" | cut -d'|' -f1)
    ip=$(echo "$line" | cut -d'|' -f2)
    jail=$(echo "$line" | cut -d'|' -f3)
    
    # Convert timestamp to epoch
    epoch=$(date -d "$timestamp" +%s 2>/dev/null || echo 0)
    
    # Create key for this IP/jail combination
    key="${ip}|${jail}"
    
    # Check if we've seen this recently
    if [[ -n "${last_seen[$key]}" ]]; then
        last_epoch="${last_seen[$key]}"
        time_diff=$((epoch - last_epoch))
        
        # Skip if within 60 seconds
        if [[ $time_diff -lt 60 ]] && [[ $time_diff -ge 0 ]]; then
            echo "  Removing duplicate: $timestamp $ip $jail (${time_diff}s after previous)"
            ((removed++))
            continue
        fi
    fi
    
    # Keep this entry - write the original line unchanged
    echo "$line" >> "$TEMP_FILE"
    
    # Update last seen time
    last_seen[$key]=$epoch
done

echo "Removed $removed duplicate entries"

# Count entries
ORIGINAL_COUNT=$(tail -n +2 "$DB_FILE" | wc -l)
NEW_COUNT=$(tail -n +2 "$TEMP_FILE" | wc -l)
REMOVED=$((ORIGINAL_COUNT - NEW_COUNT))

echo
echo "Original entries: $ORIGINAL_COUNT"
echo "New entries: $NEW_COUNT"
echo "Removed: $REMOVED duplicates"

if [[ $REMOVED -gt 0 ]]; then
    echo
    read -p "Replace database with cleaned version? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        mv "$TEMP_FILE" "$DB_FILE"
        echo "Database cleaned successfully!"
        echo "Backup saved at: $BACKUP_FILE"
    else
        rm "$TEMP_FILE"
        echo "Cleanup cancelled. No changes made."
    fi
else
    rm "$TEMP_FILE"
    echo "No duplicates found."
fi