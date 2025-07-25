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

# Process entries using awk to remove duplicates within 60-second windows
echo "Processing entries to remove duplicates..."

tail -n +2 "$DB_FILE" | awk -F'|' '
{
    # Create key from IP and jail
    key = $2 "|" $3
    
    # Convert timestamp to epoch (approximate)
    gsub(/[-:]/, " ", $1)
    cmd = "date -d \"" $1 "\" +%s 2>/dev/null"
    cmd | getline epoch
    close(cmd)
    
    # Check if we have seen this key recently
    if (key in last_seen) {
        time_diff = epoch - last_seen[key]
        if (time_diff < 60 && time_diff >= 0) {
            # Skip this duplicate
            print "  Removing duplicate:", $1, $2, $3, "(" time_diff "s after previous)"
            next
        }
    }
    
    # Record this entry
    print $0 >> "'"$TEMP_FILE"'"
    last_seen[key] = epoch
}'

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