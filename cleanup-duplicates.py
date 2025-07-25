#!/usr/bin/env python3
import sys
import os
import shutil
from datetime import datetime
from collections import defaultdict

DB_FILE = "/var/lib/saslfail/bans.db"

# Check if running as root
if os.geteuid() != 0:
    print("This script must be run as root")
    sys.exit(1)

# Check if database exists
if not os.path.exists(DB_FILE):
    print(f"Database file not found: {DB_FILE}")
    sys.exit(1)

# Create backup
backup_file = f"{DB_FILE}.backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
print(f"Creating backup at: {backup_file}")
shutil.copy2(DB_FILE, backup_file)

# Read all lines
with open(DB_FILE, 'r') as f:
    lines = f.readlines()

# Process entries
header = lines[0]
entries = lines[1:]
last_seen = {}
kept_entries = []
removed_count = 0

print("Processing entries to remove duplicates...")

for line in entries:
    line = line.strip()
    if not line:
        continue
    
    parts = line.split('|')
    if len(parts) < 6:
        continue
        
    timestamp_str = parts[0]
    ip = parts[1]
    jail = parts[2]
    
    # Parse timestamp
    try:
        timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
        epoch = timestamp.timestamp()
    except:
        # Keep malformed entries
        kept_entries.append(line + '\n')
        continue
    
    # Create key
    key = f"{ip}|{jail}"
    
    # Check if duplicate - we've seen this IP/jail combination before
    if key in last_seen:
        last_timestamp = last_seen[key]
        print(f"  Removing duplicate: {timestamp_str} {ip} {jail} (first seen at {last_timestamp})")
        removed_count += 1
        continue
    
    # Keep this entry (first occurrence)
    kept_entries.append(line + '\n')
    last_seen[key] = timestamp_str

print(f"\nOriginal entries: {len(entries)}")
print(f"New entries: {len(kept_entries)}")
print(f"Removed: {removed_count} duplicates")

if removed_count > 0:
    response = input("\nReplace database with cleaned version? (y/n): ")
    if response.lower() == 'y':
        with open(DB_FILE, 'w') as f:
            f.write(header)
            f.writelines(kept_entries)
        print("Database cleaned successfully!")
        print(f"Backup saved at: {backup_file}")
    else:
        print("Cleanup cancelled. No changes made.")
else:
    print("No duplicates found.")