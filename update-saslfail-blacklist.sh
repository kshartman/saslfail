#!/bin/bash
# Monthly update of saslfail permanent blacklist
# Run via cron to add persistent offenders to ipset blacklist

BLACKLIST_DIR="/etc/ipset-blacklist"
BLACKLIST_FILE="$BLACKLIST_DIR/ip-blacklist-saslfail.list"
DOC_PREFIX="blocked-sasl-abusers-"
TODAY=$(date '+%Y%m%d')

# Generate new IP list
/usr/local/bin/generate-blacklist.sh > "$BLACKLIST_FILE"
count=$(wc -l < "$BLACKLIST_FILE")
echo "Updated $BLACKLIST_FILE with $count IPs"

# Generate new documentation
/usr/local/bin/generate-blacklist.sh --format doc > "$BLACKLIST_DIR/${DOC_PREFIX}${TODAY}.md"
echo "Generated ${DOC_PREFIX}${TODAY}.md"

# Clean up old doc files, keep only the most recent
cd "$BLACKLIST_DIR"
ls -t ${DOC_PREFIX}*.md 2>/dev/null | tail -n +2 | xargs -r rm -f
echo "Cleaned up old documentation files"

# Reload ipset blacklist
/usr/local/sbin/update-blacklist.sh /etc/ipset-blacklist/ipset-blacklist.conf 2>&1 | tail -1
