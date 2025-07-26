#!/bin/bash
# /usr/local/bin/monitor-bans.sh
# Monitor escalating ban system status

# Detect if running in a TTY
if [ -t 1 ]; then
    # Terminal - use emojis
    STRIKE1="🥊"
    STRIKE2="⚡"
    STRIKE3="💀"
    SUMMARY="📊"
    BANNED="🚫"
    HISTORY="🔍"
else
    # Non-TTY (email/cron) - use ASCII
    STRIKE1="[STRIKE 1]"
    STRIKE2="[STRIKE 2]"
    STRIKE3="[STRIKE 3]"
    SUMMARY="[SUMMARY]"
    BANNED="==="
    HISTORY="==="
fi

echo "=== POSTFIX SASL ESCALATING BAN SYSTEM ==="
echo "$(date)"
echo

echo "$STRIKE1 FIRST STRIKE (48 hours):"
sudo fail2ban-client status postfix-sasl-first 2>/dev/null | grep -E "(Currently banned|Total banned)" || echo "  Jail not active"
echo

echo "$STRIKE2 SECOND STRIKE (8 days):"  
sudo fail2ban-client status postfix-sasl-second 2>/dev/null | grep -E "(Currently banned|Total banned)" || echo "  Jail not active"
echo

echo "$STRIKE3 THIRD STRIKE (32 days):"
sudo fail2ban-client status postfix-sasl-third 2>/dev/null | grep -E "(Currently banned|Total banned)" || echo "  Jail not active"
echo

echo "$SUMMARY SUMMARY:"
FIRST=$(sudo fail2ban-client get postfix-sasl-first banip 2>/dev/null | wc -w)
SECOND=$(sudo fail2ban-client get postfix-sasl-second banip 2>/dev/null | wc -w)  
THIRD=$(sudo fail2ban-client get postfix-sasl-third banip 2>/dev/null | wc -w)
TOTAL=$((FIRST + SECOND + THIRD))

echo "  First Strike Bans:  $FIRST"
echo "  Second Strike Bans: $SECOND" 
echo "  Third Strike Bans:  $THIRD"
echo "  Total Active Bans:  $TOTAL"
echo

# Get banned IPs from each jail
FIRST_IPS=$(sudo fail2ban-client get postfix-sasl-first banip 2>/dev/null | tr -d '[]' | tr ' ' '\n' | sort)
SECOND_IPS=$(sudo fail2ban-client get postfix-sasl-second banip 2>/dev/null | tr -d '[]' | tr ' ' '\n' | sort)
THIRD_IPS=$(sudo fail2ban-client get postfix-sasl-third banip 2>/dev/null | tr -d '[]' | tr ' ' '\n' | sort)

# Show currently banned IPs by strike level
echo "$BANNED CURRENTLY BANNED IPs:"
echo

# Third strike IPs (most severe)
echo "$STRIKE3 Third Strike Only (32 days):"
if [ -z "$THIRD_IPS" ]; then
    echo "  None"
else
    echo "$THIRD_IPS" | sed 's/^/  /'
fi
echo

# Second strike IPs (excluding those in third)
echo "$STRIKE2 Second Strike Only (8 days):"
if [ -z "$SECOND_IPS" ]; then
    echo "  None"
else
    SECOND_ONLY=$(comm -23 <(echo "$SECOND_IPS") <(echo "$THIRD_IPS") 2>/dev/null)
    if [ -z "$SECOND_ONLY" ]; then
        echo "  None (all escalated to third strike)"
    else
        echo "$SECOND_ONLY" | sed 's/^/  /'
    fi
fi
echo

# First strike IPs (excluding those in second or third)
echo "$STRIKE1 First Strike Only (48 hours):"
if [ -z "$FIRST_IPS" ]; then
    echo "  None"
else
    FIRST_ONLY=$(comm -23 <(echo "$FIRST_IPS") <(echo "$SECOND_IPS") 2>/dev/null)
    if [ -z "$FIRST_ONLY" ]; then
        echo "  None (all escalated to higher strikes)"
    else
        echo "$FIRST_ONLY" | sed 's/^/  /'
    fi
fi
echo

echo "$HISTORY RECENT BAN HISTORY (last 24h):"
sudo grep -E "\[(postfix-sasl-(second|third))\] Ban" /var/log/fail2ban.log | tail -10 || echo "  No recent escalations"
