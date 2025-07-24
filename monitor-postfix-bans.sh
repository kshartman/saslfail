#!/bin/bash
# /usr/local/bin/monitor-bans.sh
# Monitor escalating ban system status

echo "=== POSTFIX SASL ESCALATING BAN SYSTEM ==="
echo "$(date)"
echo

echo "🥊 FIRST STRIKE (48 hours):"
sudo fail2ban-client status postfix-sasl-first 2>/dev/null | grep -E "(Currently banned|Total banned)" || echo "  Jail not active"
echo

echo "⚡ SECOND STRIKE (8 days):"  
sudo fail2ban-client status postfix-sasl-second 2>/dev/null | grep -E "(Currently banned|Total banned)" || echo "  Jail not active"
echo

echo "💀 THIRD STRIKE (32 days):"
sudo fail2ban-client status postfix-sasl-third 2>/dev/null | grep -E "(Currently banned|Total banned)" || echo "  Jail not active"
echo

echo "📊 SUMMARY:"
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
echo "🚫 CURRENTLY BANNED IPs:"
echo

# Third strike IPs (most severe)
echo "💀 Third Strike Only (32 days):"
if [ -z "$THIRD_IPS" ]; then
    echo "  None"
else
    echo "$THIRD_IPS" | sed 's/^/  /'
fi
echo

# Second strike IPs (excluding those in third)
echo "⚡ Second Strike Only (8 days):"
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
echo "🥊 First Strike Only (48 hours):"
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

echo "🔍 RECENT BAN HISTORY (last 24h):"
sudo grep -E "\[(postfix-sasl-(second|third))\] Ban" /var/log/fail2ban.log | tail -10 || echo "  No recent escalations"
