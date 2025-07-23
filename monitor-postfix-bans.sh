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

echo "🔍 RECENT ESCALATIONS (last 24h):"
sudo grep -E "\[(postfix-sasl-(second|third))\] Ban" /var/log/fail2ban.log | tail -10 || echo "  No recent escalations"
