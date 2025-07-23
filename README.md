# Postfix SASL Escalating Ban System

A progressive fail2ban protection system for Postfix mail servers that escalates ban duration for repeat SASL authentication attackers.

## 🎯 How It Works

**Progressive Punishment System:**
- 🥊 **Strike 1**: First SASL auth failure → **48 hours** ban
- ⚡ **Strike 2**: Second offense → **8 days** ban  
- 💀 **Strike 3**: Third offense → **32 days** ban

## 📦 What Gets Installed

### Configuration Files
- `/etc/fail2ban/filter.d/postfix-sasl-strict.conf` - Main SASL failure detection
- `/etc/fail2ban/filter.d/postfix-sasl-recidive.conf` - Second strike detection
- `/etc/fail2ban/filter.d/postfix-sasl-recidive-third.conf` - Third strike detection
- `/etc/fail2ban/jail.d/postfix-sasl-escalating.conf` - Three-tier jail system

### Monitoring Tools
- `/usr/local/bin/monitor-postfix-bans.sh` - Real-time ban status monitoring
- Systemd timer for automated hourly monitoring

### Safety Features
- Automatic backup of existing configuration
- Configuration validation before deployment
- Easy uninstall with restoration capability

## 🚀 Quick Installation

### Clone and Install
```bash
# Clone the repository
git clone https://github.com/kshartman/saslfail.git
cd saslfail

# Run the installer
sudo ./install-postfix-escalating-bans.sh
```

### Alternative: Download Release
```bash
# Download the latest release
wget https://github.com/kshartman/saslfail/archive/refs/heads/main.zip
unzip main.zip
cd saslfail-main

# Run the installer
sudo ./install-postfix-escalating-bans.sh
```

The installer will:
1. ✅ Backup your existing fail2ban configuration
2. ✅ Optionally prompt for your email address for notifications
3. ✅ Install all required filters and jails
4. ✅ Test the configuration
5. ✅ Restart fail2ban
6. ✅ Verify all jails are active

## 📊 Monitoring Your System

### Check Ban Status
```bash
# Quick overview
monitor-postfix-bans.sh

# Detailed jail status
sudo fail2ban-client status postfix-sasl-first
sudo fail2ban-client status postfix-sasl-second
sudo fail2ban-client status postfix-sasl-third
```

### Watch Real-Time Activity
```bash
# Watch for new bans
sudo tail -f /var/log/fail2ban.log | grep "postfix-sasl"

# Check recent escalations
sudo journalctl -u postfix-ban-monitor
```

## 🛠️ Management Commands

### View Current Bans
```bash
# All current bans
sudo fail2ban-client status

# Specific jail bans
sudo fail2ban-client get postfix-sasl-first banip
```

### Manual Ban Management
```bash
# Manually ban an IP (first strike)
sudo fail2ban-client set postfix-sasl-first banip 1.2.3.4

# Unban an IP from all jails
sudo fail2ban-client set postfix-sasl-first unbanip 1.2.3.4
sudo fail2ban-client set postfix-sasl-second unbanip 1.2.3.4
sudo fail2ban-client set postfix-sasl-third unbanip 1.2.3.4
```

## 🔧 Configuration

### Email Notifications
Email notifications are optional and can be configured during installation:
- **If email provided**: Notifications sent for each escalation level
- **If no email**: Notification lines are commented out (disabled)

Notification subjects:
- First Strike: Standard ban notification
- Second Strike: "Second Strike Ban - 8 Days"
- Third Strike: "Third Strike Ban - 32 Days"

### Time Periods
| Strike | Duration | Find Time | Description |
|--------|----------|-----------|-------------|
| 1st | 48 hours | 24 hours | Initial authentication failure |
| 2nd | 8 days | 14 days | Gets banned again within 2 weeks |
| 3rd | 32 days | 32 days | Gets banned again within 32 days |

### Protected Ports
All jails protect these mail service ports:
- **25** (SMTP)
- **465** (SMTPS)
- **587** (Submission)

## 🚨 Troubleshooting

### Check Jail Status
```bash
# Verify all jails are running
sudo fail2ban-client status

# Check for errors
sudo journalctl -u fail2ban -n 50
```

### Test Filters
```bash
# Test main filter
sudo fail2ban-regex /var/log/mail.log /etc/fail2ban/filter.d/postfix-sasl-strict.conf

# Test recidive filters
sudo fail2ban-regex /var/log/fail2ban.log /etc/fail2ban/filter.d/postfix-sasl-recidive.conf
```

### Common Issues
1. **No matches found**: Check log file paths in jail configuration
2. **Jails not starting**: Verify filter syntax with `fail2ban-client -t`
3. **No escalations**: Ensure recidive filters are monitoring fail2ban.log

## 🗑️ Uninstallation

```bash
# From the cloned repository directory
sudo ./uninstall-postfix-escalating-bans.sh
```

The uninstaller will:
- Remove all escalating ban configurations
- Restore original configuration from backup
- Clear all existing bans
- Remove monitoring tools

## 📈 Expected Results

After installation, you'll see:
- Immediate protection against SASL brute force attacks
- Escalating punishment for persistent attackers
- Email notifications for ban events
- Hourly monitoring reports
- Significant reduction in authentication attempts

## 🔒 Security Features

- **Whitelist Protection**: Automatically excludes local networks
- **Multiple Log Sources**: Monitors mail.log, postfix.log, maillog
- **Persistent Bans**: Survive fail2ban restarts
- **Escalation Tracking**: Cross-references previous ban history
- **Email Alerts**: Real-time notification of security events

## 📝 Log Files

Key log locations:
- `/var/log/fail2ban.log` - fail2ban activity and escalations
- `/var/log/mail.log` - Postfix SASL authentication failures
- `/var/log/syslog` - System messages and errors

## 🤝 Support

For issues or questions:
1. Check fail2ban logs: `sudo tail -f /var/log/fail2ban.log`
2. Verify configuration: `sudo fail2ban-client -t`
3. Monitor system: `monitor-postfix-bans.sh`
4. Review jail status: `sudo fail2ban-client status`