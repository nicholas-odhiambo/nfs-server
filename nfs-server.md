### Manual Database Backup

**Priority Level**: HIGH
**Estimated Time**: 20 minutes
**Required Access**: Database user with backup privileges
**Risk Level**: MEDIUM

#### Description
Create manual database backup for MySQL/MariaDB and PostgreSQL with verification.

#### Prerequisites
- Database credentials with appropriate privileges
- Sufficient disk space for backup file
- Database not under heavy load (if possible)

#### Procedure
1. **Pre-backup Database Assessment**
   ```bash
   # Create backup directory with timestamp
   BACKUP_DATE=$(date +%Y-%m-%d_%H%M)
   BACKUP_DIR="/backup/db/manual_$BACKUP_DATE"
   sudo mkdir -p "$BACKUP_DIR"
   
   echo "=== Database Backup Assessment $(date) ==="
   echo "Backup will be stored in: $BACKUP_DIR"
   
   # Check available disk space
   df -h /backup
   
   # Estimate database sizes
   du -sh /var/lib/mysql 2>/dev/null || echo "MySQL data directory not found at standard location"
   du -sh /var/lib/postgresql 2>/dev/null || echo "PostgreSQL data directory not found at standard location"
   ```

2. **MySQL/MariaDB Backup**
   ```bash
   if command -v mysql >/dev/null 2>&1; then
     echo "=== MySQL/MariaDB Backup Process ==="
     
     # Check if MySQL is running
     if systemctl is-active --quiet mysql mysqld mariadb; then
       echo "MySQL service is running - proceeding with backup"
       
       # Get list of databases
       mysql -u backup_user -p -e "SHOW DATABASES;" > "$BACKUP_DIR/database_list.txt" 2>/dev/null
       
       # Individual database backups
       echo "Creating individual database backups..."
       mysql -u backup_user -p -e "SHOW DATABASES;" -s -N | grep -v -E '^(information_schema|performance_schema|mysql|sys)### Remove User Account

**Priority Level**: HIGH
**Estimated Time**: 20 minutes
**Required Access**: sudo
**Risk Level**: HIGH

#### Description
Safely remove user account while preserving or removing data as required by policy.

#### Prerequisites
- Written authorization for account removal
- Data retention policy requirements
- Manager/HR approval documentation
- Backup verification if data preservation required

#### Procedure
1. **Pre-removal Security Assessment**
   ```bash
   # Document current user status
   echo "=== User Removal Assessment for [username] $(date) ===" | sudo tee -a /var/log/user-management.log
   
   # Check current login sessions
   who | grep [username]
   w | grep [username]
   
   # Check for running processes
   ps -u [username] -o pid,ppid,cmd
   
   # Check crontab entries
   sudo crontab -u [username] -l 2>/dev/null || echo "No crontab found"
   
   # Find all files owned by user (limit search for performance)
   find /home /var /opt /usr/local -user [username] -type f 2>/dev/null | head -50
   
   # Check for active SSH sessions
   sudo lsof -u [username] | grep IPv
   
   # Check sudo privileges
   sudo -l -U [username] 2>/dev/null || echo "No sudo privileges"
   
   # Check group memberships
   groups [username]
   
   # Document findings
   echo "User [username] assessment completed - see above output" | sudo tee -a /var/log/user-management.log
   ```

2. **Account Lockdown (Immediate Security)**
   ```bash
   # Lock account immediately (prevents new logins)
   sudo usermod -L [username]
   sudo usermod -e 1 [username]  # Set account expiry to past date
   
   # Change shell to prevent login
   sudo usermod -s /bin/false [username]
   
   # Kill all user processes (be careful with this)
   sudo pkill -u [username]
   
   # Remove from sensitive groups
   sudo gpasswd -d [username] wheel 2>/dev/null || echo "Not in wheel group"
   sudo gpasswd -d [username] sudo 2>/dev/null || echo "Not in sudo group"
   sudo gpasswd -d [username] admin 2>/dev/null || echo "Not in admin group"
   
   # Remove SSH keys
   sudo rm -f /home/[username]/.ssh/authorized_keys
   
   echo "User [username] locked down at $(date)" | sudo tee -a /var/log/user-management.log
   ```

3. **Data Assessment and Backup**
   ```bash
   # Create backup directory
   sudo mkdir -p /backup/users/$(date +%Y-%m-%d)
   
   # Comprehensive file search and backup
   echo "=== Files owned by [username] ===" | sudo tee /backup/users/$(date +%Y-%m-%d)/[username]-files.txt
   find / -user [username] -type f 2>/dev/null | sudo tee -a /backup/users/$(date +%Y-%m-%d)/[username]-files.txt
   
   # Backup home directory
   sudo tar -czf /backup/users/$(date +%Y-%m-%d)/[username]-home.tar.gz /home/[username] 2>/dev/null
   
   # Backup user's cron jobs
   sudo crontab -u [username] -l > /backup/users/$(date +%Y-%m-%d)/[username]-crontab.txt 2>/dev/null || echo "No crontab" > /backup/users/$(date +%Y-%m-%d)/[username]-crontab.txt
   
   # Backup mail spool if exists
   if [ -f "/var/mail/[username]" ]; then
     sudo cp /var/mail/[username] /backup/users/$(date +%Y-%m-%d)/[username]-mail.txt
   fi
   
   # Create inventory of backed up data
   sudo ls -la /backup/users/$(date +%Y-%m-%d)/[username]* | sudo tee -a /var/log/user-management.log
   ```

4. **Account Removal**
   ```bash
   # Final process check and kill
   sudo pkill -9 -u [username] 2>/dev/null || echo "No processes running"
   
   # Remove user account (keeping home directory initially)
   sudo userdel [username]
   
   # Or remove user and home directory if policy allows
   # sudo userdel -r [username]
   
   # Remove from all groups (cleanup)
   sudo deluser [username] --remove-all-files 2>/dev/null || echo "User already removed from groups"
   
   # Clean up mail spool
   sudo rm -f /var/mail/[username]
   
   # Remove any leftover cron jobs
   sudo rm -f /var/spool/cron/crontabs/[username]
   sudo rm -f /var/spool/cron/[username]
   
   # Remove from passwd/shadow if somehow still there
   sudo grep -v "^[username]:" /etc/passwd > /tmp/passwd.tmp && sudo mv /tmp/passwd.tmp /etc/passwd
   sudo grep -v "^[username]:" /etc/shadow > /tmp/shadow.tmp && sudo mv /tmp/shadow.tmp /etc/shadow
   ```

5. **Post-removal Cleanup**
   ```bash
   # Handle home directory based on policy
   if [ "$KEEP_HOME" = "yes" ]; then
     # Rename and secure home directory
     sudo mv /home/[username] /home/[username].removed.$(date +%Y%m%d)
     sudo chmod 700 /home/[username].removed.$(date +%Y%m%d)
   else
     # Remove home directory after verification backup exists
     if [ -f "/backup/users/$(date +%Y-%m-%d)/[username]-home.tar.gz" ]; then
       sudo rm -rf /home/[username]
       echo "Home directory removed after backup verification" | sudo tee -a /var/log/user-management.log
     else
       echo "ERROR: Backup not found, home directory preserved" | sudo tee -a /var/log/user-management.log
     fi
   fi
   
   # Clean up application-specific data
   # Database user removal (customize for your databases)
   mysql -u root -p -e "DROP USER IF EXISTS '[username]'@'localhost';" 2>/dev/null || echo "No MySQL user found"
   
   # Web directory cleanup
   sudo rm -rf /var/www/html/~[username]
   
   # Log completion
   echo "User [username] removal completed at $(date) by $(whoami)" | sudo tee -a /var/log/user-management.log
   ```

#### Verification
```bash
# Comprehensive removal verification
echo "=== User Removal Verification ==="
echo "User in passwd: $(grep "^[username]:" /etc/passwd || echo "NOT FOUND - GOOD")"
echo "User in shadow: $(sudo grep "^[username]:" /etc/shadow || echo "NOT FOUND - GOOD")"
echo "Home directory: $(ls -ld /home/[username] 2>/dev/null || echo "NOT FOUND")"
echo "Running processes: $(ps -u [username] 2>/dev/null || echo "NONE - GOOD")"
echo "Cron jobs: $(sudo crontab -u [username] -l 2>/dev/null || echo "NONE - GOOD")"
echo "Mail spool: $(ls -l /var/mail/[username] 2>/dev/null || echo "NOT FOUND - GOOD")"
echo "Backup created: $(ls -l /backup/users/$(date +%Y-%m-%d)/[username]* 2>/dev/null || echo "NO BACKUP FOUND")"
```

#### Rollback
If removal was premature and needs to be reversed:
```bash
# Restore from backup (if within same day)
if [ -f "/backup/users/$(date +%Y-%m-%d)/[username]-home.tar.gz" ]; then
  # Recreate user account
  sudo useradd -m -s /bin/bash [username]
  
  # Restore home directory
  sudo tar -xzf /backup/users/$(date +%Y-%m-%d)/[username]-home.tar.gz -C /
  sudo chown -R [username]:[username] /home/[username]
  
  # Restore crontab if existed
  if [ -f "/backup/users/$(date +%Y-%m-%d)/[username]-crontab.txt" ] && [ -s "/backup/users/$(date +%Y-%m-%d)/[username]-crontab.txt" ]; then
    sudo crontab -u [username] /backup/users/$(date +%Y-%m-%d)/[username]-crontab.txt
  fi
  
  # Restore mail spool
  if [ -f "/backup/users/$(date +%Y-%m-%d)/[username]-mail.txt" ]; then
    sudo cp /backup/users/$(date +%Y-%m-%d)/[username]-mail.txt /var/mail/[username]
    sudo chown [username]:mail /var/mail/[username]
  fi
  
  echo "User [username] restored from backup" | sudo tee -a /var/log/user-management.log
else
  echo "ERROR: No backup found for today's date"
fi
```

### User Access Audit

**Priority Level**: MEDIUM
**Estimated Time**: 30 minutes
**Required Access**: sudo
**Risk Level**: LOW

#### Description
Comprehensive audit of user accounts, permissions, and access patterns for security compliance.

#### Prerequisites
- List of expected active users
- Company organizational chart/user list
- Previous audit report for comparison

#### Procedure
1. **Active User Inventory**
   ```bash
   # Create audit directory
   sudo mkdir -p /var/log/audit/$(date +%Y-%m)
   AUDIT_DIR="/var/log/audit/$(date +%Y-%m)"
   
   # Generate user list with details
   echo "=== User Account Audit $(date) ===" | sudo tee $AUDIT_DIR/user-audit.txt
   echo "Generated by: $(whoami)" | sudo tee -a $AUDIT_DIR/user-audit.txt
   echo "========================================" | sudo tee -a $AUDIT_DIR/user-audit.txt
   
   # All users with login shells
   echo "=== Users with Login Shells ===" | sudo tee -a $AUDIT_DIR/user-audit.txt
   getent passwd | awk -F: '$7 !~ /(nologin|false)/ {print $1 ":" $3 ":" $5 ":" $6 ":" $7}' | sudo tee -a $AUDIT_DIR/user-audit.txt
   
   # Users with UID 0 (root privileges)
   echo -e "\n=== Users with UID 0 (Root Privileges) ===" | sudo tee -a $AUDIT_DIR/user-audit.txt
   getent passwd | awk -F: '$3 == 0 {print $1}' | sudo tee -a $AUDIT_DIR/user-audit.txt
   
   # Users with sudo access
   echo -e "\n=== Users with Sudo Access ===" | sudo tee -a $AUDIT_DIR/user-audit.txt
   getent group wheel sudo admin 2>/dev/null | cut -d: -f4 | tr ',' '\n' | sort -u | sudo tee -a $AUDIT_DIR/user-audit.txt
   ```

2. **Login Activity Analysis**
   ```bash
   # Recent login activity
   echo -e "\n=== Recent Login Activity (Last 30 Days) ===" | sudo tee -a $AUDIT_DIR/user-audit.txt
   last -30 | head -50 | sudo tee -a $AUDIT_DIR/user-audit.txt
   
   # Failed login attempts
   echo -e "\n=== Failed Login Attempts ===" | sudo tee -a $AUDIT_DIR/user-audit.txt
   lastb | head -20 | sudo tee -a $AUDIT_DIR/user-audit.txt
   
   # Users who haven't logged in recently (30+ days)
   echo -e "\n=== Inactive Users (30+ days) ===" | sudo tee -a $AUDIT_DIR/user-audit.txt
   for user in $(getent passwd | awk -F: '$7 !~ /(nologin|false)/ {print $1}'); do
     last_login=$(last -1 $user | head -1 | awk '{print $4, $5, $6}')
     if [ -z "$last_login" ] || [ "$last_login" = "begins" ]; then
       echo "$user: Never logged in" | sudo tee -a $AUDIT_DIR/user-audit.txt
     else
       # Check if login is older than 30 days (simplified check)
       echo "$user: $last_login" | sudo tee -a $AUDIT_DIR/user-audit.txt
     fi
   done
   ```

3. **Permission and Group Analysis**
   ```bash
   # Group memberships for all users
   echo -e "\n=== Group Memberships ===" | sudo tee -a $AUDIT_DIR/user-audit.txt
   for user in $(getent passwd | awk -F: '$3 >= 1000 {print $1}'); do
     echo "$user: $(groups $user 2>/dev/null | cut -d: -f2)" | sudo tee -a $AUDIT_DIR/user-audit.txt
   done
   
   # SSH key analysis
   echo -e "\n=== SSH Key Analysis ===" | sudo tee -a $AUDIT_DIR/user-audit.txt
   for user in $(getent passwd | awk -F: '$3 >= 1000 {print $1}'); do
     if [ -f "/home/$user/.ssh/authorized_keys" ]; then
       key_count=$(wc -l < /home/$user/.ssh/authorized_keys)
       echo "$user: $key_count SSH key(s)" | sudo tee -a $AUDIT_DIR/user-audit.txt
       # Show key fingerprints
       ssh-keygen -l -f /home/$user/.ssh/authorized_keys 2>/dev/null | sed "s/^/  /" | sudo tee -a $AUDIT_DIR/user-audit.txt
     else
       echo "$user: No SSH keys" | sudo tee -a $AUDIT_DIR/user-audit.txt
     fi
   done
   ```

4. **Password Policy Compliance**
   ```bash
   # Password aging information
   echo -e "\n=== Password Aging Policy Compliance ===" | sudo tee -a $AUDIT_DIR/user-audit.txt
   for user in $(getent passwd | awk -F: '$3 >= 1000 {print $1}'); do
     echo "User: $user" | sudo tee -a $AUDIT_DIR/user-audit.txt
     sudo chage -l $user | grep -E "(Last password change|Password expires|Password inactive|Account expires)" | sed 's/^/  /' | sudo tee -a $AUDIT_DIR/user-audit.txt
     echo "" | sudo tee -a $AUDIT_DIR/user-audit.txt
   done
   ```

5. **Security Risk Assessment**
   ```bash
   # Accounts with empty passwords
   echo -e "\n=== Security Risk Assessment ===" | sudo tee -a $AUDIT_DIR/user-audit.txt
   echo "Users with empty passwords:" | sudo tee -a $AUDIT_DIR/user-audit.txt
   sudo awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow | sudo tee -a $AUDIT_DIR/user-audit.txt
   
   # Locked accounts
   echo -e "\nLocked accounts:" | sudo tee -a $AUDIT_DIR/user-audit.txt
   sudo awk -F: '$2 ~ /^\!/ {print $1}' /etc/shadow | sudo tee -a $AUDIT_DIR/user-audit.txt
   
   # Accounts with old passwords (90+ days)
   echo -e "\nAccounts with passwords older than 90 days:" | sudo tee -a $AUDIT_DIR/user-audit.txt
   for user in $(getent passwd | awk -F: '$3 >= 1000 {print $1}'); do
     last_change=$(sudo chage -l $user | grep "Last password change" | cut -d: -f2 | xargs)
     if [ "$last_change" != "never" ]; then
       # This is a simplified check - in production you'd want more sophisticated date comparison
       echo "$user: $last_change" | sudo tee -a $AUDIT_DIR/user-audit.txt
     fi
   done
   ```

#### Verification
- Audit report generated successfully
- All expected active users accounted for
- No unauthorized accounts found
- Password policies being enforced

#### Notes
- Schedule monthly automated runs
- Compare with previous audit reports
- Flag any discrepancies for investigation
- Use for compliance reporting# Linux System Administrator Playbook

## Table of Contents

1. [Playbook Structure & Usage](#playbook-structure--usage)
2. [Monitoring](#monitoring)
3. [User Management](#user-management)
4. [Backup Operations](#backup-operations)
5. [Networking](#networking)
6. [Security](#security)
7. [System Maintenance](#system-maintenance)
8. [Troubleshooting](#troubleshooting)
9. [Emergency Procedures](#emergency-procedures)
10. [Templates](#templates)

---

## Playbook Structure & Usage

### Standard Procedure Format

Each procedure follows this template:

```
## [PROCEDURE NAME]

**Priority Level**: [LOW/MEDIUM/HIGH/CRITICAL]
**Estimated Time**: [X minutes]
**Required Access**: [sudo/root/specific user]
**Risk Level**: [LOW/MEDIUM/HIGH]

### Description
Brief description of what this procedure accomplishes.

### Prerequisites
- System requirements
- Required permissions
- Dependencies

### Procedure
1. Step-by-step instructions
2. Include expected outputs
3. Note any confirmations needed

### Verification
How to confirm the procedure worked correctly.

### Rollback (if applicable)
Steps to undo changes if something goes wrong.

### Notes
- Distribution-specific variations
- Common issues and solutions
- Related procedures
```

---

## Monitoring

### System Health Check

**Priority Level**: MEDIUM
**Estimated Time**: 10 minutes
**Required Access**: sudo
**Risk Level**: LOW

#### Description
Comprehensive system health assessment covering CPU, memory, disk, and services.

#### Prerequisites
- SSH access to target system
- sudo privileges

#### Procedure
1. **CPU and Load Check**
   ```bash
   # Check current load
   uptime
   
   # Detailed CPU info
   top -n 1 | head -20
   
   # CPU usage by core
   mpstat -P ALL 1 1
   
   # I/O wait analysis
   iostat -x 1 3
   
   # Check for high CPU processes
   ps aux --sort=-%cpu | head -10
   ```

2. **Memory Assessment**
   ```bash
   # Memory usage overview
   free -h
   
   # Detailed memory breakdown
   cat /proc/meminfo | grep -E "(MemTotal|MemFree|MemAvailable|Cached|Buffers|SwapTotal|SwapFree)"
   
   # Top memory consumers
   ps aux --sort=-%mem | head -10
   
   # Check for memory leaks
   vmstat 1 5
   
   # OOM killer activity
   dmesg | grep -i "killed process"
   ```

3. **Disk Space Analysis**
   ```bash
   # Filesystem usage
   df -h
   
   # Inode usage (important for systems with many small files)
   df -i
   
   # Largest directories in root
   du -xh / | sort -hr | head -20 2>/dev/null
   
   # Find large files (>100MB)
   find / -type f -size +100M -exec ls -lh {} \; 2>/dev/null | head -10
   
   # Check disk I/O
   iostat -x 1 3
   
   # Identify busy filesystems
   iotop -a -o -d 3 | head -20
   ```

4. **Service Status**
   ```bash
   # Critical services check (customize list)
   CRITICAL_SERVICES=("sshd" "httpd" "nginx" "mysqld" "postgresql" "network")
   for service in "${CRITICAL_SERVICES[@]}"; do
     systemctl is-active $service 2>/dev/null && echo "$service: RUNNING" || echo "$service: NOT RUNNING"
   done
   
   # Failed services
   systemctl --failed
   
   # Services in degraded state
   systemctl status | grep -E "degraded|failed"
   
   # Check service startup times
   systemd-analyze blame | head -10
   ```

5. **Network Status**
   ```bash
   # Network interface status
   ip link show
   
   # Active connections
   netstat -tuln | head -20
   
   # Network statistics
   cat /proc/net/dev
   
   # DNS resolution test
   dig google.com +short
   ```

#### Verification
- Load average should be reasonable for your hardware (rule of thumb: under number of CPUs)
- Memory usage under 80% (adjust threshold as needed)
- No filesystems over 85% full
- All critical services running
- Network interfaces up and functional

#### Notes
- Customize service list for your environment
- Set up monitoring thresholds based on your baseline
- Consider scripting this for regular execution

### Performance Baseline Collection

**Priority Level**: MEDIUM
**Estimated Time**: 30 minutes
**Required Access**: sudo
**Risk Level**: LOW

#### Description
Collect comprehensive performance baseline data for future comparison.

#### Prerequisites
- System during normal operating conditions
- sysstat package installed (sar, iostat, mpstat)

#### Procedure
1. **Install Required Tools** (if not present)
   ```bash
   # RHEL/CentOS
   sudo yum install sysstat iotop htop -y
   
   # Ubuntu/Debian
   sudo apt-get install sysstat iotop htop -y
   ```

2. **CPU Baseline**
   ```bash
   # Collect 5-minute CPU baseline
   echo "=== CPU Baseline $(date) ===" >> /var/log/performance-baseline.log
   sar -u 60 5 >> /var/log/performance-baseline.log
   
   # Per-CPU statistics
   mpstat -P ALL 60 5 >> /var/log/performance-baseline.log
   ```

3. **Memory Baseline**
   ```bash
   echo "=== Memory Baseline $(date) ===" >> /var/log/performance-baseline.log
   sar -r 60 5 >> /var/log/performance-baseline.log
   sar -S 60 5 >> /var/log/performance-baseline.log
   ```

4. **Disk I/O Baseline**
   ```bash
   echo "=== Disk I/O Baseline $(date) ===" >> /var/log/performance-baseline.log
   iostat -x 60 5 >> /var/log/performance-baseline.log
   
   # Per-device statistics
   sar -d 60 5 >> /var/log/performance-baseline.log
   ```

5. **Network Baseline**
   ```bash
   echo "=== Network Baseline $(date) ===" >> /var/log/performance-baseline.log
   sar -n DEV 60 5 >> /var/log/performance-baseline.log
   ```

#### Verification
- Baseline file created with comprehensive data
- No anomalous readings during baseline collection

### Log Analysis Quick Check

**Priority Level**: HIGH
**Estimated Time**: 5 minutes
**Required Access**: sudo
**Risk Level**: LOW

#### Description
Quick scan of system logs for critical issues, errors, and security events.

#### Procedure
1. **System Log Review**
   ```bash
   # Recent critical/error messages
   journalctl -p err -n 50
   
   # Authentication failures (last 24 hours)
   journalctl -u ssh --since "24 hours ago" | grep -i "failed\|invalid" | tail -20
   
   # Kernel messages
   dmesg | tail -20
   
   # Last 20 logins
   last -20
   
   # Failed login attempts
   lastb -20
   
   # Check for segfaults
   journalctl --since "24 hours ago" | grep -i segfault
   ```

2. **Application Logs** (customize paths)
   ```bash
   # Web server errors
   tail -50 /var/log/httpd/error_log 2>/dev/null || tail -50 /var/log/nginx/error.log 2>/dev/null || echo "No web server logs found"
   
   # Mail logs
   tail -20 /var/log/maillog 2>/dev/null || tail -20 /var/log/mail.log 2>/dev/null || echo "No mail logs found"
   
   # Database errors (MySQL/MariaDB)
   tail -20 /var/log/mysqld.log 2>/dev/null || tail -20 /var/log/mysql/error.log 2>/dev/null || echo "No MySQL logs found"
   
   # System messages
   tail -30 /var/log/messages 2>/dev/null || tail -30 /var/log/syslog 2>/dev/null
   ```

3. **Security Event Analysis**
   ```bash
   # sudo usage
   grep "sudo:" /var/log/auth.log /var/log/secure 2>/dev/null | tail -10
   
   # Root login attempts
   grep "root" /var/log/auth.log /var/log/secure 2>/dev/null | grep -E "Failed|Invalid" | tail -10
   
   # SELinux denials (if applicable)
   ausearch -m avc --start recent 2>/dev/null | tail -10
   
   # Firewall drops (if using iptables logging)
   grep "DROP" /var/log/messages /var/log/kern.log 2>/dev/null | tail -10
   ```

#### Verification
- No recurring error patterns
- No suspicious login attempts
- Application logs show normal operation
- Security events within expected parameters

### Service Monitoring Setup

**Priority Level**: MEDIUM
**Estimated Time**: 20 minutes
**Required Access**: sudo
**Risk Level**: MEDIUM

#### Description
Set up basic service monitoring with email notifications for critical services.

#### Prerequisites
- Mail system configured (sendmail, postfix, etc.)
- List of critical services to monitor

#### Procedure
1. **Create Service Monitor Script**
   ```bash
   sudo tee /usr/local/bin/service-monitor.sh > /dev/null << 'EOF'
   #!/bin/bash
   
   # Configuration
   SERVICES=("sshd" "httpd" "nginx" "mysqld" "postgresql" "network")
   EMAIL_ADMIN="admin@your-domain.com"
   HOSTNAME=$(hostname)
   LOGFILE="/var/log/service-monitor.log"
   
   # Function to log messages
   log_message() {
       echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> $LOGFILE
   }
   
   # Function to send alert email
   send_alert() {
       local service=$1
       local status=$2
       echo "Service Alert: $service on $HOSTNAME is $status" | mail -s "ALERT: $service $status on $HOSTNAME" $EMAIL_ADMIN
       log_message "ALERT: $service is $status - email sent to $EMAIL_ADMIN"
   }
   
   # Check each service
   for service in "${SERVICES[@]}"; do
       if systemctl is-active --quiet $service; then
           log_message "OK: $service is running"
       else
           log_message "CRITICAL: $service is not running"
           send_alert $service "NOT RUNNING"
           
           # Attempt to restart service
           if systemctl start $service; then
               log_message "INFO: Successfully restarted $service"
               send_alert $service "RESTARTED"
           else
               log_message "ERROR: Failed to restart $service"
               send_alert $service "RESTART FAILED"
           fi
       fi
   done
   EOF
   
   sudo chmod +x /usr/local/bin/service-monitor.sh
   ```

2. **Create Cron Job**
   ```bash
   # Add to root crontab (runs every 5 minutes)
   (crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/service-monitor.sh") | sudo crontab -
   ```

3. **Test the Monitor**
   ```bash
   # Run manually to test
   sudo /usr/local/bin/service-monitor.sh
   
   # Check log output
   sudo tail -20 /var/log/service-monitor.log
   ```

#### Verification
- Script executes without errors
- Log entries created properly
- Email notifications sent (test by stopping a non-critical service)

#### Rollback
```bash
# Remove cron job
sudo crontab -l | grep -v service-monitor.sh | sudo crontab -

# Remove script
sudo rm /usr/local/bin/service-monitor.sh /var/log/service-monitor.log
```

---

## User Management

### Add New User Account

**Priority Level**: MEDIUM
**Estimated Time**: 15 minutes
**Required Access**: sudo
**Risk Level**: MEDIUM

#### Description
Create new user account with proper home directory, shell, security settings, and documentation.

#### Prerequisites
- Confirm user request approval in ticket system
- Determine required group memberships
- Password policy requirements
- SSH key from user (if using key-based auth)

#### Procedure
1. **Pre-creation Checks**
   ```bash
   # Verify username doesn't exist
   id [username] 2>/dev/null && echo "User exists!" || echo "Username available"
   
   # Check for existing home directory
   ls -la /home/ | grep [username]
   
   # Verify group requirements exist
   for group in wheel developers; do
     getent group $group || echo "Group $group doesn't exist"
   done
   ```

2. **Create User Account**
   ```bash
   # Create user with home directory and bash shell
   sudo useradd -m -s /bin/bash -c "Full Name - Department" [username]
   
   # Set password expiration policy (example: 90 days)
   sudo chage -M 90 -W 7 [username]
   
   # Set initial password (user must change on first login)
   sudo passwd [username]
   sudo chage -d 0 [username]  # Force password change on first login
   
   # Add to additional groups
   sudo usermod -a -G wheel,developers [username]
   ```

3. **Set Up Home Directory and Permissions**
   ```bash
   # Verify home directory creation and ownership
   ls -la /home/[username]
   
   # Set proper permissions (750 for security)
   sudo chmod 750 /home/[username]
   sudo chown [username]:[username] /home/[username]
   
   # Create .ssh directory if using SSH keys
   sudo mkdir /home/[username]/.ssh
   sudo chmod 700 /home/[username]/.ssh
   sudo chown [username]:[username] /home/[username]/.ssh
   
   # Set up authorized_keys if SSH key provided
   if [ -n "$SSH_KEY" ]; then
     echo "$SSH_KEY" | sudo tee /home/[username]/.ssh/authorized_keys
     sudo chmod 600 /home/[username]/.ssh/authorized_keys
     sudo chown [username]:[username] /home/[username]/.ssh/authorized_keys
   fi
   ```

4. **Configure Shell Environment**
   ```bash
   # Ensure skeleton files are copied
   sudo cp /etc/skel/.* /home/[username]/ 2>/dev/null
   
   # Set proper ownership for all files
   sudo chown -R [username]:[username] /home/[username]
   
   # Create custom .bashrc additions if needed
   sudo tee -a /home/[username]/.bashrc > /dev/null << 'EOF'
   
   # Custom environment settings
   export EDITOR=vim
   export HISTSIZE=10000
   export HISTFILESIZE=20000
   EOF
   
   sudo chown [username]:[username] /home/[username]/.bashrc
   ```

5. **Security and Compliance Setup**
   ```bash
   # Set up user-specific sudo rules if needed
   echo "[username] ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart myapp" | sudo tee /etc/sudoers.d/[username]
   
   # Add to security groups if required
   sudo usermod -a -G security-audit [username] 2>/dev/null || echo "security-audit group not found"
   
   # Log user creation
   echo "$(date '+%Y-%m-%d %H:%M:%S') - User [username] created by $(whoami)" | sudo tee -a /var/log/user-management.log
   ```

#### Verification
```bash
# Comprehensive user verification
echo "=== User Account Verification ==="
echo "User ID: $(id [username])"
echo "Groups: $(groups [username])"
echo "Home directory: $(ls -ld /home/[username])"
echo "Shell: $(getent passwd [username] | cut -d: -f7)"
echo "Password expiry: $(chage -l [username] | grep 'Password expires')"
echo "Last login: $(lastlog -u [username])"

# Test sudo access (if applicable)
sudo -u [username] sudo -l

# Test SSH key authentication (if configured)
ssh -i /path/to/private/key [username]@localhost "echo 'SSH key auth working'"
```

#### Documentation
```bash
# Update user database/documentation
echo "Username: [username]
Full Name: [Full Name]
Department: [Department] 
Created: $(date)
Created by: $(whoami)
Groups: $(groups [username])
SSH Key: [Yes/No]
Special Access: [List any special permissions]
Ticket: [Ticket number]
---" | sudo tee -a /var/log/user-database.txt
```

#### Notes
- Always document user creation with ticket reference
- Consider implementing user provisioning automation
- Review password complexity requirements
- Set up user monitoring if required by compliance

### Bulk User Management

**Priority Level**: MEDIUM
**Estimated Time**: 30 minutes
**Required Access**: sudo
**Risk Level**: HIGH

#### Description
Create multiple user accounts from a CSV file with consistent settings.

#### Prerequisites
- CSV file with user data (username,full_name,department,groups)
- Approved bulk user request
- SSH keys for users (if applicable)

#### Procedure
1. **Prepare User Data File**
   ```bash
   # Create sample CSV format
   cat > /tmp/new_users.csv << 'EOF'
   username,full_name,department,groups
   jdoe,John Doe,Engineering,wheel:developers
   msmith,Mary Smith,Marketing,users
   bwilson,Bob Wilson,IT,wheel:sysadmin
   EOF
   ```

2. **Create Bulk User Script**
   ```bash
   sudo tee /usr/local/bin/bulk-user-create.sh > /dev/null << 'EOF'
   #!/bin/bash
   
   CSV_FILE="$1"
   LOG_FILE="/var/log/bulk-user-creation.log"
   
   if [ -z "$CSV_FILE" ] || [ ! -f "$CSV_FILE" ]; then
       echo "Usage: $0 <csv_file>"
       exit 1
   fi
   
   echo "=== Bulk User Creation Started $(date) ===" >> $LOG_FILE
   
   # Skip header line
   tail -n +2 "$CSV_FILE" | while IFS=',' read -r username full_name department groups; do
       echo "Processing user: $username" | tee -a $LOG_FILE
       
       # Check if user exists
       if id "$username" &>/dev/null; then
           echo "  WARNING: User $username already exists" | tee -a $LOG_FILE
           continue
       fi
       
       # Create user
       if useradd -m -s /bin/bash -c "$full_name - $department" "$username"; then
           echo "  SUCCESS: Created user $username" | tee -a $LOG_FILE
           
           # Set password expiration
           chage -M 90 -W 7 "$username"
           chage -d 0 "$username"  # Force password change
           
           # Add to groups
           if [ -n "$groups" ]; then
               IFS=':' read -ra GROUP_ARRAY <<< "$groups"
               for group in "${GROUP_ARRAY[@]}"; do
                   if getent group "$group" > /dev/null; then
                       usermod -a -G "$group" "$username"
                       echo "    Added to group: $group" | tee -a $LOG_FILE
                   else
                       echo "    WARNING: Group $group does not exist" | tee -a $LOG_FILE
                   fi
               done
           fi
           
           # Set home directory permissions
           chmod 750 "/home/$username"
           chown "$username:$username" "/home/$username"
           
           echo "  COMPLETED: User $username setup finished" | tee -a $LOG_FILE
       else
           echo "  ERROR: Failed to create user $username" | tee -a $LOG_FILE
       fi
   done
   
   echo "=== Bulk User Creation Completed $(date) ===" >> $LOG_FILE
   EOF
   
   sudo chmod +x /usr/local/bin/bulk-user-create.sh
   ```

3. **Execute Bulk Creation**
   ```bash
   # Run the bulk creation script
   sudo /usr/local/bin/bulk-user-create.sh /tmp/new_users.csv
   
   # Review results
   tail -50 /var/log/bulk-user-creation.log
   ```

#### Verification
```bash
# Verify all users were created
while IFS=',' read -r username rest; do
  [ "$username" = "username" ] && continue  # Skip header
  echo "Checking $username: $(id $username 2>/dev/null && echo "EXISTS" || echo "MISSING")"
done < /tmp/new_users.csv
```

### Remove User Account

**Priority Level**: HIGH
**Estimated Time**: 10 minutes
**Required Access**: sudo
**Risk Level**: HIGH

#### Description
Safely remove user account while preserving or removing data as required.

#### Prerequisites
- Confirm removal authorization
- Determine data retention requirements
- Check for running processes

#### Procedure
1. **Pre-removal Assessment**
   ```bash
   # Check for running processes
   ps -u [username]
   
   # Check crontab entries
   sudo crontab -u [username] -l
   
   # Find files owned by user
   find / -user [username] -ls 2>/dev/null
   ```

2. **Account Removal**
   ```bash
   # Kill user processes if running
   sudo pkill -u [username]
   
   # Remove user (keep home directory for backup)
   sudo userdel [username]
   
   # Or remove user and home directory
   # sudo userdel -r [username]
   ```

3. **Cleanup Tasks**
   ```bash
   # Remove from additional groups if needed
   sudo gpasswd -d [username] [groupname]
   
   # Check mail spool
   sudo rm -f /var/mail/[username]
   
   # Archive home directory if keeping
   sudo tar -czf /backup/users/[username]-$(date +%Y%m%d).tar.gz /home/[username]
   sudo rm -rf /home/[username]
   ```

#### Verification
- User cannot log in
- No processes running under user account
- Home directory handled according to policy
- User removed from all groups

#### Rollback
If removal was premature:
```bash
# Restore from backup if available
sudo tar -xzf /backup/users/[username]-[date].tar.gz -C /
sudo useradd [username]
sudo usermod [username] -d /home/[username]
```

---

## Backup Operations

## Backup Operations

### System Backup Verification

**Priority Level**: CRITICAL
**Estimated Time**: 15 minutes
**Required Access**: sudo
**Risk Level**: LOW

#### Description
Verify backup systems are functioning and recent backups are valid and restorable.

#### Prerequisites
- Knowledge of backup system configuration
- Access to backup storage locations
- Backup verification tools available

#### Procedure
1. **Check Backup Service Status**
   ```bash
   # Check backup service/daemon status
   systemctl status backup-service bacula-fd amanda rsync 2>/dev/null || echo "Standard backup services not found"
   
   # Check custom backup scripts in cron
   crontab -l | grep -i backup
   sudo crontab -l | grep -i backup
   
   # Review recent backup logs
   echo "=== Recent Backup Logs ==="
   sudo find /var/log -name "*backup*" -type f -exec tail -10 {} \; -print
   sudo journalctl -u backup* --since "24 hours ago" | tail -20
   ```

2. **Verify Recent Backups Existence**
   ```bash
   # Common backup locations (customize for your environment)
   BACKUP_LOCATIONS=(
     "/backup/daily"
     "/backup/weekly" 
     "/backup/monthly"
     "/var/backups"
     "/mnt/backup"
   )
   
   echo "=== Backup Location Analysis ==="
   for location in "${BACKUP_LOCATIONS[@]}"; do
     if [ -d "$location" ]; then
       echo "Location: $location"
       echo "  Latest files:"
       ls -lht "$location" | head -5
       echo "  Disk usage:"
       du -sh "$location"
       echo "  File count:"
       find "$location" -type f | wc -l
       echo "---"
     else
       echo "Location $location not found"
     fi
   done
   ```

3. **Backup Size and Integrity Analysis**
   ```bash
   # Find recent backup files (last 7 days)
   echo "=== Recent Backup Files (Last 7 Days) ==="
   find /backup /var/backups /mnt/backup -type f -name "*.tar.gz" -o -name "*.tar.bz2" -o -name "*.zip" -mtime -7 2>/dev/null | while read backup_file; do
     echo "File: $backup_file"
     echo "  Size: $(ls -lh "$backup_file" | awk '{print $5}')"
     echo "  Date: $(ls -l "$backup_file" | awk '{print $6, $7, $8}')"
     
     # Basic integrity check
     case "$backup_file" in
       *.tar.gz)
         if tar -tzf "$backup_file" >/dev/null 2>&1; then
           echo "  Integrity: OK (tar.gz)"
         else
           echo "  Integrity: FAILED (tar.gz)"
         fi
         ;;
       *.tar.bz2)
         if tar -tjf "$backup_file" >/dev/null 2>&1; then
           echo "  Integrity: OK (tar.bz2)"
         else
           echo "  Integrity: FAILED (tar.bz2)"
         fi
         ;;
       *.zip)
         if unzip -t "$backup_file" >/dev/null 2>&1; then
           echo "  Integrity: OK (zip)"
         else
           echo "  Integrity: FAILED (zip)"
         fi
         ;;
     esac
     echo "---"
   done
   ```

4. **Test Restore Process**
   ```bash
   # Create test restore directory
   TEST_RESTORE_DIR="/tmp/restore-test-$(date +%s)"
   mkdir -p "$TEST_RESTORE_DIR"
   
   echo "=== Backup Restore Test ==="
   # Find the most recent backup
   LATEST_BACKUP=$(find /backup -name "*.tar.gz" -type f -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2-)
   
   if [ -n "$LATEST_BACKUP" ]; then
     echo "Testing restore from: $LATEST_BACKUP"
     
     # Extract sample files to test directory
     if tar -xzf "$LATEST_BACKUP" -C "$TEST_RESTORE_DIR" --wildcards "*/etc/passwd" "*/etc/hostname" "*/etc/fstab" 2>/dev/null; then
       echo "Sample file extraction: SUCCESS"
       echo "Extracted files:"
       find "$TEST_RESTORE_DIR" -type f -exec ls -l {} \;
     else
       echo "Sample file extraction: FAILED"
     fi
     
     # Cleanup test directory
     rm -rf "$TEST_RESTORE_DIR"
   else
     echo "No .tar.gz backup files found for testing"
   fi
   ```

5. **Database Backup Verification**
   ```bash
   echo "=== Database Backup Verification ==="
   
   # MySQL/MariaDB backup check
   if command -v mysql >/dev/null 2>&1; then
     echo "MySQL/MariaDB backups:"
     find /backup -name "*.sql" -o -name "*mysql*" -type f -mtime -7 2>/dev/null | while read sql_backup; do
       echo "  File: $sql_backup"
       echo "  Size: $(ls -lh "$sql_backup" | awk '{print $5}')"
       # Basic SQL file validation
       if head -5 "$sql_backup" | grep -q "MySQL dump\|MariaDB dump\|CREATE\|INSERT"; then
         echo "  Validity: Appears to be valid SQL dump"
       else
         echo "  Validity: May not be valid SQL dump"
       fi
       echo "---"
     done
   fi
   
   # PostgreSQL backup check
   if command -v psql >/dev/null 2>&1; then
     echo "PostgreSQL backups:"
     find /backup -name "*postgres*" -o -name "*pg_dump*" -type f -mtime -7 2>/dev/null | while read pg_backup; do
       echo "  File: $pg_backup"
       echo "  Size: $(ls -lh "$pg_backup" | awk '{print $5}')"
       echo "---"
     done
   fi
   ```

#### Verification
- Backup services running without errors
- Recent backups present and reasonable size
- Sample restore successful
- Database backups valid and recent

#### Alert Conditions
```bash
# Create backup verification alerts
if [ ! -f "/backup/daily/$(date +%Y-%m-%d)*" ]; then
  echo "ALERT: No daily backup found for today" | mail -s "Backup Alert" admin@company.com
fi

# Check backup age (shouldn't be older than 25 hours for daily backups)
find /backup/daily -name "*.tar.gz" -mtime +1 -exec echo "ALERT: Backup older than 24 hours found: {}" \;
```

### Manual System Backup

**Priority Level**: HIGH
**Estimated Time**: 45 minutes
**Required Access**: sudo
**Risk Level**: MEDIUM

#### Description
Create comprehensive manual backup of critical system files and data.

#### Prerequisites
- Sufficient disk space for backup (check with df -h)
- Backup destination mounted and writable
- System in stable state (no major operations running)

#### Procedure
1. **Pre-backup System Check**
   ```bash
   # Check system resources before backup
   echo "=== Pre-backup System Check $(date) ==="
   echo "Available disk space:"
   df -h
   echo "System load:"
   uptime
   echo "Memory usage:"
   free -h
   echo "Running processes:"
   ps aux | wc -l
   ```

2. **Critical System Files Backup**
   ```bash
   # Create backup directory with timestamp
   BACKUP_DATE=$(date +%Y-%m-%d_%H%M)
   BACKUP_DIR="/backup/manual/system_$BACKUP_DATE"
   sudo mkdir -p "$BACKUP_DIR"
   
   echo "Creating system backup in: $BACKUP_DIR"
   
   # Backup critical system configuration
   sudo tar -czf "$BACKUP_DIR/system-config.tar.gz" \
     --exclude=/etc/shadow- \
     --exclude=/etc/passwd- \
     /etc \
     /boot/grub* \
     /var/spool/cron \
     /usr/local/etc 2>/dev/null
   
   # Backup package lists
   if command -v rpm >/dev/null 2>&1; then
     rpm -qa > "$BACKUP_DIR/installed-packages-rpm.txt"
   fi
   
   if command -v dpkg >/dev/null 2>&1; then
     dpkg -l > "$BACKUP_DIR/installed-packages-dpkg.txt"
   fi
   
   # Backup network configuration
   sudo cp -r /etc/sysconfig/network-scripts "$BACKUP_DIR/" 2>/dev/null || echo "Network scripts not found (not RHEL/CentOS)"
   sudo cp -r /etc/network "$BACKUP_DIR/" 2>/dev/null || echo "Network config not found (not Debian/Ubuntu)"
   
   # Backup firewall rules
   sudo iptables-save > "$BACKUP_DIR/iptables-rules.txt" 2>/dev/null
   sudo firewall-cmd --list-all-zones > "$BACKUP_DIR/firewalld-rules.txt" 2>/dev/null || echo "Firewalld not active"
   ```

3. **User Data Backup**
   ```bash
   # Backup all home directories (excluding large cache files)
   sudo tar -czf "$BACKUP_DIR/home-directories.tar.gz" \
     --exclude='*/.cache' \
     --exclude='*/.local/share/Trash' \
     --exclude='*/Downloads' \
     --exclude='*/.mozilla/firefox/*/Cache*' \
     --exclude='*/.thunderbird/*/ImapMail' \
     /home 2>/dev/null
   
   # Backup web content (if applicable)
   if [ -d "/var/www" ]; then
     sudo tar -czf "$BACKUP_DIR/web-content.tar.gz" /var/www
   fi
   
   # Backup mail spools
   if [ -d "/var/mail" ]; then
     sudo tar -czf "$BACKUP_DIR/mail-spools.tar.gz" /var/mail
   fi
   ```

4. **Application Data Backup**
   ```bash
   # Backup log files (last 30 days only to save space)
   sudo find /var/log -name "*.log" -mtime -30 -exec tar -czf "$BACKUP_DIR/recent-logs.tar.gz" {} +
   
   # Application-specific backups
   # Add your specific applications here
   
   # Example: Apache/Nginx configurations
   if [ -d "/etc/httpd" ]; then
     sudo tar -czf "$BACKUP_DIR/apache-config.tar.gz" /etc/httpd
   fi
   if [ -d "/etc/nginx" ]; then
     sudo tar -czf "$BACKUP_DIR/nginx-config.tar.gz" /etc/nginx
   fi
   
   # Example: SSH configurations and keys
   sudo tar -czf "$BACKUP_DIR/ssh-config.tar.gz" /etc/ssh
   ```

5. **System Metadata Backup**
   ```bash
   # Collect system information
   echo "=== System Information ===" > "$BACKUP_DIR/system-info.txt"
   uname -a >> "$BACKUP_DIR/system-info.txt"
   cat /etc/os-release >> "$BACKUP_DIR/system-info.txt"
   
   # Hardware information
   echo "=== Hardware Info ===" >> "$BACKUP_DIR/system-info.txt"
   lscpu >> "$BACKUP_DIR/system-info.txt"
   free -h >> "$BACKUP_DIR/system-info.txt"
   lsblk >> "$BACKUP_DIR/system-info.txt"
   
   # Network configuration
   echo "=== Network Configuration ===" >> "$BACKUP_DIR/system-info.txt"
   ip addr >> "$BACKUP_DIR/system-info.txt"
   ip route >> "$BACKUP_DIR/system-info.txt"
   
   # Mounted filesystems
   echo "=== Mounted Filesystems ===" >> "$BACKUP_DIR/system-info.txt"
   mount >> "$BACKUP_DIR/system-info.txt"
   cat /etc/fstab >> "$BACKUP_DIR/system-info.txt"
   
   # Services status
   echo "=== Services Status ===" >> "$BACKUP_DIR/system-info.txt"
   systemctl list-unit-files --type=service | grep enabled >> "$BACKUP_DIR/system-info.txt"
   ```

6. **Backup Verification and Documentation**
   ```bash
   # Create backup manifest
   echo "=== Backup Manifest ===" > "$BACKUP_DIR/backup-manifest.txt"
   echo "Backup Date: $(date)" >> "$BACKUP_DIR/backup-manifest.txt"
   echo "Backup Created By: $(whoami)" >> "$BACKUP_DIR/backup-manifest.txt"
   echo "System: $(hostname)" >> "$BACKUP_DIR/backup-manifest.txt"
   echo "Contents:" >> "$BACKUP_DIR/backup-manifest.txt"
   
   # List all backup files with sizes
   ls -lh "$BACKUP_DIR"/* >> "$BACKUP_DIR/backup-manifest.txt"
   
   # Calculate total backup size
   TOTAL_SIZE=$(du -sh "$BACKUP_DIR" | awk '{print $1}')
   echo "Total Backup Size: $TOTAL_SIZE" >> "$BACKUP_DIR/backup-manifest.txt"
   
   # Test backup integrity
   echo "=== Backup Integrity Check ===" >> "$BACKUP_DIR/backup-manifest.txt"
   for tarfile in "$BACKUP_DIR"/*.tar.gz; do
     if [ -f "$tarfile" ]; then
       if tar -tzf "$tarfile" >/dev/null 2>&1; then
         echo "$(basename "$tarfile"): INTEGRITY OK" >> "$BACKUP_DIR/backup-manifest.txt"
       else
         echo "$(basename "$tarfile"): INTEGRITY FAILED" >> "$BACKUP_DIR/backup-manifest.txt"
       fi
     fi
   done
   
   # Set proper permissions on backup directory
   sudo chmod -R 600 "$BACKUP_DIR"
   sudo chown -R root:root "$BACKUP_DIR"
   
   echo "Manual backup completed: $BACKUP_DIR"
   echo "Total size: $TOTAL_SIZE"
   ```

#### Verification
- All backup files created successfully
- Backup integrity checks passed
- Backup manifest created
- Total backup size reasonable for available storage

#### Notes
- Customize excluded directories based on your environment
- Consider encrypting sensitive backups
- Document backup location in disaster recovery plan
- Schedule regular cleanup of old manual backups

### Manual Database Backup

**Priority Level**: HIGH
**Estimated Time**: 10 minutes
**Required Access**: Database user with backup privileges
**Risk Level**: MEDIUM

#### Description
Create manual database backup for MySQL/MariaDB.

#### Prerequisites
- Database credentials with appropriate privileges
- Sufficient disk space for backup file

#### Procedure
1. **MySQL/MariaDB Backup**
   ```bash
   # Single database backup
   mysqldump -u backup_user -p database_name > /backup/db/database_name_$(date +%Y%m%d_%H%M).sql
   
   # All databases backup
   mysqldump -u backup_user -p --all-databases > /backup/db/all_databases_$(date +%Y%m%d_%H%M).sql
   
   # Compress backup
   gzip /backup/db/database_name_$(date +%Y%m%d_%H%M).sql
   ```

2. **PostgreSQL Backup**
   ```bash
   # Single database
   pg_dump -U backup_user database_name > /backup/db/database_name_$(date +%Y%m%d_%H%M).sql
   
   # All databases
   pg_dumpall -U postgres > /backup/db/all_databases_$(date +%Y%m%d_%H%M).sql
   ```

#### Verification
- Backup file created and non-zero size
- Backup file readable and not corrupted
- Test restore in development environment if critical

---

## Networking

### Network Connectivity Troubleshooting

**Priority Level**: HIGH
**Estimated Time**: 10 minutes
**Required Access**: sudo for some commands
**Risk Level**: LOW

#### Description
Systematic approach to diagnosing network connectivity issues.

#### Procedure
1. **Basic Connectivity Tests**
   ```bash
   # Check network interfaces
   ip addr show
   
   # Check routing table
   ip route show
   
   # Test local connectivity
   ping -c 4 127.0.0.1
   
   # Test gateway connectivity
   ping -c 4 $(ip route | grep default | awk '{print $3}')
   
   # Test DNS resolution
   nslookup google.com
   dig google.com
   ```

2. **Port and Service Testing**
   ```bash
   # Check listening ports
   netstat -tlnp
   # or using ss
   ss -tlnp
   
   # Test specific port connectivity
   telnet target_host 80
   # or using nc
   nc -zv target_host 80
   ```

3. **Firewall and Security Check**
   ```bash
   # Check iptables rules
   sudo iptables -L -n
   
   # Check firewalld status (RHEL/CentOS)
   sudo firewall-cmd --state
   sudo firewall-cmd --list-all
   
   # Check ufw status (Ubuntu)
   sudo ufw status verbose
   ```

#### Verification
- All network interfaces have expected IP addresses
- Default gateway reachable
- DNS resolution working
- Required ports accessible

---

## Templates

### Incident Response Template

```markdown
# Incident Report: [INCIDENT-YYYY-MM-DD-###]

**Date/Time**: 
**Reported By**: 
**Severity**: [LOW/MEDIUM/HIGH/CRITICAL]
**Status**: [OPEN/IN-PROGRESS/RESOLVED/CLOSED]

## Summary
Brief description of the incident

## Timeline
- **HH:MM** - Initial detection/report
- **HH:MM** - Investigation started
- **HH:MM** - Root cause identified
- **HH:MM** - Resolution implemented
- **HH:MM** - System restored

## Impact
- Systems affected:
- Users affected:
- Services affected:
- Business impact:

## Root Cause
Detailed explanation of what caused the incident

## Resolution
Steps taken to resolve the incident

## Prevention
Actions to prevent recurrence

## Lessons Learned
What we learned from this incident
```

### Change Request Template

```markdown
# Change Request: [CR-YYYY-MM-DD-###]

**Requested By**: 
**Date**: 
**Priority**: [LOW/MEDIUM/HIGH/EMERGENCY]
**Risk Level**: [LOW/MEDIUM/HIGH]

## Change Description
What needs to be changed and why

## Systems Affected
List of systems that will be impacted

## Implementation Plan
Step-by-step plan for implementing the change

## Rollback Plan
How to undo the change if problems occur

## Testing Plan
How to verify the change was successful

## Maintenance Window
Proposed date/time and duration

## Approvals
- [ ] Technical Lead
- [ ] Manager
- [ ] Security (if required)
```

---

## Quick Reference Commands

### System Information
```bash
# System info
uname -a
cat /etc/os-release
uptime
who
w
```

### Process Management
```bash
# Process monitoring
ps aux
top
htop
pgrep [process_name]
pkill [process_name]
```

### Disk Operations
```bash
# Disk usage
df -h
du -sh *
lsblk
fdisk -l
```

### Network Commands
```bash
# Network info
ip addr
ip route
netstat -tuln
ss -tuln
```

### Service Management (systemd)
```bash
systemctl status [service]
systemctl start [service]
systemctl stop [service]
systemctl restart [service]
systemctl enable [service]
systemctl disable [service]
```

---

## Maintenance Schedule

### Daily Tasks
- [ ] Check system alerts
- [ ] Review critical logs
- [ ] Verify backup completion
- [ ] Monitor disk space

### Weekly Tasks
- [ ] System updates review
- [ ] Security patch assessment
- [ ] Performance trend analysis
- [ ] Backup restoration test

### Monthly Tasks
- [ ] User access review
- [ ] Security audit
- [ ] Capacity planning review
- [ ] Documentation updates

---

*Last Updated: [DATE]*
*Version: 1.0*
*Maintained By: [YOUR NAME]* | while read database; do
         echo "Backing up database: $database"
         mysqldump -u backup_user -p --single-transaction --routines --triggers --events \
           "$database" > "$BACKUP_DIR/${database}_$(date +%Y%m%d_%H%M).sql"
         
         # Compress the backup
         gzip "$BACKUP_DIR/${database}_$(date +%Y%m%d_%H%M).sql"
         
         # Verify backup was created
         if [ -f "$BACKUP_DIR/${database}_$(date +%Y%m%d_%H%M).sql.gz" ]; then
           backup_size=$(ls -lh "$BACKUP_DIR/${database}_$(date +%Y%m%d_%H%M).sql.gz" | awk '{print $5}')
           echo "  ✓ $database backup created: $backup_size"
         else
           echo "  ✗ $database backup failed"
         fi
       done
       
       # Full backup (all databases)
       echo "Creating full database backup..."
       mysqldump -u backup_user -p --single-transaction --routines --triggers --events \
         --all-databases > "$BACKUP_DIR/all_databases_$(date +%Y%m%d_%H%M).sql"
       
       # Compress full backup
       gzip "$BACKUP_DIR/all_databases_$(date +%Y%m%d_%H%M).sql"
       
       # Backup MySQL configuration
       sudo cp /etc/my.cnf "$BACKUP_DIR/" 2>/dev/null || sudo cp /etc/mysql/my.cnf "$BACKUP_DIR/" 2>/dev/null || echo "MySQL config not found in standard locations"
       
       # Record MySQL version and settings
       mysql -u backup_user -p -e "SELECT VERSION();" > "$BACKUP_DIR/mysql_version.txt" 2>/dev/null
       mysql -u backup_user -p -e "SHOW VARIABLES;" > "$BACKUP_DIR/mysql_variables.txt" 2>/dev/null
       
     else
       echo "MySQL service is not running - skipping MySQL backup"
     fi
   else
     echo "MySQL not installed - skipping MySQL backup"
   fi
   ```

3. **PostgreSQL Backup**
   ```bash
   if command -v psql >/dev/null 2>&1; then
     echo "=== PostgreSQL Backup Process ==="
     
     # Check### Remove User Account

**Priority Level**: HIGH
**Estimated Time**: 20 minutes
**Required Access**: sudo
**Risk Level**: HIGH

#### Description
Safely remove user account while preserving or removing data as required by policy.

#### Prerequisites
- Written authorization for account removal
- Data retention policy requirements
- Manager/HR approval documentation
- Backup verification if data preservation required

#### Procedure
1. **Pre-removal Security Assessment**
   ```bash
   # Document current user status
   echo "=== User Removal Assessment for [username] $(date) ===" | sudo tee -a /var/log/user-management.log
   
   # Check current login sessions
   who | grep [username]
   w | grep [username]
   
   # Check for running processes
   ps -u [username] -o pid,ppid,cmd
   
   # Check crontab entries
   sudo crontab -u [username] -l 2>/dev/null || echo "No crontab found"
   
   # Find all files owned by user (limit search for performance)
   find /home /var /opt /usr/local -user [username] -type f 2>/dev/null | head -50
   
   # Check for active SSH sessions
   sudo lsof -u [username] | grep IPv
   
   # Check sudo privileges
   sudo -l -U [username] 2>/dev/null || echo "No sudo privileges"
   
   # Check group memberships
   groups [username]
   
   # Document findings
   echo "User [username] assessment completed - see above output" | sudo tee -a /var/log/user-management.log
   ```

2. **Account Lockdown (Immediate Security)**
   ```bash
   # Lock account immediately (prevents new logins)
   sudo usermod -L [username]
   sudo usermod -e 1 [username]  # Set account expiry to past date
   
   # Change shell to prevent login
   sudo usermod -s /bin/false [username]
   
   # Kill all user processes (be careful with this)
   sudo pkill -u [username]
   
   # Remove from sensitive groups
   sudo gpasswd -d [username] wheel 2>/dev/null || echo "Not in wheel group"
   sudo gpasswd -d [username] sudo 2>/dev/null || echo "Not in sudo group"
   sudo gpasswd -d [username] admin 2>/dev/null || echo "Not in admin group"
   
   # Remove SSH keys
   sudo rm -f /home/[username]/.ssh/authorized_keys
   
   echo "User [username] locked down at $(date)" | sudo tee -a /var/log/user-management.log
   ```

3. **Data Assessment and Backup**
   ```bash
   # Create backup directory
   sudo mkdir -p /backup/users/$(date +%Y-%m-%d)
   
   # Comprehensive file search and backup
   echo "=== Files owned by [username] ===" | sudo tee /backup/users/$(date +%Y-%m-%d)/[username]-files.txt
   find / -user [username] -type f 2>/dev/null | sudo tee -a /backup/users/$(date +%Y-%m-%d)/[username]-files.txt
   
   # Backup home directory
   sudo tar -czf /backup/users/$(date +%Y-%m-%d)/[username]-home.tar.gz /home/[username] 2>/dev/null
   
   # Backup user's cron jobs
   sudo crontab -u [username] -l > /backup/users/$(date +%Y-%m-%d)/[username]-crontab.txt 2>/dev/null || echo "No crontab" > /backup/users/$(date +%Y-%m-%d)/[username]-crontab.txt
   
   # Backup mail spool if exists
   if [ -f "/var/mail/[username]" ]; then
     sudo cp /var/mail/[username] /backup/users/$(date +%Y-%m-%d)/[username]-mail.txt
   fi
   
   # Create inventory of backed up data
   sudo ls -la /backup/users/$(date +%Y-%m-%d)/[username]* | sudo tee -a /var/log/user-management.log
   ```

4. **Account Removal**
   ```bash
   # Final process check and kill
   sudo pkill -9 -u [username] 2>/dev/null || echo "No processes running"
   
   # Remove user account (keeping home directory initially)
   sudo userdel [username]
   
   # Or remove user and home directory if policy allows
   # sudo userdel -r [username]
   
   # Remove from all groups (cleanup)
   sudo deluser [username] --remove-all-files 2>/dev/null || echo "User already removed from groups"
   
   # Clean up mail spool
   sudo rm -f /var/mail/[username]
   
   # Remove any leftover cron jobs
   sudo rm -f /var/spool/cron/crontabs/[username]
   sudo rm -f /var/spool/cron/[username]
   
   # Remove from passwd/shadow if somehow still there
   sudo grep -v "^[username]:" /etc/passwd > /tmp/passwd.tmp && sudo mv /tmp/passwd.tmp /etc/passwd
   sudo grep -v "^[username]:" /etc/shadow > /tmp/shadow.tmp && sudo mv /tmp/shadow.tmp /etc/shadow
   ```

5. **Post-removal Cleanup**
   ```bash
   # Handle home directory based on policy
   if [ "$KEEP_HOME" = "yes" ]; then
     # Rename and secure home directory
     sudo mv /home/[username] /home/[username].removed.$(date +%Y%m%d)
     sudo chmod 700 /home/[username].removed.$(date +%Y%m%d)
   else
     # Remove home directory after verification backup exists
     if [ -f "/backup/users/$(date +%Y-%m-%d)/[username]-home.tar.gz" ]; then
       sudo rm -rf /home/[username]
       echo "Home directory removed after backup verification" | sudo tee -a /var/log/user-management.log
     else
       echo "ERROR: Backup not found, home directory preserved" | sudo tee -a /var/log/user-management.log
     fi
   fi
   
   # Clean up application-specific data
   # Database user removal (customize for your databases)
   mysql -u root -p -e "DROP USER IF EXISTS '[username]'@'localhost';" 2>/dev/null || echo "No MySQL user found"
   
   # Web directory cleanup
   sudo rm -rf /var/www/html/~[username]
   
   # Log completion
   echo "User [username] removal completed at $(date) by $(whoami)" | sudo tee -a /var/log/user-management.log
   ```

#### Verification
```bash
# Comprehensive removal verification
echo "=== User Removal Verification ==="
echo "User in passwd: $(grep "^[username]:" /etc/passwd || echo "NOT FOUND - GOOD")"
echo "User in shadow: $(sudo grep "^[username]:" /etc/shadow || echo "NOT FOUND - GOOD")"
echo "Home directory: $(ls -ld /home/[username] 2>/dev/null || echo "NOT FOUND")"
echo "Running processes: $(ps -u [username] 2>/dev/null || echo "NONE - GOOD")"
echo "Cron jobs: $(sudo crontab -u [username] -l 2>/dev/null || echo "NONE - GOOD")"
echo "Mail spool: $(ls -l /var/mail/[username] 2>/dev/null || echo "NOT FOUND - GOOD")"
echo "Backup created: $(ls -l /backup/users/$(date +%Y-%m-%d)/[username]* 2>/dev/null || echo "NO BACKUP FOUND")"
```

#### Rollback
If removal was premature and needs to be reversed:
```bash
# Restore from backup (if within same day)
if [ -f "/backup/users/$(date +%Y-%m-%d)/[username]-home.tar.gz" ]; then
  # Recreate user account
  sudo useradd -m -s /bin/bash [username]
  
  # Restore home directory
  sudo tar -xzf /backup/users/$(date +%Y-%m-%d)/[username]-home.tar.gz -C /
  sudo chown -R [username]:[username] /home/[username]
  
  # Restore crontab if existed
  if [ -f "/backup/users/$(date +%Y-%m-%d)/[username]-crontab.txt" ] && [ -s "/backup/users/$(date +%Y-%m-%d)/[username]-crontab.txt" ]; then
    sudo crontab -u [username] /backup/users/$(date +%Y-%m-%d)/[username]-crontab.txt
  fi
  
  # Restore mail spool
  if [ -f "/backup/users/$(date +%Y-%m-%d)/[username]-mail.txt" ]; then
    sudo cp /backup/users/$(date +%Y-%m-%d)/[username]-mail.txt /var/mail/[username]
    sudo chown [username]:mail /var/mail/[username]
  fi
  
  echo "User [username] restored from backup" | sudo tee -a /var/log/user-management.log
else
  echo "ERROR: No backup found for today's date"
fi
```

### User Access Audit

**Priority Level**: MEDIUM
**Estimated Time**: 30 minutes
**Required Access**: sudo
**Risk Level**: LOW

#### Description
Comprehensive audit of user accounts, permissions, and access patterns for security compliance.

#### Prerequisites
- List of expected active users
- Company organizational chart/user list
- Previous audit report for comparison

#### Procedure
1. **Active User Inventory**
   ```bash
   # Create audit directory
   sudo mkdir -p /var/log/audit/$(date +%Y-%m)
   AUDIT_DIR="/var/log/audit/$(date +%Y-%m)"
   
   # Generate user list with details
   echo "=== User Account Audit $(date) ===" | sudo tee $AUDIT_DIR/user-audit.txt
   echo "Generated by: $(whoami)" | sudo tee -a $AUDIT_DIR/user-audit.txt
   echo "========================================" | sudo tee -a $AUDIT_DIR/user-audit.txt
   
   # All users with login shells
   echo "=== Users with Login Shells ===" | sudo tee -a $AUDIT_DIR/user-audit.txt
   getent passwd | awk -F: '$7 !~ /(nologin|false)/ {print $1 ":" $3 ":" $5 ":" $6 ":" $7}' | sudo tee -a $AUDIT_DIR/user-audit.txt
   
   # Users with UID 0 (root privileges)
   echo -e "\n=== Users with UID 0 (Root Privileges) ===" | sudo tee -a $AUDIT_DIR/user-audit.txt
   getent passwd | awk -F: '$3 == 0 {print $1}' | sudo tee -a $AUDIT_DIR/user-audit.txt
   
   # Users with sudo access
   echo -e "\n=== Users with Sudo Access ===" | sudo tee -a $AUDIT_DIR/user-audit.txt
   getent group wheel sudo admin 2>/dev/null | cut -d: -f4 | tr ',' '\n' | sort -u | sudo tee -a $AUDIT_DIR/user-audit.txt
   ```

2. **Login Activity Analysis**
   ```bash
   # Recent login activity
   echo -e "\n=== Recent Login Activity (Last 30 Days) ===" | sudo tee -a $AUDIT_DIR/user-audit.txt
   last -30 | head -50 | sudo tee -a $AUDIT_DIR/user-audit.txt
   
   # Failed login attempts
   echo -e "\n=== Failed Login Attempts ===" | sudo tee -a $AUDIT_DIR/user-audit.txt
   lastb | head -20 | sudo tee -a $AUDIT_DIR/user-audit.txt
   
   # Users who haven't logged in recently (30+ days)
   echo -e "\n=== Inactive Users (30+ days) ===" | sudo tee -a $AUDIT_DIR/user-audit.txt
   for user in $(getent passwd | awk -F: '$7 !~ /(nologin|false)/ {print $1}'); do
     last_login=$(last -1 $user | head -1 | awk '{print $4, $5, $6}')
     if [ -z "$last_login" ] || [ "$last_login" = "begins" ]; then
       echo "$user: Never logged in" | sudo tee -a $AUDIT_DIR/user-audit.txt
     else
       # Check if login is older than 30 days (simplified check)
       echo "$user: $last_login" | sudo tee -a $AUDIT_DIR/user-audit.txt
     fi
   done
   ```

3. **Permission and Group Analysis**
   ```bash
   # Group memberships for all users
   echo -e "\n=== Group Memberships ===" | sudo tee -a $AUDIT_DIR/user-audit.txt
   for user in $(getent passwd | awk -F: '$3 >= 1000 {print $1}'); do
     echo "$user: $(groups $user 2>/dev/null | cut -d: -f2)" | sudo tee -a $AUDIT_DIR/user-audit.txt
   done
   
   # SSH key analysis
   echo -e "\n=== SSH Key Analysis ===" | sudo tee -a $AUDIT_DIR/user-audit.txt
   for user in $(getent passwd | awk -F: '$3 >= 1000 {print $1}'); do
     if [ -f "/home/$user/.ssh/authorized_keys" ]; then
       key_count=$(wc -l < /home/$user/.ssh/authorized_keys)
       echo "$user: $key_count SSH key(s)" | sudo tee -a $AUDIT_DIR/user-audit.txt
       # Show key fingerprints
       ssh-keygen -l -f /home/$user/.ssh/authorized_keys 2>/dev/null | sed "s/^/  /" | sudo tee -a $AUDIT_DIR/user-audit.txt
     else
       echo "$user: No SSH keys" | sudo tee -a $AUDIT_DIR/user-audit.txt
     fi
   done
   ```

4. **Password Policy Compliance**
   ```bash
   # Password aging information
   echo -e "\n=== Password Aging Policy Compliance ===" | sudo tee -a $AUDIT_DIR/user-audit.txt
   for user in $(getent passwd | awk -F: '$3 >= 1000 {print $1}'); do
     echo "User: $user" | sudo tee -a $AUDIT_DIR/user-audit.txt
     sudo chage -l $user | grep -E "(Last password change|Password expires|Password inactive|Account expires)" | sed 's/^/  /' | sudo tee -a $AUDIT_DIR/user-audit.txt
     echo "" | sudo tee -a $AUDIT_DIR/user-audit.txt
   done
   ```

5. **Security Risk Assessment**
   ```bash
   # Accounts with empty passwords
   echo -e "\n=== Security Risk Assessment ===" | sudo tee -a $AUDIT_DIR/user-audit.txt
   echo "Users with empty passwords:" | sudo tee -a $AUDIT_DIR/user-audit.txt
   sudo awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow | sudo tee -a $AUDIT_DIR/user-audit.txt
   
   # Locked accounts
   echo -e "\nLocked accounts:" | sudo tee -a $AUDIT_DIR/user-audit.txt
   sudo awk -F: '$2 ~ /^\!/ {print $1}' /etc/shadow | sudo tee -a $AUDIT_DIR/user-audit.txt
   
   # Accounts with old passwords (90+ days)
   echo -e "\nAccounts with passwords older than 90 days:" | sudo tee -a $AUDIT_DIR/user-audit.txt
   for user in $(getent passwd | awk -F: '$3 >= 1000 {print $1}'); do
     last_change=$(sudo chage -l $user | grep "Last password change" | cut -d: -f2 | xargs)
     if [ "$last_change" != "never" ]; then
       # This is a simplified check - in production you'd want more sophisticated date comparison
       echo "$user: $last_change" | sudo tee -a $AUDIT_DIR/user-audit.txt
     fi
   done
   ```

#### Verification
- Audit report generated successfully
- All expected active users accounted for
- No unauthorized accounts found
- Password policies being enforced

#### Notes
- Schedule monthly automated runs
- Compare with previous audit reports
- Flag any discrepancies for investigation
- Use for compliance reporting# Linux System Administrator Playbook

## Table of Contents

1. [Playbook Structure & Usage](#playbook-structure--usage)
2. [Monitoring](#monitoring)
3. [User Management](#user-management)
4. [Backup Operations](#backup-operations)
5. [Networking](#networking)
6. [Security](#security)
7. [System Maintenance](#system-maintenance)
8. [Troubleshooting](#troubleshooting)
9. [Emergency Procedures](#emergency-procedures)
10. [Templates](#templates)

---

## Playbook Structure & Usage

### Standard Procedure Format

Each procedure follows this template:

```
## [PROCEDURE NAME]

**Priority Level**: [LOW/MEDIUM/HIGH/CRITICAL]
**Estimated Time**: [X minutes]
**Required Access**: [sudo/root/specific user]
**Risk Level**: [LOW/MEDIUM/HIGH]

### Description
Brief description of what this procedure accomplishes.

### Prerequisites
- System requirements
- Required permissions
- Dependencies

### Procedure
1. Step-by-step instructions
2. Include expected outputs
3. Note any confirmations needed

### Verification
How to confirm the procedure worked correctly.

### Rollback (if applicable)
Steps to undo changes if something goes wrong.

### Notes
- Distribution-specific variations
- Common issues and solutions
- Related procedures
```

---

## Monitoring

### System Health Check

**Priority Level**: MEDIUM
**Estimated Time**: 10 minutes
**Required Access**: sudo
**Risk Level**: LOW

#### Description
Comprehensive system health assessment covering CPU, memory, disk, and services.

#### Prerequisites
- SSH access to target system
- sudo privileges

#### Procedure
1. **CPU and Load Check**
   ```bash
   # Check current load
   uptime
   
   # Detailed CPU info
   top -n 1 | head -20
   
   # CPU usage by core
   mpstat -P ALL 1 1
   
   # I/O wait analysis
   iostat -x 1 3
   
   # Check for high CPU processes
   ps aux --sort=-%cpu | head -10
   ```

2. **Memory Assessment**
   ```bash
   # Memory usage overview
   free -h
   
   # Detailed memory breakdown
   cat /proc/meminfo | grep -E "(MemTotal|MemFree|MemAvailable|Cached|Buffers|SwapTotal|SwapFree)"
   
   # Top memory consumers
   ps aux --sort=-%mem | head -10
   
   # Check for memory leaks
   vmstat 1 5
   
   # OOM killer activity
   dmesg | grep -i "killed process"
   ```

3. **Disk Space Analysis**
   ```bash
   # Filesystem usage
   df -h
   
   # Inode usage (important for systems with many small files)
   df -i
   
   # Largest directories in root
   du -xh / | sort -hr | head -20 2>/dev/null
   
   # Find large files (>100MB)
   find / -type f -size +100M -exec ls -lh {} \; 2>/dev/null | head -10
   
   # Check disk I/O
   iostat -x 1 3
   
   # Identify busy filesystems
   iotop -a -o -d 3 | head -20
   ```

4. **Service Status**
   ```bash
   # Critical services check (customize list)
   CRITICAL_SERVICES=("sshd" "httpd" "nginx" "mysqld" "postgresql" "network")
   for service in "${CRITICAL_SERVICES[@]}"; do
     systemctl is-active $service 2>/dev/null && echo "$service: RUNNING" || echo "$service: NOT RUNNING"
   done
   
   # Failed services
   systemctl --failed
   
   # Services in degraded state
   systemctl status | grep -E "degraded|failed"
   
   # Check service startup times
   systemd-analyze blame | head -10
   ```

5. **Network Status**
   ```bash
   # Network interface status
   ip link show
   
   # Active connections
   netstat -tuln | head -20
   
   # Network statistics
   cat /proc/net/dev
   
   # DNS resolution test
   dig google.com +short
   ```

#### Verification
- Load average should be reasonable for your hardware (rule of thumb: under number of CPUs)
- Memory usage under 80% (adjust threshold as needed)
- No filesystems over 85% full
- All critical services running
- Network interfaces up and functional

#### Notes
- Customize service list for your environment
- Set up monitoring thresholds based on your baseline
- Consider scripting this for regular execution

### Performance Baseline Collection

**Priority Level**: MEDIUM
**Estimated Time**: 30 minutes
**Required Access**: sudo
**Risk Level**: LOW

#### Description
Collect comprehensive performance baseline data for future comparison.

#### Prerequisites
- System during normal operating conditions
- sysstat package installed (sar, iostat, mpstat)

#### Procedure
1. **Install Required Tools** (if not present)
   ```bash
   # RHEL/CentOS
   sudo yum install sysstat iotop htop -y
   
   # Ubuntu/Debian
   sudo apt-get install sysstat iotop htop -y
   ```

2. **CPU Baseline**
   ```bash
   # Collect 5-minute CPU baseline
   echo "=== CPU Baseline $(date) ===" >> /var/log/performance-baseline.log
   sar -u 60 5 >> /var/log/performance-baseline.log
   
   # Per-CPU statistics
   mpstat -P ALL 60 5 >> /var/log/performance-baseline.log
   ```

3. **Memory Baseline**
   ```bash
   echo "=== Memory Baseline $(date) ===" >> /var/log/performance-baseline.log
   sar -r 60 5 >> /var/log/performance-baseline.log
   sar -S 60 5 >> /var/log/performance-baseline.log
   ```

4. **Disk I/O Baseline**
   ```bash
   echo "=== Disk I/O Baseline $(date) ===" >> /var/log/performance-baseline.log
   iostat -x 60 5 >> /var/log/performance-baseline.log
   
   # Per-device statistics
   sar -d 60 5 >> /var/log/performance-baseline.log
   ```

5. **Network Baseline**
   ```bash
   echo "=== Network Baseline $(date) ===" >> /var/log/performance-baseline.log
   sar -n DEV 60 5 >> /var/log/performance-baseline.log
   ```

#### Verification
- Baseline file created with comprehensive data
- No anomalous readings during baseline collection

### Log Analysis Quick Check

**Priority Level**: HIGH
**Estimated Time**: 5 minutes
**Required Access**: sudo
**Risk Level**: LOW

#### Description
Quick scan of system logs for critical issues, errors, and security events.

#### Procedure
1. **System Log Review**
   ```bash
   # Recent critical/error messages
   journalctl -p err -n 50
   
   # Authentication failures (last 24 hours)
   journalctl -u ssh --since "24 hours ago" | grep -i "failed\|invalid" | tail -20
   
   # Kernel messages
   dmesg | tail -20
   
   # Last 20 logins
   last -20
   
   # Failed login attempts
   lastb -20
   
   # Check for segfaults
   journalctl --since "24 hours ago" | grep -i segfault
   ```

2. **Application Logs** (customize paths)
   ```bash
   # Web server errors
   tail -50 /var/log/httpd/error_log 2>/dev/null || tail -50 /var/log/nginx/error.log 2>/dev/null || echo "No web server logs found"
   
   # Mail logs
   tail -20 /var/log/maillog 2>/dev/null || tail -20 /var/log/mail.log 2>/dev/null || echo "No mail logs found"
   
   # Database errors (MySQL/MariaDB)
   tail -20 /var/log/mysqld.log 2>/dev/null || tail -20 /var/log/mysql/error.log 2>/dev/null || echo "No MySQL logs found"
   
   # System messages
   tail -30 /var/log/messages 2>/dev/null || tail -30 /var/log/syslog 2>/dev/null
   ```

3. **Security Event Analysis**
   ```bash
   # sudo usage
   grep "sudo:" /var/log/auth.log /var/log/secure 2>/dev/null | tail -10
   
   # Root login attempts
   grep "root" /var/log/auth.log /var/log/secure 2>/dev/null | grep -E "Failed|Invalid" | tail -10
   
   # SELinux denials (if applicable)
   ausearch -m avc --start recent 2>/dev/null | tail -10
   
   # Firewall drops (if using iptables logging)
   grep "DROP" /var/log/messages /var/log/kern.log 2>/dev/null | tail -10
   ```

#### Verification
- No recurring error patterns
- No suspicious login attempts
- Application logs show normal operation
- Security events within expected parameters

### Service Monitoring Setup

**Priority Level**: MEDIUM
**Estimated Time**: 20 minutes
**Required Access**: sudo
**Risk Level**: MEDIUM

#### Description
Set up basic service monitoring with email notifications for critical services.

#### Prerequisites
- Mail system configured (sendmail, postfix, etc.)
- List of critical services to monitor

#### Procedure
1. **Create Service Monitor Script**
   ```bash
   sudo tee /usr/local/bin/service-monitor.sh > /dev/null << 'EOF'
   #!/bin/bash
   
   # Configuration
   SERVICES=("sshd" "httpd" "nginx" "mysqld" "postgresql" "network")
   EMAIL_ADMIN="admin@your-domain.com"
   HOSTNAME=$(hostname)
   LOGFILE="/var/log/service-monitor.log"
   
   # Function to log messages
   log_message() {
       echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> $LOGFILE
   }
   
   # Function to send alert email
   send_alert() {
       local service=$1
       local status=$2
       echo "Service Alert: $service on $HOSTNAME is $status" | mail -s "ALERT: $service $status on $HOSTNAME" $EMAIL_ADMIN
       log_message "ALERT: $service is $status - email sent to $EMAIL_ADMIN"
   }
   
   # Check each service
   for service in "${SERVICES[@]}"; do
       if systemctl is-active --quiet $service; then
           log_message "OK: $service is running"
       else
           log_message "CRITICAL: $service is not running"
           send_alert $service "NOT RUNNING"
           
           # Attempt to restart service
           if systemctl start $service; then
               log_message "INFO: Successfully restarted $service"
               send_alert $service "RESTARTED"
           else
               log_message "ERROR: Failed to restart $service"
               send_alert $service "RESTART FAILED"
           fi
       fi
   done
   EOF
   
   sudo chmod +x /usr/local/bin/service-monitor.sh
   ```

2. **Create Cron Job**
   ```bash
   # Add to root crontab (runs every 5 minutes)
   (crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/service-monitor.sh") | sudo crontab -
   ```

3. **Test the Monitor**
   ```bash
   # Run manually to test
   sudo /usr/local/bin/service-monitor.sh
   
   # Check log output
   sudo tail -20 /var/log/service-monitor.log
   ```

#### Verification
- Script executes without errors
- Log entries created properly
- Email notifications sent (test by stopping a non-critical service)

#### Rollback
```bash
# Remove cron job
sudo crontab -l | grep -v service-monitor.sh | sudo crontab -

# Remove script
sudo rm /usr/local/bin/service-monitor.sh /var/log/service-monitor.log
```

---

## User Management

### Add New User Account

**Priority Level**: MEDIUM
**Estimated Time**: 15 minutes
**Required Access**: sudo
**Risk Level**: MEDIUM

#### Description
Create new user account with proper home directory, shell, security settings, and documentation.

#### Prerequisites
- Confirm user request approval in ticket system
- Determine required group memberships
- Password policy requirements
- SSH key from user (if using key-based auth)

#### Procedure
1. **Pre-creation Checks**
   ```bash
   # Verify username doesn't exist
   id [username] 2>/dev/null && echo "User exists!" || echo "Username available"
   
   # Check for existing home directory
   ls -la /home/ | grep [username]
   
   # Verify group requirements exist
   for group in wheel developers; do
     getent group $group || echo "Group $group doesn't exist"
   done
   ```

2. **Create User Account**
   ```bash
   # Create user with home directory and bash shell
   sudo useradd -m -s /bin/bash -c "Full Name - Department" [username]
   
   # Set password expiration policy (example: 90 days)
   sudo chage -M 90 -W 7 [username]
   
   # Set initial password (user must change on first login)
   sudo passwd [username]
   sudo chage -d 0 [username]  # Force password change on first login
   
   # Add to additional groups
   sudo usermod -a -G wheel,developers [username]
   ```

3. **Set Up Home Directory and Permissions**
   ```bash
   # Verify home directory creation and ownership
   ls -la /home/[username]
   
   # Set proper permissions (750 for security)
   sudo chmod 750 /home/[username]
   sudo chown [username]:[username] /home/[username]
   
   # Create .ssh directory if using SSH keys
   sudo mkdir /home/[username]/.ssh
   sudo chmod 700 /home/[username]/.ssh
   sudo chown [username]:[username] /home/[username]/.ssh
   
   # Set up authorized_keys if SSH key provided
   if [ -n "$SSH_KEY" ]; then
     echo "$SSH_KEY" | sudo tee /home/[username]/.ssh/authorized_keys
     sudo chmod 600 /home/[username]/.ssh/authorized_keys
     sudo chown [username]:[username] /home/[username]/.ssh/authorized_keys
   fi
   ```

4. **Configure Shell Environment**
   ```bash
   # Ensure skeleton files are copied
   sudo cp /etc/skel/.* /home/[username]/ 2>/dev/null
   
   # Set proper ownership for all files
   sudo chown -R [username]:[username] /home/[username]
   
   # Create custom .bashrc additions if needed
   sudo tee -a /home/[username]/.bashrc > /dev/null << 'EOF'
   
   # Custom environment settings
   export EDITOR=vim
   export HISTSIZE=10000
   export HISTFILESIZE=20000
   EOF
   
   sudo chown [username]:[username] /home/[username]/.bashrc
   ```

5. **Security and Compliance Setup**
   ```bash
   # Set up user-specific sudo rules if needed
   echo "[username] ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart myapp" | sudo tee /etc/sudoers.d/[username]
   
   # Add to security groups if required
   sudo usermod -a -G security-audit [username] 2>/dev/null || echo "security-audit group not found"
   
   # Log user creation
   echo "$(date '+%Y-%m-%d %H:%M:%S') - User [username] created by $(whoami)" | sudo tee -a /var/log/user-management.log
   ```

#### Verification
```bash
# Comprehensive user verification
echo "=== User Account Verification ==="
echo "User ID: $(id [username])"
echo "Groups: $(groups [username])"
echo "Home directory: $(ls -ld /home/[username])"
echo "Shell: $(getent passwd [username] | cut -d: -f7)"
echo "Password expiry: $(chage -l [username] | grep 'Password expires')"
echo "Last login: $(lastlog -u [username])"

# Test sudo access (if applicable)
sudo -u [username] sudo -l

# Test SSH key authentication (if configured)
ssh -i /path/to/private/key [username]@localhost "echo 'SSH key auth working'"
```

#### Documentation
```bash
# Update user database/documentation
echo "Username: [username]
Full Name: [Full Name]
Department: [Department] 
Created: $(date)
Created by: $(whoami)
Groups: $(groups [username])
SSH Key: [Yes/No]
Special Access: [List any special permissions]
Ticket: [Ticket number]
---" | sudo tee -a /var/log/user-database.txt
```

#### Notes
- Always document user creation with ticket reference
- Consider implementing user provisioning automation
- Review password complexity requirements
- Set up user monitoring if required by compliance

### Bulk User Management

**Priority Level**: MEDIUM
**Estimated Time**: 30 minutes
**Required Access**: sudo
**Risk Level**: HIGH

#### Description
Create multiple user accounts from a CSV file with consistent settings.

#### Prerequisites
- CSV file with user data (username,full_name,department,groups)
- Approved bulk user request
- SSH keys for users (if applicable)

#### Procedure
1. **Prepare User Data File**
   ```bash
   # Create sample CSV format
   cat > /tmp/new_users.csv << 'EOF'
   username,full_name,department,groups
   jdoe,John Doe,Engineering,wheel:developers
   msmith,Mary Smith,Marketing,users
   bwilson,Bob Wilson,IT,wheel:sysadmin
   EOF
   ```

2. **Create Bulk User Script**
   ```bash
   sudo tee /usr/local/bin/bulk-user-create.sh > /dev/null << 'EOF'
   #!/bin/bash
   
   CSV_FILE="$1"
   LOG_FILE="/var/log/bulk-user-creation.log"
   
   if [ -z "$CSV_FILE" ] || [ ! -f "$CSV_FILE" ]; then
       echo "Usage: $0 <csv_file>"
       exit 1
   fi
   
   echo "=== Bulk User Creation Started $(date) ===" >> $LOG_FILE
   
   # Skip header line
   tail -n +2 "$CSV_FILE" | while IFS=',' read -r username full_name department groups; do
       echo "Processing user: $username" | tee -a $LOG_FILE
       
       # Check if user exists
       if id "$username" &>/dev/null; then
           echo "  WARNING: User $username already exists" | tee -a $LOG_FILE
           continue
       fi
       
       # Create user
       if useradd -m -s /bin/bash -c "$full_name - $department" "$username"; then
           echo "  SUCCESS: Created user $username" | tee -a $LOG_FILE
           
           # Set password expiration
           chage -M 90 -W 7 "$username"
           chage -d 0 "$username"  # Force password change
           
           # Add to groups
           if [ -n "$groups" ]; then
               IFS=':' read -ra GROUP_ARRAY <<< "$groups"
               for group in "${GROUP_ARRAY[@]}"; do
                   if getent group "$group" > /dev/null; then
                       usermod -a -G "$group" "$username"
                       echo "    Added to group: $group" | tee -a $LOG_FILE
                   else
                       echo "    WARNING: Group $group does not exist" | tee -a $LOG_FILE
                   fi
               done
           fi
           
           # Set home directory permissions
           chmod 750 "/home/$username"
           chown "$username:$username" "/home/$username"
           
           echo "  COMPLETED: User $username setup finished" | tee -a $LOG_FILE
       else
           echo "  ERROR: Failed to create user $username" | tee -a $LOG_FILE
       fi
   done
   
   echo "=== Bulk User Creation Completed $(date) ===" >> $LOG_FILE
   EOF
   
   sudo chmod +x /usr/local/bin/bulk-user-create.sh
   ```

3. **Execute Bulk Creation**
   ```bash
   # Run the bulk creation script
   sudo /usr/local/bin/bulk-user-create.sh /tmp/new_users.csv
   
   # Review results
   tail -50 /var/log/bulk-user-creation.log
   ```

#### Verification
```bash
# Verify all users were created
while IFS=',' read -r username rest; do
  [ "$username" = "username" ] && continue  # Skip header
  echo "Checking $username: $(id $username 2>/dev/null && echo "EXISTS" || echo "MISSING")"
done < /tmp/new_users.csv
```

### Remove User Account

**Priority Level**: HIGH
**Estimated Time**: 10 minutes
**Required Access**: sudo
**Risk Level**: HIGH

#### Description
Safely remove user account while preserving or removing data as required.

#### Prerequisites
- Confirm removal authorization
- Determine data retention requirements
- Check for running processes

#### Procedure
1. **Pre-removal Assessment**
   ```bash
   # Check for running processes
   ps -u [username]
   
   # Check crontab entries
   sudo crontab -u [username] -l
   
   # Find files owned by user
   find / -user [username] -ls 2>/dev/null
   ```

2. **Account Removal**
   ```bash
   # Kill user processes if running
   sudo pkill -u [username]
   
   # Remove user (keep home directory for backup)
   sudo userdel [username]
   
   # Or remove user and home directory
   # sudo userdel -r [username]
   ```

3. **Cleanup Tasks**
   ```bash
   # Remove from additional groups if needed
   sudo gpasswd -d [username] [groupname]
   
   # Check mail spool
   sudo rm -f /var/mail/[username]
   
   # Archive home directory if keeping
   sudo tar -czf /backup/users/[username]-$(date +%Y%m%d).tar.gz /home/[username]
   sudo rm -rf /home/[username]
   ```

#### Verification
- User cannot log in
- No processes running under user account
- Home directory handled according to policy
- User removed from all groups

#### Rollback
If removal was premature:
```bash
# Restore from backup if available
sudo tar -xzf /backup/users/[username]-[date].tar.gz -C /
sudo useradd [username]
sudo usermod [username] -d /home/[username]
```

---

## Backup Operations

## Backup Operations

### System Backup Verification

**Priority Level**: CRITICAL
**Estimated Time**: 15 minutes
**Required Access**: sudo
**Risk Level**: LOW

#### Description
Verify backup systems are functioning and recent backups are valid and restorable.

#### Prerequisites
- Knowledge of backup system configuration
- Access to backup storage locations
- Backup verification tools available

#### Procedure
1. **Check Backup Service Status**
   ```bash
   # Check backup service/daemon status
   systemctl status backup-service bacula-fd amanda rsync 2>/dev/null || echo "Standard backup services not found"
   
   # Check custom backup scripts in cron
   crontab -l | grep -i backup
   sudo crontab -l | grep -i backup
   
   # Review recent backup logs
   echo "=== Recent Backup Logs ==="
   sudo find /var/log -name "*backup*" -type f -exec tail -10 {} \; -print
   sudo journalctl -u backup* --since "24 hours ago" | tail -20
   ```

2. **Verify Recent Backups Existence**
   ```bash
   # Common backup locations (customize for your environment)
   BACKUP_LOCATIONS=(
     "/backup/daily"
     "/backup/weekly" 
     "/backup/monthly"
     "/var/backups"
     "/mnt/backup"
   )
   
   echo "=== Backup Location Analysis ==="
   for location in "${BACKUP_LOCATIONS[@]}"; do
     if [ -d "$location" ]; then
       echo "Location: $location"
       echo "  Latest files:"
       ls -lht "$location" | head -5
       echo "  Disk usage:"
       du -sh "$location"
       echo "  File count:"
       find "$location" -type f | wc -l
       echo "---"
     else
       echo "Location $location not found"
     fi
   done
   ```

3. **Backup Size and Integrity Analysis**
   ```bash
   # Find recent backup files (last 7 days)
   echo "=== Recent Backup Files (Last 7 Days) ==="
   find /backup /var/backups /mnt/backup -type f -name "*.tar.gz" -o -name "*.tar.bz2" -o -name "*.zip" -mtime -7 2>/dev/null | while read backup_file; do
     echo "File: $backup_file"
     echo "  Size: $(ls -lh "$backup_file" | awk '{print $5}')"
     echo "  Date: $(ls -l "$backup_file" | awk '{print $6, $7, $8}')"
     
     # Basic integrity check
     case "$backup_file" in
       *.tar.gz)
         if tar -tzf "$backup_file" >/dev/null 2>&1; then
           echo "  Integrity: OK (tar.gz)"
         else
           echo "  Integrity: FAILED (tar.gz)"
         fi
         ;;
       *.tar.bz2)
         if tar -tjf "$backup_file" >/dev/null 2>&1; then
           echo "  Integrity: OK (tar.bz2)"
         else
           echo "  Integrity: FAILED (tar.bz2)"
         fi
         ;;
       *.zip)
         if unzip -t "$backup_file" >/dev/null 2>&1; then
           echo "  Integrity: OK (zip)"
         else
           echo "  Integrity: FAILED (zip)"
         fi
         ;;
     esac
     echo "---"
   done
   ```

4. **Test Restore Process**
   ```bash
   # Create test restore directory
   TEST_RESTORE_DIR="/tmp/restore-test-$(date +%s)"
   mkdir -p "$TEST_RESTORE_DIR"
   
   echo "=== Backup Restore Test ==="
   # Find the most recent backup
   LATEST_BACKUP=$(find /backup -name "*.tar.gz" -type f -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2-)
   
   if [ -n "$LATEST_BACKUP" ]; then
     echo "Testing restore from: $LATEST_BACKUP"
     
     # Extract sample files to test directory
     if tar -xzf "$LATEST_BACKUP" -C "$TEST_RESTORE_DIR" --wildcards "*/etc/passwd" "*/etc/hostname" "*/etc/fstab" 2>/dev/null; then
       echo "Sample file extraction: SUCCESS"
       echo "Extracted files:"
       find "$TEST_RESTORE_DIR" -type f -exec ls -l {} \;
     else
       echo "Sample file extraction: FAILED"
     fi
     
     # Cleanup test directory
     rm -rf "$TEST_RESTORE_DIR"
   else
     echo "No .tar.gz backup files found for testing"
   fi
   ```

5. **Database Backup Verification**
   ```bash
   echo "=== Database Backup Verification ==="
   
   # MySQL/MariaDB backup check
   if command -v mysql >/dev/null 2>&1; then
     echo "MySQL/MariaDB backups:"
     find /backup -name "*.sql" -o -name "*mysql*" -type f -mtime -7 2>/dev/null | while read sql_backup; do
       echo "  File: $sql_backup"
       echo "  Size: $(ls -lh "$sql_backup" | awk '{print $5}')"
       # Basic SQL file validation
       if head -5 "$sql_backup" | grep -q "MySQL dump\|MariaDB dump\|CREATE\|INSERT"; then
         echo "  Validity: Appears to be valid SQL dump"
       else
         echo "  Validity: May not be valid SQL dump"
       fi
       echo "---"
     done
   fi
   
   # PostgreSQL backup check
   if command -v psql >/dev/null 2>&1; then
     echo "PostgreSQL backups:"
     find /backup -name "*postgres*" -o -name "*pg_dump*" -type f -mtime -7 2>/dev/null | while read pg_backup; do
       echo "  File: $pg_backup"
       echo "  Size: $(ls -lh "$pg_backup" | awk '{print $5}')"
       echo "---"
     done
   fi
   ```

#### Verification
- Backup services running without errors
- Recent backups present and reasonable size
- Sample restore successful
- Database backups valid and recent

#### Alert Conditions
```bash
# Create backup verification alerts
if [ ! -f "/backup/daily/$(date +%Y-%m-%d)*" ]; then
  echo "ALERT: No daily backup found for today" | mail -s "Backup Alert" admin@company.com
fi

# Check backup age (shouldn't be older than 25 hours for daily backups)
find /backup/daily -name "*.tar.gz" -mtime +1 -exec echo "ALERT: Backup older than 24 hours found: {}" \;
```

### Manual System Backup

**Priority Level**: HIGH
**Estimated Time**: 45 minutes
**Required Access**: sudo
**Risk Level**: MEDIUM

#### Description
Create comprehensive manual backup of critical system files and data.

#### Prerequisites
- Sufficient disk space for backup (check with df -h)
- Backup destination mounted and writable
- System in stable state (no major operations running)

#### Procedure
1. **Pre-backup System Check**
   ```bash
   # Check system resources before backup
   echo "=== Pre-backup System Check $(date) ==="
   echo "Available disk space:"
   df -h
   echo "System load:"
   uptime
   echo "Memory usage:"
   free -h
   echo "Running processes:"
   ps aux | wc -l
   ```

2. **Critical System Files Backup**
   ```bash
   # Create backup directory with timestamp
   BACKUP_DATE=$(date +%Y-%m-%d_%H%M)
   BACKUP_DIR="/backup/manual/system_$BACKUP_DATE"
   sudo mkdir -p "$BACKUP_DIR"
   
   echo "Creating system backup in: $BACKUP_DIR"
   
   # Backup critical system configuration
   sudo tar -czf "$BACKUP_DIR/system-config.tar.gz" \
     --exclude=/etc/shadow- \
     --exclude=/etc/passwd- \
     /etc \
     /boot/grub* \
     /var/spool/cron \
     /usr/local/etc 2>/dev/null
   
   # Backup package lists
   if command -v rpm >/dev/null 2>&1; then
     rpm -qa > "$BACKUP_DIR/installed-packages-rpm.txt"
   fi
   
   if command -v dpkg >/dev/null 2>&1; then
     dpkg -l > "$BACKUP_DIR/installed-packages-dpkg.txt"
   fi
   
   # Backup network configuration
   sudo cp -r /etc/sysconfig/network-scripts "$BACKUP_DIR/" 2>/dev/null || echo "Network scripts not found (not RHEL/CentOS)"
   sudo cp -r /etc/network "$BACKUP_DIR/" 2>/dev/null || echo "Network config not found (not Debian/Ubuntu)"
   
   # Backup firewall rules
   sudo iptables-save > "$BACKUP_DIR/iptables-rules.txt" 2>/dev/null
   sudo firewall-cmd --list-all-zones > "$BACKUP_DIR/firewalld-rules.txt" 2>/dev/null || echo "Firewalld not active"
   ```

3. **User Data Backup**
   ```bash
   # Backup all home directories (excluding large cache files)
   sudo tar -czf "$BACKUP_DIR/home-directories.tar.gz" \
     --exclude='*/.cache' \
     --exclude='*/.local/share/Trash' \
     --exclude='*/Downloads' \
     --exclude='*/.mozilla/firefox/*/Cache*' \
     --exclude='*/.thunderbird/*/ImapMail' \
     /home 2>/dev/null
   
   # Backup web content (if applicable)
   if [ -d "/var/www" ]; then
     sudo tar -czf "$BACKUP_DIR/web-content.tar.gz" /var/www
   fi
   
   # Backup mail spools
   if [ -d "/var/mail" ]; then
     sudo tar -czf "$BACKUP_DIR/mail-spools.tar.gz" /var/mail
   fi
   ```

4. **Application Data Backup**
   ```bash
   # Backup log files (last 30 days only to save space)
   sudo find /var/log -name "*.log" -mtime -30 -exec tar -czf "$BACKUP_DIR/recent-logs.tar.gz" {} +
   
   # Application-specific backups
   # Add your specific applications here
   
   # Example: Apache/Nginx configurations
   if [ -d "/etc/httpd" ]; then
     sudo tar -czf "$BACKUP_DIR/apache-config.tar.gz" /etc/httpd
   fi
   if [ -d "/etc/nginx" ]; then
     sudo tar -czf "$BACKUP_DIR/nginx-config.tar.gz" /etc/nginx
   fi
   
   # Example: SSH configurations and keys
   sudo tar -czf "$BACKUP_DIR/ssh-config.tar.gz" /etc/ssh
   ```

5. **System Metadata Backup**
   ```bash
   # Collect system information
   echo "=== System Information ===" > "$BACKUP_DIR/system-info.txt"
   uname -a >> "$BACKUP_DIR/system-info.txt"
   cat /etc/os-release >> "$BACKUP_DIR/system-info.txt"
   
   # Hardware information
   echo "=== Hardware Info ===" >> "$BACKUP_DIR/system-info.txt"
   lscpu >> "$BACKUP_DIR/system-info.txt"
   free -h >> "$BACKUP_DIR/system-info.txt"
   lsblk >> "$BACKUP_DIR/system-info.txt"
   
   # Network configuration
   echo "=== Network Configuration ===" >> "$BACKUP_DIR/system-info.txt"
   ip addr >> "$BACKUP_DIR/system-info.txt"
   ip route >> "$BACKUP_DIR/system-info.txt"
   
   # Mounted filesystems
   echo "=== Mounted Filesystems ===" >> "$BACKUP_DIR/system-info.txt"
   mount >> "$BACKUP_DIR/system-info.txt"
   cat /etc/fstab >> "$BACKUP_DIR/system-info.txt"
   
   # Services status
   echo "=== Services Status ===" >> "$BACKUP_DIR/system-info.txt"
   systemctl list-unit-files --type=service | grep enabled >> "$BACKUP_DIR/system-info.txt"
   ```

6. **Backup Verification and Documentation**
   ```bash
   # Create backup manifest
   echo "=== Backup Manifest ===" > "$BACKUP_DIR/backup-manifest.txt"
   echo "Backup Date: $(date)" >> "$BACKUP_DIR/backup-manifest.txt"
   echo "Backup Created By: $(whoami)" >> "$BACKUP_DIR/backup-manifest.txt"
   echo "System: $(hostname)" >> "$BACKUP_DIR/backup-manifest.txt"
   echo "Contents:" >> "$BACKUP_DIR/backup-manifest.txt"
   
   # List all backup files with sizes
   ls -lh "$BACKUP_DIR"/* >> "$BACKUP_DIR/backup-manifest.txt"
   
   # Calculate total backup size
   TOTAL_SIZE=$(du -sh "$BACKUP_DIR" | awk '{print $1}')
   echo "Total Backup Size: $TOTAL_SIZE" >> "$BACKUP_DIR/backup-manifest.txt"
   
   # Test backup integrity
   echo "=== Backup Integrity Check ===" >> "$BACKUP_DIR/backup-manifest.txt"
   for tarfile in "$BACKUP_DIR"/*.tar.gz; do
     if [ -f "$tarfile" ]; then
       if tar -tzf "$tarfile" >/dev/null 2>&1; then
         echo "$(basename "$tarfile"): INTEGRITY OK" >> "$BACKUP_DIR/backup-manifest.txt"
       else
         echo "$(basename "$tarfile"): INTEGRITY FAILED" >> "$BACKUP_DIR/backup-manifest.txt"
       fi
     fi
   done
   
   # Set proper permissions on backup directory
   sudo chmod -R 600 "$BACKUP_DIR"
   sudo chown -R root:root "$BACKUP_DIR"
   
   echo "Manual backup completed: $BACKUP_DIR"
   echo "Total size: $TOTAL_SIZE"
   ```

#### Verification
- All backup files created successfully
- Backup integrity checks passed
- Backup manifest created
- Total backup size reasonable for available storage

#### Notes
- Customize excluded directories based on your environment
- Consider encrypting sensitive backups
- Document backup location in disaster recovery plan
- Schedule regular cleanup of old manual backups

### Manual Database Backup

**Priority Level**: HIGH
**Estimated Time**: 10 minutes
**Required Access**: Database user with backup privileges
**Risk Level**: MEDIUM

#### Description
Create manual database backup for MySQL/MariaDB.

#### Prerequisites
- Database credentials with appropriate privileges
- Sufficient disk space for backup file

#### Procedure
1. **MySQL/MariaDB Backup**
   ```bash
   # Single database backup
   mysqldump -u backup_user -p database_name > /backup/db/database_name_$(date +%Y%m%d_%H%M).sql
   
   # All databases backup
   mysqldump -u backup_user -p --all-databases > /backup/db/all_databases_$(date +%Y%m%d_%H%M).sql
   
   # Compress backup
   gzip /backup/db/database_name_$(date +%Y%m%d_%H%M).sql
   ```

2. **PostgreSQL Backup**
   ```bash
   # Single database
   pg_dump -U backup_user database_name > /backup/db/database_name_$(date +%Y%m%d_%H%M).sql
   
   # All databases
   pg_dumpall -U postgres > /backup/db/all_databases_$(date +%Y%m%d_%H%M).sql
   ```

#### Verification
- Backup file created and non-zero size
- Backup file readable and not corrupted
- Test restore in development environment if critical

---

## Networking

### Network Connectivity Troubleshooting

**Priority Level**: HIGH
**Estimated Time**: 10 minutes
**Required Access**: sudo for some commands
**Risk Level**: LOW

#### Description
Systematic approach to diagnosing network connectivity issues.

#### Procedure
1. **Basic Connectivity Tests**
   ```bash
   # Check network interfaces
   ip addr show
   
   # Check routing table
   ip route show
   
   # Test local connectivity
   ping -c 4 127.0.0.1
   
   # Test gateway connectivity
   ping -c 4 $(ip route | grep default | awk '{print $3}')
   
   # Test DNS resolution
   nslookup google.com
   dig google.com
   ```

2. **Port and Service Testing**
   ```bash
   # Check listening ports
   netstat -tlnp
   # or using ss
   ss -tlnp
   
   # Test specific port connectivity
   telnet target_host 80
   # or using nc
   nc -zv target_host 80
   ```

3. **Firewall and Security Check**
   ```bash
   # Check iptables rules
   sudo iptables -L -n
   
   # Check firewalld status (RHEL/CentOS)
   sudo firewall-cmd --state
   sudo firewall-cmd --list-all
   
   # Check ufw status (Ubuntu)
   sudo ufw status verbose
   ```

#### Verification
- All network interfaces have expected IP addresses
- Default gateway reachable
- DNS resolution working
- Required ports accessible

---

## Templates

### Incident Response Template

```markdown
# Incident Report: [INCIDENT-YYYY-MM-DD-###]

**Date/Time**: 
**Reported By**: 
**Severity**: [LOW/MEDIUM/HIGH/CRITICAL]
**Status**: [OPEN/IN-PROGRESS/RESOLVED/CLOSED]

## Summary
Brief description of the incident

## Timeline
- **HH:MM** - Initial detection/report
- **HH:MM** - Investigation started
- **HH:MM** - Root cause identified
- **HH:MM** - Resolution implemented
- **HH:MM** - System restored

## Impact
- Systems affected:
- Users affected:
- Services affected:
- Business impact:

## Root Cause
Detailed explanation of what caused the incident

## Resolution
Steps taken to resolve the incident

## Prevention
Actions to prevent recurrence

## Lessons Learned
What we learned from this incident
```

### Change Request Template

```markdown
# Change Request: [CR-YYYY-MM-DD-###]

**Requested By**: 
**Date**: 
**Priority**: [LOW/MEDIUM/HIGH/EMERGENCY]
**Risk Level**: [LOW/MEDIUM/HIGH]

## Change Description
What needs to be changed and why

## Systems Affected
List of systems that will be impacted

## Implementation Plan
Step-by-step plan for implementing the change

## Rollback Plan
How to undo the change if problems occur

## Testing Plan
How to verify the change was successful

## Maintenance Window
Proposed date/time and duration

## Approvals
- [ ] Technical Lead
- [ ] Manager
- [ ] Security (if required)
```

---

## Quick Reference Commands

### System Information
```bash
# System info
uname -a
cat /etc/os-release
uptime
who
w
```

### Process Management
```bash
# Process monitoring
ps aux
top
htop
pgrep [process_name]
pkill [process_name]
```

### Disk Operations
```bash
# Disk usage
df -h
du -sh *
lsblk
fdisk -l
```

### Network Commands
```bash
# Network info
ip addr
ip route
netstat -tuln
ss -tuln
```

### Service Management (systemd)
```bash
systemctl status [service]
systemctl start [service]
systemctl stop [service]
systemctl restart [service]
systemctl enable [service]
systemctl disable [service]
```

---

## Maintenance Schedule

### Daily Tasks
- [ ] Check system alerts
- [ ] Review critical logs
- [ ] Verify backup completion
- [ ] Monitor disk space

### Weekly Tasks
- [ ] System updates review
- [ ] Security patch assessment
- [ ] Performance trend analysis
- [ ] Backup restoration test

### Monthly Tasks
- [ ] User access review
- [ ] Security audit
- [ ] Capacity planning review
- [ ] Documentation updates

---

*Last Updated: [DATE]*
*Version: 1.0*
*Maintained By: [YOUR NAME]*