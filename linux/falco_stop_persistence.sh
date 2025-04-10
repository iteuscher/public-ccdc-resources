#!/bin/bash
# Alert and logging scripts for persistence prevention

# Generic alert function
send_security_alert() {
    local message="$1"
    local severity="${2:-HIGH}"
    
    # Log to syslog
    logger -p local0.alert "CCDC SECURITY ALERT [$severity]: $message"
    
    # Optional: Send email or other notification
    echo "$message" | mail -s "CCDC Security Alert - $severity" security-team@yourorg.com
}

# Specific alert scripts
# 1. Web Shell Alert
ccdc_webshell_alert() {
    local filepath="$1"
    local user="$2"
    
    send_security_alert "Potential Web Shell Detected: $filepath created by $user" "CRITICAL"
    
    # Optional: Quarantine the file
    mv "$filepath" "/var/tmp/quarantine/webshell_$(basename "$filepath")"
}

# 2. Connection Block Script
ccdc_block_connection() {
    local process="$1"
    local ip="$2"
    local port="$3"
    
    # Block IP at firewall level
    /sbin/iptables -A INPUT -s "$ip" -j DROP
    /sbin/iptables -A OUTPUT -d "$ip" -j DROP
    
    send_security_alert "Blocked Suspicious Connection: $process to $ip:$port" "HIGH"
}

# 3. User Creation Alert
ccdc_user_alert() {
    local user_args="$1"
    local created_by="$2"
    
    send_security_alert "New User Account Created: $user_args by $created_by" "CRITICAL"
}

# 4. SSH Key Modification Alert
ccdc_ssh_key_alert() {
    local filename="$1"
    local user="$2"
    
    send_security_alert "SSH Key Modification Detected: $filename modified by $user" "CRITICAL"
    
    # Optionally revert SSH key changes
    # This is a simplistic example - you'd want more robust backup/restore
    if [[ -f "$filename.bak" ]]; then
        cp "$filename.bak" "$filename"
    fi
}

# 5. PAM Modification Alert
ccdc_pam_alert() {
    local filename="$1"
    local user="$2"
    
    send_security_alert "PAM Module Modification: $filename changed by $user" "CRITICAL"
    
    # Optionally restore original PAM configuration
    # Requires maintaining backup copies
}

# 6. Binary Compilation Alert
ccdc_binary_compilation_alert() {
    local directory="$1"
    local user="$2"
    
    send_security_alert "Suspicious Binary Compilation in $directory by $user" "HIGH"
}

# 7. SUID Binary Alert
ccdc_suid_alert() {
    local filename="$1"
    local user="$2"
    
    send_security_alert "New SUID Binary Created: $filename by $user" "CRITICAL"
    
    # Remove SUID bit
    chmod -s "$filename"
}

# 8. Crontab Modification Alert
ccdc_crontab_alert() {
    local filename="$1"
    local user="$2"
    
    send_security_alert "Crontab Modification Detected: $filename by $user" "HIGH"
}

# 9. Startup Script Alert
ccdc_startup_script_alert() {
    local filename="$1"
    local user="$2"
    
    send_security_alert "Startup Script Modified: $filename by $user" "CRITICAL"
}

# 10. Shell Configuration Alert
ccdc_shell_config_alert() {
    local filename="$1"
    local user="$2"
    
    send_security_alert "Shell Configuration Modified: $filename by $user" "HIGH"
}

# 11. Sudoers Modification Alert
ccdc_sudoers_alert() {
    local filename="$1"
    local user="$2"
    
    send_security_alert "Sudoers File Modified: $filename by $user" "CRITICAL"
}