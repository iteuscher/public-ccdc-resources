

##################### ADVANCED HARDENING FUNCTIONS #####################
function setup_iptables_cronjob {
    print_banner "Setting Up Iptables Persistence Cronjob"
    if grep -qi 'fedora\|centos\|rhel' /etc/os-release; then
        cron_file="/etc/cron.d/iptables_persistence"
        sudo bash -c "cat > $cron_file" <<EOF
*/5 * * * * root /sbin/iptables-save > /etc/sysconfig/iptables
EOF
        echo "[*] Cron job created at $cron_file for RHEL-based systems."
    elif grep -qi 'debian\|ubuntu' /etc/os-release; then
        cron_file="/etc/cron.d/iptables_persistence"
        sudo bash -c "cat > $cron_file" <<EOF
*/5 * * * * root /sbin/iptables-save > /etc/iptables/rules.v4
EOF
        echo "[*] Cron job created at $cron_file for Debian-based systems."
    else
        echo "[*] Unknown OS. Please set up a cron job manually for iptables persistence."
    fi
}

function disable_unnecessary_services {
    print_banner "Disabling Unnecessary Services"
    if [ "$ANSIBLE" == "true" ]; then
        echo "[*] Ansible mode: Skipping disabling services."
        return 0
    fi
    read -p "Disable SSHD? (WARNING: may lock you out if remote) (y/N): " disable_sshd
    if [[ "$disable_sshd" =~ ^[Yy]$ ]]; then
        if systemctl is-active sshd &> /dev/null; then
            sudo systemctl stop sshd
            sudo systemctl disable sshd
            echo "[*] SSHD service disabled."
        else
            echo "[*] SSHD service not active."
        fi
    fi
    read -p "Disable Cockpit? (y/N): " disable_cockpit
    if [[ "$disable_cockpit" =~ ^[Yy]$ ]]; then
        if systemctl is-active cockpit &> /dev/null; then
            sudo systemctl stop cockpit
            sudo systemctl disable cockpit
            echo "[*] Cockpit service disabled."
        else
            echo "[*] Cockpit service not active."
        fi
    fi
}

function setup_firewall_maintenance_cronjob_iptables {
    print_banner "Setting Up iptables Maintenance Cronjob"
    local script_file="/usr/local/sbin/firewall_maintain.sh"
    sudo bash -c "cat > $script_file" <<'EOF'
#!/bin/bash
open_ports=$(ss -lnt | awk 'NR>1 {split($4,a,":"); print a[length(a)]}' | sort -nu)
for port in $open_ports; do
    iptables -C INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport $port -j ACCEPT
done
EOF
    sudo chmod +x "$script_file"
    local cron_file="/etc/cron.d/firewall_maintenance"
    sudo bash -c "cat > $cron_file" <<EOF
*/5 * * * * root $script_file
EOF
    echo "[*] iptables maintenance cron job created."
}

function setup_firewall_maintenance_cronjob_ufw {
    print_banner "Setting Up UFW Maintenance Cronjob"
    backup_current_ufw_rules
    local script_file="/usr/local/sbin/ufw_maintain.sh"
    sudo bash -c "cat > $script_file" <<'EOF'
#!/bin/bash
if [ -f /tmp/ufw_backup.rules ]; then
    ufw reset
    cp /tmp/ufw_backup.rules /etc/ufw/user.rules
    ufw reload
fi
EOF
    sudo chmod +x "$script_file"
    local cron_file="/etc/cron.d/ufw_maintenance"
    sudo bash -c "cat > $cron_file" <<EOF
*/5 * * * * root /usr/local/sbin/ufw_maintain.sh
EOF
    echo "[*] UFW maintenance cron job created."
}

function setup_firewall_maintenance_cronjob {
    if command -v ufw &>/dev/null && sudo ufw status | grep -q "Status: active"; then
        setup_firewall_maintenance_cronjob_ufw
    else
        setup_firewall_maintenance_cronjob_iptables
    fi
}

function setup_nat_clear_cronjob {
    print_banner "Setting Up NAT Table Clear Cronjob"
    cron_file="/etc/cron.d/clear_nat_table"
    sudo bash -c "cat > $cron_file" <<EOF
*/5 * * * * root /sbin/iptables -t nat -F
EOF
    echo "[*] NAT table clear cron job created."
}



function setup_service_restart_cronjob {
    print_banner "Setting Up Service Restart Cronjob"
    detected_service=""
    if command -v ufw &>/dev/null && sudo ufw status 2>/dev/null | grep -q "Status: active"; then
        detected_service="ufw"
    elif systemctl is-active firewalld &>/dev/null; then
        detected_service="firewalld"
    elif systemctl is-active netfilter-persistent &>/dev/null; then
        detected_service="netfilter-persistent"
    else
        echo "[*] No recognized firewall service detected automatically."
    fi
    if [ -n "$detected_service" ]; then
        echo "[*] Detected firewall service: $detected_service"
        local script_file="/usr/local/sbin/restart_${detected_service}.sh"
        sudo bash -c "cat > $script_file" <<EOF
#!/bin/bash
systemctl restart $detected_service
EOF
        sudo chmod +x $script_file
        local cron_file="/etc/cron.d/restart_${detected_service}"
        sudo bash -c "cat > $cron_file" <<EOF
*/5 * * * * root $script_file
EOF
        echo "[*] Cron job created to restart $detected_service every 5 minutes."
    fi
    if [ "$ANSIBLE" != "true" ]; then
        read -p "Would you like to add additional services to restart via cronjob? (y/N): " add_extra
        if [[ "$add_extra" =~ ^[Yy]$ ]]; then
            while true; do
                read -p "Enter the name of the additional service (or leave blank to finish): " extra_service
                if [ -z "$extra_service" ]; then
                    break
                fi
                local extra_script_file="/usr/local/sbin/restart_${extra_service}.sh"
                sudo bash -c "cat > $extra_script_file" <<EOF
#!/bin/bash
systemctl restart $extra_service
EOF
                sudo chmod +x $extra_script_file
                local extra_cron_file="/etc/cron.d/restart_${extra_service}"
                sudo bash -c "cat > $extra_cron_file" <<EOF
*/5 * * * * root $extra_script_file
EOF
                echo "[*] Cron job created to restart $extra_service every 5 minutes."
            done
        fi
    else
        echo "[*] Ansible mode: Skipping additional service restart configuration."
    fi
    echo "[*] Service restart configuration complete."
}

function reset_advanced_hardening {
    print_banner "Resetting Advanced Hardening Configurations"
    echo "[*] Removing iptables persistence cronjob (if exists)..."
    sudo rm -f /etc/cron.d/iptables_persistence
    echo "[*] Removing firewall maintenance cronjob and script..."
    sudo rm -f /etc/cron.d/firewall_maintenance
    sudo rm -f /usr/local/sbin/firewall_maintain.sh
    echo "[*] Removing NAT table clear cronjob..."
    sudo rm -f /etc/cron.d/clear_nat_table
    echo "[*] Removing service restart cronjobs and scripts..."
    sudo rm -f /etc/cron.d/restart_*
    sudo rm -f /usr/local/sbin/restart_*
    echo "[*] Advanced hardening configurations have been reset."
}

function run_full_advanced_hardening {
    print_banner "Running Full Advanced Hardening Process"
    setup_iptables_cronjob
    disable_unnecessary_services
    setup_firewall_maintenance_cronjob
    setup_nat_clear_cronjob
    setup_service_restart_cronjob
    echo "[*] Full Advanced Hardening Process Completed."
}

#==============================================================================
# FUNCTION: advanced_hardening
# DESCRIPTION:
#   Presents a menu of advanced hardening & automation tasks, now including
#   our new toggle_permissions option.
#==============================================================================
function advanced_hardening {
    if [ "$ANSIBLE" == "true" ]; then
         echo "[*] Ansible mode: Skipping advanced hardening prompts."
         return 0
    fi

    local adv_choice
    while true; do
        print_banner "Advanced Hardening & Automation"
        echo " 1) Run Full Advanced Hardening Process"
        echo " 2) Run rkhunter scan"
        echo " 3) Check Service Integrity"
        echo " 4) Fix Web Browser Permissions"
        echo " 5) Configure SELinux or AppArmor"
        echo " 6) Disable SSHD/Cockpit services"
        echo " 7) Set up iptables persistence cronjob (dev)"
        echo " 8) Set up firewall maintenance cronjob (dev)"
        echo " 9) Set up NAT table clear cronjob (dev)"
        echo "10) Set up service restart cronjob (dev)"
        echo "11) Reset Advanced Hardening Configurations (dev)"
        echo "12) Restrict shell interpreter permissions (apply ACLs)"
        echo "13) Revert shell interpreter permissions (remove ACLs)"
        echo "14) Kill other sessions"
        echo "15) Exit Advanced Hardening Menu"
        read -p "Enter your choice [1-15]: " adv_choice
        echo

        case $adv_choice in
            1)  run_full_advanced_hardening    ;;
            2)  run_rkhunter                   ;;
            3)  check_service_integrity        ;;
            4)  fix_web_browser                ;;
            5)  configure_security_modules     ;;
            6)  disable_unnecessary_services   ;;
            7)  setup_iptables_cronjob         ;;
            8)  setup_firewall_maintenance_cronjob ;;
            9)  setup_nat_clear_cronjob        ;;
           10)  setup_service_restart_cronjob ;;
           11)  reset_advanced_hardening       ;;
           12)  toggle_permissions apply       ;;
           13)  toggle_permissions revert      ;;
           14)  kill_other_sessions            ;;
           15)  echo "[*] Exiting advanced hardening menu."; break ;;
            *)  echo "[X] Invalid option."       ;;
        esac
        echo
    done
}



##################### WEB HARDENING MENU FUNCTION #####################
function show_web_hardening_menu {
    print_banner "Web Hardening Menu"
    if [ "$ANSIBLE" == "true" ]; then
        echo "[*] Ansible mode: Running full web hardening non-interactively."
        harden_web
        disable_phpmyadmin
        return 0
    fi

    echo "1) Run Full Web Hardening Process"
    echo "2) Install ModSecurity (Manual)"
    echo "3) Install ModSecurity (Dockerized)"
    echo "4) Backup Databases"
    echo "5) Secure php.ini Files"
    echo "6) Configure Apache .htaccess"
    echo "7) Run MySQL Secure Installation"
    echo "8) Manage Web Directory Immutability"
    echo "9) Disable phpMyAdmin"
    echo "10) Configure ModSecurity (block mode with OWASP CRS)"
    echo "11) Advanced Web Hardening Menu"
    echo "12) Exit Web Hardening Menu"
    read -p "Enter your choice [1-12]: " web_menu_choice
    echo

    case $web_menu_choice in
        1)
            print_banner "Web Hardening Initiated"
            install_modsecurity_manual
            backup_databases
            secure_php_ini
            #kill_other_sessions
            configure_apache_htaccess
            my_secure_sql_installation
            disable_phpmyadmin
            #kill_other_sessions
            configure_modsecurity
            web_hardening_menu
            manage_web_immutability_menu
            #kill_other_sessions
            ;;
        2)
            print_banner "Installing Manual ModSecurity"
            install_modsecurity_manual
            ;;
        3)
            print_banner "Installing Dockerized ModSecurity"
            install_modsecurity_docker
            ;;
        4)
            print_banner "Backing Up Databases"
            backup_databases
            ;;
        5)
            print_banner "Securing php.ini Files"
            secure_php_ini
            ;;
        6)
            print_banner "Configuring Apache .htaccess"
            configure_apache_htaccess
            ;;
        7)
            print_banner "Running MySQL Secure Installation"
            my_secure_sql_installation
            ;;
        8)
            print_banner "Managing Web Directory Immutability"
            manage_web_immutability_menu
            ;;
        9)
            print_banner "Disabling phpMyAdmin"
            disable_phpmyadmin
            ;;
        10)
            print_banner "Configuring ModSecurity (Block Mode + OWASP CRS)"
            configure_modsecurity
            ;;
        11)
            print_banner "Advanced Web Hardening Configurations"
            web_hardening_menu
            ;;
        12)
            echo "[*] Exiting Web Hardening Menu"
            ;;
        *)
            echo "[X] Invalid option."
            ;;
    esac
}







# --------------------------------------------------------------------
# FUNCTION: show_menu
# --------------------------------------------------------------------
function show_menu {
    print_banner "Hardening Script Menu"
    echo "1) Full Hardening Process (Run all)"
    echo "2) User Management"
    echo "3) Firewall Configuration"
    echo "4) Backup"
    echo "5) Splunk Installation"
    echo "6) SSH Hardening"
    echo "7) PAM/Profile Fixes & System Config"
    echo "8) Setup Proxy & Install CA Certs"
    echo "9) Web Hardening"
    echo "10) Advanced Hardening"
    echo "11) Exit"
    echo
    read -p "Enter your choice [1-11]: " menu_choice
    echo
    case $menu_choice in
        1) main ;;
        2)
            detect_system_info
            install_prereqs
            create_ccdc_users
            #change_passwords
            #disable_users
            remove_sudoers
            ;;
        3)
            firewall_configuration_menu
            ;;
        4)
            backups
            ;;
        5)
            setup_splunk
            ;;
        6)
            secure_ssh
            ;;
        7)
            fix_pam
            remove_profiles
            check_permissions
            sysctl_config
            ;;
        8)
            # New menu item for Proxy & CA Certs setup.
            # You may place the proxy/CA certificate functions here. For example, if you have
            # a function called setup_proxy_and_ca, it would be called like:
            setup_proxy_and_ca
            ;;
        9)
            show_web_hardening_menu
            ;;
        10)
            advanced_hardening
            ;;
        11)
            echo "Exiting..."; exit 0
            ;;
        *)
            echo "Invalid option. Exiting."; exit 1
            ;;
    esac
}


##################### MAIN FUNCTION #####################
function main {
    kill_other_sessions
    echo "CURRENT TIME: $(date +"%Y-%m-%d_%H:%M:%S")"
    echo "[*] Start of full hardening process"
    detect_system_info
    install_prereqs
    #kill_other_sessions
    create_ccdc_users
    #change_passwords
    #kill_other_sessions
    #disable_users
    remove_sudoers
    audit_running_services
    #kill_other_sessions
    disable_other_firewalls
    firewall_configuration_menu
    #kill_other_sessions
    if [ "$ANSIBLE" != "true" ]; then
         backups
    else
         echo "[*] Ansible mode: Skipping backup section."
    fi
    if [ "$ANSIBLE" == "true" ]; then
         echo "[*] Ansible mode: Skipping Splunk installation."
    else
         setup_splunk
    fi
    secure_ssh
    remove_profiles
    fix_pam
    #kill_other_sessions
    search_ssn
    remove_unused_packages
    patch_vulnerabilities
    #kill_other_sessions
    check_permissions
    sysctl_config
    configure_login_banner
    #kill_other_sessions
    defend_against_forkbomb

    # Disable phpMyAdmin by default for both Ansible and non-interactive execution.
    disable_phpmyadmin

    if [ "$ANSIBLE" != "true" ]; then
         web_choice=$(get_input_string "Would you like to perform web hardening? (y/N): ")
         if [ "$web_choice" == "y" ]; then
             show_web_hardening_menu
         fi
         adv_choice=$(get_input_string "Would you like to perform advanced hardening? (y/N): ")
         if [ "$adv_choice" == "y" ]; then
             advanced_hardening
         fi
    else
         echo "[*] Ansible mode: Running web hardening non-interactively."
         harden_web
         echo "[*] Ansible mode: Skipping advanced hardening prompts."
    fi
    run_rkhunter
    check_service_integrity
    #kill_other_sessions
    echo "[*] End of full hardening process"
    echo "[*] Script log can be viewed at $LOG"
    echo "[*][WARNING] FORWARD chain is set to DROP. If this box is a router or network device, please run 'sudo iptables -P FORWARD ALLOW'."
    echo "[*] ***Please install system updates now***"
}





##################### ARGUMENT PARSING + LOGGING SETUP #####################
for arg in "$@"; do
    case "$arg" in
        --debug )
            echo "[*] Debug mode enabled"
            debug="true"
            ;;
        -ansible )
            echo "[*] Ansible mode enabled: Skipping interactive prompts."
            ANSIBLE="true"
            ;;
    esac
done

LOG_PATH=$(dirname "$LOG")
if [ ! -d "$LOG_PATH" ]; then
    sudo mkdir -p "$LOG_PATH"
    sudo chown root:root "$LOG_PATH"
    sudo chmod 750 "$LOG_PATH"
fi

##################### MAIN EXECUTION #####################
if [ "$ANSIBLE" == "true" ]; then
    main
else
    show_menu
fi
