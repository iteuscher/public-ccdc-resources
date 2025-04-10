# INSTALL FALCO
#apt (Debian/Ubuntu)
    #1. Trust the falcosecurity GPG key
    curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
    sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg

    #2. Configure the apt repository
    echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" | \
    sudo tee -a /etc/apt/sources.list.d/falcosecurity.list

    #3. Update the package list
    sudo apt-get update -y

    #4. Install some required dependencies that are needed to build the Kernel Module and the eBPF probe
    sudo apt install -y dkms make linux-headers-$(uname -r)
    sudo apt install -y clang llvm
    sudo apt install -y dialog

    #5. Install the Falco package
    sudo apt-get install -y falco

    # Install eBPF driver
    sudo falco-driver-loader ebpf

#yum (CentOS/RHEL/Fedora/Amazon Linux)
    #1. Trust the falcosecurity GPG key
    rpm --import https://falco.org/repo/falcosecurity-packages.asc

    #2. Configure the yum repository
    curl -s -o /etc/yum.repos.d/falcosecurity.repo https://falco.org/repo/falcosecurity-rpm.repo

    #3. Update the package list
    yum update -y

    #4. Install some required dependencies that are needed to build the Kernel Module and the eBPF probe
    yum install -y dkms make
    yum install -y kernel-devel-$(uname -r)
    yum install -y clang llvm
    yum install -y dialog

    #5. Install the Falco package
    yum install -y falco

    # Install eBPF driver
    yum falco-driver-loader ebpf

# ADD LOGGING 
    # Edit Falco configuration
    /etc/falco/falco.yaml

    # Logging configuration
    log_level: info
    log_file: /var/log/falco/falco.log

    # Output configuration
    outputs:
    - output_name: stdout
        output_format: "%evt.time,%proc.name,%evt.dir,%evt.type,%evt.args"
    - output_name: file
        filename: /var/log/falco/falco_events.log
        output_format: "%evt.time,%proc.name,%evt.dir,%evt.type,%evt.args"

    # Rule files
    rules_file:
    - /etc/falco/falco_rules.yaml
    - /etc/falco/rules.d/ccdc_custom_rules.yaml

    logging:
    enabled: true
    level: info
    output_format: json
    outputs:
        - file:
            enabled: true
            filename: /var/log/falco/falco.log



# ADD RULES
    # Create a custom rules file
    /etc/falco/rules.d/ccdc_custom_rules.yaml

    # Custom rules
    - rule: Suspicious_Process_Execution
    desc: Detect potentially suspicious process executions
    condition: >
        spawn_process and 
        (proc.name in (bash, sh, python, perl, nc, netcat) or 
        proc.cmdline contains "wget" or 
        proc.cmdline contains "curl")
    output: >
        Suspicious process executed: %proc.name (user=%user.name, command=%proc.cmdline)
    priority: WARNING
    actions:
        - log

    - rule: Unauthorized_File_Creation
    desc: Detect file creation in sensitive directories
    condition: >
        evt.type = open and 
        evt.dir = > and 
        (fd.directory startswith "/etc/" or 
        fd.directory startswith "/usr/bin" or 
        fd.directory startswith "/var/www/")
    output: >
        Unauthorized file creation detected: %fd.name in %fd.directory by %user.name
    priority: HIGH
    actions:
        - log


# RESTART FALCO
    sudo systemctl restart falco