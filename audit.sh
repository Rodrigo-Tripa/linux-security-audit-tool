#!/usr/bin/env bash

# Name: Linux Security Audit Tool
# Author: Rodrigo-Tripa (GitHub)
# Description: Performs security checks on a Linux system.
# Version: 0.2 (Alpha)

#Unofficial Bash Strict Mode
#set -euo pipefail
#IFS=$'\n\t'


#---------Functions---------

#Check if the user is root

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "INFO: This script must be used with root privileges."
        exit 1
    fi
}

#Check if there are users with UID = 0

check_uid_zero_users() {

    echo ""
    echo "----- UID ZERO USERS -----"
    echo ""

    uid_zero_users=$(awk -F: '$3 == 0 { print $1 }' /etc/passwd | awk '!/root/')
    if [[ -n "$uid_zero_users" ]]; then
        echo "WARNING: The following users with sensitive permissions have been detected: $uid_zero_users"
    else
        echo "OK: No users with sensitive permissions other than root were detected"
    fi
}

#Checks if there are world-writable files in the system

check_world_writable_files() {

    echo ""
    echo "----- WORLD WRITABLE FILES -----"
    echo ""

    world_writable_files=$(find / -xdev \
      \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /tmp -o -path /var/tmp \) -prune \
      -o -type f -perm -0002 -print 2>/dev/null)

    if [[ -n "$world_writable_files" ]]; then
        echo "WARNING: The following files have permissions that may lead to privilege escalation:
        $world_writable_files"
    else
        echo "OK: No Sensitive Files Detected"
    fi
}

#Check if SSH has any risky configurations

check_ssh_configuration() {       
                          # Note: This function required significant effort due to the complexity of SSH configuration parsing.
    echo ""                     
    echo "----- SSH CONFIGURATION -----"
    echo ""

#Check if the SSH daemon (sshd) is installed
    if ! command -v sshd >/dev/null 2>&1; then
        echo "INFO: OpenSSH server (sshd) is not installed."
        return
    fi

    echo "INFO: OpenSSH server detected."

# Determine the service name (ssh or sshd)    
    local ssh_service=""
    if systemctl show -p LoadState --value ssh 2>/dev/null | grep -qv "not-found"; then
        ssh_service="ssh"
    elif systemctl show -p LoadState --value sshd 2>/dev/null | grep -qv "not-found"; then
        ssh_service="sshd"
    else
        echo "WARNING: SSH service unit not found."
        # Even if the service is not found, we continue the configuration
        # audit, as it may exist independently of the service state
    fi

#Check the service status
    if [[ -n "$ssh_service" ]]; then
        local ssh_status
        ssh_status=$(systemctl is-active "$ssh_service" 2>/dev/null || true)

        case "$ssh_status" in
            active)
                echo "INFO: SSH service ($ssh_service) is active."
                ;;
            inactive)
                echo "WARNING: SSH service ($ssh_service) is installed but inactive."
                ;;
            failed)
                echo "WARNING: SSH service ($ssh_service) is in a failed state."
                ;;
            activating)
                echo "INFO: SSH service ($ssh_service) is activating."
                ;;
            deactivating)
                echo "INFO: SSH service ($ssh_service) is deactivating."
                ;;
            *)
                echo "WARNING: Unable to determine SSH service state."
                ;;
        esac
    fi

#Get the effective SSH configuration
    local ssh_config
    if ! ssh_config=$(sshd -T 2>/dev/null); then
        echo "WARNING: Unable to retrieve SSH configuration using 'sshd -T'."
        return
    fi

#Extract critical directives    
    local permit_root_login password_auth max_auth_tries x11_forwarding

    permit_root_login=$(awk '$1=="permitrootlogin"{print $2}' <<< "$ssh_config")
    password_auth=$(awk '$1=="passwordauthentication"{print $2}' <<< "$ssh_config")
    max_auth_tries=$(awk '$1=="maxauthtries"{print $2}' <<< "$ssh_config")
    x11_forwarding=$(awk '$1=="x11forwarding"{print $2}' <<< "$ssh_config")

#Evaluate the settings  (There is room to evolve and add more verifiers)  

    # PermitRootLogin
    if [[ "$permit_root_login" == "no" || "$permit_root_login" == "prohibit-password" ]]; then
        echo "OK: PermitRootLogin is securely configured ($permit_root_login)."
    else
        echo "WARNING: PermitRootLogin is insecurely configured ($permit_root_login)."
    fi

    # PasswordAuthentication
    if [[ "$password_auth" == "no" ]]; then
        echo "OK: PasswordAuthentication is disabled."
    else
        echo "WARNING: PasswordAuthentication is enabled."
    fi

    # MaxAuthTries
    if [[ "$max_auth_tries" =~ ^[0-9]+$ && "$max_auth_tries" -le 4 ]]; then
        echo "OK: MaxAuthTries is securely configured ($max_auth_tries)."
    else
        echo "WARNING: MaxAuthTries is higher than recommended ($max_auth_tries)."
    fi

    # X11Forwarding
    if [[ "$x11_forwarding" == "no" ]]; then
        echo "OK: X11Forwarding is disabled."
    else
        echo "WARNING: X11Forwarding is enabled."
    fi
}


# Development note: Time tracking for implementation of this function.
#1h:45min

check_open_ports() {
    
    echo ""
    echo "----- OPEN PORTS -----"
    echo ""

    local ss_output active_ports active_ports_srisk active_ports_risk
    ss_output=$(ss -tulpn 2>/dev/null || ss -tuln)
    
    active_ports=$(echo "$ss_output" | awk 'NR==1 {printf "%-6s %-25s %-20s\n", $1, $5, $6; next}
                {printf "%-6s %-25s %-20s\n", $1, $5, $6}')
    active_ports_srisk=$(echo "$ss_output" | awk 'NR>1 {split($5, a, ":"); print a[length(a)]}' | sort -n | uniq | grep -E '^(22|3389|445|139|21|23|5900|3306|5432|6379|27017|11211)$' || true)
    active_ports_risk=$(ss -tuln | awk 'NR>1 {split($5, a, ":"); print a[length(a)]}' | sort -n | uniq | grep -E '^(25|53|8080)$')
    if command -v ss >/dev/null 2>&1; then
        echo "INFO: ss command installed"
        if [[ -n "$active_ports" ]]; then
            echo "INFO: Active Ports:"
            echo "$active_ports"
            echo ""
            if [[ -n "$active_ports_srisk" ]]; then
                echo "WARNING: High Risk Open Ports:"
                echo "$active_ports_srisk"
                echo ""
            else
                echo "OK: No High-Risk Ports detected"
            fi
            if [[ -n "$active_ports_risk" ]]; then
                echo "INFO: Medium Risk Open Ports:"
                echo "$active_ports_risk"
            else 
                echo "OK: No Medium-Risk Ports Detected"
            fi
         else
            echo "INFO: No Active Ports Detected"
        fi
    else
        echo "ERROR: ss command NOT installed"
    fi
}


check_firewall_status() {

    echo ""
    echo "----- FIREWALL -----"
    echo ""

    local detect_firewall_install_ufw detect_firewall_status_ufw
    local detect_firewall_install_firewalld detect_firewall_status_firewalld
    local detect_firewall_install_nftables detect_firewall_status_nftables
    local detect_firewall_install_iptables detect_firewall_status_iptables

    # Detect installation
    detect_firewall_install_ufw=$(command -v ufw)
    detect_firewall_install_firewalld=$(systemctl list-unit-files firewalld.service 2>/dev/null | grep -q firewalld.service && echo "installed")
    detect_firewall_install_nftables=$(command -v nft)
    detect_firewall_install_iptables=$(command -v iptables)

    # Detect status
    detect_firewall_status_ufw=$(ufw status 2>/dev/null | grep -q "Status: active" && echo "active" || echo "inactive")
    detect_firewall_status_firewalld=$(systemctl is-active --quiet firewalld && echo "active" || echo "inactive")
    detect_firewall_status_nftables=$(systemctl is-active --quiet nftables && echo "active" || echo "inactive")
    detect_firewall_status_iptables=$(iptables -S 2>/dev/null | grep -qE '(^-A)|(^-P (INPUT|FORWARD) (DROP|REJECT))' && echo "active" || echo "inactive")

    # UFW
    if [[ -n "$detect_firewall_install_ufw" ]]; then
        echo "INFO: Firewall 'ufw' installed"
        if [[ "$detect_firewall_status_ufw" == "active" ]]; then
            echo "OK: Firewall 'ufw' is active"
        else
            echo "WARNING: Firewall 'ufw' is inactive"
        fi
    fi

    # firewalld
    if [[ -n "$detect_firewall_install_firewalld" ]]; then
        echo "INFO: Firewall 'firewalld' installed"
        if [[ "$detect_firewall_status_firewalld" == "active" ]]; then
            echo "OK: Firewall 'firewalld' is active"
        else
            echo "WARNING: Firewall 'firewalld' is inactive"
        fi
    fi

    # nftables
    if [[ -n "$detect_firewall_install_nftables" ]]; then
        echo "INFO: Firewall 'nftables' installed"
        if [[ "$detect_firewall_status_nftables" == "active" ]]; then
            echo "OK: Firewall 'nftables' is active"
        else
            echo "WARNING: Firewall 'nftables' is inactive"
        fi
    fi

    # iptables
    if [[ -n "$detect_firewall_install_iptables" ]]; then
        echo "INFO: Firewall 'iptables' installed"
        if [[ "$detect_firewall_status_iptables" == "active" ]]; then
            echo "OK: Firewall 'iptables' is active"
        else
            echo "WARNING: Firewall 'iptables' is inactive"
        fi
    fi

# Global classification of firewall posture

# Check if no firewall solution is installed
if [[ -z "$detect_firewall_install_ufw" &&
      -z "$detect_firewall_install_firewalld" &&
      -z "$detect_firewall_install_nftables" &&
      -z "$detect_firewall_install_iptables" ]]; then
    echo "CRITICAL: No firewall solution installed"

# Check if firewalls are installed but none are active
elif [[ ( -n "$detect_firewall_install_ufw" && "$detect_firewall_status_ufw" == "inactive" ) &&
        ( -n "$detect_firewall_install_firewalld" && "$detect_firewall_status_firewalld" == "inactive" ) &&
        ( -n "$detect_firewall_install_nftables" && "$detect_firewall_status_nftables" == "inactive" ) &&
        ( -n "$detect_firewall_install_iptables" && "$detect_firewall_status_iptables" == "inactive" ) ]]; then
    echo "CRITICAL: No active firewall detected"
fi
}


check_suid_sgid_binaries() {

    echo ""
    echo "----- SUID/SGID BINARIES -----"
    echo ""

    # Verify if 'find' command is available
    if ! command -v find >/dev/null 2>&1; then
        echo "ERROR: 'find' command is not installed."
        return
    fi

    echo "INFO: Searching for SUID and SGID binaries. This may take a while..."

    # Whitelist of common legitimate binaries
    local whitelist=(
        "/usr/bin/passwd"
        "/usr/bin/sudo"
        "/usr/bin/chsh"
        "/usr/bin/newgrp"
        "/usr/bin/gpasswd"
        "/usr/bin/mount"
        "/usr/bin/umount"
        "/usr/bin/su"
        "/usr/bin/pkexec"
        "/usr/bin/crontab"
    )

    # Locate SUID/SGID binaries while excluding pseudo-filesystems
    local suid_sgid_files
    suid_sgid_files=$(find / \
        \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /snap \) -prune -o \
        -type f -perm /6000 -print 2>/dev/null)

    if [[ -z "$suid_sgid_files" ]]; then
        echo "OK: No SUID/SGID binaries found."
        return
    fi

    echo "INFO: SUID/SGID binaries detected:"
    printf "%-50s %-10s %-10s %-12s\n" "PATH" "TYPE" "OWNER" "STATUS"

    local total_suid=0
    local total_sgid=0
    local suspicious=0

    # Function to check if a binary is whitelisted
    is_whitelisted() {
        local file="$1"
        for item in "${whitelist[@]}"; do
            [[ "$file" == "$item" ]] && return 0
        done
        return 1
    }

    while IFS= read -r file; do
        [[ -z "$file" ]] && continue

        local perms owner type status
        perms=$(stat -c "%a" "$file" 2>/dev/null)
        owner=$(stat -c "%U" "$file" 2>/dev/null)
        type=""

        # Determine SUID/SGID type using octal permissions
        if (( perms & 4000 )); then
            type="SUID"
            ((total_suid++))
        fi

        if (( perms & 2000 )); then
            [[ -n "$type" ]] && type="$type/SGID" || type="SGID"
            ((total_sgid++))
        fi

        # Determine status based on whitelist and ownership
        if is_whitelisted "$file" && [[ "$owner" == "root" ]]; then
            status="OK"
        else
            status="WARNING"
            ((suspicious++))
        fi

        # Additional risk indicator: binaries in temporary directories
        if [[ "$file" =~ ^/(tmp|var/tmp)/ ]]; then
            status="WARNING"
            ((suspicious++))
        fi

        printf "%-50s %-10s %-10s %-12s\n" "$file" "$type" "$owner" "$status"

    done <<< "$suid_sgid_files"

    echo ""
    echo "Summary:"
    echo "INFO: Total SUID binaries : $total_suid"
    echo "INFO: Total SGID binaries : $total_sgid"

    if [[ "$suspicious" -eq 0 ]]; then
        echo "OK: No suspicious SUID/SGID binaries detected."
    else
        echo "WARNING: Suspicious SUID/SGID binaries detected: $suspicious"
    fi
}


generate_report() {
    local report_date user hostname result_check_uid_zero_users result_check_world_writable_files result_check_ssh_configuration result_check_open_ports result_check_firewall_status result_check_suid_sgid_binaries
    report_date=$(date "+%Y-%m-%d %H:%M:%S")
    user=$(whoami)
    hostname=$(hostname)
    result_check_uid_zero_users=$(check_uid_zero_users)
    result_check_world_writable_files=$(check_world_writable_files)
    result_check_ssh_configuration=$(check_ssh_configuration)
    result_check_open_ports=$(check_open_ports)
    result_check_firewall_status=$(check_firewall_status)
    result_check_suid_sgid_binaries=$(check_suid_sgid_binaries)

    echo "Report generated on: $report_date"
    echo "User: $user"
    echo "Hostname: $hostname"
    echo "$result_check_uid_zero_users"
    echo "$result_check_world_writable_files"
    echo "$result_check_ssh_configuration"
    echo "$result_check_open_ports"
    echo "$result_check_firewall_status"
    echo "$result_check_suid_sgid_binaries"
}

generate_report_file() {
    local result_final report_date
    
    report_date=$(date "+%Y-%m-%d_%H-%M-%S") 
    result_final=$(generate_report)
    
    mkdir -p ./reports
    chmod 700 ./reports
    echo "$result_final" > ./reports/"result_$report_date.txt"
    chmod 600 "./reports/result_$report_date.txt"
    sha256sum "./reports/result_$report_date.txt" > ./reports/"hash_result_$report_date.txt"
}



echo "--- Generated content ---"
echo "" 

#Call functions
          
check_root
generate_report_file
