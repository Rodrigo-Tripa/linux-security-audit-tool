#!/usr/bin/env bash

# Name: Linux Security Audit Tool
# Author: Rodrigo-Tripa (GitHub)
# Description: Performs security checks on a Linux system.
# Version: 0.1 (Alpha)

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
    uid_zero_users=$(awk -F: '$3 == 0 { print $1 }' /etc/passwd | awk '!/root/')
    if [[ -n "$uid_zero_users" ]]; then
        echo "WARNING: The following users with sensitive permissions have been detected: $uid_zero_users"
    else
        echo "OK: No users with sensitive permissions other than root were detected"
    fi
}

#Checks if there are world-writable files in the system

check_world_writable_files() {
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

check_ssh_configuration() {                         # Note: This function required significant effort due to the complexity of SSH configuration parsing.
    echo "----- SSH Configuration Check -----"

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
    local active_ports active_ports_srisk active_ports_risk
    active_ports=$(ss -tulpn | awk 'NR==1 {printf "%-6s %-25s %-20s\n", $1, $5, $6; next}
                {printf "%-6s %-25s %-20s\n", $1, $5, $6}')
    active_ports_srisk=$(ss -tuln | awk 'NR>1 {split($5, a, ":"); print a[length(a)]}' | sort -n | uniq | grep -E '^(22|3389|445|139|21|23|5900|3306|5432|6379|27017|11211)$')
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

    # Global classification: only consider installed firewalls
    if [[ ( -n "$detect_firewall_install_ufw" && "$detect_firewall_status_ufw" == "inactive" ) &&
          ( -n "$detect_firewall_install_firewalld" && "$detect_firewall_status_firewalld" == "inactive" ) &&
          ( -n "$detect_firewall_install_nftables" && "$detect_firewall_status_nftables" == "inactive" ) &&
          ( -n "$detect_firewall_install_iptables" && "$detect_firewall_status_iptables" == "inactive" ) ]]; then
        echo "CRITICAL: No active firewall detected"
    fi
}

#Call functions
#You can put a # before the name of each function to disable them          
check_root
check_uid_zero_users
check_world_writable_files
check_ssh_configuration
check_open_ports
check_firewall_status
