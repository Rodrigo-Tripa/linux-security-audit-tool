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
        echo "Warning: This script must be used with root privileges."
        exit 1
    fi
}

#Check if there are users with UID = 0

check_uid_zero_users() {
    uid_zero_users=$(awk -F: '$3 == 0 { print $1 }' /etc/passwd | awk '!/root/')
    if [[ -n "$uid_zero_users" ]]; then
        echo "WARNING: The following users with sensitive permissions have been detected: $uid_zero_users"
    else
        echo "No users with sensitive permissions other than root were detected"
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
        echo "No sensitive files detected"
    fi
}

#Check if SSH has any risky configurations

check_ssh_configuration() {                         #It took me 11 hours to complete this function, what did I do wrong to you God...
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
        # Mesmo que o serviço não seja encontrado, continuamos a auditoria
        # da configuração, pois esta pode existir independentemente do estado.
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

#Call functions
#You can put a # before the name of each function to disable them          
check_root
check_uid_zero_users
check_world_writable_files
check_ssh_configuration