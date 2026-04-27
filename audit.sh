#!/usr/bin/env bash

# Name: Linux Security Audit Tool
# Author: Rodrigo-Tripa (GitHub)
# Description: Performs security checks on a Linux system.
# Version: 1.0.0

#Unofficial Bash Strict Mode
set -uo pipefail
IFS=$'\n\t'

#---------Colors & Formatting---------
readonly RED='\e[31m'
readonly GREEN='\e[32m'
readonly YELLOW='\e[33m'
readonly BLUE='\e[36m'
readonly BOLD='\e[1m'
readonly NC='\e[0m' # No Color

# Whitelist of common legitimate SUID/SGID binaries
readonly WHITELIST_SUID_SGID=(
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
#---------Functions---------

show_help() {
    echo -e "${BOLD}Linux Security Audit Tool v1.0.0${NC}"
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -v, --verbose    Display report in terminal while generating file"
    echo "  -h, --help       Show this help message"
    echo ""
    exit 0
}

#Check if the user is root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "[${BLUE}INFO${NC}] This script must be used with root privileges."
        exit 1
    fi
}

log_section() {
    echo ""
    echo -e "${BOLD}----- $1 -----${NC}"
    echo ""
}

#Check if there are users with UID = 0

check_uid_zero_users() {

    log_section "UID ZERO USERS"

    local uid_zero_users
    uid_zero_users=$(awk -F: '$3 == 0 && $1 != "root" { print $1 }' /etc/passwd)
    if [[ -n "$uid_zero_users" ]]; then
        echo -e "[${YELLOW}WARNING${NC}] Users with root permissions detected: $uid_zero_users"
    else
        echo -e "[${GREEN}OK${NC}] No unauthorized UID 0 users detected"
    fi
}

#Checks if there are world-writable files in the system
check_world_writable_files() {

    log_section "WORLD WRITABLE FILES"

    world_writable_files=$(find / -xdev \
      \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /tmp -o -path /var/tmp -o -path /snap \) -prune \
      -o -type f -perm -0002 -print 2>/dev/null)

    if [[ -n "$world_writable_files" ]]; then
        echo -e "[${YELLOW}WARNING${NC}] World-writable files found:\n$world_writable_files"
    else
        echo -e "[${GREEN}OK${NC}] No sensitive world-writable files detected"
    fi
}

#Check if SSH has any risky configurations

check_ssh_configuration() {       
    log_section "SSH CONFIGURATION"

#Check if the SSH daemon (sshd) is installed
    if ! command -v sshd >/dev/null 2>&1; then
        echo -e "[\e[36mINFO\e[0m] OpenSSH server (sshd) is not installed."
        return
    fi

    echo -e "[\e[36mINFO\e[0m] OpenSSH server detected."

# Determine the service name (ssh or sshd)    
    local ssh_service=""
    if systemctl show -p LoadState --value ssh 2>/dev/null | grep -qv "not-found"; then
        ssh_service="ssh"
    elif systemctl show -p LoadState --value sshd 2>/dev/null | grep -qv "not-found"; then
        ssh_service="sshd"
    else
        echo -e "[\e[33mWARNING\e[0m] SSH service unit not found."
        # Even if the service is not found, we continue the configuration
        # audit, as it may exist independently of the service state
    fi

#Check the service status
    if [[ -n "$ssh_service" ]]; then
        local ssh_status
        ssh_status=$(systemctl is-active "$ssh_service" 2>/dev/null || true)

        case "$ssh_status" in
            active)
                echo -e "[${BLUE}INFO${NC}] SSH service ($ssh_service) is active."
                ;;
            inactive)
                echo -e "[${YELLOW}WARNING${NC}] SSH service ($ssh_service) is installed but inactive."
                ;;
            failed)
                echo -e "[${YELLOW}WARNING${NC}] SSH service ($ssh_service) is in a failed state."
                ;;
            activating)
                echo -e "[${BLUE}INFO${NC}] SSH service ($ssh_service) is activating."
                ;;
            deactivating)
                echo -e "[${BLUE}INFO${NC}] SSH service ($ssh_service) is deactivating."
                ;;
            *)
                echo -e "[${YELLOW}WARNING${NC}] Unable to determine SSH service state."
                ;;
        esac
    fi

#Get the effective SSH configuration
    local ssh_config
    if ! ssh_config=$(sshd -T 2>/dev/null); then
        echo -e "[${YELLOW}WARNING${NC}] Unable to retrieve SSH configuration using 'sshd -T'."
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
        echo -e "[${GREEN}OK${NC}] PermitRootLogin is securely configured ($permit_root_login)."
    else
        echo -e "[${YELLOW}WARNING${NC}] PermitRootLogin is insecurely configured ($permit_root_login)."
    fi

    # PasswordAuthentication
    if [[ "$password_auth" == "no" ]]; then
        echo -e "[${GREEN}OK${NC}] PasswordAuthentication is disabled."
    else
        echo -e "[${YELLOW}WARNING${NC}] PasswordAuthentication is enabled."
    fi

    # MaxAuthTries
    if [[ "$max_auth_tries" =~ ^[0-9]+$ && "$max_auth_tries" -le 4 ]]; then
        echo -e "[${GREEN}OK${NC}] MaxAuthTries is securely configured ($max_auth_tries)."
    else
        echo -e "[${YELLOW}WARNING${NC}] MaxAuthTries is higher than recommended ($max_auth_tries)."
    fi

    # X11Forwarding
    if [[ "$x11_forwarding" == "no" ]]; then
        echo -e "[${GREEN}OK${NC}] X11Forwarding is disabled."
    else
        echo -e "[${YELLOW}WARNING${NC}] X11Forwarding is enabled."
    fi
}


check_open_ports() {
    
    log_section "OPEN PORTS"

    local ss_output active_ports active_ports_srisk active_ports_risk
    ss_output=$(ss -tulpn 2>/dev/null || ss -tuln)
    
    active_ports=$(echo "$ss_output" | awk 'NR==1 {printf "%-6s %-25s %-20s\n", $1, $5, $6; next}
                {printf "%-6s %-25s %-20s\n", $1, $5, $6}')
    active_ports_srisk=$(echo "$ss_output" | awk 'NR>1 {split($5, a, ":"); print a[length(a)]}' | sort -n | uniq | grep -E '^(22|3389|445|139|21|23|5900|3306|5432|6379|27017|11211)$' || true)
    active_ports_risk=$(ss -tuln | awk 'NR>1 {split($5, a, ":"); print a[length(a)]}' | sort -n | uniq | grep -E '^(25|53|8080)$')
    if command -v ss >/dev/null 2>&1; then
        echo -e "[${BLUE}INFO${NC}] ss command installed"
        if [[ -n "$active_ports" ]]; then
            echo -e "[${BLUE}INFO${NC}] Active Ports:"
            echo "$active_ports"
            echo ""
            if [[ -n "$active_ports_srisk" ]]; then
                echo -e "[${YELLOW}WARNING${NC}] High Risk Open Ports:"
                echo "$active_ports_srisk"
                echo ""
            else
                echo -e "[${GREEN}OK${NC}] No High-Risk Ports detected"
            fi
            if [[ -n "$active_ports_risk" ]]; then
                echo -e "[${BLUE}INFO${NC}] Medium Risk Open Ports:"
                echo "$active_ports_risk"
            else 
                echo -e "[${GREEN}OK${NC}] No Medium-Risk Ports Detected"
            fi
         else
            echo -e "[${BLUE}INFO${NC}] No Active Ports Detected"
        fi
    else
        echo -e "${RED}ERROR:${NC} ss command NOT installed"
    fi
}


check_firewall_status() {

    log_section "FIREWALL"

    local fw_found=0
    local fw_active=0

    # Check UFW
    if command -v ufw >/dev/null; then
        fw_found=1
        echo -ne "[${BLUE}INFO${NC}] Firewall 'ufw' installed. Status: "
        if ufw status | grep -q "active"; then
            echo -e "${GREEN}ACTIVE${NC}"; fw_active=1
        else echo -e "${YELLOW}INACTIVE${NC}"; fi
    fi

    # Check Firewalld
    if systemctl list-unit-files | grep -q firewalld.service; then
        fw_found=1
        echo -ne "[${BLUE}INFO${NC}] Firewall 'firewalld' installed. Status: "
        if systemctl is-active --quiet firewalld; then
            echo -e "${GREEN}ACTIVE${NC}"; fw_active=1
        else echo -e "${YELLOW}INACTIVE${NC}"; fi
    fi

    # Check Iptables (fallback)
    if command -v iptables >/dev/null; then
        fw_found=1
        echo -ne "[${BLUE}INFO${NC}] Firewall 'iptables' installed. Status: "
        if iptables -L -n | grep -qE '^(DROP|REJECT|ACCEPT)'; then
            echo -e "${GREEN}ACTIVE (Rules present)${NC}"; fw_active=1
        else echo -e "${YELLOW}INACTIVE (No rules)${NC}"; fi
    fi

    if [[ $fw_found -eq 0 ]]; then
        echo -e "[${RED}CRITICAL${NC}] No firewall solution found!"
    elif [[ $fw_active -eq 0 ]]; then
        echo -e "[${RED}CRITICAL${NC}] Firewalls are installed but none are active!"
    fi
}

check_sudoers_audit() {
    log_section "SUDOERS AUDIT"

    # Check for NOPASSWD entries
    # We search in /etc/sudoers and all files in /etc/sudoers.d/
    local nopasswd_checks
    nopasswd_checks=$(grep -rE "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^#")

    if [[ -n "$nopasswd_checks" ]]; then
        echo -e "[${YELLOW}WARNING${NC}] Users allowed to run commands without password (NOPASSWD):"
        echo "$nopasswd_checks"
    else
        echo -e "[${GREEN}OK${NC}] No NOPASSWD entries detected in active configurations."
    fi

    # Check for broad ALL permissions (excluding root)
    local broad_permissions
    broad_permissions=$(grep -rE "ALL=\(ALL(:ALL)?\) ALL" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^#" | grep -vE "^/etc/sudoers:root")

    if [[ -n "$broad_permissions" ]]; then
        echo ""
        echo -e "[${YELLOW}WARNING${NC}] Broad 'ALL' permissions detected (potential privilege escalation):"
        echo "$broad_permissions"
    else
        echo ""
        echo -e "[${GREEN}OK${NC}] No broad 'ALL' permissions (other than root) detected."
    fi
}


check_suid_sgid_binaries() {
    log_section "SUID/SGID BINARIES"

    # Verify if 'find' command is available
    if ! command -v find >/dev/null 2>&1; then
        echo -e "${RED}ERROR:${NC} 'find' command is not installed."
        return
    fi

    echo -e "[${BLUE}INFO${NC}] Searching for SUID and SGID binaries. This may take a while..."

    # Locate SUID/SGID binaries while excluding pseudo-filesystems
    local suid_sgid_files
    suid_sgid_files=$(find / \
        \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /snap \) -prune -o \
        -type f -perm /6000 -print 2>/dev/null)

    if [[ -z "$suid_sgid_files" ]]; then
        echo -e "[${GREEN}OK${NC}] No SUID/SGID binaries found."
        return
    fi

    echo -e "[${BLUE}INFO${NC}] SUID/SGID binaries detected:"
    printf "%-50s %-10s %-10s %-12s\n" "PATH" "TYPE" "OWNER" "STATUS"

    local total_suid=0
    local total_sgid=0
    local suspicious=0

    # Function to check if a binary is whitelisted
    is_whitelisted() {
        local file="$1"
        for item in "${WHITELIST_SUID_SGID[@]}"; do
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
            status="${GREEN}OK${NC}"
        else
            status="${YELLOW}WARNING${NC}"
            ((suspicious++))
        fi

        # Additional risk indicator: binaries in temporary directories
        if [[ "$file" =~ ^/(tmp|var/tmp)/ ]]; then
            status="${YELLOW}WARNING${NC}"
            ((suspicious++))
        fi

        printf "%-50s %-10s %-10s %-12b\n" "$file" "$type" "$owner" "$status"

    done <<< "$suid_sgid_files"

    echo ""
    echo "Summary:"
    echo -e "[${BLUE}INFO${NC}] Total SUID binaries : $total_suid"
    echo -e "[${BLUE}INFO${NC}] Total SGID binaries : $total_sgid"

    if [[ "$suspicious" -eq 0 ]]; then
        echo -e "[${GREEN}OK${NC}] No suspicious SUID/SGID binaries detected."
    else
        echo -e "[${YELLOW}WARNING${NC}] Suspicious SUID/SGID binaries detected: $suspicious"
    fi
}


detect_os() {
    if [[ -r /etc/os-release ]]; then
        . /etc/os-release
    else
        echo -e "${RED}ERROR:${NC} Unable to read /etc/os-release"
        return 1
    fi

    local os_id os_like
    os_id=$(echo "$ID" | tr '[:upper:]' '[:lower:]')
    os_like=$(echo "$ID_LIKE" | tr '[:upper:]' '[:lower:]')

    if [[ "$os_id" =~ (debian|ubuntu) || "$os_like" =~ debian ]]; then
        OS_FAMILY="debian"

    elif [[ "$os_id" =~ (rhel|centos|rocky|almalinux|fedora) || "$os_like" =~ rhel ]]; then
        OS_FAMILY="rhel"

    else
        OS_FAMILY="unknown"
    fi
}


check_security_updates() {
    log_section "SECURITY UPDATES"

    # Validate OS_FAMILY (must be set beforehand)
    if [[ -z "$OS_FAMILY" ]]; then
        echo -e "${RED}ERROR:${NC} OS_FAMILY is not defined. Run detect_os() first."
        return 1
    fi

    case "$OS_FAMILY" in
        debian)
            echo -e "[${BLUE}INFO${NC}] Debian-based system detected."

            local updates
            updates=$(apt list --upgradable 2>/dev/null | grep -c "upgradable" || true)
            if [[ "$updates" -gt 0 ]]; then
                echo -e "[${YELLOW}WARNING${NC}] There are $updates packages that can be updated."
                echo -e "[${BLUE}HELP${NC}] Run 'apt list --upgradable' for details."
            else
                echo -e "[${GREEN}OK${NC}] System is up to date."
            fi
            ;;

        rhel)
            echo -e "[${BLUE}INFO${NC}] RHEL-based system detected."

            local updates
            updates=$(dnf check-update --quiet | grep -c "." || true)
            if [[ "$updates" -gt 0 ]]; then
                echo -e "[${YELLOW}WARNING${NC}] Security updates available."
                echo -e "[${BLUE}HELP${NC}] Run 'dnf check-update' for details."
            else
                echo -e "[${GREEN}OK${NC}] System is up to date."
            fi
            ;;

        *)
            echo -e "[${YELLOW}WARNING${NC}] Unsupported OS family: $OS_FAMILY"
            return 1
            ;;
    esac
}


check_no_pass_users() {
    log_section "PASSWORD AUDIT"

    no_pass_users=$(awk -F: '$2 == "" { print $1 }' /etc/shadow)

    if [ -n "$no_pass_users" ]; then
        echo -e "[${YELLOW}WARNING${NC}] The following users do not have a password set:"
        echo "$no_pass_users"
        echo -e "[${BLUE}HELP${NC}] We recommend setting a password using: ${BLUE}passwd <user>${NC}"
    else
        echo -e "[${GREEN}OK${NC}] All users have a password defined."
    fi
}

check_package_integrity() {
    log_section "SYSTEM PACKAGE INTEGRITY"

    if [[ "$OS_FAMILY" == "debian" ]]; then
        echo -e "[${BLUE}INFO${NC}] Verifying Debian/Ubuntu package integrity (dpkg --verify)..."
        # Note: dpkg --verify only checks modified timestamps/sizes for core files. 
        # For deep hash verification, 'debsums' is better but not always installed.
        local integrity_issues
        integrity_issues=$(dpkg --verify 2>/dev/null | grep -E "^..5" || true)
        
        if [[ -n "$integrity_issues" ]]; then
            echo -e "[${RED}CRITICAL${NC}] Modified system binaries detected!"
            echo "$integrity_issues"
        else
            echo -e "[${GREEN}OK${NC}] All core package files passed integrity check."
        fi

    elif [[ "$OS_FAMILY" == "rhel" ]]; then
        echo -e "[${BLUE}INFO${NC}] Verifying RHEL-based package integrity (rpm -Va)..."
        local rpm_verify
        # Filter out common configuration file changes (c), documentation (d), and ghost files (g)
        rpm_verify=$(rpm -Va --nofiledigest 2>/dev/null | grep -vE "^\.\.[ \.]+[c|d|g|l|r] " || true)
        
        if [[ -n "$rpm_verify" ]]; then
            echo -e "[${YELLOW}WARNING${NC}] Modified system files detected:"
            echo "$rpm_verify"
        else
            echo -e "[${GREEN}OK${NC}] No modified binaries detected."
        fi
    fi
}

check_failed_logins() {
    log_section "BRUTE FORCE ANALYSIS"

    if ! command -v lastb >/dev/null 2>&1; then
        echo -e "[${BLUE}INFO${NC}] 'lastb' command not found. Skipping failed login analysis."
        return
    fi

    local failed_attempts
    failed_attempts=$(lastb -n 50 | head -n -2) # Get last 50 entries

    if [[ -n "$failed_attempts" ]]; then
        echo -e "[${YELLOW}WARNING${NC}] Recent failed login attempts detected (last 50):"
        echo "$failed_attempts"
        echo ""
        echo -e "[${BLUE}INFO${NC}] Top 5 offending IPs/Users:"
        lastb | awk '{print $1 " " $3}' | sort | uniq -c | sort -nr | head -n 5
    else
        echo -e "[${GREEN}OK${NC}] No failed login attempts recorded."
    fi
}

check_persistence_mechanisms() {
    log_section "PERSISTENCE AUDIT (CRON & SYSTEMD)"

    # 1. Cron jobs review
    echo -e "[${BLUE}INFO${NC}] Auditing Cron Directories..."
    local cron_files
    cron_files=$(ls -A /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly 2>/dev/null)
    
    if [[ -n "$cron_files" ]]; then
        echo -e "Files found in cron directories (verify for suspicious names):"
        echo "$cron_files" | xargs -n5 | column -t
    fi

    # 2. Check for rc.local
    if [[ -f /etc/rc.local ]]; then
        echo -e "[${YELLOW}WARNING${NC}] /etc/rc.local exists. Content:"
        cat /etc/rc.local | grep -v "^#" || true
    fi

    # 3. Non-standard systemd services
    echo ""
    echo -e "[${BLUE}INFO${NC}] Checking for non-standard Systemd services (user-defined):"
    local user_services
    user_services=$(find /etc/systemd/system -maxdepth 1 -type f -name "*.service" 2>/dev/null)
    
    if [[ -n "$user_services" ]]; then
        echo -e "Review these custom services:"
        echo "$user_services"
    else
        echo -e "[${GREEN}OK${NC}] No custom systemd services found in /etc/systemd/system."
    fi
}

check_orphaned_files() {
    log_section "UNOWNED FILES"
    
    local search_paths=("/etc" "/home" "/root" "/var" "/usr/local" "/opt")

    check_orphaned_by_type() {
        local type_label=$1
        local find_flag=$2
        echo "-- Unowned by $type_label: --"
        echo ""

        for path in "${search_paths[@]}"; do
            if [[ ! -d "$path" ]]; then continue; fi

            local orphaned
            orphaned=$(find "$path" "$find_flag" 2>/dev/null)

            if [[ -n "$orphaned" ]]; then
                echo -e "[${YELLOW}WARNING${NC}] Unowned file found in $path =>"
                echo "$orphaned"
                echo ""
            else
                echo -e "[${GREEN}OK${NC}] No unowned files found in $path"
            fi
        done
    }

    check_orphaned_by_type "Users" "-nouser"
    echo ""
    check_orphaned_by_type "Groups" "-nogroup"
}

generate_report() {
    local report_date user hostname 
    report_date=$(date "+%Y-%m-%d %H:%M:%S")
    user=$(whoami)
    hostname=$(hostname)

    echo -e "${BOLD}LINUX SECURITY AUDIT REPORT${NC}"
    echo "----------------------------"
    echo "Report generated on: $report_date"
    echo -e "User: ${BLUE}$user${NC}"
    echo "Hostname: ${BOLD}$hostname${NC}"
    echo "Operative System Family: $OS_FAMILY"
    check_root
    check_uid_zero_users
    check_world_writable_files
    check_ssh_configuration
    check_open_ports
    check_firewall_status
    check_package_integrity
    check_failed_logins
    check_suid_sgid_binaries
    check_persistence_mechanisms
    check_sudoers_audit
    check_security_updates
    check_no_pass_users
    check_orphaned_files
}

generate_report_file() {
    local report_date report_content
    
    report_date=$(date "+%Y-%m-%d_%H-%M-%S") 
    
    mkdir -p ./reports
    chmod 700 ./reports

    # Capture report content once to avoid re-executing functions
    report_content=$(generate_report | sed 's/\x1b\[[0-9;]*m//g')
    echo "$report_content" > ./reports/"result_$report_date.txt"

    chmod 600 "./reports/result_$report_date.txt"
    sha256sum "./reports/result_$report_date.txt" > ./reports/"hash_result_$report_date.txt"
}

#Call functions

VERBOSE=0
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -v|--verbose) VERBOSE=1 ;;
        -h|--help) show_help ;;
        *) echo -e "${RED}ERROR:${NC} Unknown argument $1"; exit 1 ;;
    esac
    shift
done

detect_os

if [[ $VERBOSE -eq 1 ]]; then
    echo -e "[${BLUE}INFO${NC}] Verbose Mode: ON"
    echo "--- Generated content ---"
    echo ""
    generate_report
    generate_report_file
else
    echo -e "[${BLUE}INFO${NC}] Running Audit... (File will be saved in ./reports/)"
    generate_report_file
fi
