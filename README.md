# Linux Security Audit Tool

> ⚠️ Status: Under Development

A lightweight and modular Bash-based tool designed to audit the security posture of Linux systems. The tool identifies common security misconfigurations and provides actionable insights aligned with CIS Benchmarks and MITRE ATT&CK techniques.

## Implemented Features

### 1. Root Privilege Verification
Ensures the script is executed with root privileges, which are required to perform comprehensive system security checks.

### 2. UID 0 User Detection
Identifies any users other than `root` with UID 0, which could indicate privilege escalation risks or unauthorized administrative accounts.

### 3. World-Writable File Detection
Scans the filesystem for world-writable files that may allow unauthorized modifications or privilege escalation. Critical virtual filesystems such as `/proc`, `/sys`, `/dev`, and `/run` are excluded to improve performance and accuracy.

### 4. SSH Configuration Auditing
Analyzes the effective SSH daemon configuration using `sshd -T` and evaluates key security directives:
- `PermitRootLogin`
- `PasswordAuthentication`
- `MaxAuthTries`
- `X11Forwarding`

These checks help identify insecure remote access configurations aligned with CIS Benchmarks.

## Planned Features

- SUID/SGID file detection
- Network open ports enumeration
- Firewall status verification (`ufw`/`firewalld`)
- Password policy analysis
- System update and patch assessment
- Automated report generation (TXT/JSON)

## Requirements

- Linux system (Debian/Ubuntu or RHEL-based distributions)
- Bash 4.0+
- Root privileges
- `systemctl` (systemd-based systems)
- OpenSSH Server (for SSH configuration auditing)

## Usage

```bash
sudo ./audit.sh