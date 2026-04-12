# Linux Security Audit Tool

⚠️ **Status:** Alpha – Active Development  
📌 **Current Version:** v0.2.0-alpha

A lightweight and modular Bash-based tool designed to audit the security posture of Linux systems. The tool identifies common security misconfigurations and provides actionable insights aligned with **CIS Benchmarks** and **MITRE ATT&CK** techniques.

---

## 🚀 Implemented Features

### 1. Root Privilege Verification
Ensures the script is executed with root privileges, which are required to perform comprehensive system security checks.

### 2. UID 0 User Detection
Identifies any users other than `root` with UID 0, which could indicate privilege escalation risks or unauthorized administrative accounts.

### 3. World-Writable File Detection
Scans the filesystem for world-writable files that may allow unauthorized modifications or privilege escalation. Critical virtual filesystems such as `/proc`, `/sys`, `/dev`, `/run`, `/tmp`, and `/var/tmp` are excluded to improve performance and accuracy.

### 4. SSH Configuration Auditing
Analyzes the effective SSH daemon configuration using `sshd -T` and evaluates key security directives:

- `PermitRootLogin`
- `PasswordAuthentication`
- `MaxAuthTries`
- `X11Forwarding`

These checks help identify insecure remote access configurations aligned with CIS Benchmarks.

### 5. Network Open Ports Enumeration
Enumerates active TCP and UDP listening ports using the `ss` utility. The tool categorizes ports based on their potential security risk:

- **High Risk:** Services commonly targeted by attackers (e.g., SSH, RDP, SMB, databases such as MySQL, PostgreSQL, MongoDB, Redis).
- **Medium Risk:** Services that may be legitimate but should be reviewed (e.g., DNS, SMTP, alternative HTTP ports).

### 6. Firewall Status Verification
Detects and evaluates the status of common Linux firewall solutions:

- **ufw**
- **firewalld**
- **nftables**
- **iptables**

The tool reports whether each firewall is installed and active, and raises a **CRITICAL** alert if:
- No firewall solution is installed.
- Firewalls are installed but none are active.

### 7. Automated Report Generation
Generates a timestamped security audit report stored in the `reports/` directory with restricted permissions:

- **Report File:** `result_<timestamp>.txt`
- **Integrity Hash:** `hash_result_<timestamp>.txt` (SHA-256)

This ensures audit traceability and integrity verification.

---

## 🛠️ Planned Features

- SUID/SGID file detection
- Password policy analysis
- System update and patch assessment
- JSON report export
- Running services enumeration
- Failed login attempts analysis
- CIS Benchmark scoring

---

## 📋 Requirements

- Linux system (Debian/Ubuntu or RHEL-based distributions)
- Bash **4.0+**
- Root privileges
- `systemctl` (systemd-based systems)
- `ss` (iproute2 package)
- OpenSSH Server (for SSH configuration auditing)

---

## ▶️ Usage

```bash
git clone https://github.com/rodrigo-tripa/linux-security-audit-tool.git
cd linux-security-audit-tool
chmod +x audit.sh
sudo ./audit.sh