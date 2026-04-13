# Linux Security Audit Tool

⚠️ **Status:** Alpha – Active Development  
📌 **Current Version:** `v0.3.0-alpha`

A lightweight and modular Bash-based tool for auditing the security posture of Linux systems. It identifies common misconfigurations and provides actionable insights aligned with **CIS Benchmarks** and **MITRE ATT&CK** techniques.

---

## 🚀 Implemented Features

### 1. Root Privilege Verification
Ensures the script is executed with root privileges to allow comprehensive security checks.

### 2. UID 0 User Detection
Detects accounts other than `root` with UID 0, mitigating risks of unauthorized privileged access.

### 3. World-Writable File Detection
Identifies world-writable files that may enable unauthorized modifications. Virtual filesystems such as `/proc`, `/sys`, `/dev`, `/run`, and `/snap` are excluded to improve performance and accuracy.

### 4. SSH Configuration Auditing
Analyzes the effective SSH configuration using `sshd -T`, evaluating key directives:

- `PermitRootLogin`
- `PasswordAuthentication`
- `MaxAuthTries`
- `X11Forwarding`

### 5. Network Open Ports Enumeration
Enumerates listening TCP and UDP ports using the `ss` utility, highlighting potentially exposed or high-risk services.

### 6. Firewall Status Verification
Checks the presence and status of common firewall solutions:

- **ufw**
- **firewalld**
- **nftables**
- **iptables**

A **CRITICAL** alert is generated if no firewall is installed or active.

### 7. SUID/SGID Binaries Audit 🆕
Scans the filesystem for binaries with **SUID** or **SGID** permissions using `find`. The function:

- Excludes pseudo-filesystems (`/proc`, `/sys`, `/dev`, `/run`, `/snap`).
- Uses a whitelist of legitimate binaries (e.g., `passwd`, `sudo`, `su`).
- Flags binaries not owned by `root` or located in temporary directories (`/tmp`, `/var/tmp`).
- Provides a structured summary of total SUID, SGID, and suspicious files.

This check helps detect potential **privilege escalation vectors** aligned with **MITRE ATT&CK – T1548 (Abuse Elevation Control Mechanism)**.

### 8. Automated Report Generation
Generates a timestamped audit report stored in the `reports/` directory with restricted permissions:

- **Report:** `result_<timestamp>.txt`
- **Integrity Hash:** `hash_result_<timestamp>.txt` (SHA-256)

---

## 📋 Requirements

- Linux system (Debian/Ubuntu or RHEL-based distributions)
- Bash **4.0+**
- Root privileges
- `systemctl` (systemd-based systems)
- `ss` (iproute2 package)
- OpenSSH Server (for SSH configuration auditing)
- `find`, `stat`, and `sha256sum`

---

## ▶️ Usage

```bash
git clone https://github.com/rodrigo-tripa/linux-security-audit-tool.git
cd linux-security-audit-tool
chmod +x audit.sh
sudo ./audit.sh