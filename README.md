# Linux Security Audit Tool

⚠️ **Status:** Alpha – Active Development  
📌 **Current Version:** `v0.4.2-alpha`

Lightweight Bash tool for auditing Linux security posture. Focuses on misconfigurations, privilege escalation vectors, and missing hardening controls aligned with **CIS Benchmarks** and **MITRE ATT&CK**.

---

## 🎯 Objective

Provide a fast, local audit with minimal dependencies to identify:

- Privilege escalation vectors  
- Weak file permissions  
- Misconfigured services  
- Network exposure  
- Missing security controls  

---

## 🚀 Implemented Features

### 1. UID 0 User Detection

Detects non-root accounts with UID 0.

- **Risk:** Privilege escalation / persistence  
- **MITRE ATT&CK:** T1078 (Valid Accounts)

---

### 2. World-Writable Files

Searches for:
`find / -type f -perm -0002`

Excludes:

- `/proc`, `/sys`, `/dev`, `/run`, `/tmp`, `/var/tmp`

- **Risk:** Arbitrary file modification  
- **MITRE ATT&CK:** T1222 (File Permissions Weakness)

---

### 3. SSH Configuration Audit

Uses effective configuration:
`sshd -T`

Checks:

- `PermitRootLogin`
- `PasswordAuthentication`
- `MaxAuthTries`
- `X11Forwarding`

Also:

- Detects `sshd` presence  
- Validates service state (`systemctl`)  

- **Risk:** Unauthorized remote access  
- **MITRE ATT&CK:** T1021.004 (SSH)

---

### 4. Open Ports Enumeration

Uses:
`ss -tulpn`

Risk classification:

| Level  | Ports |
|--------|------|
| High   | 21, 22, 23, 139, 445, 3389, 5900, 3306, 5432, 6379, 27017, 11211 |
| Medium | 25, 53, 8080 |

- **Risk:** Increased attack surface  
- **MITRE ATT&CK:** T1046 (Network Service Discovery)

---

### 5. Firewall Detection

Supports:

- `ufw`
- `firewalld`
- `nftables`
- `iptables`

Logic:

- **CRITICAL** → no firewall installed  
- **CRITICAL** → installed but inactive  

- **Risk:** Unfiltered network access  
- **MITRE ATT&CK:** T1562 (Impair Defenses)

---

### 6. SUID/SGID Binaries Audit

Search:
`find / -type f -perm /6000`

Features:

- Excludes pseudo-filesystems  
- Whitelist of known binaries  
- Flags:
  - Non-root ownership  
  - Binaries in `/tmp` or `/var/tmp`  

Output:

| Field | Description |
|------|------------|
| PATH | File path |
| TYPE | SUID / SGID |
| OWNER | File owner |
| STATUS | OK / WARNING |

- **Risk:** Privilege escalation  
- **MITRE ATT&CK:** T1548

---

### 7. OS Detection

Parses:
`/etc/os-release`

Sets:
`OS_FAMILY=debian | rhel | unknown`

---

### 8. Security Updates Check

| OS Family | Command |
|----------|--------|
| Debian   | `apt update` |
| RHEL     | `dnf check-update` |

- Detects pending updates  
- Handles unknown states  

- **Risk:** Unpatched vulnerabilities  
- **MITRE ATT&CK:** T1190

---

### 9. No Password Users

Detects accounts without password in:
`/etc/shadow`

- **Risk:** Account abuse / weak authentication  
- **MITRE ATT&CK:** T1078

---

### 10. Report Generation

#### Terminal

- Structured sections  
- Color-coded output:

| Status   | Meaning |
|----------|--------|
| OK       | Secure |
| WARNING  | Needs review |
| CRITICAL | Immediate risk |
| INFO     | Informational |

#### File Output

Directory:
`./reports/`

Files:

- `result_<timestamp>.txt`
- `hash_result_<timestamp>.txt`

Security controls:

- `chmod 700 reports/`
- `chmod 600 report`
- `sha256sum` integrity hash

---

## ▶️ Usage

`git clone https://github.com/rodrigo-tripa/linux-security-audit-tool.git`  
`cd linux-security-audit-tool`  
`chmod +x audit.sh`  
`sudo ./audit.sh`

Verbose mode:
`sudo ./audit.sh -v`

---

## 📋 Requirements

- Linux (Debian/Ubuntu or RHEL-based)
- Bash 4+
- Root privileges (recommended)
- `systemctl`
- `ss` (iproute2)
- `find`, `stat`, `sha256sum`
- `sshd` (optional)

---

## ⚠️ Known Limitations

- Requires root for full visibility  
- `apt update` output parsing is not fully reliable  
- Firewall detection assumes systemd  
- Static port risk classification  
- `ss` fallback (`ss -tuln`) loses process mapping  
- Large filesystems → SUID/SGID scan may be slow  

---

## 🔐 Security Best Practices

- Follow Principle of Least Privilege  
- Restrict report access (`chmod 600`)  
- Prefer SSH key authentication over passwords  
- Disable root login via SSH  
- Maintain active firewall with default deny policy  
- Periodically audit SUID/SGID binaries  
