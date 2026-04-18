# Linux Security Audit Tool

⚠️ **Status:** Alpha – Active Development
📌 **Current Version:** `v0.4.1-alpha`

A modular Bash-based tool designed to audit the security posture of Linux systems. It detects misconfigurations, weak hardening, and potential privilege escalation vectors, aligning checks with **CIS Benchmarks** and **MITRE ATT&CK** techniques.

---

## 🎯 Objective

Provide a fast, local, and dependency-light security audit that highlights:

* Privilege escalation risks
* Misconfigured services
* Weak access controls
* Network exposure
* Missing security controls

---

## 🚀 Implemented Features

### 1. UID 0 User Detection

Detects accounts other than `root` with UID 0.

* **Risk:** Privilege escalation / persistence
* **MITRE ATT&CK:** T1078 (Valid Accounts)

---

### 2. World-Writable Files Detection

Searches for files with `-perm -0002`.

* Excludes pseudo-filesystems:

  * `/proc`, `/sys`, `/dev`, `/run`, `/tmp`, `/var/tmp`
* **Risk:** Unauthorized modification → privilege escalation
* **MITRE ATT&CK:** T1222 (File Permissions Weakness)

---

### 3. SSH Configuration Audit

Uses `sshd -T` (effective config) instead of raw parsing.

Checks:

* `PermitRootLogin`
* `PasswordAuthentication`
* `MaxAuthTries`
* `X11Forwarding`

Also:

* Detects if `sshd` exists

* Validates service state via `systemctl`

* **Risk:** Remote unauthorized access

* **MITRE ATT&CK:** T1021.004 (SSH)

---

### 4. Open Ports Enumeration

Uses:

```bash
ss -tulpn
```

Categorizes ports:

| Risk Level | Ports                                          |
| ---------- | ---------------------------------------------- |
| High       | 21, 22, 23, 445, 3389, 3306, 5432, 6379, 27017 |
| Medium     | 25, 53, 8080                                   |

* **Risk:** Exposed services / attack surface
* **MITRE ATT&CK:** T1046 (Network Service Discovery)

---

### 5. Firewall Status Detection

Detects installation and state of:

* `ufw`
* `firewalld`
* `nftables`
* `iptables`

Logic:

* **CRITICAL** → no firewall installed

* **CRITICAL** → installed but none active

* **Risk:** Unfiltered network access

* **MITRE ATT&CK:** T1562 (Impair Defenses)

---

### 6. SUID/SGID Binaries Audit

Searches:

```bash
find / -type f -perm /6000
```

Features:

* Excludes pseudo-filesystems

* Uses whitelist of legitimate binaries

* Flags:

  * Non-root owned binaries
  * Files in `/tmp` or `/var/tmp`

* Outputs structured table:

  * Path
  * Type (SUID/SGID)
  * Owner
  * Status

* **Risk:** Privilege escalation

* **MITRE ATT&CK:** T1548 (Abuse Elevation Control Mechanism)

---

### 7. OS Detection

Parses:

```bash
/etc/os-release
```

Supports:

* Debian-based
* RHEL-based

Sets:

```bash
OS_FAMILY=debian | rhel | unknown
```

---

### 8. Security Updates Check

Depends on `OS_FAMILY`:

| OS Family | Command            |
| --------- | ------------------ |
| Debian    | `apt update`       |
| RHEL      | `dnf check-update` |

* Detects pending updates

* Flags inability to determine status

* **Risk:** Known vulnerabilities (unpatched CVEs)

* **MITRE ATT&CK:** T1190 (Exploit Public-Facing Application)

---

### 9. Report Generation

#### Terminal Output

* Structured sections
* Color-coded:

  * OK (green)
  * WARNING (yellow)
  * CRITICAL (red)
  * INFO (cyan)

#### File Output

Generated in:

```bash
./reports/
```

Files:

* `result_<timestamp>.txt`
* `hash_result_<timestamp>.txt`

Security controls:

```bash
chmod 700 reports/
chmod 600 report file
sha256sum integrity hash
```

---

## ▶️ Usage

```bash
git clone https://github.com/rodrigo-tripa/linux-security-audit-tool.git
cd linux-security-audit-tool
chmod +x audit.sh
sudo ./audit.sh
```

Verbose output:

```bash
sudo ./audit.sh -v
```

---

## 📋 Requirements

* Linux (Debian/Ubuntu or RHEL-based)
* Bash 4+
* Root privileges (recommended)
* `systemctl`
* `ss` (iproute2)
* `find`, `stat`, `sha256sum`
* `sshd` (optional, for SSH checks)

---

## ⚠️ Known Limitations

* Requires root for full visibility (filesystem + ports)
* `apt update` may generate noise depending on repo state
* Firewall detection assumes systemd-based systems
* Port risk classification is static (can be improved)
* Using the -v argument for verbose mode might generate output errors if "SUID/SGID BIRNARIES" is enabled
