# Linux Security Audit Tool

![Version](https://img.shields.io/badge/version-0.4.5.2--alpha-orange)
![License](https://img.shields.io/badge/license-MIT-blue)
![Bash](https://img.shields.io/badge/bash-4%2B-green)

Shell script for security auditing on Linux systems. Identifies misconfigurations, privilege escalation vectors, and hardening failures.

---

## Objective

Lightweight offline tool for quick security audits on Linux systems, focused on:

- Detection of suspicious privileged accounts
- Files with dangerous permissions
- Insecure SSH configurations
- High-risk open ports
- SUID/SGID binaries
- Sudoers configuration
- Orphaned files
- Firewall and update status

---

## Features

### 1. **UID 0 Accounts**
Detects non-root accounts with UID 0 (full privileges).

```bash
awk -F: '$3 == 0 { print $1 }' /etc/passwd | awk '!/root/'
```

**Risk:** Backdoor accounts, persistence after compromise.

---

### 2. **World-Writable Files**
Searches for files writable by any user on the system.

```bash
find / -xdev -type f -perm -0002
```

Excludes: `/proc`, `/sys`, `/dev`, `/run`, `/tmp`, `/var/tmp`

**Risk:** Code injection, modification of binaries or critical configs.

---

### 3. **SSH Audit**
Validates critical OpenSSH configurations using `sshd -T`:

| Directive               | Secure Value           |
|-------------------------|------------------------|
| `PermitRootLogin`       | `no` / `prohibit-password` |
| `PasswordAuthentication`| `no`                   |
| `MaxAuthTries`          | ≤ 4                    |
| `X11Forwarding`         | `no`                   |

Also detects:
- Presence of `sshd` daemon
- Service state (`systemctl`)
- Support for `ssh` and `sshd` as unit names

**Risk:** Brute-force, unauthorized remote access, lateral movement.

---

### 4. **Open Ports**
Enumerates TCP/UDP ports with `ss -tulpn`.

**Risk Classification:**

| Level  | Ports                                                                  |
|--------|------------------------------------------------------------------------|
| High   | 21, 22, 23, 139, 445, 3389, 5900, 3306, 5432, 6379, 27017, 11211     |
| Medium | 25, 53, 8080                                                           |

**Risk:** Increased attack surface, unnecessarily exposed services.

---

### 5. **Firewall Status**
Checks active firewalls:

- `ufw`
- `firewalld`
- `nftables`
- `iptables`

**Logic:**
- No firewall installed → `CRITICAL`
- Firewall installed but inactive → `CRITICAL`

**Risk:** Unfiltered traffic, direct service exposure.

---

### 6. **SUID/SGID Binaries**
Searches for binaries with SUID/SGID bits:

```bash
find / -xdev -type f -perm /6000
```

**Analysis:**
- Compares against whitelist of known binaries
- Flags binaries in `/tmp` or `/var/tmp`
- Detects non-root ownership

**Output Format:**

| Field  | Description          |
|--------|----------------------|
| PATH   | Binary path          |
| TYPE   | SUID / SGID          |
| OWNER  | File owner           |
| STATUS | OK / WARNING         |

**Risk:** Privilege escalation via local exploits.

---

### 7. **OS Detection**
Parses `/etc/os-release` to identify family:

- `debian` → Debian, Ubuntu
- `rhel` → RHEL, CentOS, Rocky, AlmaLinux, Fedora
- `unknown` → Other distros

---

### 8. **Security Updates**
Checks for pending updates:

| OS Family | Command           |
|-----------|-------------------|
| Debian    | `apt update`      |
| RHEL      | `dnf check-update`|

**Limitation:** Output parsing can be inconsistent.

**Risk:** Known vulnerabilities not patched.

---

### 9. **Users Without Password**
Detects accounts in `/etc/shadow` with empty password field:

```bash
awk -F: '$2 == "" { print $1 }' /etc/shadow
```

**Risk:** Login without authentication, control bypass.

---

### 10. **Orphaned Files**
Searches for files without valid user or group owner in:

- `/etc`, `/home`, `/root`, `/var`
- `/usr/local`, `/opt`, `/srv`
- `/tmp`, `/var/tmp`

**Separated by type:**
- `-nouser` (no owner)
- `-nogroup` (no group)

**Risk:** Remnants of deleted accounts, potential payload persistence.

---

### 11. **Sudoers Audit**
Analyzes `/etc/sudoers` and files in `/etc/sudoers.d/` for dangerous configurations.

**Checks:**
- `NOPASSWD`: Users who can execute commands as root without a password.
- Broad `ALL` permissions: Users or groups with `ALL=(ALL:ALL) ALL` (excluding root).

**Risk:** Privilege escalation, unauthorized administrative actions.

---

### 12. **Report Generation**

**Terminal:**
- Colored output (OK, WARNING, CRITICAL, INFO)
- Hierarchical structure

**File:**

Directory: `./reports/`

Generated files:
- `result_YYYY-MM-DD_HH-MM-SS.txt` (clean output)
- `hash_result_YYYY-MM-DD_HH-MM-SS.txt` (SHA256)

**Security:**
- `chmod 700 reports/`
- `chmod 600` on reports
- SHA256 hash for integrity

---

## Installation

```bash
git clone https://github.com/rodrigo-tripa/linux-security-audit-tool.git
cd linux-security-audit-tool
chmod +x audit.sh
```

---

## Usage

### Silent Mode
Generates report file only:

```bash
sudo ./audit.sh
```

### Verbose Mode
Terminal output + file:

```bash
sudo ./audit.sh -v
```

**Reports saved in:** `./reports/result_<timestamp>.txt`

---

## Requirements

| Component      | Required? | Notes                          |
|----------------|-----------|--------------------------------|
| Linux          | ✅        | Debian/Ubuntu or RHEL-based    |
| Bash           | ✅        | Version 4+                     |
| Root           | ✅        | Recommended for full visibility|
| `systemctl`    | ✅        | For service checks             |
| `ss`           | ✅        | Package `iproute2`             |
| `find`, `stat` | ✅        | Coreutils                      |
| `sha256sum`    | ✅        | Coreutils                      |
| `sshd`         | ⚠️        | Optional (skipped if not installed)|

---

## Known Limitations

### Permissions
- Scans without root will have reduced visibility
- Some checks may fail (`/etc/shadow`, etc)

### Performance
- SUID/SGID scan can be slow on large systems
- World-writable scan uses `-xdev` (doesn't cross mount points)

### Parsing
- `apt update` and `dnf check-update` can have unstable outputs
- Depends on specific text format

### Firewall
- Assumes systemd for state verification
- May not detect custom firewalls

### Ports
- Risk classification is static
- `ss -tulpn` requires root to see PIDs
- Fallback `ss -tuln` loses process mapping

---

## Roadmap

- [ ] Support for kernel logs (dmesg)
- [ ] Audit of suspicious cron jobs
- [ ] Verification of loaded kernel modules
- [ ] SELinux/AppArmor status check
- [ ] Scan for known backdoors (rootkits)
- [ ] JSON/CSV report output for parsing
- [ ] Diff mode (compare 2 reports)

---

## Tool Security

### Reports
- Protected directory (`700`)
- Files with `600` (owner-only)
- SHA256 hash to verify integrity

### Recommendations
- Don't share reports without sanitizing hostnames/IPs
- Delete old reports (`./reports/`)
- Run in controlled environment for testing

---

## Contributing

Pull requests are welcome. For large changes:

1. Open an issue first to discuss
2. Test on both Debian and RHEL-based if possible
3. Keep code comments in English
4. Follow existing output style

---

## License

MIT License - see [LICENSE](LICENSE)

---

## Disclaimer

This tool is for auditing **legitimate** systems where you have authorization. I'm not responsible for misuse.

---

## Contact

**GitHub:** [Rodrigo-Tripa](https://github.com/rodrigo-tripa)  
**Repo:** [linux-security-audit-tool](https://github.com/rodrigo-tripa/linux-security-audit-tool)
