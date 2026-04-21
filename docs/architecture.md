# Architecture

## Overview
Modular Bash tool for Linux security auditing focused on misconfigurations, privilege escalation, and system hardening.

## Structure
audit.sh          # Main script
├── detect_os()                       # Identify OS family (debian/rhel)
├── check_uid_zero_users()            # Detect UID 0 accounts
├── check_world_writable_files()      # Find world-writable files
├── check_ssh_configuration()         # Audit SSH settings
├── check_open_ports()                # List listening ports
├── check_firewall_status()           # Check firewall state
├── check_suid_sgid_binaries()        # Audit SUID/SGID binaries
├── check_security_updates()          # Check for pending updates
├── check_no_pass_users()             # Check for users without a pass
├── check_orphned_files()             # Check for files without:
|   ├── check_orphned_files_user()    # User owner
|   └── check_orphned_files_group()   # Group owner
├── generate_report()                 # Aggregate all checks
└── generate_report_file()            # Save report + hash

## Output
- `reports/result_YYYY-MM-DD_HH-MM-SS.txt` - Audit results  
- `reports/hash_result_YYYY-MM-DD_HH-MM-SS.txt` - SHA-256 integrity hash  

## Adding New Checks
1. Create function: `check_<name>()`  
2. Add to `generate_report()`  
3. Use severity levels: OK, INFO, HELP, WARNING, CRITICAL  
