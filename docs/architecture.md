# Architecture

## Overview
Modular Bash tool for Linux security auditing based on CIS Benchmarks.

## Structure
audit.sh          # Main script
├── check_root()                    # Verify root privileges
├── check_uid_zero_users()          # Detect UID 0 accounts
├── check_world_writable_files()    # Find writable files
├── check_ssh_configuration()       # Audit SSH settings
├── check_open_ports()              # List listening ports
├── check_firewall_status()         # Check firewall state
├── check_firewall_status()         # check_suid_sgid_binaries
└── generate_report_file()          # Create timestamped report

## Output
- `reports/result_YYYY-MM-DD_HH-MM-SS.txt` - Audit results
- `reports/hash_result_YYYY-MM-DD_HH-MM-SS.txt` - SHA-256 integrity hash

## Adding New Checks
1. Create function: `check_<name>()`
2. Add to `generate_report()`
3. Use severity levels: OK, INFO, WARNING, CRITICAL