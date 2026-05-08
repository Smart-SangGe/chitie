# GEMINI.md

This file provides guidance to Gemini cli when working with code in this repository.

## Project Overview

**chitie (赤铁)** is a Rust reimplementation of [LinPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS), a privilege escalation enumeration tool used in penetration testing. This is a defensive security tool for legitimate security assessments.

### Project Goals

1. Full compatibility with LinPEAS command-line arguments
2. Significant performance improvement (original takes 4-10 minutes)
3. Maintain readable output formatting with color-coded results
4. Implement robust report export functionality
5. Small binary size
6. Single-file deployment with no external dependencies

### Key Features to Implement

Based on LinPEAS functionality:
- System enumeration: kernel version, OS info, users, groups, sudo permissions
- Process monitoring and enumeration
- File permission checks (SUID/SGID files, writable files/folders)
- Known vulnerability detection
- Password search and API key regex scanning
- Network configuration and services
- Cron jobs and scheduled tasks
- Container/virtualization detection

## Build and Development Commands

```bash
# Build the project
cargo build

# Build optimized release binary
cargo build --release

# Run the tool
cargo run

# Run with arguments
cargo run -- [args]

# Run tests
cargo test

# Check code without building
cargo check

# Format code
cargo fmt

# Run clippy linter
cargo clippy
```

**IMPORTANT**: When checking compilation during development, ALWAYS use `cargo check` ONLY. NEVER use `cargo build` or `cargo build --release` unless explicitly requested by the user. This is much faster and sufficient for validation.

## Architecture Notes

- **Language**: Rust (edition 2024)
- **Deployment model**: Single static binary, zero external dependencies
- **Target use case**: Fast privilege escalation enumeration on Linux systems during penetration testing

The project is in early stages with minimal implementation. The core challenge will be reimplementing LinPEAS's extensive system checks in Rust while maintaining performance and compatibility.

## LinPEAS Source Code Reference

The LinPEAS source code is located in `linPEAS/builder/linpeas_parts/` directory:

```
linPEAS/builder/linpeas_parts/
├── 1_system_information/     # System checks (kernel, sudo, etc.)
├── 2_container/              # Container detection
├── 3_cloud/                  # Cloud environment detection
├── 4_procs_crons_timers_srvcs_sockets/  # Process and service checks
├── 5_network_information/    # Network configuration
├── 6_users_information/      # User and group enumeration
├── 7_software_information/   # Installed software checks
├── 8_interesting_perms_files/  # Permission checks
├── 9_interesting_files/      # File searches
├── 10_api_keys_regex/        # Secret scanning
├── functions/                # Helper functions
├── variables/                # Variable definitions (regex patterns, etc.)
└── linpeas_base/            # Base scripts
```

### Implementation Workflow

**IMPORTANT**: When implementing any check function, ALWAYS follow these steps:

1. **Read the original LinPEAS implementation** from `linPEAS/builder/linpeas_parts/` directory
2. **Understand the check logic**:
   - What files/commands it reads
   - What patterns it searches for
   - How it highlights vulnerabilities
3. **Check variable definitions** in `linPEAS/builder/linpeas_parts/variables/` for regex patterns
4. **Implement in Rust** using file system operations (avoid external commands when possible)
5. **Test the implementation** against the original

### Example: Implementing a Check

For `sudo_version` check:
1. Read: `linPEAS/builder/linpeas_parts/1_system_information/2_Sudo_version.sh`
2. Read: `linPEAS/builder/linpeas_parts/variables/sudovB.sh` for vulnerable version patterns
3. Implement using the regex pattern: `[01].[012345678].[0-9]+|1.9.[01234][^0-9]|1.9.[01234]$|1.9.5p1|1\.9\.[6-9]|1\.9\.1[0-7]`

## Code Style Guidelines

- **NO EMOJIS**: Never use emojis in any output, code, or messages. Use plain text only.
- Use pure Rust file I/O operations when possible instead of external commands
- Follow LinPEAS's regex patterns and vulnerability detection logic exactly
- Keep functions focused on single responsibility
- Use descriptive variable names in English
