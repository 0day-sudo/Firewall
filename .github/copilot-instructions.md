# Copilot Instructions for the Firewall Project

## Project Overview
This project implements a Linux kernel firewall module and user-space utilities for rule management. The main components are:
- `firewall.c`, `firewall_backup.c`: Kernel module source files
- `Rules_and_Jasson/rules.c`: User-space rule parser and Netlink communication
- `Rules_and_Jasson/firewall_rules.json`: Example ruleset in JSON format

## Architecture & Data Flow
- **Rule Parsing:**
  - Rules are defined in JSON and parsed in `rules.c` using the Jansson library.
  - Parsed rules are stored in a linked list (`rule_node`).
  - Each rule includes protocol, IP/mask, port range, and action (ACCEPT/DROP/REJECT).
- **Kernel Communication:**
  - Rules are sent to the kernel via Netlink sockets (custom protocol 31).
  - The user-space tool serializes rules and sends them using `send_rules_to_kernel()`.
- **Error Handling:**
  - Parsing errors are tracked per rule (`result_code`) and reported with detailed messages.
  - Invalid rules are still added to the list for diagnostics.

## Build & Run
- **Build Kernel Module:**
  - Use the provided `Makefile` in the root directory: `make`
- **Run User-Space Tool:**
  - Compile `rules.c` (see `gcc.txt` for example flags)
  - Run: `./rules.out Rules_and_Jasson/firewall_rules.json`
- **Debugging:**
  - Parsing progress and errors are printed to stdout/stderr.
  - After parsing, rules are printed and sent to the kernel.
  - Use `dmesg` or kernel logs to debug kernel-side issues.

## Patterns & Conventions
- **Rule Structure:** See `firewall_rule_format` in `rules.c` for all fields.
- **Error Codes:** Negative values for specific parse errors, zero for success.
- **Linked List Management:** Always use provided helper functions (`add_rule_to_list`, `clear_list`).
- **Netlink Protocol:** Custom protocol number (31) must match in kernel and user-space.
- **Port/IP Handling:**
  - "ANY" is represented as 0 (IP) or 0-65535 (port).
  - All addresses/ports are converted to network byte order before sending to kernel.

## External Dependencies
- Jansson (JSON parsing)
- Linux Netlink headers

## Key Files
- `firewall.c`, `firewall_backup.c`: Kernel logic
- `Rules_and_Jasson/rules.c`: User-space rule management
- `Rules_and_Jasson/firewall_rules.json`: Example rules
- `Makefile`, `gcc.txt`: Build instructions

## Example Workflow
1. Edit `firewall_rules.json` to define rules.
2. Build kernel module: `make`
3. Compile and run user-space tool: `gcc Rules_and_Jasson/rules.c -o rules.out -ljansson` then `./rules.out Rules_and_Jasson/firewall_rules.json`
4. Check output and kernel logs for errors.

---

If any section is unclear or missing details, please specify which part you'd like to improve or expand.
