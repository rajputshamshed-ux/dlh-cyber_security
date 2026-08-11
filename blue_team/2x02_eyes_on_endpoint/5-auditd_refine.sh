#!/bin/bash
set -euo pipefail

# ==============================================================================
# AUDITD RULE REFINEMENT - MEDDEFENSE HEALTH SYSTEMS
# Task 5: auditd Rule Refinement
# ==============================================================================
#
# WHAT THIS SCRIPT DOES:
#   Loads the current auditd rules, adds five detection‑focused rules
#   (process execution, network socket creation, SSH key access, cron
#   directory modifications, sudo configuration access), loads the updated
#   rules, and validates each new rule by triggering a test action.
#
# WHY:
#   The original auditd rules (Task 10, 2x00) covered identity files and
#   privilege escalation, but missed critical Linux visibility:
#   - execve = Linux equivalent of Sysmon EID 1
#   - socket/connect = Linux equivalent of Sysmon EID 3
#   - SSH keys, cron, sudoers = persistence & privilege targets
#   This script closes those gaps to match the telemetry depth of Sysmon.
#
# WHEN TO USE:
#   After the initial auditd deployment (2x00 Task 10). Before the
#   Linux telemetry export and SOC handoff.
#
# AUTHOR: shamshed rajput
# DATE:   30/07/2026
# TARGET: billing-srv-01 (Ubuntu 22.04 LTS)
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. Check root and auditd availability
# ------------------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] This script must be run as root (sudo)."
    exit 1
fi

if ! command -v auditctl >/dev/null 2>&1; then
    echo "[ERROR] auditd is not installed. Please run Task 10 first."
    exit 1
fi

# ------------------------------------------------------------------------------
# 2. Current rule count
# ------------------------------------------------------------------------------
CURRENT_RULES=$(auditctl -l 2>/dev/null | wc -l)
echo "[*] Current auditd rules: ${CURRENT_RULES}"

# ------------------------------------------------------------------------------
# 3. Define new rules and add them if not present
# ------------------------------------------------------------------------------
RULES_FILE="/etc/audit/rules.d/meddefense.rules"
ADDED=0

echo "[*] Adding detection-focused rules..."

# Helper function to append a rule only if it doesn't already exist
add_rule() {
    local rule="$1"
    local description="$2"
    if ! grep -qF "${rule}" "${RULES_FILE}" 2>/dev/null; then
        echo "${rule}" >> "${RULES_FILE}"
        echo "    ${description}               [ADDED]"
        ADDED=$((ADDED + 1))
    else
        echo "    ${description}               [ALREADY PRESENT]"
    fi
}

# 3a. Process execution via execve (Linux equivalent of Sysmon EID 1)
add_rule "-a always,exit -F arch=b64 -S execve -k process_exec" \
         "execve syscall tracking"

# 3b. Network socket creation (socket + connect)
add_rule "-a always,exit -F arch=b64 -S socket -S connect -k network_connect" \
         "socket/connect syscall tracking"

# 3c. SSH key file access
add_rule "-w /home/*/.ssh/ -p rwa -k ssh_keys" \
         "SSH key file monitoring"

# 3d. Cron directory modifications
add_rule "-w /etc/cron.d/ -p wa -k cron_persist" \
         "Cron directory monitoring (/etc/cron.d)"
add_rule "-w /var/spool/cron/ -p wa -k cron_persist" \
         "Cron directory monitoring (/var/spool/cron)"

# 3e. sudo configuration access
add_rule "-w /etc/sudoers.d/ -p wa -k sudoers" \
         "sudoers.d monitoring"

# ------------------------------------------------------------------------------
# 4. Load updated rules
# ------------------------------------------------------------------------------
echo "[*] Loading rules... augenrules --load"
augenrules --load >/dev/null 2>&1
echo "    augenrules --load: OK"

# Total rules after update
NEW_TOTAL=$(auditctl -l 2>/dev/null | wc -l)
echo "[*] Total rules: ${NEW_TOTAL}"

# ------------------------------------------------------------------------------
# 5. Validate each new rule with a controlled trigger
# ------------------------------------------------------------------------------
PASS=0
FAIL=0

validate() {
    local test_name="$1"
    local audit_key="$2"
    local trigger="$3"
    local search_pattern="$4"   # optional extra pattern for ausearch

    echo -n "    ${test_name}: "
    # Record time before action
    local before
    before=$(date +%s)

    # Execute the trigger command (suppress output)
    eval "${trigger}" >/dev/null 2>&1 || true

    # Give auditd a moment to flush
    sleep 1

    # Search for the event using the key
    local result
    result=$(ausearch -ts "$(date -d @"${before}" '+%H:%M:%S' 2>/dev/null || true)" -k "${audit_key}" 2>/dev/null | head -1)
    if [ -n "${result}" ]; then
        echo "[CAPTURED]"
        PASS=$((PASS + 1))
    else
        echo "[MISSED]"
        FAIL=$((FAIL + 1))
    fi
}

echo "[*] Validating new rules..."

# 5a. execve
validate "execve: ran /usr/bin/id" \
         "process_exec" \
         "/usr/bin/id" \
         "execve"

# 5b. socket/connect
# Use curl to localhost to generate a socket call
validate "socket: curl localhost" \
         "network_connect" \
         "curl -s --max-time 2 http://localhost/ >/dev/null 2>&1 || true"

# 5c. SSH keys
# Create a temporary test file under ~/.ssh/ (ensure directory exists)
SSH_TEST_DIR="/home/${SUDO_USER:-analyst}/.ssh"
mkdir -p "${SSH_TEST_DIR}"
validate "ssh_keys: touch ${SSH_TEST_DIR}/test" \
         "ssh_keys" \
         "touch ${SSH_TEST_DIR}/test && rm -f ${SSH_TEST_DIR}/test"

# 5d. cron
# Create a temporary file in /etc/cron.d/ and immediately remove it
validate "cron: touch /etc/cron.d/test" \
         "cron_persist" \
         "touch /etc/cron.d/test && rm -f /etc/cron.d/test"

# 5e. sudoers
validate "sudoers: touch /etc/sudoers.d/test" \
         "sudoers" \
         "touch /etc/sudoers.d/test && rm -f /etc/sudoers.d/test"

# ------------------------------------------------------------------------------
# 6. Summary
# ------------------------------------------------------------------------------
TOTAL_VAL=$((PASS + FAIL))
echo ""
echo "Rules added: ${ADDED} | Validation: ${PASS}/${TOTAL_VAL} PASS"

exit 0
