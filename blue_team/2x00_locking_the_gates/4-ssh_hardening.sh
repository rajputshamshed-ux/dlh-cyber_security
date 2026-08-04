#!/bin/bash
set -euo pipefail

# ==============================================================================
# SSH LOCKDOWN - MEDDEFENSE HEALTH SYSTEMS
# Task 4: The SSH Lockdown
# ==============================================================================
# Analyst: shamshed rajput
# Date: 30/07/2026
# Target: billing-srv-01, web-srv-01, log-srv-01
# Purpose: Eliminate password-based SSH authentication and reduce attack
#          surface. Addresses 1x02-F009 and Crimson Tide Phase 3.
# ==============================================================================

SSH_CONFIG="/etc/ssh/sshd_config"
SSH_BACKUP="/etc/ssh/sshd_config.bak.$(date +%Y%m%d_%H%M%S)"
BANNER_FILE="/etc/issue.net"
SETTINGS_APPLIED=0

# ------------------------------------------------------------------------------
# PRE-FLIGHT CHECKS
# ------------------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] This script must be run as root (sudo)."
    exit 1
fi

if [ ! -f "${SSH_CONFIG}" ]; then
    echo "[ERROR] SSH configuration file not found: ${SSH_CONFIG}"
    exit 1
fi

# ------------------------------------------------------------------------------
# BACKUP
# ------------------------------------------------------------------------------
echo "[*] Backing up ${SSH_CONFIG} to ${SSH_BACKUP}"
cp "${SSH_CONFIG}" "${SSH_BACKUP}"
chmod 600 "${SSH_BACKUP}"

# ------------------------------------------------------------------------------
# HELPER: Apply or update a setting
# ------------------------------------------------------------------------------
apply_setting() {
    local key="$1"
    local value="$2"
    local description="$3"

    echo "    ${description}"

    if grep -qi "^${key} " "${SSH_CONFIG}"; then
        # Update existing setting
        sed -i "s/^${key} .*/${key} ${value}/i" "${SSH_CONFIG}"
    else
        # Add new setting
        echo "${key} ${value}" >> "${SSH_CONFIG}"
    fi
    SETTINGS_APPLIED=$((SETTINGS_APPLIED + 1))
}

# ------------------------------------------------------------------------------
# APPLY HARDENING SETTINGS
# ------------------------------------------------------------------------------
echo "[*] Applying SSH hardening settings..."

# Prevent direct root login - addresses Crimson Tide Phase 3 (privilege escalation)
apply_setting "PermitRootLogin" "no" \
    "PermitRootLogin no"

# Disable password authentication - addresses 1x02-F009, Crimson Tide Phase 3 (SSH lateral movement with stolen credentials)
apply_setting "PasswordAuthentication" "no" \
    "PasswordAuthentication no"

# Block empty passwords - addresses 1x02-F009 (brute-force with empty credentials)
apply_setting "PermitEmptyPasswords" "no" \
    "PermitEmptyPasswords no"

# Disable X11 forwarding - addresses Crimson Tide Phase 4 (X11 tunneling for lateral movement)
apply_setting "X11Forwarding" "no" \
    "X11Forwarding no"

# Limit authentication attempts - addresses Crimson Tide Phase 2 (credential brute force)
apply_setting "MaxAuthTries" "3" \
    "MaxAuthTries 3"

# Idle timeout: 5 min interval × 2 max = 10 minutes - addresses Crimson Tide Phase 4 (persistent abandoned SSH sessions)
apply_setting "ClientAliveInterval" "300" \
    "ClientAliveInterval 300"
apply_setting "ClientAliveCountMax" "2" \
    "ClientAliveCountMax 2"

# Restrict SSH access to authorized administrators only
apply_setting "AllowUsers" "medadmin sysadmin" \
    "AllowUsers medadmin sysadmin"

# Enforce SSH Protocol 2 only - addresses CVE for SSHv1 weaknesses
apply_setting "Protocol" "2" \
    "Protocol 2"

# Limit login grace time to 60 seconds - reduces brute-force window
apply_setting "LoginGraceTime" "60" \
    "LoginGraceTime 60"

# Display legal banner before authentication - HIPAA compliance, user awareness
apply_setting "Banner" "${BANNER_FILE}" \
    "Banner ${BANNER_FILE}"

# ------------------------------------------------------------------------------
# CREATE BANNER FILE
# ------------------------------------------------------------------------------
echo "[*] Creating banner file: ${BANNER_FILE}"
cat > "${BANNER_FILE}" << 'BANNER_EOF'
======================================================================
  MEDDEFENSE HEALTH SYSTEMS - RESTRICTED ACCESS
======================================================================

  This system is for authorized MedDefense personnel only.
  All activities are monitored and recorded.
  Unauthorized access is prohibited and will be prosecuted
  under applicable federal and state laws (HIPAA, CFAA).

  By accessing this system, you consent to monitoring.

======================================================================
BANNER_EOF

chmod 644 "${BANNER_FILE}"

# ------------------------------------------------------------------------------
# VALIDATE CONFIGURATION
# ------------------------------------------------------------------------------
echo "[*] Validating SSH configuration..."
SSHD_TEST_OUTPUT=$(sshd -t 2>&1)
SSHD_TEST_EXIT=$?

if [ ${SSHD_TEST_EXIT} -eq 0 ]; then
    echo "    sshd -t: OK"
else
    echo "[ERROR] SSH configuration validation FAILED:"
    echo "${SSHD_TEST_OUTPUT}"
    echo ""
    echo "[*] Restoring backup: ${SSH_BACKUP}"
    cp "${SSH_BACKUP}" "${SSH_CONFIG}"
    echo "[*] Backup restored. Original configuration is intact."
    exit 1
fi

# ------------------------------------------------------------------------------
# RESTART SSH SERVICE
# ------------------------------------------------------------------------------
echo "[*] Restarting SSH service..."
systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null

# Verify service is running
if systemctl is-active --quiet sshd 2>/dev/null || systemctl is-active --quiet ssh 2>/dev/null; then
    echo "    ssh.service: active (running)"
else
    echo "[ERROR] SSH service failed to restart!"
    echo "[*] Restoring backup: ${SSH_BACKUP}"
    cp "${SSH_BACKUP}" "${SSH_CONFIG}"
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
    echo "[*] Backup restored. Service is back to original state."
    exit 1
fi

# ------------------------------------------------------------------------------
# SUMMARY
# ------------------------------------------------------------------------------
echo ""
echo "======================================================================"
echo "  SSH HARDENING COMPLETE"
echo "======================================================================"
echo "  Settings applied:     ${SETTINGS_APPLIED}"
echo "  Backup saved to:      ${SSH_BACKUP}"
echo "  SSH service:          running"
echo "======================================================================"
echo ""
echo "  Verification commands:"
echo "    sshd -T | grep -E 'permitrootlogin|passwordauth|maxauthtries'"
echo "    systemctl status sshd"
echo "======================================================================"

exit 0
