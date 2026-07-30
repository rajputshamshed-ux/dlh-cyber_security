#!/bin/bash
# ==============================================================================
# BASELINE SNAPSHOT - MEDDEFENSE HEALTH SYSTEMS
# Task 0: The Baseline Snapshot
# Analyst: shamshed rajput
# Date: 30/07/2026
# Target: billing-srv-01 (Ubuntu 22.04.3 LTS)
# Purpose: Capture complete security state BEFORE any hardening.
# ==============================================================================

set -euo pipefail

OUTPUT_DIR="/var/log/meddefense/baseline"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
HOSTNAME=$(hostname -s)
JSON_OUTPUT="${OUTPUT_DIR}/${HOSTNAME}_baseline_${TIMESTAMP}.json"

mkdir -p "$OUTPUT_DIR"

# ------------------------------------------------------------------------------
# EXECUTIVE SUMMARY
# ------------------------------------------------------------------------------
print_summary() {
    echo ""
    echo "======================================================================"
    echo "  BASELINE SNAPSHOT COMPLETE - ${HOSTNAME}"
    echo "======================================================================"
    echo "  Hostname:            ${HOSTNAME}"
    echo "  OS:                  ${OS_VERSION}"
    echo "  Kernel:              ${KERNEL_VERSION}"
    echo "  Uptime:              ${UPTIME}"
    echo "  Running services:    ${SERVICE_COUNT}"
    echo "  Open ports (TCP):    ${PORT_COUNT}"
    echo "  SUID binaries:       ${SUID_COUNT}"
    echo "  SGID binaries:       ${SGID_COUNT}"
    echo "  World-writable files: ${WW_COUNT}"
    echo "  Local user accounts:  ${USER_COUNT}"
    echo "  Sudo group members:   ${SUDO_COUNT}"
    echo "----------------------------------------------------------------------"
    echo "  JSON output:         ${JSON_OUTPUT}"
    echo "======================================================================"
    echo ""
}

# ------------------------------------------------------------------------------
# SAFE COMMAND EXECUTION
# ------------------------------------------------------------------------------
safe_cmd() {
    "$@" 2>/dev/null || echo ""
}

# ------------------------------------------------------------------------------
# MAIN BASELINE COLLECTION
# ------------------------------------------------------------------------------

echo "[$(date '+%H:%M:%S')] Starting baseline snapshot for ${HOSTNAME}..."

# 1. SYSTEM IDENTIFICATION
echo "[$(date '+%H:%M:%S')] Collecting system identification..."
OS_VERSION=$(safe_cmd grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)
KERNEL_VERSION=$(uname -r)
UPTIME=$(safe_cmd uptime -p | sed 's/^up //')
ARCHITECTURE=$(uname -m)

# 2. RUNNING SERVICES
echo "[$(date '+%H:%M:%S')] Enumerating running services..."
SERVICES_LIST=$(systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null | awk '{print $1}' | sort || true)
SERVICE_COUNT=$(echo "${SERVICES_LIST}" | grep -c . || echo 0)

# 3. OPEN PORTS
echo "[$(date '+%H:%M:%S')] Enumerating open ports..."
OPEN_PORTS_TCP=$(ss -tlnp 2>/dev/null | awk 'NR>1 {print $4}' | awk -F: '{print $NF}' | sort -n | uniq || true)
PORT_COUNT=$(echo "${OPEN_PORTS_TCP}" | grep -c . || echo 0)

# 4. SUID BINARIES
echo "[$(date '+%H:%M:%S')] Finding SUID binaries..."
SUID_BINARIES=$(timeout 30 find /usr /bin /sbin /lib -perm -4000 -type f 2>/dev/null | sort || true)
SUID_COUNT=$(echo "${SUID_BINARIES}" | grep -c . || echo 0)

# 5. SGID BINARIES
echo "[$(date '+%H:%M:%S')] Finding SGID binaries..."
SGID_BINARIES=$(timeout 30 find /usr /bin /sbin /lib -perm -2000 -type f 2>/dev/null | sort || true)
SGID_COUNT=$(echo "${SGID_BINARIES}" | grep -c . || echo 0)

# 6. WORLD-WRITABLE FILES
echo "[$(date '+%H:%M:%S')] Finding world-writable files..."
WORLD_WRITABLE=$(timeout 30 find /etc /home /var /tmp -perm -0002 -type f 2>/dev/null | sort || true)
WW_COUNT=$(echo "${WORLD_WRITABLE}" | grep -c . || echo 0)

# 7. USER ACCOUNTS
echo "[$(date '+%H:%M:%S')] Enumerating user accounts..."
LOCAL_USERS=$(awk -F: '$3>=1000 && $3<65534 {print $1}' /etc/passwd 2>/dev/null | sort || true)
USER_COUNT=$(echo "${LOCAL_USERS}" | grep -c . || echo 0)
SUDO_MEMBERS=$(getent group sudo 2>/dev/null | cut -d: -f4 | tr ',' '\n' | sort || true)
SUDO_COUNT=$(echo "${SUDO_MEMBERS}" | grep -c . || echo 0)

# 8. SSH CONFIGURATION
echo "[$(date '+%H:%M:%S')] Capturing SSH configuration..."
SSH_PERMIT_ROOT=$(sshd -T 2>/dev/null | grep "^permitrootlogin " | awk '{print $2}' || echo "NOT_FOUND")
SSH_PASSWORD_AUTH=$(sshd -T 2>/dev/null | grep "^passwordauthentication " | awk '{print $2}' || echo "NOT_FOUND")
SSH_PUBKEY_AUTH=$(sshd -T 2>/dev/null | grep "^pubkeyauthentication " | awk '{print $2}' || echo "NOT_FOUND")
SSH_EMPTY_PASSWORDS=$(sshd -T 2>/dev/null | grep "^permitemptypasswords " | awk '{print $2}' || echo "NOT_FOUND")
SSH_MAX_AUTH_TRIES=$(sshd -T 2>/dev/null | grep "^maxauthtries " | awk '{print $2}' || echo "NOT_FOUND")

# 9. FIREWALL STATUS
echo "[$(date '+%H:%M:%S')] Capturing firewall status..."
UFW_ACTIVE="NO"
if command -v ufw >/dev/null 2>&1; then
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        UFW_ACTIVE="YES"
    fi
fi

# 10. APPARMOR STATUS
echo "[$(date '+%H:%M:%S')] Capturing AppArmor status..."
APPARMOR_COUNT=0
APPARMOR_ENFORCE=0
if command -v aa-status >/dev/null 2>&1; then
    APPARMOR_COUNT=$(aa-status 2>/dev/null | grep "profiles are loaded" | awk '{print $1}' || echo 0)
    APPARMOR_ENFORCE=$(aa-status 2>/dev/null | grep "profiles are in enforce mode" | awk '{print $1}' || echo 0)
fi

# ------------------------------------------------------------------------------
# BUILD JSON OUTPUT
# ------------------------------------------------------------------------------
echo "[$(date '+%H:%M:%S')] Building JSON output..."

cat > "${JSON_OUTPUT}" << EOF
{
  "metadata": {
    "script": "0-baseline_snapshot.sh",
    "analyst": "shamshed rajput",
    "date": "$(date -Iseconds)",
    "hostname": "${HOSTNAME}",
    "project": "2x00_locking_the_gates",
    "organization": "MedDefense Health Systems"
  },
  "system_identification": {
    "hostname": "${HOSTNAME}",
    "os_version": "${OS_VERSION}",
    "kernel_version": "${KERNEL_VERSION}",
    "architecture": "${ARCHITECTURE}",
    "uptime": "${UPTIME}"
  },
  "executive_summary": {
    "running_services": ${SERVICE_COUNT},
    "open_ports_tcp": ${PORT_COUNT},
    "suid_binaries": ${SUID_COUNT},
    "sgid_binaries": ${SGID_COUNT},
    "world_writable_files": ${WW_COUNT},
    "local_users": ${USER_COUNT},
    "sudo_members": ${SUDO_COUNT},
    "apparmor_profiles": ${APPARMOR_COUNT},
    "apparmor_enforce": ${APPARMOR_ENFORCE},
    "ufw_active": "${UFW_ACTIVE}"
  },
  "ssh_configuration": {
    "permit_root_login": "${SSH_PERMIT_ROOT}",
    "password_authentication": "${SSH_PASSWORD_AUTH}",
    "pubkey_authentication": "${SSH_PUBKEY_AUTH}",
    "permit_empty_passwords": "${SSH_EMPTY_PASSWORDS}",
    "max_auth_tries": "${SSH_MAX_AUTH_TRIES}"
  }
}
EOF

chmod 600 "${JSON_OUTPUT}"

# Print executive summary
print_summary

echo "[$(date '+%H:%M:%S')] JSON report saved to: ${JSON_OUTPUT}"
exit 0
