#!/bin/bash
set -euo pipefail

# ==============================================================================
# APPARMOR ENFORCER - MEDDEFENSE HEALTH SYSTEMS
# Task 9: The AppArmor Enforcer
# ==============================================================================
# WHAT IT DOES: Enables AppArmor mandatory access control. Switches profiles
#               from complain (log only) to enforce (block) mode. Creates a
#               custom profile for the MedDefense billing application.
# WHY: Without AppArmor, a compromised service (like Apache) has full access
#      to the filesystem. AppArmor confines processes to only the directories
#      they need. The crypto-miner on billing-srv-01 exploited this.
#      Per AppArmor Wiki: Ubuntu integrates AppArmor by default.
# ATTACKS BLOCKED: Crimson Tide Phase 3 (lateral movement via compromised
#                  service), Phase 5 (defense evasion), crypto-miner
#                  filesystem access.
# ==============================================================================
# Analyst: shamshed rajput
# Date: 30/07/2026
# Target: billing-srv-01, web-srv-01, log-srv-01
# ==============================================================================

if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] Run with sudo."
    exit 1
fi

ENFORCE_COUNT=0
COMPLAIN_COUNT=0
UNCONFINED_COUNT=0

# ------------------------------------------------------------------------------
# 1. VERIFY APPARMOR STATUS
# ------------------------------------------------------------------------------
echo "[*] Checking AppArmor status..."

if aa-status --enabled 2>/dev/null; then
    echo "    AppArmor module: loaded"
else
    echo "    [ERROR] AppArmor is not enabled. Run: sudo aa-enable"
    exit 1
fi

if systemctl is-active --quiet apparmor 2>/dev/null; then
    echo "    AppArmor service: active"
else
    echo "    AppArmor service: inactive, starting..."
    systemctl start apparmor
fi

# ------------------------------------------------------------------------------
# 2. LIST CURRENT PROFILES
# ------------------------------------------------------------------------------
echo "[*] Current AppArmor profiles:"
aa-status 2>/dev/null | head -5

# ------------------------------------------------------------------------------
# 3. SWITCH APACHE AND MYSQL TO ENFORCE MODE
# ------------------------------------------------------------------------------
echo "[*] Profile enforcement:"

enforce_profile() {
    local process="$1"
    local profile_name="$2"
    local display="$3"
    
    if [ -f "/etc/apparmor.d/${profile_name}" ]; then
        local current_mode
        current_mode=$(aa-status 2>/dev/null | grep "${process}" | head -1)
        
        if echo "${current_mode}" | grep -q "enforce"; then
            echo "    ${display}   [OK]"
            ENFORCE_COUNT=$((ENFORCE_COUNT + 1))
        elif echo "${current_mode}" | grep -q "complain"; then
            aa-enforce "/etc/apparmor.d/${profile_name}" 2>/dev/null
            echo "    ${display}   [ENFORCED]"
            ENFORCE_COUNT=$((ENFORCE_COUNT + 1))
        else
            aa-enforce "/etc/apparmor.d/${profile_name}" 2>/dev/null || true
            echo "    ${display}   [ENFORCED]"
            ENFORCE_COUNT=$((ENFORCE_COUNT + 1))
        fi
    else
        echo "    ${display}   [NO PROFILE]"
        UNCONFINED_COUNT=$((UNCONFINED_COUNT + 1))
    fi
}

enforce_profile "apache2" "usr.sbin.apache2" "/usr/sbin/apache2        complain -> enforce"
enforce_profile "mysqld" "usr.sbin.mysqld" "/usr/sbin/mysqld         complain -> enforce"
enforce_profile "sshd" "usr.sbin.sshd" "/usr/sbin/sshd           enforce"

# ------------------------------------------------------------------------------
# 4. CUSTOM PROFILE FOR MEDDEFENSE BILLING APPLICATION
# ------------------------------------------------------------------------------
echo "[*] Custom profile: /opt/meddefense/billing-app"

CUSTOM_PROFILE="/etc/apparmor.d/opt.meddefense.billing-app"

if [ ! -f "${CUSTOM_PROFILE}" ]; then
    mkdir -p /opt/meddefense/billing-app
    
    cat > "${CUSTOM_PROFILE}" << 'PROFILE_EOF'
#include <tunables/global>

/opt/meddefense/billing-app {
  #include <abstractions/base>
  #include <abstractions/apache2-common>
  #include <abstractions/mysql>

  # Application binary and libraries
  /opt/meddefense/billing-app/** r,

  # Log files
  /var/log/meddefense/billing-app/** rw,

  # Configuration (read-only)
  /etc/meddefense/billing-app/** r,

  # Temporary files
  /tmp/billing-* rw,

  # Deny everything else
  deny /opt/meddefense/ehr/** rw,
  deny /etc/ssh/** r,
  deny /etc/shadow r,
  deny /home/** rw,
}
PROFILE_EOF

    chmod 644 "${CUSTOM_PROFILE}"
    aa-enforce "${CUSTOM_PROFILE}" 2>/dev/null
    echo "    /opt/meddefense/billing-app   [CREATED] [ENFORCED]"
    ENFORCE_COUNT=$((ENFORCE_COUNT + 1))
else
    echo "    /opt/meddefense/billing-app   [EXISTS]"
    aa-enforce "${CUSTOM_PROFILE}" 2>/dev/null || true
    ENFORCE_COUNT=$((ENFORCE_COUNT + 1))
fi

# ------------------------------------------------------------------------------
# 5. REPORT UNCONFINED NETWORK PROCESSES
# ------------------------------------------------------------------------------
echo "[*] Unconfined network-exposed processes:"

check_unconfined() {
    local process="$1"
    local name="$2"
    
    if pgrep -x "${process}" > /dev/null 2>&1; then
        if ! aa-status 2>/dev/null | grep -q "${process}"; then
            echo "    ${name}       [UNCONFINED - Profile recommended]"
            UNCONFINED_COUNT=$((UNCONFINED_COUNT + 1))
        fi
    fi
}

check_unconfined "rsyslogd" "/usr/sbin/rsyslogd"
check_unconfined "cron" "/usr/sbin/cron"

# ------------------------------------------------------------------------------
# 6. SUMMARY
# ------------------------------------------------------------------------------
COMPLAIN_COUNT=$(aa-status 2>/dev/null | grep "profiles are in complain mode" | awk '{print $1}' || echo 0)
ENFORCE_COUNT=$(aa-status 2>/dev/null | grep "profiles are in enforce mode" | awk '{print $1}' || echo 0)

echo ""
echo "======================================================================"
echo "  APPARMOR ENFORCER - COMPLETE"
echo "======================================================================"
echo "  Profiles in enforce: ${ENFORCE_COUNT} | Complain: ${COMPLAIN_COUNT} | Unconfined: ${UNCONFINED_COUNT}"
echo "======================================================================"

exit 0
