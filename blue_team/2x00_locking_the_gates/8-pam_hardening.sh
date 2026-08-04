#!/bin/bash
set -euo pipefail

# ==============================================================================
# PAM FORTRESS - MEDDEFENSE HEALTH SYSTEMS
# Task 8: The PAM Fortress
# ==============================================================================
# WHAT IT DOES: Hardens Linux authentication with strong password policies,
#               account lockout after failed attempts, and password history.
# WHY: Crimson Tide uses harvested credentials (Phase 2) and Kerberoasting
#      (Phase 3) for lateral movement. Weak passwords are the root cause.
#      PAM enforces password quality and locks accounts after brute-force.
# ATTACKS BLOCKED: Crimson Tide Phase 2 (credential brute-force),
#                  Phase 3 (lateral movement with weak passwords),
#                  1x02-F009 (SSH brute-force with no lockout).
# ==============================================================================
# Analyst: shamshed rajput
# Date: 30/07/2026
# Target: billing-srv-01, web-srv-01, log-srv-01
# ==============================================================================

if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] Run with sudo."
    exit 1
fi

PWQUALITY_CONF="/etc/security/pwquality.conf"
FAILLOCK_CONF="/etc/security/faillock.conf"
LOGIN_DEFS="/etc/login.defs"
PASS=0
FAIL=0

# ------------------------------------------------------------------------------
# 1. INSTALL libpam-pwquality
# ------------------------------------------------------------------------------
echo "[*] Checking libpam-pwquality..."
if dpkg -l libpam-pwquality 2>/dev/null | grep -q "^ii"; then
    VERSION=$(dpkg -l libpam-pwquality 2>/dev/null | awk 'NR==6 {print $3}')
    echo "    Already installed: libpam-pwquality ${VERSION}"
else
    echo "    Installing libpam-pwquality..."
    apt-get update -qq && apt-get install -y -qq libpam-pwquality
fi

# ------------------------------------------------------------------------------
# 2. PASSWORD QUALITY
# ------------------------------------------------------------------------------
echo "[*] Configuring password quality (${PWQUALITY_CONF})..."

apply_pwquality() {
    local key="$1"
    local value="$2"
    local display="$3"
    
    # Remove existing line if present
    sed -i "/^${key}/d" "${PWQUALITY_CONF}" 2>/dev/null || true
    
    if [ "${value}" = "present" ]; then
        # Boolean setting (just the key, no value)
        echo "${key}" >> "${PWQUALITY_CONF}"
    else
        echo "${key} = ${value}" >> "${PWQUALITY_CONF}"
    fi
    
    printf "    %-35s" "${display}"
    if grep -q "${key}" "${PWQUALITY_CONF}"; then
        echo " [SET]"
        PASS=$((PASS + 1))
    else
        echo " [FAIL]"
        FAIL=$((FAIL + 1))
    fi
}

# minlen = 14 - Minimum password length (NIST SP 800-63B recommends 8+)
apply_pwquality "minlen" "14" "minlen = 14"

# dcredit = -1 - Require at least 1 digit
apply_pwquality "dcredit" "-1" "dcredit = -1"

# ucredit = -1 - Require at least 1 uppercase letter
apply_pwquality "ucredit" "-1" "ucredit = -1"

# lcredit = -1 - Require at least 1 lowercase letter
apply_pwquality "lcredit" "-1" "lcredit = -1"

# ocredit = -1 - Require at least 1 special character
apply_pwquality "ocredit" "-1" "ocredit = -1"

# maxrepeat = 3 - Maximum 3 consecutive same characters
apply_pwquality "maxrepeat" "3" "maxrepeat = 3"

# reject_username - Reject password if it contains username
apply_pwquality "reject_username" "present" "reject_username"

# enforce_for_root - Apply same rules to root
apply_pwquality "enforce_for_root" "present" "enforce_for_root"

# ------------------------------------------------------------------------------
# 3. ACCOUNT LOCKOUT (pam_faillock)
# ------------------------------------------------------------------------------
echo "[*] Configuring account lockout (pam_faillock)..."

apply_faillock() {
    local key="$1"
    local value="$2"
    local display="$3"
    
    sed -i "/^${key}/d" "${FAILLOCK_CONF}" 2>/dev/null || true
    echo "${key} = ${value}" >> "${FAILLOCK_CONF}"
    
    printf "    %-35s" "${display}"
    if grep -q "^${key} = ${value}" "${FAILLOCK_CONF}"; then
        echo " [SET]"
        PASS=$((PASS + 1))
    else
        echo " [FAIL]"
        FAIL=$((FAIL + 1))
    fi
}

# deny = 5 - Lock after 5 failed attempts
apply_faillock "deny" "5" "deny = 5"

# unlock_time = 900 - Auto-unlock after 15 minutes
apply_faillock "unlock_time" "900" "unlock_time = 900"

# fail_interval = 900 - Reset counter after 15 min window
apply_faillock "fail_interval" "900" "fail_interval = 900"

# ------------------------------------------------------------------------------
# 4. PASSWORD HISTORY
# ------------------------------------------------------------------------------
echo "[*] Configuring password history..."

# Remember 12 passwords - prevents password reuse
if grep -q "^PASS_MIN_DAYS" "${LOGIN_DEFS}"; then
    sed -i "s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/" "${LOGIN_DEFS}"
else
    echo "PASS_MIN_DAYS 1" >> "${LOGIN_DEFS}"
fi

# Max days before password change (90 days per HIPAA best practice)
if grep -q "^PASS_MAX_DAYS" "${LOGIN_DEFS}"; then
    sed -i "s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/" "${LOGIN_DEFS}"
else
    echo "PASS_MAX_DAYS 90" >> "${LOGIN_DEFS}"
fi

# Remember 12 passwords
if grep -q "^remember" /etc/pam.d/common-password 2>/dev/null; then
    sed -i "s/remember=[0-9]*/remember=12/" /etc/pam.d/common-password
else
    sed -i "/pam_unix.so/ s/$/ remember=12/" /etc/pam.d/common-password
fi

printf "    %-35s" "remember = 12"
if grep -q "remember=12" /etc/pam.d/common-password 2>/dev/null; then
    echo " [SET]"
    PASS=$((PASS + 1))
else
    echo " [FAIL]"
    FAIL=$((FAIL + 1))
fi

# ------------------------------------------------------------------------------
# SUMMARY
# ------------------------------------------------------------------------------
echo ""
echo "======================================================================"
echo "  PAM FORTRESS - COMPLETE"
echo "======================================================================"
echo "  Password minimum length: 14"
echo "  Lockout: 5 attempts / 15 min"
echo "  History: 12 passwords remembered"
echo "  Settings applied: ${PASS} | Failed: ${FAIL}"
echo "======================================================================"

exit 0
