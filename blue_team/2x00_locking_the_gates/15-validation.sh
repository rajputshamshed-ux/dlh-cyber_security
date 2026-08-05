#!/bin/bash
set -euo pipefail

# ==============================================================================
# POST-HARDENING VALIDATOR - MEDDEFENSE HEALTH SYSTEMS
# Task 15: The Post-Hardening Validator
# ==============================================================================
# WHAT IT DOES: Read-only script that verifies every hardening control from
#               Tasks 4-13 is still in its expected state. Makes NO changes.
# WHY: Hardening is not a one-time event. Configuration drift happens: an
#      admin changes a sysctl for debugging and forgets to revert. A software
#      update overwrites sshd_config. This script catches drift before an
#      attacker exploits it.
#      IMAGINE: A security guard doing rounds every morning. Checks every
#      door and window. If one is open, reports it immediately. Never
#      touches anything - only observes and reports.
# WHEN TO USE: James Chen runs this every Monday morning. After any system
#              update. Before auditors arrive. As a cron job weekly.
# EXIT CODE: 0 = all checks pass (server is hardened)
#            1 = at least one check failed (drift detected, needs fixing)
# ==============================================================================
# Analyst: shamshed rajput
# Date: 30/07/2026
# Target: billing-srv-01, web-srv-01, log-srv-01
# ==============================================================================

if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] Run with sudo."
    exit 1
fi

PASS=0
FAIL=0

# ------------------------------------------------------------------------------
# SSH HARDENING (Task 4)
# ------------------------------------------------------------------------------
check_sshd() {
    local key="$1"
    local expected="$2"
    local display="$3"
    
    local actual
    actual=$(sshd -T 2>/dev/null | grep "^${key} " | awk '{print $2}' || echo "NOT_FOUND")
    
    if [ "${actual}" = "${expected}" ]; then
        echo "[PASS] ${display} = ${expected}"
        PASS=$((PASS + 1))
    else
        echo "[FAIL] ${display} = ${actual} (expected: ${expected})"
        FAIL=$((FAIL + 1))
    fi
}

check_sshd "permitrootlogin" "no" "PermitRootLogin"
check_sshd "passwordauthentication" "no" "PasswordAuthentication"
check_sshd "permitemptypasswords" "no" "PermitEmptyPasswords"
check_sshd "x11forwarding" "no" "X11Forwarding"
check_sshd "maxauthtries" "3" "MaxAuthTries"
check_sshd "clientaliveinterval" "300" "ClientAliveInterval"
check_sshd "clientalivecountmax" "2" "ClientAliveCountMax"

# ------------------------------------------------------------------------------
# KERNEL HARDENING (Task 5)
# ------------------------------------------------------------------------------
check_sysctl() {
    local param="$1"
    local expected="$2"
    local display="$3"
    
    local actual
    actual=$(sysctl -n "${param}" 2>/dev/null || echo "ERROR")
    
    if [ "${actual}" = "${expected}" ]; then
        echo "[PASS] ${display} = ${expected}"
        PASS=$((PASS + 1))
    else
        echo "[FAIL] ${display} = ${actual} (expected: ${expected})"
        FAIL=$((FAIL + 1))
    fi
}

check_sysctl "net.ipv4.ip_forward" "0" "net.ipv4.ip_forward"
check_sysctl "net.ipv4.conf.all.accept_redirects" "0" "net.ipv4.conf.all.accept_redirects"
check_sysctl "net.ipv4.conf.all.send_redirects" "0" "net.ipv4.conf.all.send_redirects"
check_sysctl "net.ipv4.conf.all.accept_source_route" "0" "net.ipv4.conf.all.accept_source_route"
check_sysctl "net.ipv4.conf.all.log_martians" "1" "net.ipv4.conf.all.log_martians"
check_sysctl "net.ipv4.tcp_syncookies" "1" "net.ipv4.tcp_syncookies"
check_sysctl "net.ipv4.icmp_echo_ignore_broadcasts" "1" "net.ipv4.icmp_echo_ignore_broadcasts"
check_sysctl "net.ipv6.conf.all.disable_ipv6" "1" "net.ipv6.conf.all.disable_ipv6"
check_sysctl "kernel.randomize_va_space" "2" "kernel.randomize_va_space"
check_sysctl "fs.suid_dumpable" "0" "fs.suid_dumpable"
check_sysctl "kernel.dmesg_restrict" "1" "kernel.dmesg_restrict"
check_sysctl "kernel.kptr_restrict" "2" "kernel.kptr_restrict"

# ------------------------------------------------------------------------------
# FILESYSTEM PERMISSIONS (Task 6)
# ------------------------------------------------------------------------------
check_file_perm() {
    local file="$1"
    local expected="$2"
    local display="$3"
    
    if [ -f "${file}" ]; then
        local actual
        actual=$(stat -c '%a' "${file}" 2>/dev/null || echo "ERROR")
        if [ "${actual}" = "${expected}" ]; then
            echo "[PASS] ${display} = ${expected}"
            PASS=$((PASS + 1))
        else
            echo "[FAIL] ${display} = ${actual} (expected: ${expected})"
            FAIL=$((FAIL + 1))
        fi
    fi
}

check_file_perm "/etc/ssh/sshd_config" "600" "sshd_config permissions"
check_file_perm "/etc/crontab" "600" "crontab permissions"

# ------------------------------------------------------------------------------
# SERVICES (Task 7)
# ------------------------------------------------------------------------------
check_service() {
    local service="$1"
    local expected="$2"
    local display="$3"
    
    if systemctl is-active --quiet "${service}" 2>/dev/null; then
        local actual="active"
    else
        local actual="inactive"
    fi
    
    if [ "${actual}" = "${expected}" ]; then
        echo "[PASS] ${display} = ${expected}"
        PASS=$((PASS + 1))
    else
        echo "[FAIL] ${display} = ${actual} (expected: ${expected})"
        FAIL=$((FAIL + 1))
    fi
}

check_service "sshd" "active" "sshd.service"
check_service "auditd" "active" "auditd.service"
check_service "apparmor" "active" "apparmor.service"
check_service "ufw" "active" "ufw.service"
check_service "rsyslog" "active" "rsyslog.service"
check_service "cron" "active" "cron.service"

# ------------------------------------------------------------------------------
# FIREWALL (Task 13)
# ------------------------------------------------------------------------------
echo -n ""
if ufw status 2>/dev/null | grep -q "Status: active"; then
    echo "[PASS] UFW status = active"
    PASS=$((PASS + 1))
else
    echo "[FAIL] UFW status = inactive (expected: active)"
    FAIL=$((FAIL + 1))
fi

if ufw status 2>/dev/null | grep -q "Default: deny (incoming)"; then
    echo "[PASS] Default incoming = deny"
    PASS=$((PASS + 1))
else
    echo "[FAIL] Default incoming = allow (expected: deny)"
    FAIL=$((FAIL + 1))
fi

# ------------------------------------------------------------------------------
# PAM PASSWORD QUALITY (Task 8)
# ------------------------------------------------------------------------------
if [ -f /etc/security/pwquality.conf ]; then
    if grep -q "^minlen = 14" /etc/security/pwquality.conf 2>/dev/null; then
        echo "[PASS] PAM minlen = 14"
        PASS=$((PASS + 1))
    else
        echo "[FAIL] PAM minlen not set to 14"
        FAIL=$((FAIL + 1))
    fi
fi

# ------------------------------------------------------------------------------
# APPARMOR (Task 9)
# ------------------------------------------------------------------------------
if aa-status --enabled 2>/dev/null; then
    echo "[PASS] AppArmor = enabled"
    PASS=$((PASS + 1))
else
    echo "[FAIL] AppArmor = disabled"
    FAIL=$((FAIL + 1))
fi

# ------------------------------------------------------------------------------
# SUMMARY
# ------------------------------------------------------------------------------
TOTAL=$((PASS + FAIL))
echo ""
echo "======================================================================"
echo "  POST-HARDENING VALIDATION - COMPLETE"
echo "======================================================================"
echo "  Total checks: ${TOTAL}"
echo "  Passed:        ${PASS}"
echo "  Failed:        ${FAIL}"
echo "======================================================================"

if [ "${FAIL}" -gt 0 ]; then
    exit 1
fi
exit 0

