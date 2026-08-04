#!/bin/bash
set -euo pipefail

# ==============================================================================
# KERNEL SHIELD - MEDDEFENSE HEALTH SYSTEMS
# Task 5: The Kernel Shield
# Analyst: shamshed rajput
# Target: billing-srv-01
# ==============================================================================

SYSCTL_CONF="/etc/sysctl.conf"
SYSCTL_BACKUP="/etc/sysctl.conf.bak.$(date +%Y%m%d_%H%M%S)"
PASS=0
FAIL=0
APPLIED=0

if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] Run with sudo."
    exit 1
fi

# Backup
echo "[*] Backing up ${SYSCTL_CONF}"
if [ -f "${SYSCTL_CONF}" ]; then
    cp "${SYSCTL_CONF}" "${SYSCTL_BACKUP}"
fi

# Apply settings
echo "[*] Applying kernel hardening parameters..."

cat >> "${SYSCTL_CONF}" << 'EOF'
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
kernel.randomize_va_space = 2
fs.suid_dumpable = 0
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
EOF

APPLIED=14

# Apply immediately
sysctl -p "${SYSCTL_CONF}" > /dev/null 2>&1

# Verify each setting via /proc/sys
echo ""

verify() {
    local path="$1"
    local expected="$2"
    local display="$3"
    local actual

    if [ -f "${path}" ]; then
        actual=$(cat "${path}")
    else
        actual="MISSING"
    fi

    printf "%-55s" "${display} = ${expected}"

    if [ "${actual}" = "${expected}" ]; then
        echo " [PASS]"
        PASS=$((PASS + 1))
    else
        echo " [FAIL] (got: ${actual})"
        FAIL=$((FAIL + 1))
    fi
}

verify "/proc/sys/net/ipv4/ip_forward" "0" "net.ipv4.ip_forward"
verify "/proc/sys/net/ipv4/conf/all/accept_redirects" "0" "net.ipv4.conf.all.accept_redirects"
verify "/proc/sys/net/ipv4/conf/default/accept_redirects" "0" "net.ipv4.conf.default.accept_redirects"
verify "/proc/sys/net/ipv4/conf/all/send_redirects" "0" "net.ipv4.conf.all.send_redirects"
verify "/proc/sys/net/ipv4/conf/all/accept_source_route" "0" "net.ipv4.conf.all.accept_source_route"
verify "/proc/sys/net/ipv4/conf/all/log_martians" "1" "net.ipv4.conf.all.log_martians"
verify "/proc/sys/net/ipv4/tcp_syncookies" "1" "net.ipv4.tcp_syncookies"
verify "/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts" "1" "net.ipv4.icmp_echo_ignore_broadcasts"
verify "/proc/sys/net/ipv6/conf/all/disable_ipv6" "1" "net.ipv6.conf.all.disable_ipv6"
verify "/proc/sys/net/ipv6/conf/default/disable_ipv6" "1" "net.ipv6.conf.default.disable_ipv6"
verify "/proc/sys/kernel/randomize_va_space" "2" "kernel.randomize_va_space"
verify "/proc/sys/fs/suid_dumpable" "0" "fs.suid_dumpable"
verify "/proc/sys/kernel/dmesg_restrict" "1" "kernel.dmesg_restrict"
verify "/proc/sys/kernel/kptr_restrict" "2" "kernel.kptr_restrict"

echo ""
echo "Parameters applied: ${APPLIED}"
echo "Verified PASS: ${PASS}"
echo "Verified FAIL: ${FAIL}"

exit 0
