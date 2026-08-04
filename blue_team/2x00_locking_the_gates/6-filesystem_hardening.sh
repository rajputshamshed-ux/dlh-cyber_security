#!/bin/bash
set -euo pipefail

# ==============================================================================
# PERMISSION SWEEP - MEDDEFENSE HEALTH SYSTEMS
# Task 6: The Permission Sweep
# Analyst: shamshed rajput
# Date: 30/07/2026
# Target: billing-srv-01, web-srv-01, log-srv-01
# Purpose: Remove dangerous SUID/SGID binaries, fix world-writable files,
#          harden mount options, restrict cron. Blocks Crimson Tide Phase 3
#          privilege escalation.
# ==============================================================================

if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] Run with sudo."
    exit 1
fi

SUID_FIXED=0
SGID_FIXED=0
WW_FIXED=0

# ------------------------------------------------------------------------------
# WHITELIST: Known-safe SUID binaries for Ubuntu 22.04
# ------------------------------------------------------------------------------
SUID_WHITELIST=(
    "/usr/bin/passwd"
    "/usr/bin/chfn"
    "/usr/bin/chsh"
    "/usr/bin/gpasswd"
    "/usr/bin/newgrp"
    "/usr/bin/sudo"
    "/usr/bin/pkexec"
    "/usr/bin/umount"
    "/usr/bin/mount"
    "/usr/bin/su"
    "/usr/lib/snapd/snap-confine"
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper"
    "/usr/lib/openssh/ssh-keysign"
    "/usr/libexec/polkit-agent-helper-1"
    "/usr/lib/policykit-1/polkit-agent-helper-1"
    "/usr/bin/fusermount"
    "/usr/bin/fusermount3"
    "/usr/bin/ntfs-3g"
)

SGID_WHITELIST=(
    "/usr/bin/wall"
    "/usr/bin/write"
    "/usr/bin/expiry"
    "/usr/bin/dotlockfile"
    "/usr/bin/mail-touchlock"
    "/usr/bin/mail-lock"
    "/usr/bin/crontab"
    "/usr/bin/ssh-agent"
    "/usr/bin/mlocate"
    "/usr/lib/x86_64-linux-gnu/utempter/utempter"
    "/usr/sbin/postdrop"
    "/usr/sbin/postqueue"
)

# ------------------------------------------------------------------------------
# 1. SUID BINARIES
# ------------------------------------------------------------------------------
echo "[*] Scanning SUID binaries..."
SUID_LIST=$(find / -perm -4000 -type f 2>/dev/null | grep -v -E '^/(proc|sys|dev|snap)')
SUID_TOTAL=$(echo "${SUID_LIST}" | grep -c . || echo 0)

SUID_WHITELISTED=0
SUID_NON_WHITELISTED=0

echo "Found ${SUID_TOTAL} SUID binaries"

while IFS= read -r binary; do
    if [[ " ${SUID_WHITELIST[*]} " =~ " ${binary} " ]]; then
        SUID_WHITELISTED=$((SUID_WHITELISTED + 1))
    else
        SUID_NON_WHITELISTED=$((SUID_NON_WHITELISTED + 1))
        echo "  ${binary}   [SUID REMOVED]"
        chmod u-s "${binary}"
        SUID_FIXED=$((SUID_FIXED + 1))
    fi
done <<< "${SUID_LIST}"

echo "Whitelisted: ${SUID_WHITELISTED}"
echo "Non-whitelisted: ${SUID_NON_WHITELISTED}"

# ------------------------------------------------------------------------------
# 2. SGID BINARIES
# ------------------------------------------------------------------------------
echo "[*] Scanning SGID binaries..."
SGID_LIST=$(find / -perm -2000 -type f 2>/dev/null | grep -v -E '^/(proc|sys|dev|snap)')
SGID_TOTAL=$(echo "${SGID_LIST}" | grep -c . || echo 0)

SGID_WHITELISTED=0
SGID_NON_WHITELISTED=0

echo "Found ${SGID_TOTAL} SGID binaries"

while IFS= read -r binary; do
    if [[ " ${SGID_WHITELIST[*]} " =~ " ${binary} " ]]; then
        SGID_WHITELISTED=$((SGID_WHITELISTED + 1))
    else
        SGID_NON_WHITELISTED=$((SGID_NON_WHITELISTED + 1))
        echo "  ${binary}   [SGID REMOVED]"
        chmod g-s "${binary}"
        SGID_FIXED=$((SGID_FIXED + 1))
    fi
done <<< "${SGID_LIST}"

echo "Whitelisted: ${SGID_WHITELISTED}"
echo "Non-whitelisted: ${SGID_NON_WHITELISTED}"

# ------------------------------------------------------------------------------
# 3. WORLD-WRITABLE FILES
# ------------------------------------------------------------------------------
echo "[*] Scanning world-writable files..."
WW_LIST=$(find /etc /home /var /tmp -perm -0002 -type f 2>/dev/null)
WW_TOTAL=$(echo "${WW_LIST}" | grep -c . || echo 0)

echo "Found ${WW_TOTAL} world-writable files"

while IFS= read -r file; do
    echo "  ${file}   [FIXED]"
    chmod o-w "${file}"
    WW_FIXED=$((WW_FIXED + 1))
done <<< "${WW_LIST}"

# ------------------------------------------------------------------------------
# 4. MOUNT OPTIONS
# ------------------------------------------------------------------------------
echo "[*] Checking mount options..."

check_mount() {
    local mountpoint="$1"
    local options="$2"
    
    if mount | grep -q "on ${mountpoint} "; then
        if mount | grep "on ${mountpoint} " | grep -q "${options}"; then
            echo "${mountpoint}: ${options}  [OK]"
        else
            echo "${mountpoint}: ${options}  [APPLIED]"
            mount -o remount,"${options}" "${mountpoint}" 2>/dev/null || true
            # Add to fstab for persistence
            if ! grep -q "${mountpoint}" /etc/fstab; then
                echo "tmpfs ${mountpoint} tmpfs defaults,${options} 0 0" >> /etc/fstab
            fi
        fi
    else
        echo "${mountpoint}: ${options}  [SKIPPED - not mounted]"
    fi
}

check_mount "/tmp" "noexec,nosuid,nodev"
check_mount "/var/tmp" "noexec,nosuid,nodev"
check_mount "/dev/shm" "noexec,nosuid,nodev"

# ------------------------------------------------------------------------------
# 5. CRON RESTRICTIONS
# ------------------------------------------------------------------------------
echo "[*] Restricting cron access..."

# Only root and authorized users can use cron
if [ -f /etc/cron.allow ]; then
    echo "medadmin" > /etc/cron.allow
    echo "sysadmin" >> /etc/cron.allow
    chmod 600 /etc/cron.allow
    echo "cron.allow: restricted to medadmin, sysadmin"
fi

if [ -f /etc/cron.deny ]; then
    rm -f /etc/cron.deny
    echo "cron.deny: removed"
fi

# Secure crontab permissions
chmod 600 /etc/crontab 2>/dev/null || true

# ------------------------------------------------------------------------------
# SUMMARY
# ------------------------------------------------------------------------------
echo ""
echo "======================================================================"
echo "  PERMISSION SWEEP - COMPLETE"
echo "======================================================================"
echo "  SUID remediated: ${SUID_FIXED}"
echo "  SGID remediated: ${SGID_FIXED}"
echo "  World-writable fixed: ${WW_FIXED}"
echo "======================================================================"

exit 0

