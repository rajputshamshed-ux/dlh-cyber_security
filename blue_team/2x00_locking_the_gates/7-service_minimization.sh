#!/bin/bash
set -euo pipefail

# ==============================================================================
# SERVICE MINIMIZER - MEDDEFENSE HEALTH SYSTEMS
# Task 7: The Service Minimizer
# ==============================================================================
# WHAT IT DOES: Stops and disables unnecessary services. Only keeps the 9
#               services required for MedDefense operations.
# WHY: Every running service is a potential entry point for attackers.
#      Crimson Tide exploits unnecessary services for lateral movement.
#      CIS Benchmark Section 2 mandates service minimization.
# ATTACKS BLOCKED: Crimson Tide Phase 1 (initial access via exposed services),
#                  Phase 4 (lateral movement via unnecessary network services).
# ==============================================================================
# Analyst: shamshed rajput
# Date: 30/07/2026
# Target: billing-srv-01, web-srv-01, log-srv-01
# ==============================================================================

if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] Run with sudo."
    exit 1
fi

BEFORE=0
AFTER=0
DISABLED=0

# ------------------------------------------------------------------------------
# MEDDEFENSE SERVICE WHITELIST
# ------------------------------------------------------------------------------
# Only these services are approved for production servers.
# Each comment explains why the service is required.

WHITELIST=(
    "ssh.service"               # Secure remote administration (CIS 5.2)
    "apache2.service"           # Web server for patient billing portal (billing-srv-01)
    "mysql.service"             # MySQL database for billing records (billing-srv-01)
    "ufw.service"               # Host-based firewall (CIS 3.5.1)
    "auditd.service"            # Security event logging (CIS 4.1.1)
    "apparmor.service"          # Mandatory access control (CIS 1.6.1)
    "cron.service"              # Scheduled tasks (backups, updates)
    "rsyslog.service"           # System logging to log-srv-01
    "systemd-timesyncd.service" # Time synchronization for accurate logs
)

# ------------------------------------------------------------------------------
# SCAN ENABLED SERVICES
# ------------------------------------------------------------------------------
echo "[*] Scanning enabled services..."
ENABLED_SERVICES=$(systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null | awk '{print $1}' | sort)
BEFORE=$(echo "${ENABLED_SERVICES}" | grep -c . || echo 0)
echo "    Enabled services found: ${BEFORE}"

# ------------------------------------------------------------------------------
# COMPARE AGAINST WHITELIST
# ------------------------------------------------------------------------------
echo "[*] Comparing against MedDefense whitelist (${#WHITELIST[@]} required services)..."

while IFS= read -r service; do
    if [[ " ${WHITELIST[*]} " =~ " ${service} " ]]; then
        # Service is on whitelist - keep it running
        if systemctl is-active --quiet "${service}" 2>/dev/null; then
            echo "  ${service}   [ACTIVE]"
        else
            echo "  ${service}   [STARTING]"
            systemctl start "${service}" 2>/dev/null || true
        fi
    else
        # Service NOT on whitelist - stop and disable
        echo "  ${service}   [STOPPED] [DISABLED]"
        systemctl stop "${service}" 2>/dev/null || true
        systemctl disable "${service}" 2>/dev/null || true
        DISABLED=$((DISABLED + 1))
    fi
done <<< "${ENABLED_SERVICES}"

# Also disable services that are enabled but not currently running
ALL_ENABLED=$(systemctl list-unit-files --type=service --state=enabled --no-legend --no-pager 2>/dev/null | awk '{print $1}' | sort)

while IFS= read -r service; do
    if [[ ! " ${WHITELIST[*]} " =~ " ${service} " ]]; then
        systemctl disable "${service}" 2>/dev/null || true
    fi
done <<< "${ALL_ENABLED}"

# ------------------------------------------------------------------------------
# VERIFY REQUIRED SERVICES ARE RUNNING
# ------------------------------------------------------------------------------
AFTER=$(systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null | awk '{print $1}' | grep -c . || echo 0)

# ------------------------------------------------------------------------------
# SUMMARY
# ------------------------------------------------------------------------------
echo ""
echo "======================================================================"
echo "  SERVICE MINIMIZATION - COMPLETE"
echo "======================================================================"
echo "  Before: ${BEFORE} | After: ${AFTER} | Disabled: ${DISABLED}"
echo "======================================================================"

exit 0
