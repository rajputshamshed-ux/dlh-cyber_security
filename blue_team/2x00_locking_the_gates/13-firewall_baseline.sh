#!/bin/bash
set -euo pipefail

# ==============================================================================
# FIREWALL BASELINE - MEDDEFENSE HEALTH SYSTEMS
# Task 13: The Firewall Baseline
# ==============================================================================
# WHAT IT DOES: Configures UFW with default-deny inbound policy. Allows only
#               SSH (management network), HTTP/HTTPS, MySQL (app network).
#               Enables logging of denied connections. Shows status at end.
# WHY: Service minimization (Task 7) stops services, but firewall blocks at
#      network layer. Defense in depth. 1x02 found 11 open ports - after this
#      script, only 4-5 are reachable. Even if a service restarts by accident,
#      the firewall still blocks the port.
#      IMAGINE: An apartment building. Without firewall, all doors are open.
#      With firewall, only 4 doors work, each with a guard checking IDs.
#      Failed entry attempts are written in a logbook.
# ATTACKS BLOCKED: Crimson Tide Phase 1 (port scanning - closed ports don't
#                  answer), Phase 4 (lateral movement - SSH/MySQL restricted
#                  to specific networks), Phase 6 (C2 channels logged).
# ==============================================================================
# Analyst: shamshed rajput
# Date: 30/07/2026
# Target: billing-srv-01, web-srv-01, log-srv-01
# ==============================================================================

if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] Run with sudo."
    exit 1
fi

echo "[*] Configuring UFW..."

if ! command -v ufw >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq ufw
fi

ufw --force reset > /dev/null 2>&1
ufw default deny incoming > /dev/null 2>&1
echo "    Default incoming: deny"
ufw default allow outgoing > /dev/null 2>&1
echo "    Default outgoing: allow"

echo "[*] Adding allow rules..."
RULES_ADDED=0

ufw allow from 10.10.1.0/24 to any port 22 proto tcp > /dev/null 2>&1
echo "    22/tcp from 10.10.1.0/24   [ADDED] SSH - management only"
RULES_ADDED=$((RULES_ADDED + 1))

ufw allow 80/tcp > /dev/null 2>&1
echo "    80/tcp                     [ADDED] HTTP"
RULES_ADDED=$((RULES_ADDED + 1))

ufw allow 443/tcp > /dev/null 2>&1
echo "    443/tcp                    [ADDED] HTTPS"
RULES_ADDED=$((RULES_ADDED + 1))

ufw allow from 10.10.2.0/24 to any port 3306 proto tcp > /dev/null 2>&1
echo "    3306/tcp from 10.10.2.0/24 [ADDED] MySQL - app network only"
RULES_ADDED=$((RULES_ADDED + 1))

echo "[*] Enabling logging..."
ufw logging low > /dev/null 2>&1
echo "    Logging: on (low)"

echo "[*] Activating firewall..."
ufw --force enable > /dev/null 2>&1
echo "    UFW: active"

# Validate and show status
echo "[*] Validating firewall status..."
ufw status verbose

echo ""
echo "======================================================================"
echo "  FIREWALL BASELINE - COMPLETE"
echo "======================================================================"
echo "  Default incoming: deny"
echo "  Allow rules:      ${RULES_ADDED}"
echo "  Logging:          enabled"
echo "======================================================================"

exit 0
