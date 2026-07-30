#!/bin/bash
set -euo pipefail

# ==============================================================================
# BASELINE SNAPSHOT - MEDDEFENSE HEALTH SYSTEMS
# Task 0: The Baseline Snapshot
# Analyst: shamshed rajput
# Date: 30/07/2026
# Target: billing-srv-01 (Ubuntu 22.04.3 LTS)
# ==============================================================================

OUTPUT_DIR="/var/log/meddefense/baseline"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
HOSTNAME="$(hostname -s)"
JSON_OUTPUT="${OUTPUT_DIR}/${HOSTNAME}_baseline_${TIMESTAMP}.json"

mkdir -p "${OUTPUT_DIR}"

echo "[*] Starting baseline snapshot for ${HOSTNAME}..."

# 1. System identification
OS_VERSION="$(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)"
KERNEL_VERSION="$(uname -r)"
UPTIME="$(uptime -p | sed 's/^up //')"

# 2. Running services
SERVICES_LIST="$(systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null | awk '{print $1}' | sort)"
SERVICE_COUNT="$(echo "${SERVICES_LIST}" | grep -c . || echo 0)"

# 3. Open ports
OPEN_PORTS="$(ss -tlnp 2>/dev/null | awk 'NR>1 {print $4}' | awk -F: '{print $NF}' | sort -n | uniq)"
PORT_COUNT="$(echo "${OPEN_PORTS}" | grep -c . || echo 0)"

# 4. SUID binaries
SUID_BINARIES="$(find /usr /bin /sbin /lib -perm -4000 -type f 2>/dev/null | sort)"
SUID_COUNT="$(echo "${SUID_BINARIES}" | grep -c . || echo 0)"

# 5. SGID binaries
SGID_BINARIES="$(find /usr /bin /sbin /lib -perm -2000 -type f 2>/dev/null | sort)"
SGID_COUNT="$(echo "${SGID_BINARIES}" | grep -c . || echo 0)"

# 6. World-writable files
WORLD_WRITABLE="$(find /etc /home /var /tmp -perm -0002 -type f 2>/dev/null | sort)"
WW_COUNT="$(echo "${WORLD_WRITABLE}" | grep -c . || echo 0)"

# 7. User accounts
LOCAL_USERS="$(awk -F: '$3>=1000 && $3<65534 {print $1}' /etc/passwd | sort)"
USER_COUNT="$(echo "${LOCAL_USERS}" | grep -c . || echo 0)"
SUDO_MEMBERS="$(getent group sudo 2>/dev/null | cut -d: -f4 | tr ',' '\n' | sort)"
SUDO_COUNT="$(echo "${SUDO_MEMBERS}" | grep -c . || echo 0)"

# 8. SSH configuration
SSH_PERMIT_ROOT="$(sshd -T 2>/dev/null | grep "^permitrootlogin " | awk '{print $2}' || echo "not_found")"
SSH_PASSWORD_AUTH="$(sshd -T 2>/dev/null | grep "^passwordauthentication " | awk '{print $2}' || echo "not_found")"
SSH_EMPTY_PASSWORDS="$(sshd -T 2>/dev/null | grep "^permitemptypasswords " | awk '{print $2}' || echo "not_found")"

# 9. sysctl security parameters
SYSCTL_IP_FORWARD="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "not_found")"
SYSCTL_SYN_COOKIES="$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo "not_found")"
SYSCTL_RP_FILTER="$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null || echo "not_found")"
SYSCTL_ACCEPT_REDIRECTS="$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null || echo "not_found")"
SYSCTL_ACCEPT_SOURCE_ROUTE="$(sysctl -n net.ipv4.conf.all.accept_source_route 2>/dev/null || echo "not_found")"
SYSCTL_ASLR="$(sysctl -n kernel.randomize_va_space 2>/dev/null || echo "not_found")"
SYSCTL_CORE_DUMPS="$(sysctl -n fs.suid_dumpable 2>/dev/null || echo "not_found")"

# 10. Build JSON
cat > "${JSON_OUTPUT}" << EOF
{
  "hostname": "${HOSTNAME}",
  "os": "${OS_VERSION}",
  "kernel": "${KERNEL_VERSION}",
  "uptime": "${UPTIME}",
  "services": ${SERVICE_COUNT},
  "ports": ${PORT_COUNT},
  "suid": ${SUID_COUNT},
  "sgid": ${SGID_COUNT},
  "world_writable": ${WW_COUNT},
  "users": ${USER_COUNT},
  "sudo_members": ${SUDO_COUNT},
  "ssh_permit_root": "${SSH_PERMIT_ROOT}",
  "ssh_password_auth": "${SSH_PASSWORD_AUTH}",
  "ssh_empty_passwords": "${SSH_EMPTY_PASSWORDS}",
  "sysctl_ip_forward": "${SYSCTL_IP_FORWARD}",
  "sysctl_syn_cookies": "${SYSCTL_SYN_COOKIES}",
  "sysctl_rp_filter": "${SYSCTL_RP_FILTER}",
  "sysctl_accept_redirects": "${SYSCTL_ACCEPT_REDIRECTS}",
  "sysctl_accept_source_route": "${SYSCTL_ACCEPT_SOURCE_ROUTE}",
  "sysctl_aslr": "${SYSCTL_ASLR}",
  "sysctl_core_dumps": "${SYSCTL_CORE_DUMPS}"
}
EOF

chmod 600 "${JSON_OUTPUT}"

# 11. Print summary
echo ""
echo "======================================================================"
echo "  BASELINE SNAPSHOT COMPLETE - ${HOSTNAME}"
echo "======================================================================"
echo "  Hostname:            ${HOSTNAME}"
echo "  OS:                  ${OS_VERSION}"
echo "  Kernel:              ${KERNEL_VERSION}"
echo "  Uptime:              ${UPTIME}"
echo "  Running services:    ${SERVICE_COUNT}"
echo "  Open ports:          ${PORT_COUNT}"
echo "  SUID binaries:       ${SUID_COUNT}"
echo "  SGID binaries:       ${SGID_COUNT}"
echo "  World-writable files: ${WW_COUNT}"
echo "----------------------------------------------------------------------"
echo "  JSON: ${JSON_OUTPUT}"
echo "======================================================================"

exit 0
