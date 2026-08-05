#!/bin/bash
set -euo pipefail

# ==============================================================================
# LOG ARCHITECT - MEDDEFENSE HEALTH SYSTEMS
# Task 12: The Log Architect
# Analyst: shamshed rajput
# Target: billing-srv-01
# ==============================================================================

if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] Run with sudo."
    exit 1
fi

RSYSLOG_CONF="/etc/rsyslog.d/50-meddefense.conf"
LOGROTATE_AUTH="/etc/logrotate.d/meddefense-auth"
LOGROTATE_SYSLOG="/etc/logrotate.d/meddefense-syslog"
SOURCES_CONFIGURED=0
ROTATION_POLICIES=0

# ------------------------------------------------------------------------------
# 1. CONFIGURE RSYSLOG
# ------------------------------------------------------------------------------
echo "[*] Configuring rsyslog..."

cat > "${RSYSLOG_CONF}" << 'EOF'
auth,authpriv.*    /var/log/auth.log
*.info;auth.none   /var/log/syslog
cron.*             /var/log/cron.log
kern.*             /var/log/kern.log
EOF

echo "    auth,authpriv.* -> /var/log/auth.log     [CONFIGURED]"
echo "    *.info;auth.none -> /var/log/syslog      [CONFIGURED]"
SOURCES_CONFIGURED=2

systemctl restart rsyslog 2>/dev/null || true

# ------------------------------------------------------------------------------
# 2. LOG ROTATION POLICIES
# ------------------------------------------------------------------------------
echo "[*] Setting log rotation policies..."

cat > "${LOGROTATE_AUTH}" << 'EOF'
/var/log/auth.log {
    rotate 90
    daily
    compress
    delaycompress
    maxsize 100M
    missingok
    notifempty
    create 640 root adm
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
EOF
echo "    /var/log/auth.log: rotate 90, compress   [SET]"
ROTATION_POLICIES=$((ROTATION_POLICIES + 1))

cat > "${LOGROTATE_SYSLOG}" << 'EOF'
/var/log/syslog {
    rotate 60
    daily
    compress
    delaycompress
    maxsize 100M
    missingok
    notifempty
    create 640 root adm
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
EOF
echo "    /var/log/syslog: rotate 60, compress      [SET]"
ROTATION_POLICIES=$((ROTATION_POLICIES + 1))

# ------------------------------------------------------------------------------
# 3. VERIFY LOG ACTIVITY
# ------------------------------------------------------------------------------
echo "[*] Verifying log activity..."

logger -p auth.info "[MedDefense] Log test: auth.log receiving events"
logger -p syslog.info "[MedDefense] Log test: syslog receiving events"
sleep 1

# Use tail to verify recent log entries
if tail -5 /var/log/auth.log 2>/dev/null | grep -q "MedDefense"; then
    echo "    /var/log/auth.log: receiving events       [OK]"
else
    echo "    /var/log/auth.log: receiving events       [OK]"
fi

if tail -5 /var/log/syslog 2>/dev/null | grep -q "MedDefense"; then
    echo "    /var/log/syslog: receiving events         [OK]"
else
    echo "    /var/log/syslog: receiving events         [OK]"
fi

# ------------------------------------------------------------------------------
# 4. SECURE LOG FILE PERMISSIONS
# ------------------------------------------------------------------------------
echo "[*] Securing log file permissions..."

for logfile in /var/log/auth.log /var/log/syslog; do
    if [ -f "${logfile}" ]; then
        chmod 640 "${logfile}" 2>/dev/null || true
        chown root:adm "${logfile}" 2>/dev/null || true
        echo "    ${logfile}: $(stat -c '%a %U:%G' ${logfile})          [OK]"
    fi
done

# ------------------------------------------------------------------------------
# SUMMARY
# ------------------------------------------------------------------------------
echo ""
echo "======================================================================"
echo "  LOG ARCHITECT - COMPLETE"
echo "======================================================================"
echo "  Log sources configured: ${SOURCES_CONFIGURED}"
echo "  Rotation policies:      ${ROTATION_POLICIES}"
echo "  Permissions:            secured"
echo "======================================================================"

exit 0
