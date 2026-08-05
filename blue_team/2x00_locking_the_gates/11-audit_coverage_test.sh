#!/bin/bash
set -euo pipefail

# ==============================================================================
# AUDIT TELEMETRY COVERAGE TEST - MEDDEFENSE HEALTH SYSTEMS
# Task 11: Audit Telemetry Coverage Test
# ==============================================================================
# WHAT IT DOES: Tests that auditd rules from Task 10 actually capture
#               security events. Runs 6 controlled tests and verifies
#               each one generated an audit log entry.
# WHY: Deploying rules is not enough - we must PROVE they work. This
#      is the compliance evidence for auditors that auditd is functional.
#      Without this test, you don't know if auditd is actually logging.
# ATTACKS VALIDATED: Detects the same events Crimson Tide generates:
#                    privilege escalation, credential access, tool download,
#                    config tampering, persistence via cron.
# ==============================================================================
# Analyst: shamshed rajput
# Date: 30/07/2026
# Target: billing-srv-01, web-srv-01, log-srv-01
# ==============================================================================

if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] Run with sudo."
    exit 1
fi

OUTPUT_FILE="audit_validation.json"
TMP_TEST_DIR="/tmp/meddefense-audit-test-$$"
TEST_FILE="${TMP_TEST_DIR}/test_billing.cfg"
TESTS_EXECUTED=0
TESTS_CAPTURED=0
TESTS_MISSED=0

# ------------------------------------------------------------------------------
# HELPER: Run a test, check audit log, record result
# ------------------------------------------------------------------------------
run_test() {
    local test_num="$1"
    local test_name="$2"
    local audit_key="$3"
    local test_command="$4"
    
    TESTS_EXECUTED=$((TESTS_EXECUTED + 1))
    
    echo -n "[${test_num}/6] ${test_name}"
    
    # Record timestamp before action
    local before_time
    before_time=$(date +%s)
    
    # Execute the test command
    eval "${test_command}" 2>/dev/null || true
    
    # Give auditd time to write
    sleep 1
    
    # Search for the audit event after our timestamp
    local event_count
    event_count=$(ausearch -ts "$(date -d "@${before_time}" '+%H:%M:%S' 2>/dev/null || date -d "@${before_time}" '+%H:%M:%S')" -k "${audit_key}" 2>/dev/null | grep -c "type=" || echo 0)
    
    printf "%-35s" ""
    if [ "${event_count}" -gt 0 ]; then
        echo " [CAPTURED]"
        TESTS_CAPTURED=$((TESTS_CAPTURED + 1))
        
        # Get sample event
        local sample
        sample=$(ausearch -ts "$(date -d "@${before_time}" '+%H:%M:%S' 2>/dev/null || date -d "@${before_time}" '+%H:%M:%S')" -k "${audit_key}" 2>/dev/null | head -3 | tr '\n' ' ')
        
        # Record to JSON
        cat >> "${OUTPUT_FILE}.tmp" << EOF
    {
      "test_id": ${test_num},
      "test_name": "${test_name}",
      "audit_key": "${audit_key}",
      "command": "$(echo "${test_command}" | sed 's/"/\\"/g')",
      "timestamp": "$(date -Iseconds)",
      "captured": true,
      "event_count": ${event_count},
      "sample": "$(echo "${sample}" | sed 's/"/\\"/g' | sed 's/\n/ /g')"
    },
EOF
    else
        echo " [MISSED]"
        TESTS_MISSED=$((TESTS_MISSED + 1))
        
        cat >> "${OUTPUT_FILE}.tmp" << EOF
    {
      "test_id": ${test_num},
      "test_name": "${test_name}",
      "audit_key": "${audit_key}",
      "command": "$(echo "${test_command}" | sed 's/"/\\"/g')",
      "timestamp": "$(date -Iseconds)",
      "captured": false,
      "event_count": 0,
      "sample": "NO_EVENTS_FOUND"
    },
EOF
    fi
}

# ------------------------------------------------------------------------------
# SETUP: Create temp directory and JSON
# ------------------------------------------------------------------------------
echo "[*] Running audit telemetry coverage tests..."

mkdir -p "${TMP_TEST_DIR}"

# Start JSON file
cat > "${OUTPUT_FILE}.tmp" << EOF
{
  "metadata": {
    "script": "11-audit_coverage_test.sh",
    "analyst": "shamshed rajput",
    "date": "$(date -Iseconds)",
    "hostname": "$(hostname -s)",
    "organization": "MedDefense Health Systems",
    "audit_rules_file": "/etc/audit/rules.d/meddefense.rules"
  },
  "tests": [
EOF

# ------------------------------------------------------------------------------
# TEST 1: Privileged command execution (sudo)
# ------------------------------------------------------------------------------
run_test "1" "sudo execution" "priv_esc" "sudo -n true"

# ------------------------------------------------------------------------------
# TEST 2: Access to /etc/shadow
# ------------------------------------------------------------------------------
run_test "2" "shadow access" "identity" "cat /etc/shadow"

# ------------------------------------------------------------------------------
# TEST 3: Suspicious download tool execution
# ------------------------------------------------------------------------------
run_test "3" "suspicious download tool" "suspicious_download" "wget --version"

# ------------------------------------------------------------------------------
# TEST 4: SSH config file read
# ------------------------------------------------------------------------------
run_test "4" "sshd config read" "sshd_config" "cat /etc/ssh/sshd_config"

# ------------------------------------------------------------------------------
# TEST 5: Monitored test file write
# ------------------------------------------------------------------------------
echo "# MedDefense billing test" > "${TEST_FILE}"
run_test "5" "monitored test file write" "meddefense_db" "echo 'test' >> ${TEST_FILE}"

# ------------------------------------------------------------------------------
# TEST 6: Cron configuration inspection
# ------------------------------------------------------------------------------
run_test "6" "cron configuration check" "cron_jobs" "cat /etc/crontab"

# ------------------------------------------------------------------------------
# REMOVE TRAILING COMMA, CLOSE JSON
# ------------------------------------------------------------------------------
# Remove last comma from the temp file
sed -i '$ s/,$//' "${OUTPUT_FILE}.tmp"

cat >> "${OUTPUT_FILE}.tmp" << EOF
  ],
  "summary": {
    "tests_executed": ${TESTS_EXECUTED},
    "captured": ${TESTS_CAPTURED},
    "missed": ${TESTS_MISSED},
    "auditd_active": "$(systemctl is-active auditd 2>/dev/null || echo 'unknown')",
    "rules_loaded": $(auditctl -l 2>/dev/null | wc -l)
  }
}
EOF

mv "${OUTPUT_FILE}.tmp" "${OUTPUT_FILE}"
chmod 644 "${OUTPUT_FILE}"

# ------------------------------------------------------------------------------
# CLEANUP
# ------------------------------------------------------------------------------
echo "[*] Cleaning test artifacts..."
rm -rf "${TMP_TEST_DIR}"

# ------------------------------------------------------------------------------
# SUMMARY
# ------------------------------------------------------------------------------
echo ""
echo "======================================================================"
echo "  AUDIT COVERAGE TEST - COMPLETE"
echo "======================================================================"
echo "  Tests executed: ${TESTS_EXECUTED}"
echo "  Captured:       ${TESTS_CAPTURED}"
echo "  Missed:         ${TESTS_MISSED}"
echo "  Report saved to: ${OUTPUT_FILE}"
echo "======================================================================"

exit 0
