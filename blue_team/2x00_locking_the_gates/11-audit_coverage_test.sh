#!/bin/bash
set -euo pipefail

# ==============================================================================
# AUDIT TELEMETRY COVERAGE TEST - MEDDEFENSE HEALTH SYSTEMS
# Task 11: Audit Telemetry Coverage Test
# Analyst: shamshed rajput
# Target: billing-srv-01
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

run_test() {
    local test_num="$1"
    local test_name="$2"
    local audit_key="$3"
    local test_command="$4"
    
    TESTS_EXECUTED=$((TESTS_EXECUTED + 1))
    echo -n "[${test_num}/6] ${test_name}"
    
    local before_time
    before_time=$(date +%s)
    eval "${test_command}" 2>/dev/null || true
    sleep 1
    
    local event_count
    event_count=$(ausearch -k "${audit_key}" 2>/dev/null | grep -c "type=" || echo 0)
    
    printf "%-35s" ""
    if [ "${event_count}" -gt 0 ]; then
        echo " [CAPTURED]"
        TESTS_CAPTURED=$((TESTS_CAPTURED + 1))
        echo "      {\"test_id\":${test_num},\"test_name\":\"${test_name}\",\"audit_key\":\"${audit_key}\",\"captured\":true}," >> "${OUTPUT_FILE}.tmp"
    else
        echo " [MISSED]"
        TESTS_MISSED=$((TESTS_MISSED + 1))
        echo "      {\"test_id\":${test_num},\"test_name\":\"${test_name}\",\"audit_key\":\"${audit_key}\",\"captured\":false}," >> "${OUTPUT_FILE}.tmp"
    fi
}

echo "[*] Running audit telemetry coverage tests..."
mkdir -p "${TMP_TEST_DIR}"

echo "{" > "${OUTPUT_FILE}.tmp"
echo '  "tests": [' >> "${OUTPUT_FILE}.tmp"

# Test 1: sudo (priv_esc key)
run_test "1" "sudo execution" "priv_esc" "sudo -n true"

# Test 2: shadow access (identity key)
run_test "2" "shadow access" "identity" "cat /etc/shadow"

# Test 3: wget AND curl execution (suspicious_download key)
run_test "3" "suspicious download tool" "suspicious_download" "wget --version; curl --version"

# Test 4: sshd_config read (sshd_config key)
run_test "4" "sshd config read" "sshd_config" "cat /etc/ssh/sshd_config"

# Test 5: monitored file write (meddefense_db key)
echo "# MedDefense billing test" > "${TEST_FILE}"
run_test "5" "monitored test file write" "meddefense_db" "echo 'test' >> ${TEST_FILE}"

# Test 6: cron config check (cron_jobs key)
run_test "6" "cron configuration check" "cron_jobs" "cat /etc/crontab"

# Remove trailing comma, close JSON
sed -i '$ s/,$//' "${OUTPUT_FILE}.tmp"
cat >> "${OUTPUT_FILE}.tmp" << EOF
  ],
  "summary": {
    "tests_executed": ${TESTS_EXECUTED},
    "captured": ${TESTS_CAPTURED},
    "missed": ${TESTS_MISSED}
  }
}
EOF

mv "${OUTPUT_FILE}.tmp" "${OUTPUT_FILE}"

echo "[*] Cleaning test artifacts..."
rm -rf "${TMP_TEST_DIR}"

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
