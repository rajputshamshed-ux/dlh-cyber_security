#!/bin/bash
set -euo pipefail

# ==============================================================================
# PRODUCTION HARDENING ORCHESTRATOR - MEDDEFENSE HEALTH SYSTEMS
# Task 14: Production Hardening Orchestrator
# ==============================================================================
# WHAT IT DOES: Runs all 13 hardening scripts in dependency order. Captures
#               before/after Lynis scores, records timing and exit codes,
#               and generates JSON evidence of the hardening delta.
# WHY: Running scripts one by one is error-prone. This orchestrator ensures
#      correct order, stops on failure, and produces auditable proof that
#      hardening was applied. The JSON output is compliance evidence for
#      HIPAA and Board reporting.
#      IMAGINE: A chef preparing a 13-course meal. Each dish must be done
#      in order. If one fails, the kitchen stops. At the end, a report
#      shows what was cooked, how long it took, and the before/after taste.
# WHEN TO USE: New server deployment, compromised server rebuild, HIPAA
#              audit evidence, Crimson Tide emergency hardening of 3 servers
#              in 2 hours with a single command instead of 13 manual steps.
# ATTACKS BLOCKED: All Crimson Tide phases (1-7) through layered hardening.
# ==============================================================================
# Analyst: shamshed rajput
# Date: 30/07/2026
# Target: billing-srv-01, web-srv-01, log-srv-01
# ==============================================================================

if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] Run with sudo."
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUN_LOG="hardening_run.json"
IMPROVEMENT_LOG="hardening_improvement.json"
TEMP_DIR="/tmp/meddefense-orchestrator-$$"
BEFORE_SCORE=0
AFTER_SCORE=0
STEPS_SCHEDULED=0
STEPS_COMPLETED=0
STEPS_FAILED=0

mkdir -p "${TEMP_DIR}"

# ------------------------------------------------------------------------------
# HARDENING WORKFLOW (in dependency order)
# ------------------------------------------------------------------------------
SCRIPTS=(
    "0-baseline_snapshot.sh"
    "4-ssh_hardening.sh"
    "5-sysctl_hardening.sh"
    "6-filesystem_hardening.sh"
    "7-service_minimization.sh"
    "8-pam_hardening.sh"
    "9-apparmor_config.sh"
    "10-auditd_config.sh"
    "11-audit_coverage_test.sh"
    "12-log_config.sh"
    "13-firewall_baseline.sh"
    "15-validation.sh"
)

STEPS_SCHEDULED=${#SCRIPTS[@]}

# ------------------------------------------------------------------------------
# PRE-CHECKS: Verify all required scripts exist
# ------------------------------------------------------------------------------
echo "[*] Running pre-checks..."

MISSING=0
for script in "${SCRIPTS[@]}"; do
    if [ ! -f "${SCRIPT_DIR}/${script}" ]; then
        echo "    [MISSING] ${script} - file does not exist"
        MISSING=$((MISSING + 1))
    else
        echo "    [OK] ${script} exists"
    fi
done

if [ "${MISSING}" -gt 0 ]; then
    echo "[ERROR] ${MISSING} script(s) missing. Aborting."
    exit 1
fi

echo "Pre-checks: PASS"
echo "Steps scheduled: ${STEPS_SCHEDULED}"

# ------------------------------------------------------------------------------
# CAPTURE BEFORE LYNIS SCORE
# ------------------------------------------------------------------------------
echo "[*] Capturing before Lynis score..."

if command -v lynis >/dev/null 2>&1; then
    lynis audit system --quick 2>/dev/null || true
    if [ -f /var/log/lynis-report.dat ]; then
        BEFORE_SCORE=$(grep "^hardening_index=" /var/log/lynis-report.dat 2>/dev/null | cut -d'=' -f2 || echo 0)
    fi
fi
echo "Before Lynis score: ${BEFORE_SCORE}"

# ------------------------------------------------------------------------------
# START JSON LOG
# ------------------------------------------------------------------------------
cat > "${TEMP_DIR}/run_log.json" << EOF
{
  "metadata": {
    "script": "14-hardening_orchestrator.sh",
    "analyst": "shamshed rajput",
    "date": "$(date -Iseconds)",
    "hostname": "$(hostname -s)",
    "organization": "MedDefense Health Systems"
  },
  "before_score": ${BEFORE_SCORE},
  "steps": [
EOF

# ------------------------------------------------------------------------------
# EXECUTE SCRIPTS
# ------------------------------------------------------------------------------
FIRST_STEP=true

for script in "${SCRIPTS[@]}"; do
    echo ""
    echo "--- Running: ${script} ---"
    
    START_TIME=$(date +%s)
    
    if bash "${SCRIPT_DIR}/${script}" 2>&1; then
        EXIT_CODE=0
        STATUS="PASS"
        STEPS_COMPLETED=$((STEPS_COMPLETED + 1))
        echo "--- ${script}: PASS ---"
    else
        EXIT_CODE=$?
        STATUS="FAIL"
        STEPS_FAILED=$((STEPS_FAILED + 1))
        echo "--- ${script}: FAIL (exit code ${EXIT_CODE}) ---"
    fi
    
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    
    if [ "${FIRST_STEP}" = true ]; then
        FIRST_STEP=false
    else
        echo "," >> "${TEMP_DIR}/run_log.json"
    fi
    
    cat >> "${TEMP_DIR}/run_log.json" << EOF
    {
      "step": "${script}",
      "status": "${STATUS}",
      "exit_code": ${EXIT_CODE},
      "duration_seconds": ${DURATION},
      "timestamp": "$(date -Iseconds)"
    }
EOF
    
    if [ "${STATUS}" = "FAIL" ]; then
        echo ""
        echo "[ERROR] Hardening failed at: ${script}"
        echo "[ERROR] Check logs above for details."
        break
    fi
done

# ------------------------------------------------------------------------------
# CAPTURE AFTER LYNIS SCORE
# ------------------------------------------------------------------------------
echo ""
echo "[*] Capturing after Lynis score..."

if command -v lynis >/dev/null 2>&1; then
    lynis audit system --quick 2>/dev/null || true
    if [ -f /var/log/lynis-report.dat ]; then
        AFTER_SCORE=$(grep "^hardening_index=" /var/log/lynis-report.dat 2>/dev/null | cut -d'=' -f2 || echo 0)
    fi
fi

DELTA=$((AFTER_SCORE - BEFORE_SCORE))
echo "After Lynis score: ${AFTER_SCORE}"
echo "Delta: ${DELTA}"

# ------------------------------------------------------------------------------
# CLOSE JSON LOG
# ------------------------------------------------------------------------------
cat >> "${TEMP_DIR}/run_log.json" << EOF
  ],
  "after_score": ${AFTER_SCORE},
  "delta": ${DELTA},
  "summary": {
    "steps_scheduled": ${STEPS_SCHEDULED},
    "steps_completed": ${STEPS_COMPLETED},
    "steps_failed": ${STEPS_FAILED}
  }
}
EOF

mv "${TEMP_DIR}/run_log.json" "${SCRIPT_DIR}/${RUN_LOG}"
chmod 644 "${SCRIPT_DIR}/${RUN_LOG}"

# ------------------------------------------------------------------------------
# BUILD IMPROVEMENT JSON
# ------------------------------------------------------------------------------
cat > "${SCRIPT_DIR}/${IMPROVEMENT_LOG}" << EOF
{
  "metadata": {
    "script": "14-hardening_orchestrator.sh",
    "date": "$(date -Iseconds)",
    "hostname": "$(hostname -s)"
  },
  "lynis_score": {
    "before": ${BEFORE_SCORE},
    "after": ${AFTER_SCORE},
    "delta": ${DELTA}
  },
  "verdict": "$(if [ "${DELTA}" -gt 20 ]; then echo "SIGNIFICANT_IMPROVEMENT"; elif [ "${DELTA}" -gt 10 ]; then echo "MODERATE_IMPROVEMENT"; else echo "MINIMAL_IMPROVEMENT"; fi)"
}
EOF

chmod 644 "${SCRIPT_DIR}/${IMPROVEMENT_LOG}"

# ------------------------------------------------------------------------------
# CLEANUP
# ------------------------------------------------------------------------------
rm -rf "${TEMP_DIR}"

# ------------------------------------------------------------------------------
# FINAL SUMMARY
# ------------------------------------------------------------------------------
echo ""
echo "======================================================================"
echo "  HARDENING ORCHESTRATOR - COMPLETE"
echo "======================================================================"
echo "  Pre-checks:         PASS"
echo "  Steps scheduled:    ${STEPS_SCHEDULED}"
echo "  Steps completed:    ${STEPS_COMPLETED}"
echo "  Steps failed:       ${STEPS_FAILED}"
echo "  Before Lynis score: ${BEFORE_SCORE}"
echo "  After Lynis score:  ${AFTER_SCORE}"
echo "  Delta:              ${DELTA}"
echo "----------------------------------------------------------------------"
echo "  Run log saved to:   ${RUN_LOG}"
echo "  Improvement saved:  ${IMPROVEMENT_LOG}"
echo "======================================================================"

exit 0
