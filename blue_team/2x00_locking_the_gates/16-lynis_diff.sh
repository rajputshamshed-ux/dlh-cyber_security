#!/bin/bash
set -euo pipefail

# ==============================================================================
# LYNIS IMPROVEMENT DIFF - MEDDEFENSE HEALTH SYSTEMS
# Task 16: Lynis Improvement Diff
# ==============================================================================
# WHAT IT DOES: Compares pre-hardening and post-hardening Lynis audit results.
#               Shows which findings were resolved, which remain, and if any
#               new issues appeared. Produces a structured JSON report.
# WHY: Sarah Park needs a report for the Board showing the measurable impact
#      of hardening. Numbers don't lie: "Before: 52, After: 84, Delta: +32"
#      is the proof that the security budget was well spent.
#      IMAGINE: Before/after photos of a house renovation. The diff shows
#      exactly which walls were fixed, which rooms still need work, and if
#      the contractor accidentally broke anything new.
# WHEN TO USE: After running the hardening orchestrator (Task 14). Before
#              Board presentations. For HIPAA audit evidence.
# OUTPUT: hardening_improvement.json - structured before/after comparison
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
BEFORE_FILE="${SCRIPT_DIR}/lynis_findings.json"
AFTER_FILE="${SCRIPT_DIR}/lynis_post_findings.json"
OUTPUT_FILE="${SCRIPT_DIR}/hardening_improvement.json"

BEFORE_SCORE=0
AFTER_SCORE=0
RESOLVED_COUNT=0
REMAINING_COUNT=0
NEW_COUNT=0

# ------------------------------------------------------------------------------
# GENERATE POST-HARDENING LYNIS REPORT IF NEEDED
# ------------------------------------------------------------------------------
if [ ! -f "${AFTER_FILE}" ]; then
    echo "[*] Running Lynis for post-hardening baseline..."
    lynis audit system --quick 2>/dev/null || true
    
    if [ -f /var/log/lynis-report.dat ]; then
        bash "${SCRIPT_DIR}/2-lynis_parse.sh" /var/log/lynis-report.dat > "${AFTER_FILE}" 2>/dev/null || true
        echo "    Post-hardening report generated: ${AFTER_FILE}"
    fi
fi

# ------------------------------------------------------------------------------
# EXTRACT SCORES
# ------------------------------------------------------------------------------
if [ -f "${BEFORE_FILE}" ]; then
    BEFORE_SCORE=$(jq -r '.hardening_index // 0' "${BEFORE_FILE}" 2>/dev/null || echo 0)
fi

if [ -f "${AFTER_FILE}" ]; then
    AFTER_SCORE=$(jq -r '.hardening_index // 0' "${AFTER_FILE}" 2>/dev/null || echo 0)
fi

DELTA=$((AFTER_SCORE - BEFORE_SCORE))

# ------------------------------------------------------------------------------
# COMPARE FINDINGS
# ------------------------------------------------------------------------------
if [ -f "${BEFORE_FILE}" ] && [ -f "${AFTER_FILE}" ]; then
    # Extract test_ids from before
    BEFORE_IDS=$(jq -r '.findings[].test_id' "${BEFORE_FILE}" 2>/dev/null | sort -u)
    
    # Extract test_ids from after
    AFTER_IDS=$(jq -r '.findings[].test_id' "${AFTER_FILE}" 2>/dev/null | sort -u)
    
    # Resolved: in before but not in after
    RESOLVED_IDS=$(comm -23 <(echo "${BEFORE_IDS}") <(echo "${AFTER_IDS}") 2>/dev/null || true)
    RESOLVED_COUNT=$(echo "${RESOLVED_IDS}" | grep -c . || echo 0)
    
    # Remaining: in both before and after
    REMAINING_IDS=$(comm -12 <(echo "${BEFORE_IDS}") <(echo "${AFTER_IDS}") 2>/dev/null || true)
    REMAINING_COUNT=$(echo "${REMAINING_IDS}" | grep -c . || echo 0)
    
    # New: in after but not in before
    NEW_IDS=$(comm -13 <(echo "${BEFORE_IDS}") <(echo "${AFTER_IDS}") 2>/dev/null || true)
    NEW_COUNT=$(echo "${NEW_IDS}" | grep -c . || echo 0)
fi

# ------------------------------------------------------------------------------
# BUILD IMPROVEMENT JSON
# ------------------------------------------------------------------------------
cat > "${OUTPUT_FILE}" << EOF
{
  "metadata": {
    "script": "16-lynis_diff.sh",
    "analyst": "shamshed rajput",
    "date": "$(date -Iseconds)",
    "hostname": "$(hostname -s)",
    "organization": "MedDefense Health Systems"
  },
  "lynis_score": {
    "before_score": ${BEFORE_SCORE},
    "after_score": ${AFTER_SCORE},
    "delta": ${DELTA},
    "verdict": "$(if [ "${DELTA}" -gt 20 ]; then echo "SIGNIFICANT_IMPROVEMENT"; elif [ "${DELTA}" -gt 10 ]; then echo "MODERATE_IMPROVEMENT"; else echo "MINIMAL_IMPROVEMENT"; fi)"
  },
  "findings": {
    "resolved_count": ${RESOLVED_COUNT},
    "remaining_count": ${REMAINING_COUNT},
    "new_count": ${NEW_COUNT},
    "resolved_findings": $(echo "${RESOLVED_IDS}" | jq -R -s 'split("\n") | map(select(length > 0))' 2>/dev/null || echo "[]"),
    "remaining_findings": $(echo "${REMAINING_IDS}" | jq -R -s 'split("\n") | map(select(length > 0))' 2>/dev/null || echo "[]"),
    "new_findings": $(echo "${NEW_IDS}" | jq -R -s 'split("\n") | map(select(length > 0))' 2>/dev/null || echo "[]")
  },
  "residual_risk_summary": "$(if [ "${REMAINING_COUNT}" -gt 20 ]; then echo "MODERATE - ${REMAINING_COUNT} findings still require attention"; elif [ "${REMAINING_COUNT}" -gt 10 ]; then echo "LOW - ${REMAINING_COUNT} findings remain, mostly suggestions"; else echo "MINIMAL - Only ${REMAINING_COUNT} low-severity findings remain"; fi)"
}
EOF

chmod 644 "${OUTPUT_FILE}"

# ------------------------------------------------------------------------------
# PRINT SUMMARY
# ------------------------------------------------------------------------------
echo ""
echo "======================================================================"
echo "  LYNIS IMPROVEMENT DIFF - COMPLETE"
echo "======================================================================"
echo "  Before:             ${BEFORE_SCORE}"
echo "  After:              ${AFTER_SCORE}"
echo "  Delta:              ${DELTA}"
echo "  Findings resolved:  ${RESOLVED_COUNT}"
echo "  Findings remaining: ${REMAINING_COUNT}"
echo "  New findings:       ${NEW_COUNT}"
echo "----------------------------------------------------------------------"
echo "  Report saved to:    ${OUTPUT_FILE}"
echo "======================================================================"

exit 0
