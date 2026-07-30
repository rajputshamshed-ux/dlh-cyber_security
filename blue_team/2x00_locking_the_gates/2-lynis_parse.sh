#!/bin/bash
set -euo pipefail

# ==============================================================================
# LYNIS AUDIT PARSER - MEDDEFENSE HEALTH SYSTEMS
# Task 2: The Lynis Audit Parser
# ==============================================================================
# Analyst: shamshed rajput
# Date: 30/07/2026
# Purpose: Parse a Lynis report file (.dat) and produce a structured JSON
#          summary of hardening index, warnings, suggestions, and manual
#          checks. Output is machine-readable for automated analysis.
# ==============================================================================

# ------------------------------------------------------------------------------
# USAGE CHECK
# ------------------------------------------------------------------------------
if [ $# -lt 1 ]; then
    echo "Usage: $0 <path-to-lynis-report.dat>"
    echo "Example: $0 /var/log/lynis-report.dat"
    exit 1
fi

REPORT_FILE="$1"

if [ ! -f "${REPORT_FILE}" ]; then
    echo "Error: Report file not found: ${REPORT_FILE}"
    echo "Run a Lynis audit first: sudo lynis audit system"
    exit 1
fi

# ------------------------------------------------------------------------------
# EXTRACT HARDENING INDEX
# ------------------------------------------------------------------------------
HARDENING_INDEX=$(grep "^hardening_index=" "${REPORT_FILE}" 2>/dev/null | cut -d'=' -f2 || echo "0")

# ------------------------------------------------------------------------------
# EXTRACT FINDINGS
# ------------------------------------------------------------------------------

# Temporary file for building JSON array
TMP_JSON=$(mktemp)

# Start JSON array
echo "[" > "${TMP_JSON}"

FIRST=true

# Function to parse a section (warning[], suggestion[], manual_check[])
parse_section() {
    local severity="$1"
    local section="$2"
    
    grep "^${section}\[" "${REPORT_FILE}" 2>/dev/null | while IFS= read -r line; do
        # Extract fields from format: section[index]=test_id|message|details
        # Remove the prefix "section[index]="
        content="${line#*=}"
        
        # Split on | separator
        test_id=$(echo "${content}" | cut -d'|' -f1)
        message=$(echo "${content}" | cut -d'|' -f2-)
        
        # Escape special characters for JSON
        message_escaped=$(echo "${message}" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')
        test_id_escaped=$(echo "${test_id}" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')
        
        # Add comma if not first entry
        if [ "${FIRST}" = true ]; then
            FIRST=false
        else
            echo "," >> "${TMP_JSON}"
        fi
        
        cat >> "${TMP_JSON}" << EOF
    {
      "severity": "${severity}",
      "test_id": "${test_id_escaped}",
      "message": "${message_escaped}"
    }
EOF
    done
}

# Parse warnings (highest priority)
parse_section "warning" "warning"

# Parse manual checks (medium priority)
parse_section "manual_check" "manual"

# Parse suggestions (lowest priority)
parse_section "suggestion" "suggestion"

# Close JSON array
echo "" >> "${TMP_JSON}"
echo "]" >> "${TMP_JSON}"

# ------------------------------------------------------------------------------
# BUILD FINAL JSON OUTPUT
# ------------------------------------------------------------------------------

# Count findings by severity
WARNING_COUNT=$(grep "^warning\[" "${REPORT_FILE}" 2>/dev/null | wc -l || echo 0)
MANUAL_COUNT=$(grep "^manual_check\[" "${REPORT_FILE}" 2>/dev/null | wc -l || echo 0)
SUGGESTION_COUNT=$(grep "^suggestion\[" "${REPORT_FILE}" 2>/dev/null | wc -l || echo 0)
TOTAL_FINDINGS=$((WARNING_COUNT + MANUAL_COUNT + SUGGESTION_COUNT))

FINDINGS_JSON=$(cat "${TMP_JSON}")

# Build complete JSON
cat << EOF
{
  "metadata": {
    "script": "2-lynis_parse.sh",
    "analyst": "shamshed rajput",
    "date": "$(date -Iseconds)",
    "report_file": "${REPORT_FILE}",
    "organization": "MedDefense Health Systems"
  },
  "hardening_index": ${HARDENING_INDEX},
  "finding_counts": {
    "total": ${TOTAL_FINDINGS},
    "warnings": ${WARNING_COUNT},
    "manual_checks": ${MANUAL_COUNT},
    "suggestions": ${SUGGESTION_COUNT}
  },
  "findings": ${FINDINGS_JSON}
}
EOF

# Cleanup
rm -f "${TMP_JSON}"

# Print summary to stderr (doesn't affect JSON stdout)
echo "[*] Lynis report parsed successfully:" >&2
echo "[*]   Hardening Index: ${HARDINGEN_INDEX}" >&2
echo "[*]   Warnings: ${WARNING_COUNT}" >&2
echo "[*]   Manual Checks: ${MANUAL_COUNT}" >&2
echo "[*]   Suggestions: ${SUGGESTION_COUNT}" >&2
echo "[*]   Total Findings: ${TOTAL_FINDINGS}" >&2
echo "[*] Pipe output to jq or save to file." >&2

exit 0
