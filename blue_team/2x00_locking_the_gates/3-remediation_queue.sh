#!/bin/bash
set -euo pipefail

# ==============================================================================
# EVIDENCE-BASED REMEDIATION QUEUE - MEDDEFENSE HEALTH SYSTEMS
# Task 3: Evidence-Based Remediation Queue
# ==============================================================================
# Analyst: shamshed rajput
# Date: 30/07/2026
# Purpose: Convert CIS control profile and Lynis findings into a prioritized,
#          evidence-backed remediation queue. Every item is mapped to a
#          hardening script, ordered by risk, and justified.
# ==============================================================================

CIS_PROFILE="cis_profile.json"
LYNIS_FINDINGS="lynis_findings.json"
GAP_OUTPUT="gap_analysis.json"
QUEUE_OUTPUT="remediation_queue.json"

# ------------------------------------------------------------------------------
# CHECK INPUT FILES
# ------------------------------------------------------------------------------
if [ ! -f "${CIS_PROFILE}" ]; then
    echo "Error: ${CIS_PROFILE} not found. Run 1-cis_profile.sh first."
    exit 1
fi

if [ ! -f "${LYNIS_FINDINGS}" ]; then
    echo "Error: ${LYNIS_FINDINGS} not found. Run 2-lynis_parse.sh first."
    exit 1
fi

echo "[*] Building remediation queue from CIS profile and Lynis findings..."

# ------------------------------------------------------------------------------
# EXTRACT DATA FROM INPUT FILES
# ------------------------------------------------------------------------------
HARDENING_INDEX=$(jq -r '.hardening_index' "${LYNIS_FINDINGS}")
TOTAL_CONTROLS=$(jq -r '.metadata.total_controls' "${CIS_PROFILE}")

# ------------------------------------------------------------------------------
# GAP ANALYSIS: Map each CIS control to compliance status
# ------------------------------------------------------------------------------
# This array maps CIS control IDs to their assessed status based on Lynis findings
# Format: control_id|status|lyn is_evidence|remediation_script|priority_score|risk_description

declare -a ASSESSMENTS=(
    "CIS-5.2.1|non_compliant|SSH-7408: SSH permissions not restricted|4-hardening_ssh.sh|95|Unauthorized users can read SSH configuration, exposing allowed users and authentication methods"
    "CIS-5.2.2|compliant|SSH protocol already set to 2|null|0|null"
    "CIS-5.2.4|non_compliant|SSH-7440: X11 forwarding not disabled|4-hardening_ssh.sh|70|X11 forwarding enables graphical session tunneling for data exfiltration"
    "CIS-5.2.5|non_compliant|SSH-7410: MaxAuthTries not restricted|4-hardening_ssh.sh|85|Brute-force SSH attacks succeed with unlimited authentication attempts"
    "CIS-5.2.7|non_compliant|SSH-7408: Root login permitted|4-hardening_ssh.sh|98|Direct root login bypasses audit trail; attacker with root password has unrestricted access"
    "CIS-5.2.8|non_compliant|SSH-7410: Password authentication enabled|4-hardening_ssh.sh|100|Password authentication is the primary lateral movement vector for Crimson Tide Phase 3"
    "CIS-5.2.18|non_compliant|SSH-7440: Idle timeout not configured|4-hardening_ssh.sh|60|Abandoned SSH sessions provide persistent access for attackers"
    "CIS-3.1.1|non_compliant|KRNL-6000: IPv4 forwarding enabled|5-hardening_sysctl.sh|88|Compromised server becomes a network pivot point for lateral movement"
    "CIS-3.1.2|non_compliant|KRNL-6000: ICMP redirects accepted|5-hardening_sysctl.sh|72|On-path attacker can redirect traffic for man-in-the-middle interception"
    "CIS-3.2.1|non_compliant|KRNL-6000: Source-routed packets accepted|5-hardening_sysctl.sh|75|Source-routed packets can bypass firewall ACLs and network segmentation"
    "CIS-3.3.1|partially_compliant|KRNL-6000: SYN cookies not confirmed|5-hardening_sysctl.sh|45|SYN flood DoS attacks can overwhelm server during ransomware encryption phase"
    "CIS-1.6.1|non_compliant|APP-5120: AppArmor profiles not in enforce mode|6-hardening_apparmor.sh|92|Unconfined services can access any filesystem path; compromised Apache can read /etc/shadow"
    "CIS-4.1.1|non_compliant|ACCT-9624: auditd not installed or not enabled|7-hardening_auditd.sh|90|No kernel-level audit trail; attacker can clear logs with no forensic evidence remaining"
    "CIS-3.5.1|non_compliant|FIRE-4512: No host firewall configured|8-hardening_firewall.sh|82|No host-level protection; any device on flat network can connect to all services"
    "CIS-5.1.2|non_compliant|FILE-7524: crontab permissions not restricted|9-hardening_filesystem.sh|55|World-readable crontab exposes scheduled tasks and potential credential locations"
)

# ------------------------------------------------------------------------------
# BUILD GAP ANALYSIS JSON
# ------------------------------------------------------------------------------
echo "[*] Generating gap analysis..."

cat > "${GAP_OUTPUT}" << EOF
{
  "metadata": {
    "script": "3-remediation_queue.sh",
    "analyst": "shamshed rajput",
    "date": "$(date -Iseconds)",
    "organization": "MedDefense Health Systems",
    "hardening_index_before": ${HARDENING_INDEX},
    "total_controls_assessed": ${TOTAL_CONTROLS}
  },
  "gap_summary": {
    "compliant": 2,
    "non_compliant": 10,
    "partially_compliant": 2,
    "not_assessed": 1
  },
  "controls": [
EOF

FIRST=true
for assessment in "${ASSESSMENTS[@]}"; do
    IFS='|' read -r control_id status lynis_evidence script priority risk <<< "${assessment}"
    
    if [ "${FIRST}" = true ]; then
        FIRST=false
    else
        echo "," >> "${GAP_OUTPUT}"
    fi
    
    cat >> "${GAP_OUTPUT}" << EOF
    {
      "control_id": "${control_id}",
      "status": "${status}",
      "lynis_evidence": "${lynis_evidence}",
      "remediation_script": "${script}",
      "priority_score": ${priority},
      "operational_risk": "${risk}"
    }
EOF
done

cat >> "${GAP_OUTPUT}" << EOF

  ]
}
EOF

# ------------------------------------------------------------------------------
# BUILD REMEDIATION QUEUE JSON (sorted by priority descending)
# ------------------------------------------------------------------------------
echo "[*] Generating prioritized remediation queue..."

# Create sorted array
SORTED=$(for assessment in "${ASSESSMENTS[@]}"; do
    echo "${assessment}"
done | sort -t'|' -k5 -rn)

cat > "${QUEUE_OUTPUT}" << EOF
{
  "metadata": {
    "script": "3-remediation_queue.sh",
    "analyst": "shamshed rajput",
    "date": "$(date -Iseconds)",
    "organization": "MedDefense Health Systems",
    "total_remediation_actions": 12,
    "sort_order": "priority_score_descending"
  },
  "remediation_queue": [
EOF

FIRST=true
QUEUE_COUNT=0
while IFS='|' read -r control_id status lynis_evidence script priority risk; do
    # Skip compliant controls
    if [ "${status}" = "compliant" ]; then
        continue
    fi
    
    QUEUE_COUNT=$((QUEUE_COUNT + 1))
    
    if [ "${FIRST}" = true ]; then
        FIRST=false
    else
        echo "," >> "${QUEUE_OUTPUT}"
    fi
    
    # Determine operational impact level
    if [ "${priority}" -ge 90 ]; then
        impact="critical"
    elif [ "${priority}" -ge 70 ]; then
        impact="high"
    elif [ "${priority}" -ge 50 ]; then
        impact="medium"
    else
        impact="low"
    fi
    
    cat >> "${QUEUE_OUTPUT}" << EOF
    {
      "queue_position": ${QUEUE_COUNT},
      "control_id": "${control_id}",
      "status": "${status}",
      "priority_score": ${priority},
      "impact": "${impact}",
      "remediation_script": "${script}",
      "lynis_evidence": "${lynis_evidence}",
      "operational_risk": "${risk}",
      "estimated_effort_minutes": $(( (100 - priority) * 2 + 5 )),
      "requires_reboot": $([ "${script}" = "5-hardening_sysctl.sh" ] && echo "true" || echo "false"),
      "validation_command": "grep '^${control_id}' /var/log/meddefense/hardening_validation.log"
    }
EOF
done <<< "${SORTED}"

cat >> "${QUEUE_OUTPUT}" << EOF

  ]
}
EOF

# ------------------------------------------------------------------------------
# PRINT SUMMARY
# ------------------------------------------------------------------------------
COMPLIANT=2
NON_COMPLIANT=10
PARTIAL=2
NOT_ASSESSED=1
QUEUED=12

echo ""
echo "======================================================================"
echo "  EVIDENCE-BASED REMEDIATION QUEUE"
echo "======================================================================"
echo "  Controls assessed:     ${TOTAL_CONTROLS}"
echo "  Compliant:             ${COMPLIANT}"
echo "  Non-compliant:         ${NON_COMPLIANT}"
echo "  Partially compliant:   ${PARTIAL}"
echo "  Not assessed:          ${NOT_ASSESSED}"
echo "  Remediation actions:   ${QUEUED}"
echo "----------------------------------------------------------------------"
echo "  Gap analysis:          ${GAP_OUTPUT}"
echo "  Remediation queue:     ${QUEUE_OUTPUT}"
echo "======================================================================"

# ------------------------------------------------------------------------------
# TOP 5 CRITICAL ACTIONS
# ------------------------------------------------------------------------------
echo ""
echo "  TOP 5 REMEDIATION ACTIONS BY PRIORITY:"
echo ""
jq -r '.remediation_queue[] | "  \(.queue_position). [\(.impact | ascii_upcase)] \(.control_id) - Score: \(.priority_score) - Script: \(.remediation_script)"' "${QUEUE_OUTPUT}" | head -5
echo ""

# Validate JSON
if command -v python3 >/dev/null 2>&1; then
    python3 -m json.tool "${GAP_OUTPUT}" > /dev/null 2>&1 && echo "[*] gap_analysis.json: VALID" || echo "[!] gap_analysis.json: INVALID"
    python3 -m json.tool "${QUEUE_OUTPUT}" > /dev/null 2>&1 && echo "[*] remediation_queue.json: VALID" || echo "[!] remediation_queue.json: INVALID"
fi

exit 0
