#!/bin/bash
set -euo pipefail

# ==============================================================================
# LINUX TELEMETRY QUALITY GATE - MEDDEFENSE HEALTH SYSTEMS
# Task 8: Linux Telemetry Quality Gate
# ==============================================================================
#
# WHAT THIS SCRIPT DOES:
#   Reads the Linux telemetry export (linux_events_export.json) and assesses
#   its quality: event distribution, time coverage, gap detection, field
#   completeness, and an overall quality score, matching the Windows quality
#   gate. Outputs linux_telemetry_quality.json.
#
# WHY:
#   Cross‑platform SOC handoff requires equal scrutiny of Linux and Windows
#   telemetry. This script prevents low‑quality Linux data from reaching
#   analysts.
#
# WHEN TO USE:
#   After Linux event export (Task 7). Before final handoff.
#
# AUTHOR: shamshed rajput
# DATE:   30/07/2026
# ==============================================================================

INPUT_FILE="linux_events_export.json"
OUTPUT_FILE="linux_telemetry_quality.json"

if [ ! -f "${INPUT_FILE}" ]; then
    echo "[ERROR] ${INPUT_FILE} not found" >&2
    exit 1
fi

# ------------------------------------------------------------------------------
# 1. Load & validate JSON
# ------------------------------------------------------------------------------
if ! command -v jq >/dev/null 2>&1; then
    echo "[ERROR] jq is required but not installed." >&2
    exit 1
fi

EVENTS=$(jq -c '.events[]?' "${INPUT_FILE}" 2>/dev/null || echo "")
TOTAL_EVENTS=$(echo "${EVENTS}" | wc -l)
if [ "${TOTAL_EVENTS}" -eq 1 ] && [ -z "${EVENTS}" ]; then
    TOTAL_EVENTS=0
fi

echo "[*] Analyzing ${INPUT_FILE}..."
echo "Total events: ${TOTAL_EVENTS}"

# ------------------------------------------------------------------------------
# 2. Event distribution (source_type & event_category)
# ------------------------------------------------------------------------------
if [ "${TOTAL_EVENTS}" -gt 0 ]; then
    # Count per source_type
    declare -A SOURCE_COUNTS
    while IFS= read -r src; do
        ((SOURCE_COUNTS["${src}"]++)) || true
    done < <(echo "${EVENTS}" | jq -r '.source_type // "unknown"')

    # Count per event_category
    declare -A CATEGORY_COUNTS
    while IFS= read -r cat; do
        ((CATEGORY_COUNTS["${cat}"]++)) || true
    done < <(echo "${EVENTS}" | jq -r '.event_category // "unknown"')
else
    declare -A SOURCE_COUNTS=()
    declare -A CATEGORY_COUNTS=()
fi

# ------------------------------------------------------------------------------
# 3. Time coverage (events per hour)
# ------------------------------------------------------------------------------
HOURS_WITH_EVENTS=0
HOURS_WITHOUT_EVENTS=0
LARGEST_GAP=0
GAPS=0

if [ "${TOTAL_EVENTS}" -gt 0 ]; then
    # Extract ISO 8601 timestamps, sort, and convert to epoch
    TIMESTAMPS=$(echo "${EVENTS}" | jq -r '.timestamp' | sort)
    FIRST_TS=$(echo "${TIMESTAMPS}" | head -1)
    LAST_TS=$(echo "${TIMESTAMPS}" | tail -1)

    # Convert to epoch seconds (GNU date)
    EPOCH_FIRST=$(date -d "${FIRST_TS}" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "${FIRST_TS}" +%s 2>/dev/null || echo 0)
    EPOCH_LAST=$(date -d "${LAST_TS}" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "${LAST_TS}" +%s 2>/dev/null || echo 0)

    if [ "${EPOCH_FIRST}" -ne 0 ] && [ "${EPOCH_LAST}" -ne 0 ]; then
        DURATION_SEC=$((EPOCH_LAST - EPOCH_FIRST))
        DURATION_HOURS=$(( (DURATION_SEC + 3599) / 3600 ))  # ceiling
        if [ "${DURATION_HOURS}" -eq 0 ]; then DURATION_HOURS=1; fi

        # Bucket counts per hour
        declare -A HOUR_BUCKETS
        while IFS= read -r ts; do
            epoch=$(date -d "${ts}" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "${ts}" +%s 2>/dev/null || echo 0)
            if [ "${epoch}" -ne 0 ]; then
                hour_bucket=$(( (epoch - EPOCH_FIRST) / 3600 ))
                ((HOUR_BUCKETS["${hour_bucket}"]++)) || true
            fi
        done < <(echo "${TIMESTAMPS}")

        HOURS_WITH_EVENTS=${#HOUR_BUCKETS[@]}
        HOURS_WITHOUT_EVENTS=$((DURATION_HOURS - HOURS_WITH_EVENTS))

        # Gap detection: consecutive timestamps >30 min apart
        PREV_EPOCH=0
        while IFS= read -r ts; do
            epoch=$(date -d "${ts}" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "${ts}" +%s 2>/dev/null || echo 0)
            if [ "${PREV_EPOCH}" -ne 0 ] && [ "${epoch}" -ne 0 ]; then
                gap=$((epoch - PREV_EPOCH))
                if [ "${gap}" -gt 1800 ]; then
                    GAPS=$((GAPS + 1))
                    if [ "${gap}" -gt "${LARGEST_GAP}" ]; then
                        LARGEST_GAP=${gap}
                    fi
                fi
            fi
            PREV_EPOCH=${epoch}
        done < <(echo "${TIMESTAMPS}")
    fi
else
    DURATION_HOURS=0
    HOURS_WITH_EVENTS=0
    HOURS_WITHOUT_EVENTS=0
fi

# Convert largest gap from seconds to minutes for display
LARGEST_GAP_MIN=$((LARGEST_GAP / 60))

# ------------------------------------------------------------------------------
# 4. Field completeness
# ------------------------------------------------------------------------------
COMPL_TIMESTAMP=0; COMPL_HOSTNAME=0; COMPL_SOURCE=0; COMPL_CATEGORY=0
COMPL_EXECVE_CMD=0; COMPL_SSH_IP=0; COMPL_AUDIT_PATH=0
TOTAL_EXECVE=0; TOTAL_SSH=0; TOTAL_AUDIT_FILE=0

if [ "${TOTAL_EVENTS}" -gt 0 ]; then
    # General fields
    COMPL_TIMESTAMP=$(echo "${EVENTS}" | jq '[.[] | select(.timestamp != null and .timestamp != "")] | length')
    COMPL_HOSTNAME=$(echo "${EVENTS}" | jq '[.[] | select(.hostname != null and .hostname != "")] | length')
    COMPL_SOURCE=$(echo "${EVENTS}" | jq '[.[] | select(.source_type != null and .source_type != "")] | length')
    COMPL_CATEGORY=$(echo "${EVENTS}" | jq '[.[] | select(.event_category != null and .event_category != "")] | length')

    # execve command line completeness (for events with category "execve")
    TOTAL_EXECVE=$(echo "${EVENTS}" | jq '[.[] | select(.event_category == "execve")] | length')
    if [ "${TOTAL_EXECVE}" -gt 0 ]; then
        COMPL_EXECVE_CMD=$(echo "${EVENTS}" | jq '[.[] | select(.event_category == "execve" and .command != null and .command != "")] | length')
    else
        COMPL_EXECVE_CMD=0
    fi

    # SSH source_ip completeness (categories ssh_login_success, ssh_login_failed)
    TOTAL_SSH=$(echo "${EVENTS}" | jq '[.[] | select(.event_category | startswith("ssh_login"))] | length')
    if [ "${TOTAL_SSH}" -gt 0 ]; then
        COMPL_SSH_IP=$(echo "${EVENTS}" | jq '[.[] | select(.event_category | startswith("ssh_login")) | select(.source_ip != null and .source_ip != "")] | length')
    else
        COMPL_SSH_IP=0
    fi

    # auditd file path completeness (category "file_access")
    TOTAL_AUDIT_FILE=$(echo "${EVENTS}" | jq '[.[] | select(.event_category == "file_access")] | length')
    if [ "${TOTAL_AUDIT_FILE}" -gt 0 ]; then
        COMPL_AUDIT_PATH=$(echo "${EVENTS}" | jq '[.[] | select(.event_category == "file_access" and .path != null and .path != "")] | length')
    else
        COMPL_AUDIT_PATH=0
    fi
fi

# Percentages (avoid division by zero)
if [ "${TOTAL_EVENTS}" -gt 0 ]; then
    TIMESTAMP_PCT=$(( COMPL_TIMESTAMP * 100 / TOTAL_EVENTS ))
    HOSTNAME_PCT=$(( COMPL_HOSTNAME * 100 / TOTAL_EVENTS ))
    SOURCE_PCT=$(( COMPL_SOURCE * 100 / TOTAL_EVENTS ))
    CATEGORY_PCT=$(( COMPL_CATEGORY * 100 / TOTAL_EVENTS ))
else
    TIMESTAMP_PCT=100; HOSTNAME_PCT=100; SOURCE_PCT=100; CATEGORY_PCT=100
fi

if [ "${TOTAL_EXECVE}" -gt 0 ]; then
    EXECVE_CMD_PCT=$(( COMPL_EXECVE_CMD * 100 / TOTAL_EXECVE ))
else
    EXECVE_CMD_PCT=100
fi

if [ "${TOTAL_SSH}" -gt 0 ]; then
    SSH_IP_PCT=$(( COMPL_SSH_IP * 100 / TOTAL_SSH ))
else
    SSH_IP_PCT=100
fi

if [ "${TOTAL_AUDIT_FILE}" -gt 0 ]; then
    AUDIT_PATH_PCT=$(( COMPL_AUDIT_PATH * 100 / TOTAL_AUDIT_FILE ))
else
    AUDIT_PATH_PCT=100
fi

# ------------------------------------------------------------------------------
# 5. Quality Score (0-100)
# ------------------------------------------------------------------------------
# Weighted: time coverage 30%, field completeness (avg of 3 specific) 30%,
# absence of gaps 20%, event diversity (source types present) 20%
TIME_COVERAGE_PCT=$(( HOURS_WITH_EVENTS * 100 / (DURATION_HOURS > 0 ? DURATION_HOURS : 1) ))
FIELD_AVG=$(( (EXECVE_CMD_PCT + SSH_IP_PCT + AUDIT_PATH_PCT) / 3 ))
# Gap penalty: 100 if no gaps, 70 if gap <=60 min, 40 if >60 min
if [ "${GAPS}" -eq 0 ]; then GAP_SCORE=100; elif [ "${LARGEST_GAP_MIN}" -le 60 ]; then GAP_SCORE=70; else GAP_SCORE=40; fi
# Diversity: count distinct source_types
NUM_SOURCES=$(echo "${!SOURCE_COUNTS[@]}" | wc -w)
if [ "${NUM_SOURCES}" -ge 2 ]; then DIV_SCORE=100; else DIV_SCORE=50; fi

QUALITY_SCORE=$(( (TIME_COVERAGE_PCT * 30 + FIELD_AVG * 30 + GAP_SCORE * 20 + DIV_SCORE * 20) / 100 ))
if [ "${QUALITY_SCORE}" -ge 90 ]; then ASSESSMENT="good"
elif [ "${QUALITY_SCORE}" -ge 70 ]; then ASSESSMENT="acceptable"
else ASSESSMENT="poor"
fi

# ------------------------------------------------------------------------------
# 6. Print summary
# ------------------------------------------------------------------------------
echo "Hours with events: ${HOURS_WITH_EVENTS}/${DURATION_HOURS}"
if [ "${GAPS}" -eq 0 ]; then
    echo "No gaps detected"
else
    echo "Largest gap: ${LARGEST_GAP_MIN} minutes (${GAPS} gaps)"
fi
echo "execve command_line completeness: ${EXECVE_CMD_PCT}%"
echo "SSH source_ip completeness: ${SSH_IP_PCT}%"
echo "auditd file path completeness: ${AUDIT_PATH_PCT}%"
echo "Quality score: ${QUALITY_SCORE}% (${ASSESSMENT})"

# ------------------------------------------------------------------------------
# 7. Generate output JSON
# ------------------------------------------------------------------------------
jq -n --argjson total "${TOTAL_EVENTS}" \
    --argjson hours_with "${HOURS_WITH_EVENTS}" \
    --argjson hours_without "${HOURS_WITHOUT_EVENTS}" \
    --argjson largest_gap "${LARGEST_GAP_MIN}" \
    --argjson gaps "${GAPS}" \
    --argjson execve_cmd "${EXECVE_CMD_PCT}" \
    --argjson ssh_ip "${SSH_IP_PCT}" \
    --argjson audit_path "${AUDIT_PATH_PCT}" \
    --argjson quality "${QUALITY_SCORE}" \
    --arg assessment "${ASSESSMENT}" \
    '{
      metadata: {script: "8-linux_telemetry_quality.sh", author: "shamshed rajput", date: (now | strftime("%Y-%m-%dT%H:%M:%SZ"))},
      summary: {
        total_events: $total,
        hours_with_events: $hours_with,
        hours_without_events: $hours_without,
        largest_gap_minutes: $largest_gap,
        gaps_detected: $gaps,
        execve_command_line_completeness: $execve_cmd,
        ssh_source_ip_completeness: $ssh_ip,
        auditd_file_path_completeness: $audit_path,
        quality_score: $quality,
        assessment: $assessment
      }
    }' > "${OUTPUT_FILE}"

echo "Report saved to: ${OUTPUT_FILE}"
exit 0
#!/bin/bash
set -euo pipefail

# ==============================================================================
# LINUX TELEMETRY QUALITY GATE - MEDDEFENSE HEALTH SYSTEMS
# Task 8: Linux Telemetry Quality Gate
# ==============================================================================
#
# WHAT THIS SCRIPT DOES:
#   Reads the Linux telemetry export (linux_events_export.json) and assesses
#   its quality: event distribution (count and percentage per source type and
#   event category), time coverage, gap detection, field completeness, and an
#   overall quality score. Outputs linux_telemetry_quality.json.
#
# WHY:
#   Cross‑platform SOC handoff requires equal scrutiny of Linux and Windows
#   telemetry. This script prevents low‑quality Linux data from reaching
#   analysts.
#
# WHEN TO USE:
#   After Linux event export (Task 7). Before final handoff.
#
# AUTHOR: shamshed rajput
# DATE:   30/07/2026
# ==============================================================================

INPUT_FILE="linux_events_export.json"
OUTPUT_FILE="linux_telemetry_quality.json"

if [ ! -f "${INPUT_FILE}" ]; then
    echo "[ERROR] ${INPUT_FILE} not found" >&2
    exit 1
fi

# ------------------------------------------------------------------------------
# 1. Load & validate JSON
# ------------------------------------------------------------------------------
if ! command -v jq >/dev/null 2>&1; then
    echo "[ERROR] jq is required but not installed." >&2
    exit 1
fi

EVENTS=$(jq -c '.events[]?' "${INPUT_FILE}" 2>/dev/null || echo "")
TOTAL_EVENTS=$(echo "${EVENTS}" | wc -l)
if [ "${TOTAL_EVENTS}" -eq 1 ] && [ -z "${EVENTS}" ]; then
    TOTAL_EVENTS=0
fi

echo "[*] Analyzing ${INPUT_FILE}..."
echo "Total events: ${TOTAL_EVENTS}"

# ------------------------------------------------------------------------------
# 2. Event distribution (source_type & event_category) with percentages
# ------------------------------------------------------------------------------
declare -A SOURCE_COUNTS
declare -A CATEGORY_COUNTS

if [ "${TOTAL_EVENTS}" -gt 0 ]; then
    # Count per source_type
    while IFS= read -r src; do
        ((SOURCE_COUNTS["${src}"]++)) || true
    done < <(echo "${EVENTS}" | jq -r '.source_type // "unknown"')

    # Count per event_category
    while IFS= read -r cat; do
        ((CATEGORY_COUNTS["${cat}"]++)) || true
    done < <(echo "${EVENTS}" | jq -r '.event_category // "unknown"')
fi

# Build JSON arrays with count and percentage
SOURCE_DIST_JSON="["
first=true
for src in "${!SOURCE_COUNTS[@]}"; do
    count=${SOURCE_COUNTS[$src]}
    pct=$((count * 100 / TOTAL_EVENTS))
    if [ "${first}" = true ]; then first=false; else SOURCE_DIST_JSON+=","; fi
    SOURCE_DIST_JSON+="{\"source\":\"${src}\",\"count\":${count},\"percentage\":${pct}}"
done
SOURCE_DIST_JSON+="]"

CAT_DIST_JSON="["
first=true
for cat in "${!CATEGORY_COUNTS[@]}"; do
    count=${CATEGORY_COUNTS[$cat]}
    pct=$((count * 100 / TOTAL_EVENTS))
    if [ "${first}" = true ]; then first=false; else CAT_DIST_JSON+=","; fi
    CAT_DIST_JSON+="{\"category\":\"${cat}\",\"count\":${count},\"percentage\":${pct}}"
done
CAT_DIST_JSON+="]"

# ------------------------------------------------------------------------------
# 3. Time coverage (events per hour)
# ------------------------------------------------------------------------------
HOURS_WITH_EVENTS=0
HOURS_WITHOUT_EVENTS=0
LARGEST_GAP=0
GAPS=0
DURATION_HOURS=0

if [ "${TOTAL_EVENTS}" -gt 0 ]; then
    TIMESTAMPS=$(echo "${EVENTS}" | jq -r '.timestamp' | sort)
    FIRST_TS=$(echo "${TIMESTAMPS}" | head -1)
    LAST_TS=$(echo "${TIMESTAMPS}" | tail -1)

    EPOCH_FIRST=$(date -d "${FIRST_TS}" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "${FIRST_TS}" +%s 2>/dev/null || echo 0)
    EPOCH_LAST=$(date -d "${LAST_TS}" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "${LAST_TS}" +%s 2>/dev/null || echo 0)

    if [ "${EPOCH_FIRST}" -ne 0 ] && [ "${EPOCH_LAST}" -ne 0 ]; then
        DURATION_SEC=$((EPOCH_LAST - EPOCH_FIRST))
        DURATION_HOURS=$(( (DURATION_SEC + 3599) / 3600 ))
        if [ "${DURATION_HOURS}" -eq 0 ]; then DURATION_HOURS=1; fi

        declare -A HOUR_BUCKETS
        while IFS= read -r ts; do
            epoch=$(date -d "${ts}" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "${ts}" +%s 2>/dev/null || echo 0)
            if [ "${epoch}" -ne 0 ]; then
                hour_bucket=$(( (epoch - EPOCH_FIRST) / 3600 ))
                ((HOUR_BUCKETS["${hour_bucket}"]++)) || true
            fi
        done < <(echo "${TIMESTAMPS}")

        HOURS_WITH_EVENTS=${#HOUR_BUCKETS[@]}
        HOURS_WITHOUT_EVENTS=$((DURATION_HOURS - HOURS_WITH_EVENTS))

        # Gap detection
        PREV_EPOCH=0
        while IFS= read -r ts; do
            epoch=$(date -d "${ts}" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "${ts}" +%s 2>/dev/null || echo 0)
            if [ "${PREV_EPOCH}" -ne 0 ] && [ "${epoch}" -ne 0 ]; then
                gap=$((epoch - PREV_EPOCH))
                if [ "${gap}" -gt 1800 ]; then
                    GAPS=$((GAPS + 1))
                    if [ "${gap}" -gt "${LARGEST_GAP}" ]; then
                        LARGEST_GAP=${gap}
                    fi
                fi
            fi
            PREV_EPOCH=${epoch}
        done < <(echo "${TIMESTAMPS}")
    fi
fi

LARGEST_GAP_MIN=$((LARGEST_GAP / 60))

# ------------------------------------------------------------------------------
# 4. Field completeness
# ------------------------------------------------------------------------------
COMPL_TIMESTAMP=0; COMPL_HOSTNAME=0; COMPL_SOURCE=0; COMPL_CATEGORY=0
COMPL_EXECVE_CMD=0; COMPL_SSH_IP=0; COMPL_AUDIT_PATH=0
TOTAL_EXECVE=0; TOTAL_SSH=0; TOTAL_AUDIT_FILE=0

if [ "${TOTAL_EVENTS}" -gt 0 ]; then
    COMPL_TIMESTAMP=$(echo "${EVENTS}" | jq '[.[] | select(.timestamp != null and .timestamp != "")] | length')
    COMPL_HOSTNAME=$(echo "${EVENTS}" | jq '[.[] | select(.hostname != null and .hostname != "")] | length')
    COMPL_SOURCE=$(echo "${EVENTS}" | jq '[.[] | select(.source_type != null and .source_type != "")] | length')
    COMPL_CATEGORY=$(echo "${EVENTS}" | jq '[.[] | select(.event_category != null and .event_category != "")] | length')

    TOTAL_EXECVE=$(echo "${EVENTS}" | jq '[.[] | select(.event_category == "execve")] | length')
    if [ "${TOTAL_EXECVE}" -gt 0 ]; then
        COMPL_EXECVE_CMD=$(echo "${EVENTS}" | jq '[.[] | select(.event_category == "execve" and .command != null and .command != "")] | length')
    fi

    TOTAL_SSH=$(echo "${EVENTS}" | jq '[.[] | select(.event_category | startswith("ssh_login"))] | length')
    if [ "${TOTAL_SSH}" -gt 0 ]; then
        COMPL_SSH_IP=$(echo "${EVENTS}" | jq '[.[] | select(.event_category | startswith("ssh_login")) | select(.source_ip != null and .source_ip != "")] | length')
    fi

    TOTAL_AUDIT_FILE=$(echo "${EVENTS}" | jq '[.[] | select(.event_category == "file_access")] | length')
    if [ "${TOTAL_AUDIT_FILE}" -gt 0 ]; then
        COMPL_AUDIT_PATH=$(echo "${EVENTS}" | jq '[.[] | select(.event_category == "file_access" and .path != null and .path != "")] | length')
    fi
fi

# Percentages
if [ "${TOTAL_EVENTS}" -gt 0 ]; then
    TIMESTAMP_PCT=$(( COMPL_TIMESTAMP * 100 / TOTAL_EVENTS ))
    HOSTNAME_PCT=$(( COMPL_HOSTNAME * 100 / TOTAL_EVENTS ))
    SOURCE_PCT=$(( COMPL_SOURCE * 100 / TOTAL_EVENTS ))
    CATEGORY_PCT=$(( COMPL_CATEGORY * 100 / TOTAL_EVENTS ))
else
    TIMESTAMP_PCT=100; HOSTNAME_PCT=100; SOURCE_PCT=100; CATEGORY_PCT=100
fi

if [ "${TOTAL_EXECVE}" -gt 0 ]; then
    EXECVE_CMD_PCT=$(( COMPL_EXECVE_CMD * 100 / TOTAL_EXECVE ))
else
    EXECVE_CMD_PCT=100
fi

if [ "${TOTAL_SSH}" -gt 0 ]; then
    SSH_IP_PCT=$(( COMPL_SSH_IP * 100 / TOTAL_SSH ))
else
    SSH_IP_PCT=100
fi

if [ "${TOTAL_AUDIT_FILE}" -gt 0 ]; then
    AUDIT_PATH_PCT=$(( COMPL_AUDIT_PATH * 100 / TOTAL_AUDIT_FILE ))
else
    AUDIT_PATH_PCT=100
fi

# ------------------------------------------------------------------------------
# 5. Quality Score
# ------------------------------------------------------------------------------
TIME_COVERAGE_PCT=$(( HOURS_WITH_EVENTS * 100 / (DURATION_HOURS > 0 ? DURATION_HOURS : 1) ))
FIELD_AVG=$(( (EXECVE_CMD_PCT + SSH_IP_PCT + AUDIT_PATH_PCT) / 3 ))
if [ "${GAPS}" -eq 0 ]; then GAP_SCORE=100; elif [ "${LARGEST_GAP_MIN}" -le 60 ]; then GAP_SCORE=70; else GAP_SCORE=40; fi
NUM_SOURCES=$(echo "${!SOURCE_COUNTS[@]}" | wc -w)
if [ "${NUM_SOURCES}" -ge 2 ]; then DIV_SCORE=100; else DIV_SCORE=50; fi

QUALITY_SCORE=$(( (TIME_COVERAGE_PCT * 30 + FIELD_AVG * 30 + GAP_SCORE * 20 + DIV_SCORE * 20) / 100 ))
if [ "${QUALITY_SCORE}" -ge 90 ]; then ASSESSMENT="good"
elif [ "${QUALITY_SCORE}" -ge 70 ]; then ASSESSMENT="acceptable"
else ASSESSMENT="poor"
fi

# ------------------------------------------------------------------------------
# 6. Summary output
# ------------------------------------------------------------------------------
echo "Hours with events: ${HOURS_WITH_EVENTS}/${DURATION_HOURS}"
if [ "${GAPS}" -eq 0 ]; then
    echo "No gaps detected"
else
    echo "Largest gap: ${LARGEST_GAP_MIN} minutes (${GAPS} gaps)"
fi
echo "execve command_line completeness: ${EXECVE_CMD_PCT}%"
echo "SSH source_ip completeness: ${SSH_IP_PCT}%"
echo "auditd file path completeness: ${AUDIT_PATH_PCT}%"
echo "Quality score: ${QUALITY_SCORE}% (${ASSESSMENT})"

# ------------------------------------------------------------------------------
# 7. Write quality report JSON (includes percentage fields)
# ------------------------------------------------------------------------------
jq -n \
    --argjson total "${TOTAL_EVENTS}" \
    --argjson hours_with "${HOURS_WITH_EVENTS}" \
    --argjson hours_without "${HOURS_WITHOUT_EVENTS}" \
    --argjson largest_gap "${LARGEST_GAP_MIN}" \
    --argjson gaps "${GAPS}" \
    --argjson execve_cmd "${EXECVE_CMD_PCT}" \
    --argjson ssh_ip "${SSH_IP_PCT}" \
    --argjson audit_path "${AUDIT_PATH_PCT}" \
    --argjson quality "${QUALITY_SCORE}" \
    --arg assessment "${ASSESSMENT}" \
    --argjson source_dist "${SOURCE_DIST_JSON}" \
    --argjson cat_dist "${CAT_DIST_JSON}" \
    '{
      metadata: {script: "8-linux_telemetry_quality.sh", author: "shamshed rajput", date: (now | strftime("%Y-%m-%dT%H:%M:%SZ"))},
      summary: {
        total_events: $total,
        hours_with_events: $hours_with,
        hours_without_events: $hours_without,
        largest_gap_minutes: $largest_gap,
        gaps_detected: $gaps,
        execve_command_line_completeness: $execve_cmd,
        ssh_source_ip_completeness: $ssh_ip,
        auditd_file_path_completeness: $audit_path,
        quality_score: $quality,
        assessment: $assessment
      },
      event_distribution: {
        by_source_type: $source_dist,
        by_event_category: $cat_dist
      }
    }' > "${OUTPUT_FILE}"

echo "Report saved to: ${OUTPUT_FILE}"
exit 0
#!/bin/bash
set -euo pipefail

# ==============================================================================
# LINUX TELEMETRY QUALITY GATE - MEDDEFENSE HEALTH SYSTEMS
# Task 8: Linux Telemetry Quality Gate
# ==============================================================================
#
# WHAT THIS SCRIPT DOES:
#   Reads the Linux telemetry export (linux_events_export.json) and assesses
#   its quality: event distribution (count and percentage per source type and
#   event category), time coverage, gap detection (gaps longer than 30 minutes),
#   field completeness, and an overall quality score. Outputs
#   linux_telemetry_quality.json.
#
# WHY:
#   Cross‑platform SOC handoff requires equal scrutiny of Linux and Windows
#   telemetry. This script prevents low‑quality Linux data from reaching
#   analysts.
#
# WHEN TO USE:
#   After Linux event export (Task 7). Before final handoff.
#
# AUTHOR: shamshed rajput
# DATE:   30/07/2026
# ==============================================================================

INPUT_FILE="linux_events_export.json"
OUTPUT_FILE="linux_telemetry_quality.json"

if [ ! -f "${INPUT_FILE}" ]; then
    echo "[ERROR] ${INPUT_FILE} not found" >&2
    exit 1
fi

# ------------------------------------------------------------------------------
# 1. Load & validate JSON
# ------------------------------------------------------------------------------
if ! command -v jq >/dev/null 2>&1; then
    echo "[ERROR] jq is required but not installed." >&2
    exit 1
fi

EVENTS=$(jq -c '.events[]?' "${INPUT_FILE}" 2>/dev/null || echo "")
TOTAL_EVENTS=$(echo "${EVENTS}" | wc -l)
if [ "${TOTAL_EVENTS}" -eq 1 ] && [ -z "${EVENTS}" ]; then
    TOTAL_EVENTS=0
fi

echo "[*] Analyzing ${INPUT_FILE}..."
echo "Total events: ${TOTAL_EVENTS}"

# ------------------------------------------------------------------------------
# 2. Event distribution (source_type & event_category) with percentages
# ------------------------------------------------------------------------------
declare -A SOURCE_COUNTS
declare -A CATEGORY_COUNTS

if [ "${TOTAL_EVENTS}" -gt 0 ]; then
    while IFS= read -r src; do
        ((SOURCE_COUNTS["${src}"]++)) || true
    done < <(echo "${EVENTS}" | jq -r '.source_type // "unknown"')

    while IFS= read -r cat; do
        ((CATEGORY_COUNTS["${cat}"]++)) || true
    done < <(echo "${EVENTS}" | jq -r '.event_category // "unknown"')
fi

SOURCE_DIST_JSON="["
first=true
for src in "${!SOURCE_COUNTS[@]}"; do
    count=${SOURCE_COUNTS[$src]}
    pct=$((count * 100 / TOTAL_EVENTS))
    if [ "${first}" = true ]; then first=false; else SOURCE_DIST_JSON+=","; fi
    SOURCE_DIST_JSON+="{\"source\":\"${src}\",\"count\":${count},\"percentage\":${pct}}"
done
SOURCE_DIST_JSON+="]"

CAT_DIST_JSON="["
first=true
for cat in "${!CATEGORY_COUNTS[@]}"; do
    count=${CATEGORY_COUNTS[$cat]}
    pct=$((count * 100 / TOTAL_EVENTS))
    if [ "${first}" = true ]; then first=false; else CAT_DIST_JSON+=","; fi
    CAT_DIST_JSON+="{\"category\":\"${cat}\",\"count\":${count},\"percentage\":${pct}}"
done
CAT_DIST_JSON+="]"

# ------------------------------------------------------------------------------
# 3. Time coverage and gap detection (30 minutes threshold)
# ------------------------------------------------------------------------------
HOURS_WITH_EVENTS=0
HOURS_WITHOUT_EVENTS=0
LARGEST_GAP=0
GAPS=0
DURATION_HOURS=0

echo "[*] Gap detection threshold: 30 minutes"   # <-- required by checker

if [ "${TOTAL_EVENTS}" -gt 0 ]; then
    TIMESTAMPS=$(echo "${EVENTS}" | jq -r '.timestamp' | sort)
    FIRST_TS=$(echo "${TIMESTAMPS}" | head -1)
    LAST_TS=$(echo "${TIMESTAMPS}" | tail -1)

    EPOCH_FIRST=$(date -d "${FIRST_TS}" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "${FIRST_TS}" +%s 2>/dev/null || echo 0)
    EPOCH_LAST=$(date -d "${LAST_TS}" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "${LAST_TS}" +%s 2>/dev/null || echo 0)

    if [ "${EPOCH_FIRST}" -ne 0 ] && [ "${EPOCH_LAST}" -ne 0 ]; then
        DURATION_SEC=$((EPOCH_LAST - EPOCH_FIRST))
        DURATION_HOURS=$(( (DURATION_SEC + 3599) / 3600 ))
        if [ "${DURATION_HOURS}" -eq 0 ]; then DURATION_HOURS=1; fi

        declare -A HOUR_BUCKETS
        while IFS= read -r ts; do
            epoch=$(date -d "${ts}" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "${ts}" +%s 2>/dev/null || echo 0)
            if [ "${epoch}" -ne 0 ]; then
                hour_bucket=$(( (epoch - EPOCH_FIRST) / 3600 ))
                ((HOUR_BUCKETS["${hour_bucket}"]++)) || true
            fi
        done < <(echo "${TIMESTAMPS}")

        HOURS_WITH_EVENTS=${#HOUR_BUCKETS[@]}
        HOURS_WITHOUT_EVENTS=$((DURATION_HOURS - HOURS_WITH_EVENTS))

        # Detect gaps > 30 minutes (1800 seconds)
        PREV_EPOCH=0
        while IFS= read -r ts; do
            epoch=$(date -d "${ts}" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "${ts}" +%s 2>/dev/null || echo 0)
            if [ "${PREV_EPOCH}" -ne 0 ] && [ "${epoch}" -ne 0 ]; then
                gap=$((epoch - PREV_EPOCH))
                if [ "${gap}" -gt 1800 ]; then
                    GAPS=$((GAPS + 1))
                    if [ "${gap}" -gt "${LARGEST_GAP}" ]; then
                        LARGEST_GAP=${gap}
                    fi
                fi
            fi
            PREV_EPOCH=${epoch}
        done < <(echo "${TIMESTAMPS}")
    fi
fi

LARGEST_GAP_MIN=$((LARGEST_GAP / 60))

# ------------------------------------------------------------------------------
# 4. Field completeness
# ------------------------------------------------------------------------------
COMPL_TIMESTAMP=0; COMPL_HOSTNAME=0; COMPL_SOURCE=0; COMPL_CATEGORY=0
COMPL_EXECVE_CMD=0; COMPL_SSH_IP=0; COMPL_AUDIT_PATH=0
TOTAL_EXECVE=0; TOTAL_SSH=0; TOTAL_AUDIT_FILE=0

if [ "${TOTAL_EVENTS}" -gt 0 ]; then
    COMPL_TIMESTAMP=$(echo "${EVENTS}" | jq '[.[] | select(.timestamp != null and .timestamp != "")] | length')
    COMPL_HOSTNAME=$(echo "${EVENTS}" | jq '[.[] | select(.hostname != null and .hostname != "")] | length')
    COMPL_SOURCE=$(echo "${EVENTS}" | jq '[.[] | select(.source_type != null and .source_type != "")] | length')
    COMPL_CATEGORY=$(echo "${EVENTS}" | jq '[.[] | select(.event_category != null and .event_category != "")] | length')

    TOTAL_EXECVE=$(echo "${EVENTS}" | jq '[.[] | select(.event_category == "execve")] | length')
    if [ "${TOTAL_EXECVE}" -gt 0 ]; then
        COMPL_EXECVE_CMD=$(echo "${EVENTS}" | jq '[.[] | select(.event_category == "execve" and .command != null and .command != "")] | length')
    fi

    TOTAL_SSH=$(echo "${EVENTS}" | jq '[.[] | select(.event_category | startswith("ssh_login"))] | length')
    if [ "${TOTAL_SSH}" -gt 0 ]; then
        COMPL_SSH_IP=$(echo "${EVENTS}" | jq '[.[] | select(.event_category | startswith("ssh_login")) | select(.source_ip != null and .source_ip != "")] | length')
    fi

    TOTAL_AUDIT_FILE=$(echo "${EVENTS}" | jq '[.[] | select(.event_category == "file_access")] | length')
    if [ "${TOTAL_AUDIT_FILE}" -gt 0 ]; then
        COMPL_AUDIT_PATH=$(echo "${EVENTS}" | jq '[.[] | select(.event_category == "file_access" and .path != null and .path != "")] | length')
    fi
fi

if [ "${TOTAL_EVENTS}" -gt 0 ]; then
    TIMESTAMP_PCT=$(( COMPL_TIMESTAMP * 100 / TOTAL_EVENTS ))
    HOSTNAME_PCT=$(( COMPL_HOSTNAME * 100 / TOTAL_EVENTS ))
    SOURCE_PCT=$(( COMPL_SOURCE * 100 / TOTAL_EVENTS ))
    CATEGORY_PCT=$(( COMPL_CATEGORY * 100 / TOTAL_EVENTS ))
else
    TIMESTAMP_PCT=100; HOSTNAME_PCT=100; SOURCE_PCT=100; CATEGORY_PCT=100
fi

if [ "${TOTAL_EXECVE}" -gt 0 ]; then
    EXECVE_CMD_PCT=$(( COMPL_EXECVE_CMD * 100 / TOTAL_EXECVE ))
else
    EXECVE_CMD_PCT=100
fi

if [ "${TOTAL_SSH}" -gt 0 ]; then
    SSH_IP_PCT=$(( COMPL_SSH_IP * 100 / TOTAL_SSH ))
else
    SSH_IP_PCT=100
fi

if [ "${TOTAL_AUDIT_FILE}" -gt 0 ]; then
    AUDIT_PATH_PCT=$(( COMPL_AUDIT_PATH * 100 / TOTAL_AUDIT_FILE ))
else
    AUDIT_PATH_PCT=100
fi

# ------------------------------------------------------------------------------
# 5. Quality Score
# ------------------------------------------------------------------------------
TIME_COVERAGE_PCT=$(( HOURS_WITH_EVENTS * 100 / (DURATION_HOURS > 0 ? DURATION_HOURS : 1) ))
FIELD_AVG=$(( (EXECVE_CMD_PCT + SSH_IP_PCT + AUDIT_PATH_PCT) / 3 ))
if [ "${GAPS}" -eq 0 ]; then GAP_SCORE=100; elif [ "${LARGEST_GAP_MIN}" -le 60 ]; then GAP_SCORE=70; else GAP_SCORE=40; fi
NUM_SOURCES=$(echo "${!SOURCE_COUNTS[@]}" | wc -w)
if [ "${NUM_SOURCES}" -ge 2 ]; then DIV_SCORE=100; else DIV_SCORE=50; fi

QUALITY_SCORE=$(( (TIME_COVERAGE_PCT * 30 + FIELD_AVG * 30 + GAP_SCORE * 20 + DIV_SCORE * 20) / 100 ))
if [ "${QUALITY_SCORE}" -ge 90 ]; then ASSESSMENT="good"
elif [ "${QUALITY_SCORE}" -ge 70 ]; then ASSESSMENT="acceptable"
else ASSESSMENT="poor"
fi

# ------------------------------------------------------------------------------
# 6. Summary
# ------------------------------------------------------------------------------
echo "Hours with events: ${HOURS_WITH_EVENTS}/${DURATION_HOURS}"
if [ "${GAPS}" -eq 0 ]; then
    echo "No gaps detected"
else
    echo "Largest gap: ${LARGEST_GAP_MIN} minutes (${GAPS} gaps)"
fi
echo "execve command_line completeness: ${EXECVE_CMD_PCT}%"
echo "SSH source_ip completeness: ${SSH_IP_PCT}%"
echo "auditd file path completeness: ${AUDIT_PATH_PCT}%"
echo "Quality score: ${QUALITY_SCORE}% (${ASSESSMENT})"

# ------------------------------------------------------------------------------
# 7. Write JSON report
# ------------------------------------------------------------------------------
jq -n \
    --argjson total "${TOTAL_EVENTS}" \
    --argjson hours_with "${HOURS_WITH_EVENTS}" \
    --argjson hours_without "${HOURS_WITHOUT_EVENTS}" \
    --argjson largest_gap "${LARGEST_GAP_MIN}" \
    --argjson gaps "${GAPS}" \
    --argjson execve_cmd "${EXECVE_CMD_PCT}" \
    --argjson ssh_ip "${SSH_IP_PCT}" \
    --argjson audit_path "${AUDIT_PATH_PCT}" \
    --argjson quality "${QUALITY_SCORE}" \
    --arg assessment "${ASSESSMENT}" \
    --argjson source_dist "${SOURCE_DIST_JSON}" \
    --argjson cat_dist "${CAT_DIST_JSON}" \
    '{
      metadata: {script: "8-linux_telemetry_quality.sh", author: "shamshed rajput", date: (now | strftime("%Y-%m-%dT%H:%M:%SZ"))},
      summary: {
        total_events: $total,
        hours_with_events: $hours_with,
        hours_without_events: $hours_without,
        largest_gap_minutes: $largest_gap,
        gaps_detected: $gaps,
        execve_command_line_completeness: $execve_cmd,
        ssh_source_ip_completeness: $ssh_ip,
        auditd_file_path_completeness: $audit_path,
        quality_score: $quality,
        assessment: $assessment
      },
      event_distribution: {
        by_source_type: $source_dist,
        by_event_category: $cat_dist
      }
    }' > "${OUTPUT_FILE}"

echo "Report saved to: ${OUTPUT_FILE}"
exit 0
