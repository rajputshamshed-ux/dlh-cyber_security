#!/bin/bash
set -euo pipefail

# ==============================================================================
# LINUX LOG SOURCE MAPPING - MEDDEFENSE HEALTH SYSTEMS
# Task 6: Linux Log Source Mapping
# ==============================================================================
#
# WHAT THIS SCRIPT DOES:
#   Discovers all active log sources on the hardened Linux system
#   (auth.log, syslog, audit.log, kern.log, dpkg.log, apache2 logs, etc.),
#   and documents for each: file path, format type, rotation policy,
#   current file size, estimated events per hour, and security relevance
#   rating (critical, high, medium, low).
#
# WHY:
#   Linux telemetry comes from multiple sources with different formats.
#   Before exporting data in a consistent format (Task 7), you must
#   inventory exactly what you have. This inventory becomes the input
#   specification for the export pipeline and the SOC handoff.
#
# WHEN TO USE:
#   After auditd refinement (Task 5). Before Linux telemetry export
#   (Task 7). Weekly audit of log source health.
#
# AUTHOR: shamshed rajput
# DATE:   30/07/2026
# TARGET: billing-srv-01 (Ubuntu 22.04 LTS)
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. CONFIGURATION
# ------------------------------------------------------------------------------
LOG_DIR="/var/log"
AUDIT_LOG_DIR="/var/log/audit"
APACHE_LOG_DIR="/var/log/apache2"
MYSQL_LOG_DIR="/var/log/mysql"
OUTPUT_FILE="log_source_map.json"

FOUND=0
MISSING=0
declare -a SOURCES_JSON

echo "[*] Discovering log sources..."
echo ""
printf "%-20s %-30s %-10s %-12s %-10s %-10s\n" "Source" "Path" "Format" "Rotation" "Events/hr" "Relevance"
printf "%-20s %-30s %-10s %-12s %-10s %-10s\n" "------" "----" "------" "--------" "---------" "---------"

# ------------------------------------------------------------------------------
# 2. HELPER FUNCTIONS
# ------------------------------------------------------------------------------

# Function to get file size in human-readable format
get_size() {
    local file="$1"
    if [ -f "${file}" ]; then
        du -h "${file}" 2>/dev/null | cut -f1 || echo "0"
    else
        echo "N/A"
    fi
}

# Function to estimate events per hour from a log file
# Counts lines added in the last hour, or returns estimate based on total lines
estimate_events_per_hour() {
    local file="$1"
    if [ ! -f "${file}" ] || [ ! -r "${file}" ]; then
        echo "<1"
        return
    fi
    
    local lines=0
    local one_hour_ago
    one_hour_ago=$(date -d '1 hour ago' '+%Y-%m-%d %H:' 2>/dev/null || date -d '1 hour ago' '+%b %d %H:' 2>/dev/null || echo "")
    
    if [ -n "${one_hour_ago}" ]; then
        lines=$(grep -c "${one_hour_ago}" "${file}" 2>/dev/null || echo 0)
    fi
    
    if [ "${lines}" -gt 0 ]; then
        echo "${lines}"
    else
        # Fallback: total lines divided by hours since file creation
        local total_lines
        total_lines=$(wc -l < "${file}" 2>/dev/null || echo 0)
        local file_age_hours
        file_age_hours=$(( ($(date +%s) - $(stat -c %Y "${file}" 2>/dev/null || echo 0)) / 3600 ))
        if [ "${file_age_hours}" -gt 0 ] && [ "${total_lines}" -gt 0 ]; then
            echo $(( total_lines / file_age_hours ))
        else
            echo "<1"
        fi
    fi
}

# Function to get rotation policy from logrotate config
get_rotation() {
    local log_name="$1"
    local default_rotation="unknown"
    
    # Search in logrotate configs
    for conf in /etc/logrotate.conf /etc/logrotate.d/*; do
        if [ -f "${conf}" ] && grep -q "${log_name}" "${conf}" 2>/dev/null; then
            local rotate
            rotate=$(grep -E "^[[:space:]]*rotate[[:space:]]+" "${conf}" 2>/dev/null | head -1 | awk '{print $2}')
            if [ -n "${rotate}" ]; then
                echo "${rotate} days"
                return
            fi
        fi
    done
    
    echo "${default_rotation}"
}

# Function to determine format type
get_format() {
    local file="$1"
    local name="$2"
    
    case "${name}" in
        audit*)
            echo "audit"
            ;;
        apache*|access*)
            echo "combined"
            ;;
        auth*|syslog|kern*)
            echo "syslog"
            ;;
        dpkg*)
            echo "custom"
            ;;
        mysql*)
            echo "custom"
            ;;
        *)
            # Try to detect format by sampling first line
            if [ -f "${file}" ] && [ -r "${file}" ]; then
                local first_line
                first_line=$(head -1 "${file}" 2>/dev/null || echo "")
                if echo "${first_line}" | grep -q "type="; then
                    echo "audit"
                elif echo "${first_line}" | jq . >/dev/null 2>&1; then
                    echo "json"
                else
                    echo "syslog"
                fi
            else
                echo "unknown"
            fi
            ;;
    esac
}

# Function to process a log source
process_source() {
    local name="$1"
    local path="$2"
    local relevance="$3"
    
    if [ -f "${path}" ] && [ -r "${path}" ]; then
        local format
        format=$(get_format "${path}" "${name}")
        local rotation
        rotation=$(get_rotation "${name}")
        local size
        size=$(get_size "${path}")
        local events
        events=$(estimate_events_per_hour "${path}")
        
        printf "%-20s %-30s %-10s %-12s %-10s %-10s\n" "${name}" "${path}" "${format}" "${rotation}" "${events}" "${relevance}"
        
        # Add to JSON array
        SOURCES_JSON+=("{\"source\":\"${name}\",\"path\":\"${path}\",\"format\":\"${format}\",\"rotation\":\"${rotation}\",\"size\":\"${size}\",\"events_per_hour\":\"${events}\",\"relevance\":\"${relevance}\"}")
        
        FOUND=$((FOUND + 1))
    else
        printf "%-20s %-30s %-10s %-12s %-10s %-10s\n" "${name}" "${path}" "N/A" "N/A" "N/A" "MISSING"
        SOURCES_JSON+=("{\"source\":\"${name}\",\"path\":\"${path}\",\"status\":\"missing\"}")
        MISSING=$((MISSING + 1))
    fi
}

# ------------------------------------------------------------------------------
# 3. INVENTORY ALL LOG SOURCES
# ------------------------------------------------------------------------------

# Critical sources
process_source "auth.log" "/var/log/auth.log" "critical"
process_source "audit.log" "/var/log/audit/audit.log" "critical"

# High relevance sources
process_source "syslog" "/var/log/syslog" "high"
process_source "apache2 access" "/var/log/apache2/access.log" "high"
process_source "apache2 error" "/var/log/apache2/error.log" "high"

# Medium relevance sources
process_source "kern.log" "/var/log/kern.log" "medium"
process_source "mysql error" "/var/log/mysql/error.log" "medium"

# Low relevance sources
process_source "dpkg.log" "/var/log/dpkg.log" "medium"
process_source "cron.log" "/var/log/cron.log" "medium"

# ------------------------------------------------------------------------------
# 4. ADDITIONAL DISCOVERY: find any other security-relevant logs
# ------------------------------------------------------------------------------
# Check for any additional log files in /var/log that are actively being written to
if [ -d "${LOG_DIR}" ]; then
    for logfile in "${LOG_DIR}"/*.log; do
        if [ -f "${logfile}" ] && [ -r "${logfile}" ]; then
            local basename
            basename=$(basename "${logfile}")
            # Skip already processed sources
            case "${basename}" in
                auth.log|syslog|kern.log|dpkg.log|cron.log)
                    continue
                    ;;
                *)
                    # Check if file was modified recently (last 24 hours)
                    if [ -n "$(find "${logfile}" -mmin -1440 2>/dev/null)" ]; then
                        process_source "${basename}" "${logfile}" "low"
                    fi
                    ;;
            esac
        fi
    done
fi

# ------------------------------------------------------------------------------
# 5. SUMMARY
# ------------------------------------------------------------------------------
echo ""
echo "Sources found: ${FOUND} | Missing: ${MISSING}"

# ------------------------------------------------------------------------------
# 6. EXPORT JSON
# ------------------------------------------------------------------------------
if [ "${#SOURCES_JSON[@]}" -gt 0 ]; then
    echo "[" > "${OUTPUT_FILE}"
    local first=true
    for entry in "${SOURCES_JSON[@]}"; do
        if [ "${first}" = true ]; then
            first=false
        else
            echo "," >> "${OUTPUT_FILE}"
        fi
        echo "  ${entry}" >> "${OUTPUT_FILE}"
    done
    echo "]" >> "${OUTPUT_FILE}"
    echo "[*] Map saved to: ${OUTPUT_FILE}"
fi

exit 0
#!/bin/bash
set -euo pipefail

# ==============================================================================
# LINUX LOG SOURCE MAPPING - MEDDEFENSE HEALTH SYSTEMS
# Task 6: Linux Log Source Mapping
# ==============================================================================
#
# WHAT THIS SCRIPT DOES:
#   Discovers all active log sources on the hardened Linux system
#   (auth.log, syslog, audit.log, kern.log, dpkg.log, apache2 logs, etc.),
#   and documents for each: file path, format type, rotation policy,
#   current file size, estimated events per hour, and security relevance
#   rating (critical, high, medium, low).  Also flags sources that are
#   missing or inactive (zero events/hr).
#
# WHY:
#   Linux telemetry comes from multiple sources with different formats.
#   Before exporting data in a consistent format (Task 7), you must
#   inventory exactly what you have. This inventory becomes the input
#   specification for the export pipeline and the SOC handoff.
#
# WHEN TO USE:
#   After auditd refinement (Task 5). Before Linux telemetry export
#   (Task 7). Weekly audit of log source health.
#
# AUTHOR: shamshed rajput
# DATE:   30/07/2026
# TARGET: billing-srv-01 (Ubuntu 22.04 LTS)
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. CONFIGURATION
# ------------------------------------------------------------------------------
LOG_DIR="/var/log"
OUTPUT_FILE="log_source_map.json"

FOUND=0
MISSING=0
INACTIVE=0
declare -a SOURCES_JSON

echo "[*] Discovering log sources..."
echo ""
printf "%-20s %-30s %-10s %-12s %-10s %-10s\n" "Source" "Path" "Format" "Rotation" "events/hr" "Relevance"
printf "%-20s %-30s %-10s %-12s %-10s %-10s\n" "------" "----" "------" "--------" "---------" "---------"

# ------------------------------------------------------------------------------
# 2. HELPER FUNCTIONS
# ------------------------------------------------------------------------------

get_size() {
    local file="$1"
    if [ -f "${file}" ]; then
        du -h "${file}" 2>/dev/null | cut -f1 || echo "0"
    else
        echo "N/A"
    fi
}

estimate_events_per_hour() {
    local file="$1"
    if [ ! -f "${file}" ] || [ ! -r "${file}" ]; then
        echo "0"
        return
    fi

    local lines=0
    local one_hour_ago
    one_hour_ago=$(date -d '1 hour ago' '+%Y-%m-%d %H:' 2>/dev/null || date -d '1 hour ago' '+%b %d %H:' 2>/dev/null || echo "")

    if [ -n "${one_hour_ago}" ]; then
        lines=$(grep -c "${one_hour_ago}" "${file}" 2>/dev/null || echo 0)
    fi

    if [ "${lines}" -gt 0 ]; then
        echo "${lines}"
    else
        local total_lines
        total_lines=$(wc -l < "${file}" 2>/dev/null || echo 0)
        local file_age_hours
        local mtime
        mtime=$(stat -c %Y "${file}" 2>/dev/null || echo 0)
        if [ "${mtime}" -gt 0 ]; then
            file_age_hours=$(( ($(date +%s) - mtime) / 3600 ))
        else
            file_age_hours=0
        fi
        if [ "${file_age_hours}" -gt 0 ] && [ "${total_lines}" -gt 0 ]; then
            echo $(( total_lines / file_age_hours ))
        else
            echo "<1"
        fi
    fi
}

get_rotation() {
    local log_name="$1"
    local default_rotation="unknown"

    for conf in /etc/logrotate.conf /etc/logrotate.d/*; do
        if [ -f "${conf}" ] && grep -q "${log_name}" "${conf}" 2>/dev/null; then
            local rotate
            rotate=$(grep -E "^[[:space:]]*rotate[[:space:]]+" "${conf}" 2>/dev/null | head -1 | awk '{print $2}')
            if [ -n "${rotate}" ]; then
                echo "${rotate} days"
                return
            fi
        fi
    done

    echo "${default_rotation}"
}

get_format() {
    local file="$1"
    local name="$2"

    case "${name}" in
        audit*)   echo "audit" ;;
        apache*|access*) echo "combined" ;;
        auth*|syslog|kern*) echo "syslog" ;;
        dpkg*)    echo "custom" ;;
        mysql*)   echo "custom" ;;
        *)
            if [ -f "${file}" ] && [ -r "${file}" ]; then
                local first_line
                first_line=$(head -1 "${file}" 2>/dev/null || echo "")
                if echo "${first_line}" | grep -q "type="; then
                    echo "audit"
                elif command -v jq >/dev/null 2>&1 && echo "${first_line}" | jq . >/dev/null 2>&1; then
                    echo "json"
                else
                    echo "syslog"
                fi
            else
                echo "unknown"
            fi
            ;;
    esac
}

process_source() {
    local name="$1"
    local path="$2"
    local relevance="$3"

    if [ -f "${path}" ] && [ -r "${path}" ]; then
        local format rotation size events status
        format=$(get_format "${path}" "${name}")
        rotation=$(get_rotation "${name}")
        size=$(get_size "${path}")
        events=$(estimate_events_per_hour "${path}")

        # Flag as inactive if events per hour is very low
        if [ "${events}" = "0" ] || [ "${events}" = "<1" ]; then
            status="inactive"
            INACTIVE=$((INACTIVE + 1))
        else
            status="active"
            FOUND=$((FOUND + 1))
        fi

        printf "%-20s %-30s %-10s %-12s %-10s %-10s\n" "${name}" "${path}" "${format}" "${rotation}" "${events}" "${relevance}"

        SOURCES_JSON+=("{\"source\":\"${name}\",\"path\":\"${path}\",\"format\":\"${format}\",\"rotation\":\"${rotation}\",\"size\":\"${size}\",\"events_per_hour\":\"${events}\",\"relevance\":\"${relevance}\",\"status\":\"${status}\"}")
    else
        printf "%-20s %-30s %-10s %-12s %-10s %-10s\n" "${name}" "${path}" "N/A" "N/A" "0" "MISSING"
        SOURCES_JSON+=("{\"source\":\"${name}\",\"path\":\"${path}\",\"status\":\"missing\"}")
        MISSING=$((MISSING + 1))
    fi
}

# ------------------------------------------------------------------------------
# 3. INVENTORY ALL LOG SOURCES
# ------------------------------------------------------------------------------

process_source "auth.log" "/var/log/auth.log" "critical"
process_source "audit.log" "/var/log/audit/audit.log" "critical"
process_source "syslog" "/var/log/syslog" "high"
process_source "apache2 access" "/var/log/apache2/access.log" "high"
process_source "apache2 error" "/var/log/apache2/error.log" "high"
process_source "kern.log" "/var/log/kern.log" "medium"
process_source "mysql error" "/var/log/mysql/error.log" "medium"
process_source "dpkg.log" "/var/log/dpkg.log" "medium"
process_source "cron.log" "/var/log/cron.log" "medium"

# ------------------------------------------------------------------------------
# 4. ADDITIONAL DISCOVERY
# ------------------------------------------------------------------------------
if [ -d "${LOG_DIR}" ]; then
    for logfile in "${LOG_DIR}"/*.log; do
        if [ -f "${logfile}" ] && [ -r "${logfile}" ]; then
            local basename
            basename=$(basename "${logfile}")
            case "${basename}" in
                auth.log|syslog|kern.log|dpkg.log|cron.log) continue ;;
                *)
                    if [ -n "$(find "${logfile}" -mmin -1440 2>/dev/null)" ]; then
                        process_source "${basename}" "${logfile}" "low"
                    fi
                    ;;
            esac
        fi
    done
fi

# ------------------------------------------------------------------------------
# 5. SUMMARY
# ------------------------------------------------------------------------------
echo ""
echo "Sources found: ${FOUND} | Missing: ${MISSING} | Inactive: ${INACTIVE}"

# ------------------------------------------------------------------------------
# 6. EXPORT JSON
# ------------------------------------------------------------------------------
if [ "${#SOURCES_JSON[@]}" -gt 0 ]; then
    echo "[" > "${OUTPUT_FILE}"
    local first=true
    for entry in "${SOURCES_JSON[@]}"; do
        if [ "${first}" = true ]; then
            first=false
        else
            echo "," >> "${OUTPUT_FILE}"
        fi
        echo "  ${entry}" >> "${OUTPUT_FILE}"
    done
    echo "]" >> "${OUTPUT_FILE}"
    echo "[*] Map saved to: ${OUTPUT_FILE}"
fi

exit 0
