#!/bin/bash
whois "$1" | awk -F: '/^(Registrant|Admin|Tech) / {field = $1; value = ""; for (i = 2; i <= NF; i++) {if (i > 2) value = value ":"; value = value $i} gsub(/^ /, "", value); if (field ~ /Street/) value = value " "; if (field ~ /Ext/) { field = field ":"; value = "" } printf "%s,%s\n", field, value}'
