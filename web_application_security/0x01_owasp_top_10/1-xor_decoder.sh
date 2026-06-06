#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: $0 {xor}HASH"
    exit 1
fi

hash="${1#\{xor\}}"
decoded=$(echo "$hash" | base64 -d 2>/dev/null)

result=""
for (( i=0; i<${#decoded}; i++ )); do
    char="${decoded:$i:1}"
    ascii=$(printf "%d" "'$char")
    xor=$((ascii ^ 0x5F))
    result+=$(printf "\\$(printf '%03o' $xor)")
done

echo "$result"
