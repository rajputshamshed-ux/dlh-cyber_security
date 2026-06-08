#!/bin/bash

[ -z "$1" ] && { echo "Usage: $0 {xor}HASH"; exit 1; }

echo "$1" \
| sed 's/^{xor}//' \
| base64 -d \
| perl -pe '$_ ^= "\x5A" x length($_)'

echo
