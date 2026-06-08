echo "$1" \
| sed 's/^{xor}//' \
| base64 -d \
| perl -pe '$_ ^= "\x5A" x length($_)'
