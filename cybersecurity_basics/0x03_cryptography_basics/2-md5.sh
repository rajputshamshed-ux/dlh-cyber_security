#!/bin/bash
password="$1"
hash=$(echo -n "$password" | md5sum)
hash=${hash%% *}
echo -e "$hash\n" > 2_hash.txt