#!/bin/bash
random=$(openssl rand -hex 8) && echo -n "$1$random" | openssl dgst -sha512 > 3_hash.txt