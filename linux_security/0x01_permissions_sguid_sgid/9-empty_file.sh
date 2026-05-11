#!/bin/bash
find "$1" -empty -type f -exec chmod a+rwx {} \; 2>/dev/null