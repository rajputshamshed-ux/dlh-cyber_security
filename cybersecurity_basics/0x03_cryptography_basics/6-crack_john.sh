#!/bin/bash
john --show "$1" | grep -v ":" > 6-password.txt
