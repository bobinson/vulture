#!/bin/sh
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root" >&2  # EXPECT: clean
    exit 1
fi
