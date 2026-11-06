#!/bin/sh
set -eu

# Sandboxes live at most one hour; retain logs for 24 hours for Agent ingestion.
find /var/log/runsc -maxdepth 1 -type f \
    \( -name '*.jsonl' -o -name '*.panic.log' \) \
    -mmin +1440 -delete
