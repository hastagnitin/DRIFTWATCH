#!/bin/bash

set -a
source .env
set +a

while true; do
    echo "Starting DriftWatch Check at $(date)" | tee -a drift.log
    python3 -u drift_engine/core.py 2>&1 | tee -a drift.log
    echo "Finished Check" | tee -a drift.log
    sleep 300
done