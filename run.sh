#!/bin/bash

LOG_FILE="${DRIFT_LOG_FILE:-drift.log}"
CHECK_INTERVAL="${CHECK_INTERVAL_SECONDS:-300}"

while true; do
    echo "Starting DriftWatch Check at $(date -u '+%Y-%m-%d %H:%M:%S UTC')" | tee -a "${LOG_FILE}"
    driftwatch scan 2>&1 | tee -a "${LOG_FILE}"
    echo "Finished Check" | tee -a "${LOG_FILE}"
    sleep "${CHECK_INTERVAL}"
done