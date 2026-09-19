#!/bin/bash

REGION="${AWS_DEFAULT_REGION:-ap-south-1}"
STATE_PATH="${TF_STATE_PATH:-terraform/terraform.tfstate}"
CHECK_INTERVAL="${CHECK_INTERVAL_SECONDS:-300}"
LOG_FILE="${DRIFT_LOG_FILE:-drift.log}"

echo "Starting DriftWatch Automation..."
echo "  Region:        ${REGION}"
echo "  State:         ${STATE_PATH}"
echo "  Poll Interval: ${CHECK_INTERVAL}s"
echo "  Log File:      ${LOG_FILE}"

while true; do
    echo "========================================================" | tee -a "${LOG_FILE}"
    echo "DriftWatch Scan started at $(date -u '+%Y-%m-%d %H:%M:%S UTC')" | tee -a "${LOG_FILE}"
    echo "========================================================" | tee -a "${LOG_FILE}"

    driftwatch scan \
        --region "${REGION}" \
        --state "${STATE_PATH}" \
        --fail-on CRITICAL 2>&1 | tee -a "${LOG_FILE}"

    SCAN_EXIT_CODE=$?
    if [ ${SCAN_EXIT_CODE} -ne 0 ]; then
        echo "[WARNING] DriftWatch reported an issue or gate failure (exit code: ${SCAN_EXIT_CODE})." | tee -a "${LOG_FILE}"
    else
        echo "[INFO] DriftWatch scan completed successfully." | tee -a "${LOG_FILE}"
    fi

    echo "Next scan in ${CHECK_INTERVAL} seconds..." | tee -a "${LOG_FILE}"
    sleep "${CHECK_INTERVAL}"
done
