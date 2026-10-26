#!/bin/bash

# ---------------------------------------------------------
# CUSTOM HONEYPOT STARTUP SCRIPT
# ---------------------------------------------------------

echo "============================================================"
echo "          STARTING CUSTOM HONEYPOT SYSTEM"
echo "============================================================"

# Go to the project directory
cd "$(dirname "$0")"

# Activate virtual environment
source venv/bin/activate

# Start API server
echo "[+] Starting API server..."
python3 api/api_server.py > logs/api_server.log 2>&1 &

# Start Dashboard server
echo "[+] Starting Dashboard server..."
python3 dashboard/dashboard_server.py > logs/dashboard_server.log 2>&1 &

echo ""
echo "============================================================"
echo "              HONEYPOT SYSTEM STARTED"
echo "============================================================"

echo "API:       http://127.0.0.1:5000"
echo "Dashboard: http://127.0.0.1:5001"

echo ""
echo "Both servers are running in the background."
echo "============================================================"
