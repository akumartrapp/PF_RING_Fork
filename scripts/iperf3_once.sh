#!/bin/bash

# Configurable parameters
SERVER_IP="10.31.1.157"   # Your eth0 IP (receiver)
BANDWIDTH="1G"            # UDP bandwidth rate
DURATION=10               # Duration of the test in seconds

echo "Starting iperf3 UDP test to $SERVER_IP for $DURATION seconds at $BANDWIDTH..."
iperf3 -c "$SERVER_IP" -u -b "$BANDWIDTH" -t "$DURATION"

echo "Test completed."
