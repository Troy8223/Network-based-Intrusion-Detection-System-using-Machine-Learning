#!/bin/bash

# Set the network interface to monitor
interface="ens33"

#Set hostname
host=$(hostname)

# Set the destination infomation for sending the captured files
destination="192.168.224.135"
destination_username="IoT-monitor"
destination_password="ubuntu"

# Set the directory to store the captured files
capture_dir="/home/$host/Documents/pcaps_temp"

# Set the directory to store the sent files
sent_dir="/home/$destination_username/Documents/NIDS-IoT/data/raw_pcap"

# Create the capture directory if it doesn't exist
mkdir -p "$capture_dir"

# Capture network traffic using tcpdump
timestamp=$(date +%Y%m%d%H%M%S)
capture_file="${capture_dir}/${host}_${timestamp}.pcap"

tcpdump -i "$interface" -w "$capture_file" &

# Sleep for an hour
sleep 30

# Stop tcpdump
killall tcpdump

# Send the captured files to the destination via scp
sshpass -p $destination_password scp "$capture_dir"/*.pcap $destination_username@"$destination":"$sent_dir"

# Remove the captured files
rm -f "$capture_dir"/*.pcap