#!/bin/bash
# This script is for debian only

# install tcpreplay
sudo apt-get install tcpreplay

# clone https://github.com/sbousseaden/PCAP-ATTACK.git
git clone https://github.com/sbousseaden/PCAP-ATTACK.git

# list all network interfaces with ip address
echo "List all network interfaces with ip address"
ip addr show

echo "List all pcapng files in sbousseaden/PCAP-ATTACK"
ls -R PCAP-ATTACK/*.pcapng


# iterate over network interfaces and for each interface replay pcapng file from all subfolders of PCAP-ATTACK folder
for interface in $(ip link show | grep "state UP" | awk '{print $2}' | cut -d: -f1); do
    for file in PCAP-ATTACK/*/*.pcapng; do
        echo "Replaying $file on $interface"
        sudo tcpreplay -i $interface $file
    done
done
    