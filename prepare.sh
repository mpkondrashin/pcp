#!/bin/bash
# This script is for debian only

# install tcpreplay and wget
sudo apt-get install tcpreplay wget

# clone https://github.com/sbousseaden/PCAP-ATTACK.git
# git clone https://github.com/sbousseaden/PCAP-ATTACK.git

echo "List all pcap files in mta2025"
ls -R mta2025/*.pcap

wget https://www.dropbox.com/scl/fi/3r0psthr423l0kepmp7mz/mta2025.zip\?rlkey\=h59iyrcyga7qnyrd1jq2fsbwm
unzip mta2025.zip
for interface in $(ip link show | grep "state UP" | awk '{print $2}' | cut -d: -f1); do
    echo "Interface: $interface"
done

read -p "Interface: " interface

for file in mta2025/*.pcap; do
    echo "Replaying $file on $interface"
    sudo tcpreplay -i $interface $file
done

