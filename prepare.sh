#!/bin/bash
# This script is for debian only
# wget --mirror --convert-links --adjust-extension --page-requisites --no-parent https://www.malware-traffic-analysis.net/2025/index.html

# install tcpreplay and wget
sudo apt-get install tcpreplay wget

# clone https://github.com/sbousseaden/PCAP-ATTACK.git
# git clone https://github.com/sbousseaden/PCAP-ATTACK.git

wget -O c1.zip https://trendmicro-my.sharepoint.com/:u:/p/michael_kondrashin/ESgFspHc7DFLiQUu27WPVVABiwF81L_3QnNeakL3ioEy3Q?e=NWbg8w
unzip c1.zip

wget -O c2.zip https://trendmicro-my.sharepoint.com/:u:/p/michael_kondrashin/EZMdFGEs1TBGqEIkjKOxl-EBTF22SJoSDdsnXb6cRBJlRw?e=UAPKt7
unzip c2.zip


#echo "List all pcap files in mta2025"
#ls -R mta2025/*.pcap

#wget https://www.dropbox.com/scl/fi/3r0psthr423l0kepmp7mz/mta2025.zip\?rlkey\=h59iyrcyga7qnyrd1jq2fsbwm
#unzip mta2025.zip
for interface in $(ip link show | grep "state UP" | awk '{print $2}' | cut -d: -f1); do
    echo "Interface: $interface"
done

read -p "Interface: " interface

for file in c1/*.pcap; do
    echo "Replaying $file on $interface"
    sudo tcpreplay -i $interface $file
    read -p "Press Enter to continue..." 
done

for file in c2/*.pcap; do
    echo "Replaying $file on $interface"
    sudo tcpreplay -i $interface $file
    read -p "Press Enter to continue..." 
done
