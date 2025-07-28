#!/usr/bin/env python3

from io import BytesIO
from scapy.all import rdpcap
import hashlib
import os
import re
import logging
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from collections import namedtuple
import http.client as http_client
# temporary commented out http_client.HTTPConnection.debuglevel = 1

def hash_normalized_pcap(pcap_data: bytes) -> str:
    packets = rdpcap(BytesIO(pcap_data))
    payloads = b"".join(bytes(pkt) for pkt in packets)
    return hashlib.sha1(payloads).hexdigest()


def rename_pcaps(syslog_file: str, output_dir: str):
    with open(syslog_file) as f:
        for line in f:
            match = re.search(r'alert=(.+?)\s+alertId=([^\s]+)', line)
            if not match:
                logger.warning(f"No match found for line: {line}")
                continue
            alert_text = match.group(1)
            alert_id = match.group(2)
            rename_pcap(alert_id, alert_text, output_dir)

def rename_pcap(alert_id, alert_text, output_dir):
    file_name = os.path.join(output_dir, alert_id + ".pcap")
    if not os.path.exists(file_name):
        logger.warning(f"File {file_name} does not exist")
        return
    pcap_data = open(file_name, "rb").read()
    if len(pcap_data) == 0:
        os.remove(file_name)
        logger.warning(f"Removed empty file {file_name}")
        return
    if "Exception upload exception getting the eventIds file" in pcap_data.decode("utf-8"):
        os.remove(file_name)
        logger.warning(f"Removed file {file_name}")
        return
    pcap_data_sha1 = hash_normalized_pcap(pcap_data)
    alert_text = sanitize_string_for_using_as_filename(alert_text)
    output_filename = f"{alert_text}_{pcap_data_sha1}.pcap"
    output_path = os.path.join(output_dir, output_filename)
    os.rename(file_name, output_path)
    logger.info(f"Renamed {file_name} to {output_path}")
        

def sanitize_string_for_using_as_filename(s: str) -> str:
    return re.sub(r'[^a-zA-Z0-9]', '_', s)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('sms_traffic_capture')


if __name__ == "__main__":
    # Example usage when script is run directly
    import argparse
    from datetime import datetime, timedelta
    
    parser = argparse.ArgumentParser(description='Download traffic captures from SMS server')
    parser.add_argument('--pcaps-folder', required=True, help='SMS server URL')
    parser.add_argument('--syslog-file', default="/var/log/syslog", help='Path to the syslog file with SMS alerts')
    
    args = parser.parse_args()
    
    rename_pcaps(args.pcaps_folder, args.syslog_file)
