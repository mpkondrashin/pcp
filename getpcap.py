#!/usr/bin/env python3

from io import BytesIO
from scapy.all import rdpcap
import hashlib
import os
import re
import logging
import requests
from typing import  Dict, Optional, Tuple
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from collections import namedtuple
import http.client as http_client
# temporary commented out http_client.HTTPConnection.debuglevel = 1

class SMSClient:
    def __init__(
        self,
        sms_server: str,
        auth_type: str = "api_key",
        api_key: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: bool = True
    ):
        self.sms_server = sms_server
        self.auth_type = auth_type
        self.api_key = api_key
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl

    def post(self, url: str, params: Optional[Dict[str, str]] = None, files: Optional[Dict[str, Tuple[str, bytes]]] = None, data: Optional[str] = None) -> requests.Response:
        session = requests.Session()
        session.verify = self.verify_ssl
        #session.headers.update({'Expect': ''})
        if self.auth_type == "api_key":
            session.headers.update({"X-SMS-API-KEY": self.api_key})
        else:
            session.auth = (self.username, self.password)
        response = session.post("https://" + self.sms_server + url, params=params, files=files, data=data)
        response.raise_for_status()
        return response
      
    def get_traffic_capture(self, alert_id: str):        
        logger.info(f"Downloading packet trace for alert {alert_id}...")
        pcap_url = "/pcaps/getByEventIds"
        pcap_response = self.post(pcap_url, data=alert_id)
        pcap_response.raise_for_status()
        return pcap_response.content


def hash_normalized_pcap(pcap_data: bytes) -> str:
    packets = rdpcap(BytesIO(pcap_data))
    payloads = b"".join(bytes(pkt) for pkt in packets)
    return hashlib.sha1(payloads).hexdigest()


def get_traffic_captures(sms: SMSClient, syslog_file: str, output_dir: str):
    syslog_format_regex = "alert=.* alertId=.*"
    with open(syslog_file) as f:
        for line in f:
            match = re.search(r'alert=([^\s]+)\s+alertId=([^\s]+)', line)
            if not match:
                logger.warning(f"No match found for line: {line}")
                continue
            alert_text = match.group(1)
            alert_id = match.group(2)
            get_traffic_capture(sms, alert_id, alert_text, output_dir)

def get_traffic_capture(sms: SMSClient, alert_id: str, alert_text: str, output_dir: str):
    pcap_data = sms.get_traffic_capture(alert_id)
    if len(pcap_data) == 0:
        logger.warning(f"No packet trace found for alert {alert_id}")
        return
    pcap_data_sha1 = hash_normalized_pcap(pcap_data)
    alert_text = sanitize_string_for_using_as_filename(alert_text)
    output_filename = f"{alert_text}_{pcap_data_sha1}.pcap"
    output_path = os.path.join(output_dir, output_filename)
    with open(output_path, 'wb') as f:
        f.write(pcap_data)
    logger.info(f"Saved packet trace for alert {alert_id} to {output_path}")
        

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
    parser.add_argument('--server', required=True, help='SMS server URL')
    parser.add_argument('--output-dir', required=True, help='Directory to save traffic captures')
    parser.add_argument('--auth-type', choices=['api_key', 'http_basic'], default='api_key', help='Authentication type')
    parser.add_argument('--api-key', help='API key for authentication')
    parser.add_argument('--username', help='Username for HTTP basic authentication')
    parser.add_argument('--password', help='Password for HTTP basic authentication')
    parser.add_argument('--no-verify-ssl', action='store_true', help='Disable SSL certificate verification')
    parser.add_argument('--syslog-file', default="/var/log/syslog", help='Path to the syslog file with SMS alerts')
    
    args = parser.parse_args()
    
    sms = SMSClient(
        sms_server=args.server,
        auth_type=args.auth_type,
        api_key=args.api_key,
        username=args.username,
        password=args.password,
        verify_ssl=not args.no_verify_ssl
    )

    get_traffic_captures(
        sms,
        args.syslog_file,
        args.output_dir,
    )
