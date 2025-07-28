#!/usr/bin/env python3
"""
SMS Traffic Capture Downloader

This module provides functionality to download traffic captures for alerts
from a TippingPoint Security Management System (SMS) within a specified time interval.
"""

import os
import re
import csv
import time
import sys
import logging
import tempfile
import requests
from datetime import datetime
from typing import  Union, Dict, List, Optional, Any, Tuple
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from collections import namedtuple
import hashlib
import http.client as http_client
#http_client.HTTPConnection.debuglevel = 1

Signature = namedtuple("Signature", ["ID","NUM","SEVERITY_ID","NAME","CLASS","PRODUCT_CATEGORY_ID","PROTOCOL","TAXONOMY_ID","CVE_ID","BUGTRAQ_ID","DESCRIPTION","MESSAGE"])

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
        self.signatures = {}

    def get(self, url: str, params: Optional[Dict[str, str]] = None) -> requests.Response:
        """
        Make a GET request to the SMS server.
        
        Parameters:
        -----------
        url : str
            The URL to make the request to
        params : dict, optional
            Query parameters for the request (default: None)
        
        Returns:
        --------
        requests.Response
            The response from the server
        
        Raises:
        -------
        ConnectionError
            If connection to the SMS server fails
        AuthenticationError
            If authentication fails
        APIError
            If the API returns an error
        """
        session = requests.Session()
        session.verify = self.verify_ssl
        #session.headers.update({'Expect': ''})
        if self.auth_type == "api_key":
            session.headers.update({"X-SMS-API-KEY": self.api_key})
        else:  # http_basic
            session.auth = (self.username, self.password)
        response = session.get("https://" + self.sms_server + url, params=params)
        response.raise_for_status()
        return response

    def post(self, url: str, params: Optional[Dict[str, str]] = None, files: Optional[Dict[str, Tuple[str, bytes]]] = None) -> requests.Response:
        session = requests.Session()
        session.verify = self.verify_ssl
        #session.headers.update({'Expect': ''})
        if self.auth_type == "api_key":
            session.headers.update({"X-SMS-API-KEY": self.api_key})
        else:
            session.auth = (self.username, self.password)
        response = session.post("https://" + self.sms_server + url, params=params, files=files)
        response.raise_for_status()
        return response

    def iterate_alerts(
        self,
        start_time: Union[datetime, int],
        end_time: Union[datetime, int],
    ) -> List[Dict[str, str]]:
        url = "/dbAccess/tptDBServlet"
        if isinstance(start_time, datetime):
            start_time = int(start_time.timestamp() * 1000)
        if isinstance(end_time, datetime):
            end_time = int(end_time.timestamp() * 1000)
        params = {
            "method": "GetData",
            "table": "ALERTS",
            "begin_time": start_time,
            "end_time": end_time,
            "format": "csv"
        }
        response = self.get(url, params=params)
        csv_data = response.text.splitlines()
        if not csv_data:
            logger.warning("No alerts found in the specified time interval")
            return []
        reader = csv.DictReader(csv_data)
        for row in reader:
            yield row
    
    def iterate_alerts_with_packet_trace(
        self,
        start_time: Union[datetime, int],
        end_time: Union[datetime, int],
    ) -> List[Dict[str, str]]:
        for alert in self.iterate_alerts(start_time, end_time):
            if alert.get("PACKET_TRACE") != "1":
                continue
            yield alert

    def iterate_signatures(self):
        with open("signature.csv") as f:
            reader = csv.DictReader(f)
            for row in reader:
                yield Signature(row["ID"], row["NUM"], row["SEVERITY_ID"], row["NAME"], row["CLASS"], row["PRODUCT_CATEGORY_ID"], row["PROTOCOL"], row["TAXONOMY_ID"], row["CVE_ID"], row["BUGTRAQ_ID"], row["DESCRIPTION"], row["MESSAGE"])
  
    def populate_signatures_dict(self):
        for signature in self.iterate_signatures():
            self.signatures[signature.ID] = signature

    def get_signature(self, signature_id: str) -> Optional[Signature]:
        print(f"get_signature {signature_id}")
        return self.signatures.get(signature_id)

    def get_traffic_capture(self, alert_id: str):
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            temp_file.write(f"{alert_id}\n")
            temp_file_path = temp_file.name
        
        logger.info(f"Downloading packet trace for alert {alert_id}...")
        
        pcap_url = "/pcaps/getByEventIds"
        with open(temp_file_path, 'rb') as f:
            files = {'file': f}
            pcap_response = self.post(pcap_url, files=files)
            pcap_response.raise_for_status()
            return pcap_response.content


def get_traffic_captures(sms: SMSClient, start_time: Union[datetime, int], end_time: Union[datetime, int], output_dir: str):
    for alert in sms.iterate_alerts_with_packet_trace(start_time, end_time):
        alert_id = alert["DEVICE_TRACE_BEGIN_SEQ"]
        pcap_data = sms.get_traffic_capture(alert_id)
        pcap_data_sha1 = hashlib.sha1(pcap_data).hexdigest()
        alert_description = sms.get_signature(alert["SIGNATURE_ID"]).DESCRIPTION
        alert_description = sanitize_string_for_using_as_filename(alert_description)
        output_filename = f"{alert_id}_{pcap_data_sha1}.pcap"
        output_path = os.path.join(output_dir, output_filename)
        with open(output_path, 'wb') as f:
            f.write(pcap_data)
        logger.info(f"Saved packet trace for alert {alert_id} to {output_path}")
        

    
def sanitize_string_for_using_as_filename(s: str) -> str:
    return re.sub(r'[^a-zA-Z0-9]', '_', s)



# Set up logging
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
    parser.add_argument('--start-time', help='Start time (ISO format, e.g., 2025-07-23T00:00:00)')
    parser.add_argument('--end-time', help='End time (ISO format, e.g., 2025-07-24T00:00:00)')
    parser.add_argument('--hours', type=int, default=24, help='Number of hours to look back (default: 24)')
    parser.add_argument('--auth-type', choices=['api_key', 'http_basic'], default='api_key', help='Authentication type')
    parser.add_argument('--api-key', help='API key for authentication')
    parser.add_argument('--username', help='Username for HTTP basic authentication')
    parser.add_argument('--password', help='Password for HTTP basic authentication')
    parser.add_argument('--no-verify-ssl', action='store_true', help='Disable SSL certificate verification')
    parser.add_argument('--max-alerts', type=int, help='Maximum number of alerts to process')
    parser.add_argument('--filename-format', default="{device_id}_{alert_type}_{timestamp}_{sequence_num}.pcap", 
                        help='Format string for output filenames')
    
    args = parser.parse_args()
    
    # Determine time interval
    if args.start_time and args.end_time:
        start_time = datetime.fromisoformat(args.start_time)
        end_time = datetime.fromisoformat(args.end_time)
    else:
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=args.hours)
    
    sms = SMSClient(
        sms_server=args.server,
        auth_type=args.auth_type,
        api_key=args.api_key,
        username=args.username,
        password=args.password,
        verify_ssl=not args.no_verify_ssl
    )

    print("populate_signatures_dict")
    sms.populate_signatures_dict()

    # Run the download function
    result = get_traffic_captures(
        sms,
        start_time,
        end_time,
        args.output_dir
    )
    # Print summary
    print("\nOperation Summary:")
    print(f"Total alerts: {result['total_alerts']}")
    print(f"Alerts with packet trace: {result['alerts_with_packet_trace']}")
    print(f"Successful downloads: {result['successful_downloads']}")
    print(f"Failed downloads: {result['failed_downloads']}")
        
    if result['errors']:
        print("\nErrors:")
        for error in result['errors']:
            print(f"  - {error}")
        print()