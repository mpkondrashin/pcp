#!/usr/bin/env python3
"""
SMS Traffic Capture Downloader

This module provides functionality to download traffic captures for alerts
from a TippingPoint Security Management System (SMS) within a specified time interval.
"""

import os
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
http_client.HTTPConnection.debuglevel = 1



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
        session.headers.update({'Expect': ''})
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
        session.headers.update({'Expect': ''})
        if self.auth_type == "api_key":
            session.headers.update({"X-SMS-API-KEY": self.api_key})
        else:  # http_basic
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
                
        try:
            csv_data = response.text.splitlines()
            if not csv_data:
                logger.warning("No alerts found in the specified time interval")
                return []
            reader = csv.DictReader(csv_data)
            for row in reader:
                yield row
        except Exception as e:
            logger.error(f"Failed to parse alerts data: {str(e)}")
            raise ValueError(f"Failed to parse alerts data: {str(e)}")
    
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
        url = "/dbAccess/tptDBServlet"
        params = {
            "method": "GetData",
            "table": "SIGNATURE",
            "format": "csv"
        }
        response = self.get(url, params=params)
                
        try:
            csv_data = response.text.splitlines()
            if not csv_data:
                logger.warning("No signatures found")
                return []
            reader = csv.DictReader(csv_data)
            for row in reader:
                yield Signature(row["ID"], row["NUM"], row["SEVERITY_ID"], row["NAME"], row["CLASS"], row["PRODUCT_CATEGORY_ID"], row["PROTOCOL"], row["TAXONOMY_ID"], row["CVE_ID"], row["BUGTRAQ_ID"], row["DESCRIPTION"], row["MESSAGE"])
        except Exception as e:
            logger.error(f"Failed to parse signatures data: {str(e)}")
            raise ValueError(f"Failed to parse signatures data: {str(e)}")

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
        

def download_traffic_captures_DELETE_LATER(
    sms_server: str,
    start_time: Union[datetime, int],
    end_time: Union[datetime, int],
    output_dir: str,
    auth_type: str = "api_key",
    api_key: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    verify_ssl: bool = True,
    max_alerts: Optional[int] = None,
    filename_format: str = "{device_id}_{alert_type}_{timestamp}_{sequence_num}.pcap"
) -> Dict[str, Any]:
    """
    Download traffic captures for alerts in the specified time interval.
    
    Parameters:
    -----------
    sms_server : str
        The SMS server URL (e.g., "https://sms.example.com")
    start_time : datetime or int
        Start time of the interval (datetime object or milliseconds since epoch)
    end_time : datetime or int
        End time of the interval (datetime object or milliseconds since epoch)
    output_dir : str
        Directory where traffic captures will be saved
    auth_type : str, optional
        Authentication type: "api_key" or "http_basic" (default: "api_key")
    api_key : str, optional
        API key for authentication (required if auth_type is "api_key")
    username : str, optional
        Username for HTTP basic authentication (required if auth_type is "http_basic")
    password : str, optional
        Password for HTTP basic authentication (required if auth_type is "http_basic")
    verify_ssl : bool, optional
        Whether to verify SSL certificates (default: True)
    max_alerts : int, optional
        Maximum number of alerts to process (default: None, process all alerts)
    filename_format : str, optional
        Format string for output filenames (default: "{device_id}_{alert_type}_{timestamp}_{sequence_num}.pcap")
        Available placeholders: device_id, alert_type, timestamp, sequence_num, severity
    
    Returns:
    --------
    dict
        Summary of the operation with counts of processed alerts and downloaded captures
    
    Raises:
    -------
    ValueError
        If required parameters are missing or invalid
    ConnectionError
        If connection to the SMS server fails
    AuthenticationError
        If authentication fails
    APIError
        If the API returns an error
    """
    # Initialize result summary
    result = {
        "total_alerts": 0,
        "alerts_with_packet_trace": 0,
        "successful_downloads": 0,
        "failed_downloads": 0,
        "errors": []
    }
    
    # 1. Parameter Validation
    logger.info("Validating parameters...")
    
    # Validate SMS server URL
    if not sms_server:
        raise ValueError("SMS server URL is required")
    if not sms_server.startswith(("http://", "https://")):
        sms_server = f"https://{sms_server}"
    
    # Validate authentication parameters
    if auth_type == "api_key" and not api_key:
        raise ValueError("API key is required when auth_type is 'api_key'")
    if auth_type == "http_basic" and (not username or not password):
        raise ValueError("Username and password are required when auth_type is 'http_basic'")
    
    # Convert datetime objects to milliseconds if needed
    if isinstance(start_time, datetime):
        start_time = int(start_time.timestamp() * 1000)
    if isinstance(end_time, datetime):
        end_time = int(end_time.timestamp() * 1000)
    
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    # 2. Authentication Setup
    logger.info("Setting up authentication...")
    session = requests.Session()
    session.verify = verify_ssl
    
    if auth_type == "api_key":
        session.headers.update({"X-SMS-API-KEY": api_key})
    else:  # http_basic
        session.auth = (username, password)
    
    # 3. Retrieve Alerts
    logger.info(f"Retrieving alerts from {start_time} to {end_time}...")
    
    # Construct the URL for the GetData API endpoint
    alerts_url = f"{sms_server}/dbAccess/tptDBServlet"
    params = {
        "method": "GetData",
        "table": "ALERTS",
        "begin_time": start_time,
        "end_time": end_time,
        "format": "csv"
    }
    
    if max_alerts:
        params["limit"] = max_alerts
    
    try:
        response = session.get(alerts_url, params=params)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to retrieve alerts: {str(e)}")
        result["errors"].append(f"Failed to retrieve alerts: {str(e)}")
        return result
    
    # Parse the CSV response
    alerts = []
    try:
        csv_data = response.text.splitlines()
        if not csv_data:
            logger.warning("No alerts found in the specified time interval")
            return result
        
        reader = csv.DictReader(csv_data)
        for row in reader:
            print(row)
            alerts.append(row)
    except Exception as e:
        logger.error(f"Failed to parse alerts data: {str(e)}")
        result["errors"].append(f"Failed to parse alerts data: {str(e)}")
        return result
    
    result["total_alerts"] = len(alerts)
    logger.info(f"Retrieved {len(alerts)} alerts")
    
    # 4. Filter alerts to only include those with PACKET_TRACE=true
    alerts_with_packet_trace = [alert for alert in alerts if alert.get("PACKET_TRACE") == "1"]
    result["alerts_with_packet_trace"] = len(alerts_with_packet_trace)
    logger.info(f"Found {len(alerts_with_packet_trace)} alerts with packet trace")
    
    # 5. Process Alerts and Download Traffic Captures
    logger.info("Processing alerts and downloading traffic captures...")
    
    for alert in alerts_with_packet_trace:
        try:
            # Extract alert attributes
            device_id = alert.get("DEVICE_ID", "unknown")
            sequence_num = alert.get("SEQUENCE_NUM", "unknown")
            alert_type = alert.get("ALERT_TYPE_ID", "unknown")
            timestamp = alert.get("END_TIME", str(int(time.time() * 1000)))
            severity = alert.get("SEVERITY", "unknown")
            event_id = alert.get("DEVICE_TRACE_BEGIN_SEQ", "")
            # Format the output filename
            filename = filename_format.format(
                device_id=device_id,
                alert_type=alert_type,
                timestamp=timestamp,
                sequence_num=sequence_num,
                severity=severity
            )
            output_path = os.path.join(output_dir, filename)
            
            # Create a temporary file with the event ID
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
                temp_file.write(f"{event_id}\n")
                temp_file_path = temp_file.name
            
            # Download the packet trace
            logger.info(f"Downloading packet trace for alert {device_id}:{sequence_num}...")
            
            try:
                # Use the pcaps/getByEventIds endpoint with a POST request
                pcap_url = f"{sms_server}/pcaps/getByEventIds"
                with open(temp_file_path, 'rb') as f:
                    files = {'file': f}
                    pcap_response = session.post(pcap_url, files=files)
                    pcap_response.raise_for_status()
                
                # Save the response content to the output file
                with open(output_path, 'wb') as f:
                    f.write(pcap_response.content)
                
                logger.info(f"Successfully downloaded packet trace to {output_path}")
                result["successful_downloads"] += 1
            
            except requests.exceptions.RequestException as e:
                logger.error(f"Failed to download packet trace for alert {device_id}:{sequence_num}: {str(e)}")
                result["errors"].append(f"Failed to download packet trace for alert {device_id}:{sequence_num}: {str(e)}")
                result["failed_downloads"] += 1
            
            finally:
                # Clean up the temporary file
                if os.path.exists(temp_file_path):
                    os.unlink(temp_file_path)
        
        except Exception as e:
            logger.error(f"Error processing alert: {str(e)}")
            result["errors"].append(f"Error processing alert: {str(e)}")
            result["failed_downloads"] += 1
    
    # 6. Return the summary
    logger.info(f"Operation completed: {result['successful_downloads']} successful downloads, {result['failed_downloads']} failed downloads")
    return result
