#!/usr/bin/env python3
"""
SMS Traffic Capture Downloader

This module provides functionality to download traffic captures for alerts
from a TippingPoint Security Management System (SMS) within a specified time interval.
"""

import os
import csv
import time
import logging
import tempfile
import requests
from datetime import datetime
from typing import Union, Dict, List, Optional, Any, Tuple

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('sms_traffic_capture')

def list_alert_event_ids(
    sms_server: str,
    start_time: Union[datetime, int],
    end_time: Union[datetime, int],
    auth_type: str = "api_key",
    api_key: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    verify_ssl: bool = True,
    max_alerts: Optional[int] = None,
    only_with_packet_trace: bool = True
) -> List[Dict[str, str]]:
    """
    List event IDs for alerts in the specified time interval.
    
    Parameters:
    -----------
    sms_server : str
        The SMS server URL (e.g., "https://sms.example.com")
    start_time : datetime or int
        Start time of the interval (datetime object or milliseconds since epoch)
    end_time : datetime or int
        End time of the interval (datetime object or milliseconds since epoch)
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
    only_with_packet_trace : bool, optional
        Whether to only include alerts with packet traces available (default: True)
    
    Returns:
    --------
    list of dict
        List of dictionaries containing event ID information for each alert:
        [
            {
                "device_id": "123",
                "alert_type": "456",
                "sequence_num": "789",
                "event_id": "123,456,789",  # Combined event ID format used by the API
                "timestamp": "1627384950000",
                "severity": "Critical",
                "has_packet_trace": True
            },
            ...
        ]
    
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
        raise ConnectionError(f"Failed to retrieve alerts: {str(e)}")
    
    # Parse the CSV response
    alerts = []
    try:
        csv_data = response.text.splitlines()
        if not csv_data:
            logger.warning("No alerts found in the specified time interval")
            return []
        
        reader = csv.DictReader(csv_data)
        for row in reader:
            alerts.append(row)
    except Exception as e:
        logger.error(f"Failed to parse alerts data: {str(e)}")
        raise ValueError(f"Failed to parse alerts data: {str(e)}")
    
    logger.info(f"Retrieved {len(alerts)} alerts")
    
    # 4. Filter alerts if needed and extract event IDs
    result = []
    for alert in alerts:
        has_packet_trace = alert.get("PACKET_TRACE") == "1"
        
        # Skip alerts without packet trace if only_with_packet_trace is True
        if only_with_packet_trace and not has_packet_trace:
            continue
        
        # Extract alert attributes
        device_id = alert.get("DEVICE_ID", "unknown")
        sequence_num = alert.get("SEQUENCE_NUM", "unknown")
        alert_type = alert.get("ALERT_TYPE_ID", "unknown")
        timestamp = alert.get("END_TIME", str(int(time.time() * 1000)))
        severity = alert.get("SEVERITY", "unknown")
        
        # Create the event ID in the format expected by the API
        event_id = f"{device_id},{alert_type},{sequence_num}"
        
        # Add to result list
        result.append({
            "device_id": device_id,
            "alert_type": alert_type,
            "sequence_num": sequence_num,
            "event_id": event_id,
            "timestamp": timestamp,
            "severity": severity,
            "has_packet_trace": has_packet_trace
        })
    
    logger.info(f"Found {len(result)} alerts{' with packet trace' if only_with_packet_trace else ''}")
    return result

def download_traffic_captures(
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

def download_packet_traces_by_event_ids(
    sms_server: str,
    event_ids: List[str],
    output_dir: str,
    auth_type: str = "api_key",
    api_key: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    verify_ssl: bool = True,
    filename_format: str = "{event_id}.pcap"
) -> Dict[str, Any]:
    """
    Download packet traces using a list of event IDs.
    
    Parameters:
    -----------
    sms_server : str
        The SMS server URL (e.g., "https://sms.example.com")
    event_ids : list of str
        List of event IDs in the format "device_id,alert_type,sequence_num"
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
    filename_format : str, optional
        Format string for output filenames (default: "{event_id}.pcap")
        Available placeholders: event_id
    
    Returns:
    --------
    dict
        Summary of the operation with counts of processed event IDs and downloaded captures
    """
    # Initialize result summary
    result = {
        "total_event_ids": len(event_ids),
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
    
    # 3. Process Event IDs and Download Packet Traces
    logger.info(f"Processing {len(event_ids)} event IDs and downloading packet traces...")
    
    for event_id in event_ids:
        try:
            # Format the output filename
            filename = filename_format.format(event_id=event_id.replace(',', '_'))
            output_path = os.path.join(output_dir, filename)
            
            # Create a temporary file with the event ID
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
                temp_file.write(event_id)
                temp_file_path = temp_file.name
            
            # Download the packet trace
            logger.info(f"Downloading packet trace for event ID {event_id}...")
            
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
                logger.error(f"Failed to download packet trace for event ID {event_id}: {str(e)}")
                result["errors"].append(f"Failed to download packet trace for event ID {event_id}: {str(e)}")
                result["failed_downloads"] += 1
            
            finally:
                # Clean up the temporary file
                if os.path.exists(temp_file_path):
                    os.unlink(temp_file_path)
        
        except Exception as e:
            logger.error(f"Error processing event ID {event_id}: {str(e)}")
            result["errors"].append(f"Error processing event ID {event_id}: {str(e)}")
            result["failed_downloads"] += 1
    
    # 4. Return the summary
    logger.info(f"Operation completed: {result['successful_downloads']} successful downloads, {result['failed_downloads']} failed downloads")
    return result


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
    parser.add_argument('--list-only', action='store_true', help='Only list event IDs without downloading')
    
    args = parser.parse_args()
    
    # Determine time interval
    if args.start_time and args.end_time:
        start_time = datetime.fromisoformat(args.start_time)
        end_time = datetime.fromisoformat(args.end_time)
    else:
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=args.hours)
    
    if args.list_only:
        # Just list the event IDs
        event_ids = list_alert_event_ids(
            sms_server=args.server,
            start_time=start_time,
            end_time=end_time,
            auth_type=args.auth_type,
            api_key=args.api_key,
            username=args.username,
            password=args.password,
            verify_ssl=not args.no_verify_ssl,
            max_alerts=args.max_alerts
        )
        
        print(f"\nFound {len(event_ids)} alerts with packet traces:")
        for i, alert in enumerate(event_ids, 1):
            print(f"{i}. Event ID: {alert['event_id']}")
            print(f"   Device ID: {alert['device_id']}")
            print(f"   Alert Type: {alert['alert_type']}")
            print(f"   Sequence Number: {alert['sequence_num']}")
            print(f"   Timestamp: {alert['timestamp']}")
            print(f"   Severity: {alert['severity']}")
            print()
    else:
        # Run the download function
        result = download_traffic_captures(
            sms_server=args.server,
            start_time=start_time,
            end_time=end_time,
            output_dir=args.output_dir,
            auth_type=args.auth_type,
            api_key=args.api_key,
            username=args.username,
            password=args.password,
            verify_ssl=not args.no_verify_ssl,
            max_alerts=args.max_alerts,
            filename_format=args.filename_format
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