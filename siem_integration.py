#!/usr/bin/env python3
# SIEM integration - sends alerts to Splunk

import os
import time
import logging
import json
import requests
import configparser
from typing import Dict

# Basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(module)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/siem.log'),
        logging.StreamHandler()
    ]
)

class SplunkEventForwarder:
    """Sends alerts to Splunk"""
    
    def __init__(self, config_path: str = '/app/config/settings.ini'):
        # Load config
        self.config = configparser.ConfigParser()
        
        if not os.path.exists(config_path):
            logging.error(f"Config not found: {config_path}")
            raise FileNotFoundError(f"Missing config: {config_path}")
            
        self.config.read(config_path)
        
        # Splunk settings
        self.splunk_url = self.config.get('SIEM', 'url')
        self.splunk_token = self.config.get('SIEM', 'token')
        
        # Standard headers
        self.headers = {
            "Authorization": f"Splunk {self.splunk_token}",
            "Content-Type": "application/json"
        }
        
        self.source_id = "network_anomaly_detector"
        
        logging.info(f"SIEM ready! URL: {self.splunk_url}")

    def send(self, alert_details: Dict) -> bool:
        """Send alert to Splunk HEC"""
        
        # Check config
        if not self.splunk_url or not self.splunk_token:
            logging.error("Missing URL or token")
            return False
            
        try:
            # Prepare Splunk payload
            event_data = {
                "time": time.time(),
                "event": alert_details,
                "sourcetype": "edge_ai_anomaly",
                "source": self.source_id
            }
            
            # Try a few times - Splunk can be flaky
            max_tries = 3
            for attempt in range(max_tries):
                try:
                    # TODO: Add SSL verification
                    response = requests.post(
                        self.splunk_url,
                        headers=self.headers,
                        json=event_data,
                        verify=False,  # Not great but works for now
                        timeout=10
                    )
                    
                    # Success
                    if response.status_code == 200:
                        logging.info(f"Alert sent successfully! Response: {response.text}")
                        return True
                        
                    # Failed
                    logging.warning(
                        f"Try {attempt + 1}/{max_tries} failed: "
                        f"Status: {response.status_code}, "
                        f"Response: {response.text}"
                    )
                    
                    # Wait before retry
                    if attempt < max_tries - 1:
                        time.sleep(2 ** attempt)
                        
                except requests.RequestException as e:
                    logging.warning(f"Request failed on try {attempt + 1}: {str(e)}")
                    if attempt < max_tries - 1:
                        time.sleep(2 ** attempt)
                        
            # All retries failed
            logging.error(f"Giving up after {max_tries} tries")
            return False
            
        except Exception as e:
            logging.error(f"Error sending alert: {str(e)}")
            return False

# TODO:
# - Add SSL validation
# - Make retry count configurable
# - Maybe add queue for failed alerts
