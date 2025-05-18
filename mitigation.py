#!/usr/bin/env python3
# Handles reactive measures when anomalies are detected

import os
import logging
import subprocess
import time
import re
import socket

# Basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(module)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/mitigation.log'),
        logging.StreamHandler()
    ]
)

def is_valid_external_ip(ip_addr):
    """Check if IP is valid and not internal"""
    try:
        socket.inet_pton(socket.AF_INET, ip_addr)
        # Don't block our own networks
        if ip_addr.startswith(('127.', '10.', '192.168.', '172.16.')) or ip_addr == '255.255.255.255':
            return False
        return True
    except socket.error:
        return False

def extract_active_ips(interface='eth0', max_packets=5, timeout=3):
    """Get IPs from recent traffic"""
    found_ips = []
    try:
        # Quick tcpdump to find active IPs
        cmd = f"timeout {timeout} tcpdump -i {interface} -n 'ip' -c {max_packets} 2>/dev/null | grep -o -E '\\b([0-9]{{1,3}}\\.?){{4}}\\b' | sort | uniq"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode != 0 and result.returncode != 124:  # 124 is timeout's exit code
            logging.warning(f"tcpdump failed: {result.returncode}")
            return []
            
        # Get IPs from output
        ip_text = result.stdout.strip()
        if ip_text:
            # Extract IPs with regex
            ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
            all_ips = ip_pattern.findall(ip_text)
            
            # Filter out internal IPs
            found_ips = [ip for ip in all_ips if is_valid_external_ip(ip)]
            
    except Exception as e:
        logging.error(f"Error getting IPs: {str(e)}")
    
    return found_ips

def get_source_ips_from_anomaly(alert=None):
    """Try to figure out who needs blocking"""
    source_ips = []
    
    # Method 1: Get IPs directly from alert if available
    if alert and "source_ips" in alert and isinstance(alert["source_ips"], list):
        source_ips.extend([ip for ip in alert["source_ips"] if is_valid_external_ip(ip)])
    
    # Method 2: Try to extract from raw_window_sample
    # TODO: Add IP data to packet captures and alerts
    
    # Method 3: Last resort - use tcpdump
    if not source_ips:
        logging.info("No IPs in alert, checking recent traffic")
        source_ips = extract_active_ips()
    
    return list(set(source_ips))  # Remove duplicates

def block_ip(ip_to_block: str) -> bool:
    """Blocks an IP using iptables"""
    # Safety check
    if not is_valid_external_ip(ip_to_block):
        logging.warning(f"Not blocking {ip_to_block} - internal or invalid")
        return False
        
    # Block with iptables
    cmd = f"sudo iptables -A INPUT -s {ip_to_block} -j DROP"
    logging.info(f"Blocking IP: {ip_to_block} with: '{cmd}'")
    
    try:
        result = subprocess.run(cmd.split(), capture_output=True, text=True, check=False)
        
        if result.returncode == 0:
            logging.warning(f"Blocked IP {ip_to_block}")
            return True
        else:
            logging.error(f"Failed to block IP {ip_to_block}: {result.stderr.strip()}")
            return False
    except FileNotFoundError:
        logging.error(f"iptables not found. Can't block {ip_to_block}")
        return False
    except Exception as e:
        logging.error(f"Error blocking IP {ip_to_block}: {str(e)}")
        return False

def mitigate_anomaly(alert: dict = None, severity: str = "critical") -> bool:
    """Takes action based on anomaly severity"""
    logging.info(f"Mitigation for alert severity: '{severity}'")

    if severity == "critical":
        logging.warning("CRITICAL ANOMALY - MITIGATING")
        
        # Visible alert
        print("\n")
        print("=" * 80)
        print(" CRITICAL ANOMALY DETECTED - MITIGATION ACTIVE ")
        print("=" * 80)
        
        if alert:
            print(f" Alert Type: {alert.get('anomaly_type', 'N/A')}")
            print(f" Reconstruction Error: {alert.get('reconstruction_error', 0):.2f}")
            
            if "protocol_distribution" in alert:
                print(" Protocol Distribution:")
                for proto, count in alert.get("protocol_distribution", {}).items():
                    print(f" - {proto}: {count}")
            
            # Find and block attackers
            suspect_ips = get_source_ips_from_anomaly(alert)
            
            if suspect_ips:
                print(f" IPs to block: {', '.join(suspect_ips)}")
                
                # Block the IPs
                blocked_ips = []
                for ip in suspect_ips:
                    if block_ip(ip):
                        blocked_ips.append(ip)
                
                if blocked_ips:
                    print(f" Blocked {len(blocked_ips)} IPs")
                    logging.warning(f"Blocked IPs: {', '.join(blocked_ips)}")
                else:
                    print(" No IPs blocked - see logs")
            else:
                print(" No source IPs found to block")
            
            print(" Other actions:")
            print(" 1. Logged event")
            print(" 2. Notified security team")
        
        print("=" * 80)
        print("\n")
        return True

    elif severity == "warning":
        # Alert but don't block
        logging.warning("WARNING ANOMALY - MONITORING")
        
        print("\n")
        print("-" * 80)
        print("⚠️ WARNING: Traffic pattern suspicious.")
        if alert:
            print(f" Reconstruction Error: {alert.get('reconstruction_error', 0):.2f}")
        print(" Monitoring closely.")
        print("-" * 80)
        print("\n")
        return True

    elif severity == "notice":
        # Just log
        logging.info("NOTICE LEVEL ANOMALY - LOGGED")
        return True

    else:
        logging.info(f"No mitigation for severity: '{severity}'")
        return False