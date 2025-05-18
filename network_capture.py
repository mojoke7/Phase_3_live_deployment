# this is the network packet capture and processing script
# it handles grabbing network data and preparing it for our ML model
# the last updated was 5/18/25
# Fixing the buffer overflow issue

import subprocess
import threading
import time
import numpy as np
import os
import configparser
import logging
from datetime import datetime

# Basic logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(module)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/capture.log'),  # main logfile
        logging.StreamHandler()  # console output for debugging
    ]
)

# Maps protocols to numbers for the ML model
# TODO: Maybe add more protocols later?
PROTOCOL_TO_NUMBER_MAPPING = {
    'tcp': 1,    # most common
    'udp': 2,    # seeing a lot of these lately
    'icmp': 3,   # mostly ping traffic
}
UNKNOWN_PROTOCOL_ID = 0  # for anything we don't recognize

class NetworkCapture:
        # Captures network packets for analysis
    
    def __init__(self, config: str = '/app/config/settings.ini'):
        #  setup
        self.packet_buffer = []
        self.packet_buffer_lock = threading.Lock()
        self.stop_capture_event = threading.Event()
        self.capture_thread = None
        
        # Loads the config
        self._load_settings(config)
        
        # Checks for tcpdump
        if not self._check_tcpdump():
            logging.error("tcpdump missing! Can't continue.")
            raise RuntimeError("tcpdump not found")       
        logging.info(f"Ready to capture on {self.network_interface_name},
                      window_size={self.window_size}")
    
    # Loads the settings from the config
    def _load_settings(self, config):
        #   Loads the settings from the config
        self.config = configparser.ConfigParser()
        if not os.path.exists(config):
            logging.error(f"Config file not found: {config}")
            raise FileNotFoundError(f"Missing config: {config}")   
        self.config.read(config)
        self.network_interface_name = self.config.get(
            'Network', 'interface', fallback='eth0')
        self.window_size = self.config.getint(
            'Network', 'packet_window_size', fallback=100)
        self.capture_filter = self.config.get(
            'Network', 'pcap_filter', fallback='ip')
    
    def _check_tcpdump(self) -> bool:
        # Checks if tcpdump is installed
        try:
            subprocess.run(['tcpdump', '--version'], capture_output=True, check=True, text=True)
            return True
        except Exception:
            return False
    
    def _monitor_errors(self, stderr_pipe):
        # Watches tcpdump error output
        try:
            for line in iter(stderr_pipe.readline, ''):
                if line:
                    logging.warning(f"tcpdump: {line.strip()}")
            stderr_pipe.close()
        except Exception as e:
            logging.error(f"Error reading stderr: {e}")
    
    def _start_capture(self):
        # Runs tcpdump and processes output
        # Build command
        cmd = [
            'tcpdump',
            '-i', self.network_interface_name,
            '-l',                 # line buffered
            '-n',                 # no name resolution
            '-tttt',              # timestamp format
            self.capture_filter   # filter
        ]
        
        logging.info(f"Starting tcpdump: {' '.join(cmd)}")
        
        try:
            # Start tcpdump
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Monitor errors
            error_thread = threading.Thread(target=self._monitor_errors, args=(process.stderr,), daemon=True)
            error_thread.start()
            
            # Main loop
            while not self.stop_capture_event.is_set():
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                    
                if line:
                    self._parse_packet(line)
            
            # Clean shutdown
            if process.poll() is None:
                logging.info("Stopping tcpdump...")
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    logging.warning("tcpdump not responding - killing")
                    process.kill()
                    
            logging.info("Capture stopped")
            
        except FileNotFoundError:
            logging.error("tcpdump not found")
            raise
        except Exception as e:
            logging.error(f"Capture failed: {e}")
            raise
    
    def _parse_packet(self, line):
        # Parses a tcpdump output line
        try:
            parts = line.strip().split()
            if "length" in line and "IP" in line:
                # Gets timestamp
                timestamp_str = parts[0] + " " + parts[1]
                dt = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S.%f")
                timestamp = dt.timestamp()
                
                # Gets packet length
                length_idx = parts.index("length") + 1
                packet_length = int(parts[length_idx].replace(':', ''))
                
                # Gets protocol
                protocol = "unknown"
                if "TCP" in line: protocol = "tcp"
                elif "UDP" in line: protocol = "udp"
                elif "ICMP" in line: protocol = "icmp"
                
                # Stores packet info
                with self.packet_buffer_lock:
                    self.packet_buffer.append((timestamp, packet_length, protocol))
        except Exception as e:
            logging.warning(f"Parse error: '{line.strip()}' - {e}")
    
    def start(self):
        # Starts packet capture
        if self.capture_thread and self.capture_thread.is_alive():
            logging.warning("Already capturing!")
            return
            
        self.stop_capture_event.clear()
        self.capture_thread = threading.Thread(target=self._start_capture, daemon=True)
        self.capture_thread.start()
        logging.info("Started capture")
    
    def stop(self):
        # Stops packet capture
        logging.info("Stopping capture...")
        self.stop_capture_event.set()
        
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=10)
            if self.capture_thread.is_alive():
                logging.warning("Capture thread stuck")
                
        logging.info("Capture stopped")
    
    def get_packet_feature_window(self) -> np.ndarray:
        # Gets window of packets for anomaly detection
        with self.packet_buffer_lock:
            if len(self.packet_buffer) < self.window_size:
                return np.array([])  # not enough packets
                
            # Get latest packets
            latest_packets = self.packet_buffer[-self.window_size:]
            features = []
            
            # Convert to model features
            start_time = latest_packets[0][0]
            for timestamp, length, protocol in latest_packets:
                protocol_id = PROTOCOL_TO_NUMBER_MAPPING.get(protocol.lower(), UNKNOWN_PROTOCOL_ID)
                time_offset = timestamp - start_time
                features.append([float(length), float(protocol_id), float(time_offset)])
                
            return np.array(features, dtype=np.float32)


