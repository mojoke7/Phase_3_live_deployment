# This is the  brain of the anomaly detection system this used for testing and the main deployemnt after Phase 1 and 2
# It coordinates all the components and runs the ML model thast created in Phase 1 

import os
import time
import logging
import numpy as np
import configparser
import torch  # PyTorch is used for inference

# Here Im importing the model, data acquisition, alerting, and mitigation modules 
from scripts.models.lstm_autoencoder import LSTMAutoencoder  # Model definition
from network_capture import NetworkCapture  # Data acquisition 
from siem_integration import SplunkEventForwarder  # Alerting
from mitigation import mitigate_anomaly, block_ip  # Response actions

# This is the logging for the anomaly detector module
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(module)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/detector.log'),  
        logging.StreamHandler()  
    ]
)

# This is where the anomaly detection starts using the LSTM Autoencoder.

class AnomalyDetector:
    #this sets up the anomaly detector with the configuration file and stops if the file is not found.#
    def __init__(self, configuration: str = '/app/config/settings.ini'):
        logging.info(f"Setting up Anomaly Detector: {configuration}")
        self.config = configparser.ConfigParser()
        if not os.path.exists(configuration):
            logging.error(f"Can't find the config file {configuration}")
            raise FileNotFoundError(f"Config file {configuration} not found.")
               
        # Here is the Model Configuration 
        # it uses the CPU for inference makes sure it can be run on any edge system 
        self.config.read(configuration)
        self.device = torch.device("cpu") 
        self.model_path = self.config.get(
            'Model', 
            'model_path', fallback='/app/model/lstm_ae_rocm.pth')
        self.model_sequence_length = self.config.getint(
            'Network',
            'packet_window_size',
            fallback=100)
        self.input_size = 3  # For the first stess test it used 2 but for the final version it used 3 features 
        self.model = self._load_model()
        
        # Aomaly Thresholds
       # Pulls values from config with fallbacks
        # Higher reconstruction error means stranger traffic meaning it is more likely to be something malicious 
        self.critical_error_threshold = self.config.getfloat(
            'Model', 'critical_threshold', fallback=4500.0)
        self.warning_error_threshold = self.config.getfloat(
            'Model', 'warning_threshold', fallback=4800.0)
        self.notice_error_threshold = self.config.getfloat(
            'Model', 'notice_threshold', fallback=5000.0)
        
        logging.warning(f"Anomaly Thresholds: Notice={self.notice_error_threshold}, Warning={self.warning_error_threshold}, Critical={self.critical_error_threshold}.")
        
        #  Utility Clients 
        # Create our packet reader and alerting system
        self.packet_stream_reader = NetworkCapture(configuration=configuration)
        siem_enabled = self.config.getboolean('SIEM', 'enabled', fallback=False)
        self.event_alerter = SplunkEventForwarder(configuration=configuration) if siem_enabled else None
        
        if siem_enabled:
            logging.info("SIEM integration is enabled.")
        else:
            logging.info("SIEM integration is disabled.")
        
        #  Mitigation config 
        # basicaly this is asking if we should automatically block the suspicious IPs
        self.enable_automatic_blocking = self.config.getboolean('Mitigation', 'auto_block', fallback=False)
        self.autoblock_threshold = self.config.get('Mitigation', 'block_threshold', fallback='critical').lower()
        self.is_detector_active = False
        logging.info("Detector is active")

    def _load_model(self) -> LSTMAutoencoder:
        # Loads the PyTorch model
        logging.info(f"Loading model from: {self.model_path}")
        
        lstm_hidden_size = 64
        lstm_num_layers = 2
        
        model = LSTMAutoencoder(
            input_size=self.input_size,
            hidden_size=lstm_hidden_size,
            num_layers=lstm_num_layers,
            seq_len=self.model_sequence_length
        ).to(self.device)
        
        try:
            if not os.path.exists(self.model_path):
                logging.error(f"the Model file is not found: {self.model_path}")
                raise FileNotFoundError(f"Model file missing")
            
            model.load_state_dict(torch.load(self.model_path, map_location=self.device))
            model.eval()
            logging.info(f"Model loaded to {self.device}")
                
        except Exception as e:
            logging.error(f"Error loading model: {e}")
            raise
            
        return model
    
    def _preprocess_window(self, raw_data: np.ndarray) -> torch.Tensor:
        # Convert numpy to PyTorch format
        return torch.tensor(raw_data, dtype=torch.float32).unsqueeze(0).to(self.device)
    
    def _get_reconstruction_error(self, original: torch.Tensor, reconstructed: torch.Tensor) -> float:
        # Calculate MSE between original and reconstructed data
        loss_fn = torch.nn.MSELoss()
        return loss_fn(reconstructed, original).item()
    
    def _determine_severity(self, error: float) -> tuple[str, bool]:
        # Map error value to severity levels
        local_critical = self.critical_error_threshold
        local_warning = self.warning_error_threshold
        local_notice = self.notice_error_threshold
        
        # checks the thresholds are set right
        if not (local_notice <= local_warning <= local_critical):
            logging.warning(f"Weird threshold config: Notice={local_notice}, Warning={local_warning}, Critical={local_critical}")
        
        # checks the severity levels
        if error > local_critical:
            return "critical", True
        elif error > local_warning:
            return "warning", True
        elif error > local_notice:
            return "notice", True
        else:
            return "normal", False
    
    def run(self):
        # this is the main detection loop
        logging.info("Starting detection loop...")
        self.packet_stream_reader.start()
        self.is_detector_active = True
        
        try:
            while self.is_detector_active:
                # Gets network packets
                packet_window = self.packet_stream_reader.get_packet_feature_window()
                
                    # Skips if theses not enough packets
                if packet_window.size == 0:
                    time.sleep(0.1)
                    continue
                
                # Checks data shape matches model expectations
                if packet_window.shape[0] != self.model_sequence_length or packet_window.shape[1] != self.input_size:
                    logging.warning(f"Data shape wrong. Expected: ({self.model_sequence_length}, {self.input_size}), Got: {packet_window.shape}")
                    continue
                
                #  Prepares for model
                model_input = self._preprocess_window(packet_window)
                
                #  Runs the model
                with torch.no_grad():
                    model_output = self.model(model_input)
                
                #  Calculates error
                error = self._get_reconstruction_error(model_input, model_output)
                logging.info(f"Reconstruction Error: {error:.4f}")
                
                #  Checks if  theres an anomaly
                severity, is_anomaly = self._determine_severity(error)
                
                #  Handles anomalies
                if is_anomaly:
                    logging.warning(f"ANOMALY! Severity: {severity.upper()}, Error: {error:.4f}")
                    
                    # Packages alert info for SIEM
                    alert_info = {
                        "type": "network_anomaly",
                        "reconstruction_error": round(error, 4),
                        "severity": severity,
                        "timestamp": time.time(),
                        "raw_window_sample": packet_window[:5].tolist()
                    }
                    
                    # Sends to SIEM if enabled
                    if self.event_alerter:
                        logging.info(f"Sending to SIEM: {alert_info}")
                        self.event_alerter.send(alert_info)
                    
                        #  Decides if we should block
                    should_block = False
                    if self.enable_automatic_blocking:
                        if severity == "critical" and self.autoblock_threshold == "critical":
                            should_block = True
                        elif severity == "warning" and self.autoblock_threshold == "warning":
                            should_block = True
                    
                    #  Blocks if needed
                    if should_block:
                        logging.warning(f"Auto-blocking for severity '{severity}'")
                        mitigate_anomaly(alert=alert_info, severity=severity)
                
                # Avoid CPU hogging
                time.sleep(0.1)
                
        except KeyboardInterrupt:
            logging.info("Keyboard interrupt. Stopping.")
        except Exception as e:
            logging.error(f"Error in detection loop: {e}", exc_info=True)
        finally:
            self.stop()

    def stop(self):
        # Shut down everything
        logging.info("Stopping detector...")
        self.is_detector_active = False

        if self.packet_stream_reader:
            self.packet_stream_reader.stop()

        logging.info("Detector stopped.")
