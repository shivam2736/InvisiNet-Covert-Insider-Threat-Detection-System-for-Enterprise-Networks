import os
from dataclasses import dataclass
from typing import Dict, List
import yaml

@dataclass
class NetworkConfig:
    tap_interfaces: List[str]
    mirror_ports: List[str]
    data_diode_endpoints: List[str]
    management_network: str
    
@dataclass
class DetectionConfig:
    zeek_config_path: str
    suricata_config_path: str
    ml_model_path: str
    threat_threshold: float
    anomaly_threshold: float
    
@dataclass
class SecurityConfig:
    encryption_key_path: str
    certificate_path: str
    audit_log_path: str
    max_log_retention_days: int

class InvisiNetConfig:
    def __init__(self, config_file: str = "config/invisinet.yaml"):
        self.config_file = config_file
        self.load_config()
    
    def load_config(self):
        with open(self.config_file, 'r') as f:
            config = yaml.safe_load(f)
        
        self.network = NetworkConfig(**config['network'])
        self.detection = DetectionConfig(**config['detection'])
        self.security = SecurityConfig(**config['security'])
        self.debug_mode = config.get('debug_mode', False)
