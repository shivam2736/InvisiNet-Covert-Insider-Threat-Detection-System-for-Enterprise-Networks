import subprocess
import os
import json
from typing import Dict, List
import logging

class ZeekManager:
    def __init__(self, config: InvisiNetConfig):
        self.config = config
        self.zeek_process = None
        self.log_dir = "/opt/invisinet/logs/zeek"
        
    def deploy_custom_scripts(self):
        """Deploy custom Zeek scripts"""
        script_dir = "/opt/zeek/share/zeek/site"
        
        # Write the insider threat script
        with open(f"{script_dir}/insider_threat.zeek", "w") as f:
            f.write(ZEEK_SCRIPT)
            
        # Update local.zeek to include our script
        local_zeek_path = f"{script_dir}/local.zeek"
        with open(local_zeek_path, "a") as f:
            f.write("\n@load ./insider_threat.zeek\n")
            
        logging.info("Custom Zeek scripts deployed")
    
    def start_zeek(self, interfaces: List[str]):
        """Start Zeek with custom configuration"""
        cmd = [
            "zeek",
            "-i", ",".join(interfaces),
            f"Log::default_logdir={self.log_dir}",
            "local"
        ]
        
        self.zeek_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd="/opt/zeek/share/zeek/site"
        )
        
        logging.info(f"Zeek started on interfaces: {interfaces}")
    
    def parse_zeek_logs(self) -> List[Dict]:
        """Parse Zeek logs for threat indicators"""
        threats = []
        log_file = f"{self.log_dir}/insider_threats.log"
        
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                for line in f:
                    if line.startswith('#'):
                        continue
                    parts = line.strip().split('\t')
                    if len(parts) >= 7:
                        threat = {
                            'timestamp': float(parts[0]),
                            'user': parts[1],
                            'src_ip': parts[2],
                            'dst_ip': parts[3],
                            'action': parts[4],
                            'severity': int(parts[5]),
                            'details': parts[6] if len(parts) > 6 else ""
                        }
                        threats.append(threat)
        
        return threats
