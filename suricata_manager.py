import subprocess
import yaml
import os
from typing import List, Dict
import logging

class SuricataManager:
    def __init__(self, config: InvisiNetConfig):
        self.config = config
        self.suricata_process = None
        self.rules_dir = "/opt/invisinet/suricata/rules"
        self.log_dir = "/opt/invisinet/logs/suricata"
        
    def generate_custom_rules(self):
        """Generate custom Suricata rules for insider threats"""
        rules = [
            # Data exfiltration detection
            'alert tcp $HOME_NET any -> !$HOME_NET any (msg:"InvisiNet: Large Data Upload Detected"; flow:established,to_server; dsize:>10000000; threshold:type limit, track by_src, count 1, seconds 300; sid:1000001; rev:1; classtype:policy-violation;)',
            
            # Credential harvesting
            'alert tcp any any -> $HOME_NET 445 (msg:"InvisiNet: Possible Password Spraying on SMB"; flow:established,to_server; content:"NTLMSSP"; threshold:type threshold, track by_src, count 50, seconds 60; sid:1000002; rev:1; classtype:attempted-admin;)',
            
            # Admin tool usage
            'alert tcp $HOME_NET any -> $HOME_NET any (msg:"InvisiNet: PsExec Usage Detected"; flow:established; content:"PsExec"; nocase; sid:1000003; rev:1; classtype:system-call-detect;)',
            
            # USB device detection
            'alert tcp any any -> any any (msg:"InvisiNet: USB Mass Storage Device"; content:"USB"; nocase; content:"Mass Storage"; nocase; distance:0; within:100; sid:1000004; rev:1; classtype:hardware-event;)',
            
            # RDP brute force
            'alert tcp any any -> $HOME_NET 3389 (msg:"InvisiNet: RDP Brute Force Attempt"; flow:established,to_server; threshold:type both, track by_src, count 20, seconds 60; sid:1000005; rev:1; classtype:attempted-admin;)',
            
            # DNS tunneling
            'alert dns any any -> any any (msg:"InvisiNet: Suspicious DNS Query Length"; dns_query; content:"|00|"; dsize:>100; sid:1000006; rev:1; classtype:policy-violation;)',
            
            # Email data exfiltration
            'alert tcp $HOME_NET any -> !$HOME_NET [25,587,465] (msg:"InvisiNet: Large Email Attachment"; flow:established,to_server; content:"Content-Type|3a| application"; content:"Content-Length|3a|"; pcre:"/Content-Length\\x3a\\s+([5-9]\\d{7,}|\\d{8,})/i"; sid:1000007; rev:1; classtype:policy-violation;)',
            
            # Cloud storage uploads
            'alert tls $HOME_NET any -> !$HOME_NET any (msg:"InvisiNet: Cloud Storage Upload"; tls_sni; content:"dropbox.com"; sid:1000008; rev:1; classtype:policy-violation;)',
            'alert tls $HOME_NET any -> !$HOME_NET any (msg:"InvisiNet: Google Drive Upload"; tls_sni; content:"drive.google.com"; sid:1000009; rev:1; classtype:policy-violation;)',
            
            # Database access anomalies
            'alert tcp $HOME_NET any -> $HOME_NET [1433,3306,5432,1521] (msg:"InvisiNet: After Hours Database Access"; threshold:type limit, track by_src, count 1, seconds 3600; sid:1000010; rev:1; classtype:policy-violation;)',
        ]
        
        # Write custom rules file
        rules_file = f"{self.rules_dir}/invisinet.rules"
        os.makedirs(self.rules_dir, exist_ok=True)
        
        with open(rules_file, 'w') as f:
            for rule in rules:
                f.write(rule + '\n')
                
        logging.info(f"Generated {len(rules)} custom Suricata rules")
        return rules_file
    
    def create_suricata_config(self):
        """Create Suricata configuration file"""
        config = {
            'vars': {
                'address-groups': {
                    'HOME_NET': '[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]',
                    'EXTERNAL_NET': '!$HOME_NET',
                    'HTTP_SERVERS': '$HOME_NET',
                    'SMTP_SERVERS': '$HOME_NET',
                    'SQL_SERVERS': '$HOME_NET',
                    'DNS_SERVERS': '$HOME_NET',
                    'TELNET_SERVERS': '$HOME_NET',
                    'AIM_SERVERS': '$EXTERNAL_NET',
                    'DC_SERVERS': '$HOME_NET',
                    'DNP3_SERVER': '$HOME_NET',
                    'DNP3_CLIENT': '$HOME_NET',
                    'MODBUS_CLIENT': '$HOME_NET',
                    'MODBUS_SERVER': '$HOME_NET',
                    'ENIP_CLIENT': '$HOME_NET',
                    'ENIP_SERVER': '$HOME_NET'
                },
                'port-groups': {
                    'HTTP_PORTS': '80',
                    'SHELLCODE_PORTS': '!80',
                    'ORACLE_PORTS': '1521',
                    'SSH_PORTS': '22',
                    'DNP3_PORTS': '20000',
                    'MODBUS_PORTS': '502',
                    'FILE_DATA_PORTS': '[$HTTP_PORTS,110,143]',
                    'FTP_PORTS': '21',
                    'GENEVE_PORTS': '6081',
                    'VXLAN_PORTS': '4789',
                    'TEREDO_PORTS': '3544'
                }
            },
            'default-log-dir': self.log_dir,
            'stats': {
                'enabled': True,
                'interval': 8
            },
            'outputs': [
                {
                    'eve-log': {
                        'enabled': True,
                        'filetype': 'regular',
                        'filename': 'eve.json',
                        'types': [
                            {'alert': {'tagged-packets': True}},
                            'anomaly',
                            'http',
                            'dns',
                            'tls',
                            'files',
                            'smtp',
                            'ssh',
                            'stats',
                            'flow'
                        ]
                    }
                }
            ],
            'logging': {
                'default-log-level': 'notice',
                'outputs': [
                    {
                        'console': {
                            'enabled': True
                        }
                    },
                    {
                        'file': {
                            'enabled': True,
                            'level': 'info',
                            'filename': 'suricata.log'
                        }
                    }
                ]
            },
            'af-packet': [
                {
                    'interface': 'eth0',
                    'threads': 'auto',
                    'cluster-id': 99,
                    'cluster-type': 'cluster_flow',
                    'defrag': True
                }
            ],
            'pcap': [
                {
                    'interface': 'eth0'
                }
            ],
            'app-layer': {
                'protocols': {
                    'tls': {
                        'enabled': True,
                        'detection-ports': {
                            'dp': '443'
                        }
                    },
                    'http': {
                        'enabled': True,
                        'libhtp': {
                            'default-config': {
                                'personality': 'IDS',
                                'request-body-limit': 100000,
                                'response-body-limit': 100000,
                                'request-body-minimal-inspect-size': 32768,
                                'request-body-inspect-window': 4096,
                                'response-body-minimal-inspect-size': 40000,
                                'response-body-inspect-window': 16384,
                                'response-body-decompress-layer-limit': 2,
                                'http-body-inline': 'auto',
                                'swf-decompression': {
                                    'enabled': True,
                                    'type': 'both',
                                    'compress-depth': 100000,
                                    'decompress-depth': 100000
                                },
                                'double-decode-path': False,
                                'double-decode-query': False
                            }
                        }
                    },
                    'ftp': {
                        'enabled': True
                    },
                    'ssh': {
                        'enabled': True
                    },
                    'smtp': {
                        'enabled': True,
                        'raw-extraction': False,
                        'mime': {
                            'decode-mime': True,
                            'decode-base64': True,
                            'decode-quoted-printable': True,
                            'header-value-depth': 2000,
                            'extract-urls': True,
                            'body-md5': False
                        },
                        'inspected-tracker': {
                            'content-limit': 100000,
                            'content-inspect-min-size': 32768,
                            'content-inspect-window': 4096
                        }
                    },
                    'dns': {
                        'tcp': {
                            'enabled': True,
                            'detection-ports': {
                                'dp': '53'
                            }
                        },
                        'udp': {
                            'enabled': True,
                            'detection-ports': {
                                'dp': '53'
                            }
                        }
                    },
                    'smb': {
                        'enabled': True,
                        'detection-ports': {
                            'dp': '139,445'
                        }
                    }
                }
            },
            'asn1-max-frames': 256,
            'engine-analysis': {
                'rules-fast-pattern': True,
                'rules': True
            },
            'pcre': {
                'match-limit': 3500,
                'match-limit-recursion': 1500
            },
            'host-mode': 'auto',
            'unix-command': {
                'enabled': 'auto'
            },
            'legacy': {
                'uricontent': 'enabled'
            }
        }
        
        config_file = "/opt/invisinet/suricata/suricata.yaml"
        os.makedirs(os.path.dirname(config_file), exist_ok=True)
        
        with open(config_file, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
            
        return config_file
    
    def start_suricata(self, interface: str):
        """Start Suricata with custom configuration"""
        config_file = self.create_suricata_config()
        rules_file = self.generate_custom_rules()
        
        cmd = [
            "suricata",
            "-c", config_file,
            "-S", rules_file,
            "-i", interface,
            "-l", self.log_dir,
            "--init-errors-fatal"
        ]
        
        self.suricata_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        logging.info(f"Suricata started on interface: {interface}")
    
    def parse_suricata_alerts(self) -> List[Dict]:
        """Parse Suricata EVE JSON logs"""
        alerts = []
        eve_log = f"{self.log_dir}/eve.json"
        
        if os.path.exists(eve_log):
            with open(eve_log, 'r') as f:
                for line in f:
                    try:
                        event = json.loads(line.strip())
                        if event.get('event_type') == 'alert':
                            alerts.append(event)
                    except json.JSONDecodeError:
                        continue
        
        return alerts
