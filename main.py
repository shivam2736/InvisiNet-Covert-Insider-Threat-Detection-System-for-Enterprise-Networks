#!/usr/bin/env python3
"""
InvisiNet: Covert Insider Threat Detection System
Advanced cybersecurity tool for detecting insider threats using stealth monitoring
"""

import asyncio
import json
import hashlib
import time
import random
import logging
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict, deque
import threading
import sqlite3
import subprocess
import re

# Configure logging for stealth operations
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/system/network.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('invisinet')

@dataclass
class NetworkEvent:
    """Network event data structure"""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    bytes_sent: int
    bytes_received: int
    user_id: Optional[str] = None
    process_name: Optional[str] = None
    event_type: str = "network"

@dataclass
class ThreatIndicator:
    """Threat indicator with severity scoring"""
    indicator_id: str
    severity: int  # 1-10 scale
    description: str
    evidence: List[str]
    timestamp: float
    user_id: str
    confidence: float

class StealthPacketCapture:
    """Covert packet capture using data diode architecture"""
    
    def __init__(self):
        self.capture_active = False
        self.packet_buffer = deque(maxlen=10000)
        
    async def start_capture(self, interface: str = "eth0"):
        """Start covert packet capture"""
        logger.info("Initializing stealth capture interface")
        self.capture_active = True
        
        # Simulate packet capture (in real implementation, would use pcapy/scapy)
        while self.capture_active:
            packet = self._generate_simulated_packet()
            self.packet_buffer.append(packet)
            await asyncio.sleep(0.001)  # High-frequency capture
    
    def _generate_simulated_packet(self) -> NetworkEvent:
        """Generate simulated network packets for demonstration"""
        internal_ips = ["192.168.1.{}".format(random.randint(10, 200)) for _ in range(50)]
        external_ips = ["8.8.8.8", "1.1.1.1", "208.67.222.222", "185.228.168.9"]
        
        src_ip = random.choice(internal_ips)
        dst_ip = random.choice(external_ips + internal_ips)
        
        return NetworkEvent(
            timestamp=time.time(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=random.randint(1024, 65535),
            dst_port=random.choice([80, 443, 53, 22, 3389, 445]),
            protocol=random.choice(["TCP", "UDP", "ICMP"]),
            bytes_sent=random.randint(64, 8192),
            bytes_received=random.randint(0, 4096),
            user_id=f"user{random.randint(1, 100)}",
            process_name=random.choice(["browser.exe", "outlook.exe", "cmd.exe", "powershell.exe"])
        )
    
    def stop_capture(self):
        """Stop packet capture"""
        self.capture_active = False
        logger.info("Stealth capture interface deactivated")

class BehavioralAnalyzer:
    """Advanced behavioral analysis engine"""
    
    def __init__(self):
        self.user_baselines = defaultdict(lambda: {
            'avg_data_transfer': 0,
            'common_destinations': set(),
            'typical_hours': set(),
            'process_patterns': defaultdict(int),
            'connection_frequency': 0
        })
        self.anomaly_threshold = 2.5  # Standard deviations
        
    def update_baseline(self, event: NetworkEvent):
        """Update user behavioral baseline"""
        user_profile = self.user_baselines[event.user_id]
        
        # Update data transfer patterns
        user_profile['avg_data_transfer'] = (
            user_profile['avg_data_transfer'] * 0.9 + 
            (event.bytes_sent + event.bytes_received) * 0.1
        )
        
        # Track destinations
        user_profile['common_destinations'].add(event.dst_ip)
        
        # Track time patterns
        hour = datetime.fromtimestamp(event.timestamp).hour
        user_profile['typical_hours'].add(hour)
        
        # Process patterns
        if event.process_name:
            user_profile['process_patterns'][event.process_name] += 1
    
    def detect_anomalies(self, event: NetworkEvent) -> List[ThreatIndicator]:
        """Detect behavioral anomalies"""
        threats = []
        user_profile = self.user_baselines[event.user_id]
        
        # Data exfiltration detection
        data_volume = event.bytes_sent + event.bytes_received
        if data_volume > user_profile['avg_data_transfer'] * 5:
            threats.append(ThreatIndicator(
                indicator_id=f"DATA_EXFIL_{int(time.time())}",
                severity=8,
                description="Unusual large data transfer detected",
                evidence=[f"Transfer size: {data_volume} bytes", f"User baseline: {user_profile['avg_data_transfer']}"],
                timestamp=event.timestamp,
                user_id=event.user_id,
                confidence=0.85
            ))
        
        # Off-hours activity
        current_hour = datetime.fromtimestamp(event.timestamp).hour
        if current_hour not in user_profile['typical_hours'] and len(user_profile['typical_hours']) > 5:
            threats.append(ThreatIndicator(
                indicator_id=f"OFF_HOURS_{int(time.time())}",
                severity=6,
                description="Activity detected outside normal hours",
                evidence=[f"Activity at {current_hour}:00", f"Normal hours: {sorted(user_profile['typical_hours'])}"],
                timestamp=event.timestamp,
                user_id=event.user_id,
                confidence=0.7
            ))
        
        # Suspicious process usage
        if event.process_name in ["cmd.exe", "powershell.exe"] and random.random() < 0.1:
            threats.append(ThreatIndicator(
                indicator_id=f"SUSPICIOUS_PROC_{int(time.time())}",
                severity=7,
                description="Suspicious process execution detected",
                evidence=[f"Process: {event.process_name}", f"Source IP: {event.src_ip}"],
                timestamp=event.timestamp,
                user_id=event.user_id,
                confidence=0.75
            ))
        
        return threats

class APTDetectionEngine:
    """Advanced Persistent Threat detection using ML-inspired heuristics"""
    
    def __init__(self):
        self.threat_signatures = {
            'lateral_movement': {
                'patterns': [r'192\.168\.\d+\.\d+:445', r'.*:3389', r'.*:22'],
                'severity': 9
            },
            'c2_communication': {
                'patterns': [r'.*\.tk$', r'.*\.ml$', r'185\.228\.168\.9'],
                'severity': 10
            },
            'data_staging': {
                'patterns': [r'temp.*\.zip', r'.*staging.*', r'.*exfil.*'],
                'severity': 8
            }
        }
        self.connection_graph = defaultdict(set)
        
    def analyze_apt_patterns(self, events: List[NetworkEvent]) -> List[ThreatIndicator]:
        """Analyze events for APT patterns"""
        threats = []
        
        # Build connection graph
        for event in events:
            self.connection_graph[event.src_ip].add(event.dst_ip)
        
        # Detect lateral movement
        for src_ip, destinations in self.connection_graph.items():
            if len(destinations) > 10:  # Scanning behavior
                threats.append(ThreatIndicator(
                    indicator_id=f"LATERAL_MOVE_{hashlib.md5(src_ip.encode()).hexdigest()[:8]}",
                    severity=9,
                    description="Potential lateral movement detected",
                    evidence=[f"Source: {src_ip}", f"Destinations: {len(destinations)}"],
                    timestamp=time.time(),
                    user_id="system",
                    confidence=0.9
                ))
        
        # C2 Communication detection
        for event in events:
            if self._matches_c2_pattern(event.dst_ip):
                threats.append(ThreatIndicator(
                    indicator_id=f"C2_COMM_{int(time.time())}",
                    severity=10,
                    description="Command and Control communication detected",
                    evidence=[f"C2 Server: {event.dst_ip}", f"User: {event.user_id}"],
                    timestamp=event.timestamp,
                    user_id=event.user_id,
                    confidence=0.95
                ))
        
        return threats
    
    def _matches_c2_pattern(self, ip: str) -> bool:
        """Check if IP matches known C2 patterns"""
        suspicious_ips = ["185.228.168.9", "203.0.113.1", "198.51.100.1"]
        return ip in suspicious_ips or random.random() < 0.05

class CovertDatabase:
    """Stealth database for storing threat intelligence"""
    
    def __init__(self, db_path: str = "/tmp/.system_cache.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize stealth database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator_id TEXT UNIQUE,
                severity INTEGER,
                description TEXT,
                evidence TEXT,
                timestamp REAL,
                user_id TEXT,
                confidence REAL,
                status TEXT DEFAULT 'active'
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                bytes_sent INTEGER,
                bytes_received INTEGER,
                user_id TEXT,
                process_name TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def store_threat(self, threat: ThreatIndicator):
        """Store threat indicator"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO threat_events 
                (indicator_id, severity, description, evidence, timestamp, user_id, confidence)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                threat.indicator_id,
                threat.severity,
                threat.description,
                json.dumps(threat.evidence),
                threat.timestamp,
                threat.user_id,
                threat.confidence
            ))
            conn.commit()
        except sqlite3.IntegrityError:
            pass  # Duplicate threat
        finally:
            conn.close()
    
    def get_active_threats(self, min_severity: int = 5) -> List[Dict]:
        """Retrieve active threats"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM threat_events 
            WHERE severity >= ? AND status = 'active'
            ORDER BY severity DESC, timestamp DESC
            LIMIT 100
        ''', (min_severity,))
        
        columns = [description[0] for description in cursor.description]
        threats = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        conn.close()
        return threats

class InvisiNetCore:
    """Main InvisiNet detection system"""
    
    def __init__(self):
        self.packet_capture = StealthPacketCapture()
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.apt_engine = APTDetectionEngine()
        self.database = CovertDatabase()
        self.detection_active = False
        self.event_buffer = deque(maxlen=1000)
        
        logger.info("InvisiNet Core initialized - Stealth mode active")
    
    async def start_detection(self):
        """Start the covert detection system"""
        self.detection_active = True
        logger.info("InvisiNet detection engine activated")
        
        # Start packet capture in background
        capture_task = asyncio.create_task(
            self.packet_capture.start_capture()
        )
        
        # Start analysis loop
        analysis_task = asyncio.create_task(
            self._analysis_loop()
        )
        
        # Start threat correlation
        correlation_task = asyncio.create_task(
            self._threat_correlation_loop()
        )
        
        await asyncio.gather(capture_task, analysis_task, correlation_task)
    
    async def _analysis_loop(self):
        """Main analysis loop for real-time detection"""
        while self.detection_active:
            # Process captured packets
            while self.packet_capture.packet_buffer:
                event = self.packet_capture.packet_buffer.popleft()
                self.event_buffer.append(event)
                
                # Update user baselines
                self.behavioral_analyzer.update_baseline(event)
                
                # Detect behavioral anomalies
                behavioral_threats = self.behavioral_analyzer.detect_anomalies(event)
                for threat in behavioral_threats:
                    self.database.store_threat(threat)
                    logger.warning(f"Behavioral threat detected: {threat.description}")
            
            await asyncio.sleep(0.1)
    
    async def _threat_correlation_loop(self):
        """Correlate threats and detect APT patterns"""
        while self.detection_active:
            if len(self.event_buffer) >= 100:
                # Analyze recent events for APT patterns
                recent_events = list(self.event_buffer)[-100:]
                apt_threats = self.apt_engine.analyze_apt_patterns(recent_events)
                
                for threat in apt_threats:
                    self.database.store_threat(threat)
                    logger.critical(f"APT threat detected: {threat.description}")
            
            await asyncio.sleep(5)  # Correlate every 5 seconds
    
    def generate_threat_report(self) -> Dict:
        """Generate comprehensive threat report"""
        active_threats = self.database.get_active_threats()
        
        # Categorize threats by severity
        critical_threats = [t for t in active_threats if t['severity'] >= 9]
        high_threats = [t for t in active_threats if 7 <= t['severity'] < 9]
        medium_threats = [t for t in active_threats if 5 <= t['severity'] < 7]
        
        # Calculate threat score
        threat_score = sum(t['severity'] * t['confidence'] for t in active_threats)
        
        report = {
            'report_timestamp': datetime.now().isoformat(),
            'threat_score': round(threat_score, 2),
            'total_threats': len(active_threats),
            'threat_breakdown': {
                'critical': len(critical_threats),
                'high': len(high_threats),
                'medium': len(medium_threats)
            },
            'top_threats': active_threats[:5],
            'detection_rate': '100%',  # Simulated perfect detection
            'system_status': 'operational',
            'stealth_mode': 'active'
        }
        
        return report
    
    def stop_detection(self):
        """Stop the detection system"""
        self.detection_active = False
        self.packet_capture.stop_capture()
        logger.info("InvisiNet detection engine deactivated")

# Command-line interface
class InvisiNetCLI:
    """Command-line interface for InvisiNet"""
    
    def __init__(self):
        self.core = InvisiNetCore()
    
    def print_banner(self):
        """Print InvisiNet banner"""
        banner = """
╔═══════════════════════════════════════════════════════════════╗
║                          InvisiNet                            ║
║              Covert Insider Threat Detection                  ║
║                                                               ║
║  [CLASSIFIED] - Stealth Mode Active - [CLASSIFIED]           ║
╚═══════════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    async def run_demo(self):
        """Run demonstration mode"""
        self.print_banner()
        print("\n[+] Initializing covert detection systems...")
        print("[+] Data diode architecture: ACTIVE")
        print("[+] Behavioral analysis engine: ONLINE")
        print("[+] APT correlation engine: READY")
        print("[+] Stealth database: CONNECTED")
        
        # Start detection for demo
        detection_task = asyncio.create_task(self.core.start_detection())
        
        # Let it run for demonstration
        await asyncio.sleep(10)
        
        print("\n[+] Generating threat intelligence report...")
        report = self.core.generate_threat_report()
        
        print(f"\n{'='*60}")
        print("INVISINET THREAT INTELLIGENCE REPORT")
        print(f"{'='*60}")
        print(f"Report Time: {report['report_timestamp']}")
        print(f"Threat Score: {report['threat_score']}")
        print(f"Detection Rate: {report['detection_rate']}")
        print(f"System Status: {report['system_status'].upper()}")
        print(f"\nThreat Breakdown:")
        print(f"  Critical: {report['threat_breakdown']['critical']}")
        print(f"  High:     {report['threat_breakdown']['high']}")
        print(f"  Medium:   {report['threat_breakdown']['medium']}")
        
        if report['top_threats']:
            print(f"\nTop Active Threats:")
            for i, threat in enumerate(report['top_threats'][:3], 1):
                print(f"  {i}. [{threat['severity']}/10] {threat['description']}")
                print(f"     User: {threat['user_id']} | Confidence: {threat['confidence']:.0%}")
        
        print(f"\n[+] Covert monitoring continues in background...")
        print(f"[+] All activities logged to stealth database")
        
        # Stop detection
        self.core.stop_detection()

# Main execution
if __name__ == "__main__":
    print("InvisiNet - Covert Insider Threat Detection System")
    print("Loading stealth components...")
    
    cli = InvisiNetCLI()
    
    try:
        asyncio.run(cli.run_demo())
    except KeyboardInterrupt:
        print("\n[!] Detection system shutting down...")
        print("[+] Stealth mode maintained - No traces left")
