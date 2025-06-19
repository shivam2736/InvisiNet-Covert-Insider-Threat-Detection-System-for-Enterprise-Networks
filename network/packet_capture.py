import socket
import struct
import threading
import time
from scapy.all import sniff, get_if_list
from cryptography.fernet import Fernet
import logging

class StealthPacketCapture:
    def __init__(self, config: InvisiNetConfig):
        self.config = config
        self.capture_threads = []
        self.running = False
        self.packet_buffer = []
        self.encryption_key = self._load_encryption_key()
        
    def _load_encryption_key(self) -> Fernet:
        """Load encryption key for packet data"""
        with open(self.config.security.encryption_key_path, 'rb') as f:
            key = f.read()
        return Fernet(key)
    
    def start_capture(self):
        """Start stealth packet capture on all interfaces"""
        self.running = True
        
        for interface in self.config.network.tap_interfaces:
            thread = threading.Thread(
                target=self._capture_interface,
                args=(interface,)
            )
            thread.daemon = True
            thread.start()
            self.capture_threads.append(thread)
            
        logging.info(f"Started capture on {len(self.config.network.tap_interfaces)} interfaces")
    
    def _capture_interface(self, interface: str):
        """Capture packets on specific interface"""
        def packet_handler(packet):
            if self.running:
                encrypted_packet = self._encrypt_packet(packet)
                self.packet_buffer.append({
                    'timestamp': time.time(),
                    'interface': interface,
                    'data': encrypted_packet
                })
        
        # Use promiscuous mode for stealth capture
        sniff(iface=interface, prn=packet_handler, store=0, promisc=True)
    
    def _encrypt_packet(self, packet) -> bytes:
        """Encrypt packet data for secure storage"""
        packet_bytes = bytes(packet)
        return self.encryption_key.encrypt(packet_bytes)
    
    def get_packets(self, count: int = 100) -> List[Dict]:
        """Retrieve encrypted packets from buffer"""
        if len(self.packet_buffer) >= count:
            packets = self.packet_buffer[:count]
            self.packet_buffer = self.packet_buffer[count:]
            return packets
        return []
    
    def stop_capture(self):
        """Stop all packet capture threads"""
        self.running = False
        for thread in self.capture_threads:
            thread.join(timeout=5)
