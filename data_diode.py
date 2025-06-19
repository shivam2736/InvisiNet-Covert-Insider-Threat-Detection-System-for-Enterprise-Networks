import socket
import ssl
import threading
import json
from typing import Any, Dict
import logging

class DataDiode:
    def __init__(self, config: InvisiNetConfig):
        self.config = config
        self.sender_socket = None
        self.receiver_socket = None
        self.running = False
        
    def setup_sender(self, host: str, port: int):
        """Setup sender side of data diode"""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        self.sender_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sender_socket = context.wrap_socket(self.sender_socket)
        self.sender_socket.connect((host, port))
        
    def setup_receiver(self, host: str, port: int):
        """Setup receiver side of data diode"""
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(self.config.security.certificate_path)
        
        self.receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.receiver_socket.bind((host, port))
        self.receiver_socket.listen(5)
        
    def send_data(self, data: Dict[str, Any]):
        """Send data through diode (one-way only)"""
        if not self.sender_socket:
            raise RuntimeError("Sender not configured")
            
        json_data = json.dumps(data).encode('utf-8')
        data_length = len(json_data)
        
        # Send length first, then data
        self.sender_socket.send(struct.pack('!I', data_length))
        self.sender_socket.send(json_data)
        
    def receive_data(self) -> Dict[str, Any]:
        """Receive data through diode"""
        if not self.receiver_socket:
            raise RuntimeError("Receiver not configured")
            
        conn, addr = self.receiver_socket.accept()
        
        # Receive length first
        length_data = conn.recv(4)
        data_length = struct.unpack('!I', length_data)[0]
        
        # Receive actual data
        json_data = b""
        while len(json_data) < data_length:
            chunk = conn.recv(min(data_length - len(json_data), 4096))
            if not chunk:
                break
            json_data += chunk
            
        conn.close()
        return json.loads(json_data.decode('utf-8'))
