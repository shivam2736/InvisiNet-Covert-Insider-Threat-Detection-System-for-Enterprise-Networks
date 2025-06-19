import socket

# One-way socket sender (data diode simulation)
def data_diode_send(data, target_ip, target_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(data.encode(), (target_ip, target_port))
    s.close()

# Receiver (only accepts data, never sends)
def data_diode_receive(bind_ip, bind_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((bind_ip, bind_port))
    print(f"Listening on {bind_ip}:{bind_port} (one-way)")

    while True:
        data, addr = s.recvfrom(1024)
        print(f"Received (one-way): {data.decode()} from {addr}")

if __name__ == "__main__":
    import threading

    # Start receiver in a thread
    recv_thread = threading.Thread(target=data_diode_receive, args=("0.0.0.0", 9999), daemon=True)
    recv_thread.start()

    # Simulate sending alerts covertly (one-way)
    import time
    while True:
        data_diode_send("Covert alert: suspicious activity detected", "127.0.0.1", 9999)
        time.sleep(10)
