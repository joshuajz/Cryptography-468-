import socket
import threading
import os
from zeroconf import Zeroconf, ServiceInfo, ServiceBrowser

# Define port number, service type, and service name
SERVICE_TYPE = "_ping._tcp.local."
SERVICE_PORT = 12345
MESSAGE_BUFFER = []
SERVICE_NAME = "PythonPeer._ping._tcp.local."

def tcp_listener(port=SERVICE_PORT):
    # Sets up TCP listening port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('', port))
    sock.listen(1)
    MESSAGE_BUFFER.append(f"Listening for TCP file transfers on port {port}...")

    while True:
        # Displays current connection and checks for file transfer
        conn, addr = sock.accept()
        with conn:
            MESSAGE_BUFFER.append(f"Connection from {addr}")
            buffer = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buffer += chunk

            if b"\n" in buffer:
                # If file is sent, download it
                filename, filedata = buffer.split(b"\n", 1)
                filename = filename.decode()
                with open(f"received_{filename}", "wb") as f:
                    f.write(filedata)
                MESSAGE_BUFFER.append(f"✅ Received file '{filename}' from {addr}")

def get_ip():
    # Get IP connections
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        return s.getsockname()[0]
    except:
        return '127.0.0.1'
    finally:
        s.close()

class Listener:
    # Listener class for listening ports
    def __init__(self):
        self.peers = set()
        self.messages = []  # List to store messages for displaying

    def add_service(self, zeroconf, type, name):
        # Displays discovered IPs using mDNS through Zeroconf
        info = zeroconf.get_service_info(type, name)
        if info:
            ip = socket.inet_ntoa(info.addresses[0])
            self.peers.add((name, ip, info.port))
            self.messages.append(f"Discovered service: {name} at {ip}:{info.port}")

    def remove_service(self, zeroconf, type, name):
        # Removes a discovered IP from display
        self.messages.append(f"Peer removed: {name}")
        self.peers = {peer for peer in self.peers if peer[0] != name}

def send_file(ip, port, filename):
    try:
        with open(filename, "rb") as f:
            # Open file, connect to where you want to send it, send the encoded file name with the data
            # Display what file was sent and to which IP and port 
            file_data = f.read()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Connect to the peer you want to send file to. Send file. 
            sock.connect((ip, port))
            sock.sendall(filename.encode() + b"\n" + file_data)
            # Close connection after file sent
            sock.close()
            MESSAGE_BUFFER.append(f"✅ Sent file '{filename}' to {ip}:{port}")
    except FileNotFoundError:
        # Displays error if file not found
        MESSAGE_BUFFER.append(f"❌ File '{filename}' not found.")
    except Exception as e:
        MESSAGE_BUFFER.append(f"❌ Error: {e}")

def main():
    ip = get_ip()
    zeroconf = Zeroconf()

    # Register the service with a unique service name
    info = ServiceInfo(
        SERVICE_TYPE,
        SERVICE_NAME,
        addresses=[socket.inet_aton(ip)],
        port=SERVICE_PORT,
        properties={}
    )
    # Register an mDNS service with the info we have defined
    zeroconf.register_service(info)
    MESSAGE_BUFFER.append(f"Registered {SERVICE_NAME} on {ip}:{SERVICE_PORT}")

    # Starts TCP listener
    threading.Thread(target=tcp_listener, args=(SERVICE_PORT,), daemon=True).start()

    listener = Listener()
    browser = ServiceBrowser(zeroconf, SERVICE_TYPE, listener)

    try:
        while True:
            # Display buffered messages before clearing the terminal
            os.system('cls' if os.name == 'nt' else 'clear')
            print("Peers:")
            peers = list(listener.peers)

            for i, (name, peer_ip, peer_port) in enumerate(peers):
                print(f"[{i}] {name} at {peer_ip}:{peer_port}")

            print("\nLogs:")
            for message in MESSAGE_BUFFER:
                print(message)  # Print all messages stored in the buffer
            print('\n')

            if peers:
                # Input system for sending files. 
                # Select file and user to send file to
                choice = input("Send file to which peer? Enter number or 'r' to refresh: ").strip()
                if choice.isdigit():
                    idx = int(choice)
                    if 0 <= idx < len(peers):
                        filename = input("Enter the filename to send: ").strip()
                        peer = peers[idx]
                        MESSAGE_BUFFER.append(f'Sending to peer: {peer[1]} {peer[2]} {filename}')
                        send_file(peer[1], peer[2], filename)

    except KeyboardInterrupt:
        # Shuts down with keyboard interrupt
        print("Shutting down...")
    finally:
        # Close all connections
        zeroconf.unregister_service(info)
        zeroconf.close()

if __name__ == "__main__":
    main()
