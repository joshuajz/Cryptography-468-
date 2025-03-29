from zeroconf import Zeroconf, ServiceInfo, ServiceBrowser
import socket
import threading
import time
import os

# define port number, service type, and service name
SERVICE_TYPE = "_ping._tcp.local."
SERVICE_NAME = "PythonPeer._ping._tcp.local."
SERVICE_PORT = 12345

def tcp_listener(port=SERVICE_PORT):
    # sets up tcp listening port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('', port))
    sock.listen(1)
    print(f"Listening for TCP file transfers on port {port}...")

    while True:
        # displays current connection and checks for file transfer
        conn, addr = sock.accept()
        with conn:
            print(f"Connection from {addr}")
            buffer = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buffer += chunk

            if b"\n" in buffer:
                # if file is sent, download it
                filename, filedata = buffer.split(b"\n", 1)
                filename = filename.decode()
                with open(f"received_{filename}", "wb") as f:
                    f.write(filedata)
                print(f"✅ Received file '{filename}' from {addr}")

def get_ip():
    # get IP connections
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        return s.getsockname()[0]
    except:
        return '127.0.0.1'
    finally:
        s.close()

class Listener:
    # listener class for listening ports 
    def __init__(self):
        self.peers = set()

    def add_service(self, zeroconf, type, name):
        # Displays discovered IPs using mDNS through zeroconf
        info = zeroconf.get_service_info(type, name)
        if info:
            ip = socket.inet_ntoa(info.addresses[0])
            self.peers.add((name, ip, info.port))
            print(f"Discovered service: {name} at {ip}:{info.port}")

    def remove_service(self, zeroconf, type, name):
        # removes a discovered IP from display
        print(f"Peer removed: {name}")
        self.peers = {peer for peer in self.peers if peer[0] != name}

def send_file(ip, port, filename):
    try:
        with open(filename, "rb") as f:
            # open file, connect to where you want to send it, send the encoded file name with the data
            # display what file was sent and to which ip and port 
            file_data = f.read()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # connect to the peer you want to send file too. Send file. 
            sock.connect((ip, port))
            sock.sendall(filename.encode() + b"\n" + file_data)
            # close connection after file sent
            sock.close()
            print(f"✅ Sent file '{filename}' to {ip}:{port}")
    except FileNotFoundError:
        # displays error if file not found
        print(f"❌ File '{filename}' not found.")
    except Exception as e:
        print(f"❌ Error: {e}")

def main():

    ip = get_ip()
    zeroconf = Zeroconf()

    info = ServiceInfo(
        SERVICE_TYPE,
        SERVICE_NAME,
        addresses=[socket.inet_aton(ip)],
        port=SERVICE_PORT,
        properties={}
    )
    # register an mDNS service with the info we have defined
    zeroconf.register_service(info)
    print(f"Registered {SERVICE_NAME} on {ip}:{SERVICE_PORT}")
    
    # starts TCP listener 
    threading.Thread(target=tcp_listener, args=(SERVICE_PORT,), daemon=True).start()

    listener = Listener()
    browser = ServiceBrowser(zeroconf, SERVICE_TYPE, listener)

    try:
        while True:
            # displays known peers and gives prompt to send files to specific users.
            print("\nKnown peers:")
            peers = list(listener.peers)
            for i, (name, peer_ip, peer_port) in enumerate(peers):
                print(f"[{i}] {name} at {peer_ip}:{peer_port}")

            if peers:
                # input system for sending files. 
                # select file and user to send file to
                choice = input("Send file to which peer? Enter number or 'n' to skip: ").strip()
                if choice.isdigit():
                    idx = int(choice)
                    if 0 <= idx < len(peers):
                        filename = input("Enter the filename to send: ").strip()
                        peer = peers[idx]
                        print('Sending to peer|:', peer[1], peer[2], filename)
                        send_file(peer[1], peer[2], filename)
            time.sleep(10)
    except KeyboardInterrupt:
        # shuts down with keyboard interrupt
        print("Shutting down...")
    finally:
        # close all connections
        zeroconf.unregister_service(info)
        zeroconf.close()

if __name__ == "__main__":
    main()
