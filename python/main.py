from zeroconf import Zeroconf, ServiceInfo, ServiceBrowser
import socket
import time
import threading

SERVICE_TYPE = "_ping._tcp.local."
SERVICE_NAME = "Python._ping._tcp.local."
SERVICE_PORT = 12345

def udp_listener(port=SERVICE_PORT):
    # Creates a socket to continuously listen for UDP messages
    
    # Create our socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', port))
    
    print(f"Listening for UDP messages on port {port}...")
    
    # Listen for the message, and receive it in 1024 increments
    while True:
        data, addr = sock.recvfrom(1024)
        print(f"Received from {addr}: {data.decode()}")

def get_ip():
    # Finds our local IP
    
    # Creates a socket, that calls 10.255.255.255 which is a placeholder
    # for the local broadcast address allowing usu to find it dynamically

    # We use a try-except-finally to close the socket after returning
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        return s.getsockname()[0]
    except:
        return '127.0.0.1'
    finally:
        s.close()

class Listener:
    # Listens for messages
    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        # Prints the discovered service & IP
        if info:
            ip = socket.inet_ntoa(info.addresses[0])
            print(f"Discovered service: {name} at {ip}:{info.port}")

def main():
    # Finds our IP
    ip = get_ip()
    # Setup zeroconf (library)
    zeroconf = Zeroconf()
    
    # Listener for messages
    threading.Thread(target=udp_listener, args=(SERVICE_PORT,), daemon=True).start()

    # Register our service
    info = ServiceInfo(
        SERVICE_TYPE,
        SERVICE_NAME,
        addresses=[socket.inet_aton(ip)],
        port=SERVICE_PORT,
        properties={}
    )

    zeroconf.register_service(info)
    print(f"Registered {SERVICE_NAME} on {ip}:{SERVICE_PORT}")

    # Look for peers
    browser = ServiceBrowser(zeroconf, SERVICE_TYPE, Listener())

    # Keep the program running
    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        print("Shutting down...")
        zeroconf.unregister_service(info)
        zeroconf.close()

if __name__ == "__main__":
    main()
