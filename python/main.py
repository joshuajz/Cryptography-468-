
# libraries for network connections
from zeroconf import Zeroconf, ServiceInfo, ServiceBrowser
import socket
import threading
import time
import os

# libraries for cryptography specifically 
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Hash import HMAC, SHA256
from hashlib import sha256
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt

# DHKE Parameters (using some small values for simplicity)
p = 23  # Prime modulus (using a small prime for illustration)
g = 5   # Generator (primitive root mod p)
private_key = random.randint(2, p - 2)  # Private key for this node
public_key = pow(g, private_key, p)  # Public key (g^a mod p)

# define port number, service type, and service name
SERVICE_TYPE = "_ping._tcp.local."
SERVICE_NAME = "PythonPeer._ping._tcp.local."
SERVICE_PORT = 12345
MESSAGE_BUFFER = []

def generate_shared_secret(peer_public_key):
    # Compute the shared secret (g^ab mod p) where `peer_public_key` is the peer's public key
    shared_secret = pow(peer_public_key, private_key, p)
    return shared_secret

def derive_key(shared_secret):
    # Derive a key using the shared secret and scrypt (instead of PBKDF2)
    salt = get_random_bytes(16)  # Random salt
    key = scrypt(str(shared_secret).encode(), salt, dklen=32, N=2**14, r=8, p=1)
    return key

def calculate_hmac(key, data):
    # Calculate HMAC using SHA256
    hmac_obj = HMAC.new(key, data, SHA256)
    return hmac_obj.digest()

def encrypt_file(key, filename):
    salt = get_random_bytes(16)  # Generate a random salt
    iv = get_random_bytes(AES.block_size)  # Generate a random IV
    key = derive_key(key)  # Derive the encryption key from shared secret
    
    # Read the file to encrypt
    with open(filename, 'rb') as f:
        plaintext = f.read()
    
    # Encrypt the file using AES CBC
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    
    # Generate HMAC of the ciphertext
    hmac_tag = calculate_hmac(key, ciphertext)
    
    # Write encrypted file with salt, IV, HMAC, and ciphertext
    with open(f'{filename}.enc', 'wb') as enc_file:
        enc_file.write(salt)
        enc_file.write(iv)
        enc_file.write(hmac_tag)
        enc_file.write(ciphertext)
    
    print(f"Encrypted file saved as {filename}.enc")

def decrypt_file(key, filename):
    with open(filename, 'rb') as f:
        data = f.read()
    
    salt = data[:16]  # Extract salt
    iv = data[16:32]  # Extract IV
    hmac_tag = data[32:64]  # Extract HMAC tag
    ciphertext = data[64:]  # Extract ciphertext
    
    # Derive key from shared secret
    key = derive_key(key)
    
    # Verify HMAC tag
    if hmac_tag != calculate_hmac(key, ciphertext):
        print("HMAC verification failed!")
        return
    
    # Decrypt the file using AES CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    
    # Write decrypted file
    with open(f'{filename[:-4]}.dec', 'wb') as dec_file:
        dec_file.write(plaintext)
    
    print(f"Decrypted file saved as {filename[:-4]}.dec")



def tcp_listener(port=SERVICE_PORT):
    # sets up tcp listening port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('', port))
    sock.listen(1)
    MESSAGE_BUFFER.append(f"Listening for TCP file transfers on port {port}...")

    while True:
        # displays current connection and checks for file transfer
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
                # if file is sent, download it
                filename, filedata = buffer.split(b"\n", 1)
                filename = filename.decode()
                with open(f"received_{filename}", "wb") as f:
                    f.write(filedata)

                # Here we assume the shared secret was already derived using DHKE
                shared_secret = int(input("Enter shared secret (received from peer): "))  # Example input
                decryption_key = derive_key(shared_secret)
                decrypt_file(decryption_key, f"received_{filename}.enc")
                
                MESSAGE_BUFFER.append(f"✅ Received file '{filename}' from {addr}")

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
        self.messages = []  # List to store messages for displaying

    def add_service(self, zeroconf, service_type, service_name):
        # Adds the discovered service to the peer list
        info = zeroconf.get_service_info(service_type, service_name)
        if info:
            ip = socket.inet_ntoa(info.addresses[0])
            self.peers.add((service_name, ip, info.port))
            self.messages.append(f"Discovered service: {service_name} at {ip}:{info.port}")

    def remove_service(self, zeroconf, service_type, service_name):
        # Removes a discovered IP from the list
        self.messages.append(f"Peer removed: {service_name}")
        self.peers = {peer for peer in self.peers if peer[0] != service_name}

def send_file(ip, port, filename):
    try:
          with open(filename, "rb") as f:
            file_data = f.read()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, port))

            # Derive a shared secret (for illustration, we assume it's pre-calculated or exchanged)
            shared_secret = int(input("Enter shared secret: "))  # Example input from DHKE

            encryption_key = derive_key(shared_secret)

            # Encrypt the file before sending it
            encrypt_file(encryption_key, filename)

            # Read the encrypted file and send it
            with open(f"{filename}.enc", "rb") as enc_file:
                enc_file_data = enc_file.read()
                sock.sendall(filename.encode() + b"\n" + enc_file_data)
            sock.close()
            MESSAGE_BUFFER.append(f"✅ Sent encrypted file '{filename}' to {ip}:{port}")
    except FileNotFoundError:
        MESSAGE_BUFFER.append(f"❌ File '{filename}' not found.")
    except Exception as e:
        MESSAGE_BUFFER.append(f"❌ Error: {e}")

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
    MESSAGE_BUFFER.append(f"Registered {SERVICE_NAME} on {ip}:{SERVICE_PORT}")
    
    # starts TCP listener 
    threading.Thread(target=tcp_listener, args=(SERVICE_PORT,), daemon=True).start()

    listener = Listener()
    browser = ServiceBrowser(zeroconf, SERVICE_TYPE, listener)

    try:
        while True:
            # Display buffered messages before clearing the terminal
            os.system('cls' if os.name == 'nt' else 'clear')
            print("Peers:")
            # for message in listener.messages:
                # print(message)  # Print all messages stored in the buffer
            
            # listener.messages = []  # Clear messages after displaying them
            
            peers = list(listener.peers)
            
            for i, (name, peer_ip, peer_port) in enumerate(peers):
                print(f"[{i}] {name} at {peer_ip}:{peer_port}")

            print("\nLogs:")

            for message in MESSAGE_BUFFER:
                print(message)  # Print all messages stored in the buffer
            print('\n')

            if peers:
                # input system for sending files. 
                # select file and user to send file to
                choice = input("Send file to which peer? Enter number or 'r' to refresh: ").strip()
                if choice.isdigit():
                    idx = int(choice)
                    if 0 <= idx < len(peers):
                        filename = input("Enter the filename to send: ").strip()
                        peer = peers[idx]
                        MESSAGE_BUFFER.append(f'Sending to peer|: {peer[1]} {peer[2]} {filename}')
                        send_file(peer[1], peer[2], filename)
            
            
    except KeyboardInterrupt:
        # shuts down with keyboard interrupt
        print("Shutting down...")
    finally:
        # close all connections
        zeroconf.unregister_service(info)
        zeroconf.close()

if __name__ == "__main__":
    main()
