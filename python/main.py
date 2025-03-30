# libraries for network connections
from zeroconf import Zeroconf, ServiceInfo, ServiceBrowser
import socket
import threading
import json
import time
import os

# libraries for cryptography specifically 
import random
import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Hash import HMAC, SHA256
from Crypto.Random.random import getrandbits
from hashlib import sha256
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.number import getPrime, inverse

def generate_dh_keypair():
    # Standard 2048-bit safe prime for DHKE (can be changed to a larger prime if needed)
    p = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
            "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16)
    g = 2
    private_key = getrandbits(2048) % p
    public_key = pow(g, private_key, p)
    return p, g, private_key, public_key

# define port number, service type, and service name
SERVICE_TYPE = "_ping._tcp.local."
SERVICE_NAME = "PythonPeer._ping._tcp.local."
SERVICE_PORT = 12345
MESSAGE_BUFFER = []

def compute_shared_secret(peer_public_key, private_key, p):
    return pow(peer_public_key, private_key, p)

def derive_key(shared_secret):
    # Derive a key using the shared secret and scrypt (instead of PBKDF2)
    salt = get_random_bytes(16)  # Random salt
    key = scrypt(str(shared_secret).encode(), salt, 2**14, 8, 1, 32)
    return key, salt

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
    # Listener class for managing service state changes
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
        # Removes a discovered service from the list
        self.messages.append(f"Peer removed: {service_name}")
        self.peers = {peer for peer in self.peers if peer[0] != service_name}

    def update_service(self, zeroconf, service_type, service_name):
        # Updates the service state if it changes
        # Here we can simply call add_service again (or perform a different action)
        self.add_service(zeroconf, service_type, service_name)

def send_file(ip, port, filename):
    try:
          with open(filename, "rb") as f:
            file_data = f.read()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, port))

            # Derive a shared secret 
            shared_secret = int(input("Enter shared secret: "))  # do we need this? they should send shared keys rather than type them in

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
                choice = input("Select a peer: ").strip()
                if choice.isdigit():
                    idx = int(choice)
                    if 0 <= idx < len(peers):

                        mode = int(input("1. Exchange Keys | 2. Send File: "))

                        if mode == 1:
                            peer_ip, peer_port = peers[idx][1], peers[idx][2]  # Get the chosen peer's IP and port
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.connect((peer_ip, peer_port))  # <-- Connect to the peer
                            p, g, private_key, public_key = generate_dh_keypair()

                            print('public_key (hex):', hex(public_key))
                            public_key_hex = hex(public_key)  # Convert the public key to a hex string
                            sock.sendall(json.dumps({'public_key': public_key_hex}).encode())


                            print("Python is sending their public key:", public_key)
                             # Send DH parameters to peer
                            # sock.sendall(str(public_key).encode())
                            # print(json.dumps({'p': p, 'g': g, 'public_key': public_key}).encode())
                            server_data = sock.recv(4096)

                            if server_data:
                                print('server data:', server_data)
                                server_data = json.loads(server_data.decode('utf-8'))  # Decode properly with UTF-8
                                server_public_key = int(server_data['public_key'])
                                shared_secret = compute_shared_secret(server_public_key, private_key, p)
                                symmetric_key = derive_key(shared_secret)
                            else:
                                print("No data received from the server.")

                        elif mode == 2:
                            print("send file")
                        else:
                            break 

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
