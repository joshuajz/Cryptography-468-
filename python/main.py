# libraries for network connections
from zeroconf import Zeroconf, ServiceInfo, ServiceBrowser
import socket
import threading
import json
import time
import os
import traceback

# libraries for cryptography specifically
import random
import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Hash import HMAC, SHA256
from hashlib import sha256 as sh
from Crypto.Random.random import getrandbits
from hashlib import sha256
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.number import getPrime, inverse

# define port number, service type, and service name
SERVICE_TYPE = "_ping._tcp.local."
SERVICE_NAME = "PythonPeer._ping._tcp.local."
SERVICE_PORT = 12345

# Keys
KEYS = {}

# Shared Files
SHARED_FILES = []

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

def compute_shared_secret(peer_public_key, private_key, p):
    shared_secret = pow(peer_public_key, private_key, p)
    shared_secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')

    return shared_secret_bytes

def derive_key(shared_secret):
    salt = bytes(16)  # 16-byte salt (same as Go)


    key = hashlib.pbkdf2_hmac('sha256', shared_secret, salt, 100000, dklen=32)  # Derive 32-byte key

    print("PYTHON SHARED SECRET: ", shared_secret.hex())
    print("PYTHON DERIVED KEY: ", key.hex())

    return key

def calculate_hmac(key, data):
    # Calculate HMAC using SHA256
    print("Python HMAC Data Length:", len(data))
    print("Python Key Length:", len(key))
    hmac_obj = hmac.new(key, data, SHA256)
    return hmac_obj.digest()

def encrypt_file(key, filename):
    # CHANGE TO FIXED OR COMMUNICATED
    salt = bytes(b"1234567890abcdef")  # 16-byte salt
    iv = bytes(b"fedcba098b765432")   # 16-byte IV
    
    # Read the file to encrypt
    with open(filename, 'rb') as f:
        plaintext = f.read()
    
    # Encrypt the file using AES CBC
    cipher = AES.new(key, AES.MODE_CBC, iv) 
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    salt_iv_ciphertext = salt + iv + ciphertext
    
    # Generate HMAC of the ciphertext
    hmac_tag = calculate_hmac(key, salt_iv_ciphertext)
    
    # Write encrypted file with salt, IV, HMAC, and ciphertext
    with open(f'{filename}.enc', 'wb') as enc_file:
        enc_file.write(salt_iv_ciphertext)
        enc_file.write(hmac_tag)
    
    print(f"🔒 Encrypted File As {filename}.enc")

def decrypt_file(sym_key, filename):

    print("Decrypting the file")
    with open(filename, 'rb') as f:
        data = f.read()
    
    SALT_SIZE = 16
    IV_SIZE = 16
    HMAC_SIZE = 32

    salt = data[:SALT_SIZE]  # Extract salt
    iv = data[SALT_SIZE:SALT_SIZE + IV_SIZE]  # Extract IV
    ciphertext = data[SALT_SIZE + IV_SIZE:-HMAC_SIZE]  # Extract ciphertext
    hmac_tag = data[-HMAC_SIZE:]  # Extract hmac
    salt_iv_ciphertext = salt + iv + ciphertext



    # Verify HMAC tag
    if hmac_tag != calculate_hmac(sym_key, salt_iv_ciphertext):


        check = calculate_hmac(sym_key, salt_iv_ciphertext)

        print("HMAC verification failed!")
        return
    else:
        print("HMAC verification successful")
    
    # Decrypt the file using AES CBC mode
    print("Decrypting file")
    cipher = AES.new(sym_key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    
    # Write decrypted file
    with open(f'{filename[:-4]}.dec', 'wb') as dec_file:
        dec_file.write(plaintext)
    
    print(f"Decrypted file saved as {filename[:-4]}.dec")

def handle_client_connection(connection, address):
    print(f"Connection from {address[0]}:{address[1]}")
    
    buffer = b""
    print('buffer:', buffer)
    while True:
        chunk = connection.recv(4096)

        if not chunk:
            break # connection probably closed
            
        buffer += chunk

        # Checking if the message is a key
        try:
         
            message = json.loads(buffer)
      
            if "public_key" in message:
                public_key = message["public_key"]
                print(f"🔑 Received a public key from {address[0]}:{address[1]}: {message['public_key']}")

                # Store the symmetric key
                p, g, private_key, public_key = generate_dh_keypair()
                print('public key:', message["public_key"])
                shared_secret = compute_shared_secret(int(message['public_key']), private_key, p)
                # shared_secret = compute_shared_secret(private_key, message['public_key'], p)
                derived_key = derive_key(shared_secret)
                KEYS[f"{address[0]}"] = derived_key

                # Send our public key back to the client (DH exchange)
                public_key_hex = hex(public_key)  # Convert the public key to a hex string
                connection.sendall(json.dumps({'public_key': public_key_hex}).encode())
                print("📨 Sent Public Key to client:", public_key)
                return
            elif "files" in message:
                print('message', message)
        except:
            if b"\n" in buffer:
                filename, filedata = buffer.split(b"\n", 1)
                filename = filename.decode(errors="ignore")  # Handle any invalid UTF-8 characters

                # Save the file to disk
                with open(f"received_{filename}", "wb") as f:
                    f.write(filedata)

                # Check if a symmetric key is available for decryption
                if address[0] in KEYS:
                    # In a real scenario, you'd derive the symmetric key based on the public key
                    sym_key = KEYS[address[0]]  # For now, just using public_key directly as a placeholder
                    print(f"🔓 Decrypting file {filename} using symmetric key.")
                    decrypt_file(sym_key, f"received_{filename}")
                else:
                    print(f"❌🛡️ No symmetric key found for {address[0]}, unable to decrypt the file.")

def tcp_listener(port=SERVICE_PORT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('', port))
    sock.listen(5)
    print(f"Listening on port {port} for incoming connections...")

    while True:
        conn, addr = sock.accept()
        print("Calling handle connection")
        handle_client_connection(conn, addr)
        conn.close()

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

def send_file(ip, port, filename, symmetric_key):
    try:
          with open(filename, "rb") as f:
            file_data = f.read()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, port))

            # Encrypt the file before sending it
            encrypt_file(symmetric_key, filename)

            # Read the encrypted file and send it
            with open(f"{filename}.enc", "rb") as enc_file:
                enc_file_data = enc_file.read()
                sock.sendall(filename.encode() + b"\n" + enc_file_data)
            sock.close()
            print(f"✅📨 Sent Encrypted File '{filename}' to {ip}:{port}")
    except FileNotFoundError:
        print(f"❌ File '{filename}' not found.")
        traceback.print_exc()
    except Exception as e:
        print(f"❌ Error: {e}")
        traceback.print_exc()

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
    print(f"👍 Registered {SERVICE_NAME} on {ip}:{SERVICE_PORT}")

    # starts TCP listener 
    threading.Thread(target=tcp_listener, args=(SERVICE_PORT,), daemon=True).start()

    listener = Listener()
    browser = ServiceBrowser(zeroconf, SERVICE_TYPE, listener)

    try:
        while True:
            menu(listener)
    except KeyboardInterrupt:
        # shuts down with keyboard interrupt
        print("Shutting down...")
    finally:
        # close all connections
        zeroconf.unregister_service(info)
        zeroconf.close()

def integer_input(text):
    while True:
        try:
            menuItem = int(input(text))
            return menuItem
        except ValueError:
            print("❌ Enter an integer.")

def sha256_hash(filename):
    with open(filename, 'rb', buffering=0) as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()

def menu(listener: Listener):
    def print_peers():
        peers = list(listener.peers)
        for i, (name, peer_ip, peer_port) in enumerate(peers):
            print(f"[{i}] {name} at {peer_ip}:{peer_port}")
        return peers

    print("\nMenu:")
    print("0. Peer List")
    print("1. Key Verification/Transfer")
    print("2. Send a File")
    print("3. Add File to Share")
    print("4. Display Shared Files")
    print("5. Request Shared File List")
    print("6. Request a Shared File")
    menuItem = integer_input("Select an Option: ")

    match menuItem:
        case 0: # 0. Peer List
            print_peers()
        case 1: # 1. Key Verification
            peers = print_peers()
            peer_id = integer_input("Select a Peer for key verification: ")
            
            peer_ip, peer_port = peers[peer_id][1], peers[peer_id][2]  # Get the chosen peer's IP and port
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((peer_ip, peer_port))  # Connect to the peer
            p, g, private_key, public_key = generate_dh_keypair()

            public_key_hex = hex(public_key)  # Convert the public key to a hex string
            sock.sendall(json.dumps({'public_key': public_key_hex}).encode())

            print("📨 Python Sent Public Key:", public_key)

            server_data = sock.recv(4096)

            if server_data:
               
                server_data = json.loads(server_data.decode('utf-8'))  # Decode properly with UTF-8
                server_public_key = int(server_data['public_key'])
                shared_secret = compute_shared_secret(server_public_key, private_key, p)

                key = derive_key(shared_secret)
                print("🔑 Key Derived:", key)
                KEYS[f"{peer_ip}"] = key
            else:
                print("❌ No data returned from server for verification of key.")
        case 2: # 2. Send a File
            peers = print_peers()
            peer_id = integer_input("Select a Peer for file transfer: ")

            peer_ip, peer_port = peers[peer_id][1], peers[peer_id][2]  # Get the chosen peer's IP and port
            peer = peers[peer_id]

            if not(f"{peer_ip}" in KEYS):
                print("❌ You must exchange keys before file transfer (option 1)")

            filename = input("Enter the filename to send: ").strip()
            send_file(peer[1], peer[2], filename, KEYS[f"{peer_ip}"])
        case 3: # 3. Add a file to share
            filename = input("Enter the filename to share: ").strip()
            if os.path.isfile(filename):
                sha256 = sha256_hash(filename)
                SHARED_FILES.append([filename, sha256])
                print(f"🔗 Added {filename} ({sha256}) to the Shared List.")
            else:
                print(f"❌ {filename} does not exist.")
        case 4: #4. Display shared files
            print("Shared Files:")
            for f in SHARED_FILES:
                print(f"{f[0]}: {f[1]}")
        case 5: # 5. Request Shared File List
            peers = print_peers()
            peer_id = integer_input("Select a Peer to Request  File List: ")
            
            peer_ip, peer_port = peers[peer_id][1], peers[peer_id][2]  # Get the chosen peer's IP and port

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((peer_ip, peer_port))  # Connect to the peer
            sock.sendall(json.dumps({'request': 'file_list'}).encode())

            data = sock.recv(4096)  # Adjust buffer size if necessary
            if data:
                # Decode the JSON response
                response = json.loads(data.decode('utf-8'))
                print("Received response:", response)
            else:
                print("No response received from the server.")
if __name__ == "__main__":
    main()
