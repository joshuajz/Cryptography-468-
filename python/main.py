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
from Crypto.Util.number import getPrime, inverse
import nacl.bindings  # Using X25519 for DHKE


# define port number, service type, and service name
SERVICE_TYPE = "_ping._tcp.local."
SERVICE_NAME = "PythonPeer._ping._tcp.local."
SERVICE_PORT = 12345

# Keys
KEYS = {}

# Shared Files
SHARED_FILES = []



def generate_ephemeral_keypair():
    # Generate a new ephemeral DH key pair using X25519
    priv_key = os.urandom(32)  # Generate random private key
    pub_key = nacl.bindings.crypto_scalarmult_base(priv_key)  # Compute public key
    return priv_key, pub_key

def derive_shared_secret(my_priv_key, peer_pub_key):
    # Compute the shared secret using X25519
    return nacl.bindings.crypto_scalarmult(my_priv_key, peer_pub_key)


def calculate_hmac(key, data):
    # Calculate HMAC using SHA256
    print("Python HMAC Data Length:", len(data))
    print("Python Key Length:", len(key))
    hmac_obj = hmac.new(key, data, SHA256)
    return hmac_obj.digest()


def encrypt_file(key, filename):
    # predefined salt and IV not as secure but is what we managed to implement 
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
    print("DECRYPT FILE SYMMETRIC KEY:", sym_key, "/n")
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

    print("SALTIVCIPHER: ", salt_iv_ciphertext.hex())



    # Verify HMAC tag
    if hmac_tag != calculate_hmac(sym_key, salt_iv_ciphertext):

        print("DATA RETREIVED FROM GO: ", data.hex())
        print("HMAC TAG: ", hmac_tag.hex())
        check = calculate_hmac(sym_key, salt_iv_ciphertext)
        print(" Python Calculated HMAC: ", check.hex())
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
    buffer = b""

    while True:
        chunk = connection.recv(4096)
        if not chunk:
            break  # connection probably closed

        buffer += chunk

        # Try parsing multiple JSON objects
        try:
            stream = buffer.decode("utf-8")
            decoder = json.JSONDecoder()
            pos = 0
            while pos < len(stream):
                try:
                    obj, idx = decoder.raw_decode(stream[pos:])
                    pos += idx
                    if isinstance(obj, dict) and "public_key" in obj:

                        public_key_hex = obj["public_key"]
                        print(f"🔑 Received a public key from {address[0]}:{address[1]}: {public_key_hex}")
                        print("RECEIVED PUBLIC KEY IN BYTES: ", bytes.fromhex(public_key_hex))
                        print("RAW BUFFER: ", buffer)

                        # Generate our key pair
                        private_key, public_key = generate_ephemeral_keypair()
                        print("PUBLIC KEY HEX: ", public_key_hex)
                        public_key_bytes = bytes.fromhex(public_key_hex)
                        print("Received public key (bytes):", public_key_bytes)


                        shared_secret = derive_shared_secret(private_key, bytes.fromhex(public_key_hex))
                        print(f"Derived Shared Secret: {shared_secret.hex()}")

                        derived_key = hashlib.sha256(shared_secret).digest()
                        print(f"Symmetric Key: {derived_key.hex()}")
                        KEYS[f"{address[0]}"] = derived_key

                        # Send our public key
                        response = json.dumps({"public_key": public_key.hex()}).encode()
                        connection.sendall(response)
                        print("📨 Sent Public Key to client:", public_key.hex())

                        return
                except json.JSONDecodeError:
                    # Couldn't decode full object yet — wait for more data
                    break
        except UnicodeDecodeError:
            # Not a JSON message — fall back to file handling
            print("Unicode decode failed — maybe this is a file?")
            if b"\n" in buffer:
                filename, filedata = buffer.split(b"\n", 1)
                filename = filename.decode(errors="ignore")

                with open(f"received_{filename}", "wb") as f:
                    f.write(filedata)

                if address[0] in KEYS:
                    print(f"🔓 Decrypting file {filename} using symmetric key.")
                    decrypt_file(KEYS[address[0]], f"received_{filename}")
                else:
                    print(f"❌🛡️ No symmetric key found for {address[0]}, unable to decrypt the file.")


def tcp_listener(port=SERVICE_PORT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('', port))
    sock.listen(5)
    print(f"Listening on port {port} for incoming connections...")

    while True:
        conn, addr = sock.accept()
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
    print("5. Request a Shared File")
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
            private_key, public_key = generate_ephemeral_keypair()

            public_key_hex = public_key.hex()  # Convert the public key to a hex string
            sock.sendall(json.dumps({'public_key': public_key_hex}).encode())

            print("📨 Python Sent Public Key:", public_key)

            server_data = sock.recv(4096)

            if server_data:
                print('✉️ Other Server Provided Data:', server_data)
                server_data = json.loads(server_data.decode('utf-8'))  # Decode properly with UTF-8
                server_public_key = server_data['public_key']
                shared_secret = derive_shared_secret(private_key,bytes.fromhex(server_public_key) )                
                print("SHARED SECRET: ", shared_secret.hex())
                key = hashlib.sha256(shared_secret).digest()
                print(f"Symmetric Key: {key.hex()}")
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
                SHARED_FILES.append(filename)
                print(f"🔗 Added {filename} to the Shared List.")
            else:
                print(f"❌ {filename} does not exist.")
        case 4: #4. Display shared files
            print("Shared Files:")
            for f in SHARED_FILES:
                print(f"- {f}")

if __name__ == "__main__":
    main()
