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
SYMMETRIC_KEY = None

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
    print("Python Derived Key:", key.hex())
    print("PYTHON SALT: ", salt)
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
    iv = bytes(b"fedcba0987654321")   # 16-byte IV
    
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
    
    print(f"Encrypted file saved as {filename}.enc")





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




def tcp_listener(port=SERVICE_PORT):
    global SYMMETRIC_KEY
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

                # NEED TO CHANGE TO USING DERIVED KEY
                # decryption_key = derive_key(SYMMETRIC_KEY)
                decrypt_file(SYMMETRIC_KEY, f"received_{filename}")
                
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
            print(f"✅ Sent encrypted file '{filename}' to {ip}:{port}")
    except FileNotFoundError:
        print(f"❌ File '{filename}' not found.")
        traceback.print_exc()
    except Exception as e:
        print(f"❌ Error: {e}")
        traceback.print_exc()

def main():
    global SYMMETRIC_KEY

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
            # Display buffered messages before clearing the terminal
            print("Peers:")
            # for message in listener.messages:
                # print(message)  # Print all messages stored in the buffer
            
            # listener.messages = []  # Clear messages after displaying them
            
            peers = list(listener.peers)
            
            for i, (name, peer_ip, peer_port) in enumerate(peers):
                print(f"[{i}] {name} at {peer_ip}:{peer_port}")

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
                                SYMMETRIC_KEY = derive_key(shared_secret) #! TODO: Use this for decryption
                            else:
                                print("No data received from the server.")

                        elif mode == 2:
                            filename = input("Enter the filename to send: ").strip()
                            peer = peers[idx]
                            if not(SYMMETRIC_KEY):
                                print("Error: You must first exchange keys.")
                                continue
                            print("SYMMETRIC KEY: ", SYMMETRIC_KEY)
                            print(f'Sending to peer|: {peer[1]} {peer[2]} {filename}')
                            send_file(peer[1], peer[2], filename, SYMMETRIC_KEY)
                        else:
                            continue 

    except KeyboardInterrupt:
        # shuts down with keyboard interrupt
        print("Shutting down...")
    finally:
        # close all connections
        zeroconf.unregister_service(info)
        zeroconf.close()

if __name__ == "__main__":
    main()
