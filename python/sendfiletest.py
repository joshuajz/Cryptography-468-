import socket

def send_file(ip, port, filename):
    try:
        with open(filename, "rb") as f:
            file_data = f.read()
            message = b"FILE:" + filename.encode() + b"\n" + file_data
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(message, (ip, port))
            print(f"🐧🐧🐧🐧 Sent file '{filename}' to {ip}:{port}")
    
    except FileNotFoundError:
        print(f"NO: File '{filename}' not found.")
    
    except Exception as e:
        print(f"NO: Error: {e}")

if __name__ == "__main__":
    ip = "192.168.68.103"
    port = 12345

    send_file(ip, port, "file.txt")
