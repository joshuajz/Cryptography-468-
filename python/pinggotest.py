import socket


def simple_send(ip):
    target_port = 12346

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    message = b"Ping from Python!!!!!!! WOOO"
    sock.sendto(message, (ip, target_port))

    print("Sent to GO")

def file_send(filename, server_ip, server_port):
    # Open the file to send
    try:
        with open(filename, 'rb') as f:
            filedata = f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            # Connect to the server
            s.connect((server_ip, server_port))
            print(f"Connected to {server_ip} on port {server_port}")

            # Send the filename (including a newline separator)
            s.sendall(f"{filename}\n".encode())

            # Send the file data
            s.sendall(filedata)
            print(f"File '{filename}' sent successfully.")
        except Exception as e:
            print(f"Error sending file: {e}")

# simple_send('192.168.56.1')
file_send("file.txt", "192.168.68.104", 12345)