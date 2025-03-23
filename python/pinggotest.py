import socket

target_ip = "10.216.23.252"   # Replace with the Go machine's IP
target_port = 12345

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
message = b"Ping from Python!!!!!!! WOOO"
sock.sendto(message, (target_ip, target_port))

print("Sent to GO")
