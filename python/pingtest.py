import socket

# Simple ping test

# 10.144.0.31:12345
target_ip = "192.168.68.104"
target_port = 12345

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(b"Hello LOUISE!", (target_ip, target_port))
print("Ping sent!")