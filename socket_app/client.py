import socket

SERVER_IP = "127.0.0.1"
SERVER_PORT = 5000

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

client.connect((SERVER_IP, SERVER_PORT))

message = "Hello from TCP client"

client.sendall(message.encode())

response = client.recv(1024)

print("Server:", response.decode())

client.close()
