import socket 
HOST = "0.0.0.0"
PORT = 5000

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server.bind((HOST, PORT))
server.listen(5)

print(f"TCP Server listening on port {PORT}...")

while True:
    conn, addr = server.accept()

    print(f"Connection from {addr}")

    data = conn.recv(1024)

    if data:
        message = data.decode()
        print(f"Received: {message}")

        conn.sendall(b"ACK: Message received")

    conn.close()
