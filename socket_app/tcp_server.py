import socket
import threading
from datetime import datetime

HOST = "0.0.0.0"
PORT = 8080
BUFFER_SIZE = 1024


def handle_client(conn, addr):
    print(f"[CONNECTED] {addr[0]}:{addr[1]}")

    try:
        with conn:
            while True:
                data = conn.recv(BUFFER_SIZE)

                if not data:
                    break

                message = data.decode("utf-8", errors="replace").strip()
                print(f"[RECEIVED] {addr[0]}:{addr[1]}: {message}")

                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                response = f"ACK: {timestamp} Received\n"
                conn.sendall(response.encode("utf-8"))

    except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError) as exc:
        print(f"[DISCONNECTED] {addr}: {exc}")

    except OSError as exc:
        print(f"[SOCKET ERROR] {addr}: {exc}")

    finally:
        print(f"[CLOSED] {addr[0]}:{addr[1]}")


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((HOST, PORT))
        server.listen(10)

        print(f"TCP Server listening on {HOST}:{PORT}")

        while True:
            conn, addr = server.accept()
            thread = threading.Thread(
                target=handle_client,
                args=(conn, addr),
                daemon=True,
            )
            thread.start()

    except KeyboardInterrupt:
        print("\nServer shutting down.")

    except OSError as exc:
        print(f"[SERVER ERROR] {exc}")

    finally:
        server.close()


if __name__ == "__main__":
    main()
