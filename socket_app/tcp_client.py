import argparse
import socket
import sys


def main():
    parser = argparse.ArgumentParser(description="TCP client for SDN firewall testing")
    parser.add_argument("--server-ip", default="10.0.0.3", help="Server IP address")
    parser.add_argument("--port", type=int, default=8080, help="Server port")
    parser.add_argument("--messages", type=int, default=1, help="Number of messages")
    parser.add_argument(
        "--mode",
        choices=["normal", "forbidden"],
        default="normal",
        help="Traffic mode",
    )
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("Port must be between 1 and 65535")

    if args.messages < 1:
        parser.error("--messages must be at least 1")

    if args.mode == "forbidden":
        print("[FORBIDDEN MODE] Testing traffic that the firewall should block.")

    for i in range(args.messages):
        message = f"MSG: {args.mode} test message {i + 1}"

        try:
            with socket.create_connection(
                (args.server_ip, args.port), timeout=3.0
            ) as sock:
                sock.settimeout(3.0)
                sock.sendall((message + "\n").encode("utf-8"))
                response = sock.recv(1024)

                if response:
                    print(f"[ACK] {response.decode('utf-8', errors='replace').strip()}")
                else:
                    print("[ERROR] Server closed the connection without a response.")

        except socket.timeout:
            print(
                f"[FIREWALL BLOCK] Connection timed out to "
                f"{args.server_ip}:{args.port}"
            )
        except ConnectionRefusedError:
            print(
                f"[CONNECTION REFUSED] {args.server_ip}:{args.port} "
                "is reachable, but the connection was refused."
            )
        except OSError as exc:
            print(f"[CONNECTION ERROR] {exc}")


if __name__ == "__main__":
    main()
