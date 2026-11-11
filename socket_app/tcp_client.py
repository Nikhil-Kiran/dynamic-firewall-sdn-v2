import argparse
import socket
import sys
import time


def main():
    parser = argparse.ArgumentParser(description="TCP client for SDN firewall testing")
    parser.add_argument("--server-ip", default="10.0.0.3", help="Server IP address")
    parser.add_argument("--port", type=int, default=8080, help="Server port")
    parser.add_argument("--messages", type=int, default=1, help="Number of messages")
    parser.add_argument(
        "--mode",
        choices=["normal", "forbidden", "rapid_scan", "flood"],
        default="normal",
        help="Traffic mode",
    )
    parser.add_argument("--count", type=int, default=30,
                        help="Number of attempts in flood mode")
    parser.add_argument("--interval", type=float, default=0.02,
                        help="Delay between flood attempts in seconds")
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("Port must be between 1 and 65535")

    if args.messages < 1:
        parser.error("--messages must be at least 1")

    if args.count < 1 or args.interval < 0:
        parser.error("--count must be positive and --interval cannot be negative")

    if args.mode == "rapid_scan":
        ports = [21, 22, 23, 80, 443, 4444, 5555, 6667, 8080, 9999]
        print(f"[RAPID SCAN] Testing {len(ports)} TCP ports on {args.server_ip}")
        for port in ports:
            try:
                with socket.create_connection((args.server_ip, port), timeout=0.4):
                    print(f"[SCAN] Port {port}: open")
            except (socket.timeout, ConnectionRefusedError, OSError):
                print(f"[SCAN] Port {port}: closed/filtered")
        print("[RAPID SCAN] Finished. Check the controller for [AUTO BLOCK].")
        return

    if args.mode == "flood":
        print(f"[FLOOD TEST] Sending {args.count} rapid TCP connection attempts to {args.server_ip}:{args.port}")
        for i in range(args.count):
            try:
                with socket.create_connection((args.server_ip, args.port), timeout=0.4):
                    pass
            except OSError:
                pass
            if args.interval:
                time.sleep(args.interval)
        print("[FLOOD TEST] Finished. Check the controller for [AUTO BLOCK].")
        return

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
