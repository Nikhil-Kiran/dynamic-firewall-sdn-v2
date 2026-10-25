#!/usr/bin/env python3
"""
Upgraded Centralized Security Event Logging Server (SIEM Collector)
Listens over TCP for structured JSON security telemetry from the OS-Ken SDN
Controller, providing real-time console alerts and thread-safe persistence.
"""

import argparse
import datetime
import json
import os
import signal
import socket
import sys
import threading

file_lock = threading.Lock()
stats_lock = threading.Lock()
event_counter = 0

# ANSI color codes for terminal SOC dashboard
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BLUE = "\033[94m"
RESET = "\033[0m"
BOLD = "\033[1m"


def increment_counter():
    global event_counter
    with stats_lock:
        event_counter += 1
        return event_counter


def write_to_logfile(log_path: str, event_data: dict):
    """Thread-safe append of structured JSON security records to disk."""
    with file_lock:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event_data) + "\n")


def format_and_print_alert(event: dict, event_id: int):
    """Prints an upgraded SOC-grade security alert banner to the console."""
    action = event.get("action", "UNKNOWN").upper()
    color = RED if "DROP" in action or "BLOCK" in action or "REJECT" in action else YELLOW

    print(f"\n{color}{BOLD}[SOC ALERT #{event_id:04d}] {event.get('logged_at')}{RESET}")
    print(f"{CYAN}Event Type     :{RESET} {event.get('event_type', 'SDN_FIREWALL_EVENT')}")
    print(f"{CYAN}Enforced Action:{RESET} {color}{BOLD}{action}{RESET}")
    print(
        f"{CYAN}Flow Tuple     :{RESET} {event.get('src_ip')}:{event.get('src_port', '*')} "
        f"---> {event.get('dst_ip')}:{event.get('dst_port')} ({event.get('protocol', 'TCP')})"
    )
    print(f"{CYAN}Violation Note :{RESET} {event.get('reason', 'Security policy violation')}")
    if event.get("timeout_sec"):
        print(f"{CYAN}Flow Timeout   :{RESET} Dynamic hard_timeout expiration in {event.get('timeout_sec')}s")
    print(f"{BLUE}{'—' * 60}{RESET}", flush=True)


def handle_client_connection(conn: socket.socket, addr: tuple, log_path: str):
    """Handles incoming TCP telemetry streams with stream fragmentation buffering."""
    buffer = ""
    try:
        conn.settimeout(6.0)
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buffer += chunk.decode("utf-8", errors="replace")

            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    event["logged_at"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                    event["reporter_ip"] = addr[0]

                    ev_id = increment_counter()
                    format_and_print_alert(event, ev_id)
                    write_to_logfile(log_path, event)
                    
                    conn.sendall(json.dumps({"status": "ACK", "event_id": ev_id}).encode("utf-8") + b"\n")
                except json.JSONDecodeError:
                    print(f"{YELLOW}[WARN] Malformed JSON payload received from {addr}: {line}{RESET}", flush=True)
                    conn.sendall(b'{"status": "ERROR", "reason": "Invalid JSON syntax"}\n')

        # Handle remaining unbuffered line if connection closes abruptly
        if buffer.strip():
            try:
                event = json.loads(buffer.strip())
                event["logged_at"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                event["reporter_ip"] = addr[0]
                ev_id = increment_counter()
                format_and_print_alert(event, ev_id)
                write_to_logfile(log_path, event)
                conn.sendall(json.dumps({"status": "ACK", "event_id": ev_id}).encode("utf-8") + b"\n")
            except json.JSONDecodeError:
                pass

    except (socket.timeout, ConnectionResetError):
        pass
    except Exception as exc:
        print(f"{YELLOW}[ERROR] Logger connection handler exception ({addr}): {exc}{RESET}", flush=True)
    finally:
        conn.close()


def start_log_server(host: str, port: int, log_path: str):
    """Initializes and runs the multi-threaded TCP Security Event Logger."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_sock.bind((host, port))
        server_sock.listen(32)
    except OSError as exc:
        print(f"{RED}[FATAL] Logger Server failed to bind to {host}:{port} -> {exc}{RESET}")
        sys.exit(1)

    log_dir = os.path.dirname(os.path.abspath(log_path))
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)

    print(f"{GREEN}{BOLD}[SOC LOGGER ACTIVE] Listening for SDN Telemetry on {host}:{port} (TCP){RESET}")
    print(f"{GREEN}[PERSISTENCE PATH] Writing structured JSON logs to: {os.path.abspath(log_path)}{RESET}\n", flush=True)

    def shutdown_handler(sig, frame):
        print(f"\n{YELLOW}[SOC LOGGER] Gracefully shutting down event collector...{RESET}")
        server_sock.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    while True:
        try:
            conn, addr = server_sock.accept()
            worker = threading.Thread(
                target=handle_client_connection,
                args=(conn, addr, log_path),
                daemon=True,
            )
            worker.start()
        except OSError:
            break


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SDN Centralized TCP Security Event Logger")
    parser.add_argument("--host", default="0.0.0.0", help="Bind IP address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=9999, help="Bind TCP port (default: 9999)")
    parser.add_argument("--logfile", default="security_events.log", help="Output JSON log file path")
    args = parser.parse_args()
    start_log_server(args.host, args.port, args.logfile)
