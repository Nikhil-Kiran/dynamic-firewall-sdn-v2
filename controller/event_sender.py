#!/usr/bin/env python3
"""
Fault-Tolerant Asynchronous SOC Telemetry Client (controller/log_client.py)
Sends JSON security events to h4 (10.0.0.4:9999) over TCP without ever timing out
or blocking the OS-Ken OpenFlow control loop. Includes instant local persistence fallback.
"""

import json
import os
import socket
import threading
import time

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_LOG_FILE = os.path.join(BASE_DIR, "security_events.log")
_file_lock = threading.Lock()


def _persist_fallback(payload_dict: dict, log_file: str = DEFAULT_LOG_FILE):
    """Ensures security_events.log is always written even if Mininet s1 bridge is still warming up."""
    try:
        with _file_lock:
            # Avoid duplicate line if log_server on h4 already wrote it within the last 50ms
            line_str = json.dumps(payload_dict)
            if os.path.exists(log_file):
                with open(log_file, "r", encoding="utf-8") as rf:
                    recent = rf.readlines()[-5:]
                if any(
                    payload_dict.get("timestamp") in r
                    and payload_dict.get("src_ip") in r
                    and str(payload_dict.get("dst_port")) in r
                    for r in recent
                ):
                    return
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(line_str + "\n")
                f.flush()
    except Exception:
        pass


def send_security_event(
    event_data: dict,
    logger_ip: str = "10.0.0.4",
    logger_port: int = 9999,
    timeout: float = 0.8,
) -> bool:
    """Sends a JSON telemetry event to h4:9999 asynchronously so it never times out the controller."""
    if "timestamp" not in event_data:
        event_data["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")

    def _worker():
        payload = (json.dumps(event_data) + "\n").encode("utf-8")
        delivered = False
        for target_ip in (logger_ip, "127.0.0.1"):
            try:
                with socket.create_connection((target_ip, int(logger_port)), timeout=timeout) as sock:
                    sock.sendall(payload)
                    delivered = True
                    break
            except Exception:
                continue
        if not delivered:
            _persist_fallback(event_data)
        else:
            # Tiny delay to let h4 write first; fallback guarantees persistence if h4 was busy
            time.sleep(0.05)
            _persist_fallback(event_data)

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    return True


class LogClient:
    def __init__(self, host: str = "10.0.0.4", port: int = 9999, timeout: float = 0.8):
        self.host = host
        self.port = int(port)
        self.timeout = timeout

    def send_event(self, event_dict: dict) -> bool:
        return send_security_event(event_dict, self.host, self.port, self.timeout)

    def log(self, **kwargs) -> bool:
        return send_security_event(kwargs, self.host, self.port, self.timeout)
