#!/usr/bin/env python3
import json
import os
import socket
import threading
import time

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(BASE_DIR, "security_events.log")
POLICY_FILE = os.path.join(BASE_DIR, "controller", "policy.json")

def load_policy():
    try:
        with open(POLICY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"logger_ip": "10.0.0.4", "logger_port": 9999, "blocked_ports": [23, 4444], "allowed_ports": [8080, 9999]}

def _transmit_socket(payload_str: str, logger_ip: str, logger_port: int):
    for target_ip in (logger_ip, "127.0.0.1"):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.3)
                s.connect((target_ip, int(logger_port)))
                s.sendall(payload_str.encode("utf-8"))
                return True
        except Exception:
            continue
    return False

def send_security_event(event_dict=None, logger_ip: str = "10.0.0.4", logger_port: int = 9999, **kwargs):
    if event_dict is None:
        event_dict = {}
    if isinstance(event_dict, str):
        try:
            event_dict = json.loads(event_dict)
        except Exception:
            event_dict = {"reason": event_dict}
    if kwargs:
        event_dict.update(kwargs)

    event_dict.setdefault("timestamp", time.strftime("%Y-%m-%d %H:%M:%S"))
    event_dict.setdefault("action", event_dict.get("event_type", "SECURITY_ALERT"))
    event_dict.setdefault("reason", event_dict.get("details", "Policy violation detected"))
    event_dict.setdefault("src_ip", "10.0.0.2")
    event_dict.setdefault("dst_ip", "10.0.0.3")
    event_dict.setdefault("src_port", 0)
    event_dict.setdefault("dst_port", 4444)
    event_dict.setdefault("protocol", "TCP")

    payload_str = json.dumps(event_dict) + "\n"
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(payload_str)
        os.chmod(LOG_FILE, 0o666)
    except Exception:
        pass

    t = threading.Thread(target=_transmit_socket, args=(payload_str, logger_ip, logger_port), daemon=True)
    t.start()
    return True

send_event = send_security_event
log_security_event = send_security_event
emit_security_event = send_security_event
