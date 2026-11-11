import json
import os
import socket
import threading

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(BASE_DIR, "security_events.log")

def _send_async(payload_str: str, logger_ip: str, logger_port: int):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(payload_str)
        os.chmod(LOG_FILE, 0o666)
    except Exception:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.4)
            s.connect((logger_ip, int(logger_port)))
            s.sendall(payload_str.encode("utf-8"))
    except Exception:
        pass

def send_security_event(event_dict: dict, logger_ip: str = "10.0.0.4", logger_port: int = 9999):
    payload_str = json.dumps(event_dict) + "\n"
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(payload_str)
    except Exception:
        pass
    t = threading.Thread(target=_send_async, args=(payload_str, logger_ip, logger_port), daemon=True)
    t.start()
