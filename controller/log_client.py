#!/usr/bin/env python3
"""
Fault-tolerant asynchronous SOC telemetry client.
Based on the latest GitHub logger fallback implementation, with a compatibility
adapter for the keyword-based calls used by the enhanced local IPS controller.
"""
import json
import os
import socket
import threading
import time

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_LOG_FILE = os.path.join(BASE_DIR, "security_events.log")
DEFAULT_LOGGER_IP = os.environ.get("SDN_LOGGER_IP", "10.0.0.4")
DEFAULT_LOGGER_PORT = int(os.environ.get("SDN_LOGGER_PORT", "9999"))
_file_lock = threading.Lock()


def _persist_fallback(payload_dict: dict, log_file: str = DEFAULT_LOG_FILE):
    """Persist locally if SOC logger delivery fails; avoid recent duplicates."""
    try:
        with _file_lock:
            line_str = json.dumps(payload_dict)
            if os.path.exists(log_file):
                with open(log_file, "r", encoding="utf-8") as rf:
                    recent = rf.readlines()[-5:]
                if any(
                    payload_dict.get("timestamp") in row
                    and payload_dict.get("src_ip") in row
                    and str(payload_dict.get("dst_port")) in row
                    for row in recent
                ):
                    return
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(line_str + "\n")
                f.flush()
    except Exception as exc:
        print(f"[LOG_CLIENT WARN] Local fallback persistence failed: {exc}", flush=True)


def send_security_event(
    event_data=None,
    logger_ip: str = DEFAULT_LOGGER_IP,
    logger_port: int = DEFAULT_LOGGER_PORT,
    timeout: float = 0.8,
    **kwargs,
) -> bool:
    """
    Queue a JSON event for asynchronous delivery to h4:9999.

    Accepts both the latest GitHub API:
        send_security_event(event_dict, logger_ip=..., logger_port=...)
    and the enhanced controller API:
        send_security_event(src_ip=..., dst_ip=..., action=..., async_send=True, ...)
    """
    payload = dict(event_data) if isinstance(event_data, dict) else {}
    async_send = kwargs.pop("async_send", True)  # delivery is intentionally always asynchronous
    payload.update(kwargs)
    payload.setdefault("timestamp", time.strftime("%Y-%m-%d %H:%M:%S"))
    payload.setdefault("event_type", "SDN_FIREWALL_RULE")

    def _worker():
        wire_data = (json.dumps(payload) + "\n").encode("utf-8")
        delivered = False
        targets = [logger_ip]
        if logger_ip != "127.0.0.1":
            targets.append("127.0.0.1")
        for target_ip in targets:
            try:
                with socket.create_connection((target_ip, int(logger_port)), timeout=timeout) as sock:
                    sock.sendall(wire_data)
                    delivered = True
                    break
            except Exception:
                continue

        # The SOC server also writes to the shared log file. This fallback
        # covers logger outages and deduplicates events already persisted by h4.
        if delivered:
            time.sleep(0.05)
        _persist_fallback(payload)

    threading.Thread(target=_worker, daemon=True).start()
    return True


class LogClient:
    def __init__(self, host: str = DEFAULT_LOGGER_IP, port: int = DEFAULT_LOGGER_PORT, timeout: float = 0.8):
        self.host = host
        self.port = int(port)
        self.timeout = timeout

    def send_event(self, event_dict: dict) -> bool:
        return send_security_event(event_dict, logger_ip=self.host, logger_port=self.port, timeout=self.timeout)

    def log(self, **kwargs) -> bool:
        return send_security_event(logger_ip=self.host, logger_port=self.port, timeout=self.timeout, **kwargs)
