#!/usr/bin/env python3
"""
Upgraded Non-Blocking TCP Security Event Client (Socket-SDN Integration Bridge)
Supports both OS-Ken eventlet green-threads and standard POSIX threads.
"""

import argparse
import datetime
import json
import os
import socket
import sys
import threading

DEFAULT_LOGGER_IP = os.environ.get("SDN_LOGGER_IP", "10.0.0.4")
DEFAULT_LOGGER_PORT = int(os.environ.get("SDN_LOGGER_PORT", "9999"))


def _transmit_event_sync(payload: dict, logger_ip: str, logger_port: int, timeout: float = 2.0) -> bool:
    """Internal synchronous helper transmitting JSON telemetry over TCP."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((logger_ip, logger_port))
            message = json.dumps(payload) + "\n"
            sock.sendall(message.encode("utf-8"))
            _ = sock.recv(256)
        return True
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        print(f"[LOG_CLIENT WARN] Unable to deliver security event to Logger at {logger_ip}:{logger_port} -> {exc}")
        return False


def send_security_event(
    src_ip: str = "0.0.0.0",
    dst_ip: str = "0.0.0.0",
    dst_port: int = 0,
    action: str = "DROP_FLOW_INSTALLED",
    reason: str = "Security policy violation",
    src_port: int = 0,
    protocol: str = "TCP",
    event_type: str = "SDN_FIREWALL_RULE",
    timeout_sec: int = 30,
    logger_ip: str = DEFAULT_LOGGER_IP,
    logger_port: int = DEFAULT_LOGGER_PORT,
    async_send: bool = True,
) -> bool:
    """
    Dispatches structured security telemetry to the centralized TCP Logger.
    Automatically uses eventlet green-threads if loaded inside OS-Ken, or daemon threads otherwise.
    """
    payload = {
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "event_type": event_type,
        "action": action,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": protocol,
        "reason": reason,
        "timeout_sec": timeout_sec,
    }

    if async_send:
        if "eventlet" in sys.modules:
            import eventlet
            eventlet.spawn_n(_transmit_event_sync, payload, logger_ip, logger_port)
        else:
            worker = threading.Thread(
                target=_transmit_event_sync,
                args=(payload, logger_ip, logger_port),
                daemon=True,
            )
            worker.start()
        return True
    else:
        return _transmit_event_sync(payload, logger_ip, logger_port)


# Alias for teammates who call log_event(dict) or send_event(...)
def send_event(event_dict: dict, logger_ip: str = DEFAULT_LOGGER_IP, logger_port: int = DEFAULT_LOGGER_PORT) -> bool:
    """Flexible dict-based wrapper in case firewall_controller passes a custom dictionary."""
    return send_security_event(
        src_ip=event_dict.get("src_ip", "0.0.0.0"),
        dst_ip=event_dict.get("dst_ip", "0.0.0.0"),
        dst_port=int(event_dict.get("dst_port", 0)),
        src_port=int(event_dict.get("src_port", 0)),
        action=event_dict.get("action", "DROP"),
        reason=event_dict.get("reason", event_dict.get(" details", "Policy violation")),
        protocol=event_dict.get("protocol", "TCP"),
        event_type=event_dict.get("event_type", "SDN_FIREWALL_RULE"),
        logger_ip=logger_ip,
        logger_port=logger_port,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test dispatching a security event to log_server.py")
    parser.add_argument("--logger-ip", default="127.0.0.1", help="Logger IP address")
    parser.add_argument("--logger-port", type=int, default=9999, help="Logger TCP port")
    parser.add_argument("--src-ip", default="10.0.0.1", help="Source IP")
    parser.add_argument("--dst-ip", default="10.0.0.3", help="Destination IP")
    parser.add_argument("--dst-port", type=int, default=4444, help="Destination Port")
    parser.add_argument("--action", default="DROP_FLOW_INSTALLED", help="Action enforced")
    parser.add_argument("--reason", default="Forbidden TCP port violation", help="Violation reason")
    args = parser.parse_args()

    print(f"[TEST CLIENT] Dispatching test telemetry to {args.logger_ip}:{args.logger_port}...")
    success = send_security_event(
        src_ip=args.src_ip,
        dst_ip=args.dst_ip,
        dst_port=args.dst_port,
        action=args.action,
        reason=args.reason,
        logger_ip=args.logger_ip,
        logger_port=args.logger_port,
        async_send=False,
    )
    if success:
        print("[TEST SUCCESS] Telemetry acknowledged by log_server.py!")
    else:
        print("[TEST FAILED] Ensure log_server.py is running.")
