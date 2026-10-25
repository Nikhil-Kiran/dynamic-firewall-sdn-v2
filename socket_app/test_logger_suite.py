#!/usr/bin/env python3
"""
Automated Verification Suite for Centralized Security Event Logger & SDN Bridge
Validates single-event transmission, forbidden-port drops, blacklisted host blocks,
and multi-threaded concurrent stress telemetry.
"""

import json
import os
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "controller")))
from log_client import send_security_event

TEST_LOG_FILE = "test_security_events.log"
TEST_PORT = 9998


def run_test_suite():
    if os.path.exists(TEST_LOG_FILE):
        os.remove(TEST_LOG_FILE)

    print("=" * 70)
    print(" UPGRADED SDN DYNAMIC FIREWALL - LOGGER & INTEGRATION TEST SUITE")
    print("=" * 70)

    # Start log_server.py instance in a subprocess
    server_proc = subprocess.Popen(
        [
            sys.executable,
            os.path.join(os.path.dirname(__file__), "log_server.py"),
            "--host",
            "127.0.0.1",
            "--port",
            str(TEST_PORT),
            "--logfile",
            TEST_LOG_FILE,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    time.sleep(1.0)

    try:
        # Test 1: Forbidden Port Drop Telemetry (h1 -> h3:4444)
        print("\n[TEST 1] Testing SDN Drop Rule for Forbidden TCP Port 4444...")
        ok1 = send_security_event(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.3",
            dst_port=4444,
            src_port=51234,
            action="DROP_FLOW_INSTALLED",
            reason="Forbidden TCP port 4444 access attempt",
            logger_ip="127.0.0.1",
            logger_port=TEST_PORT,
            async_send=False,
        )
        print(f" -> Result: {'PASS' if ok1 else 'FAIL'}")

        # Test 2: Blacklisted Host Drop Telemetry (h2 -> h3:8080)
        print("\n[TEST 2] Testing SDN Drop Rule for Blacklisted Host 10.0.0.2...")
        ok2 = send_security_event(
            src_ip="10.0.0.2",
            dst_ip="10.0.0.3",
            dst_port=8080,
            src_port=51235,
            action="HOST_BLOCKED",
            reason="Blacklisted source IP 10.0.0.2 rejected",
            logger_ip="127.0.0.1",
            logger_port=TEST_PORT,
            async_send=False,
        )
        print(f" -> Result: {'PASS' if ok2 else 'FAIL'}")

        # Test 3: Application-Layer Security Anomaly Alert
        print("\n[TEST 3] Testing Application-Layer Security Anomaly Alert...")
        ok3 = send_security_event(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.3",
            dst_port=8080,
            src_port=51236,
            event_type="APP_LAYER_ALERT",
            action="PAYLOAD_REJECTED",
            reason="Forbidden payload signature detected",
            logger_ip="127.0.0.1",
            logger_port=TEST_PORT,
            async_send=False,
        )
        print(f" -> Result: {'PASS' if ok3 else 'FAIL'}")

        # Test 4: Concurrency Stress Test (10 simultaneous threads)
        print("\n[TEST 4] Dispatching 10 Concurrent Security Alerts (Thread-Safety Stress Check)...")
        threads = []
        for i in range(10):
            t = threading.Thread(
                target=send_security_event,
                kwargs={
                    "src_ip": f"10.0.0.{10 + i}",
                    "dst_ip": "10.0.0.3",
                    "dst_port": 4444,
                    "action": "DROP_FLOW_INSTALLED",
                    "reason": f"Concurrent stress test event #{i + 1}",
                    "logger_ip": "127.0.0.1",
                    "logger_port": TEST_PORT,
                    "async_send": False,
                },
            )
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        time.sleep(0.6)

        # Verify exact record count (3 individual + 10 concurrent = 13 records)
        with open(TEST_LOG_FILE, "r", encoding="utf-8") as f:
            lines = [json.loads(line) for line in f if line.strip()]

        expected_count = 13
        ok4 = len(lines) == expected_count
        print(f" -> Verified {len(lines)}/{expected_count} JSON records successfully persisted: {'PASS' if ok4 else 'FAIL'}")

        print("\n" + "=" * 70)
        if ok1 and ok2 and ok3 and ok4:
            print(" FINAL VERDICT: ALL UPGRADED TEST SUITES PASSED (13/13 EVENTS LOGGED)")
        else:
            print(" FINAL VERDICT: SOME TESTS ENCOUNTERED FAILURES")
        print("=" * 70)

    finally:
        server_proc.terminate()
        server_proc.wait()
        if os.path.exists(TEST_LOG_FILE):
            os.remove(TEST_LOG_FILE)


if __name__ == "__main__":
    run_test_suite()
