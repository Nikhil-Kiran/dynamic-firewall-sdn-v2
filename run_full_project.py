#!/usr/bin/env python3
"""
Unified Master Project Runner: SDN-Based Dynamic Firewall with Centralized Security Event Logger (TCP)
Executes the entire project pipeline end-to-end:
  Stage 1: Boot OpenFlow 1.3 Topology & Background Servers (h3 TCP Server, h4 SOC Logger)
  Stage 2: Live Traffic Verification (Authorized TCP, Forbidden Port Attack, Blacklisted Host Attack)
  Stage 3: Data-Plane & Telemetry Inspection (OVS Flow Table, Live SOC Console, JSON Logs)
  Stage 4: Multi-Threaded Logger Stress Verification (13/13 Concurrency Suite)
  Stage 5: Live Network Performance & Baseline Evaluation + PNG Graph Generation
"""

import os
import subprocess
import sys
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "mininet"))

from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from topology import FirewallTopo
import benchmark_d2 as bench

LOG_SERVER_SCRIPT = os.path.join(BASE_DIR, "socket_app", "log_server.py")
TCP_SERVER_SCRIPT = os.path.join(BASE_DIR, "socket_app", "tcp_server.py")
TCP_CLIENT_SCRIPT = os.path.join(BASE_DIR, "socket_app", "tcp_client.py")
LOG_FILE_PATH = os.path.join(BASE_DIR, "security_events.log")


def banner(title: str):
    print("\n" + "=" * 78)
    print(f" {title}")
    print("=" * 78, flush=True)


def main():
    setLogLevel("warning")

    banner("STAGE 1: CLEANING ENVIRONMENT & STARTING UNIFIED SDN NETWORK")
    subprocess.run(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if os.path.exists(LOG_FILE_PATH):
        os.remove(LOG_FILE_PATH)

    topo = FirewallTopo()
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip="127.0.0.1", port=6653),
        switch=OVSSwitch,
        autoSetMacs=True,
    )
    net.start()

    subprocess.run(["ip", "addr", "flush", "dev", "s1"], stderr=subprocess.DEVNULL)
    subprocess.run(["ip", "addr", "add", "10.0.0.254/24", "dev", "s1"], stderr=subprocess.DEVNULL)
    subprocess.run(["ip", "link", "set", "s1", "up"], stderr=subprocess.DEVNULL)
    bench.ensure_table_miss_rule()

    h1, h2, h3, h4 = net.get("h1", "h2", "h3", "h4")

    h4.cmd(f"python3 -u {LOG_SERVER_SCRIPT} --host 0.0.0.0 --port 9999 --logfile {LOG_FILE_PATH} > /tmp/h4_logger.out 2>&1 &")
    h3.cmd(f"python3 -u {TCP_SERVER_SCRIPT} > /tmp/h3_server.out 2>&1 &")
    time.sleep(1.2)

    print(" -> OpenFlow 1.3 Switch s1 (10.0.0.254/24) connected to SDN Controller (127.0.0.1:6653)")
    print(" -> Application TCP Server active on h3 (10.0.0.3:8080)")
    print(" -> Centralized Security Event Logger active on h4 (10.0.0.4:9999)")

    banner("STAGE 2: EXECUTING LIVE FIREWALL TRAFFIC SCENARIOS")

    print("\n[Scenario 1] Authorized Client Traffic (h1 [10.0.0.1] -> h3 [10.0.0.3:8080]):")
    out1 = h1.cmd(f"python3 {TCP_CLIENT_SCRIPT} --server-ip 10.0.0.3 --port 8080 --mode normal --messages 2")
    print(out1.strip())

    print("\n[Scenario 2] Unauthorized Port Attack (h1 [10.0.0.1] -> h3 [10.0.0.3:4444]):")
    out2 = h1.cmd(f"python3 {TCP_CLIENT_SCRIPT} --server-ip 10.0.0.3 --port 4444 --mode forbidden --messages 1")
    print(out2.strip())

    print("\n[Scenario 3] Blacklisted Host Attack (h2 [10.0.0.2] -> h3 [10.0.0.3:8080]):")
    out3 = h2.cmd(f"python3 {TCP_CLIENT_SCRIPT} --server-ip 10.0.0.3 --port 8080 --mode normal --messages 1")
    print(out3.strip())
    time.sleep(0.5)

    banner("STAGE 3: VERIFYING OPENFLOW SWITCH RULES & CENTRALIZED SOC LOGS")

    print("\n--- [A] Application TCP Server Log on h3 (/tmp/h3_server.out) ---")
    with open("/tmp/h3_server.out", "r", encoding="utf-8") as f:
        print(f.read().strip())

    print("\n--- [B] Live SOC Logger Console on h4 (/tmp/h4_logger.out) ---")
    with open("/tmp/h4_logger.out", "r", encoding="utf-8") as f:
        print(f.read().strip())

    print("\n--- [C] Persistent JSON Security Telemetry (security_events.log) ---")
    if os.path.exists(LOG_FILE_PATH):
        with open(LOG_FILE_PATH, "r", encoding="utf-8") as f:
            print(f.read().strip())

    print("\n--- [D] Active OpenFlow 1.3 Flow Table on Switch s1 ---")
    print(bench.dump_flows().strip())

    banner("STAGE 4: RUNNING LIVE NETWORK PERFORMANCE & BASELINE BENCHMARK")
    response_times = bench.measure_blocking_response_times(h1, trials=10)
    impact = bench.evaluate_network_impact(h1, h2)
    bench.generate_plots(response_times, impact)

    net.stop()

    banner("STAGE 5: RUNNING MULTI-THREADED LOGGER CONCURRENCY SUITE (13/13)")
    subprocess.run(["python3", os.path.join(BASE_DIR, "socket_app", "test_logger_suite.py")], check=False)

    if os.path.exists(LOG_FILE_PATH):
        os.remove(LOG_FILE_PATH)

    banner("ALL PROJECT MODULES VERIFIED SUCCESSFULLY!")


if __name__ == "__main__":
    main()
