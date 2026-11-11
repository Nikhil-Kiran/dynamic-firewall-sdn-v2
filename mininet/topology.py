#!/usr/bin/env python3
"""
Custom Mininet OpenFlow 1.3 Topology for SDN Dynamic Firewall (Person B)
Automatically starts the Centralized Security Event Logger on h4 (10.0.0.4:9999)
and the Multi-Threaded TCP Server on h3 (10.0.0.3:8080) on boot.
"""

import os
import json
import subprocess
import time
from mininet.cli import CLI
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_SERVER_SCRIPT = os.path.join(BASE_DIR, "socket_app", "log_server.py")
TCP_SERVER_SCRIPT = os.path.join(BASE_DIR, "socket_app", "tcp_server.py")
LOG_FILE_PATH = os.path.join(BASE_DIR, "security_events.log")
PID_FILE_PATH = "/tmp/dynamic-firewall-mininet-pids.json"


class FirewallTopo(Topo):
    def build(self):
        s1 = self.addSwitch("s1", protocols="OpenFlow13")

        h1 = self.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
        h2 = self.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
        h3 = self.addHost("h3", ip="10.0.0.3/24", mac="00:00:00:00:00:03")
        h4 = self.addHost("h4", ip="10.0.0.4/24", mac="00:00:00:00:00:04")

        for h in (h1, h2, h3, h4):
            self.addLink(h, s1)


def run_topology():
    topo = FirewallTopo()
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip="127.0.0.1", port=6653),
        switch=OVSSwitch,
        autoSetMacs=True,
    )

    net.start()

    # Publish real Mininet host shell PIDs for the dashboard's namespace runner.
    # The dashboard uses these PIDs with mnexec -a; it never fabricates traffic.
    try:
        with open(PID_FILE_PATH, "w", encoding="utf-8") as pid_file:
            json.dump({name: net.get(name).pid for name in ("h1", "h2", "h3", "h4")}, pid_file)
        os.chmod(PID_FILE_PATH, 0o644)
        info(f"*** Dashboard host PID registry written to {PID_FILE_PATH}\n")
    except Exception as exc:
        info(f"*** WARNING: Could not write dashboard PID registry: {exc}\n")

    info("\n*** Configuring root-bridge interface on s1 (10.0.0.254/24) for SDN-to-Logger telemetry...\n")
    subprocess.run(["ip", "addr", "flush", "dev", "s1"], stderr=subprocess.DEVNULL)
    subprocess.run(["ip", "addr", "add", "10.0.0.254/24", "dev", "s1"], stderr=subprocess.DEVNULL)
    subprocess.run(["ip", "link", "set", "s1", "up"], stderr=subprocess.DEVNULL)

    h3 = net.get("h3")
    h4 = net.get("h4")

    # Clean old log outputs
    for fpath in ("/tmp/h4_logger.out", "/tmp/h3_server.out", LOG_FILE_PATH):
        if os.path.exists(fpath):
            os.remove(fpath)

    info("*** Auto-starting Centralized Security Event Logger on h4 (10.0.0.4:9999)...\n")
    h4.cmd(f"python3 -u {LOG_SERVER_SCRIPT} --host 0.0.0.0 --port 9999 --logfile {LOG_FILE_PATH} > /tmp/h4_logger.out 2>&1 &")

    info("*** Auto-starting Multi-Threaded TCP Server on h3 (10.0.0.3:8080)...\n")
    h3.cmd(f"python3 -u {TCP_SERVER_SCRIPT} > /tmp/h3_server.out 2>&1 &")

    time.sleep(1.0)

    info("*** Verifying background services:\n")
    info(h4.cmd("cat /tmp/h4_logger.out"))
    info(h3.cmd("cat /tmp/h3_server.out"))
    info("\n*** SDN Firewall Topology & Services Ready! Run your client tests below:\n\n")

    CLI(net)
    net.stop()
    try:
        if os.path.exists(PID_FILE_PATH):
            os.remove(PID_FILE_PATH)
    except OSError:
        pass


if __name__ == "__main__":
    setLogLevel("info")
    run_topology()
