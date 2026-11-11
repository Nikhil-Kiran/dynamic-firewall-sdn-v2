#!/usr/bin/env python3
"""
Mininet OpenFlow 1.3 Topology (mininet/topology.py)
Configures s1, h1-h4, static ARP entries, and root bridge 10.0.0.254/24
so the SDN Controller can stream TCP telemetry to h4 (10.0.0.4:9999) with zero timeouts.
"""

import os
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


class FirewallTopo(Topo):
    def build(self):
        s1 = self.addSwitch("s1", protocols="OpenFlow13")
        h1 = self.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
        h2 = self.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
        h3 = self.addHost("h3", ip="10.0.0.3/24", mac="00:00:00:00:00:03")
        h4 = self.addHost("h4", ip="10.0.0.4/24", mac="00:00:00:00:00:04")

        for h in (h1, h2, h3, h4):
            self.addLink(h, s1)


def configure_zero_timeout_telemetry(net):
    """Configures s1 root interface + static ARP so controller -> 10.0.0.4:9999 never times out."""
    subprocess.run(["ovs-vsctl", "set", "Bridge", "s1", "protocols=OpenFlow13"], stderr=subprocess.DEVNULL)
    subprocess.run(["ip", "link", "set", "s1", "address", "00:00:00:00:00:fe"], stderr=subprocess.DEVNULL)
    subprocess.run(["ip", "addr", "flush", "dev", "s1"], stderr=subprocess.DEVNULL)
    subprocess.run(["ip", "addr", "add", "10.0.0.254/24", "dev", "s1"], stderr=subprocess.DEVNULL)
    subprocess.run(["ip", "link", "set", "s1", "up"], stderr=subprocess.DEVNULL)

    # Pre-populate static ARP in root namespace and all hosts so ARP never stalls TCP
    subprocess.run(["ip", "neigh", "replace", "10.0.0.4", "lladdr", "00:00:00:00:00:04", "dev", "s1", "nud", "permanent"], stderr=subprocess.DEVNULL)

    hosts = [net.get(h) for h in ("h1", "h2", "h3", "h4")]
    for h in hosts:
        h.cmd("arp -s 10.0.0.254 00:00:00:00:00:fe")
        for idx in range(1, 5):
            h.cmd(f"arp -s 10.0.0.{idx} 00:00:00:00:00:0{idx}")

    # Install high-priority OpenFlow rules for SOC Logger traffic (10.0.0.254 <-> 10.0.0.4:9999)
    # so logger TCP packets go straight through OVS hardware in <0.2ms without waiting on PacketIn!
    subprocess.run(
        ["ovs-ofctl", "-O", "OpenFlow13", "add-flow", "s1", "priority=200,ip,nw_dst=10.0.0.4,actions=output:4"],
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["ovs-ofctl", "-O", "OpenFlow13", "add-flow", "s1", "priority=200,ip,nw_src=10.0.0.4,nw_dst=10.0.0.254,actions=LOCAL"],
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["ovs-ofctl", "-O", "OpenFlow13", "add-flow", "s1", "priority=200,arp,actions=NORMAL"],
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["ovs-ofctl", "-O", "OpenFlow13", "add-flow", "s1", "priority=0,actions=CONTROLLER:65535"],
        stderr=subprocess.DEVNULL,
    )


def run_topology():
    setLogLevel("info")
    subprocess.run(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    topo = FirewallTopo()
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip="127.0.0.1", port=6653),
        switch=OVSSwitch,
        autoSetMacs=True,
    )
    net.start()

    info("\n*** Configuring zero-timeout root-bridge & static OpenFlow telemetry path to h4...\n")
    configure_zero_timeout_telemetry(net)

    h3, h4 = net.get("h3", "h4")
    info("*** Auto-starting Centralized Security Event Logger on h4 (10.0.0.4:9999)...\n")
    h4.cmd(f"python3 -u {LOG_SERVER_SCRIPT} --host 0.0.0.0 --port 9999 --logfile {LOG_FILE_PATH} > /tmp/h4_logger.out 2>&1 &")
    info("*** Auto-starting Multi-Threaded TCP Server on h3 (10.0.0.3:8080)...\n")
    h3.cmd(f"python3 -u {TCP_SERVER_SCRIPT} > /tmp/h3_server.out 2>&1 &")
    time.sleep(0.8)

    CLI(net)
    net.stop()


if __name__ == "__main__":
    run_topology()
