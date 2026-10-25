#!/usr/bin/env python3
"""
Custom Mininet OpenFlow 1.3 Topology for SDN Dynamic Firewall (Person B)
Creates 1 Open vSwitch (s1) and 4 hosts (h1-h4), and configures s1 bridge
interface (10.0.0.254/24) so the host OS controller can stream TCP logs to h4.
"""

import subprocess
from mininet.cli import CLI
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo


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

    info("\n*** Configuring root-bridge interface on s1 (10.0.0.254/24) for SDN-to-Logger telemetry...\n")
    subprocess.run(["ip", "addr", "flush", "dev", "s1"], stderr=subprocess.DEVNULL)
    subprocess.run(["ip", "addr", "add", "10.0.0.254/24", "dev", "s1"], stderr=subprocess.DEVNULL)
    subprocess.run(["ip", "link", "set", "s1", "up"], stderr=subprocess.DEVNULL)

    info("*** SDN Firewall Topology Ready:\n")
    info("    h1 (10.0.0.1) : Authorized Client\n")
    info("    h2 (10.0.0.2) : Restricted / Blacklisted Host\n")
    info("    h3 (10.0.0.3) : Multi-Threaded TCP Server (Port 8080 Allowed, Port 4444 Forbidden)\n")
    info("    h4 (10.0.0.4) : Centralized Security Event Logger (Port 9999)\n\n")

    CLI(net)
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    run_topology()
