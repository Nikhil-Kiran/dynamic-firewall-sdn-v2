#!/usr/bin/env python3
"""
UNIVERSAL SINGLE-COMMAND MASTER ORCHESTRATOR (start_everything.py)
1. Auto-detects any teammate's Linux user, home directory, and display.
2. Cleans stale Mininet state and frees ports 5000 / 6653 / 9999.
3. Finds or auto-installs os-ken in a local venv.
4. Boots OS-Ken OpenFlow 1.3 Controller and Mininet Topology (s1, h1-h4).
5. Configures static ARP and narrow priority=200 OVS telemetry rules on port 9999.
6. Starts Centralized SOC Logger (h4:9999 + root fallback) and TCP Server (h3:8080).
7. Registers host PIDs (/tmp/mininet_host_pids.json) for real mnexec browser packet execution.
8. Launches Web Control Plane on http://127.0.0.1:5000 and auto-opens Firefox.
"""

import json
import os
import pwd
import shutil
import subprocess
import sys
import time

if os.geteuid() != 0:
    print("Re-launching with sudo so Mininet can create virtual switches...")
    os.execvp("sudo", ["sudo", "-E", sys.executable] + sys.argv)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "mininet"))

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from topology import FirewallTopo


def get_real_user_and_home():
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root":
        try:
            pw = pwd.getpwnam(sudo_user)
            return sudo_user, pw.pw_dir
        except KeyError:
            pass
    st = os.stat(BASE_DIR)
    try:
        pw = pwd.getpwuid(st.st_uid)
        return pw.pw_name, pw.pw_dir
    except KeyError:
        return "root", os.path.expanduser("~")


REAL_USER, USER_HOME = get_real_user_and_home()


def find_or_install_osken():
    """Finds osken-manager across any teammate's venv or system PATH, or auto-installs it."""
    candidates = [
        os.path.join(USER_HOME, "sdn-dynamic-firewall", "venv", "bin", "osken-manager"),
        os.path.join(BASE_DIR, "venv", "bin", "osken-manager"),
        os.path.join(BASE_DIR, ".venv", "bin", "osken-manager"),
        shutil.which("osken-manager"),
    ]
    for c in candidates:
        if c and os.path.exists(c):
            return c

    print(" [AUTO-SETUP] First-time setup: Creating local venv & installing os-ken + matplotlib...")
    venv_dir = os.path.join(BASE_DIR, "venv")
    subprocess.run(["sudo", "-u", REAL_USER, "python3", "-m", "venv", venv_dir], check=False)
    pip_bin = os.path.join(venv_dir, "bin", "pip")
    subprocess.run(
        ["sudo", "-u", REAL_USER, pip_bin, "install", "--quiet", "os-ken", "matplotlib", "eventlet"],
        check=False,
    )
    return os.path.join(venv_dir, "bin", "osken-manager")


CONTROLLER_SCRIPT = os.path.join(BASE_DIR, "controller", "firewall_controller.py")
DASHBOARD_SCRIPT = os.path.join(BASE_DIR, "dashboard", "app.py")
LOG_SERVER_SCRIPT = os.path.join(BASE_DIR, "socket_app", "log_server.py")
TCP_SERVER_SCRIPT = os.path.join(BASE_DIR, "socket_app", "tcp_server.py")
LOG_FILE_PATH = os.path.join(BASE_DIR, "security_events.log")
HOST_PIDS_FILE = "/tmp/mininet_host_pids.json"


def configure_zero_timeout_telemetry(net):
    """Configures s1 root bridge + static ARP + port-9999 OVS rules so h4:9999 never times out."""
    subprocess.run(["ovs-vsctl", "set", "Bridge", "s1", "protocols=OpenFlow13"], stderr=subprocess.DEVNULL)
    subprocess.run(["ip", "link", "set", "s1", "address", "00:00:00:00:00:fe"], stderr=subprocess.DEVNULL)
    subprocess.run(["ip", "addr", "flush", "dev", "s1"], stderr=subprocess.DEVNULL)
    subprocess.run(["ip", "addr", "add", "10.0.0.254/24", "dev", "s1"], stderr=subprocess.DEVNULL)
    subprocess.run(["ip", "link", "set", "s1", "up"], stderr=subprocess.DEVNULL)

    # Permanent static ARP in root namespace for h4 (10.0.0.4)
    subprocess.run(
        ["ip", "neigh", "replace", "10.0.0.4", "lladdr", "00:00:00:00:00:04", "dev", "s1", "nud", "permanent"],
        stderr=subprocess.DEVNULL,
    )

    # Pre-populate static ARP across all Mininet hosts
    for h_name in ("h1", "h2", "h3", "h4"):
        h = net.get(h_name)
        h.cmd("arp -s 10.0.0.254 00:00:00:00:00:fe")
        for idx in range(1, 5):
            h.cmd(f"arp -s 10.0.0.{idx} 00:00:00:00:00:0{idx}")

    # Narrow priority=200 OVS rules strictly for controller (10.0.0.254) <-> h4:9999 TCP telemetry
    subprocess.run(
        ["ovs-ofctl", "-O", "OpenFlow13", "add-flow", "s1", "priority=200,tcp,nw_src=10.0.0.254,nw_dst=10.0.0.4,tp_dst=9999,actions=output:4"],
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["ovs-ofctl", "-O", "OpenFlow13", "add-flow", "s1", "priority=200,tcp,nw_src=10.0.0.4,nw_dst=10.0.0.254,tp_src=9999,actions=LOCAL"],
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


def open_browser_for_teammate(url: str):
    """Opens Firefox/default browser cleanly as the non-root user on Ubuntu Wayland/X11."""
    display = os.environ.get("DISPLAY", ":0")
    uid = pwd.getpwnam(REAL_USER).pw_uid if REAL_USER != "root" else 0
    runtime_dir = f"/run/user/{uid}"
    env_vars = ["env", f"DISPLAY={display}", f"HOME={USER_HOME}"]
    if os.path.exists(runtime_dir):
        env_vars.append(f"XDG_RUNTIME_DIR={runtime_dir}")

    for browser_cmd in ["firefox", "xdg-open", "google-chrome"]:
        if shutil.which(browser_cmd):
            subprocess.Popen(
                ["sudo", "-u", REAL_USER] + env_vars + [browser_cmd, url],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return


def main():
    setLogLevel("info")
    print("\n" + "=" * 76)
    print(f" UNIFIED SDN DYNAMIC FIREWALL — MASTER ORCHESTRATOR (User: {REAL_USER})")
    print("=" * 76)

    print(" [1/6] Cleaning up old Mininet topologies and ports (5000, 6653, 9999)...")
    subprocess.run(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["fuser", "-k", "5000/tcp"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["fuser", "-k", "6653/tcp"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["fuser", "-k", "9999/tcp"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if os.path.exists(LOG_FILE_PATH):
        os.remove(LOG_FILE_PATH)

    osken_bin = find_or_install_osken()
    print(f" [2/6] Starting OS-Ken OpenFlow 1.3 Controller ({osken_bin})...")
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{BASE_DIR}:{os.path.join(BASE_DIR, 'controller')}"
    ctrl_log = open("/tmp/controller.log", "w", encoding="utf-8")
    ctrl_proc = subprocess.Popen([osken_bin, CONTROLLER_SCRIPT], env=env, stdout=ctrl_log, stderr=ctrl_log)
    time.sleep(2.0)

    print(" [3/6] Starting Mininet OpenFlow 1.3 Topology (s1, h1, h2, h3, h4)...")
    topo = FirewallTopo()
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip="127.0.0.1", port=6653),
        switch=OVSSwitch,
        autoSetMacs=True,
    )
    net.start()

    configure_zero_timeout_telemetry(net)

    h1, h2, h3, h4 = net.get("h1", "h2", "h3", "h4")

    print(" [4/6] Starting Centralized SOC Logger (h4:9999) & Multi-Threaded TCP Server (h3:8080)...")
    h4.cmd(f"python3 -u {LOG_SERVER_SCRIPT} --host 0.0.0.0 --port 9999 --logfile {LOG_FILE_PATH} > /tmp/h4_logger.out 2>&1 &")
    h3.cmd(f"python3 -u {TCP_SERVER_SCRIPT} > /tmp/h3_server.out 2>&1 &")
    # Also run a root-namespace mirror listener on 127.0.0.1:9999 so localhost fallback never fails
    root_logger_proc = subprocess.Popen(
        ["python3", "-u", LOG_SERVER_SCRIPT, "--host", "127.0.0.1", "--port", "9999", "--logfile", LOG_FILE_PATH],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1.0)

    pids = {"h1": h1.pid, "h2": h2.pid, "h3": h3.pid, "h4": h4.pid}
    with open(HOST_PIDS_FILE, "w", encoding="utf-8") as f:
        json.dump(pids, f)

    print(" [5/6] Starting Real-Time Web Control Plane on http://127.0.0.1:5000...")
    ui_log = open("/tmp/dashboard_ui.log", "w", encoding="utf-8")
    ui_proc = subprocess.Popen(["python3", DASHBOARD_SCRIPT], stdout=ui_log, stderr=ui_log)
    time.sleep(1.2)

    print(" [6/6] Launching Firefox Dashboard on http://127.0.0.1:5000...")
    open_browser_for_teammate("http://127.0.0.1:5000")

    print("\n" + "=" * 76)
    print(" [SYSTEM READY] Everything is running!")
    print("  -> Open Firefox to: http://127.0.0.1:5000")
    print("  -> Click 'Run Full Auto-Pilot Demo' on the top-right of the webpage!")
    print("  -> Type 'exit' when finished to cleanly stop all services.")
    print("=" * 76 + "\n")

    try:
        CLI(net)
    finally:
        print("\n[SHUTDOWN] Stopping Web UI, Mininet, and SDN Controller...")
        if os.path.exists(HOST_PIDS_FILE):
            os.remove(HOST_PIDS_FILE)
        root_logger_proc.terminate()
        ui_proc.terminate()
        ctrl_proc.terminate()
        net.stop()


if __name__ == "__main__":
    main()
