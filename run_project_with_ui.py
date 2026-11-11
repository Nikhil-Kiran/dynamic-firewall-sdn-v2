#!/usr/bin/env python3
"""
Unified SDN Firewall Master Launcher with Automated Web UI & Browser Startup
"""

import os
import subprocess
import sys
import time
import webbrowser

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DASHBOARD_SCRIPT = os.path.join(BASE_DIR, "dashboard", "app.py")
CONTROLLER_SCRIPT = os.path.join(BASE_DIR, "controller", "firewall_controller.py")
VENV_PYTHON = os.path.expanduser("~/sdn-dynamic-firewall/venv/bin/python3")
OSKEN_MANAGER = os.path.expanduser("~/sdn-dynamic-firewall/venv/bin/osken-manager")


def main():
    print("=" * 70)
    print(" STARTING SDN DYNAMIC FIREWALL & SOC CONTROL PLANE")
    print("=" * 70, flush=True)

    subprocess.run(["sudo", "mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print(" [1/3] Starting Web UI Dashboard on http://127.0.0.1:5000...")
    ui_proc = subprocess.Popen([VENV_PYTHON, DASHBOARD_SCRIPT], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)

    print(" [2/3] Opening Firefox Control Plane...")
    webbrowser.open("http://127.0.0.1:5000")

    print(" [3/3] Starting OS-Ken SDN Controller...")
    print("\n -> Dashboard is active! You can now start Mininet in another tab:")
    print("    sudo python3 mininet/topology.py\n")
    print("Press Ctrl+C to stop the dashboard and controller when finished.\n", flush=True)

    env = os.environ.copy()
    env["PYTHONPATH"] = os.path.join(BASE_DIR, "controller")
    try:
        subprocess.run([OSKEN_MANAGER, CONTROLLER_SCRIPT], env=env)
    except KeyboardInterrupt:
        print("\n[INFO] Shutting down SDN Firewall project...")
        ui_proc.terminate()


if __name__ == "__main__":
    main()
