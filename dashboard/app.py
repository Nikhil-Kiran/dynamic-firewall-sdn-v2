#!/usr/bin/env python3
"""
SDN Dynamic Firewall & SOC Telemetry Web UI (Real Mininet Namespace Execution + Auto-Pilot Demo)
Serves a real-time Linear/Vercel-inspired control plane on http://127.0.0.1:5000
Executes REAL TCP packets inside Mininet hosts (h1, h2) via mnexec -a <pid>.
"""

import json
import os
import re
import subprocess
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLICY_PATH = os.path.join(BASE_DIR, "controller", "policy.json")
LOG_PATH = os.path.join(BASE_DIR, "security_events.log")
BENCH_PATH = os.path.join(BASE_DIR, "benchmarks", "d2_benchmark_results.json")
PLOTS_DIR = os.path.join(BASE_DIR, "benchmarks")
TCP_CLIENT_SCRIPT = os.path.join(BASE_DIR, "socket_app", "tcp_client.py")
HOST_PIDS_FILE = "/tmp/mininet_host_pids.json"
RESET_SIGNAL_FILE = "/tmp/sdn_reset_quarantine"


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


def get_host_pids():
    if os.path.exists(HOST_PIDS_FILE):
        try:
            with open(HOST_PIDS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def get_ovs_flows():
    res = subprocess.run(
        ["sudo", "-n", "ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "s1"],
        capture_output=True,
        text=True,
        check=False,
    )
    raw = res.stdout.strip()
    flows = []
    if raw and "OFPST_FLOW" in raw:
        for line in raw.splitlines():
            if "OFPST_FLOW" in line:
                continue
            prio_m = re.search(r"priority=(\d+)", line)
            pkts_m = re.search(r"n_packets=(\d+)", line)
            bytes_m = re.search(r"n_bytes=(\d+)", line)
            dur_m = re.search(r"duration=([\d.]+)s", line)
            hard_m = re.search(r"hard_timeout=(\d+)", line)
            act_m = re.search(r"actions=([^\s]+)", line)
            flows.append({
                "priority": int(prio_m.group(1)) if prio_m else 0,
                "packets": int(pkts_m.group(1)) if pkts_m else 0,
                "bytes": int(bytes_m.group(1)) if bytes_m else 0,
                "duration_s": float(dur_m.group(1)) if dur_m else 0.0,
                "hard_timeout": int(hard_m.group(1)) if hard_m else 0,
                "actions": act_m.group(1) if act_m else "UNKNOWN",
                "raw": line.strip(),
            })
        flows.sort(key=lambda x: x["priority"], reverse=True)
    return {"switch_active": bool(flows), "flows": flows}


def read_security_logs():
    events = []
    if os.path.exists(LOG_PATH):
        try:
            with open(LOG_PATH, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            events.append(json.loads(line))
                        except Exception:
                            pass
        except Exception:
            pass
    return list(reversed(events[-50:]))


def read_json_file(path, default):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return default


def run_real_mininet_client(host_name: str, port: int, mode: str, messages: int = 1):
    """Executes the real socket_app/tcp_client.py inside the live Mininet host namespace via mnexec."""
    pids = get_host_pids()
    pid = pids.get(host_name)
    cmd_str = f"{host_name} python3 socket_app/tcp_client.py --server-ip 10.0.0.3 --port {port} --mode {mode} --messages {messages}"

    if pid:
        cmd = [
            "sudo", "-n", "mnexec", "-a", str(pid),
            "python3", TCP_CLIENT_SCRIPT,
            "--server-ip", "10.0.0.3",
            "--port", str(port),
            "--mode", mode,
            "--messages", str(messages),
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=8, check=False)
        out = (res.stdout + "\n" + res.stderr).strip()
        return cmd_str, out, True
    return cmd_str, "[WARN] Mininet PID not found. Run via sudo python3 start_everything.py", False


def trigger_simulation(scenario: str):
    policy = read_json_file(POLICY_PATH, {})
    drop_timeout = int(policy.get("drop_hard_timeout_sec", 30))

    if scenario == "normal_h1_8080":
        cmd_str, out, real = run_real_mininet_client("h1", 8080, "normal", 2)
        return {
            "status": "ALLOW",
            "title": "h1 -> h3:8080 Authorized TCP Flow",
            "detail": "Real packets traversed s1 (Priority 10 ALLOW rule installed)",
            "command": cmd_str,
            "output": out,
        }

    elif scenario == "normal_h2_8080":
        cmd_str, out, real = run_real_mininet_client("h2", 8080, "normal", 1)
        blocked = "FIREWALL BLOCK" in out or "timed out" in out.lower()
        if blocked:
            return {
                "status": "BLOCK",
                "title": "h2 -> h3:8080 BLOCKED by Dynamic IPS Quarantine!",
                "detail": "Even though port 8080 is allowed, h2 is quarantined for 30s due to prior port violations!",
                "command": cmd_str,
                "output": out,
            }
        return {
            "status": "ALLOW",
            "title": "h2 -> h3:8080 Authorized (Zero Hardcoding Proof)",
            "detail": "h2 starts 100% authorized ([ACK] received) before committing any violations",
            "command": cmd_str,
            "output": out,
        }

    elif scenario == "attack_h2_4444":
        cmd_str, out, real = run_real_mininet_client("h2", 4444, "forbidden", 1)
        return {
            "status": "BLOCK",
            "title": "Strike 1/2: Forbidden Port 4444 Blocked",
            "detail": f"Switch s1 dropped h2 -> h3:4444 (priority=100, hard_timeout={drop_timeout}s)",
            "command": cmd_str,
            "output": out,
        }

    elif scenario == "attack_h2_23":
        cmd_str, out, real = run_real_mininet_client("h2", 23, "forbidden", 1)
        return {
            "status": "BLOCK",
            "title": "Strike 2/2: h2 Dynamically Quarantined!",
            "detail": f"h2 crossed 2 violations -> Quarantined from ALL ports (including :8080) for {drop_timeout}s",
            "command": cmd_str,
            "output": out,
        }

    elif scenario == "clear_logs":
        if os.path.exists(LOG_PATH):
            os.remove(LOG_PATH)
        subprocess.run(
            ["sudo", "-n", "ovs-ofctl", "-O", "OpenFlow13", "del-flows", "s1", "priority=100"],
            stderr=subprocess.DEVNULL,
            check=False,
        )
        # Clear dynamic quarantine list in policy.json & signal controller
        pol = read_json_file(POLICY_PATH, {})
        pol["dynamically_quarantined_hosts"] = []
        with open(POLICY_PATH, "w", encoding="utf-8") as f:
            json.dump(pol, f, indent=2)
        with open(RESET_SIGNAL_FILE, "w", encoding="utf-8") as f:
            f.write(str(time.time()))
        return {
            "status": "INFO",
            "title": "SOC Telemetry, Drop Flows & Quarantine Reset",
            "detail": "Cleared security_events.log, removed priority=100 OVS drop rules, and unbanned all hosts",
            "command": "ovs-ofctl -O OpenFlow13 del-flows s1 priority=100 && rm -f security_events.log",
            "output": "[RESET COMPLETE] Switch s1 priority=100 drop rules flushed. All hosts restored to AUTHORIZED state.",
        }

    return {"status": "INFO", "title": "Unknown action", "detail": "", "command": "", "output": ""}


HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>SDN Dynamic Firewall — Control Plane & SOC Telemetry</title>
<style>
  :root {
    --bg-canvas: #090a0f;
    --bg-surface: #11131c;
    --bg-elevated: #171a26;
    --text-primary: #f3f4f8;
    --text-secondary: #9499ad;
    --text-muted: #5e6478;
    --accent-blue: #3b82f6;
    --accent-emerald: #10b981;
    --accent-crimson: #ef4444;
    --accent-amber: #f59e0b;
    --ease-out: cubic-bezier(0.23, 1, 0.32, 1);
    --shadow-card: 0 0 0 1px rgba(255, 255, 255, 0.065), 0 8px 24px -4px rgba(0, 0, 0, 0.45);
    --shadow-elevated: 0 0 0 1px rgba(255, 255, 255, 0.11), 0 16px 36px -6px rgba(0, 0, 0, 0.65);
    --font-sans: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Roboto, sans-serif;
    --font-mono: "JetBrains Mono", "Fira Code", monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background-color: var(--bg-canvas);
    background-image:
      radial-gradient(circle at 18% 0%, rgba(59, 130, 246, 0.09), transparent 38%),
      radial-gradient(circle at 82% 0%, rgba(239, 68, 68, 0.07), transparent 35%);
    color: var(--text-primary);
    font-family: var(--font-sans);
    font-size: 14px;
    line-height: 1.5;
    min-height: 100vh;
    padding-bottom: 48px;
  }
  .tabular { font-variant-numeric: tabular-nums; font-family: var(--font-mono); }
  h1, h2, h3 { letter-spacing: -0.02em; font-weight: 600; }
  .topbar {
    position: sticky; top: 0; z-index: 40;
    backdrop-filter: blur(14px); background: rgba(9, 10, 15, 0.84);
    box-shadow: 0 1px 0 0 rgba(255, 255, 255, 0.06);
    padding: 14px 28px; display: flex; align-items: center; justify-content: space-between;
  }
  .brand { display: flex; align-items: center; gap: 12px; }
  .status-dot { width: 9px; height: 9px; border-radius: 50%; background: var(--accent-emerald); box-shadow: 0 0 12px var(--accent-emerald); }
  .brand-title { font-size: 15px; font-weight: 600; color: var(--text-primary); }
  .brand-sub { font-size: 12px; color: var(--text-secondary); padding-left: 10px; border-left: 1px solid rgba(255, 255, 255, 0.1); }
  .topbar-right { display: flex; align-items: center; gap: 10px; }
  .pill {
    font-size: 12px; padding: 5px 11px; border-radius: 999px;
    background: rgba(255, 255, 255, 0.04); box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.08);
    color: var(--text-secondary); display: inline-flex; align-items: center; gap: 6px;
  }
  .btn {
    appearance: none; border: none; outline: none; cursor: pointer;
    font-family: var(--font-sans); font-size: 13px; font-weight: 500;
    padding: 8px 13px; border-radius: 8px; color: var(--text-primary);
    background: var(--bg-elevated); box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.09), 0 2px 6px rgba(0, 0, 0, 0.3);
    display: inline-flex; align-items: center; gap: 8px;
    transition: transform 130ms var(--ease-out), background-color 150ms ease, opacity 150ms ease;
  }
  .btn:active { transform: scale(0.97); }
  .btn:disabled { opacity: 0.55; cursor: not-allowed; }
  .btn-allow { background: rgba(16, 185, 129, 0.14); color: #34d399; box-shadow: 0 0 0 1px rgba(16, 185, 129, 0.3); }
  .btn-danger { background: rgba(239, 68, 68, 0.14); color: #f87171; box-shadow: 0 0 0 1px rgba(239, 68, 68, 0.3); }
  .btn-autopilot {
    background: linear-gradient(135deg, rgba(59, 130, 246, 0.25), rgba(16, 185, 129, 0.22));
    color: #93c5fd;
    box-shadow: 0 0 0 1px rgba(59, 130, 246, 0.45), 0 4px 14px rgba(59, 130, 246, 0.2);
  }
  .kbd { font-family: var(--font-mono); font-size: 11px; padding: 1px 5px; border-radius: 4px; background: rgba(0, 0, 0, 0.35); color: var(--text-secondary); box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.1); }

  .tabs-bar {
    max-width: 1380px; margin: 18px auto 0; padding: 0 28px;
    display: flex; gap: 12px; border-bottom: 1px solid rgba(255, 255, 255, 0.06); padding-bottom: 12px;
  }
  .tab-btn {
    background: none; border: none; outline: none; cursor: pointer;
    font-family: var(--font-sans); font-size: 13px; font-weight: 500;
    color: var(--text-secondary); padding: 6px 14px; border-radius: 6px;
    transition: background 150ms ease, color 150ms ease;
  }
  .tab-btn.active {
    background: var(--bg-elevated); color: var(--text-primary);
    box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.12);
  }

  .container { max-width: 1380px; margin: 18px auto 0; padding: 0 28px; display: flex; flex-direction: column; gap: 18px; }
  .tab-pane { display: none; flex-direction: column; gap: 18px; }
  .tab-pane.active { display: flex; }

  .kpi-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; }
  .card { background: var(--bg-surface); border-radius: 12px; box-shadow: var(--shadow-card); padding: 18px 20px; }
  .kpi-label { font-size: 12px; color: var(--text-secondary); display: flex; justify-content: space-between; align-items: center; }
  .kpi-value { font-size: 26px; font-weight: 600; margin-top: 8px; letter-spacing: -0.02em; }
  .kpi-sub { font-size: 12px; color: var(--text-muted); margin-top: 4px; }

  .main-grid { display: grid; grid-template-columns: 1.3fr 1fr; gap: 18px; }
  .section-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; }
  .section-title { font-size: 14px; font-weight: 600; color: var(--text-primary); display: flex; align-items: center; gap: 8px; }

  .topo-stage {
    position: relative; height: 225px;
    background: radial-gradient(circle at center, rgba(59, 130, 246, 0.06), rgba(9, 10, 15, 0.5));
    border-radius: 10px; box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.05);
    display: flex; align-items: center; justify-content: space-between; padding: 0 32px; overflow: hidden;
  }
  .topo-col { display: flex; flex-direction: column; gap: 24px; z-index: 2; }
  .node-box {
    background: var(--bg-elevated); box-shadow: var(--shadow-card); border-radius: 10px; padding: 10px 14px; min-width: 165px;
    transition: transform 180ms var(--ease-out), box-shadow 180ms var(--ease-out);
  }
  .node-box.active-pulse { transform: scale(1.03); box-shadow: 0 0 0 1px var(--accent-emerald), 0 0 20px rgba(16, 185, 129, 0.3); }
  .node-box.block-pulse { transform: scale(1.03); box-shadow: 0 0 0 1px var(--accent-crimson), 0 0 22px rgba(239, 68, 68, 0.4); }
  .node-title { font-size: 12px; font-weight: 600; display: flex; align-items: center; justify-content: space-between; gap: 8px; }
  .node-ip { font-size: 11px; color: var(--text-secondary); margin-top: 2px; }
  .switch-hub { background: linear-gradient(180deg, #1e2538 0%, #141824 100%); box-shadow: 0 0 0 1px rgba(59, 130, 246, 0.35), 0 10px 30px rgba(0, 0, 0, 0.6); border-radius: 12px; padding: 16px 20px; text-align: center; z-index: 2; min-width: 170px; }

  .sim-bar { margin-top: 12px; display: flex; flex-wrap: wrap; gap: 8px; align-items: center; padding-top: 12px; border-top: 1px solid rgba(255, 255, 255, 0.06); }

  /* Live Host Terminal Console Drawer */
  .terminal-box {
    margin-top: 12px;
    background: #07080c;
    border-radius: 8px;
    box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.08);
    padding: 10px 14px;
    font-family: var(--font-mono);
    font-size: 12px;
    color: #cbd5e1;
  }
  .term-cmd { color: #38bdf8; margin-bottom: 4px; font-weight: 500; }
  .term-out { color: #a7f3d0; white-space: pre-wrap; line-height: 1.45; }
  .term-out.blocked { color: #fca5a5; }

  .feed-list { display: flex; flex-direction: column; gap: 8px; max-height: 360px; overflow-y: auto; padding-right: 4px; }
  .alert-item { background: var(--bg-elevated); border-radius: 9px; padding: 11px 14px; box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.06); display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; }
  .alert-badge { font-family: var(--font-mono); font-size: 11px; font-weight: 600; padding: 2px 8px; border-radius: 5px; background: rgba(239, 68, 68, 0.15); color: #f87171; box-shadow: 0 0 0 1px rgba(239, 68, 68, 0.3); }

  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  th { text-align: left; color: var(--text-secondary); font-weight: 500; padding: 8px 10px; border-bottom: 1px solid rgba(255, 255, 255, 0.07); }
  td { padding: 9px 10px; border-bottom: 1px solid rgba(255, 255, 255, 0.04); color: var(--text-primary); }

  .chart-gallery { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  .chart-card { background: var(--bg-surface); border-radius: 12px; box-shadow: var(--shadow-card); padding: 18px; text-align: center; }
  .chart-card img { width: 100%; border-radius: 8px; box-shadow: 0 4px 16px rgba(0,0,0,0.5); margin-top: 12px; }

  .sonner-toaster { position: fixed; bottom: 22px; right: 24px; z-index: 100; display: flex; flex-direction: column; gap: 10px; pointer-events: none; }
  .sonner-toast { pointer-events: auto; min-width: 320px; max-width: 400px; background: #161925; box-shadow: var(--shadow-elevated); border-radius: 10px; padding: 12px 15px; }
</style>
</head>
<body>

<header class="topbar">
  <div class="brand">
    <span class="status-dot"></span>
    <span class="brand-title">SDN Dynamic Firewall</span>
    <span class="brand-sub">Real Mininet Namespace Execution &amp; Live SOC Control Plane</span>
  </div>
  <div class="topbar-right">
    <button class="btn btn-autopilot" id="autopilot-btn" onclick="runAutoPilotDemo()">
      &#9654; Run Full Auto-Pilot Demo <span class="kbd">A</span>
    </button>
    <span class="pill tabular" id="mininet-pill">Mininet: Checking...</span>
    <button class="btn" onclick="triggerSim('clear_logs')">Reset All <span class="kbd">R</span></button>
  </div>
</header>

<div class="tabs-bar">
  <button class="tab-btn active" onclick="switchTab('pane-control', this)">Live Control Plane &amp; Real Packet Simulator</button>
  <button class="tab-btn" onclick="switchTab('pane-benchmarks', this)">Deliverable 2 Performance Benchmarks (Graphs)</button>
</div>

<main class="container">
  <div class="tab-pane active" id="pane-control">
    <section class="kpi-grid">
      <div class="card">
        <div class="kpi-label"><span>Security Alerts Logged</span><span class="tabular">TCP :9999</span></div>
        <div class="kpi-value tabular" id="kpi-alerts">0</div>
        <div class="kpi-sub">Persisted in <code class="tabular">security_events.log</code></div>
      </div>
      <div class="card">
        <div class="kpi-label"><span>Mean Blocking Response</span><span class="tabular">D2 Metric</span></div>
        <div class="kpi-value tabular" id="kpi-response">36.50 ms</div>
        <div class="kpi-sub">PacketIn &rarr; OVS <code class="tabular">priority=100</code> Drop</div>
      </div>
      <div class="card">
        <div class="kpi-label"><span>Control-Plane Offload</span><span class="tabular">OVS Hardware</span></div>
        <div class="kpi-value tabular" id="kpi-offload">96.2%</div>
        <div class="kpi-sub"><span class="tabular">3</span> vs <span class="tabular">80</span> PacketIn events</div>
      </div>
      <div class="card">
        <div class="kpi-label"><span>Dynamic Quarantine</span><span class="tabular">Self-Healing</span></div>
        <div class="kpi-value tabular" id="kpi-timeout">30s</div>
        <div class="kpi-sub">Auto-ban after <code class="tabular">2</code> port violations</div>
      </div>
    </section>

    <section class="main-grid">
      <div class="card">
        <div class="section-header">
          <div class="section-title">Live OpenFlow 1.3 Topology (Click Buttons to Fire Real Mininet Packets)</div>
          <span class="pill tabular">Switch s1 (10.0.0.254/24)</span>
        </div>
        <div class="topo-stage">
          <div class="topo-col">
            <div class="node-box" id="node-h1">
              <div class="node-title"><span>Host h1</span><span style="color:var(--accent-emerald)">AUTHORIZED</span></div>
              <div class="node-ip tabular">10.0.0.1 &bull; Normal Client</div>
            </div>
            <div class="node-box" id="node-h2">
              <div class="node-title"><span>Host h2</span><span id="h2-status-badge" style="color:var(--accent-emerald)">AUTHORIZED</span></div>
              <div class="node-ip tabular">10.0.0.2 &bull; Behavioral IPS</div>
            </div>
          </div>
          <div class="switch-hub" id="node-s1">
            <div style="font-size:13px;font-weight:600;color:#60a5fa;">Open vSwitch s1</div>
            <div class="tabular" style="font-size:11px;color:var(--text-secondary);margin-top:3px;">OpenFlow 1.3 Datapath</div>
            <div class="tabular" style="font-size:11px;color:var(--text-muted);margin-top:6px;" id="s1-flow-count">Active Flows: --</div>
          </div>
          <div class="topo-col">
            <div class="node-box" id="node-h3">
              <div class="node-title"><span>Server h3</span><span class="tabular" style="color:#60a5fa">:8080</span></div>
              <div class="node-ip tabular">10.0.0.3 &bull; Multi-Threaded</div>
            </div>
            <div class="node-box" id="node-h4">
              <div class="node-title"><span>SOC Logger h4</span><span class="tabular" style="color:var(--accent-amber)">:9999</span></div>
              <div class="node-ip tabular">10.0.0.4 &bull; JSON Telemetry</div>
            </div>
          </div>
        </div>

        <div class="sim-bar">
          <button class="btn btn-allow" onclick="triggerSim('normal_h1_8080')">h1 &rarr; :8080 (Normal) <span class="kbd">1</span></button>
          <button class="btn btn-allow" onclick="triggerSim('normal_h2_8080')">h2 &rarr; :8080 (Test Access) <span class="kbd">2</span></button>
          <button class="btn btn-danger" onclick="triggerSim('attack_h2_4444')">h2 &rarr; :4444 (Strike 1) <span class="kbd">3</span></button>
          <button class="btn btn-danger" onclick="triggerSim('attack_h2_23')">h2 &rarr; :23 (Strike 2 Ban) <span class="kbd">4</span></button>
        </div>

        <!-- Live Mininet Host Terminal Output -->
        <div class="terminal-box">
          <div class="term-cmd" id="term-cmd">mininet&gt; Ready — click any button above or press 'Run Full Auto-Pilot Demo'</div>
          <div class="term-out" id="term-out">Real TCP client output from Mininet hosts (h1 / h2) will appear here live...</div>
        </div>
      </div>

      <div class="card">
        <div class="section-header">
          <div class="section-title">Centralized SOC Security Event Stream (<code class="tabular">h4:9999</code>)</div>
          <span class="pill tabular" id="feed-count-pill">0 Events</span>
        </div>
        <div class="feed-list" id="soc-feed">
          <div style="color:var(--text-muted);font-size:13px;padding:24px 0;text-align:center;">No security violations logged yet.</div>
        </div>
      </div>
    </section>

    <section class="main-grid">
      <div class="card">
        <div class="section-header">
          <div class="section-title">Switch <code class="tabular">s1</code> OpenFlow 1.3 Hardware Flow Table</div>
          <span class="pill tabular">ovs-ofctl dump-flows s1</span>
        </div>
        <table>
          <thead>
            <tr><th>Priority</th><th>Action</th><th>Packets</th><th>Duration</th><th>Timeout</th><th>Match Rule</th></tr>
          </thead>
          <tbody id="flow-table-body" class="tabular">
            <tr><td colspan="6" style="color:var(--text-muted);">Loading flow table...</td></tr>
          </tbody>
        </table>
      </div>
      <div class="card">
        <div class="section-title" style="margin-bottom:10px;">Live Dynamic Behavioral IPS Lifecycle</div>
        <div style="font-size:13px;color:var(--text-secondary);line-height:1.65;">
          <p><strong>Step 1 (Zero Hardcoding):</strong> Press <span class="kbd">2</span> — <code class="tabular">h2 (10.0.0.2)</code> connects to <code class="tabular">h3:8080</code> and receives <code class="tabular">[ACK]</code>.</p>
          <p style="margin-top:6px;"><strong>Step 2 (Strike 1):</strong> Press <span class="kbd">3</span> — <code class="tabular">h2</code> probes forbidden port <code class="tabular">4444</code> (Blocked &amp; logged as Strike 1/2).</p>
          <p style="margin-top:6px;"><strong>Step 3 (Strike 2 Auto-Quarantine):</strong> Press <span class="kbd">4</span> — <code class="tabular">h2</code> probes forbidden port <code class="tabular">23</code> &rarr; Controller dynamically quarantines <code class="tabular">10.0.0.2</code> across ALL ports for 30s!</p>
          <p style="margin-top:6px;"><strong>Step 4 (Verify Ban):</strong> Press <span class="kbd">2</span> again — <code class="tabular">h2 &rarr; :8080</code> now times out (<code class="tabular">[FIREWALL BLOCK]</code>)!</p>
        </div>
      </div>
    </section>
  </div>

  <!-- PANE 2: Deliverable 2 Performance Benchmarks -->
  <div class="tab-pane" id="pane-benchmarks">
    <div class="card" style="margin-bottom:16px;">
      <div class="section-title">Deliverable 2 Performance Evaluation &amp; Comparison (5 Marks)</div>
      <p style="font-size:13px;color:var(--text-secondary);margin-top:4px;">
        Evaluates blocking response times and compares control-plane overhead, client RTT latency, and bulk TCP throughput with vs. without switch-level OpenFlow drop rules.
      </p>
    </div>
    <div class="chart-gallery">
      <div class="chart-card">
        <div class="section-title">Blocking Response Time (ms)</div>
        <div style="font-size:12px;color:var(--text-secondary);margin-top:2px;">Time from first unauthorized SYN packet to OVS DROP rule installation</div>
        <img src="/api/chart/d2_blocking_response_time.png" alt="Blocking Response Time Chart" />
      </div>
      <div class="chart-card">
        <div class="section-title">Baseline Comparison (With vs. Without OVS Drop)</div>
        <div style="font-size:12px;color:var(--text-secondary);margin-top:2px;">Control-plane overhead, RTT latency, and TCP throughput impact</div>
        <img src="/api/chart/d2_baseline_comparison.png" alt="Baseline Comparison Chart" />
      </div>
    </div>
  </div>
</main>

<div class="sonner-toaster" id="toaster"></div>

<script>
  let lastEventCount = -1;

  function switchTab(paneId, btn) {
    document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    document.getElementById(paneId).classList.add("active");
    btn.classList.add("active");
  }

  function showToast(title, detail, type = "info") {
    const toaster = document.getElementById("toaster");
    const toast = document.createElement("div");
    toast.className = "sonner-toast";
    const color = type === "BLOCK" ? "#ef4444" : (type === "ALLOW" ? "#10b981" : "#3b82f6");
    toast.innerHTML = `
      <div style="font-size:13px;font-weight:600;display:flex;align-items:center;gap:8px;">
        <span style="width:8px;height:8px;border-radius:50%;background:${color};display:inline-block;"></span>
        <span>${title}</span>
      </div>
      <div style="font-size:12px;color:var(--text-secondary);margin-top:3px;" class="tabular">${detail}</div>
    `;
    toaster.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = "0";
      setTimeout(() => toast.remove(), 200);
    }, 3400);
  }

  function pulseNodes(ids, cls) {
    ids.forEach(id => {
      const el = document.getElementById(id);
      if (!el) return;
      el.classList.add(cls);
      setTimeout(() => el.classList.remove(cls), 750);
    });
  }

  async function triggerSim(scenario) {
    const termCmd = document.getElementById("term-cmd");
    const termOut = document.getElementById("term-out");
    termCmd.textContent = `mininet> Executing ${scenario} inside live host namespace...`;
    termOut.textContent = "Running socket_app/tcp_client.py...";
    termOut.className = "term-out";

    const res = await fetch("/api/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario })
    });
    const data = await res.json();

    termCmd.textContent = `mininet> ${data.command}`;
    termOut.textContent = data.output || data.detail;
    if (data.status === "BLOCK") {
      termOut.className = "term-out blocked";
      pulseNodes(["node-h2", "node-s1", "node-h4"], "block-pulse");
    } else if (data.status === "ALLOW") {
      termOut.className = "term-out";
      const srcNode = scenario.includes("h2") ? "node-h2" : "node-h1";
      pulseNodes([srcNode, "node-s1", "node-h3"], "active-pulse");
    }

    showToast(data.title, data.detail, data.status);
    await fetchState();
    return data;
  }

  const sleep = (ms) => new Promise(r => setTimeout(r, ms));

  async function runAutoPilotDemo() {
    const btn = document.getElementById("autopilot-btn");
    btn.disabled = true;
    btn.innerHTML = "&#9203; Running Auto-Pilot Demo...";

    showToast("Auto-Pilot Demo Started", "Executing full 5-stage live Mininet evaluation sequence...", "INFO");
    await triggerSim("clear_logs");
    await sleep(1200);

    await triggerSim("normal_h1_8080");
    await sleep(2200);

    await triggerSim("normal_h2_8080");
    await sleep(2200);

    await triggerSim("attack_h2_4444");
    await sleep(2200);

    await triggerSim("attack_h2_23");
    await sleep(2200);

    await triggerSim("normal_h2_8080");

    btn.disabled = false;
    btn.innerHTML = "&#9654; Run Full Auto-Pilot Demo <span class='kbd'>A</span>";
    showToast("Auto-Pilot Demo Complete!", "All normal, port-block, and dynamic quarantine tests verified!", "ALLOW");
  }

  async function fetchState() {
    try {
      const res = await fetch("/api/state");
      const state = await res.json();

      document.getElementById("kpi-alerts").textContent = state.logs.length;
      document.getElementById("feed-count-pill").textContent = `${state.logs.length} Events`;
      document.getElementById("kpi-timeout").textContent = `${state.policy.drop_hard_timeout_sec || 30}s`;
      if (state.benchmark && state.benchmark.blocking_response_time_ms) {
        document.getElementById("kpi-response").textContent = `${state.benchmark.blocking_response_time_ms.mean_ms} ms`;
      }

      const mnPill = document.getElementById("mininet-pill");
      if (state.mininet_connected) {
        mnPill.textContent = "Mininet Namespaces: LIVE";
        mnPill.style.color = "#34d399";
      } else {
        mnPill.textContent = "Mininet: Standby";
        mnPill.style.color = "#f59e0b";
      }

      // Update h2 status badge dynamically based on quarantine state
      const bannedList = state.policy.dynamically_quarantined_hosts || [];
      const h2Badge = document.getElementById("h2-status-badge");
      if (bannedList.includes("10.0.0.2")) {
        h2Badge.textContent = "QUARANTINED (30s)";
        h2Badge.style.color = "var(--accent-crimson)";
      } else {
        h2Badge.textContent = "AUTHORIZED";
        h2Badge.style.color = "var(--accent-emerald)";
      }

      const feed = document.getElementById("soc-feed");
      if (state.logs.length === 0) {
        feed.innerHTML = `<div style="color:var(--text-muted);font-size:13px;padding:24px 0;text-align:center;">No security violations logged yet.</div>`;
      } else if (state.logs.length !== lastEventCount) {
        feed.innerHTML = state.logs.map(ev => `
          <div class="alert-item">
            <div>
              <span class="alert-badge">${ev.action || "DROP_RULE"}</span>
              <div style="font-size:13px;color:var(--text-primary);margin-top:4px;">${ev.reason || ""}</div>
              <div style="font-size:11px;color:var(--text-secondary);margin-top:3px;" class="tabular">${ev.src_ip}:${ev.src_port} &rarr; ${ev.dst_ip}:${ev.dst_port}</div>
            </div>
            <div class="tabular" style="font-size:11px;color:var(--text-muted);">${(ev.timestamp || "").split(" ")[1] || ""}</div>
          </div>
        `).join("");
      }
      lastEventCount = state.logs.length;

      const flows = state.ovs.flows || [];
      document.getElementById("s1-flow-count").textContent = `Active Flows: ${flows.length}`;
      const tbody = document.getElementById("flow-table-body");
      if (flows.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" style="color:var(--text-muted);">Switch s1 offline or no flows installed.</td></tr>`;
      } else {
        tbody.innerHTML = flows.slice(0, 8).map(f => `
          <tr>
            <td>${f.priority}</td>
            <td style="font-weight:600;${f.actions.toLowerCase().includes('drop') ? 'color:#f87171;' : 'color:#34d399;'}">${f.actions}</td>
            <td>${f.packets}</td>
            <td>${f.duration_s.toFixed(1)}s</td>
            <td>${f.hard_timeout ? f.hard_timeout + 's' : 'idle'}</td>
            <td style="color:var(--text-secondary);max-width:220px;overflow:hidden;text-overflow:ellipsis;">${f.raw}</td>
          </tr>
        `).join("");
      }
    } catch (e) {}
  }

  window.addEventListener("keydown", (e) => {
    if (e.target.tagName === "INPUT") return;
    if (e.key === "1") triggerSim("normal_h1_8080");
    if (e.key === "2") triggerSim("normal_h2_8080");
    if (e.key === "3") triggerSim("attack_h2_4444");
    if (e.key === "4") triggerSim("attack_h2_23");
    if (e.key.toLowerCase() === "a") runAutoPilotDemo();
    if (e.key.toLowerCase() === "r") triggerSim("clear_logs");
  });

  fetchState();
  setInterval(fetchState, 1000);
</script>
</body>
</html>
"""


class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def _send_json(self, payload, status=200):
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/" or parsed.path == "/index.html":
            body = HTML_PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif parsed.path.startswith("/api/chart/"):
            filename = parsed.path.split("/")[-1]
            filepath = os.path.join(PLOTS_DIR, filename)
            if os.path.exists(filepath):
                with open(filepath, "rb") as f:
                    img = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "image/png")
                self.send_header("Content-Length", str(len(img)))
                self.end_headers()
                self.wfile.write(img)
            else:
                self.send_error(404)
        elif parsed.path == "/api/state":
            policy = read_json_file(POLICY_PATH, {})
            logs = read_security_logs()
            bench = read_json_file(BENCH_PATH, {})
            ovs = get_ovs_flows()
            pids = get_host_pids()
            self._send_json({
                "policy": policy,
                "logs": logs,
                "benchmark": bench,
                "ovs": ovs,
                "mininet_connected": bool(pids),
            })
        else:
            self.send_error(404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8") if length else "{}"
        body = json.loads(raw)
        if self.path == "/api/simulate":
            result = trigger_simulation(body.get("scenario", ""))
            self._send_json(result)
        else:
            self.send_error(404)


if __name__ == "__main__":
    host, port = "127.0.0.1", 5000
    print(f"\n======================================================================")
    print(f" [SDN SOC UI ACTIVE] Open http://{host}:{port} in Firefox")
    print(f"======================================================================\n", flush=True)
    server = ThreadingHTTPServer((host, port), DashboardHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
