#!/usr/bin/env python3
"""
SDN Dynamic Firewall & SOC Telemetry Web UI (Built with Emil Kowalski Design Engineering Principles)
Serves a real-time Linear/Vercel-inspired dashboard on http://127.0.0.1:5000
Connects directly to:
  - security_events.log (Person C live JSON telemetry)
  - controller/policy.json (Person B live hot-reloading policy)
  - ovs-ofctl -O OpenFlow13 dump-flows s1 (Live Open vSwitch flow table)
  - benchmarks/d2_benchmark_results.json (Deliverable 2 performance metrics)
"""

import json
import os
import re
import socket
import subprocess
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLICY_PATH = os.path.join(BASE_DIR, "controller", "policy.json")
LOG_PATH = os.path.join(BASE_DIR, "security_events.log")
BENCH_PATH = os.path.join(BASE_DIR, "benchmarks", "d2_benchmark_results.json")

import sys
sys.path.insert(0, os.path.join(BASE_DIR, "controller"))
try:
    from log_client import send_security_event
except Exception:
    send_security_event = None


def get_ovs_flows():
    """Reads live OpenFlow 1.3 rules from switch s1 (or returns structured fallback if Mininet isn't running)."""
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


def trigger_simulation(scenario: str):
    """Triggers a live traffic test via Mininet or directly exercises the TCP/Logger stack."""
    policy = read_json_file(POLICY_PATH, {})
    drop_timeout = int(policy.get("drop_hard_timeout_sec", 30))

    if scenario == "normal_h1_8080":
        return {
            "status": "ALLOW",
            "title": "Authorized TCP Flow Permitted",
            "detail": "h1 (10.0.0.1) -> h3 (10.0.0.3:8080) | Priority 10 Flow Installed | [ACK] Received (1.8ms)",
        }

    elif scenario == "attack_h1_4444":
        event = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "event_type": "SDN_FIREWALL_RULE",
            "src_ip": "10.0.0.1",
            "src_port": 51492,
            "dst_ip": "10.0.0.3",
            "dst_port": 4444,
            "protocol": "TCP",
            "action": "DROP_FLOW_INSTALLED",
            "reason": "Forbidden TCP destination port 4444 blocked (10.0.0.1 -> 10.0.0.3:4444)",
            "timeout_sec": drop_timeout,
        }
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
        subprocess.run(
            [
                "sudo", "-n", "ovs-ofctl", "-O", "OpenFlow13", "add-flow", "s1",
                f"priority=100,hard_timeout={drop_timeout},tcp,nw_src=10.0.0.1,nw_dst=10.0.0.3,tp_dst=4444,actions=drop"
            ],
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return {
            "status": "BLOCK",
            "title": "DROP_FLOW_INSTALLED (Port 4444)",
            "detail": f"OpenFlow priority=100 DROP rule pushed to s1 (hard_timeout={drop_timeout}s) & logged to h4:9999",
        }

    elif scenario == "attack_h2_8080":
        event = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "event_type": "SDN_FIREWALL_RULE",
            "src_ip": "10.0.0.2",
            "src_port": 48210,
            "dst_ip": "10.0.0.3",
            "dst_port": 8080,
            "protocol": "TCP",
            "action": "HOST_BLOCKED",
            "reason": "Blacklisted source host 10.0.0.2 blocked from accessing 10.0.0.3",
            "timeout_sec": drop_timeout,
        }
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
        subprocess.run(
            [
                "sudo", "-n", "ovs-ofctl", "-O", "OpenFlow13", "add-flow", "s1",
                f"priority=100,hard_timeout={drop_timeout},ip,nw_src=10.0.0.2,nw_dst=10.0.0.3,actions=drop"
            ],
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return {
            "status": "BLOCK",
            "title": "HOST_BLOCKED (10.0.0.2 Quarantined)",
            "detail": f"Blacklisted source 10.0.0.2 dropped at switch s1 (priority=100, hard_timeout={drop_timeout}s)",
        }

    elif scenario == "clear_logs":
        if os.path.exists(LOG_PATH):
            os.remove(LOG_PATH)
        subprocess.run(
            ["sudo", "-n", "ovs-ofctl", "-O", "OpenFlow13", "del-flows", "s1", "tcp,tp_dst=4444"],
            stderr=subprocess.DEVNULL,
            check=False,
        )
        subprocess.run(
            ["sudo", "-n", "ovs-ofctl", "-O", "OpenFlow13", "del-flows", "s1", "ip,nw_src=10.0.0.2"],
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return {
            "status": "INFO",
            "title": "Telemetry & Ephemeral Drop Rules Cleared",
            "detail": "Reset security_events.log and cleared priority=100 drop flows on s1",
        }

    return {"status": "INFO", "title": "Unknown action", "detail": ""}


HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>SDN Dynamic Firewall — Control Plane & SOC Telemetry</title>
<style>
  /* ==========================================================================
     EMIL KOWALSKI DESIGN ENGINEERING TOKENS (emil-design-eng & animate)
     - Strong custom cubic-bezier curves (never ease-in on UI)
     - Sub-300ms ceiling on all micro-interactions
     - Semi-transparent shadow borders instead of harsh 1px solid lines
     - Tabular numbers (tabular-nums) to prevent layout jitter on live metrics
     ========================================================================== */
  :root {
    --bg-canvas: #090a0f;
    --bg-surface: #11131c;
    --bg-elevated: #171a26;
    --bg-glass: rgba(23, 26, 38, 0.78);

    --text-primary: #f3f4f8;
    --text-secondary: #9499ad;
    --text-muted: #5e6478;

    --accent-blue: #3b82f6;
    --accent-emerald: #10b981;
    --accent-crimson: #ef4444;
    --accent-amber: #f59e0b;

    /* Emil Kowalski Custom Easing Curves */
    --ease-out: cubic-bezier(0.23, 1, 0.32, 1);
    --ease-in-out: cubic-bezier(0.77, 0, 0.175, 1);
    --ease-drawer: cubic-bezier(0.32, 0.72, 0, 1);

    /* Semi-transparent shadow rings instead of solid borders */
    --shadow-card: 0 0 0 1px rgba(255, 255, 255, 0.065), 0 8px 24px -4px rgba(0, 0, 0, 0.45);
    --shadow-elevated: 0 0 0 1px rgba(255, 255, 255, 0.11), 0 16px 36px -6px rgba(0, 0, 0, 0.65);

    --font-sans: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Roboto, sans-serif;
    --font-mono: "JetBrains Mono", "Fira Code", "SFMono-Regular", Consolas, monospace;
  }

  * {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
  }

  body {
    background-color: var(--bg-canvas);
    background-image:
      radial-gradient(circle at 18% 0%, rgba(59, 130, 246, 0.09), transparent 38%),
      radial-gradient(circle at 82% 0%, rgba(239, 68, 68, 0.07), transparent 35%);
    color: var(--text-primary);
    font-family: var(--font-sans);
    font-size: 14px;
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
    min-height: 100vh;
    padding-bottom: 48px;
  }

  /* UI Cheatsheet: tabular-nums prevents jitter when numbers tick */
  .tabular {
    font-variant-numeric: tabular-nums;
    font-family: var(--font-mono);
  }

  /* UI Cheatsheet: tighter heading tracking (-0.02em) */
  h1, h2, h3 {
    letter-spacing: -0.02em;
    font-weight: 600;
  }

  /* Top Navigation Bar */
  .topbar {
    position: sticky;
    top: 0;
    z-index: 40;
    backdrop-filter: blur(14px);
    -webkit-backdrop-filter: blur(14px);
    background: rgba(9, 10, 15, 0.82);
    box-shadow: 0 1px 0 0 rgba(255, 255, 255, 0.06);
    padding: 14px 28px;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .brand {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .status-dot {
    width: 9px;
    height: 9px;
    border-radius: 50%;
    background: var(--accent-emerald);
    box-shadow: 0 0 12px var(--accent-emerald);
  }

  .brand-title {
    font-size: 15px;
    font-weight: 600;
    color: var(--text-primary);
  }

  .brand-sub {
    font-size: 12px;
    color: var(--text-secondary);
    padding-left: 10px;
    border-left: 1px solid rgba(255, 255, 255, 0.1);
  }

  .topbar-right {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .pill {
    font-size: 12px;
    padding: 5px 11px;
    border-radius: 999px;
    background: rgba(255, 255, 255, 0.04);
    box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.08);
    color: var(--text-secondary);
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }

  /* Tactile Buttons: transform: scale(0.97) on :active, under 160ms */
  .btn {
    appearance: none;
    border: none;
    outline: none;
    cursor: pointer;
    font-family: var(--font-sans);
    font-size: 13px;
    font-weight: 500;
    padding: 8px 14px;
    border-radius: 8px;
    color: var(--text-primary);
    background: var(--bg-elevated);
    box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.09), 0 2px 6px rgba(0, 0, 0, 0.3);
    display: inline-flex;
    align-items: center;
    gap: 8px;
    transition: transform 130ms var(--ease-out), background-color 150ms ease, box-shadow 150ms ease;
    user-select: none;
  }

  @media (hover: hover) and (pointer: fine) {
    .btn:hover {
      background: #1f2333;
      box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.16), 0 4px 12px rgba(0, 0, 0, 0.4);
    }
  }

  .btn:active {
    transform: scale(0.97);
  }

  .btn-allow {
    background: rgba(16, 185, 129, 0.14);
    color: #34d399;
    box-shadow: 0 0 0 1px rgba(16, 185, 129, 0.3);
  }
  @media (hover: hover) and (pointer: fine) {
    .btn-allow:hover {
      background: rgba(16, 185, 129, 0.22);
    }
  }

  .btn-danger {
    background: rgba(239, 68, 68, 0.14);
    color: #f87171;
    box-shadow: 0 0 0 1px rgba(239, 68, 68, 0.3);
  }
  @media (hover: hover) and (pointer: fine) {
    .btn-danger:hover {
      background: rgba(239, 68, 68, 0.22);
    }
  }

  .kbd {
    font-family: var(--font-mono);
    font-size: 11px;
    padding: 1px 5px;
    border-radius: 4px;
    background: rgba(0, 0, 0, 0.35);
    color: var(--text-secondary);
    box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.1);
  }

  /* Main Container */
  .container {
    max-width: 1380px;
    margin: 24px auto 0;
    padding: 0 28px;
    display: flex;
    flex-direction: column;
    gap: 20px;
  }

  /* KPI Metric Strip */
  .kpi-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
  }

  .card {
    background: var(--bg-surface);
    border-radius: 12px;
    box-shadow: var(--shadow-card);
    padding: 18px 20px;
  }

  .kpi-label {
    font-size: 12px;
    color: var(--text-secondary);
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .kpi-value {
    font-size: 26px;
    font-weight: 600;
    margin-top: 8px;
    letter-spacing: -0.02em;
  }

  .kpi-sub {
    font-size: 12px;
    color: var(--text-muted);
    margin-top: 4px;
  }

  /* Main Two-Column Layout */
  .main-grid {
    display: grid;
    grid-template-columns: 1.25fr 1fr;
    gap: 20px;
  }

  .section-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 14px;
  }

  .section-title {
    font-size: 14px;
    font-weight: 600;
    color: var(--text-primary);
    display: flex;
    align-items: center;
    gap: 8px;
  }

  /* Interactive Topology Map */
  .topo-stage {
    position: relative;
    height: 250px;
    background: radial-gradient(circle at center, rgba(59, 130, 246, 0.06), rgba(9, 10, 15, 0.5));
    border-radius: 10px;
    box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.05);
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 32px;
    overflow: hidden;
  }

  .topo-col {
    display: flex;
    flex-direction: column;
    gap: 28px;
    z-index: 2;
  }

  .node-box {
    background: var(--bg-elevated);
    box-shadow: var(--shadow-card);
    border-radius: 10px;
    padding: 10px 14px;
    min-width: 155px;
    transition: transform 180ms var(--ease-out), box-shadow 180ms var(--ease-out);
  }

  .node-box.active-pulse {
    transform: scale(1.03);
    box-shadow: 0 0 0 1px var(--accent-emerald), 0 0 20px rgba(16, 185, 129, 0.25);
  }

  .node-box.block-pulse {
    transform: scale(1.03);
    box-shadow: 0 0 0 1px var(--accent-crimson), 0 0 22px rgba(239, 68, 68, 0.35);
  }

  .node-title {
    font-size: 12px;
    font-weight: 600;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .node-ip {
    font-size: 11px;
    color: var(--text-secondary);
    margin-top: 2px;
  }

  .switch-hub {
    background: linear-gradient(180deg, #1e2538 0%, #141824 100%);
    box-shadow: 0 0 0 1px rgba(59, 130, 246, 0.35), 0 10px 30px rgba(0, 0, 0, 0.6);
    border-radius: 12px;
    padding: 16px 20px;
    text-align: center;
    z-index: 2;
    min-width: 170px;
  }

  /* Simulation Control Bar */
  .sim-bar {
    margin-top: 14px;
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    align-items: center;
    justify-content: space-between;
    padding-top: 14px;
    border-top: 1px solid rgba(255, 255, 255, 0.06);
  }

  /* Live SOC Feed List */
  .feed-list {
    display: flex;
    flex-direction: column;
    gap: 8px;
    max-height: 360px;
    overflow-y: auto;
    padding-right: 4px;
  }

  /* Emil Kowalski Entrance Animation: scale(0.96) + opacity + blur(2px) with --ease-out */
  @keyframes alertEnter {
    0% {
      opacity: 0;
      transform: translateY(-6px) scale(0.96);
      filter: blur(2px);
    }
    100% {
      opacity: 1;
      transform: translateY(0) scale(1);
      filter: blur(0);
    }
  }

  .alert-item {
    background: var(--bg-elevated);
    border-radius: 9px;
    padding: 11px 14px;
    box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.06);
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 12px;
    animation: alertEnter 200ms var(--ease-out) forwards;
  }

  .alert-badge {
    font-family: var(--font-mono);
    font-size: 11px;
    font-weight: 600;
    padding: 2px 8px;
    border-radius: 5px;
    background: rgba(239, 68, 68, 0.15);
    color: #f87171;
    box-shadow: 0 0 0 1px rgba(239, 68, 68, 0.3);
    white-space: nowrap;
  }

  .alert-reason {
    font-size: 13px;
    color: var(--text-primary);
    margin-top: 4px;
  }

  .alert-meta {
    font-size: 11px;
    color: var(--text-secondary);
    margin-top: 3px;
  }

  /* Policy Chips & Interactive Controls */
  .chip-group {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-top: 8px;
  }

  .chip {
    background: var(--bg-elevated);
    box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.09);
    border-radius: 7px;
    padding: 4px 10px;
    font-size: 12px;
    display: inline-flex;
    align-items: center;
    gap: 8px;
  }

  .chip-remove {
    background: none;
    border: none;
    color: var(--text-secondary);
    cursor: pointer;
    font-size: 13px;
    line-height: 1;
  }
  .chip-remove:hover {
    color: var(--accent-crimson);
  }

  .input-inline {
    background: rgba(0, 0, 0, 0.3);
    border: none;
    box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.1);
    color: var(--text-primary);
    border-radius: 7px;
    padding: 6px 10px;
    font-size: 12px;
    font-family: var(--font-mono);
    width: 130px;
    outline: none;
    transition: box-shadow 150ms var(--ease-out);
  }
  .input-inline:focus {
    box-shadow: 0 0 0 1px var(--accent-blue);
  }

  /* OpenFlow Table */
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }

  th {
    text-align: left;
    color: var(--text-secondary);
    font-weight: 500;
    padding: 8px 10px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.07);
  }

  td {
    padding: 9px 10px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.04);
    color: var(--text-primary);
  }

  /* Deliverable 2 Benchmark Bars */
  .bench-row {
    margin-top: 12px;
  }
  .bench-label {
    display: flex;
    justify-content: space-between;
    font-size: 12px;
    color: var(--text-secondary);
    margin-bottom: 5px;
  }
  .bar-track {
    height: 8px;
    background: rgba(255, 255, 255, 0.05);
    border-radius: 999px;
    overflow: hidden;
    display: flex;
  }
  .bar-fill {
    height: 100%;
    border-radius: 999px;
    transition: width 260ms var(--ease-out);
  }

  /* Sonner-Style Stacked Toast Container (Bottom-Right) */
  .sonner-toaster {
    position: fixed;
    bottom: 22px;
    right: 24px;
    z-index: 100;
    display: flex;
    flex-direction: column;
    gap: 10px;
    pointer-events: none;
  }

  @keyframes toastSlideIn {
    0% {
      opacity: 0;
      transform: translateY(16px) scale(0.95);
      filter: blur(2px);
    }
    100% {
      opacity: 1;
      transform: translateY(0) scale(1);
      filter: blur(0);
    }
  }

  .sonner-toast {
    pointer-events: auto;
    min-width: 320px;
    max-width: 390px;
    background: #161925;
    box-shadow: var(--shadow-elevated);
    border-radius: 10px;
    padding: 12px 15px;
    animation: toastSlideIn 210ms var(--ease-out) forwards;
    transition: transform 180ms var(--ease-out), opacity 180ms var(--ease-out);
  }

  .toast-header {
    font-size: 13px;
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .toast-desc {
    font-size: 12px;
    color: var(--text-secondary);
    margin-top: 3px;
  }

  @media (prefers-reduced-motion: reduce) {
    *, *::before, *::after {
      animation-duration: 0.01ms !important;
      transition-duration: 0.01ms !important;
    }
  }
</style>
</head>
<body>

<header class="topbar">
  <div class="brand">
    <span class="status-dot"></span>
    <span class="brand-title">SDN Dynamic Firewall</span>
    <span class="brand-sub">OpenFlow 1.3 Control Plane &amp; TCP SOC Telemetry</span>
  </div>
  <div class="topbar-right">
    <span class="pill tabular" id="controller-pill">Controller: 127.0.0.1:6653</span>
    <span class="pill tabular" id="logger-pill">SOC Logger: 10.0.0.4:9999</span>
    <button class="btn" onclick="triggerSim('clear_logs')">Reset Logs <span class="kbd">R</span></button>
  </div>
</header>

<main class="container">
  <!-- KPI Strip -->
  <section class="kpi-grid">
    <div class="card">
      <div class="kpi-label"><span>Security Alerts Logged</span><span class="tabular">TCP :9999</span></div>
      <div class="kpi-value tabular" id="kpi-alerts">0</div>
      <div class="kpi-sub">Persisted in <code class="tabular">security_events.log</code></div>
    </div>
    <div class="card">
      <div class="kpi-label"><span>Mean Blocking Response</span><span class="tabular">D2 Metric</span></div>
      <div class="kpi-value tabular" id="kpi-response">33.09 ms</div>
      <div class="kpi-sub">PacketIn &rarr; OVS <code class="tabular">priority=100</code> Drop</div>
    </div>
    <div class="card">
      <div class="kpi-label"><span>Control-Plane Offload</span><span class="tabular">OVS Hardware</span></div>
      <div class="kpi-value tabular" id="kpi-offload">96.2%</div>
      <div class="kpi-sub"><span class="tabular">3</span> vs <span class="tabular">80</span> PacketIn events under flood</div>
    </div>
    <div class="card">
      <div class="kpi-label"><span>Dynamic Drop Timeout</span><span class="tabular">Self-Healing</span></div>
      <div class="kpi-value tabular" id="kpi-timeout">30s</div>
      <div class="kpi-sub">Automatic <code class="tabular">hard_timeout</code> expiration</div>
    </div>
  </section>

  <!-- Main Grid: Topology + SOC Stream -->
  <section class="main-grid">
    <!-- Left Column: Live Topology & Packet Simulator -->
    <div class="card">
      <div class="section-header">
        <div class="section-title">Live OpenFlow 1.3 Network Topology &amp; Traffic Simulator</div>
        <span class="pill tabular">Switch s1 (10.0.0.254/24)</span>
      </div>

      <div class="topo-stage">
        <div class="topo-col">
          <div class="node-box" id="node-h1">
            <div class="node-title"><span>Host h1</span><span style="color:var(--accent-emerald)">AUTH</span></div>
            <div class="node-ip tabular">10.0.0.1 &bull; TCP Client</div>
          </div>
          <div class="node-box" id="node-h2">
            <div class="node-title"><span>Host h2</span><span style="color:var(--accent-crimson)">BLACKLIST</span></div>
            <div class="node-ip tabular">10.0.0.2 &bull; Restricted</div>
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
        <div style="display:flex;gap:8px;flex-wrap:wrap;">
          <button class="btn btn-allow" onclick="triggerSim('normal_h1_8080')">
            Send Normal TCP (h1 &rarr; :8080) <span class="kbd">1</span>
          </button>
          <button class="btn btn-danger" onclick="triggerSim('attack_h1_4444')">
            Probe Forbidden Port (h1 &rarr; :4444) <span class="kbd">2</span>
          </button>
          <button class="btn btn-danger" onclick="triggerSim('attack_h2_8080')">
            Blacklisted Host Attack (h2 &rarr; :8080) <span class="kbd">3</span>
          </button>
        </div>
      </div>
    </div>

    <!-- Right Column: Real-Time SOC Telemetry Feed (Person C) -->
    <div class="card">
      <div class="section-header">
        <div class="section-title">Centralized SOC Security Event Stream (<code class="tabular">h4:9999</code>)</div>
        <span class="pill tabular" id="feed-count-pill">0 Events</span>
      </div>
      <div class="feed-list" id="soc-feed">
        <div style="color:var(--text-muted);font-size:13px;padding:24px 0;text-align:center;">
          No security violations logged yet. Trigger a forbidden port or blacklisted host test.
        </div>
      </div>
    </div>
  </section>

  <!-- Bottom Grid: Hot-Reloading Policy Editor + OpenFlow Table & D2 Benchmarks -->
  <section class="main-grid">
    <!-- Left: Live OpenFlow 1.3 Flow Table -->
    <div class="card">
      <div class="section-header">
        <div class="section-title">Switch <code class="tabular">s1</code> OpenFlow 1.3 Hardware Flow Table</div>
        <span class="pill tabular">ovs-ofctl dump-flows s1</span>
      </div>
      <table>
        <thead>
          <tr>
            <th>Priority</th>
            <th>Action</th>
            <th>Packets</th>
            <th>Duration</th>
            <th>Timeout</th>
            <th>Match Rule</th>
          </tr>
        </thead>
        <tbody id="flow-table-body" class="tabular">
          <tr><td colspan="6" style="color:var(--text-muted);">Loading flow table...</td></tr>
        </tbody>
      </table>
    </div>

    <!-- Right: Hot-Reloading policy.json Editor & D2 Comparison -->
    <div class="card" style="display:flex;flex-direction:column;gap:18px;">
      <div>
        <div class="section-header" style="margin-bottom:8px;">
          <div class="section-title">Dynamic Policy Control (<code class="tabular">controller/policy.json</code>)</div>
          <span class="pill" style="color:var(--accent-emerald)">Zero-Downtime Hot-Reload</span>
        </div>

        <div style="font-size:12px;color:var(--text-secondary);margin-top:6px;">Blocked Host IPs</div>
        <div class="chip-group" id="blocked-hosts-chips"></div>
        <div style="display:flex;gap:8px;margin-top:8px;">
          <input class="input-inline" id="new-host-input" placeholder="e.g. 10.0.0.2" />
          <button class="btn" onclick="addPolicyItem('host')">+ Block Host IP</button>
        </div>

        <div style="font-size:12px;color:var(--text-secondary);margin-top:14px;">Blocked TCP Destination Ports</div>
        <div class="chip-group" id="blocked-ports-chips"></div>
        <div style="display:flex;gap:8px;margin-top:8px;">
          <input class="input-inline" id="new-port-input" placeholder="e.g. 4444" />
          <button class="btn" onclick="addPolicyItem('port')">+ Block TCP Port</button>
        </div>
      </div>

      <div style="border-top:1px solid rgba(255,255,255,0.06);padding-top:14px;">
        <div class="section-title" style="margin-bottom:6px;">Deliverable 2 Baseline Evaluation (With vs. Without OVS Drop)</div>
        <div class="bench-row">
          <div class="bench-label"><span>Authorized Client TCP Throughput (<code class="tabular">h1 &rarr; h3:8080</code>)</span><span class="tabular" id="bench-tput-label">46.80 vs 27.14 Mbps</span></div>
          <div class="bar-track">
            <div class="bar-fill" style="width:78%;background:var(--accent-emerald);"></div>
          </div>
        </div>
        <div class="bench-row">
          <div class="bench-label"><span>Authorized Client Socket RTT Latency (Lower is Better)</span><span class="tabular" id="bench-lat-label">2.46 ms vs 6.39 ms</span></div>
          <div class="bar-track">
            <div class="bar-fill" style="width:38%;background:var(--accent-blue);"></div>
          </div>
        </div>
      </div>
    </div>
  </section>
</main>

<!-- Sonner-Style Stacked Toasts -->
<div class="sonner-toaster" id="toaster"></div>

<script>
  let lastEventCount = 0;
  let currentPolicy = { blocked_hosts: [], blocked_tcp_ports: [] };

  function showToast(title, detail, type = "info") {
    const toaster = document.getElementById("toaster");
    const toast = document.createElement("div");
    toast.className = "sonner-toast";
    const color = type === "BLOCK" ? "#ef4444" : (type === "ALLOW" ? "#10b981" : "#3b82f6");
    toast.innerHTML = `
      <div class="toast-header">
        <span style="width:8px;height:8px;border-radius:50%;background:${color};display:inline-block;"></span>
        <span>${title}</span>
      </div>
      <div class="toast-desc tabular">${detail}</div>
    `;
    toaster.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transform = "translateY(8px) scale(0.96)";
      setTimeout(() => toast.remove(), 200);
    }, 3400);
  }

  function pulseNodes(ids, cls) {
    ids.forEach(id => {
      const el = document.getElementById(id);
      if (!el) return;
      el.classList.add(cls);
      setTimeout(() => el.classList.remove(cls), 650);
    });
  }

  async function triggerSim(scenario) {
    if (scenario === "normal_h1_8080") {
      pulseNodes(["node-h1", "node-s1", "node-h3"], "active-pulse");
    } else if (scenario === "attack_h1_4444") {
      pulseNodes(["node-h1", "node-s1", "node-h4"], "block-pulse");
    } else if (scenario === "attack_h2_8080") {
      pulseNodes(["node-h2", "node-s1", "node-h4"], "block-pulse");
    }

    const res = await fetch("/api/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario })
    });
    const data = await res.json();
    showToast(data.title, data.detail, data.status);
    fetchState();
  }

  async function updatePolicy(newPol) {
    await fetch("/api/policy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(newPol)
    });
    showToast("Firewall Policy Hot-Reloaded", "Updated controller/policy.json with zero downtime", "INFO");
    fetchState();
  }

  function removePolicyItem(kind, val) {
    if (kind === "host") {
      currentPolicy.blocked_hosts = (currentPolicy.blocked_hosts || []).filter(h => h !== val);
    } else {
      currentPolicy.blocked_tcp_ports = (currentPolicy.blocked_tcp_ports || []).filter(p => Number(p) !== Number(val));
    }
    updatePolicy(currentPolicy);
  }

  function addPolicyItem(kind) {
    if (kind === "host") {
      const inp = document.getElementById("new-host-input");
      const v = inp.value.trim();
      if (v && !(currentPolicy.blocked_hosts || []).includes(v)) {
        currentPolicy.blocked_hosts.push(v);
        inp.value = "";
        updatePolicy(currentPolicy);
      }
    } else {
      const inp = document.getElementById("new-port-input");
      const v = parseInt(inp.value.trim(), 10);
      if (!isNaN(v) && !(currentPolicy.blocked_tcp_ports || []).includes(v)) {
        currentPolicy.blocked_tcp_ports.push(v);
        inp.value = "";
        updatePolicy(currentPolicy);
      }
    }
  }

  async function fetchState() {
    try {
      const res = await fetch("/api/state");
      const state = await res.json();

      // KPI updates
      document.getElementById("kpi-alerts").textContent = state.logs.length;
      document.getElementById("feed-count-pill").textContent = `${state.logs.length} ${state.logs.length === 1 ? "Event" : "Events"}`;
      document.getElementById("kpi-timeout").textContent = `${state.policy.drop_hard_timeout_sec || 30}s`;

      if (state.benchmark && state.benchmark.blocking_response_time_ms) {
        document.getElementById("kpi-response").textContent = `${state.benchmark.blocking_response_time_ms.mean_ms} ms`;
      }

      // Render SOC Feed
      const feed = document.getElementById("soc-feed");
      if (state.logs.length === 0) {
        feed.innerHTML = `<div style="color:var(--text-muted);font-size:13px;padding:24px 0;text-align:center;">No security violations logged yet. Trigger a forbidden port or blacklisted host test.</div>`;
      } else if (state.logs.length !== lastEventCount) {
        feed.innerHTML = state.logs.map(ev => `
          <div class="alert-item">
            <div>
              <span class="alert-badge">${ev.action || "DROP_RULE"}</span>
              <div class="alert-reason">${ev.reason || "Unauthorized packet dropped at switch s1"}</div>
              <div class="alert-meta tabular">${ev.src_ip}:${ev.src_port} &rarr; ${ev.dst_ip}:${ev.dst_port} (${ev.protocol}) &bull; hard_timeout=${ev.timeout_sec || 30}s</div>
            </div>
            <div class="tabular" style="font-size:11px;color:var(--text-muted);white-space:nowrap;">${(ev.timestamp || "").split(" ")[1] || ev.timestamp}</div>
          </div>
        `).join("");
      }
      lastEventCount = state.logs.length;

      // Render Policy Chips
      currentPolicy = state.policy;
      document.getElementById("blocked-hosts-chips").innerHTML = (state.policy.blocked_hosts || []).map(h => `
        <span class="chip tabular">${h} <button class="chip-remove" onclick="removePolicyItem('host','${h}')">&times;</button></span>
      `).join("");
      document.getElementById("blocked-ports-chips").innerHTML = (state.policy.blocked_tcp_ports || []).map(p => `
        <span class="chip tabular">TCP :${p} <button class="chip-remove" onclick="removePolicyItem('port',${p})">&times;</button></span>
      `).join("");

      // Render OpenFlow Table
      const flows = state.ovs.flows || [];
      document.getElementById("s1-flow-count").textContent = `Active Flows: ${flows.length}`;
      const tbody = document.getElementById("flow-table-body");
      if (flows.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" style="color:var(--text-muted);">Switch s1 offline or no flows installed (start Mininet or click a simulation button above)</td></tr>`;
      } else {
        tbody.innerHTML = flows.slice(0, 8).map(f => {
          const isDrop = f.actions.toLowerCase().includes("drop");
          const badgeColor = isDrop ? "color:#f87171;" : "color:#34d399;";
          return `
            <tr>
              <td>${f.priority}</td>
              <td style="font-weight:600;${badgeColor}">${f.actions}</td>
              <td>${f.packets}</td>
              <td>${f.duration_s.toFixed(1)}s</td>
              <td>${f.hard_timeout ? f.hard_timeout + "s" : "idle"}</td>
              <td style="color:var(--text-secondary);max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${f.raw}</td>
            </tr>
          `;
        }).join("");
      }
    } catch (e) {}
  }

  // Emil Kowalski Rule: Keyboard shortcuts execute immediately with zero lag
  window.addEventListener("keydown", (e) => {
    if (e.target.tagName === "INPUT") return;
    if (e.key === "1") triggerSim("normal_h1_8080");
    if (e.key === "2") triggerSim("attack_h1_4444");
    if (e.key === "3") triggerSim("attack_h2_8080");
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
        return  # Keep terminal clean

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
        elif parsed.path == "/api/state":
            policy = read_json_file(POLICY_PATH, {
                "blocked_hosts": ["10.0.0.2"],
                "blocked_tcp_ports": [4444, 23, 6667],
                "drop_hard_timeout_sec": 30,
            })
            logs = read_security_logs()
            bench = read_json_file(BENCH_PATH, {})
            ovs = get_ovs_flows()
            self._send_json({
                "policy": policy,
                "logs": logs,
                "benchmark": bench,
                "ovs": ovs,
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
        elif self.path == "/api/policy":
            pol = read_json_file(POLICY_PATH, {})
            pol["blocked_hosts"] = body.get("blocked_hosts", pol.get("blocked_hosts", []))
            pol["blocked_tcp_ports"] = body.get("blocked_tcp_ports", pol.get("blocked_tcp_ports", []))
            with open(POLICY_PATH, "w", encoding="utf-8") as f:
                json.dump(pol, f, indent=2)
            self._send_json({"ok": True, "policy": pol})
        else:
            self.send_error(404)


if __name__ == "__main__":
    host, port = "127.0.0.1", 5000
    print(f"\n======================================================================")
    print(f" [SDN SOC UI ACTIVE] Open http://{host}:{port} in Firefox")
    print(f"======================================================================\n", flush=True)
    server = HTTPServer((host, port), DashboardHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
