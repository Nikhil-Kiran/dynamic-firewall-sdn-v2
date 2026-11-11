#!/usr/bin/env python3
"""
OS-Ken OpenFlow 1.3 Dynamic IPS Firewall & Behavioral Packet Classifier
- Zero hardcoded blocked hosts required: dynamically quarantines any host IP
  that probes forbidden ports (>=2 strikes) or exceeds TCP SYN rate limits.
- Supports live policy.json hot-reloading (including manual UI host blocks).
- Installs reactive OpenFlow 1.3 priority=100 DROP rules with 30s self-healing timeouts.
"""

import json
import os
import sys
import time

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.lib.packet import ethernet, ether_types, in_proto, ipv4, packet, tcp
from os_ken.ofproto import ofproto_v1_3

CONTROLLER_DIR = os.path.dirname(os.path.abspath(__file__))
if CONTROLLER_DIR not in sys.path:
    sys.path.insert(0, CONTROLLER_DIR)

from log_client import send_security_event

POLICY_PATH = os.path.join(CONTROLLER_DIR, "policy.json")


class DynamicFirewallController(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DynamicFirewallController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.policy = {}
        self.policy_mtime = 0.0
        self.recent_alerts = {}

        # Dynamic runtime behavioral state (no hardcoded attacker IPs!)
        self.dynamic_quarantine = {}   # src_ip -> unban_epoch
        self.violation_counts = {}     # src_ip -> [timestamps]
        self.tcp_syn_timestamps = {}   # src_ip -> [timestamps]

        # Additional configurable port-scan / TCP-flood detection state.
        self.scan_activity = {}
        self.dynamic_blocked_hosts = {}
        self.attack_history = {}

        self._load_policy(force=True)

    def _load_policy(self, force: bool = False):
        try:
            mtime = os.path.getmtime(POLICY_PATH)
            if force or mtime > self.policy_mtime:
                with open(POLICY_PATH, "r", encoding="utf-8") as f:
                    self.policy = json.load(f)
                self.policy_mtime = mtime
                print(
                    f"[FIREWALL POLICY LOADED] Static Blocked Hosts: {self.policy.get('blocked_hosts')} | "
                    f"Blocked TCP Ports: {self.policy.get('blocked_tcp_ports')} | "
                    f"Dynamic Behavioral IPS: ACTIVE",
                    flush=True,
                )
        except Exception as exc:
            print(f"[FIREWALL WARN] Failed to load policy.json ({exc})", flush=True)

    def _sync_dynamic_state_to_policy_file(self):
        """Exposes active dynamic quarantines so the Web UI can display them live."""
        try:
            now = time.time()
            active_bans = {
                ip for ip, exp in self.dynamic_quarantine.items() if exp > now
            }
            active_bans.update(
                ip for ip, exp in self.dynamic_blocked_hosts.items() if exp > now
            )
            self.policy["dynamically_quarantined_hosts"] = sorted(active_bans)
            expiry_map = {}
            expiry_map.update({ip: exp for ip, exp in self.dynamic_quarantine.items() if exp > now})
            expiry_map.update({ip: exp for ip, exp in self.dynamic_blocked_hosts.items() if exp > now})
            self.policy["dynamic_block_expiry"] = expiry_map
            with open(POLICY_PATH, "w", encoding="utf-8") as f:
                json.dump(self.policy, f, indent=2)
            self.policy_mtime = os.path.getmtime(POLICY_PATH)
        except Exception:
            pass

    def _detect_abuse(self, src_ip, dst_ip, dst_port, tcp_pkt, datapath):
        """Detect rapid port scans and TCP connection floods with escalating blocks."""
        syn_only = (tcp_pkt.bits & tcp.TCP_SYN) and not (tcp_pkt.bits & tcp.TCP_ACK)
        if not syn_only:
            return False

        now = time.time()
        scan_window = int(self.policy.get("scan_window_sec", 10))
        scan_threshold = int(self.policy.get("port_scan_threshold", 5))
        flood_window = int(self.policy.get("flood_window_sec", 5))
        flood_threshold = int(self.policy.get("flood_threshold", 20))

        events = self.scan_activity.setdefault(src_ip, [])
        events.append((now, dst_port))
        events[:] = [(t, port) for t, port in events
                     if now - t <= max(scan_window, flood_window)]

        scan_ports = {port for t, port in events if now - t <= scan_window}
        flood_count = sum(1 for t, _ in events if now - t <= flood_window)

        attack_type = None
        if len(scan_ports) >= scan_threshold:
            attack_type = "port_scan"
            reason = f"Port scan detected from {src_ip} ({len(scan_ports)} ports in {scan_window}s)"
        elif flood_count >= flood_threshold:
            attack_type = "tcp_flood"
            reason = f"TCP connection flood detected from {src_ip} ({flood_count} attempts in {flood_window}s)"
        else:
            return False

        repeat_window = int(self.policy.get("repeat_attack_window_sec", 300))
        history = self.attack_history.setdefault(src_ip, [])
        history[:] = [t for t in history if now - t <= repeat_window]
        history.append(now)

        repeat_threshold = int(self.policy.get("repeat_attack_threshold", 2))
        if len(history) >= repeat_threshold:
            block_timeout = int(self.policy.get("repeat_attack_block_sec", 120))
            reason += f"; repeat attack #{len(history)} within {repeat_window}s"
        elif attack_type == "port_scan":
            block_timeout = int(self.policy.get("port_scan_block_sec", 30))
        else:
            block_timeout = int(self.policy.get("tcp_flood_block_sec", 60))

        test_override = self.policy.get("dashboard_test_timeout_sec")
        if test_override is not None:
            block_timeout = max(0, int(test_override))
        if block_timeout > 0:
            self.dynamic_blocked_hosts[src_ip] = now + block_timeout
            match = datapath.ofproto_parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip
            )
            self._add_flow(
                datapath, priority=200, match=match, actions=[], hard_timeout=block_timeout
            )
            self._sync_dynamic_state_to_policy_file()
            print(f"[AUTO BLOCK] {reason} (blocked for {block_timeout}s)", flush=True)
            action = "AUTO_BLOCK"
        else:
            print(f"[AUTO DETECT ONLY] {reason} (dashboard test override: no block)", flush=True)
            action = "ATTACK_DETECTED"
        self._emit_alert_once(
            src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port,
            src_port=tcp_pkt.src_port, action=action,
            reason=reason, protocol="TCP", timeout_sec=block_timeout,
        )
        return True

    def _add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id is not None and buffer_id != ofproto.OFP_NO_BUFFER:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                idle_timeout=idle_timeout,
                hard_timeout=hard_timeout,
                priority=priority,
                match=match,
                instructions=inst,
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                idle_timeout=idle_timeout,
                hard_timeout=hard_timeout,
                priority=priority,
                match=match,
                instructions=inst,
            )
        datapath.send_msg(mod)

    def _emit_alert_once(self, src_ip, dst_ip, dst_port, src_port, action, reason, protocol="TCP", timeout_sec=30):
        now = time.time()
        key = (src_ip, dst_ip, dst_port, action)
        if now - self.recent_alerts.get(key, 0.0) < 1.0:
            return
        self.recent_alerts[key] = now

        logger_cfg = self.policy.get("logger_server", {})
        logger_ip = logger_cfg.get("ip", "10.0.0.4")
        logger_port = int(logger_cfg.get("port", 9999))

        send_security_event(
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            src_port=src_port,
            protocol=protocol,
            action=action,
            reason=reason,
            timeout_sec=timeout_sec,
            logger_ip=logger_ip,
            logger_port=logger_port,
            async_send=True,
        )

    def _is_dynamically_quarantined(self, src_ip: str) -> bool:
        now = time.time()
        unban_time = self.dynamic_quarantine.get(src_ip)
        if unban_time is None:
            return False
        if now < unban_time:
            return True
        del self.dynamic_quarantine[src_ip]
        self.violation_counts.pop(src_ip, None)
        self._sync_dynamic_state_to_policy_file()
        print(f"[DYNAMIC IPS] 30s quarantine expired for {src_ip}. Host restored to AUTHORIZED state.", flush=True)
        return False

    def _record_violation_and_check_quarantine(self, src_ip: str, quarantine_sec: int, max_violations: int) -> bool:
        now = time.time()
        history = [t for t in self.violation_counts.get(src_ip, []) if now - t < 60.0]
        history.append(now)
        self.violation_counts[src_ip] = history

        if len(history) >= max_violations:
            self.dynamic_quarantine[src_ip] = now + quarantine_sec
            self._sync_dynamic_state_to_policy_file()
            return True
        return False

    def _check_syn_flood_rate(self, src_ip: str, max_syn_per_10s: int, quarantine_sec: int) -> bool:
        now = time.time()
        history = [t for t in self.tcp_syn_timestamps.get(src_ip, []) if now - t < 10.0]
        history.append(now)
        self.tcp_syn_timestamps[src_ip] = history

        if len(history) > max_syn_per_10s:
            self.dynamic_quarantine[src_ip] = now + quarantine_sec
            self._sync_dynamic_state_to_policy_file()
            return True
        return False

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, priority=0, match=match, actions=actions)
        print(f"[SDN CONTROLLER] OpenFlow 1.3 Switch connected (dpid={datapath.id}). Table-miss rule installed.", flush=True)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        self._load_policy()

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth_packets = pkt.get_protocols(ethernet.ethernet)
        if not eth_packets:
            return
        eth = eth_packets[0]

        if eth.ethertype in (ether_types.ETH_TYPE_LLDP, ether_types.ETH_TYPE_IPV6):
            return

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port
        out_port = self.mac_to_port[dpid].get(eth.dst, ofproto.OFPP_FLOOD)

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            actions = [parser.OFPActionOutput(out_port)]
            data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
            out = parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data
            )
            datapath.send_msg(out)
            return

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            proto = ip_pkt.proto

            blocked_hosts = set(self.policy.get("blocked_hosts", []))
            blocked_ports = set(int(p) for p in self.policy.get("blocked_tcp_ports", []))
            drop_timeout = int(self.policy.get("drop_hard_timeout_sec", 30))
            allow_timeout = int(self.policy.get("allow_idle_timeout_sec", 60))
            logger_ip = self.policy.get("logger_server", {}).get("ip", "10.0.0.4")

            ips_cfg = self.policy.get("dynamic_ips_settings", {})
            max_violations = int(ips_cfg.get("max_violations_before_host_ban", 2))
            max_syn_rate = int(ips_cfg.get("max_tcp_syn_rate_per_10s", 8))
            quarantine_sec = int(ips_cfg.get("quarantine_duration_sec", drop_timeout))
            test_timeout = self.policy.get("dashboard_test_timeout_sec")
            if test_timeout is not None:
                test_timeout = max(0, int(test_timeout))
                drop_timeout = test_timeout
                quarantine_sec = test_timeout

            tcp_pkt = pkt.get_protocol(tcp.tcp)

            # Always permit telemetry traffic to/from SOC Logger h4 (10.0.0.4:9999)
            if dst_ip == logger_ip or (tcp_pkt and (tcp_pkt.dst_port == 9999 or tcp_pkt.src_port == 9999)):
                actions = [parser.OFPActionOutput(out_port)]
                if out_port != ofproto.OFPP_FLOOD:
                    match = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=dst_ip
                    )
                    self._add_flow(datapath, priority=50, match=match, actions=actions, idle_timeout=allow_timeout)
                data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
                out = parser.OFPPacketOut(
                    datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data
                )
                datapath.send_msg(out)
                return

            # Expire custom temporary blocks and refresh the Web UI state when needed.
            expired_custom_block = (
                src_ip in self.dynamic_blocked_hosts
                and self.dynamic_blocked_hosts[src_ip] <= time.time()
            )
            if expired_custom_block:
                self.dynamic_blocked_hosts.pop(src_ip, None)
                self._sync_dynamic_state_to_policy_file()

            # Apply configurable port-scan / fast-flood detection before legacy IPS checks.
            # This ensures the configured 30s / 60s / repeat-offence durations are used.
            if tcp_pkt and src_ip not in blocked_hosts:
                if self._detect_abuse(src_ip, dst_ip, tcp_pkt.dst_port, tcp_pkt, datapath):
                    return

            # CHECK 1: Dynamically Quarantined Host OR Policy-Blocked Host
            is_dynamically_banned = self._is_dynamically_quarantined(src_ip)
            is_custom_blocked = self.dynamic_blocked_hosts.get(src_ip, 0) > time.time()
            if is_dynamically_banned or is_custom_blocked or src_ip in blocked_hosts:
                dst_port = tcp_pkt.dst_port if tcp_pkt else 0
                src_port = tcp_pkt.src_port if tcp_pkt else 0
                proto_name = "TCP" if tcp_pkt else ("ICMP" if proto == in_proto.IPPROTO_ICMP else "IPv4")

                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=dst_ip
                )
                host_drop_timeout = drop_timeout
                if is_custom_blocked:
                    host_drop_timeout = max(
                        1, int(self.dynamic_blocked_hosts[src_ip] - time.time())
                    )
                self._add_flow(
                    datapath, priority=100, match=match, actions=[],
                    hard_timeout=host_drop_timeout
                )

                if is_dynamically_banned:
                    reason = f"Dynamically quarantined attacker {src_ip} blocked from accessing {dst_ip}:{dst_port}"
                    action_label = "DYNAMIC_HOST_BLOCKED"
                elif is_custom_blocked:
                    reason = f"Automatically blocked attacker {src_ip} blocked from accessing {dst_ip}:{dst_port}"
                    action_label = "AUTO_BLOCK_ACTIVE"
                else:
                    reason = f"Policy-blocked source host {src_ip} blocked from accessing {dst_ip}"
                    action_label = "HOST_BLOCKED"

                print(f"[FIREWALL BLOCK] {reason} (priority=100, hard_timeout={drop_timeout}s)", flush=True)
                self._emit_alert_once(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    src_port=src_port,
                    action=action_label,
                    reason=reason,
                    protocol=proto_name,
                    timeout_sec=drop_timeout,
                )
                return

            # CHECK 2: TCP Behavioral Inspection (Forbidden Ports & SYN Flood Rate Limiting)
            if tcp_pkt:
                src_port = tcp_pkt.src_port
                dst_port = tcp_pkt.dst_port

                # Detect forbidden port access (4444, 23, 6667)
                if dst_port in blocked_ports:
                    quarantined_now = self._record_violation_and_check_quarantine(
                        src_ip, quarantine_sec, max_violations
                    )

                    if quarantined_now:
                        # Strike 2 reached -> full-host quarantine across all ports.
                        if quarantine_sec > 0:
                            match_host = parser.OFPMatch(
                                eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip
                            )
                            self._add_flow(
                                datapath, priority=100, match=match_host, actions=[], hard_timeout=quarantine_sec
                            )
                            self.dynamic_quarantine[src_ip] = time.time() + quarantine_sec
                            self._sync_dynamic_state_to_policy_file()
                            reason = (
                                f"Host {src_ip} triggered {max_violations} port violations (probed port {dst_port}) -> "
                                f"Dynamically Quarantined from ALL ports for {quarantine_sec}s"
                            )
                            print(f"[DYNAMIC IPS QUARANTINE] {reason}", flush=True)
                            action = "DYNAMIC_HOST_QUARANTINED"
                        else:
                            reason = (
                                f"Host {src_ip} reached {max_violations} forbidden-port strikes; "
                                "quarantine suppressed by dashboard no-block test override"
                            )
                            print(f"[DYNAMIC IPS DETECTED] {reason}", flush=True)
                            action = "QUARANTINE_DETECTED_ONLY"
                        self._emit_alert_once(
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            dst_port=dst_port,
                            src_port=src_port,
                            action=action,
                            reason=reason,
                            protocol="TCP",
                            timeout_sec=quarantine_sec,
                        )
                    else:
                        # Strike 1 -> Block the specific forbidden port and record strike
                        match_port = parser.OFPMatch(
                            eth_type=ether_types.ETH_TYPE_IP,
                            ip_proto=in_proto.IPPROTO_TCP,
                            ipv4_src=src_ip,
                            ipv4_dst=dst_ip,
                            tcp_dst=dst_port,
                        )
                        if drop_timeout > 0:
                            self._add_flow(
                                datapath, priority=100, match=match_port, actions=[], hard_timeout=drop_timeout
                            )
                        strikes = len(self.violation_counts.get(src_ip, []))
                        reason = (
                            f"Forbidden TCP port {dst_port} blocked ({src_ip} -> {dst_ip}:{dst_port}) "
                            f"[Strike {strikes}/{max_violations}]"
                        )
                        if drop_timeout > 0:
                            print(f"[FIREWALL DROP] {reason} (priority=100, hard_timeout={drop_timeout}s)", flush=True)
                            action = "DROP_FLOW_INSTALLED"
                        else:
                            print(f"[FIREWALL DETECT ONLY] {reason} (dashboard no-block override)", flush=True)
                            action = "FORBIDDEN_PORT_DETECTED"
                        self._emit_alert_once(
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            dst_port=dst_port,
                            src_port=src_port,
                            action=action,
                            reason=reason,
                            protocol="TCP",
                            timeout_sec=drop_timeout,
                        )
                    return

                # Authorized TCP Flow -> Match specific 5-tuple so subsequent connections still get inspected
                actions = [parser.OFPActionOutput(out_port)]
                if out_port != ofproto.OFPP_FLOOD:
                    match = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ip_proto=in_proto.IPPROTO_TCP,
                        ipv4_src=src_ip,
                        ipv4_dst=dst_ip,
                        tcp_src=src_port,
                        tcp_dst=dst_port,
                    )
                    self._add_flow(
                        datapath,
                        priority=10,
                        match=match,
                        actions=actions,
                        buffer_id=msg.buffer_id,
                        idle_timeout=allow_timeout,
                    )
                    print(f"[FIREWALL ALLOW] Authorized TCP flow {src_ip}:{src_port} -> {dst_ip}:{dst_port}", flush=True)
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        return

                data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
                out = parser.OFPPacketOut(
                    datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data
                )
                datapath.send_msg(out)
                return

        # Default L2 forwarding for ICMP / other traffic
        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src)
            self._add_flow(datapath, priority=5, match=match, actions=actions, idle_timeout=30)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data
        )
        datapath.send_msg(out)


app_manager.require_app("os_ken.controller.ofp_handler")
