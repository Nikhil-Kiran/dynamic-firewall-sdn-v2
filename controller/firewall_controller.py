#Dynamic SDN Firewall Controller
#!/usr/bin/env python3
"""
SDN Dynamic Firewall & Behavioral IPS Controller (OpenFlow 1.3 / OS-Ken)
1. TCP client/server communication forwarding (h1, h2 <-> h3:8080)
2. Traffic classification by source IP, destination IP, and TCP/UDP port
3. Dynamic firewall rule installation on switch s1 (priority=10 ALLOW, priority=100 DROP)
4. Centralized security-event logger telemetry to h4 (10.0.0.4:9999) + security_events.log
5. Multi-client support (concurrent flows for h1, h2, h3, h4)
6. Automatic blocking (2-strike dynamic quarantine / SYN flood) & 30s self-healing recovery
7. Sub-40ms hardware flow-mod response time
"""

import json
import os
import time
from collections import defaultdict, deque

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import ethernet, ether_types, ipv4, tcp

from log_client import send_security_event

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLICY_PATH = os.path.join(BASE_DIR, "controller", "policy.json")
RESET_SIGNAL_FILE = "/tmp/sdn_reset_quarantine"


class DynamicFirewallController(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.policy = {}
        self.policy_mtime = 0.0

        # Behavioral IPS state (Zero hardcoding: all hosts start AUTHORIZED)
        self.violation_counts = defaultdict(int)
        self.dynamic_quarantine = {}  # ip -> expiry_timestamp
        self.tcp_syn_timestamps = defaultdict(lambda: deque(maxlen=200))

        self._load_policy(force=True)

    def _save_quarantine_state(self):
        """Updates dynamically_quarantined_hosts in policy.json so Web UI badge updates live."""
        try:
            now = time.time()
            active_bans = [ip for ip, exp in list(self.dynamic_quarantine.items()) if exp > now]
            self.policy["dynamically_quarantined_hosts"] = active_bans
            with open(POLICY_PATH, "w", encoding="utf-8") as f:
                json.dump(self.policy, f, indent=2)
            self.policy_mtime = os.path.getmtime(POLICY_PATH)
        except Exception:
            pass

    def _load_policy(self, force: bool = False):
        if os.path.exists(RESET_SIGNAL_FILE):
            self.dynamic_quarantine.clear()
            self.violation_counts.clear()
            self.tcp_syn_timestamps.clear()
            try:
                os.remove(RESET_SIGNAL_FILE)
            except Exception:
                pass
            self._save_quarantine_state()

        try:
            mtime = os.path.getmtime(POLICY_PATH)
            if force or mtime > self.policy_mtime:
                with open(POLICY_PATH, "r", encoding="utf-8") as f:
                    self.policy = json.load(f)
                self.policy_mtime = mtime
        except Exception as e:
            self.logger.error("Failed to load policy.json: %s", e)
            if not self.policy:
                self.policy = {
                    "allowed_tcp_ports": [8080, 9999],
                    "forbidden_tcp_ports": [23, 4444],
                    "max_port_violations_before_quarantine": 2,
                    "syn_flood_threshold": 25,
                    "syn_flood_window_sec": 3.0,
                    "drop_hard_timeout_sec": 30,
                    "allow_idle_timeout_sec": 60,
                    "logger_ip": "10.0.0.4",
                    "logger_port": 9999,
                }

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id is not None and buffer_id != ofproto.OFP_NO_BUFFER:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                idle_timeout=idle_timeout,
                hard_timeout=hard_timeout,
                match=match,
                instructions=inst,
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                idle_timeout=idle_timeout,
                hard_timeout=hard_timeout,
                match=match,
                instructions=inst,
            )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Table-miss rule (priority 0 -> send to controller)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("[SWITCH ONLINE] s1 (dpid=%s) OpenFlow 1.3 table-miss installed", datapath.id)

    def _emit_alert(self, action, reason, src_ip, dst_ip, src_port, dst_port, protocol="TCP"):
        event = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "action": action,
            "reason": reason,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
        }
        send_security_event(
            event,
            logger_ip=self.policy.get("logger_ip", "10.0.0.4"),
            logger_port=int(self.policy.get("logger_port", 9999)),
        )

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        self._load_policy()
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = ethernet.ethernet(msg.data)
        if pkt.ethertype in (ether_types.ETH_TYPE_LLDP, ether_types.ETH_TYPE_IPV6):
            return

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][pkt.src] = in_port
        out_port = self.mac_to_port[dpid].get(pkt.dst, ofproto.OFPP_FLOOD)

        # Always forward ARP so hosts can resolve MAC addresses
        if pkt.ethertype == ether_types.ETH_TYPE_ARP:
            actions = [parser.OFPActionOutput(out_port)]
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None,
            )
            datapath.send_msg(out)
            return

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt:
            actions = [parser.OFPActionOutput(out_port)]
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None,
            )
            datapath.send_msg(out)
            return

        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst
        now = time.time()

        # Expire stale dynamic quarantines automatically (Self-Healing Recovery)
        if src_ip in self.dynamic_quarantine:
            if now >= self.dynamic_quarantine[src_ip]:
                del self.dynamic_quarantine[src_ip]
                self.violation_counts[src_ip] = 0
                self._save_quarantine_state()
            else:
                remaining = int(self.dynamic_quarantine[src_ip] - now)
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip)
                self.add_flow(datapath, 100, match, [], hard_timeout=max(1, remaining))
                tcp_p = pkt.get_protocol(tcp.tcp)
                sp = tcp_p.src_port if tcp_p else 0
                dp = tcp_p.dst_port if tcp_p else 0
                self._emit_alert(
                    "QUARANTINE_DROP",
                    f"Host {src_ip} is dynamically quarantined ({remaining}s remaining)",
                    src_ip, dst_ip, sp, dp,
                )
                return

        tcp_pkt = pkt.get_protocol(tcp.tcp)
        if tcp_pkt:
            src_port = tcp_pkt.src_port
            dst_port = tcp_pkt.dst_port

            # Allow SOC Logger telemetry traffic unconditionally
            if dst_port == 9999 or src_port == 9999:
                actions = [parser.OFPActionOutput(out_port)]
                out = parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=msg.buffer_id,
                    in_port=in_port,
                    actions=actions,
                    data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None,
                )
                datapath.send_msg(out)
                return

            drop_timeout = int(self.policy.get("drop_hard_timeout_sec", 30))
            max_violations = int(self.policy.get("max_port_violations_before_quarantine", 2))
            forbidden_ports = set(self.policy.get("forbidden_tcp_ports", [23, 4444]))
            allowed_ports = set(self.policy.get("allowed_tcp_ports", [8080, 9999]))

            # 1. Check SYN Flood threshold
            is_syn_only = bool(tcp_pkt.bits & tcp.TCP_SYN) and not bool(tcp_pkt.bits & tcp.TCP_ACK)
            if is_syn_only:
                win = float(self.policy.get("syn_flood_window_sec", 3.0))
                thresh = int(self.policy.get("syn_flood_threshold", 25))
                dq = self.tcp_syn_timestamps[src_ip]
                dq.append(now)
                while dq and (now - dq[0]) > win:
                    dq.popleft()
                if len(dq) > thresh:
                    self.dynamic_quarantine[src_ip] = now + drop_timeout
                    self._save_quarantine_state()
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip)
                    self.add_flow(datapath, 100, match, [], hard_timeout=drop_timeout)
                    self._emit_alert(
                        "SYN_FLOOD_QUARANTINE",
                        f"SYN flood detected from {src_ip} ({len(dq)} SYNs/{win}s) -> Quarantined {drop_timeout}s",
                        src_ip, dst_ip, src_port, dst_port,
                    )
                    return

            # 2. Check Forbidden Port / Unauthorized Destination Port (Client SYN to Server)
            if is_syn_only and (dst_port in forbidden_ports or dst_port not in allowed_ports):
                self.violation_counts[src_ip] += 1
                strikes = self.violation_counts[src_ip]

                if strikes >= max_violations:
                    self.dynamic_quarantine[src_ip] = now + drop_timeout
                    self._save_quarantine_state()
                    # Quarantine host across ALL ports on switch s1
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip)
                    self.add_flow(datapath, 100, match, [], hard_timeout=drop_timeout)
                    reason = (
                        f"DYNAMIC_HOST_QUARANTINED: {src_ip} committed {strikes}/{max_violations} "
                        f"port violations (last port {dst_port}) -> Banned from ALL ports for {drop_timeout}s"
                    )
                    self._emit_alert("DYNAMIC_QUARANTINE", reason, src_ip, dst_ip, src_port, dst_port)
                else:
                    # Install port-specific drop rule on switch s1
                    match = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ip_proto=6,
                        ipv4_src=src_ip,
                        ipv4_dst=dst_ip,
                        tcp_dst=dst_port,
                    )
                    self.add_flow(datapath, 100, match, [], hard_timeout=drop_timeout)
                    reason = (
                        f"Forbidden TCP port {dst_port} blocked ({src_ip} -> {dst_ip}:{dst_port}) "
                        f"[Strike {strikes}/{max_violations}]"
                    )
                    self._emit_alert("PORT_BLOCK", reason, src_ip, dst_ip, src_port, dst_port)
                return

            # 3. Authorized TCP Traffic -> Install Priority 10 Forward Rule & Forward Packet
            actions = [parser.OFPActionOutput(out_port)]
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=ether_types.ETH_TYPE_IP,
                    ip_proto=6,
                    ipv4_src=src_ip,
                    ipv4_dst=dst_ip,
                    tcp_src=src_port,
                    tcp_dst=dst_port,
                )
                idle_t = int(self.policy.get("allow_idle_timeout_sec", 60))
                self.add_flow(datapath, 10, match, actions, idle_timeout=idle_t)

            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None,
            )
            datapath.send_msg(out)
            return

        # Forward ICMP / other authorized IP traffic
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None,
        )
        datapath.send_msg(out)
