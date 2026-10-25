#!/usr/bin/env python3
"""
OS-Ken OpenFlow 1.3 Dynamic Firewall & L2/L3/L4 Packet Classifier (Person B)
Enforces dynamic security policies from policy.json, installs OpenFlow 1.3
DROP/ALLOW rules on switch s1, and streams telemetry to log_server.py via log_client.py.
"""

import json
import os
import sys
import time

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.lib.packet import arp, ethernet, ether_types, icmp, in_proto, ipv4, packet, tcp
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
        self._load_policy(force=True)

    def _load_policy(self, force: bool = False):
        try:
            mtime = os.path.getmtime(POLICY_PATH)
            if force or mtime > self.policy_mtime:
                with open(POLICY_PATH, "r", encoding="utf-8") as f:
                    self.policy = json.load(f)
                self.policy_mtime = mtime
                print(
                    f"[FIREWALL POLICY LOADED] Blocked Hosts: {self.policy.get('blocked_hosts')} | "
                    f"Blocked TCP Ports: {self.policy.get('blocked_tcp_ports')}",
                    flush=True,
                )
        except Exception as exc:
            print(f"[FIREWALL WARN] Failed to load policy.json ({exc}), using defaults.", flush=True)
            if not self.policy:
                self.policy = {
                    "blocked_hosts": ["10.0.0.2"],
                    "blocked_tcp_ports": [4444],
                    "allowed_tcp_ports": [8080, 9999],
                    "drop_hard_timeout_sec": 30,
                    "allow_idle_timeout_sec": 60,
                    "logger_server": {"ip": "10.0.0.4", "port": 9999},
                }

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
        if now - self.recent_alerts.get(key, 0.0) < 2.0:
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
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype in (ether_types.ETH_TYPE_LLDP, ether_types.ETH_TYPE_IPV6):
            return

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port
        out_port = self.mac_to_port[dpid].get(eth.dst, ofproto.OFPP_FLOOD)

        # Allow ARP
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

            tcp_pkt = pkt.get_protocol(tcp.tcp)
            # Always permit telemetry traffic to/from Logger h4 (10.0.0.4:9999)
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

            # RULE 1: Blacklisted Source Host (10.0.0.2)
            if src_ip in blocked_hosts:
                dst_port = tcp_pkt.dst_port if tcp_pkt else 0
                src_port = tcp_pkt.src_port if tcp_pkt else 0
                proto_name = "TCP" if tcp_pkt else ("ICMP" if proto == in_proto.IPPROTO_ICMP else "IPv4")

                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=dst_ip
                )
                self._add_flow(datapath, priority=100, match=match, actions=[], hard_timeout=drop_timeout)
                reason = f"Blacklisted source host {src_ip} blocked from accessing {dst_ip}"
                print(f"[FIREWALL BLOCK] {reason} (priority=100, hard_timeout={drop_timeout}s)", flush=True)

                self._emit_alert_once(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    src_port=src_port,
                    action="HOST_BLOCKED",
                    reason=reason,
                    protocol=proto_name,
                    timeout_sec=drop_timeout,
                )
                return

            # RULE 2: Forbidden TCP Destination Port (e.g., 4444)
            if tcp_pkt:
                src_port = tcp_pkt.src_port
                dst_port = tcp_pkt.dst_port

                if dst_port in blocked_ports:
                    match = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ip_proto=in_proto.IPPROTO_TCP,
                        ipv4_src=src_ip,
                        ipv4_dst=dst_ip,
                        tcp_dst=dst_port,
                    )
                    self._add_flow(datapath, priority=100, match=match, actions=[], hard_timeout=drop_timeout)
                    reason = f"Forbidden TCP destination port {dst_port} blocked ({src_ip} -> {dst_ip}:{dst_port})"
                    print(f"[FIREWALL DROP] {reason} (priority=100, hard_timeout={drop_timeout}s)", flush=True)

                    self._emit_alert_once(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        src_port=src_port,
                        action="DROP_FLOW_INSTALLED",
                        reason=reason,
                        protocol="TCP",
                        timeout_sec=drop_timeout,
                    )
                    return

                # Authorized TCP Flow -> Install priority=10 forwarding rule
                actions = [parser.OFPActionOutput(out_port)]
                if out_port != ofproto.OFPP_FLOOD:
                    match = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ip_proto=in_proto.IPPROTO_TCP,
                        ipv4_src=src_ip,
                        ipv4_dst=dst_ip,
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

        # Default L2 forwarding for non-blocked ICMP/other traffic
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
