# SDN-Based Dynamic Firewall with Centralized Security Event Logger

An OpenFlow 1.3 Software-Defined Networking (SDN) dynamic firewall and closed-loop TCP security telemetry system built with **OS-Ken**, **Mininet**, **Open vSwitch**, and **Python POSIX TCP Sockets**.

---

## 1. System Architecture & Communication Flow

```mermaid
flowchart TB
    subgraph Control_Plane["SDN Control Plane (Host OS)"]
        CTRL["OS-Ken SDN Controller<br/>(firewall_controller.py)<br/>OpenFlow 1.3 | Port 6653"]
        POL[("policy.json<br/>Dynamic ACLs & Quotas")]
        LOG_CLI["Non-Blocking Log Client<br/>(log_client.py)"]
        POL --> CTRL
        CTRL --> LOG_CLI
    end

    subgraph Data_Plane["Mininet OpenFlow 1.3 Data Plane (10.0.0.0/24)"]
        SW(("Open vSwitch s1<br/>Bridge IP: 10.0.0.254"))
        H1["Host h1 (10.0.0.1)<br/>Authorized TCP Client<br/>(tcp_client.py)"]
        H2["Host h2 (10.0.0.2)<br/>Unauthorized / Attacker Host<br/>(tcp_client.py)"]
        H3["Host h3 (10.0.0.3:8080)<br/>Multi-Threaded TCP Server<br/>(tcp_server.py)"]
        H4["Host h4 (10.0.0.4:9999)<br/>Security Event Logger Server<br/>(log_server.py)"]

        H1 <==>|"TCP App Traffic (8080)"| SW
        H2 -.->|"Blocked Traffic (4444 / 8080)"| SW
        SW <==>|"Allowed Flows"| H3
        SW ===>|"TCP JSON Alerts (9999)"| H4
    end

    CTRL <==>|"OpenFlow 1.3 (PacketIn / FlowMod)"| SW
    LOG_CLI ===>|"TCP Socket (JSON Telemetry)"| SW
```

### Network Addressing Plan
| Node | IP Address | Role & Component | Port / Protocol |
| :--- | :--- | :--- | :--- |
| **c0** | 127.0.0.1 | OS-Ken OpenFlow 1.3 SDN Controller (controller/firewall_controller.py) | 6653/TCP (OpenFlow) |
| **s1** | 10.0.0.254 | Open vSwitch (OVSSwitch) enforcing L3/L4 flow rules | OpenFlow 1.3 |
| **h1** | 10.0.0.1 | Legitimate Client Node (socket_app/tcp_client.py) | Ephemeral TCP |
| **h2** | 10.0.0.2 | Restricted / Attacker Client Node (socket_app/tcp_client.py) | Ephemeral TCP |
| **h3** | 10.0.0.3 | Multi-Threaded Application Server (socket_app/tcp_server.py) | 8080/TCP (Allowed), 4444/TCP (Forbidden) |
| **h4** | 10.0.0.4 | Centralized Security Event Logger (socket_app/log_server.py) | 9999/TCP (JSON Telemetry) |

---

## 2. Running the Full End-to-End Demo (Deliverable 1)

1. **Terminal 1 (Start OS-Ken Controller):**
   source venv/bin/activate && PYTHONPATH=.:controller osken-manager controller.firewall_controller
2. **Terminal 2 (Start Mininet Topology):**
   sudo python3 mininet/topo.py
3. **Inside mininet> CLI (Start Logger on h4 and App Server on h3):**
   mininet> xterm h3 h4
   - On h4: python3 socket_app/log_server.py --host 0.0.0.0 --port 9999
   - On h3: python3 socket_app/tcp_server.py --host 0.0.0.0 --port 8080
4. **Run Automated Logger & Integration Verification Suite:**
   python3 socket_app/test_logger_suite.py
