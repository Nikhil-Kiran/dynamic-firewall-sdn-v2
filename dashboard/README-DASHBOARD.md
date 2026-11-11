# Dashboard integration notes

The dashboard now executes traffic inside the real Mininet host namespaces using the host PIDs exported by `mininet/topology.py`.

## Start order

1. Start the OS-Ken controller on port 6653.
2. Start Mininet with `sudo python3 mininet/topology.py`. The topology automatically starts the TCP server on h3 and SOC logger on h4, and writes `/tmp/dynamic-firewall-mininet-pids.json`.
3. In a separate Ubuntu terminal, run `sudo -v` and enter your password. Then start the dashboard in that same terminal:
   ```
   cd ~/dynamic-firewall-osken281/dynamic-firewall
   .venv281/bin/python dashboard/app.py
   ```
   The `sudo -v` credential cache allows the dashboard's restricted `sudo -n mnexec` and `ovs-ofctl` commands to run without prompting from the web request handler.
4. Open `http://127.0.0.1:5000`.

The dashboard remains bound to localhost. Do not expose it to an untrusted network: it can execute a small fixed set of Mininet test actions.

## Test console

- Access attempts: controls repeated normal/static-host attempts, flood connection count, and the number of distinct forbidden-port strikes / scan ports.
- Timeout override: `Policy defaults` preserves the native feature values (port scan 30s, flood 60s, repeat attack 120s, forbidden-port quarantine 30s). `0` means detection-only for dynamic IPS tests; `30`, `60`, and `120` override the temporary block/quarantine timeout used by the controller. This is written to `controller/policy.json` and hot-loaded by the controller.
- Strike 1 uses h1 -> TCP/4444. Strike 2 uses h1 -> TCP/23. They are different forbidden ports so the first per-port drop rule does not hide the second strike.
- Port scan uses distinct non-forbidden ports, not the legacy rapid-scan list. The default attempts value is `5`, which reaches the current scan threshold. Increase attempts to probe more ports.
- TCP flood creates actual TCP connections from h1 to h3:8080. With the current policy, set attempts to at least `20` to reach the 20 SYN / 5-second threshold.
- Logger test sends a real JSON event to h4:9999 and checks the ACK.
- The flow table reports the actual `ovs-ofctl` output and surfaces permission/command errors instead of silently showing an empty table.

The dashboard does not clear controller in-memory strike/attack history when logs are reset. Use a fresh controller process / fresh Mininet run for a clean demonstration if you need to reset that state.
