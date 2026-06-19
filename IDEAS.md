# Future Ideas

## [MED-HIGH] Mesh-wide DNS

Local DNS resolution on every router so that human-readable names are reachable across the entire mesh without relying on any external DNS.

**Proposed naming scheme (to be finalized):**

The DNS hierarchy mirrors the per-node namespace used for `allowFrom` references — `{LocalName}.{NodeName}` is the qualified-reference syntax read right-to-left.

- `{deviceName}.{nodeName}` — for LAN devices (e.g., `printer.Home`)
- `{nodeName}` — for the router itself (e.g., `Home`)
- `{vpnClientName}.{nodeName}` — for VPN clients hosted by that node (e.g., `Pixel8.Home`); flat 2-level matches the per-node namespace where VPN client names are unique within a node across all VPN interfaces
- `{globalClientName}` — for global clients in `config.clients` (no node prefix; they roam between nodes)

**Two approaches to consider — both could coexist:**

1. **Automatic records** — splot auto-generates DNS entries for every named thing (lanDevice, VPN client, node) that exposes at least one service. No extra config required.
2. **Explicit domains** — an optional `domain` field (or array) per device/node/client allows overriding or adding custom hostnames independent of the automatic scheme.

**Implementation notes:**

- OpenWRT uses dnsmasq; records can be injected via UCI (`dhcp` config) or a dnsmasq include file
- Each router would hold the full DNS picture for the mesh (all nodes, all devices), not just its own
- Records need to be regenerated and reloaded whenever the config changes (ties into the CLI `apply` command)

---

## [MED] Distributed Reload System

A coordinated, safe config push across the entire mesh from a single entry point.

**Flow:**

1. Operator connects to any router in the mesh (the "master" for this operation)
2. Master receives config — either via CLI flag pointing to a local file, or by downloading a remote config
3. Master distributes the new config to all other mesh nodes
4. Master waits for acknowledgement from every node — if any node does not respond:
   - Abort and report which nodes failed, or
   - Show the operator the state and ask how to proceed
5. If operator confirms: master sends an "apply" command to all nodes and waits for ack from each
6. All nodes (including master) apply the new config, saving the previous config as a backup
7. A 60-second verification timer starts on each node independently
8. Each node pings every other mesh node to verify reachability
9. After the test, behavior depends on whether the node can still reach the master:
   - **Node can reach master:** it sends its test results to master and waits for operator input — no automatic rollback
   - **Node cannot reach master:** after the 60-second window expires, it automatically rolls back to the backup config
10. On the master side, if any node becomes unreachable: the operator is informed that the mesh will now roll back, and the master initiates rollback across all reachable nodes

**Open design question — master connectivity:**

How nodes reach the master is undecided. Options:

- **Via mesh** — nodes contact master over WireGuard. Any node can be master. Fails if the new config broke mesh connectivity (the thing most likely to go wrong).
- **Via internet** — nodes contact master over its public IP. Survives mesh breakage. Requires master to have a reachable external IP, so not all nodes qualify.
- **Both, user's choice** — splot supports either mode; operator picks based on their setup.

The mesh approach is simpler and works for most cases, but has a fundamental weakness: if the config change breaks WireGuard, nodes can't reach master to report failure, and the keepalive/rollback path becomes the only safety net. The internet approach is more resilient but requires infrastructure not everyone has.

Worth deciding before implementation starts.

---

**Keepalive during operator wait:**
While any node is in the "waiting for operator input" state, the master continuously sends keepalive pings to it. If a node stops responding to keepalives, it is treated the same as "node cannot reach master" — automatic rollback after the timeout, and the master is notified to initiate a full mesh rollback.

**Key properties:**

- No single router needs to be the permanent master — any node can initiate a push
- Rollback is always possible because each node keeps the previous config
- Nodes that lost master connectivity self-heal after 60 seconds — nodes that kept connectivity defer to the operator
- This avoids split-brain: a node never unilaterally rolls back while the master still considers the operation in-progress
- Keepalives ensure that a node silently dying mid-wait is caught and handled the same as a connectivity failure

---

## [MED] Dynamic device presence — local firewall and WAN forward retargeting

A daemon running on each node that watches for DHCP lease events. When a known shared device's MAC address appears in the leases, the daemon dynamically applies the firewall rules for that device. When the lease expires or the device disconnects, the rules are removed.

This is the DHCP-based counterpart to static shared device configuration — it enables roaming devices to gain firewall access automatically without needing a pre-assigned static IP.

**How it works:**

- Watch `/tmp/dhcp.leases` (or dnsmasq lease script hooks) for MAC addresses matching any `sharedDevice` or global `client` with `macs` declared
- On appearance: generate and apply firewall rules for that device using its current leased IP
- On expiry/removal: tear down those rules

**WAN forward retargeting (extension):**

The daemon also resolves two WAN-forward limitations the static rule can't handle:

1. **Latency optimization.** When a global client with `meshIp` appears on a router's LAN, the daemon rewrites that router's WAN-forward `dest_ip` from `meshIp` to the current LAN IP. Traffic skips the mesh hop and reaches the client directly. On disappearance, the daemon restores `dest_ip` to `meshIp`. Operator-invisible — the forward just keeps working, optimally routed.

2. **Static-rejection cases.** The static rule rejects exposure of a `meshIp`-less global client via a router the client has no local presence on (see CONFIG.md → Destination IP selection). With the daemon running, the operator could opt into dynamic-only exposure: the daemon would watch where the client actually appears on the mesh and retarget all forwards to wherever it currently is. This isn't possible statically because the target depends on runtime presence; the daemon is the right layer for it. Likely requires a future config knob to mark a `wan.via` entry as "dynamic-only" so the validator knows to defer the resolvability check to the daemon.

Flow (for the latency-optimization case):

- Client appears on this router's LAN → daemon rewrites this router's WAN redirect `dest_ip` to `leased_ip`
- Client disappears (lease expiry or DHCP release) → daemon restores `dest_ip` to the static value
- Operator never sees this — the redirect just keeps working, optimally routed

The daemon turns "stable static target vs. latency-optimized local target" from a tradeoff into a layered design: static gives you a target that works whenever the mesh is up; dynamic improves it whenever the client is locally present; combined with the future dynamic-only knob, it also unlocks exposure scenarios the static rule has to reject for safety.

**Dependency:** Requires shared devices to be defined in the config (Roadmap item 2) so the daemon knows which MACs to watch for and what tags/services apply to them.

---

## [MED] Dynamic device presence — mesh-wide notification and DNS

A daemon (same or separate from the local firewall daemon above) that broadcasts device presence events to all other nodes in the mesh. When a shared device appears on any node, all nodes (including the one it connected to) create or update a DNS record for it pointing to its current LAN IP on the hosting node.

**How it works:**

1. Local node detects a known shared device via DHCP lease
2. Broadcasts a presence event to all other mesh nodes (IP, device name, MAC)
3. All nodes update their local dnsmasq DNS record: `{deviceName}` → current IP
4. On device disconnect: broadcast removal, all nodes delete or invalidate the DNS record

**DNS integration:**
This enables a dynamic variant of the Mesh-wide DNS explicit domain feature — `{deviceName}` resolves to wherever the device currently is, without knowing which node it's on in advance.

**Inter-node communication:**
The same broadcast/notification channel used here would also be needed by the Distributed Reload System. These two features could share a common inter-node messaging layer, or be implemented as separate lightweight connections — worth deciding when either is implemented.

---

## [LOW] allowedIps / Client as Gateway

Currently each VPN client has a single IP. Adding an optional `allowedIps` field would let a client act as a gateway to another network (e.g., a second router or a non-mesh subnet behind a VPN client).

**Tag resolution behavior:**

- A client's tag currently resolves to its own IP
- With `allowedIps`, the tag would resolve to both the client's IP and all declared subnets
- This allows `allowFrom: "SomeGateway"` to grant access to everything reachable through that client

**Note:** When implementing, consider whether the client's own IP and its routed subnets need different handling in `TagResolutionAddress` — e.g., the client's IP is a valid `dest_ip` for rules targeting that device directly, while the routed subnets are only valid as `src_ip` sources.

---

## [LOWEST] Multiple addresses per zone

A zone currently has a single `address` (one CIDR). OpenWRT supports binding multiple interfaces with different subnets into the same firewall zone — splot doesn't model this today.

**When this matters:** unusual setups where two physical networks must share one firewall zone (rather than being modeled as two zones). Most real cases — including VLANs — are naturally one-subnet-per-zone and don't need this.

**Migration cost when needed (small):**

- `address: Ipv4Interface` → `addresses: OneOrManyUnique<Ipv4Interface>` (single-value YAML still parses — `OneOrManyUnique` already handles that)
- Anywhere reading `zone.address` iterates `zone.addresses` instead
- Device IP validation: device IP must fall within *one of* the zone's subnets
- Tag resolution emits one entry per subnet
- Validator: subnets within one zone must not overlap each other (probably)

**Defer until:** a concrete setup forces it. Until then keep the schema single-subnet-per-zone — simpler to read, fewer edge cases.
