# Future Ideas

## [MED-HIGH] Mesh-wide DNS

Local DNS resolution on every router so that human-readable names are reachable across the entire mesh without relying on any external DNS.

**Proposed naming scheme (to be finalized):**

The DNS hierarchy mirrors the per-node namespace used for `allowFrom` references — `{LocalName}.{NodeName}` is the qualified-reference syntax read right-to-left.

- `{deviceName}.{nodeName}` — for LAN devices (e.g., `printer.Jawo`)
- `{nodeName}` — for the router itself (e.g., `Jawo`)
- `{vpnClientName}.{nodeName}` — for VPN clients hosted by that node (e.g., `Pixel8.Jawo`); flat 2-level matches the per-node namespace where VPN client names are unique within a node across all VPN interfaces
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

## [MED] Dynamic device presence — local firewall

A daemon running on each node that watches for DHCP lease events. When a known shared device's MAC address appears in the leases, the daemon dynamically applies the firewall rules for that device. When the lease expires or the device disconnects, the rules are removed.

This is the DHCP-based counterpart to static shared device configuration — it enables roaming devices to gain firewall access automatically without needing a pre-assigned static IP.

**How it works:**

- Watch `/tmp/dhcp.leases` (or dnsmasq lease script hooks) for MAC addresses matching any `sharedDevice`
- On appearance: generate and apply firewall rules for that device using its current leased IP
- On expiry/removal: tear down those rules

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

## [LOW] Port forwards / WAN-side service exposure

Let services declared in splot config be reachable from outside the mesh — typically via a node's WAN interface.

**Why it might belong in splot:**

- The `services` model already expresses "X is reachable from Y" — port forwarding is the same idea, just rendered as DNAT on a NAT-ed zone instead of a plain accept rule
- Single source of truth: today, mesh-side exposure is in splot while WAN-side exposure is hand-edited in OpenWRT, fragmenting the answer to "where is `printer:9100` reachable from?"
- Cross-node case becomes natural: a node without a public IP can have one of its services exposed via another node's WAN, by writing `allowFrom: OtherNode.wan` on the service. Splot would generate the port forward on the WAN-owning node plus the rules along the mesh path.

**Why it's deferred:**

- Different uci section type (`redirect`, not `rule`) — additional generation surface
- Possibly need to model node public IP / DDNS, or punt that to the operator
- Mesh setup is the real ergonomic pain — single-router port forwards in LuCI are fine. Value is weaker than the mesh case while operational risk is higher.

**Suggested shape (when implemented):**

WAN is **not special** — it's just another zone the operator declares under a node's `zones`, with a marker that says "traffic from here is NAT-ed." Same per-node-zones model as LAN/VLAN; same `{NodeName}.{zoneName}` reference syntax in `allowFrom`. Splot does not manage the WAN zone in OpenWRT (the operator configures it); splot just references it by name.

```yaml
nodes:
  Jawo:
    zones:
      lan:
        address: 192.168.84.1/24
        devices:
          stacjonara:
            ip: 192.168.84.10
            services:
              ssh:
                port: "2222:22" # external 2222 → internal 22
                proto: tcp
                allowFrom: [admin, $node.wan, Karcze.wan]
      wan:
        nat: true # marks the zone as NAT-ed; enables port-forward rendering
        # no address — the operator manages this zone in OpenWRT
```

**Encoding rules:**

- `port` string in `wanPort:devicePort` form is only meaningful when `allowFrom` resolves to at least one NAT-ed zone — splot uses the `wanPort` half for the DNAT redirect, the `devicePort` half for the accept rule.
- For non-NAT-ed sources (regular LAN, mesh, VPN), only the right half (`devicePort`) is used.
- A bare port like `"22"` is shorthand for `"22:22"`.

**Cross-node WAN exposure:** `allowFrom: Karcze.wan` on a Jawo-hosted service means: generate a port forward on Karcze that DNATs the WAN port to the Jawo device's mesh-reachable IP, plus the accept rules along the path on both routers.

**Open questions to resolve when picking this up:**

- Whether the public IP (or DDNS hostname) needs to be in config, or comes from the router's actual WAN interface at apply time
- How to handle WAN port collisions (two services trying to claim the same `wanPort` on the same zone)
- Whether a NAT-ed zone needs additional fields beyond `nat: true` (e.g., interface name override)

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
