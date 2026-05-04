# Roadmap

Confirmed next implementation steps, in priority order.

---

## 1. Config validation

Validate `splot.json` before any UCI commands are generated. Fail early with clear error messages.

Rules to enforce (see CONFIG.md for full definitions):

- **Global name uniqueness** — node names, LAN device names, VPN interface names, and VPN client names must all be unique across the entire config
- **No name/tag collisions** — explicit tags must not duplicate any object name (they share the same namespace)
- **Valid characters in names** — alphanumeric, `-`, `_` only; no spaces or special characters
- **Subnet non-overlap** — `meshIp` prefixes, `lan.address` subnets, and VPN interface subnets must not overlap with each other across the entire mesh
- **Device IPs within LAN subnet** — each LAN device `ip` must fall within its node's `lan.address` subnet
- **VPN client IPs within interface subnet** — each VPN client `ip` must fall within its interface's `address` subnet
- **`allowFrom` references must exist** — every tag/name used in `allowFrom` must resolve to at least one known entity

---

## 2. CLI Interface

A proper CLI for interacting with splot on a router:

- `splot validate` — validate the local config file and report errors
- `splot dry-run` — generate and print all UCI commands that would be applied, without executing them
- `splot apply` — full pipeline: validate, generate, apply via uci, reload affected services

This is the first user-facing entry point and should land right after validation so the validator is reachable without a wrapper.

Implement structured logging (e.g. `tracing`) at the same time — not deferred. Each pipeline stage (load, validate, generate, apply) should emit actionable log output at appropriate levels (`info` for progress, `debug` for generated commands, `error` for failures). This makes `dry-run` and `apply` debuggable from day one.

---

## 3. Zones in config + egress rules + per-zone rule scoping

A single coherent change: introduce zones as a first-class config concept, finish the egress-rule generation path that depends on it, and tighten the generated firewall rules with explicit src/dest zone scoping. These three were previously separate items but they touch the same area of the code and code-share the same zone-aware tag resolution map — splitting them produces extra churn.

### 3a. Zones as a per-node HashMap

Replace the `lan` field on a node with a `zones` map. Each entry's key is the OpenWRT zone name on that router; the value carries `address` and `devices`. The single-LAN case becomes a one-entry map; multi-zone setups (e.g. an `iot` VLAN) drop in without schema changes.

```yaml
nodes:
  Jawo:
    zones:
      lan:
        address: 192.168.84.1/24
        devices: { ... }
      iot:
        address: 192.168.10.1/24
        devices: { ... }
```

Splot does not manage these zones in OpenWRT — the operator configures them. Splot only references them by name when generating rules. Same contract as today.

### 3b. Reference resolution rules in `allowFrom`

Reference forms (full table in CLAUDE.md / CONFIG.md):

- **Bare name** — global namespace: explicit tag, node name, or global client name
- **Qualified `{NodeName}.{LocalName}`** — anything inside a node: zone, device, VPN interface, or VPN client
- **`$node`** / **`$node.{LocalName}`** — the current router; context-dependent

Key behavioral changes from the current model:

- **Implicit name-tags shrink to the global namespace only.** Today every named thing has an implicit global tag — `allowFrom: printer` resolves directly to that device. New model: only nodes, global clients, and explicit tags get implicit global tags. Per-node objects (zones, devices, VPN interfaces, VPN clients) require qualified `{Node}.{Name}` references.
- **Per-node objects share one flat per-node namespace.** Within a single node, names of zones, devices, VPN interfaces, and VPN clients must all be unique among each other. They can recur freely across nodes — two routers can both have a `printer` device.
- **Bare node name fans out broader.** `allowFrom: Jawo` now resolves to the union of all of Jawo's `zones` subnets *and* all of Jawo's `vpnInterfaces` subnets — every downstream subnet on Jawo. Today it resolves only to `lan_subnet`. Single-zone single-vpn-interface setups see no behavioral difference.
- **`$node` becomes multi-IP.** It resolves to the union of the router's own IPs across all its `zones` and `vpnInterfaces`, not just the LAN IP. IP-vs-subnet distinction matters: `Jawo` returns subnets (broad), `$node` returns IPs (narrow — "the router as a host").
- **`$node.{LocalName}` is a new form** for narrow per-zone references (e.g. `$node.lan` = router's IP on lan zone only).
- **Addressless zones contribute nothing** to any aggregating reference. A WAN zone declared with no `address` is silently excluded from `Jawo`, `$node`, etc. — preventing broad references from accidentally meaning "the public internet."

### 3c. Extend egress rule generation to all service types

Today's egress rule generator iterates only `node.services` for remote nodes — it misses services declared on remote devices, VPN clients, and global clients. A LAN device on node A trying to reach a device service on node B never connects because A's firewall doesn't forward LAN→mesh for that destination. Iterate the full set of remote service locations using the same `generate_rule_from_service` helper.

### 3d. Per-zone src/dest scoping in generated rules

Generated rules currently set `src=*` and `dest=*`, matching only on `src_ip` / `dest_ip`. Replace `*` with computed zone names from the zone-aware tag resolution map.

When a rule's `allowFrom` resolves to source IPs across N zones, emit N rules — one per source zone, each with that zone's name in `src` and only that zone's IPs in `src_ip`. The `dest` zone is the zone the target IP belongs to (`device` if the target is `$node`, otherwise the matching zone). This naturally distinguishes input rules (router as destination) from forward rules (downstream destination) without separate code paths.

The same-network filter on the source IP set stays — it correctly skips rules that would never match because the traffic doesn't traverse the firewall (same-subnet, L2-bridged). It is not replaced with a same-zone filter — same-zone-different-subnet traffic is intra-zone forwarding and may legitimately need rules.

### Suggested order

Zones-first: rename `lan` → `zones` and finish the in-progress zone-aware tag resolution refactor (currently mid-edit in `firewall.rs`). Then extend egress (3c). Then the per-zone scoping (3d). Tested end-to-end with: a LAN device on one node successfully reaches a LAN device service on another node, and rules in `/etc/config/firewall` show explicit src/dest zone names with no `*`.
