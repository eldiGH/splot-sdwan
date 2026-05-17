# Roadmap

Confirmed next implementation steps, in priority order.

---

## 1. WAN exposure (port forwards)

Make services declared in splot config externally reachable through a router's WAN zone. This is the next big config feature — it ties together a lot of existing work and unlocks practical deployments where some services need to be public.

See [CONFIG.md → WAN exposure](CONFIG.md#wan-exposure) for the final design.

### Config-shape changes

**Node-level:**

- New `wanZone: string` field on `Node` — name of the OpenWRT firewall zone that's WAN-facing. Optional in general; required if any service uses this node in `wan.via`.

**Service-level:**

- New `wan` field: object with `via: [<nodeName>...]` and optional `sourceAddresses: [<CIDR>...]`.
- `allowFrom` becomes optional — a service with only `wan` is valid (WAN-only exposure).
- At least one of `allowFrom` or `wan` must be set; both empty is a warning (`ServiceUnreachable`).

**Zone-level cleanup (drops addressless zones entirely):**

- `zone.address` becomes required (no more `Option<Ipv4Interface>`).
- WAN is *not* a zone in splot's model — it's a name referenced via `node.wanZone`, declared by the operator in OpenWRT, never managed by splot.

### Validator changes

Remove:

- Optional `zone.address` and everything that depends on it
- `DevicesInAddresslessZone` error variant
- `ClientIpInAddresslessZone` error variant
- Silent-exclusion handling for addressless zones in `tag_resolution.rs`
- All addressless-zone mentions in CONFIG.md and CLAUDE.md (already done)

Add:

- For each `wan.via` entry: must be a known node name. Each listed node must declare `wanZone`. No special identifiers (`$node` etc.) — validator must reject them with a clear error.
- For each `wan.sourceAddresses` entry: must parse as a valid IPv4 CIDR. No identifier resolution.
- External port uniqueness check per `(router, proto)` — two services can't both bind external port 8080/tcp on the same router's WAN.
- (Optional, defer if complex) Reachability check: a service's hosting IP must be reachable from each router in `wan.via`. For global clients this typically means a mesh IP; for devices, an IP on a zone the router serves or has a mesh path to.

Update:

- `ServiceAllowFromEmpty` warning becomes `ServiceUnreachable` — fires when both `allowFrom` and `wan` are empty (no access from any direction).

### Generation changes

- New UCI section type emitted: `config redirect` for port forwards. Goes in `/etc/config/firewall`.
- For each `(router, service-with-wan)` pair: emit one `redirect` per protocol with `src = wanZone`, `src_dport`, `dest_ip`, `dest_port`, and `src_ip` (when `sourceAddresses` is non-empty).
- Existing `allowFrom`-based accept rules continue to be generated independently — `wan` and `allowFrom` populate separate UCI sections, no cross-coupling.
- The `port: "external:internal"` shorthand is used as: external for the WAN redirect's `src_dport`, internal for the redirect's `dest_port` and for any LAN accept rules.

### Open questions to resolve during implementation

- **Destination IP resolution for global clients:** when a service is on a global client with multiple IPs across nodes, which IP does the redirect target? Default suggestion: prefer the client's `meshIp`; if absent, prefer an IP on a network the WAN-providing router can reach directly. Reject at validation if no reachable IP exists.
- **`port` field type:** still a string for compatibility with the existing `"external:internal"` syntax, or split into structured `externalPort` / `internalPort` fields? Probably keep the string form; cheap to parse, matches existing config.
- **Whether to support per-router external ports** via map form of `via` (e.g., `via: { HomeRouter: 8080, BackupRouter: 80 }`). Defer until a real case demands it; list form covers ~all real usage.
- **Multi-WAN routers** (two ISPs, failover). Single `wanZone` per node for MVP; widen to `wanZones: [...]` later if needed.

---

## 2. CLI Interface

A proper CLI for interacting with splot on a router:

- `splot validate` — validate the local config file and report errors
- `splot dry-run` — generate and print all UCI commands that would be applied, without executing them
- `splot apply` — full pipeline: validate, generate, apply via uci, reload affected services

This is the first user-facing entry point. Implement structured logging (e.g. `tracing`) at the same time — not deferred. Each pipeline stage (load, validate, generate, apply) should emit actionable log output at appropriate levels (`info` for progress, `debug` for generated commands, `error` for failures). This makes `dry-run` and `apply` debuggable from day one.

---

## 3. Per-zone src/dest scoping in generated rules

Generated rules currently set `src=*` and `dest=*`, matching only on `src_ip` / `dest_ip`. Replace `*` with computed zone names from the zone-aware tag resolution map.

When a rule's `allowFrom` resolves to source IPs across N zones, emit N rules — one per source zone, each with that zone's name in `src` and only that zone's IPs in `src_ip`. The `dest` zone is the zone the target IP belongs to (`device` if the target is `$node`, otherwise the matching zone). This naturally distinguishes input rules (router as destination) from forward rules (downstream destination) without separate code paths.

The same-network filter on the source IP set stays — it correctly skips rules that would never match because the traffic doesn't traverse the firewall (same-subnet, L2-bridged). It is not replaced with a same-zone filter — same-zone-different-subnet traffic is intra-zone forwarding and may legitimately need rules.

Tested end-to-end: rules in `/etc/config/firewall` show explicit src/dest zone names with no `*`, and access from a wrong-zone source is rejected.
