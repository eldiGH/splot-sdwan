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

- New `wan` field: object with `via: [<nodeName>...]` and optional `sources: [<CIDR>...]`.
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

- For each `wan.via` entry: parse as either bare `{Node}` or qualified `{Node}.{Network}`.
  - **Bare form**: must be a known node name; must declare `wanZone`; no special identifiers (`$node` etc.).
  - **Qualified form**: only allowed on global client services. `{Node}` must exist + declare `wanZone`. `{Network}` must be a zone or VPN interface on that node. The client must have an IP entry at `ips.{Node}.{Network}`.
- For each `wan.sources` entry: must parse as a valid IPv4 CIDR. No identifier resolution.
- External port uniqueness check per `(router, proto)` — two services can't both bind external port 8080/tcp on the same router's WAN.
- Destination IP resolvability per `(client service, bare via entry)`:
  - If the bare entry produces multiple VPN-interface candidates (no `meshIp`, no zone IP on R, ≥2 VPN-interface IPs on R) → require qualified form.
  - If the bare entry produces zero candidates (no `meshIp`, no local presence on R) → unreachable.

Update:

- `ServiceAllowFromEmpty` warning becomes `ServiceUnreachable` — fires when both `allowFrom` and `wan` are empty (no access from any direction).

### Generation changes

- New UCI section type emitted: `config redirect` for port forwards. Goes in `/etc/config/firewall`.
- For each `(router, service-with-wan)` pair: emit one `redirect` per protocol with `src = wanZone`, `src_dport`, `dest_ip`, `dest_port`, and `src_ip` (when `sources` is non-empty).
- **Emit accept rules along the mesh path.** When the host is on a different node than the WAN-providing router, the post-DNAT traffic crosses the mesh: WAN zone on entry router → mesh zone on entry router → mesh zone on host router → host's zone (LAN/VPN). Each hop needs a forward-accept rule for the rewritten 5-tuple. Splot's design guarantees the *route* exists (mesh `allowed_ips` covers everything); the generator's job is to lay the firewall rules along it.
- Existing `allowFrom`-based accept rules continue to be generated independently — `wan` and `allowFrom` populate separate UCI sections, no cross-coupling.
- The `port: "external:internal"` shorthand is used as: external for the WAN redirect's `src_dport`, internal for the redirect's `dest_port` and for any LAN accept rules.

### Open questions to resolve during implementation

- **Destination IP resolution:** finalized.
  - Node, zone-device, VPN-interface-client services: unambiguous single-IP target, exposable from any node with `wanZone`.
  - Global client services: bare `via` entry triggers priority rule per WAN-providing router R — `meshIp` → zone IP on R → unique VPN-interface IP on R → ambiguity error (multi-VPN) or unreachable error (none). Without `meshIp`, exposure is restricted to nodes the client has a local IP on.
  - Qualified `via` form `{Node}.{Network}` (client-only) bypasses the chain and forces a specific network's IP as the target. Used to disambiguate multi-VPN cases or override the chain.
  - Implementation: shared resolution function used by both validator and generator, taking the parsed `WanViaTarget` (bare or qualified) and returning the resolved IP or a typed error reason. See CONFIG.md → [Destination IP selection](CONFIG.md#destination-ip-selection) for the full rule.
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

---

## 4. Replace `ConfigPath` with a typed location enum

`ConfigPath` is currently `Vec<String>` — every path segment allocates, literals (`"nodes"`, `"services"`) get copied to heap, and the path's structure is invisible to the type system. Replace with an enum that captures the meaningful locations in the config tree, e.g.:

```rust
pub enum ConfigLocation {
    MeshNetwork,
    Node(Identifier),
    NodeListenPort(Identifier),
    NodeService(Identifier, Identifier),
    Zone(Identifier, Identifier),
    Device(Identifier, Identifier, Identifier),
    VpnInterfaceClientService(Identifier, Identifier, Identifier, Identifier),
    // ... etc.
}
```

`Display` impl renders each variant as the dotted path. Wins: zero allocation for static segments, type-safe construction (the validator can't accidentally build `nodes.foo.zones.tags.tags` like the old `tags.rs` bug), every error site is a single enum variant — easier to test and to find all sites touching a given config location.

Trade-off: more variants to maintain when adding new locations; less flexible for ad-hoc paths during exploration.

Open design choices:

- **Embed `ServiceLocation` as a variant** (`ConfigLocation::Service(ServiceLocation)`) vs flat layout with `From<ServiceLocation>` conversion. Embedded models the natural "services are a kind of config location" relationship in the type system; flat reads slightly cleaner per variant.
- **Owned `Identifier` vs borrowed `&'a Identifier`** in variant fields. Borrowed is allocation-free but propagates a lifetime through `ValidationError<'a>` and `ValidationReport<'a>` — fine for sync use-immediately validators, problematic if reports ever need to outlive the config or cross thread boundaries. Start owned; switch to borrowed only if profiling shows the allocations matter.

---

## 5. `Config::services()` iterator / `ServiceLocation` abstraction

Multiple validators and generators iterate the same set of service hosts (clients, node services, zone-device services, vpn-interface-client services) with near-identical nested-loop boilerplate. Extract:

```rust
pub enum ServiceLocation<'a> {
    Client { client_name: &'a Identifier, service_name: &'a Identifier },
    NodeService { node_name: &'a Identifier, service_name: &'a Identifier },
    ZoneDevice {
        node_name: &'a Identifier,
        zone_name: &'a Identifier,
        device_name: &'a Identifier,
        service_name: &'a Identifier,
    },
    VpnClient {
        node_name: &'a Identifier,
        vpn_interface_name: &'a Identifier,
        client_name: &'a Identifier,
        service_name: &'a Identifier,
    },
}

impl Config {
    pub fn services(&self) -> impl Iterator<Item = (&Service, ServiceLocation<'_>)>;
}
```

Validators consume the iterator; `ServiceLocation::to_config_path()` (or `ConfigLocation` per item 4) lives in the validator. Generators (rules.rs, redirect.rs) use the same iterator with their own per-host logic via match.

Cleans up ~150 lines of nested-loop duplication across validators and generators. Defer until WAN feature lands and the duplication is fully visible.
