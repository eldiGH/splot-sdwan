# splot-sdwan

## Project Purpose

A Rust helper tool for managing WireGuard mesh networks on OpenWRT routers. It synchronizes configuration between multiple routers and configures network, DHCP, and firewall settings using the `uci` utility.

## Goals

- Automate WireGuard mesh network setup across multiple OpenWRT routers
- Sync configuration state between routers
- Drive network, DHCP, and firewall config via `uci`

## Project Context

This is a hobby/learning project. The primary goal is to learn Rust and systems programming concepts through building something practical.

**Collaboration style:** Do not edit code directly. Instead, present options, suggestions, and explanations so the owner can make informed decisions and learn by doing.

---

## Design Decisions

### Config philosophy

The config is intentionally free of OpenWRT/uci implementation details. The user thinks in terms of nodes, zones, devices, and tags. The app translates those to firewall rules and uci commands. If a concept belongs to the implementation (uci section types, splot's own naming conventions for generated objects), it does not belong in the config.

Real network architecture (subnets, VLANs, NAT) is not an implementation detail — those concepts can appear in the config when they reflect what the operator genuinely needs to express.

### Top-level config shape

- `meshNetwork` — subnet for the WireGuard mesh substrate
- `nodes` — map of routers participating in the mesh
- `clients` — map of *global* clients: roaming things (phones, laptops) with optional MACs and per-node IPs, accessible across the mesh

Each node carries:

- mesh metadata (`publicKey`, `endpoint`, `listenPort`, `meshIp`)
- `zones` — map of downstream networks the router serves (LAN, VLANs). The map key is the OpenWRT zone name on that router. Splot does not manage these zones in OpenWRT — the operator configures them — splot only references them when generating rules.
- `vpnInterfaces` — additional WireGuard interfaces hosted by this router for external clients. These zones *are* managed by splot (created in OpenWRT, named after the interface).
- `services` — services exposed by the router itself
- `wanZone` — name of the OpenWRT firewall zone that is WAN-facing (only required if any service uses this node in `wan.via`)
- `tags` — explicit tags on the node

### Tags

Tags are the sole access control abstraction. They appear in `allowFrom` on services. They can be applied to nodes, devices, VPN interfaces, VPN clients, and global clients.

### Implicit name-tags and uniqueness

Every named thing has an implicit tag equal to its name. The namespace scope depends on what kind of thing it is.

**Globally-scoped** (bare name in `allowFrom` works):

- Node names
- Global client names (`config.clients`)
- Explicit tag names

These three share one global namespace. Names must be unique across the entire config — no collisions between any of them.

**Per-node-scoped** (must be referenced as `{NodeName}.{LocalName}`):

- Zone names
- Device names
- VPN interface names
- VPN client names

All four share one flat per-node namespace — within a single node, names across all four kinds must be unique. They can recur freely across nodes (`Home` and `Cabin` can both have a `printer` and a `lan`).

A bare name in `allowFrom` resolves only against the global namespace. To reference anything inside a node, qualify it with the node name.

### Tag resolution

A reference in `allowFrom` is one of:

- **Bare name** — globally-scoped: explicit tag, node, or global client
- **Qualified `{NodeName}.{LocalName}`** — anything inside a node (zone, device, VPN interface, VPN client)
- **`$node`** — the current router; context-dependent (resolves differently per router being configured)

Resolution always produces a set of IPs or subnets — never zone names. Zone names are tracked separately on the resolved IPs and used to scope generated firewall rules.

| Reference                                | Resolves to                                                              |
| ---------------------------------------- | ------------------------------------------------------------------------ |
| Explicit tag (e.g. `admin`)              | All IPs/subnets of things tagged with it (across the whole config)       |
| Node name (e.g. `Home`)                  | Union of all of Home's `zones` subnets and `vpnInterfaces` subnets       |
| Global client name (e.g. `Pixel8`)       | All of the client's known IPs                                            |
| `{Node}.{Zone}` (e.g. `Home.lan`)        | That zone's subnet                                                       |
| `{Node}.{Device}` (e.g. `Home.printer`)  | The device's IP                                                          |
| `{Node}.{VpnInterface}`                  | The interface's subnet                                                   |
| `{Node}.{VpnClient}`                     | The client's IP                                                          |
| `$node`                                  | Union of router's own IPs across all its `zones` and `vpnInterfaces`     |

**Subnets vs IPs.** Bare/qualified node-name forms (`Home`, `Home.lan`) resolve to *subnets* — broad, "any device on those networks." `$node` resolves to *IPs* — narrow, "the router itself as a host." These are complementary, not interchangeable.

### Zones

Zones are first-class in the config (under each node's `zones` map). They represent the downstream networks the router serves; the operator configures them in OpenWRT, splot just references them.

Beyond user-declared zones, splot also creates and manages OpenWRT zones for the things it owns: the mesh interface (`spl_mesh`) and each `vpnInterface` (named after the interface). Splot-managed zones default to `input DROP`; access is granted only via explicit service rules.

Generated firewall rules are scoped per-zone in both `src` and `dest` — when an `allowFrom` set resolves to source IPs across multiple zones, splot emits one rule per source zone with that zone in `src` and only that zone's IPs in `src_ip`.

### Forwarding rules (forwardTo)

`forwardTo` was dropped entirely. It expressed broad zone-to-zone access, which is anti-zero-trust. All access control goes through `services` with explicit `allowFrom`, port, and protocol. No broad subnet or zone access is allowed by default.

### Services

The only mechanism for access control. Each service declares:

- `port` — port number or range (string). `"external:internal"` form translates ports for WAN forwards; bare `"22"` means same external/internal.
- `proto` — `tcp`, `udp`, or array (`OneOrMany`)
- `allowFrom` — optional; one or more tag/name references granting LAN/mesh access
- `wan` — optional; declares WAN exposure on listed routers (see below)

A service must grant access in at least one direction — either `allowFrom` or `wan` must be set. Otherwise the service declaration is operationally meaningless (a warning).

Services can be declared at multiple levels: on a node (router-hosted), on a device, on a VPN client, or on a global client.

### WAN exposure

Port forwarding is expressed *on the service itself*, not as a separate top-level construct. The principle: a service is the single source of truth — port, protocol, and exposure decisions live in one place.

```yaml
wan:
  via: [HomeRouter]                       # list of routers that expose this service via their wanZone
  sources: ["1.2.3.4/32"]         # optional; CIDR-only allowlist. Empty/missing = publicly accessible
```

Key design points:

- **WAN is binary at the splot level**: either a service is publicly exposed (with optional CIDR restriction) or it isn't. There's no middle ground using splot identifiers, because no internal identifier has a meaningful WAN-side equivalent.
- **`sources` is CIDR-only**, not splot identifiers. Reason: splot identifiers resolve to internal addresses; nothing in the config has meaningful WAN-side semantics. Real WAN allowlists (office IP, partner CIDRs, webhook source ranges) are always arbitrary public CIDRs.
- **`allowFrom` and `wan.sources` serve different planes**: `allowFrom` controls LAN/mesh accept rules using splot identifiers; `wan.sources` restricts WAN-side sources using raw CIDRs. Distinct names so operators can't confuse the two.
- **`wan.via` takes explicit node names, never `$node` or other shortcuts**: the security cost of an operator misunderstanding a shortcut (and mass-exposing a service) outweighs the few characters saved. The one exception: for **global-client services**, an entry may be qualified as `{Node}.{Network}` to pick which of the client's networks on that node to forward to. The qualified form is client-only — using it on a node/device/VPN-client service is a validation error, since those hosts have a single unambiguous address.
- **Cross-node WAN exposure works naturally**: a service on a global client (Phone) can be exposed via `wan.via: [HomeRouter]`. HomeRouter generates the redirect to Phone's mesh-reachable IP. No change to Phone's config.
- **Splot does not manage the WAN zone in OpenWRT** — the operator owns its declaration. Splot just references it by name via `node.wanZone`.

### meshIp

Each node declares its mesh IP explicitly. This is intentional:

- Inserting a new node must not silently change existing nodes' IPs
- Mesh IPs are the addressing substrate the future distributed apply mechanism will run on — they must be stable across config updates
- Auto-assignment from node order in the file was considered and rejected for these reasons

---

## Testing

### Scope

Tests cover the **deterministic core**: type parsers (`src/types/`), WAN/config resolution (`src/config.rs`), all validator passes (`src/validator/`), the tag-resolution map, the UCI generators (firewall redirects/rules/zones, network, dhcp), and UCI command/builder rendering. The process/IO layer (`uci` executor, `wg`, `splot_config`, `env`, `pipeline`, `main`) is **out of scope** for now — it shells out and touches the filesystem; revisit as integration tests later.

### Placement

Tests are inline `#[cfg(test)] mod tests { use super::*; ... }` modules, always the **last item in the file**. Inline (not a separate `tests/` dir) because this is a binary crate and tests need access to private / `pub(super)` items (validator passes, generator helpers, the `UciSectionBuilder`). Follow `src/types/mac.rs` as the style reference.

### Fixtures

- **Pure type parsers** are driven directly through `FromStr` with a small local `parse()` helper.
- **Config-level tests** build a `Config` from a YAML string via `serde_yml::from_str` — this mirrors real loading and exercises the serde layer too. Shared helpers live in `src/test_support.rs` (`#[cfg(test)]`-only, `pub(crate)`): `config()`, `report()`, and `has_error` / `has_warning` / `error_at` matchers. The matchers take closures because `ValidationError` / `ValidationWarning` don't derive `PartialEq` — match on the variant with `matches!(..)`.

### Conventions

- **`HashMap` iteration is nondeterministic** — never assert on positional order. Assert "contains an item matching a predicate", collect into sets, or rely on the builder's *sorted* output (e.g. `extend_list` sorts; an empty list emits no line, which is how "no `wan.sources` ⇒ public" is pinned down).
- **A test must be able to fail.** Avoid fixtures where the asserted name/value can't occur — a check against something absent from the fixture passes vacuously and proves nothing. When a test guards a filter, assert both the positive (expected thing appears) and the negative (the wrong thing is absent), ideally in both generation directions.
- **Use generic placeholder names** in fixtures — `Home`, `Cabin`, `Phone`, and obviously-fake keys/endpoints (`AAAA`, `1.2.3.4`). Never real deployment names, keys, or endpoints; real config lives only in the git-ignored `splot.yml`.

### Verify

`cargo test`, `cargo fmt --check`, and `cargo clippy -- -D warnings` all stay clean. Sanity-check a new test by temporarily inverting the condition it guards — if it still passes, it isn't testing what it claims.
