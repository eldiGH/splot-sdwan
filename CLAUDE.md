# splot-sdwan

## Project Purpose

A Rust helper tool for managing WireGuard mesh networks on OpenWRT routers. It synchronizes configuration between multiple routers and configures network, DHCP, and firewall settings using the `uci` utility.

## Goals

- Automate WireGuard mesh network setup across multiple OpenWRT routers
- Sync configuration state between routers
- Drive network, DHCP, and firewall config via `uci`

## Project Context

This is a hobby project that started as a way to learn Rust and systems programming. The goal now is a tool the owner actually runs on their network — while keeping full control over its architecture and direction.

**Collaboration style — the owner is the architect, Claude is the engineer:**

- **The owner decides:** architecture, config shape, design decisions (tasks tagged `decision`), and whether each change goes in. When a task runs into a real design question, stop and ask — don't pick an answer silently.
- **Claude implements** one task at a time from the owner's task list: tests first (watch them fail), then the change; `cargo test`, `cargo fmt --check` and `cargo clippy -- -D warnings` clean.
- **Review gate:** leave each task's changes **uncommitted**. The owner reviews them in Neovim (diffview / gitsigns) and says "commit" or asks for changes; only then commit, with the task ID in the subject.
- **Every task ends with a review guide:** what changed and why; where the risk is and the 2–3 spots worth reading; what the tests prove and what was verified; which files are mechanical and safe to skim. Keep commits single-purpose — formatting-only or mechanical changes separate from logic.

---

## Design Decisions

### Config philosophy

The config is intentionally free of OpenWRT/uci implementation details. The user thinks in terms of nodes, zones, devices, and tags. The app translates those to firewall rules and uci commands. If a concept belongs to the implementation (uci section types, splot's own naming conventions for generated objects), it does not belong in the config.

Real network architecture (subnets, VLANs, NAT) is not an implementation detail — those concepts can appear in the config when they reflect what the operator genuinely needs to express.

### Top-level config shape

- `meshNetwork` — the whole WireGuard mesh address space: the nodes' and global clients' `meshIp`, and the nodes' hub networks
- `nodes` — map of routers participating in the mesh
- `clients` — map of *global* clients: roaming things (phones, laptops) with optional MACs and per-node IPs, accessible across the mesh

Each node carries:

- mesh metadata (`publicKey`, `endpoint`, `listenPort`, `meshIp`)
- `zones` — map of downstream networks the router serves (LAN, VLANs). The map key is the OpenWRT zone name on that router. Splot does not manage these zones in OpenWRT — the operator configures them — splot only references them when generating rules.
- `hub` — a network inside `meshNetwork` for devices that reach the mesh through this node alone (hub clients). See "Hubs".
- `services` — services exposed by the router itself
- `wanZone` — name of the OpenWRT firewall zone that is WAN-facing (only required if any service uses this node in `wan.via`)
- `tags` — explicit tags on the node

### Tags

Tags are the sole access control abstraction. They appear in `allowFrom` on services. They can be applied to nodes, zones, devices, hubs, hub clients, and global clients.

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
- Hub client names

All three share one flat per-node namespace — within a single node, names across all three kinds must be unique. They can recur freely across nodes (`Home` and `Cabin` can both have a `printer` and a `lan`). `hub` is reserved in every node's namespace: `{NodeName}.hub` refers to the node's hub network.

A bare name in `allowFrom` resolves only against the global namespace. To reference anything inside a node, qualify it with the node name.

### Tag resolution

A reference in `allowFrom` is one of:

- **Bare name** — globally-scoped: explicit tag, node, or global client
- **Qualified `{NodeName}.{LocalName}`** — anything inside a node (zone, device, hub client, or the hub itself as `{NodeName}.hub`)
- **`$node`** — the current router; context-dependent (resolves differently per router being configured)

Resolution always produces a set of IPs or subnets — never zone names. Zone names are tracked separately on the resolved IPs and used to scope generated firewall rules.

| Reference                                | Resolves to                                                              |
| ---------------------------------------- | ------------------------------------------------------------------------ |
| Explicit tag (e.g. `admin`)              | All IPs/subnets of things tagged with it (across the whole config)       |
| Node name (e.g. `Home`)                  | Union of Home's `zones` subnets and its hub network                      |
| Global client name (e.g. `Pixel8`)       | All of the client's known IPs                                            |
| `{Node}.{Zone}` (e.g. `Home.lan`)        | That zone's subnet                                                       |
| `{Node}.{Device}` (e.g. `Home.printer`)  | The device's IP                                                          |
| `{Node}.hub` (e.g. `Home.hub`)           | The node's hub network                                                   |
| `{Node}.{HubClient}`                     | The hub client's IP                                                      |
| `$node`                                  | Union of router's own IPs across all its `zones`                         |

**Subnets vs IPs.** Bare/qualified node-name forms (`Home`, `Home.lan`) resolve to *subnets* — broad, "any device on those networks." `$node` resolves to *IPs* — narrow, "the router itself as a host." These are complementary, not interchangeable.

### Zones

Zones are first-class in the config (under each node's `zones` map). They represent the downstream networks the router serves; the operator configures them in OpenWRT, splot just references them.

Beyond user-declared zones, splot also creates and manages one zone of its own: the mesh interface's (`spl_mesh`). Everything that arrives over WireGuard is in it — other nodes, global clients, and hub clients. It defaults to `input` and `forward` `DROP` (and `output ACCEPT`); access is granted only via explicit service rules.

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

Services can be declared at multiple levels: on a node (router-hosted), on a device, on a hub client, or on a global client.

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
- **`wan.via` takes explicit node names, never `$node` or other shortcuts**: the security cost of an operator misunderstanding a shortcut (and mass-exposing a service) outweighs the few characters saved. The one exception: for **global-client services**, an entry may be qualified as `{Node}.{Network}` to pick which of the client's networks on that node to forward to. The qualified form is client-only — using it on a node/device/hub-client service is a validation error, since those hosts have a single unambiguous address.
- **Cross-node WAN exposure works naturally**: a service on a global client (Phone) can be exposed via `wan.via: [HomeRouter]`. HomeRouter generates the redirect to Phone's mesh-reachable IP. No change to Phone's config.
- **Splot does not manage the WAN zone in OpenWRT** — the operator owns its declaration. Splot just references it by name via `node.wanZone`.

### meshIp

Each node declares its mesh IP explicitly. This is intentional:

- Inserting a new node must not silently change existing nodes' IPs
- Mesh IPs are the addressing substrate the future distributed apply mechanism will run on — they must be stable across config updates
- Auto-assignment from node order in the file was considered and rejected for these reasons

### Hubs

A hub is a network inside `meshNetwork` that a node sets aside for devices reaching the mesh through it alone — typically something behind NAT that offers services (a camera on an LTE modem). Hub clients are peers on the node's mesh interface (same key, same port), not on a separate WireGuard interface. Hubs replaced per-node `vpnInterfaces`.

- **Why no separate interface:** WireGuard drops any packet whose source isn't in the sending peer's `AllowedIPs`, so on one interface the source IP identifies the peer, and splot's IP-based rules are as strong as per-interface zones — provided `AllowedIPs` never overlap.
- **One address, one path:** WireGuard sends to the peer with the longest matching prefix and doesn't check whether that peer is up. Every other node routes the whole hub network to the hub node (it's in that node's peer `AllowedIPs`, even while the hub is empty), so hub networks don't overlap and no `meshIp` lies inside one. A hub network lies inside `meshNetwork`: the mesh is one address space.
- **Hub client vs global client:** a hub client is a peer on its hub node only; a global client with `meshIp` is a peer on every node.
- **Firewall:** everything on a hub arrives over the mesh interface, so it's in splot's mesh zone; rules tell hub clients apart by source IP.
- **References:** hub clients join the node's namespace (`Home.camera`); `Home.hub` and the hub's `tags` refer to the whole hub network, the way a zone's name and tags do; a bare node name includes it.

---

## Testing

### Scope

Tests cover the **deterministic core**: type parsers (`src/types/`), WAN/config resolution (`src/config.rs`), all validator passes (`src/validator/`), the tag-resolution map, the UCI generators (firewall redirects/rules/zones, network, dhcp), and UCI command/builder rendering. The process/IO layer (`uci` executor, `wg`, `splot_config`, `env`, `pipeline`, `main`) is **out of scope** for now — it shells out and touches the filesystem; revisit as integration tests later.

### Placement

Tests are inline `#[cfg(test)] mod tests { use super::*; ... }` modules, always the **last item in the file**. Inline (not a separate `tests/` dir) because this is a binary crate and tests need access to private / `pub(super)` items (validator passes, generator helpers, the `UciSectionBuilder`). Follow `src/types/mac.rs` as the style reference.

### Fixtures

- **Pure type parsers** are driven directly through `FromStr` with a small local `parse()` helper.
- **Config-level tests** build a `Config` from a YAML string via `serde_norway::from_str` — this mirrors real loading and exercises the serde layer too. Shared helpers live in `src/test_support.rs` (`#[cfg(test)]`-only, `pub(crate)`): `config()`, `report()`, and `has_error` / `has_warning` / `error_at` matchers. The matchers take closures because `ValidationError` / `ValidationWarning` don't derive `PartialEq` — match on the variant with `matches!(..)`.

### Snapshots

`example_config_snapshot` (in `src/managers/mod.rs`) pins the complete UCI output of all managers for every node of `splot.example.yml`, using [`insta`](https://insta.rs). Snapshot files live in `src/managers/snapshots/` and are committed. They record what splot generates today, known-wrong parts included.

- **Any change to generator output fails this test on purpose.** Insta prints the line diff of the generated config; the diff is the review: "is this the config change I meant?"
- **Accept an intended change** with `cargo insta review` (needs `cargo install cargo-insta`), or `INSTA_UPDATE=always cargo test` and then review the `.snap` diff in git. Never accept a snapshot change you haven't read.
- **A change that touches generator output** comes with its snapshot diff in the same commit, so the commit shows what it does to the generated router config.
- Keep the example config representative: a new feature that generates config should appear in `splot.example.yml`, which puts it under the snapshot too.

### Conventions

- **Iteration order is deterministic** — config collections are `BTreeMap`/`BTreeSet`, so walking the config (and with it validation output and generated UCI) happens in sorted key order, and tests may assert positional order. The `HashMap`/`HashSet` left in the validator are lookup-only; don't iterate them into output. Where order isn't what a test is about, a predicate-style assertion ("contains an item matching …") is still the sturdier choice. The builder sorts list values (`extend_list`), and an empty list emits no line — which is how "no `wan.sources` ⇒ public" is pinned down.
- **Sorted order can hide order-dependent bugs.** When a check compares items against each other (name collisions, shadowing, overlaps), a fixture that only works because of how its names sort proves nothing — cover both orderings (e.g. the conflicting name sorting before *and* after the thing it collides with).
- **A test must be able to fail.** Avoid fixtures where the asserted name/value can't occur — a check against something absent from the fixture passes vacuously and proves nothing. When a test guards a filter, assert both the positive (expected thing appears) and the negative (the wrong thing is absent), ideally in both generation directions.
- **Use generic placeholder names** in fixtures — `Home`, `Cabin`, `Phone`, and obviously-fake endpoints (`1.2.3.4`) and keys. Public keys are validated, so a fake must still be well-formed: 42 × one letter + `A=` (`AAAA…AAA=`, `BBBB…BBA=`), a different letter per entity since keys must be unique. Never real deployment names, keys, or endpoints; real config lives only in the git-ignored `splot.yml`.

### Verify

`cargo test`, `cargo fmt --check`, and `cargo clippy -- -D warnings` all stay clean. Sanity-check a new test by temporarily inverting the condition it guards — if it still passes, it isn't testing what it claims.

When dependencies change, `cargo audit` (RustSec advisory database) must report no advisories. It exits 0 even for "unsound"/"unmaintained" warnings, so read its output rather than the exit code.

**Against real OpenWrt:** unit tests check the generators against splot's own assumptions; `scripts/openwrt-check.sh [VERSION...]` checks them against OpenWrt. It boots an OpenWrt container per version (default: the versions in use), runs `splot apply` there with `splot.example.yml` as node Home, and asks OpenWrt's own tools: `fw4 check` (every section accepted, not skipped), the live ruleset, `dnsmasq --test` and dnsmasq running, WireGuard interfaces up with their peers and address, no errors in the log, a second apply that changes nothing, and a peer update reaching WireGuard (live where the version supports renew). Run it when a change touches generated config or the apply/reload path. Needs podman, the Rust target `x86_64-unknown-linux-musl`, and the host's `wireguard` kernel module (`sudo modprobe wireguard`). The container workarounds (IPv4 package downloads, AppArmor, ujail, a DHCP WAN) are explained in `scripts/openwrt/prepare.sh`.
