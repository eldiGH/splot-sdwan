# Implementation Status

Snapshot of what splot currently does. Treat this as a complement to [ROADMAP.md](ROADMAP.md) (what's planned) and [CONFIG.md](CONFIG.md) (full config reference).

---

## Done and working

### Config parsing

- YAML config loader at `src/config.rs` — deserializes `splot.yml` into typed Rust structs (`Config`, `Node`, `NodeZone`, `NodeHub`, `Client`, `Service`, etc.).
- Custom `OneOrManyUnique<T>` type — accepts a single value or a list in YAML, deduplicated into a `BTreeSet`. Used for `tags`, `macs`, `proto`, `allowFrom`.
- All config maps and sets are `BTreeMap`/`BTreeSet`, so iteration order — and with it validation output and generated UCI — is deterministic across runs.
- `deny_unknown_fields` on every config struct: a misspelled key anywhere is a parse error naming the config path, the unknown key, the valid keys, and the line/column.
- Typed IP / network handling via `src/types/ip.rs` (`Ipv4Addr`, `Ipv4Interface`, `Ipv4Network` with subnet membership / overlap predicates).
- Typed MAC handling via `src/types/mac.rs`.
- Typed WireGuard public keys via `src/types/wg_key.rs` (`WgPublicKey`): 44 characters of canonical base64 ending in `=` — the same check stored private keys go through, and the same rule `wg` itself enforces.

### Splot config (persistent local state)

- Local state file (`/etc/config/splot`) managed by `src/backend/openwrt/splot_config.rs` via the `SplotConfig` struct (the OpenWrt backend's key store) — stores the node's one private key, for the mesh interface (`splot.config.private_key`).
- `SplotConfig::load()` reads and validates the key, generating and committing one on first run (idempotent init — handles missing file, section, or option uniformly).
- A stored key is validated on load; a corrupt key is a hard error, never silently regenerated (regeneration would orphan the node's peers).
- Designed to grow as more local-only state is needed (e.g., last-applied config snapshot for distributed-reload rollback — see IDEAS.md).

### Config validator (`src/model/validator/`)

Multi-pass validator that checks `splot.yml` before any UCI commands are generated. Several passes, the first few producing data the next consumes:

1. **`names`** — collects global + per-node names; checks identifier syntax, namespace uniqueness, cross-namespace collisions, reserved prefixes (`spl_` and `{NodeName}_`) and the reserved local name `hub`; registers `{NodeName}.hub` for nodes with a hub.
2. **`tags`** — collects valid tags; checks tag syntax and tag/name collisions.
3. **`entities`** — semantic checks: client IPs reference valid node/network, mac/publicKey required-iff-used, public keys unique across nodes / hub clients / global clients, unreachable clients.
4. **`networks`** — subnet uniqueness across mesh + zones; hub networks lie inside `meshNetwork`, don't overlap each other, and hold no `meshIp`; IP-in-subnet containment, and host IPs may not be their subnet's network or broadcast address (/31 and /32 excepted); IP uniqueness per mesh/zone/hub; `client.ips` ≤ 1 zone per `(client, node)`.
5. **`ports`** — per-host service-port uniqueness, the node's WireGuard listen port included, and external-port uniqueness on each router's WAN.
6. **`services`** — each service's references (`references.rs`): every `allowFrom` reference resolves to a known identifier, and a service with neither `allowFrom` nor `wan` is a warning; and its WAN exposure (`wan.rs`): each `wan.via` target resolves to a reachable destination, the qualified `{Node}.{Network}` form is rejected on non-client services, `wanZone` is declared where needed; declared-but-unused `wanZone` is a warning.
7. **`wanZone`** — doesn't collide with a zone or the mesh name.

Validation is how the checked model (`src/model/`) gets built: `model::validate(&Config) -> Result<Validated, ValidationReport>` returns a `Network` plus the warnings, or every error and warning. Only `validate` can make a `Network` (its fields are private to `model`), so whatever reads one can rely on what validation checked.

- The passes build the model's pieces while they check: what fails a check is reported and left out, and a `Network` exists only when nothing failed. Each piece is built once, whole, by the pass that knows all of it; nothing is filled in later.
- **Hosts** (`src/model/host.rs`), built by the `networks` pass: every node, zone device, hub client and global client, in config order, as a `HostRef` (its identity: `Node`, `Local { node, name }` or `Client`), its addresses, its MACs and its WireGuard key (hub and global clients). Each address is its IP with the prefix of the subnet it's on, checked to be a host there, and where it lives (`Zone { node, zone }`, `Hub { node }` or `Mesh`).
- **Nodes** (`src/model/node.rs`), built by the same pass: each router's name, key, endpoint and listen port, its mesh address (its mesh IP with the mesh network's prefix, checked), its zones' subnets, its hub network and its `wanZone`. A node whose mesh IP fails its check is left out; a zone or hub that fails its checks is left out of the node.
- **Services** (`src/model/service.rs`), each built whole by the `services` pass and kept in the `Network` by its host: the service's port, protocols, sources and WAN exposure. The sources are its `allowFrom` resolved to the networks each reference names, with where each lives: explicit tags, bare node names (the node's zone subnets and hub network), global client names (all their IPs), qualified `{Node}.{LocalName}` forms (including `{Node}.hub`), and `$node`, which resolves on each node to that router's own address on each of its zones. An unknown reference is an error; a network two references name is listed once. The WAN exposure is: for every `wan.via` node, the host address it forwards to (a node's mesh IP; a device's or hub client's IP; a global client's mesh IP, else its IP on that node's zone, or the zone a qualified `{Node}.{Zone}` names), and the allowed source CIDRs. A target whose address failed its own check is left out, with no second error.
- The planner reads only the `Network`; `main` finds its own node there (by public key, until `--node`). The raw `Config` is read by validation alone.

### Node plan (`src/plan/`)

What one node has to do, by concern, worked out from the `Network`, with no platform in it: `plan::plan(&Network, node) -> Option<NodePlan>`, where `NodePlan { wireguard, firewall, dhcp }`. Each section comes from its own pure planner function, which takes the `Network` and the node (looked up once, by `plan`, so a planner only ever sees one of this network's nodes); DNS joins once it's implemented.

- **`wireguard`**: the mesh interface (listen port, mesh address) and its peers: every other node (routed, with its endpoint), every global client with a mesh IP, and this node's hub clients. Each peer carries its keepalive. No private key: the backend holds it.
- **`firewall`**: the mesh zone's policy (input and forward drop, output accept), the rules (ingress, then egress), and the redirects.
- **`dhcp`**: a lease for every address a host with MACs has on this node's zones.
- Plan objects carry identity (a `HostRef`, the service, a rule's direction), never a backend's name for them: the OpenWrt renderer derives uci section names and labels from it.
- `NodePlan`'s `Display` is a plain-text view of everything in it, one object per line in config notation (`Home`, `Cabin.camera`), snapshot-tested per node of the example config.

### Firewall (planned in `src/plan/firewall/`, rendered by `src/backend/openwrt/firewall/`)

- **Zones (`zones.rs`)**: splot's one managed zone, the mesh zone (`spl_mesh`), rendered as a `config zone` UCI section. Everything that arrives over WireGuard is in it, hub clients included. Default policy `input`/`forward` `DROP`, `output ACCEPT`; access granted only via explicit service rules.
- **Rules (`rules.rs`)**: per-service `config rule` UCI sections for every host's services (node, device, hub client, global client), from the model's hosts: an ingress rule toward the host's addresses on this node, an egress rule toward its addresses on other nodes. A global client's `meshIp` gets no rule yet. Its sources are the service's resolved `allowFrom` as seen from this node (sources on the destination's own zone are filtered out, since they don't traverse this router; the mesh and hubs are routed, so nothing there is filtered). Rules currently match on `src_ip` / `dest_ip` with `src` / `dest` left as `*` — per-zone scoping is still pending (see [ROADMAP.md](ROADMAP.md)).
- **Redirects (`redirect.rs`)**: `config redirect` (DNAT port-forward) UCI sections for services that declare `wan`. `wan.via` selects which routers expose the service via their `wanZone`; each forwards to the target the model resolved for it (see the `wan` pass above), in the mesh zone for mesh and hub addresses. Forwarding to a host on another node isn't right yet: the redirect names the destination zone as it is on the host's own node. `wan.sources` (the CIDR allowlist) is applied as the redirect's `src_ip`: empty/missing means publicly reachable, a non-empty list restricts the forward to those CIDRs.

### WireGuard (planned in `src/plan/wireguard.rs`, rendered by `src/backend/openwrt/network.rs`)

- Generates the `config interface` UCI section for the node's one WireGuard interface, the mesh interface (`spl_mesh`).
- Peer sections (`config wireguard_spl_mesh`):
  - each remote node, with `AllowedIPs` = its `meshIp`, its zones and its hub network (even while the hub is empty);
  - each global client with `meshIp`;
  - this node's own hub clients (peers on their hub node only).
- Includes WireGuard-specific knobs: `listen_port`, `private_key`, `addresses` (the option OpenWrt's WireGuard handler reads; not `address`), `public_key`, `endpoint_host`, `endpoint_port`, `allowed_ips`, `persistent_keepalive`.

### DHCP (planned in `src/plan/dhcp.rs`, rendered by `src/backend/openwrt/dhcp.rs`)

- Generates `config host` UCI sections for static DHCP leases.
- Sources:
  - Zone devices with `macs` — one lease per zone IP, attached to each declared MAC.
  - Global clients with `macs` and zone IPs on the current node.
- Lease ties MAC to the zone IP so the device gets a predictable address every connection.

### Backends (`src/backend/`)

- A `Backend` turns a node's plan into its platform's config: `render(&NodePlan)` (pure, snapshot-tested), `dry_run(&rendered)` (shows what `apply` would change, changing nothing) and `apply(&rendered)` (makes it live, returns what changed). `main` is load → validate → plan → backend.
- The OpenWrt backend (`src/backend/openwrt/`) is the only one so far: it renders the plan as the `network`, `firewall` and `dhcp` uci files, applies them with uci (below) and reloads the services. Its key store is `SplotConfig`.

### Applying on OpenWrt (`src/backend/openwrt/apply.rs`, `uci.rs`)

- Apply is the whole OpenWrt apply — check, stage, commit, reload — so `main` only reports the result.
- Apply refuses to start while `network`, `firewall` or `dhcp` has uncommitted uci changes. uci keeps staged changes in one place per file, shared by every uci user on the router, so splot would commit (or revert) someone else's changes together with its own.
- It reads each file's current state with `uci export` (not `uci show`, which prints a one-value list exactly like an option) and diffs splot's sections against the rendered ones (`diff.rs`). The diff yields logical changes (a section added or removed, an option set or removed, splot's block reordered) that point at the sections they're about; uci commands are produced from them only right before staging, in one place that knows how uci spells them. It stages only deletes for sections that are gone, whole new sections, `set` for changed options, whole-list replacements for changed lists, and `reorder` when splot's sections are out of order. splot's sections stay one block after the operator's, in plan order; the operator's sections are never touched. An unchanged config stages nothing: no batch, no commit, no reload, and the files aren't rewritten.
- What differs is staged in one `uci batch` without commits. `uci batch` exits 0 even when it rejects a line — it prints the error to stderr and carries on — so any stderr output counts as failure: splot reverts its staged changes and commits nothing.
- `--dry-run` prints exactly what would be staged (`# Nothing to change.` when nothing would), with the private key as its placeholder.
- Only then does it commit the files that change, one by one. Commits across files aren't atomic: if one fails (e.g. a full flash), the files before it keep the new config, and the error says which.
- The uci module exposes plain functions (`get`, `show`, `has_changes`, `batch`, `commit`, `revert`) over a shared `run()` helper with typed errors (`uci::Error`): spawn failures, I/O errors, non-zero exits and rejected input (stderr output) are distinguished, and uci's exact `Entry not found` message is classified as legitimate absence (`Ok(None)`) rather than failure.
- The node's private key is never in what's rendered: the plan has no key, so the rendered config holds a placeholder (`<private key>`) where it goes, and so do the snapshot and the dry run. `apply` fills the key in from the key store just before staging. The placeholder isn't a valid key, so it can't pass for one.

### Reloading services after apply (`src/backend/openwrt/reload.rs`)

- `uci commit` only writes files. After committing, splot reloads the services of the files that changed (those the diff touched) and reports any failure; nothing changed → no reload.
- `reload_config` reloads every service whose config changed: fw4 for `firewall`, dnsmasq for `dhcp`, netifd for interface-level changes (key, port, addresses). procd runs these reloads a second later.
- netifd's reload doesn't see peer changes (peers are separate `wireguard_<interface>` sections), so when `network` changed, splot runs `ubus call network reload` (netifd re-reads the config now, so new interfaces exist) and then updates each of its WireGuard interfaces. It asks netifd first (`ubus call network get_proto_handlers`) whether the WireGuard handler supports renew:
  - yes (OpenWrt 25.12+): `ubus call network.interface.<iface> renew` re-runs the setup with `wg syncconf`; live, tunnels stay up.
  - no (24.10): `down` + `up` on the interface; the tunnels drop for a moment.
- Every command is a request to procd/netifd that returns at once; the daemons do the restarts afterwards, independently of splot's session, so a reload that briefly drops the mesh can't cut splot off halfway. splot runs all commands even after one fails, then reports every failure.
- `apply` fails before writing anything when `ubus` isn't available. `--dry-run` lists the reload commands as `#` comments, which `uci batch` ignores.

### CLI (`src/cli.rs`, `src/main.rs`)

- clap-based CLI: `splot check` (validate, report errors/warnings) and `splot apply [--dry-run]`; `-c/--config` overrides the config path (default `splot.yml`).
- `main` returns `anyhow::Result` — errors propagate with context chains (thiserror-typed at module boundaries, anyhow at the application layer); validation failures and an unenrolled router abort with actionable messages.
- Logging via `log`/`env_logger` (`info` progress per manager, `debug` for details).

### WireGuard key handling (`src/wg.rs`)

- Generates new private keys via `wg genkey`.
- Derives public keys from private keys via `wg pubkey`.
- Failures are typed errors (`wg::Error`): a missing `wg` binary, a non-zero exit (with wg's stderr), or non-UTF-8 output — never a panic or an empty key.
- Validates stored private keys structurally (`validate_private_key` — length, base64 charset, padding).
- Used during `splot_config` initialization and to identify the current node by matching the local pubkey against `node.publicKey` in the config.

### UCI section naming (`src/backend/openwrt/section.rs` `UciSection`, `naming.rs`)

- Section names are a uci concern. The OpenWrt renderers implement `UciSection` on the plan objects (the mesh interface and zone, rules, redirects, leases, and peers via `PeerSection`): its file, its uci section type, an id derived from the object's identity (what tells it apart from other sections of the same type), and its options. Other backends will name things their own way.
- The section name is derived from that, the same way for every type: `spl_<section type>_<id>`, e.g. `spl_rule_in_Home_ssh`, `spl_redirect_Home_nas_https`, `spl_zone_mesh`, `spl_host_printer`, `spl_wireguard_spl_mesh_Phone`. uci has one namespace per file; the type keeps sections of different types apart. A rule's id includes its direction (`in`: traffic to this node's hosts; `out`: from local sources to other nodes); cross-node rules are namespaced by node name (`spl_rule_out_Home_printer_ssh`).
- Labels are in the config's notation, so what LuCI shows can be searched for in `splot.yml`: a rule's `name` (`[SPLOT] in: Home ssh`, `[SPLOT] out: Cabin.camera rtsp`), a redirect's (`[SPLOT] Home.nas https`), a peer's `description` (`[SPLOT] Home.lte-cam`). Section names keep uci's character set.
- Exception: an interface's section name is the interface name (`spl_mesh`). Zone `network` lists and peer section types refer to it, and netifd names the WireGuard device after it (at most 15 characters).
- `UciSectionName` does the mechanics: the `spl_` prefix (declared in `consts.rs`) keeps splot-managed sections apart from operator-managed ones, parts are joined with `_`, and `-` is mapped to `_` by `uci::name` (uci rejects `-` in section and option names).
- Safety net: apply refuses a rendered config that holds the same section twice in one file (`find_duplicate_sections`, on the sections themselves), instead of letting uci merge the two into one. It runs before splot touches uci at all.

### Tests (`cargo test`)

Unit-test suite over the deterministic core (~280 tests). Covers: type parsers (`src/types/`), config parsing (`src/config.rs`), all validator passes and the model they build (hosts, reference resolution, WAN targets; `src/model/`), the planners and the plan's plain-text view (`src/plan/`), the uci renderers (firewall zone/rules/redirects, network, dhcp), UCI command/builder rendering, the uci not-found classification and the private-key fill-in, and private-key validation. Tests are inline `#[cfg(test)] mod tests` at the bottom of each module; config-level cases build fixtures from YAML via `serde_norway` with shared helpers in `src/test_support.rs` (plus a test-only `SplotConfig::for_tests` constructor). The process/IO layer (uci process execution, wg, splot_config state, env, the OpenWrt apply) is intentionally out of scope — to be covered later as integration tests. Conventions: [CLAUDE.md → Testing](CLAUDE.md#testing).

---

## Not done yet

See [ROADMAP.md](ROADMAP.md). At a glance, in priority order:

1. **Per-zone src/dest scoping** — replace `src=*` / `dest=*` in generated accept rules with explicit zone names (redirects are already zone-scoped).
2. **Nodes behind NAT** — optional `endpoint` for the hub-and-spoke shape.
3. **Enrollment UX** — a `splot pubkey` subcommand (ensure key exists, print the public key) so new routers can be enrolled over SSH without hopping consoles.

See [IDEAS.md](IDEAS.md) for longer-horizon ideas (mesh-wide DNS, distributed reload, dynamic device presence, etc.).
