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

- Local state file (`/etc/config/splot`) managed by `src/splot_config.rs` via the `SplotConfig` struct — stores the node's one private key, for the mesh interface (`splot.config.private_key`).
- `SplotConfig::load()` reads and validates the key, generating and committing one on first run (idempotent init — handles missing file, section, or option uniformly).
- A stored key is validated on load; a corrupt key is a hard error, never silently regenerated (regeneration would orphan the node's peers).
- Designed to grow as more local-only state is needed (e.g., last-applied config snapshot for distributed-reload rollback — see IDEAS.md).

### Config validator (`src/validator/`)

Multi-pass validator that checks `splot.yml` before any UCI commands are generated. Several passes, the first few producing data the next consumes:

1. **`names`** — collects global + per-node names; checks identifier syntax, namespace uniqueness, cross-namespace collisions, reserved prefixes (`spl_` and `{NodeName}_`) and the reserved local name `hub`; registers `{NodeName}.hub` for nodes with a hub.
2. **`tags`** — collects valid tags; checks tag syntax and tag/name collisions.
3. **`identifiers`** — checks every `allowFrom` reference resolves to a known identifier; warns on empty `allowFrom`.
4. **`entities`** — semantic checks: client IPs reference valid node/network, mac/publicKey required-iff-used, public keys unique across nodes / hub clients / global clients, unreachable clients.
5. **`networks`** — subnet uniqueness across mesh + zones; hub networks lie inside `meshNetwork`, don't overlap each other, and hold no `meshIp`; IP-in-subnet containment, and host IPs may not be their subnet's network or broadcast address (/31 and /32 excepted); IP uniqueness per mesh/zone/hub; `client.ips` ≤ 1 zone per `(client, node)`.

Plus a `ports` pass (per-host service-port uniqueness, the node's WireGuard listen port included, and external-port uniqueness on each router's WAN) and a `wan` pass: each `wan.via` target resolves to a reachable destination; the qualified `{Node}.{Network}` form is rejected on non-client services; `wanZone` is declared where needed and doesn't collide with a zone or the mesh name; declared-but-unused `wanZone` is a warning.

The validator runs in `main.rs` before any UCI generation — validation errors abort the run.

### Firewall config generation (`src/managers/firewall/`)

- **Zones (`zones.rs`)**: splot's one managed zone, the mesh zone (`spl_mesh`), rendered as a `config zone` UCI section. Everything that arrives over WireGuard is in it, hub clients included. Default policy `input`/`forward` `DROP`, `output ACCEPT`; access granted only via explicit service rules.
- **Rules (`rules.rs`)**: per-service `config rule` UCI sections generated from `services` declared anywhere in the config (node, device, hub client, global client). Each `allowFrom` reference is resolved through the tag-resolution map to a set of source IPs (same-LAN sources are filtered out, since they don't traverse this router). Rules currently match on `src_ip` / `dest_ip` with `src` / `dest` left as `*` — per-zone scoping is still pending (see [ROADMAP.md](ROADMAP.md)).
- **Redirects (`redirect.rs`)**: `config redirect` (DNAT port-forward) UCI sections for services that declare `wan`. `wan.via` selects which routers expose the service via their `wanZone`; the destination IP and zone are resolved per host type (node → `meshIp`, device → `ip`, hub client → `ip` in the mesh zone, global client → priority chain). Cross-node exposure works — one node can forward to a service hosted on another over the mesh. `wan.sources` (the CIDR allowlist) is applied as the redirect's `src_ip`: empty/missing means publicly reachable, a non-empty list restricts the forward to those CIDRs.
- **Tag resolution (`tag_resolution.rs`)**: builds the IP/subnet → zone map used by rule generation. Handles explicit tags, bare node names, qualified `{Node}.{LocalName}` forms (including `{Node}.hub`), and `$node`. Everything on a hub resolves under the mesh zone. Currently the only mechanism for LAN/mesh access control.

### Network interface generation (`src/managers/network.rs`)

- Generates the `config interface` UCI section for the node's one WireGuard interface, the mesh interface (`spl_mesh`).
- Peer sections (`config wireguard_spl_mesh`):
  - each remote node, with `AllowedIPs` = its `meshIp`, its zones and its hub network (even while the hub is empty);
  - each global client with `meshIp`;
  - this node's own hub clients (peers on their hub node only).
- Includes WireGuard-specific knobs: `listen_port`, `private_key`, `public_key`, `endpoint_host`, `endpoint_port`, `allowed_ips`, `persistent_keepalive`.

### DHCP config generation (`src/managers/dhcp.rs`)

- Generates `config host` UCI sections for static DHCP leases.
- Sources:
  - Zone devices with `macs` — one lease per zone IP, attached to each declared MAC.
  - Global clients (`config.clients`) with `macs` and zone IPs on the current node.
- Lease ties MAC to the zone IP so the device gets a predictable address every connection.

### Batch UCI command execution (`src/uci.rs`, `src/pipeline/`)

- `UciPipeline` runs registered managers in sequence on each apply. It is the whole OpenWrt apply — check, stage, commit, reload — so `main` only reports the result.
- Apply refuses to start while `network`, `firewall` or `dhcp` has uncommitted uci changes. uci keeps staged changes in one place per file, shared by every uci user on the router, so splot would commit (or revert) someone else's changes together with its own.
- It then stages everything (deleting splot's old sections, creating the new ones) in one `uci batch` without commits. `uci batch` exits 0 even when it rejects a line — it prints the error to stderr and carries on — so any stderr output counts as failure: splot reverts its staged changes and commits nothing.
- Only then does it commit, file by file. Commits across files aren't atomic: if one fails (e.g. a full flash), the files before it keep the new config, and the error says which.
- The uci module exposes plain functions (`get`, `show`, `has_changes`, `batch`, `commit`, `revert`) over a shared `run()` helper with typed errors (`uci::Error`): spawn failures, I/O errors, non-zero exits and rejected input (stderr output) are distinguished, and uci's exact `Entry not found` message is classified as legitimate absence (`Ok(None)`) rather than failure.
- Dry-run output redacts private-key values (`UciBatchCommand::redacted()`); the real batch input is never redacted.

### Reloading services after apply (`src/pipeline/reload.rs`)

- `uci commit` only writes files. After a commit that changed anything (each file's `uci show` is compared before and after), splot reloads the affected services and reports any failure; nothing changed → no reload.
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

### UCI section naming (`managers/mod.rs` `UciSection`, `managers/naming.rs`)

- Section names are a uci concern. Every generated struct (`WgInterface`, `FirewallZone`, `FirewallRule`, `FirewallRedirect`, `DhcpStaticLease`, and peers via `PeerSection`) implements `UciSection`: its file, its uci section type, an id (what tells it apart from other sections of the same type), and its options. Other backends will name things their own way.
- The section name is derived from that, the same way for every type: `spl_<section type>_<id>`, e.g. `spl_rule_in_Home_ssh`, `spl_redirect_Home_nas_https`, `spl_zone_mesh`, `spl_host_printer`, `spl_wireguard_spl_mesh_Phone`. uci has one namespace per file; the type keeps sections of different types apart. A rule's id includes its direction (`in`: traffic to this node's hosts; `out`: from local sources to other nodes); cross-node rules are namespaced by node name (`spl_rule_out_Home_printer_ssh`).
- Exception: an interface's section name is the interface name (`spl_mesh`). Zone `network` lists and peer section types refer to it, and netifd names the WireGuard device after it (at most 15 characters).
- `UciSectionName` does the mechanics: the `spl_` prefix (declared in `consts.rs`) keeps splot-managed sections apart from operator-managed ones, parts are joined with `_`, and `-` is mapped to `_` by `uci::name` (uci rejects `-` in section and option names).
- Safety net: the pipeline refuses a batch that creates the same section twice (`find_duplicate_sections`), instead of letting uci merge the two into one. It runs before splot touches uci at all.

### Tests (`cargo test`)

Unit-test suite over the deterministic core (~280 tests). Covers: type parsers (`src/types/`), WAN/config resolution (`src/config.rs`), all validator passes (`src/validator/`), the tag-resolution map, the UCI generators (firewall redirects/rules/zones, network, dhcp), UCI command/builder rendering, the uci not-found classification and dry-run redaction, and private-key validation. Tests are inline `#[cfg(test)] mod tests` at the bottom of each module; config-level cases build fixtures from YAML via `serde_norway` with shared helpers in `src/test_support.rs` (plus a test-only `SplotConfig::for_tests` constructor). The process/IO layer (uci process execution, wg, splot_config state, env, pipeline) is intentionally out of scope — to be covered later as integration tests. Conventions: [CLAUDE.md → Testing](CLAUDE.md#testing).

---

## Not done yet

See [ROADMAP.md](ROADMAP.md). At a glance, in priority order:

1. **Per-zone src/dest scoping** — replace `src=*` / `dest=*` in generated accept rules with explicit zone names (redirects are already zone-scoped).
2. **Nodes behind NAT** — optional `endpoint` for the hub-and-spoke shape.
3. **Enrollment UX** — a `splot pubkey` subcommand (ensure key exists, print the public key) so new routers can be enrolled over SSH without hopping consoles.

See [IDEAS.md](IDEAS.md) for longer-horizon ideas (mesh-wide DNS, distributed reload, dynamic device presence, etc.).
