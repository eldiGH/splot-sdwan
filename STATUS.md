# Implementation Status

Snapshot of what splot currently does. Treat this as a complement to [ROADMAP.md](ROADMAP.md) (what's planned) and [CONFIG.md](CONFIG.md) (full config reference).

---

## Done and working

### Config parsing

- YAML config loader at `src/config.rs` — deserializes `splot.yml` into typed Rust structs (`Config`, `Node`, `Zone`, `VpnInterface`, `Client`, `Service`, etc.).
- Custom `OneOrManyUnique<T>` type — accepts a single value or a list in YAML, deduplicated into a `BTreeSet`. Used for `tags`, `macs`, `proto`, `allowFrom`.
- All config maps and sets are `BTreeMap`/`BTreeSet`, so iteration order — and with it validation output and generated UCI — is deterministic across runs.
- `deny_unknown_fields` on every config struct: a misspelled key anywhere is a parse error naming the config path, the unknown key, the valid keys, and the line/column.
- Typed IP / network handling via `src/types/ip.rs` (`Ipv4Addr`, `Ipv4Interface`, `Ipv4Network` with subnet membership / overlap predicates).
- Typed MAC handling via `src/types/mac.rs`.
- Typed WireGuard public keys via `src/types/wg_key.rs` (`WgPublicKey`): 44 characters of canonical base64 ending in `=` — the same check stored private keys go through, and the same rule `wg` itself enforces.

### Splot config (persistent local state)

- Local state file (`/etc/config/splot`) managed by `src/splot_config.rs` via the `SplotConfig` struct — stores the mesh private key (`splot.config.private_key`) and one private key per `vpnInterface` on this node (`splot.vpn_interface_keys.<name>`).
- `SplotConfig::load()` reads and validates the mesh key, generating and committing one on first run (idempotent init — handles missing file, section, or option uniformly). `ensure_vpn_keys()` does the same per declared VPN interface, batching new keys into a single commit.
- Stored keys are validated on load; a corrupt key is a hard error naming the offending interface, never silently regenerated (regeneration would orphan paired clients).
- Designed to grow as more local-only state is needed (e.g., last-applied config snapshot for distributed-reload rollback — see IDEAS.md).

### Config validator (`src/validator/`)

Multi-pass validator that checks `splot.yml` before any UCI commands are generated. Several passes, the first few producing data the next consumes:

1. **`names`** — collects global + per-node names; checks identifier syntax, namespace uniqueness, cross-namespace collisions, reserved prefixes (`spl_` and `{NodeName}_`).
2. **`tags`** — collects valid tags; checks tag syntax and tag/name collisions.
3. **`identifiers`** — checks every `allowFrom` reference resolves to a known identifier; warns on empty `allowFrom`.
4. **`entities`** — semantic checks: client IPs reference valid node/network, mac/publicKey required-iff-used, public keys unique across nodes / VPN clients / global clients, unreachable clients.
5. **`networks`** — subnet uniqueness across mesh + zones + VPN interfaces; IP-in-subnet containment, and host IPs may not be their subnet's network or broadcast address (/31 and /32 excepted); IP uniqueness per mesh/zone/VPN-interface; `client.ips` ≤ 1 zone per `(client, node)`.

Plus a `ports` pass (per-node listen-port uniqueness — `node.listen_port` vs each `vpn_interface.listen_port`) and a `wan` pass: each `wan.via` target resolves to a reachable destination; the qualified `{Node}.{Network}` form is rejected on non-client services; `wanZone` is declared where needed and doesn't collide with a zone / VPN-interface / mesh name; declared-but-unused `wanZone` is a warning.

The validator runs in `main.rs` before any UCI generation — validation errors abort the run.

### Firewall config generation (`src/managers/firewall/`)

- **Zones (`zones.rs`)**: splot-managed zones rendered as `config zone` UCI sections — the mesh zone (`spl_mesh`) and one per `vpnInterface` on the current node. Default policy `input`/`forward` `DROP`, `output ACCEPT`; access granted only via explicit service rules.
- **Rules (`rules.rs`)**: per-service `config rule` UCI sections generated from `services` declared anywhere in the config (node, device, VPN client, global client). Each `allowFrom` reference is resolved through the tag-resolution map to a set of source IPs (same-LAN sources are filtered out, since they don't traverse this router). Rules currently match on `src_ip` / `dest_ip` with `src` / `dest` left as `*` — per-zone scoping is still pending (see [ROADMAP.md](ROADMAP.md)).
- **Redirects (`redirect.rs`)**: `config redirect` (DNAT port-forward) UCI sections for services that declare `wan`. `wan.via` selects which routers expose the service via their `wanZone`; the destination IP and zone are resolved per host type (node → `meshIp`, device → `ip`, VPN client → `ip`, global client → priority chain). Cross-node exposure works — one node can forward to a service hosted on another over the mesh. `wan.sources` (the CIDR allowlist) is applied as the redirect's `src_ip`: empty/missing means publicly reachable, a non-empty list restricts the forward to those CIDRs.
- **Tag resolution (`tag_resolution.rs`)**: builds the IP/subnet → zone map used by rule generation. Handles explicit tags, bare node names, qualified `{Node}.{LocalName}` forms, and `$node`. Currently the only mechanism for LAN/mesh access control.

### Network interface generation (`src/managers/network.rs`)

- Generates `config interface` UCI sections for the splot-managed WireGuard interfaces on the current node:
  - The mesh interface (one per node, `spl_mesh`)
  - One per `vpnInterface` declared on the node
- Peer sections (`config wireguard_<iface>`) for each remote node (mesh peers) and each VPN client.
- Includes WireGuard-specific knobs: `listen_port`, `private_key`, `public_key`, `endpoint_host`, `endpoint_port`, `allowed_ips`, `persistent_keepalive`.

### DHCP config generation (`src/managers/dhcp.rs`)

- Generates `config host` UCI sections for static DHCP leases.
- Sources:
  - Zone devices with `macs` — one lease per zone IP, attached to each declared MAC.
  - Global clients (`config.clients`) with `macs` and zone IPs on the current node.
- Lease ties MAC to the zone IP so the device gets a predictable address every connection.

### Batch UCI command execution (`src/uci.rs`, `src/pipeline.rs`)

- `UciPipeline` runs registered managers in sequence on each apply.
- Generated UCI commands are accumulated into a batch and applied via `uci batch`, then committed atomically per affected config file (`network`, `dhcp`, `firewall`).
- Reduces overhead vs invoking `uci` once per setting; gives all-or-nothing semantics per config file.
- The uci module exposes plain functions (`get`, `show`, `batch`) over a shared `run()` helper with typed errors (`uci::Error`): spawn failures, I/O errors, and non-zero exits are distinguished, and uci's exact `Entry not found` message is classified as legitimate absence (`Ok(None)`) rather than failure.
- Dry-run output redacts private-key values (`UciBatchCommand::redacted()`); the real batch input is never redacted.

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

### UCI section naming (`src/managers/naming.rs`)

- Section names are a uci concern: the generated structs (`FirewallRule`, `FirewallRedirect`, …) carry what an object is (its name, a rule's `direction`), and `to_uci_commands()` turns that into a section name. Other backends will name things their own way.
- Every generated section name, and every reference to one, is built by `UciSectionName`: the `spl_` prefix (declared in `consts.rs`) keeps splot-managed sections apart from operator-managed ones, parts are joined with `_`, and `-` is mapped to `_` by `uci::name` (uci rejects `-` in section and option names).
- Where a uci file mixes kinds, the name carries a kind tag, so different kinds can't collide: WireGuard peers `spl_peer_<interface>_<name>`, firewall rules `spl_in_…` (traffic to this node's hosts) / `spl_out_…` (from local sources to other nodes), port forwards `spl_dnat_…`. Interfaces, zones and DHCP hosts keep `spl_<name>`, because other config refers to them by name.
- Cross-node rules are namespaced by node name (e.g. `spl_out_Home_printer_ssh`).
- Safety net: the pipeline refuses a batch that creates the same section twice (`find_duplicate_sections`), instead of letting uci merge the two into one. It runs before splot touches uci at all.

### Tests (`cargo test`)

Unit-test suite over the deterministic core (~213 tests). Covers: type parsers (`src/types/`), WAN/config resolution (`src/config.rs`), all validator passes (`src/validator/`), the tag-resolution map, the UCI generators (firewall redirects/rules/zones, network, dhcp), UCI command/builder rendering, the uci not-found classification and dry-run redaction, private-key validation, and mesh-vs-vpn key routing in generated interfaces. Tests are inline `#[cfg(test)] mod tests` at the bottom of each module; config-level cases build fixtures from YAML via `serde_norway` with shared helpers in `src/test_support.rs` (plus a test-only `SplotConfig::for_tests` constructor). The process/IO layer (uci process execution, wg, splot_config state, env, pipeline) is intentionally out of scope — to be covered later as integration tests. Conventions: [CLAUDE.md → Testing](CLAUDE.md#testing).

---

## Not done yet

See [ROADMAP.md](ROADMAP.md). At a glance, in priority order:

1. **Per-zone src/dest scoping** — replace `src=*` / `dest=*` in generated accept rules with explicit zone names (redirects are already zone-scoped).
2. **Nodes behind NAT** — optional `endpoint` for the hub-and-spoke shape.
3. **Stale VPN-key pruning** — detect keys stored for interfaces no longer in the config; warn by default, delete behind an explicit `--prune-keys` flag.
4. **Enrollment UX** — a `splot pubkey` subcommand (ensure key exists, print the public key) so new routers can be enrolled over SSH without hopping consoles.

See [IDEAS.md](IDEAS.md) for longer-horizon ideas (mesh-wide DNS, distributed reload, dynamic device presence, etc.).
