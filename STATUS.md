# Implementation Status

Snapshot of what splot currently does. Treat this as a complement to [ROADMAP.md](ROADMAP.md) (what's planned) and [CONFIG.md](CONFIG.md) (full config reference).

---

## Done and working

### Config parsing

- YAML config loader at `src/config.rs` — deserializes `splot.yml` into typed Rust structs (`Config`, `Node`, `Zone`, `VpnInterface`, `Client`, `Service`, etc.).
- Custom `OneOrManyUnique<T>` type — accepts a single value or a list in YAML, deduplicated into a `HashSet`. Used for `tags`, `macs`, `proto`, `allowFrom`.
- `deny_unknown_fields` at the top-level `Config` struct catches typos in field names.
- Typed IP / network handling via `src/types/ip.rs` (`Ipv4Addr`, `Ipv4Interface`, `Ipv4Network` with subnet membership / overlap predicates).
- Typed MAC handling via `src/types/mac.rs`.

### Splot config (persistent local state)

- Local state file managed by `src/splot_config.rs` — currently stores only the WireGuard private key.
- `ensure_initialized()` creates the file with a generated keypair on first run; subsequent runs read the existing key.
- Designed to grow as more local-only state is needed (e.g., last-applied config snapshot for distributed-reload rollback — see IDEAS.md).

### Config validator (`src/validator/`)

Multi-pass validator that checks `splot.yml` before any UCI commands are generated. Five passes, each producing data the next consumes:

1. **`names`** — collects global + per-node names; checks identifier syntax, namespace uniqueness, cross-namespace collisions, reserved prefixes (`spl_` and `{NodeName}_`).
2. **`tags`** — collects valid tags; checks tag syntax and tag/name collisions.
3. **`identifiers`** — checks every `allowFrom` reference resolves to a known identifier; warns on empty `allowFrom`.
4. **`entities`** — semantic checks: client IPs reference valid node/network, mac/publicKey required-iff-used, unreachable clients, devices in addressless zones (will be dropped with WAN work).
5. **`networks`** — subnet uniqueness across mesh + zones + VPN interfaces; IP-in-subnet containment; IP uniqueness per mesh/zone/VPN-interface; `client.ips` ≤ 1 zone per `(client, node)`.

Plus a `ports` pass: per-node listen-port uniqueness (`node.listen_port` vs each `vpn_interface.listen_port`).

The validator is module-complete but not yet wired into `main.rs` — that lands with the CLI work.

### Firewall config generation (`src/managers/firewall/`)

- **Zones (`zones.rs`)**: splot-managed zones rendered as `config zone` UCI sections — the mesh zone (`spl_mesh`) and one per `vpnInterface` on the current node. Default policy `input DROP`; access granted only via explicit service rules.
- **Rules (`rules.rs`)**: per-service `config rule` UCI sections generated from `services` declared anywhere in the config (node, device, VPN client, global client). Each `allowFrom` reference is resolved through the tag-resolution map to a set of source IPs, then split into one rule per source zone.
- **Tag resolution (`tag_resolution.rs`)**: builds the IP/subnet → zone map used by rule generation. Handles explicit tags, bare node names, qualified `{Node}.{LocalName}` forms, and `$node`. Currently the only mechanism for access control.

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

### WireGuard key handling (`src/wg.rs`)

- Generates new private keys via `wg genkey`.
- Derives public keys from private keys via `wg pubkey`.
- Used during `splot_config` initialization and to identify the current node by matching the local pubkey against `node.publicKey` in the config.

### UCI section naming (`src/naming.rs`)

- Canonical names for splot-generated UCI sections — uses the `spl_` prefix (declared in `consts.rs`) to keep splot-managed sections distinct from operator-managed ones.
- Qualified naming scheme for cross-node rules: a remote device's service is namespaced by node name (e.g., `Jawo_printer_ssh`), preventing collisions with same-name objects on different nodes.

---

## Not done yet

See [ROADMAP.md](ROADMAP.md). At a glance, in priority order:

1. **WAN exposure** — port forwards as a first-class service feature; drops addressless-zone support along the way.
2. **CLI** — `validate` / `dry-run` / `apply` entry points; wires the validator into the pipeline and adds structured logging.
3. **Per-zone src/dest scoping** — replace `src=*` / `dest=*` in generated rules with explicit zone names.

See [IDEAS.md](IDEAS.md) for longer-horizon ideas (mesh-wide DNS, distributed reload, dynamic device presence, etc.).
