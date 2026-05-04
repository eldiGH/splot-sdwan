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

All four share one flat per-node namespace — within a single node, names across all four kinds must be unique. They can recur freely across nodes (`Jawo` and `Karcze` can both have a `printer` and a `lan`).

A bare name in `allowFrom` resolves only against the global namespace. To reference anything inside a node, qualify it with the node name.

### Tag resolution

A reference in `allowFrom` is one of:

- **Bare name** — globally-scoped: explicit tag, node, or global client
- **Qualified `{NodeName}.{LocalName}`** — anything inside a node (zone, device, VPN interface, VPN client)
- **`$node`** or **`$node.{LocalName}`** — the current router; context-dependent (resolves differently per router being configured)

Resolution always produces a set of IPs or subnets — never zone names. Zone names are tracked separately on the resolved IPs and used to scope generated firewall rules.

| Reference                                | Resolves to                                                              |
| ---------------------------------------- | ------------------------------------------------------------------------ |
| Explicit tag (e.g. `admin`)              | All IPs/subnets of things tagged with it (across the whole config)       |
| Node name (e.g. `Jawo`)                  | Union of all of Jawo's `zones` subnets and `vpnInterfaces` subnets       |
| Global client name (e.g. `Pixel8`)       | All of the client's known IPs                                            |
| `{Node}.{Zone}` (e.g. `Jawo.lan`)        | That zone's subnet                                                       |
| `{Node}.{Device}` (e.g. `Jawo.printer`)  | The device's IP                                                          |
| `{Node}.{VpnInterface}`                  | The interface's subnet                                                   |
| `{Node}.{VpnClient}`                     | The client's IP                                                          |
| `$node`                                  | Union of router's own IPs across all its `zones` and `vpnInterfaces`     |
| `$node.{Zone}` or `$node.{VpnInterface}` | Router's own IP on that specific zone or VPN interface                   |

**Subnets vs IPs.** Bare/qualified node-name forms (`Jawo`, `Jawo.lan`) resolve to *subnets* — broad, "any device on those networks." `$node` forms resolve to *IPs* — narrow, "the router itself as a host." These are complementary, not interchangeable.

**Addressless zones contribute nothing.** A zone declared without an `address` (e.g. a NAT-ed WAN whose IP is managed by the operator) is silently excluded from anything that aggregates subnets or IPs — including bare node names and bare `$node`.

### Zones

Zones are first-class in the config (under each node's `zones` map). They represent the downstream networks the router serves; the operator configures them in OpenWRT, splot just references them.

Beyond user-declared zones, splot also creates and manages OpenWRT zones for the things it owns: the mesh interface (`spl_mesh`) and each `vpnInterface` (named after the interface). Splot-managed zones default to `input DROP`; access is granted only via explicit service rules.

Generated firewall rules are scoped per-zone in both `src` and `dest` — when an `allowFrom` set resolves to source IPs across multiple zones, splot emits one rule per source zone with that zone in `src` and only that zone's IPs in `src_ip`.

### Forwarding rules (forwardTo)

`forwardTo` was dropped entirely. It expressed broad zone-to-zone access, which is anti-zero-trust. All access control goes through `services` with explicit `allowFrom`, port, and protocol. No broad subnet or zone access is allowed by default.

### Services

The only mechanism for access control. Each service declares:

- `port` — port number or range (string)
- `proto` — `tcp`, `udp`, or array (`OneOrMany`)
- `allowFrom` — one or more tag/name references; resolved as above

Services can be declared at multiple levels: on a node (router-hosted), on a device, on a VPN client, or on a global client.

### meshIp

Each node declares its mesh IP explicitly. This is intentional:

- Inserting a new node must not silently change existing nodes' IPs
- Mesh IPs are the addressing substrate the future distributed apply mechanism will run on — they must be stable across config updates
- Auto-assignment from node order in the file was considered and rejected for these reasons
