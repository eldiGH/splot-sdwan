# splot Configuration Reference

The config file (`splot.yml`) describes the entire mesh network. Every router in the mesh uses the same shared config. splot reads it, identifies which node it is by matching its WireGuard public key, and generates the appropriate network, DHCP, and firewall configuration for that router.

---

## Top-level structure

```yaml
meshNetwork: 10.0.0.0/16
keepaliveInterval: 25
nodes:
  <nodeName>: { ... }
clients:
  <clientName>: { ... }
```

| Field               | Type                    | Required | Description                                                                                                                                                                                                     |
| ------------------- | ----------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `meshNetwork`       | CIDR (`x.x.x.x/prefix`) | yes      | The whole WireGuard mesh address space: every `meshIp` and every hub network.                                                                                                                                   |
| `keepaliveInterval` | integer (seconds)       | no       | Seconds between WireGuard keepalives, for the hosts that send them: only a host behind NAT that offers services does, to keep its NAT mapping open for whoever connects to it. Default `25`; `0` turns none on. |
| `nodes`             | map of name → Node      | yes      | Routers participating in the mesh.                                                                                                                                                                              |
| `clients`           | map of name → Client    | no       | Roaming devices accessible across the mesh (phones, laptops). Global, cross-node.                                                                                                                               |

---

## Node

Represents a single router in the mesh.

```yaml
HomeRouter:
  publicKey: base64...
  endpoint: 1.2.3.4
  listenPort: 51820
  meshIp: 10.0.0.1
  zones:
    lan: { ... }
  hub: { ... }
  services: { ... }
  tags: home
```

| Field           | Type                       | Required | Description                                                                                                                                                                                                       |
| --------------- | -------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `publicKey`     | string                     | yes      | WireGuard public key as printed by `wg pubkey` (44 characters, ending in `=`; unique across all nodes and clients). splot uses this to identify which node it's running on.                                                                                                                            |
| `endpoint`      | IPv4 address               | yes      | Public IP used by other mesh nodes to establish WireGuard connections.                                                                                                                                            |
| `listenPort`    | integer                    | yes      | WireGuard listen port for the mesh interface.                                                                                                                                                                     |
| `meshIp`        | IPv4 address               | yes      | This node's IP on the mesh WireGuard interface (within `meshNetwork`).                                                                                                                                            |
| `zones`         | map of name → Zone         | no       | Downstream networks the router serves (LAN, VLANs).                                                                                                                                                               |
| `hub`           | Hub                        | no       | A network inside `meshNetwork` for devices that reach the mesh through this node alone. See [Hub](#hub).                                                                                                         |
| `services`      | map of name → Service      | no       | Services exposed by the router itself (e.g. SSH, admin UI).                                                                                                                                                       |
| `wanZone`       | string                     | no\*     | Name of the OpenWRT firewall zone that is WAN-facing on this router. Splot does not manage this zone; it only references it when generating port forwards. \*Required if any service uses this node in `wan.via`. |
| `tags`          | string or list of strings  | no       | Explicit tags assigned to the node. See [Tags](#tags).                                                                                                                                                            |

---

## Zone

A downstream network the router serves. Splot does **not** manage zones in OpenWRT — the operator configures them — splot only references them when generating rules. The map key is the OpenWRT zone name on that router.

```yaml
lan:
  address: 192.168.1.1/24
  devices:
    Printer: { ... }
  tags: trusted
```

| Field     | Type                      | Required | Description                                                         |
| --------- | ------------------------- | -------- | ------------------------------------------------------------------- |
| `address` | CIDR (`x.x.x.x/prefix`)   | yes      | The router's IP and subnet on this zone.                            |
| `devices` | map of name → ZoneDevice  | no       | Known devices on this zone.                                         |
| `tags`    | string or list of strings | no       | Explicit tags assigned to this zone. Resolves to the zone's subnet. |

WAN zones are not modeled here — they are not splot zones. If a router has a WAN interface that needs port forwards, declare its OpenWRT zone name in the node's `wanZone` field. See [WAN exposure](#wan-exposure).

---

## Zone Device

A known device on one of the node's zones.

```yaml
Printer:
  ip: 192.168.1.50
  macs: aa:bb:cc:dd:ee:ff
  tags: admin
  services:
    access:
      port: "9100"
      proto: tcp
      allowFrom: admin
```

| Field      | Type                      | Required | Description                                                             |
| ---------- | ------------------------- | -------- | ----------------------------------------------------------------------- |
| `ip`       | IPv4 address              | yes      | Device's IP. Must fall within its containing zone's `address` subnet.   |
| `macs`     | MAC string or list        | no       | MAC addresses. Used to generate static DHCP leases on the hosting node. |
| `tags`     | string or list of strings | no       | Explicit tags assigned to this device.                                  |
| `services` | map of name → Service     | no       | Services exposed by this device.                                        |

---

## Hub

A network inside `meshNetwork` that the node sets aside for devices reaching the mesh through it alone — typically something behind NAT that offers services, like a camera on an LTE modem. Its clients are WireGuard peers on the node's mesh interface (same key, same port); splot creates no extra interface or firewall zone for them.

```yaml
hub:
  network: 10.0.10.0/24
  clients:
    lte-cam: { ... }
  tags: cameras
```

| Field     | Type                      | Required | Description                                                                                                                       |
| --------- | ------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `network` | CIDR (`x.x.x.x/prefix`)   | yes      | The hub's network. Must lie inside `meshNetwork`, must not overlap another node's hub, and must not contain any node's or global client's `meshIp`. |
| `clients` | map of name → HubClient   | no       | The devices behind this hub. A hub may be empty.                                                                                  |
| `tags`    | string or list of strings | no       | Explicit tags assigned to the hub. Resolve to the hub's network.                                                                  |

How a hub is wired:

- A hub client is a peer **on its hub node only**. (A global client with `meshIp`, by contrast, is a peer on every node.)
- Every other node routes the **whole hub network** through the hub node — it's part of the hub node's peer `AllowedIPs` everywhere, even while the hub has no clients. Adding a client later changes only the hub node.
- **One address, one path.** WireGuard sends a packet to the peer whose `AllowedIPs` match it most specifically, without checking whether that peer is up. So no two peers may claim the same address: the hub network belongs to the hub node alone, which is why no `meshIp` may lie inside it and hubs may not overlap.
- Everything on a hub arrives over the mesh interface, so it's in splot's mesh zone. Firewall rules tell hub clients apart by source IP: WireGuard drops any packet whose source isn't in the sending peer's `AllowedIPs`, so the source IP identifies the client.
- `{NodeName}.hub` refers to the hub network (see [Tags](#tags)); `hub` is a reserved name on every node.

---

## Hub Client

A device that reaches the mesh through its hub node.

```yaml
lte-cam:
  publicKey: base64...
  ip: 10.0.10.10
  tags: cameras
  services: { ... }
```

| Field       | Type                      | Required | Description                                                                                                         |
| ----------- | ------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------- |
| `publicKey` | string                    | yes      | WireGuard public key as printed by `wg pubkey` (44 characters, ending in `=`; unique across all nodes and clients). |
| `ip`        | IPv4 address              | yes      | The client's IP. Must lie inside the hub's `network` (not its network or broadcast address) and be unique in it.     |
| `tags`      | string or list of strings | no       | Explicit tags assigned to this client.                                                                              |
| `services`  | map of name → Service     | no       | Services exposed by this client and accessible through the mesh.                                                    |

---

## Client (global)

A roaming device that can be reached across the mesh. Unlike a hub client (which reaches the mesh through one node), a global client with `meshIp` is a peer on every node, and it may also have IPs on several nodes' zones.

```yaml
Phone:
  meshIp: 10.0.0.100
  publicKey: base64...
  macs:
    - aa:bb:cc:dd:ee:01
    - aa:bb:cc:dd:ee:02
  ips:
    HomeRouter:
      lan: 192.168.1.30
    WorkRouter:
      lan: 192.168.10.30
  services: { ... }
  tags: admin
```

| Field       | Type                                                | Required | Description                                                                                                                          |
| ----------- | --------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `meshIp`    | IPv4 address                                        | no       | The client's IP on the mesh interface (within `meshNetwork`). Set when the client connects directly to the mesh via WireGuard.       |
| `publicKey` | string                                              | no       | WireGuard public key as printed by `wg pubkey` (44 characters, ending in `=`; unique across all nodes and clients). Required if `meshIp` is set — otherwise the client can't be a WireGuard peer.                          |
| `macs`      | MAC string or list                                  | no       | MAC addresses. Used to generate static DHCP leases for the client's zone IPs on each node.                                           |
| `ips`       | map of nodeName → (map of localName → IPv4 address) | no       | The client's IPs on each node, keyed by zone name within that node. See [Tags](#tags) for resolution.                                |
| `services`  | map of name → Service                               | no       | Services exposed by this client.                                                                                                     |
| `tags`      | string or list of strings                           | no       | Explicit tags assigned to this client.                                                                                               |

---

## Service

A network service that should be reachable from specific parts of the mesh, externally via WAN, or both.

```yaml
ssh:
  port: "22"
  proto: tcp
  allowFrom: [admin, HomeRouter.Printer]
  wan:
    via: [HomeRouter]
    sources: ["1.2.3.4/32"]
```

| Field       | Type                      | Required | Description                                                                                                                         |
| ----------- | ------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `port`      | string                    | yes      | Port number or range. Use `"external:internal"` form to translate ports for WAN forwards; bare `"22"` means same external/internal. |
| `proto`     | string or list of strings | yes      | Protocol(s). Accepted values: `tcp`, `udp`.                                                                                         |
| `allowFrom` | string or list of strings | no       | Tags or qualified references whose resolved addresses are granted LAN/mesh access. See [Tags](#tags).                               |
| `wan`       | WAN exposure object       | no       | Declares external (WAN) exposure of this service. See [WAN exposure](#wan-exposure).                                                |

A service must grant access in at least one direction — either `allowFrom` or `wan` must be set. A service with neither is operationally meaningless (warning).

Services may be declared on:

- A **node** (`node.services`) — the router itself hosts the service
- A **zone device** (`zone.devices.<name>.services`) — the device hosts the service
- A **hub client** (`hub.clients.<name>.services`) — the client hosts the service
- A **global client** (`client.services`) — the client hosts the service, reachable on any node where it has an IP

---

## WAN exposure

A service can be exposed on the public internet via one or more routers' WAN zones using its `wan` field. This generates an OpenWRT port forward (DNAT) on each listed router.

```yaml
wan:
  via: [HomeRouter, BackupRouter]
  sources: ["1.2.3.4/32", "203.0.113.0/24"]
```

| Field             | Type                                    | Required | Description                                                                                                                                                                           |
| ----------------- | --------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `via`             | string or list of WAN targets           | yes      | Nodes whose `wanZone` should forward to this service. Each entry is either a bare node name (`HomeRouter`) or — for global client services only — a qualified `{Node}.{Network}` form (`HomeRouter.lan`). Each listed node must declare `wanZone`. Special identifiers like `$node` are _not_ allowed. See [Destination IP selection](#destination-ip-selection). |
| `sources` | CIDR string or list (e.g. `1.2.3.4/32`) | no       | Allowlist of public source CIDRs that may hit the forward. Missing or empty = publicly accessible.                                                                                    |

### Semantics

- **`via` lists which routers expose this service.** The forward is rendered on each listed router's `wanZone`. Multi-router exposure is just adding to the list.
- **`via` accepts only explicit node names.** Special identifiers like `$node` are deliberately not allowed — WAN exposure is security-sensitive, and shortcuts here invite mass-exposure accidents. List the routers you actually mean.
- **For global client services, `via` entries can be qualified** as `{Node}.{Network}` to explicitly target one of the client's networks on that node (bypassing the automatic resolution chain). See [Destination IP selection](#destination-ip-selection).
- **The forward destination is the service's hosting IP**, automatically resolved per WAN-providing router. See [Destination IP selection](#destination-ip-selection) below for the rule.
- **`sources` is CIDR-only** — splot identifiers are not accepted because they all resolve to internal addresses with no meaningful WAN-side semantics. Real WAN allowlists (office IP, partner CIDRs, webhook source ranges) are always arbitrary public CIDRs.
- **Empty/missing `sources` means public** — anyone on the internet can reach the forwarded port. Use `sources` to restrict.
- **`wan.sources` does not overlap with service-level `allowFrom`**: `allowFrom` controls LAN/mesh accept rules using splot identifiers; `sources` restricts WAN-side sources using raw CIDRs. They're independent.
- **Splot does not gate WAN exposure beyond `sources`** — if you need richer logic, configure the OpenWRT firewall directly.

### Destination IP selection

A port forward needs a single DNAT destination IP. Splot picks the target per WAN-providing router based on the service's host. Three of the four host types have unambiguous targets; only global clients require a priority rule.

**Per host type:**

| Service host | DNAT target | Exposable from |
| --- | --- | --- |
| **Node service** (`node.services`) | The hosting node's `meshIp` | Any node with `wanZone` |
| **Zone device service** (`zone.devices.*.services`) | The device's `ip` | Any node with `wanZone` |
| **Hub client service** (`hub.clients.*.services`) | The client's `ip` | Any node with `wanZone` |
| **Global client service** (`config.clients.*.services`) | See priority rule below | Restricted — see below |

For the first three host types, the host has exactly one canonical address. The mesh routing reaches that address from every router, so any node with `wanZone` can expose them via cross-node DNAT. No restrictions.

**Global client priority rule, per WAN-providing router R (bare `via` entry):**

1. If the client has `meshIp` → use it.
2. Else if the client has a zone IP on R → use it (a client has at most one zone per node).
3. Else → **validation error**: the client has no reachable address from R.

This produces strict restrictions for global clients without `meshIp`:

- **With `meshIp`**: client can be exposed via any node with `wanZone`. DNAT targets `meshIp`.
- **Without `meshIp`**: client can only be exposed via nodes it has a zone IP on. Attempts to expose via any other node fail validation.

### Qualified `via` form for global clients

For global client services, a `via` entry may use the qualified form `{Node}.{Network}` where `{Network}` is the name of a **zone** on `{Node}`. The qualified form is **client-only** — using it on a service hosted by a node, zone device, or hub client is a validation error (those have unambiguous single-IP targets; no choice to make).

**Semantics:**

- `via: [HomeRouter.lan]` — target the client's IP at `ips.HomeRouter.lan`. The bare-form resolution chain is **not** consulted at all.
- The qualified form **overrides** even `meshIp`. If the operator writes `HomeRouter.lan`, the DNAT target is the client's lan IP on HomeRouter, regardless of whether `meshIp` is set.
- The client **must** have an IP entry at `ips.{Node}.{Network}`. If not declared, validation fails (`WanClientNotOnQualifiedNetwork`).
- `{Network}` must be a zone on `{Node}`. References to other per-node entities (devices, hub clients) are rejected — they're not "networks the global client is reachable on."

**When to use which form:**

- **Bare `{Node}`** (preferred default) — let splot pick the most stable address via the priority rule.
- **Qualified `{Node}.{Network}`** — use when you need to force a specific routing leg for operational reasons (e.g., target the client's LAN IP even though `meshIp` exists).

**Why `meshIp` takes precedence.** A client's `meshIp` is reachable from every node whenever the client's mesh tunnel is up — _regardless of where the client is physically located_. Even when a client is connected to a router's LAN as a wired device, an active mesh WireGuard tunnel still terminates on its `meshIp` (the WG-encapsulated traffic just travels over the LAN instead of the internet). So `meshIp` is the most stable static target.

**Why local IPs are restricted to same-node exposure.** A client's zone IP only addresses the client when the client is physically present on that network. Using a client's IP on node A to expose it via node B's WAN would produce a forward that only works when the client happens to be at A — a silently-broken state whenever the client is elsewhere. Splot doesn't generate such forwards statically; the operator must either declare `meshIp` (stable cross-node address) or add the client to B's networks too.

**Stationary clients can also be zone devices.** A device with a single IP on one zone and no need to roam (a wired printer, an IoT sensor) can be modeled as a `zone.devices` entry instead of a `client`. Zone devices have one IP by structure and can be WAN-exposed from any node with no restrictions. Use the global client model when a device legitimately has presence on multiple nodes or needs to be reachable across the mesh by a stable name.

**Dynamic retargeting (future).** A planned daemon (see IDEAS.md → Dynamic device presence) will watch DHCP leases on each router and dynamically retarget WAN forwards based on where the client actually is at runtime. This enables exposure scenarios the static rule rejects — e.g., exposing a no-`meshIp` client via a router it doesn't statically have an IP on, because the daemon retargets at runtime to wherever the client currently appears. Static config behavior is unchanged.

### Cross-node WAN exposure

A service on a global client can be forwarded by any router that can reach the client. For example, a service on `Phone` (with a mesh IP) can be exposed via `HomeRouter`'s WAN:

```yaml
clients:
  Phone:
    meshIp: 10.0.0.100
    publicKey: ...
    services:
      webApp:
        port: 8080
        proto: tcp
        wan:
          via: [HomeRouter] # HomeRouter forwards 8080 → Phone's mesh IP:8080
```

`Phone`'s config doesn't reference `HomeRouter`. If `WorkRouter` should also expose Phone's service, just add it to `via`. The two forwards are independent.

### Security note

The splot WAN model is intentionally minimal: a service is either WAN-exposed or it isn't, with optional CIDR-based source filtering. No splot identifier participates in WAN allowlisting. The principle is to minimize external attack surface — every `wan` field in `splot.yml` is a publicly visible port, easy to audit with `grep wan splot.yml`.

---

## Tags

Tags are the sole access control abstraction. They appear in `allowFrom` on services to define which sources are permitted.

### How tags are assigned

Tags can be assigned explicitly via the `tags` field on any named object (node, zone, zone device, hub, hub client, global client). Additionally, every named object has an **implicit tag equal to its own name** — but the namespace scope depends on the kind of object.

### Reference forms in `allowFrom`

A reference is one of:

- **Bare name** — resolves in the global namespace: an explicit tag, a node name, or a global client name
- **Qualified `{NodeName}.{LocalName}`** — resolves in that node's per-node namespace: a zone, zone device, or hub client — or the hub itself, as `{NodeName}.hub`
- **`$node`** — the current router being configured (context-dependent — resolves to a different router per node being generated)

### What a reference resolves to

Resolution always produces a set of IP addresses or subnets — never zone names directly. Zone names are tracked separately and used to scope generated firewall rules.

| Reference                                         | Resolves to                                                              |
| ------------------------------------------------- | ------------------------------------------------------------------------ |
| Explicit tag (e.g. `admin`)                       | All IPs/subnets of things tagged with it (across the whole config)       |
| Node name (e.g. `HomeRouter`)                     | Union of the node's `zones` subnets and its hub network                  |
| Global client name (e.g. `Phone`)                 | All of the client's known IPs                                            |
| `{Node}.{Zone}` (e.g. `HomeRouter.lan`)           | That zone's subnet                                                       |
| `{Node}.{ZoneDevice}` (e.g. `HomeRouter.Printer`) | The device's IP                                                          |
| `{Node}.hub` (e.g. `HomeRouter.hub`)              | The node's hub network                                                   |
| `{Node}.{HubClient}` (e.g. `HomeRouter.lte-cam`)  | The hub client's IP                                                      |
| `$node`                                           | Union of the router's own IPs across all its `zones`                     |

A single tag can group multiple objects if they share it. `allowFrom: admin` grants access from every device, client, or hub tagged `admin` — across multiple nodes.

### Subnets vs IPs

Bare and qualified node-name forms (`HomeRouter`, `HomeRouter.lan`) resolve to **subnets** — broad, meaning "any device on those networks." `$node` resolves to **IPs** — narrow, meaning "the router itself as a host." These are complementary, not interchangeable.

Use the bare node name when you want any traffic from that node's downstream networks. Use `$node` (on that node's own rules) when you specifically want the router's interface IPs as source or destination.

### Examples

```yaml
allowFrom: admin                          # everything tagged admin (cross-node)
allowFrom: HomeRouter                     # all of the node's zone subnets + its hub network
allowFrom: HomeRouter.lan                 # only the node's lan zone subnet
allowFrom: HomeRouter.Printer             # specific device's IP
allowFrom: HomeRouter.hub                 # the node's hub network
allowFrom: HomeRouter.lte-cam             # a hub client's IP
allowFrom: Phone                          # global client's IPs
allowFrom: [admin, HomeRouter.iot]        # admin-tagged things + the node's iot zone subnet
allowFrom: $node                          # the router's own IPs across all its interfaces
```

---

## Uniqueness rules

Splot uses two namespaces with strict no-collision rules.

### Global namespace

The global namespace contains exactly three kinds of names:

- Node names (keys of top-level `nodes`)
- Global client names (keys of top-level `clients`)
- Explicit tag names (any string used in any `tags` field, anywhere)

**Within the global namespace, all names must be unique.** No collisions between any of these three groups, and no duplicates within any single group. `allowFrom: foo` in any service must resolve to exactly one global entity.

### Per-node namespace

Each node has its own per-node namespace, holding the names of:

- The node's `zones`
- All zone devices (`zones.<zone>.devices.<name>`)
- All hub clients (`hub.clients.<name>`)

**Within a single node, names across all three categories must be unique.** A node can't have a zone named `Printer` and a device named `Printer`, for example. Names can recur freely across different nodes — two nodes can both have a `lan` zone, or both have a `Printer` device.

### Cross-namespace collisions are also forbidden

A name in any node's per-node namespace must not collide with any name in the global namespace. So if `HomeRouter` is a node name, no node may have a zone, device, or hub client also named `HomeRouter`. This keeps every reference unambiguous.

### Implicit name-tags

Every named object has an implicit tag equal to its name. Where that tag lives:

- **Globally-scoped implicit tags** (referenced by bare name): nodes, global clients
- **Per-node-scoped implicit tags** (referenced as `{NodeName}.{LocalName}`): zones, zone devices, hub clients — and the hub itself, as `{NodeName}.hub`

The qualified `{NodeName}.{LocalName}` syntax is intentionally only **two levels deep** — the per-node namespace is flat. There is no `{NodeName}.{Zone}.{Device}` form; a device is referenced as `{NodeName}.{Device}` directly. This works because per-node names across all three categories are unique.

### `$node`

`$node` is a special context-dependent tag that resolves to the router currently being configured. It produces the router's own IPs across all of its `zones`.

### Allowed characters

Names must contain only alphanumeric characters, `-`, and `_`. Spaces, dots, and other special characters are forbidden — names are used as part of generated UCI section identifiers, and `.` is reserved as the qualified-reference separator.

### Reserved names

`hub` can't name a zone, zone device, or hub client on any node: `{NodeName}.hub` always refers to the node's hub network. It's reserved on nodes without a hub too, so adding a hub later can't break a config.

### Reserved prefixes for per-node-scoped names

A per-node-scoped name (zone, zone device, hub client) must not start with `{NodeName}_` where `{NodeName}` is the name of any node in the config. For example, if there is a node named `Home`, no per-node-scoped name anywhere may be `Home_printer`, `Home_lan`, etc.

The reason is generated UCI rule names. Splot qualifies a rule for a remote node's object by prefixing the node name with `_` (e.g. `Home_printer_ssh` for an `ssh` service on Home's `printer`). A literal name like `Home_printer` on another node would collide with that qualified form. `_` itself stays a valid character — only the specific `{NodeName}_` prefix is reserved.

---

## Subnet uniqueness

Every subnet in the mesh must be unique and non-overlapping. This includes:

- The `meshNetwork` subnet
- Each zone's `address` subnet (when present)

Hub networks are the exception: each lies **inside** `meshNetwork`, which is the whole mesh address space. They must not overlap each other, and no node's or global client's `meshIp` may lie inside one (see [Hub](#hub)).

Overlapping subnets cause ambiguous routing and may produce incorrect or conflicting firewall rules. The validator enforces this across the entire config.

---

## `client.ips` rules

A global client's `ips` field maps each node's name to a per-node map keyed by zone name on that node and valued by the client's IP on that zone.

**At most one zone entry per `(client, node)`.** A client may not have IPs on multiple zones of the same node — DHCP can't generate two static leases under the same client name on the same router. A device that physically appears on only one zone at a time (the realistic case) fits this trivially. For the rare multi-NIC-on-one-router setup, model it as two separate client entries.

Each IP must fall within its named network's subnet. The validator enforces this — a key like `HomeRouter.lan: 10.5.5.5` is rejected if `10.5.5.5` is not in HomeRouter's `lan` zone subnet.

---

## Holistic validation

Beyond the structural rules above, the validator flags configurations that are syntactically valid but operationally meaningless. These may be reported as **warnings** or **errors** depending on the severity of the resulting silent no-op:

- **Global client with neither `meshIp` nor `ips`.** Such a client is unreachable: nothing addresses it. The client name resolves to the empty set of IPs but never matches traffic.
- **Global client with `publicKey` but no `meshIp`.** The public key isn't used anywhere — a global client is a WireGuard peer only through its `meshIp`. Either remove the key or add a `meshIp`.
- **Subnet-mismatched IPs in `client.ips`.** As above — the IP doesn't fall within the named network's subnet.
- **Service with neither `allowFrom` nor `wan`.** No source can reach this service from any direction; the service declaration has no effect.

Future entries in this list will land here as the validator grows.
