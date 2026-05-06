# splot Configuration Reference

The config file (`splot.yml`) describes the entire mesh network. Every router in the mesh uses the same shared config. splot reads it, identifies which node it is by matching its WireGuard public key, and generates the appropriate network, DHCP, and firewall configuration for that router.

---

## Top-level structure

```yaml
meshNetwork: 10.0.0.0/24
nodes:
  <nodeName>: { ... }
clients:
  <clientName>: { ... }
```

| Field         | Type                              | Required | Description                                                                          |
| ------------- | --------------------------------- | -------- | ------------------------------------------------------------------------------------ |
| `meshNetwork` | CIDR (`x.x.x.x/prefix`)           | yes      | Subnet for the WireGuard mesh substrate that connects all nodes.                     |
| `nodes`       | map of name → Node                | yes      | Routers participating in the mesh.                                                   |
| `clients`     | map of name → Client              | no       | Roaming devices accessible across the mesh (phones, laptops). Global, cross-node.    |

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
  vpnInterfaces:
    wg_admin: { ... }
  services: { ... }
  tags: home
```

| Field           | Type                          | Required | Description                                                                            |
| --------------- | ----------------------------- | -------- | -------------------------------------------------------------------------------------- |
| `publicKey`     | string                        | yes      | WireGuard public key (base64). splot uses this to identify which node it's running on. |
| `endpoint`      | IPv4 address                  | yes      | Public IP used by other mesh nodes to establish WireGuard connections.                 |
| `listenPort`    | integer                       | yes      | WireGuard listen port for the mesh interface.                                          |
| `meshIp`        | IPv4 address                  | yes      | This node's IP on the mesh WireGuard interface (within `meshNetwork`).                 |
| `zones`         | map of name → Zone            | no       | Downstream networks the router serves (LAN, VLANs).                                    |
| `vpnInterfaces` | map of name → VpnInterface    | no       | Additional WireGuard interfaces hosted by this router for external clients.            |
| `services`      | map of name → Service         | no       | Services exposed by the router itself (e.g. SSH, admin UI).                            |
| `tags`          | string or list of strings     | no       | Explicit tags assigned to the node. See [Tags](#tags).                                 |

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

| Field     | Type                          | Required | Description                                                                                                                        |
| --------- | ----------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `address` | CIDR (`x.x.x.x/prefix`)       | no       | The router's IP and subnet on this zone. Omit for zones managed externally with no splot-known IP (e.g. a NAT-ed WAN zone).        |
| `devices` | map of name → ZoneDevice      | no       | Known devices on this zone.                                                                                                        |
| `tags`    | string or list of strings     | no       | Explicit tags assigned to this zone. Resolves to the zone's subnet.                                                                |

A zone with no `address` is silently excluded from broad references like bare node names or bare `$node`. See [Addressless zones](#addressless-zones).

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

| Field      | Type                            | Required | Description                                                                |
| ---------- | ------------------------------- | -------- | -------------------------------------------------------------------------- |
| `ip`       | IPv4 address                    | yes      | Device's IP. Must fall within its containing zone's `address` subnet.      |
| `macs`     | MAC string or list              | no       | MAC addresses. Used to generate static DHCP leases on the hosting node.    |
| `tags`     | string or list of strings       | no       | Explicit tags assigned to this device.                                     |
| `services` | map of name → Service           | no       | Services exposed by this device.                                           |

---

## VPN Interface

An additional WireGuard interface hosted by this router, used to give external clients (phones, laptops) access to the mesh. Splot **does** manage these zones in OpenWRT — it creates a firewall zone named after the interface.

```yaml
wg_admin:
  listenPort: 51821
  address: 10.8.5.1/24
  clients:
    Phone: { ... }
  tags: admin
```

| Field        | Type                               | Required | Description                                                                                                |
| ------------ | ---------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------- |
| `listenPort` | integer                            | yes      | WireGuard listen port for this interface. Must differ from the mesh listen port and other VPN interfaces.  |
| `address`    | CIDR (`x.x.x.x/prefix`)            | yes      | The router's IP on this interface and its subnet. The host part is the router; the prefix defines clients. |
| `clients`    | map of name → VpnInterfaceClient   | no       | WireGuard peers allowed to connect to this interface.                                                      |
| `tags`       | string or list of strings          | no       | Explicit tags assigned to the interface. Resolves to the interface's subnet.                               |

---

## VPN Interface Client

A WireGuard peer connecting to a VPN interface.

```yaml
Phone:
  publicKey: base64...
  ip: 10.8.5.2
  tags: admin
  services: { ... }
```

| Field       | Type                            | Required | Description                                                                |
| ----------- | ------------------------------- | -------- | -------------------------------------------------------------------------- |
| `publicKey` | string                          | yes      | WireGuard public key of this client (base64).                              |
| `ip`        | IPv4 address                    | yes      | The client's IP on the interface's subnet.                                 |
| `tags`      | string or list of strings       | no       | Explicit tags assigned to this client.                                     |
| `services`  | map of name → Service           | no       | Services exposed by this client and accessible through the mesh.           |

---

## Client (global)

A roaming device that can be reached across the mesh. Unlike a VPN Interface Client (which is tied to one specific interface on one node), a global client may have IPs on multiple nodes' zones and/or VPN interfaces, plus its own IP on the mesh substrate itself.

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
      wg_admin: 10.8.5.5
    WorkRouter:
      lan: 192.168.10.30
  services: { ... }
  tags: admin
```

| Field       | Type                                                | Required | Description                                                                                                                                                                                |
| ----------- | --------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `meshIp`    | IPv4 address                                        | no       | The client's IP on the mesh interface (within `meshNetwork`). Set when the client connects directly to the mesh via WireGuard.                                                             |
| `publicKey` | string                                              | no       | WireGuard public key (base64). Required if `meshIp` or any VPN interface IP is set — otherwise the client can't be a WireGuard peer.                                                       |
| `macs`      | MAC string or list                                  | no       | MAC addresses. Used to generate static DHCP leases for the client's zone IPs on each node.                                                                                                 |
| `ips`       | map of nodeName → (map of localName → IPv4 address) | no       | The client's IPs on each node, keyed by zone or VPN interface name within that node. See [Tags](#tags) for resolution.                                                                     |
| `services`  | map of name → Service                               | no       | Services exposed by this client.                                                                                                                                                           |
| `tags`      | string or list of strings                           | no       | Explicit tags assigned to this client.                                                                                                                                                     |

---

## Service

A network service that should be reachable from specific parts of the mesh.

```yaml
ssh:
  port: "22"
  proto: tcp
  allowFrom: [admin, HomeRouter.Printer]
```

| Field       | Type                          | Required | Description                                                                                  |
| ----------- | ----------------------------- | -------- | -------------------------------------------------------------------------------------------- |
| `port`      | string                        | yes      | Port number or range.                                                                        |
| `proto`     | string or list of strings     | yes      | Protocol(s). Accepted values: `tcp`, `udp`.                                                  |
| `allowFrom` | string or list of strings     | no       | Tags or qualified references whose resolved addresses are granted access. See [Tags](#tags). |

Services may be declared on:

- A **node** (`node.services`) — the router itself hosts the service
- A **zone device** (`zone.devices.<name>.services`) — the device hosts the service
- A **VPN interface client** (`vpnInterface.clients.<name>.services`) — the client hosts the service
- A **global client** (`client.services`) — the client hosts the service, reachable on any node where it has an IP

---

## Tags

Tags are the sole access control abstraction. They appear in `allowFrom` on services to define which sources are permitted.

### How tags are assigned

Tags can be assigned explicitly via the `tags` field on any named object (node, zone, zone device, VPN interface, VPN interface client, global client). Additionally, every named object has an **implicit tag equal to its own name** — but the namespace scope depends on the kind of object.

### Reference forms in `allowFrom`

A reference is one of:

- **Bare name** — resolves in the global namespace: an explicit tag, a node name, or a global client name
- **Qualified `{NodeName}.{LocalName}`** — resolves in that node's per-node namespace: a zone, zone device, VPN interface, or VPN interface client
- **`$node`** or **`$node.{LocalName}`** — the current router being configured (context-dependent — resolves to a different router per node being generated)

### What a reference resolves to

Resolution always produces a set of IP addresses or subnets — never zone names directly. Zone names are tracked separately and used to scope generated firewall rules.

| Reference                                         | Resolves to                                                              |
| ------------------------------------------------- | ------------------------------------------------------------------------ |
| Explicit tag (e.g. `admin`)                       | All IPs/subnets of things tagged with it (across the whole config)       |
| Node name (e.g. `HomeRouter`)                     | Union of all of the node's `zones` subnets and `vpnInterfaces` subnets   |
| Global client name (e.g. `Phone`)                 | All of the client's known IPs                                            |
| `{Node}.{Zone}` (e.g. `HomeRouter.lan`)           | That zone's subnet                                                       |
| `{Node}.{ZoneDevice}` (e.g. `HomeRouter.Printer`) | The device's IP                                                          |
| `{Node}.{VpnInterface}`                           | The interface's subnet                                                   |
| `{Node}.{VpnInterfaceClient}`                     | The client's IP                                                          |
| `$node`                                           | Union of the router's own IPs across all its `zones` and `vpnInterfaces` |
| `$node.{Zone}` or `$node.{VpnInterface}`          | The router's own IP on that specific zone or VPN interface               |

A single tag can group multiple objects if they share it. `allowFrom: admin` grants access from every device, client, or interface tagged `admin` — across multiple nodes.

### Subnets vs IPs

Bare and qualified node-name forms (`HomeRouter`, `HomeRouter.lan`) resolve to **subnets** — broad, meaning "any device on those networks." `$node` forms resolve to **IPs** — narrow, meaning "the router itself as a host." These are complementary, not interchangeable.

Use the bare node name when you want any traffic from that node's downstream networks. Use `$node` (on that node's own rules) when you specifically want the router's interface IPs as source or destination.

### Addressless zones

A zone declared without an `address` (e.g. a NAT-ed WAN zone whose IP is managed by the operator at the OpenWRT level) is silently excluded from anything that aggregates subnets or IPs — including bare node names and bare `$node`. This is the safety property that prevents broad references like `allowFrom: HomeRouter` from accidentally including "anyone on the internet" if the node declares a WAN zone.

### Examples

```yaml
allowFrom: admin                          # everything tagged admin (cross-node)
allowFrom: HomeRouter                     # all of the node's zone + VPN interface subnets
allowFrom: HomeRouter.lan                 # only the node's lan zone subnet
allowFrom: HomeRouter.Printer             # specific device's IP
allowFrom: HomeRouter.wg_admin            # specific VPN interface's subnet
allowFrom: Phone                          # global client's IPs
allowFrom: [admin, HomeRouter.iot]        # admin-tagged things + the node's iot zone subnet
allowFrom: $node                          # the router's own IPs across all its interfaces
allowFrom: $node.lan                      # only the router's IP on its lan zone
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
- The node's `vpnInterfaces`
- All zone devices (`zones.<zone>.devices.<name>`)
- All VPN interface clients (`vpnInterfaces.<iface>.clients.<name>`)

**Within a single node, names across all four categories must be unique.** A node can't have a zone named `Printer` and a device named `Printer`, for example. Names can recur freely across different nodes — two nodes can both have a `lan` zone, or both have a `Printer` device.

### Cross-namespace collisions are also forbidden

A name in any node's per-node namespace must not collide with any name in the global namespace. So if `HomeRouter` is a node name, no node may have a zone, device, VPN interface, or VPN interface client also named `HomeRouter`. This keeps every reference unambiguous.

### Implicit name-tags

Every named object has an implicit tag equal to its name. Where that tag lives:

- **Globally-scoped implicit tags** (referenced by bare name): nodes, global clients
- **Per-node-scoped implicit tags** (referenced as `{NodeName}.{LocalName}`): zones, zone devices, VPN interfaces, VPN interface clients

The qualified `{NodeName}.{LocalName}` syntax is intentionally only **two levels deep** — the per-node namespace is flat. There is no `{NodeName}.{Zone}.{Device}` form; a device is referenced as `{NodeName}.{Device}` directly. This works because per-node names across all four categories are unique.

### `$node` and `$node.{name}`

`$node` is a special context-dependent tag that resolves to the router currently being configured. It produces the router's own IPs across all of its `zones` and `vpnInterfaces`. The qualified form `$node.{name}` narrows to a single zone or VPN interface on that router.

### Allowed characters

Names must contain only alphanumeric characters, `-`, and `_`. Spaces, dots, and other special characters are forbidden — names are used as part of generated UCI section identifiers, and `.` is reserved as the qualified-reference separator.

### Reserved prefixes for per-node-scoped names

A per-node-scoped name (zone, zone device, VPN interface, VPN interface client) must not start with `{NodeName}_` where `{NodeName}` is the name of any node in the config. For example, if there is a node named `Jawo`, no per-node-scoped name anywhere may be `Jawo_printer`, `Jawo_lan`, etc.

The reason is generated UCI rule names. Splot qualifies a rule for a remote node's object by prefixing the node name with `_` (e.g. `Jawo_printer_ssh` for an `ssh` service on Jawo's `printer`). A literal name like `Jawo_printer` on another node would collide with that qualified form. `_` itself stays a valid character — only the specific `{NodeName}_` prefix is reserved.

---

## Subnet uniqueness

Every subnet in the mesh must be unique and non-overlapping. This includes:

- The `meshNetwork` subnet
- Each zone's `address` subnet (when present)
- Each VPN interface's `address` subnet

Overlapping subnets cause ambiguous routing and may produce incorrect or conflicting firewall rules. The validator enforces this across the entire config.

---

## `client.ips` rules

A global client's `ips` field maps each node's name to a per-node map keyed by local network name (a zone or VPN interface name on that node) and valued by the client's IP on that network.

Two rules apply:

1. **At most one zone entry per `(client, node)`.** A client may not have IPs on multiple zones of the same node — DHCP can't generate two static leases under the same client name on the same router. A device that physically appears on only one zone at a time (the realistic case) fits this trivially. For the rare multi-NIC-on-one-router setup, model it as two separate client entries.
2. **No limit on VPN interface entries per `(client, node)`.** A client can have IPs on multiple VPN interfaces of the same node — these are statically assigned via WireGuard config and don't go through DHCP, so no collision exists.

Each IP must fall within its named network's subnet. The validator enforces this — a key like `HomeRouter.lan: 10.5.5.5` is rejected if `10.5.5.5` is not in HomeRouter's `lan` zone subnet.

---

## Holistic validation

Beyond the structural rules above, the validator flags configurations that are syntactically valid but operationally meaningless. These may be reported as **warnings** or **errors** depending on the severity of the resulting silent no-op:

- **Global client with neither `macs` nor `ips`.** Such a client is unreachable: no DHCP lease, and no firewall rule can resolve to anything useful. The client name still resolves to the empty set of IPs but never matches traffic.
- **Global client with `publicKey` but no `meshIp` and no IP on any VPN interface (`ips.<node>.<vpnInterface>`).** The public key isn't used anywhere — splot has no WireGuard interface to attach this peer to. Either remove the key or add an IP that places the client as a peer on some interface.
- **`allowFrom` references that resolve to no IPs.** A tag with no tagged things, an explicit tag never assigned, or a reference to an addressless zone produce a service rule whose `src_ip` set is empty. The rule is generated but matches nothing.
- **Subnet-mismatched IPs in `client.ips`.** As above — the IP doesn't fall within the named network's subnet.
- **Service with empty or omitted `allowFrom`.** No source can reach this service; the service declaration has no effect.

Future entries in this list will land here as the validator grows.
