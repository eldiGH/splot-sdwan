# splot Configuration Reference

The config file (`splot.json`) describes the entire mesh network. Every router in the mesh uses the same shared config file. splot reads it, identifies which node it is by matching its WireGuard public key, and generates the appropriate network and firewall configuration for that router.

---

## Top-level structure

```json
{
  "nodes": {
    "<nodeName>": { ... }
  }
}
```

| Field   | Type                       | Required | Description                        |
|---------|----------------------------|----------|------------------------------------|
| `nodes` | map of name → Node object  | yes      | All routers in the mesh            |

---

## Node

Represents a single router in the mesh.

```json
"HomeRouter": {
  "publicKey": "base64...",
  "endpoint": "1.2.3.4",
  "listenPort": 51820,
  "meshIp": "10.0.0.1/24",
  "lan": { ... },
  "vpnInterfaces": { ... },
  "tags": "home",
  "services": { ... }
}
```

| Field            | Type                    | Required | Description |
|------------------|-------------------------|----------|-------------|
| `publicKey`      | string                  | yes      | WireGuard public key (base64). Used by splot to identify which node it is running on. |
| `endpoint`       | IPv4 address            | yes      | Public IP address used by other mesh nodes to establish WireGuard connections. |
| `listenPort`     | integer                 | yes      | WireGuard listen port for the mesh interface. |
| `meshIp`         | CIDR (`x.x.x.x/prefix`) | yes      | This node's IP on the mesh WireGuard interface. Must be unique across all nodes. |
| `lan`            | LAN object              | yes      | The node's local network. |
| `vpnInterfaces`  | map of name → VpnInterface | no    | Additional WireGuard interfaces hosted by this router (e.g., client VPN access). |
| `tags`           | string or array         | no       | One or more tags assigned to this node. See [Tags](#tags). |
| `services`       | map of name → Service   | no       | Services exposed by the router itself (e.g., SSH, admin UI). |

---

## LAN

Describes the router's local network.

```json
"lan": {
  "address": "192.168.1.1/24",
  "devices": { ... }
}
```

| Field     | Type                        | Required | Description |
|-----------|-----------------------------|----------|-------------|
| `address` | CIDR (`x.x.x.x/prefix`)    | yes      | The router's LAN IP and subnet mask. The host part is the router's own LAN IP; the prefix defines the subnet. |
| `devices` | map of name → LanDevice     | no       | Known devices on this LAN. |

---

## LAN Device

A known device on a node's local network.

```json
"Printer": {
  "ip": "192.168.1.50",
  "mac": "aa:bb:cc:dd:ee:ff",
  "tags": ["office", "shared"],
  "services": { ... }
}
```

| Field      | Type             | Required | Description |
|------------|------------------|----------|-------------|
| `ip`       | IPv4 address     | yes      | The device's IP address on the LAN. Must be within the node's LAN subnet. |
| `mac`      | string           | no       | MAC address. Reserved for future use (DHCP static leases). |
| `tags`     | string or array  | no       | One or more tags assigned to this device. See [Tags](#tags). |
| `services` | map of name → Service | no  | Services exposed by this device. |

---

## VPN Interface

An additional WireGuard interface hosted by this router, used to give external clients (phones, laptops) access to the mesh.

```json
"wg_admin": {
  "listenPort": 51821,
  "address": "10.8.5.1/24",
  "tags": "admin",
  "clients": { ... }
}
```

| Field        | Type                        | Required | Description |
|--------------|-----------------------------|----------|-------------|
| `listenPort` | integer                     | yes      | WireGuard listen port for this interface. Must be different from the mesh listen port and all other VPN interface ports on this node. |
| `address`    | CIDR (`x.x.x.x/prefix`)    | yes      | The router's IP on this VPN interface and the subnet it serves. The host part is the router's own address; the prefix defines the subnet for clients. |
| `tags`       | string or array             | no       | Tags assigned to this interface as a whole. Resolves to the interface's subnet. See [Tags](#tags). |
| `clients`    | map of name → VpnClient     | yes      | WireGuard peers allowed to connect to this interface. |

---

## VPN Client

A WireGuard peer connecting to a VPN interface.

```json
"Pixel_8": {
  "publicKey": "base64...",
  "ip": "10.8.5.2",
  "tags": "admin",
  "services": { ... }
}
```

| Field        | Type             | Required | Description |
|--------------|------------------|----------|-------------|
| `publicKey`  | string           | yes      | WireGuard public key of this client (base64). |
| `ip`         | IPv4 address     | yes      | The client's IP on the VPN interface subnet. No prefix — the subnet is inherited from the interface. |
| `tags`       | string or array  | no       | Tags assigned to this client. Resolves to the client's specific IP. See [Tags](#tags). |
| `services`   | map of name → Service | no  | Services exposed by this client and accessible through the mesh. |

---

## Service

A network service that should be accessible from specific parts of the mesh.

```json
"ssh": {
  "port": "22",
  "proto": "tcp",
  "allowFrom": ["admin", "HomeRouter"]
}
```

| Field       | Type             | Required | Description |
|-------------|------------------|----------|-------------|
| `port`      | string           | yes      | Port number or range. |
| `proto`     | string or array  | yes      | Protocol(s). Accepted values: `tcp`, `udp`. |
| `allowFrom` | string or array  | no       | Tags or names whose resolved addresses are granted access. If omitted, no access is granted. See [Tags](#tags). |

---

## Tags

Tags are the sole access control abstraction. They appear in `allowFrom` on services to define which sources are permitted.

### How tags are assigned

Tags can be assigned explicitly via the `tags` field on any named object (node, LAN device, VPN interface, VPN client). Additionally, every named object automatically has an **implicit tag equal to its own name** — no explicit declaration needed.

### What a tag resolves to

When used in `allowFrom`, a tag resolves to a set of IP addresses or subnets:

| Source of the tag          | Resolves to                              |
|----------------------------|------------------------------------------|
| LAN device name or tag     | That device's specific IP address        |
| VPN client name or tag     | That client's specific IP address        |
| VPN interface name or tag  | That interface's entire subnet           |
| Node name or tag           | That node's entire LAN subnet            |
| `$node`                    | The own router's LAN IP (special built-in tag) |

A single tag can group multiple devices or interfaces if they share that tag. `allowFrom: "admin"` grants access from every device, client, and interface tagged `"admin"`.

### Examples

```json
"allowFrom": "Printer"
```
Grants access from exactly the IP of the device named `Printer`.

```json
"allowFrom": "HomeRouter"
```
Grants access from the entire LAN subnet of the node named `HomeRouter`.

```json
"allowFrom": ["admin", "wg_guest"]
```
Grants access from all sources tagged `"admin"` plus the entire `wg_guest` interface subnet.

```json
"allowFrom": "$node"
```
Grants access from the router's own LAN IP (useful for services the router itself should be able to reach).

---

## Uniqueness rules

**All names across the entire config must be globally unique.** This includes node names, LAN device names, VPN interface names, and VPN client names. No two things of any type may share a name.

**Tag names share the same namespace as object names.** Because every object name is also an implicit tag, you cannot create an explicit tag with the same name as any object — it would be ambiguous whether `allowFrom: "Printer"` means "the device named Printer" or "the tag named Printer". Since they are the same thing, this is enforced by construction.

**Names must not contain spaces or special characters.** Names are used as part of generated UCI section identifiers. Allowed characters: alphanumeric, `-`, `_`.

---

## Subnet uniqueness

Every subnet in the mesh must be unique and non-overlapping. This includes:

- Each node's `meshIp` prefix (the mesh WireGuard interface subnet)
- Each node's `lan.address` subnet
- Each VPN interface's `address` subnet

Overlapping subnets cause ambiguous routing and may produce incorrect or conflicting firewall rules. The config validator enforces this.
