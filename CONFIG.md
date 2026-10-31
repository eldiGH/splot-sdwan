# splot Configuration Reference

The config file (`splot.yml`) describes the entire mesh network. Every router in the mesh uses the same shared config. splot reads it, takes which node a peer is from `--node` (and checks the peer's WireGuard key is that node's `publicKey`), and generates the appropriate network, DHCP, and firewall configuration for that router.

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
| `keepaliveInterval` | integer (seconds)       | no       | Seconds between WireGuard keepalives, for the hosts that send them: a host nobody can dial that others connect to keeps its NAT mapping open with them. A node without an `endpoint` is one (the other nodes ping it). Default `25`; `0` turns none on. |
| `nodes`             | map of name → Node      | yes      | Routers participating in the mesh.                                                                                                                                                                              |
| `clients`           | map of name → Client    | no       | Roaming devices accessible across the mesh (phones, laptops). Global, cross-node.                                                                                                                               |

---

## Node

Represents a single router in the mesh.

```yaml
HomeRouter:
  platform:
    os: openwrt
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
| `platform`      | Platform                   | yes      | The OS the node runs, and which concerns splot manages there. See [Platform](#platform). |
| `publicKey`     | string                     | yes      | WireGuard public key as printed by `wg pubkey` (44 characters, ending in `=`; unique across all nodes and clients). Before splot acts as this node (`--node`), it checks the peer's own key is this one.                                                                                                                            |
| `endpoint`      | IPv4 address or DNS name   | no       | Where other mesh nodes dial this node: its public IP, or a DNS name that resolves to it (labels of letters, digits and hyphens). Leave it out when nobody can dial the node (behind NAT or CGNAT with no port forward, or behind a firewall that drops what comes in): it then dials the others, and keeps its NAT mapping open with keepalives so they can reach it too. At least one node needs an endpoint; a node without one can't host a [hub](#hub), and two nodes without one have no tunnel between them (a warning). A name must resolve through public DNS, never through the mesh: the tunnel can't need itself to come up. Peers resolve it when their mesh interface comes up, so a changed address reaches them the next time it does; a name that doesn't resolve keeps that whole interface down, not just this peer (on OpenWrt and with wg-quick alike). Where splot runs the node's firewall and WireGuard, it lets the `listenPort` in from the `wanZone` (UDP, to the node itself), so the node needs one. |
| `listenPort`    | integer                    | yes      | WireGuard listen port for the mesh interface. On a node with an `endpoint`, splot lets it in from the `wanZone`.                                                                                                |
| `psk`           | boolean                    | no       | Whether this node's WireGuard pairs use a preshared key. Default `true`; a pair has one only when both ends want it. See [Preshared keys](#preshared-keys). |
| `meshIp`        | IPv4 address               | yes      | This node's IP on the mesh WireGuard interface (within `meshNetwork`).                                                                                                                                            |
| `zones`         | map of name → Zone         | no       | Downstream networks the router serves (LAN, VLANs).                                                                                                                                                               |
| `hub`           | Hub                        | no       | A network inside `meshNetwork` for devices that reach the mesh through this node alone. See [Hub](#hub).                                                                                                         |
| `services`      | map of name → Service      | no       | Services exposed by the router itself (e.g. SSH, admin UI).                                                                                                                                                       |
| `wanZone`       | string                     | no\*     | Name of the OpenWRT firewall zone that is WAN-facing on this router (where splot manages the firewall, not starting with a digit, as fw4's zone names don't). Splot does not manage this zone; it only references it when generating port forwards, and to let the node's WireGuard `listenPort` in. \*Required if any service uses this node in `wan.via`, or the node has an `endpoint` (others dial it), unless the node leaves its firewall alone (`firewall: none`). An `endpoint` doesn't need it where splot leaves the WireGuard alone (`wireguard: none`). |
| `tags`          | string or list of strings  | no       | Explicit tags assigned to the node. See [Tags](#tags).                                                                                                                                                            |

---

## Platform

Which software a node runs, and which concerns splot manages there: per concern, the program splot manages it with, or `none` to leave it to you.

```yaml
platform:
  os: openwrt      # every concern managed with what OpenWrt ships...
  dhcp: none       # ...except DHCP, which you keep by hand
  ssh: root@192.168.1.1   # where splot reaches it
```

```yaml
platform:
  os: linux        # every concern written out
  wireguard: wg-quick
  firewall: nftables
  dhcp: dnsmasq
  dns: none
  interfaces:      # nftables: which interfaces each zone, and the WAN, are on
    lan: eth0
    iot: [eth0.20, wlan0]
    wan: eth1
```

| Field       | Values                                             | Required                              | Description                                                                 |
| ----------- | -------------------------------------------------- | ------------------------------------- | --------------------------------------------------------------------------- |
| `os`        | `openwrt`, `linux`                                 | yes                                   | The node's operating system.                                                |
| `wireguard` | `netifd` (OpenWrt), `wg-quick` (Linux), `none`     | OpenWrt: no (`netifd`); Linux: yes    | The mesh interface and its peers.                                           |
| `firewall`  | `fw4` (OpenWrt), `nftables` (Linux), `none`        | OpenWrt: no (`fw4`); Linux: yes       | The mesh zone, access between zones (the rules `allowFrom` grants, a drop for the rest), the port forwards `wan` makes, the WireGuard listen port on the WAN. See [Access between zones](#access-between-zones). |
| `dhcp`      | `dnsmasq`, `none`                                  | OpenWrt: no (`dnsmasq`); Linux: yes   | Static leases for devices and global clients.                               |
| `dns`       | `dnsmasq`, `none`                                  | OpenWrt: no (`dnsmasq`); Linux: yes   | Nothing yet: splot generates no DNS config so far.                          |
| `ssh`       | anything `ssh` takes                               | no                                    | Where splot reaches the node. See below.                                    |
| `interfaces` | map of zone → interface name or list              | with `firewall: nftables`             | The interfaces each zone, and the `wanZone`, are on (Linux only). See below. |

- **Every node says what it runs.** There's no default OS, and splot doesn't detect it: `splot check` validates every node without reaching any, and the config keeps its meaning when a node is reinstalled. On the node itself, splot does check it's what the config says, and refuses otherwise.
- **On OpenWrt** a concern left out is managed with what OpenWrt ships. **On Linux** there's no usual setup to assume: every concern is written out, `none` included, and one left out is an error.
- **A program the OS doesn't have** (`wg-quick` on OpenWrt) is an error.
- **`none`** leaves that concern to you: splot generates nothing for it and doesn't touch what's there, its own sections from before included (on OpenWrt that file isn't staged, committed or reloaded). What's then yours to do:
  - **`firewall: none`**, with WireGuard managed by splot: the mesh interface (`spl_mesh` on OpenWrt) is in none of splot's zones. Put it into one of yours (e.g. `lan`, as a hand-made `wg0` usually is) and, if the node has an `endpoint`, let its listen port in from the WAN. Nothing `allowFrom` says is enforced on that node, and nothing is forwarded from its WAN.
  - **`dhcp: none`**: the addresses the config gives devices and global clients are yours to make true, with a reservation in your DHCP server or a static address on the device. Firewall rules use them either way.
  - **`wireguard: none`** (the node is in the mesh, its WireGuard set up by hand): splot keeps no key there, so `splot init` has nothing to create, and before it writes anything it checks the node by your WireGuard instead: one of the peer's interfaces must have the node's `publicKey` (and be up). With the firewall managed by splot, there's no mesh zone, so mesh traffic arrives in whichever zone your interface is in, and nothing is forwarded from the WAN to a host reached over the mesh. Its listen port is yours to let in from the WAN, as it is with your interface: splot opens only its own. The rules `allowFrom` grants between the node's zones are still written, and so is splot's drop between them; what crosses the mesh is under your rules, and the node's warning names those services. Keep your interface in a zone `splot.yml` doesn't declare: in one it declares, splot's drop between its zones covers what arrives over the mesh too, and nothing from the mesh is let through. Such a node can't have a [hub](#hub) (an error): hub clients are peers on splot's mesh interface. A WireGuard server of your own, with its own subnet, is a [zone](#zone) to splot.
  - `firewall: none` and `dhcp: none` together: splot manages the mesh alone.
- **`splot check` warns**, once per node and concern, where a concern left alone leaves part of the config undone, naming what (the services whose `allowFrom` isn't enforced there or that another node forwards to it from its WAN, those not forwarded from its own WAN) and what's yours to do. A concern left alone with nothing asked of it gets no warning.
- **`ssh`** is where splot reaches the node over ssh: `root@192.168.1.1`, a host of your `~/.ssh/config`, `ssh://root@router:2222`, given to the system `ssh` as it is (so your ssh config and agent apply). It can't start with `-` (ssh would read it as an option) or hold spaces or control characters. `splot apply` without `--node` reaches every node splot manages here, so each needs one (a node where every concern is `none` is left out). A command on one node (`--node`) reaches it at `--ssh <destination>` when given, else here; with neither, or with `--local`, splot acts on the machine it runs on, and refuses if that isn't the node. An address over the mesh (its `meshIp`) works once the node is in the mesh, but not for a node that isn't yet, or whose tunnel is down.
- **`interfaces`** says which network interfaces each of the node's zones, and its `wanZone`, are on: nftables tells them apart by their interfaces, as fw4 does by its zones. With `firewall: nftables` every zone and the `wanZone` (when the node has one) needs one, an interface name or a list (`eth0`, `[eth0.20, wlan0]`): what Linux takes (at most 15 characters), in letters, digits, `.`, `-` and `_`. Each key is one of the node's zones or its `wanZone`. Two zones can't share an interface, since splot couldn't tell them apart (each is a network of its own), but the WAN may come in on a zone's: a host that isn't its site's gateway, reached through a port forward on the router in front of it. No zone is on `spl_mesh`, splot's mesh interface. On OpenWrt it's an error: there a zone's key is the name of its fw4 zone, which says which interfaces it covers.
- **On Linux, WireGuard and the firewall so far:** splot runs the mesh with wg-quick and its firewall with nftables, both through systemd (see [Linux](#linux)), and `splot apply` refuses a Linux node whose `dhcp` names a program until splot manages it there: set it to `none` to apply the rest. `splot check` validates the node either way.

### Linux

What a Linux node needs, and what splot does there:

- **systemd, wireguard-tools and iproute2.** splot runs the mesh through systemd's `wg-quick@spl_mesh`, and starts and enables it, so it comes back after a reboot.
- **splot owns `/etc/wireguard/spl_mesh.conf`**, keys included (readable by root only), and rewrites it whole: don't edit it. Its keys are in `/etc/splot/keys`.
- **A change to a peer** (a new client, a key, an endpoint, a PSK) is applied live (`systemctl reload`, which runs `wg syncconf`): the tunnels stay up.
- **A change to the interface's address or routes** (a new node or zone, a changed `meshIp`) restarts it (`systemctl restart`): wg-quick sets them only when it starts, so the tunnels drop for a moment. The dry run says which and why.
- **An interface you brought up yourself** under that name (`wg-quick up spl_mesh`) is refused: bring it down and apply again.

With `firewall: nftables`:

- **nftables (`nft`).** splot's firewall is a table of its own, `inet splot`, which it writes to `/etc/splot/firewall.nft` (rewritten whole: don't edit it) and loads through a unit of its own, `splot-firewall.service`, started and enabled so the table is back at every boot before the network comes up. Each apply replaces the table whole, in one transaction: there's no moment without it.
- **Your own tables stay as they are**, and splot never runs `flush ruleset`. What splot drops stays dropped whatever they say; what it accepts gets through only where they accept it too. So the dry run warns about each of your chains that drops what it doesn't accept (`policy drop`, Docker's `FORWARD` say): let through there what splot's services grant.
- **A ruleset loaded with `flush ruleset` removes splot's table too.** Debian's `nftables.service` loads `/etc/nftables.conf` with one: splot's unit loads after it at boot, and again whenever it restarts or reloads. Starting it when it wasn't running, or `nft -f` of such a file by hand, leaves splot's table out: run `systemctl reload splot-firewall`, or apply again (the dry run says the table isn't loaded).

---

## Zone

A downstream network the router serves: one subnet, a LAN or a VLAN. Splot does **not** create zones in OpenWRT — the operator configures them — it decides what may cross between them (see [Access between zones](#access-between-zones)). The map key is the OpenWRT zone name on that router, so where splot manages the firewall (fw4) it can't start with a digit, as fw4's zone names don't. No VLAN ID goes here: nothing splot generates depends on one.

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

Inside a zone everything reaches everything: that traffic never passes the router, so splot can't filter it. A device that needs protecting from its neighbours needs a zone of its own.

WAN zones are not modeled here — they are not splot zones. If a router has a WAN interface that needs port forwards, or that the other nodes dial it on, declare its OpenWRT zone name in the node's `wanZone` field. See [WAN exposure](#wan-exposure).

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
| `macs`     | MAC string or list        | no\*     | MAC addresses. Used to generate static DHCP leases on the hosting node, which hand the device its name as its host name (see [Allowed characters](#allowed-characters)). \*Required where splot manages the node's DHCP: a device with a static address lists them too, so the reservation keeps the pool from handing its address to another. Where splot leaves the node's DHCP alone (`dhcp: none`) they're unused, and a warning says to remove them. |
| `tags`     | string or list of strings | no       | Explicit tags assigned to this device.                                  |
| `services` | map of name → Service     | no       | Services exposed by this device.                                        |

---

## Hub

A network inside `meshNetwork` that the node sets aside for devices reaching the mesh through it alone — typically something behind NAT that offers services, like a camera on an LTE modem. Its clients are WireGuard peers on the node's mesh interface (same key, same port); splot creates no extra interface or firewall zone for them. The node needs an `endpoint` (hub clients dial it), and splot must manage its WireGuard (no `wireguard: none`).

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
- `{NodeName}.$hub` refers to the hub network (see [Tags](#tags)).

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
| `psk`       | boolean                   | no       | Whether this client's WireGuard pair with its hub node uses a preshared key. Default `true`. See [Preshared keys](#preshared-keys). |
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
| `psk`       | boolean                                             | no       | For a client with a `publicKey`: whether its WireGuard pairs use a preshared key. Default `true`. See [Preshared keys](#preshared-keys). |
| `macs`      | MAC string or list                                  | no\*      | MAC addresses. Used to generate static DHCP leases for the client's zone IPs on each node. \*Required when one of its `ips` is on a node whose DHCP splot manages; unused (a warning) when none is. |
| `ips`       | map of nodeName → (map of localName → IPv4 address) | no       | The client's IPs on each node, keyed by zone name within that node. See [Tags](#tags) for resolution.                                |
| `services`  | map of name → Service                               | no       | Services exposed by this client.                                                                                                     |
| `tags`      | string or list of strings                           | no       | Explicit tags assigned to this client.                                                                                               |

**Its services** are reached at its `meshIp`, through its tunnel wherever it is, and at its IPs on the zones (at home with the tunnel off, say):

- It's a peer on every node, so each node sends what's behind it (its zones, its hub) straight to the `meshIp`, and lets out what `allowFrom` names there. Each node is the only gate between what's behind it and the client: one whose firewall or WireGuard splot leaves alone lets its networks through as your own rules do, and `splot check` names the service in that node's warning.
- Another global client can't reach it at its `meshIp`: no node relays between clients, so `allowFrom: Laptop` on a phone's service lets nothing in there.

---

## Preshared keys

Every WireGuard pair (node and node, node and client) uses a preshared key (PSK) by default: a secret both ends share, mixed into the handshake. Against today's attackers it adds nothing (the keys already authenticate both ends); it protects recorded traffic against a future quantum computer breaking the key exchange.

- A pair has one only when **both ends want it**. `psk: false` on a node, a hub client or a global client turns it off for all of that host's pairs: a PSK must exist on both ends, so one end is enough. Meant for WireGuard clients without a field for one, or profiles typed in by hand.
- Each pair has its own PSK; the same key goes on both ends. Generate one with `wg genpsk`.
- PSKs never go in `splot.yml`. Each node keeps its own in its key store, next to its private key and readable by root only (on OpenWrt `/etc/config/splot`, on Linux `/etc/splot/keys`), and splot fills them in when it applies; `--dry-run` shows `<preshared key>` instead.
- Store one on a node with `splot psk set --node <Name> <peer>`, which reads it from stdin (`splot psk set --node Home Cabin < cabin.psk`, so it stays out of your shell history). The peer is named as in the config: `Cabin`, `Phone`, `Home.camera`. On the other end, store the same key the same way, or put it in a client's WireGuard profile as `PresharedKey`.
- `splot apply` refuses while a pair that uses a PSK has none stored, and names the peers.

---

## Service

A network service that should be reachable from specific parts of the mesh, externally via WAN, or both. Nothing else is: where splot runs a node's firewall, what crosses between its zones, over the mesh or at the site, is dropped unless a service lets it through (see [Access between zones](#access-between-zones)). One exception: every WireGuard peer of a node (other nodes, global clients, hub clients) may ping the node's own mesh IP, and only that (echo requests to the router itself, nothing forwarded). splot uses it to check a node's tunnels after it applies a change.

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
- A **global client** (`client.services`) — the client hosts the service, reached at its `meshIp` and at its IPs on the zones (see [Client (global)](#client-global))

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
- **No NAT reflection.** Hosts inside your networks reach a forwarded service at its own address, as `allowFrom` lets them, not at your WAN address: splot turns OpenWrt's reflection off on its forwards (it would ignore `sources`), and writes none on Linux.
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

For the first three host types, the host has exactly one canonical address. The mesh routing reaches that address from every router, so any node with `wanZone` can expose them via cross-node DNAT (see [Cross-node WAN exposure](#cross-node-wan-exposure)). No restrictions.

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

A router can forward a service it reaches over the mesh: a device or a router at another site, a hub client, a global client's mesh IP. For example, a device behind `Cabin`, published at `HomeRouter`'s fixed address:

```yaml
nodes:
  Cabin:
    zones:
      lan:
        address: 192.168.2.1/24
        devices:
          weather:
            ip: 192.168.2.40
            services:
              http:
                port: "8080:80"
                proto: tcp
                wan:
                  via: [HomeRouter] # HomeRouter forwards 8080 → 192.168.2.40:80, over the mesh
```

The host's config doesn't reference `HomeRouter`. If `WorkRouter` should also expose it, just add it to `via`. The two forwards are independent.

**The forward crosses the mesh as the router.** `HomeRouter` sends it from its own `meshIp`, and `Cabin` lets that address in to the service (a rule of its own, `[SPLOT] in: Cabin.weather http, via HomeRouter`). It has to: WireGuard at `Cabin` takes from `HomeRouter` only `HomeRouter`'s own addresses, so the internet's address would be dropped there, and the station would answer the internet by its own route anyway. From the router's `meshIp`, the replies come back through `HomeRouter`. A global client's mesh IP, or a hub client of the router itself, is reached straight from the router: nothing in between to let in.

**What the host sees is the router, not who's asking.** Its logs show `HomeRouter`'s `meshIp`, and `allowFrom` on the service can't tell internet clients apart (it doesn't need to name `HomeRouter` either: the forward is let in on its own). Say who may come on the WAN side, with `sources`.

On OpenWrt the router can't tell what it forwarded from what else goes to the same place, so when the forward is public (no `sources`), what its own networks send that service over the mesh goes as the router too: the host sees the router for them as well. They still reach it only where `allowFrom` lets them out of the router.

Where the host's router leaves its firewall alone (`firewall: none`), let the forward in from the forwarding router's `meshIp` yourself; where the forwarding router does, forward it yourself, from its `meshIp`. `splot check` warns about the first.

### Security note

The splot WAN model is intentionally minimal: a service is either WAN-exposed or it isn't, with optional CIDR-based source filtering. No splot identifier participates in WAN allowlisting. The principle is to minimize external attack surface — every `wan` field in `splot.yml` is a publicly visible port, easy to audit with `grep wan splot.yml`.

---

## Access between zones

Where splot runs a node's firewall, it decides what crosses between zones, at one site and over the mesh alike: what a service's `allowFrom` grants gets through, and nothing else. Whether a source is at the same site or across the mesh changes where splot puts the rule, never what `allowFrom` means.

### What splot can enforce

- **A zone is the smallest unit.** Inside a zone (one subnet) everything reaches everything, and that traffic never passes the router. Sources in a service's own zone get no rule: `allowFrom: admin` on a device doesn't keep out the other devices of its zone. A device that needs protecting from its neighbours needs a zone of its own (a VLAN).
- **Only what passes a node splot manages.** Mesh traffic always does (it goes through the node's WireGuard), so splot enforces mesh access even on a node that isn't its site's router. Traffic between two zones of a site does only when the node is their router: a switch must not route between VLANs.
- **A global client's `meshIp`, at each node.** The client is a peer on every node, so what's behind a node reaches it through that node alone: each node lets out what `allowFrom` names there. One whose firewall splot leaves alone lets the rest through too, as your rules do.
- **On the router itself, what comes over the mesh.** For a service on the router (`node.services`), `allowFrom` decides what reaches it over the mesh. What reaches the router from its own zones (DHCP, DNS, LuCI, ssh from the LAN) is yours, so a source in one of them gets no rule there.
- **No VLAN IDs, no L2 across the mesh.** A VLAN ID is local to its site, and nothing splot generates depends on one. Zones at different sites are grouped with tags (`iot`). splot routes between distinct subnets; it never bridges a network across the mesh.

### Who owns what

| You (the router's own config) | splot |
| --- | --- |
| VLANs, switch ports, access points | access between zones, local and over the mesh (`services`) |
| internet access per zone, NAT, PPPoE | the drop between its zones, for everything no service grants |
| DHCP pools | the WireGuard mesh: sites, global clients, hub clients |
| the WAN zone, zones `splot.yml` doesn't declare | static leases (DNS records planned) |
| what reaches the router from your zones (DHCP, DNS, LuCI, ssh from the LAN) | port forwards (`wan`) |

### The default policy

A node's splot zones are its mesh zone and every zone `splot.yml` declares for it. splot never relies on a platform's default (fw4's `defaults`, an "allow LAN to any" rule): the same `splot.yml` means the same on every platform.

- **Between splot zones, and in and out of the mesh zone,** every packet ends in splot's own verdict: accepted by a rule a service grants, else dropped.
- **Dropped, not rejected:** what's forbidden gets no answer, so a compromised device can't map the network quickly. Logging splot's drops is planned.
- **Left alone:** traffic to and from the WAN zone and the zones `splot.yml` doesn't declare, and what reaches the router from your zones. splot's own exceptions: anything leaving the mesh zone (to the WAN too), the forwards a service's `wan` asks for, and the WireGuard listen port on the WAN of a node with an `endpoint` (when the WireGuard is splot's).
- **Ping** between zones is dropped like anything else: a ping sweep is how mapping a network starts. Replies, and the ICMP errors of a connection that was let through (path MTU, unreachable, traceroute), always pass. Every WireGuard peer of a node may ping the node's mesh IP (see [Service](#service)).

What follows:

- **No internet through the mesh:** what comes from the mesh is dropped on its way to the WAN. Using a node as the way out for clients is planned.
- **What a node sends itself over the mesh** (its DNS forwarding, a proxy on it) comes from its `meshIp`, which `allowFrom: Home` doesn't cover: let it in with `allowFrom: Home.$node` (see [A node itself](#a-node-itself-nodenode)).
- **Your `forwarding` sections between splot zones stop working:** fw4 checks rules before forwardings, so splot's drop wins. Declare the flows they carried as services (`allowFrom: Home.lan` for a whole zone).
- **Your `rule` sections there decide before splot's:** fw4 takes rules in the file's order, and splot's come last. One that accepts lets through what no service grants; one that drops or rejects stops what a service grants. Declare what they're for as services, and remove them.
- **The dry run warns about both** (every `splot apply` shows it before asking): each forwarding or rule of yours between splot zones, out of the mesh zone (to the WAN too), or into the router from the mesh zone, saying what it does there and what to do instead. The router's stock sections (`lan` to `wan`, the WAN's rules) are none of these.
- **On Linux** there's no fw4 to share: splot's drops hold whatever your own nft tables say, and the dry run warns about each of your chains that drops what it doesn't accept, where splot's accepts need yours (see [Linux](#linux)).
- **Switching it on stops every flow nobody declared**, all at once. Move a site over with `firewall: none` first (see [Platform](#platform)): declare its flows, then let splot run its firewall.
- A node that isn't its zones' router enforces only what passes through it.

---

## Tags

Tags are the sole access control abstraction. They appear in `allowFrom` on services to define which sources are permitted.

### How tags are assigned

Tags can be assigned explicitly via the `tags` field on any named object (node, zone, zone device, hub, hub client, global client). Additionally, every named object has an **implicit tag equal to its own name** — but the namespace scope depends on the kind of object.

### Reference forms in `allowFrom`

A reference is one of:

- **Bare name** — resolves in the global namespace: an explicit tag, a node name, or a global client name
- **Qualified `{NodeName}.{LocalName}`** — resolves in that node's per-node namespace: a zone, zone device, or hub client
- **`{NodeName}.$hub`** — that node's hub network
- **`{NodeName}.$node`** — that node itself, as a host, named from anywhere (see [A node itself](#a-node-itself-nodenode))
- **`$node`** — the node the rule is on (context-dependent — resolves to a different node per node being generated)

### What a reference resolves to

Resolution always produces a set of IP addresses or subnets — never zone names directly. Zone names are tracked separately and used to scope generated firewall rules.

| Reference                                         | Resolves to                                                              |
| ------------------------------------------------- | ------------------------------------------------------------------------ |
| Explicit tag (e.g. `admin`)                       | All IPs/subnets of things tagged with it (across the whole config)       |
| Node name (e.g. `HomeRouter`)                     | Union of the node's `zones` subnets and its hub network                  |
| Global client name (e.g. `Phone`)                 | All of the client's known IPs                                            |
| `{Node}.{Zone}` (e.g. `HomeRouter.lan`)           | That zone's subnet                                                       |
| `{Node}.{ZoneDevice}` (e.g. `HomeRouter.Printer`) | The device's IP                                                          |
| `{Node}.$hub` (e.g. `HomeRouter.$hub`)            | The node's hub network                                                   |
| `{Node}.{HubClient}` (e.g. `HomeRouter.lte-cam`)  | The hub client's IP                                                      |
| `{Node}.$node` (e.g. `HomeRouter.$node`)          | The node itself: its `meshIp` and its own address on each of its `zones` |
| `$node`                                           | The same, for the node the rule is on                                    |

A single tag can group multiple objects if they share it. `allowFrom: admin` grants access from every device, client, or hub tagged `admin` — across multiple nodes.

### Subnets vs IPs

Bare and qualified node-name forms (`HomeRouter`, `HomeRouter.lan`) resolve to **subnets** — broad, meaning "any device on those networks." `HomeRouter.$node` and `$node` resolve to **IPs** — narrow, meaning "the node itself as a host." These are complementary, not interchangeable.

Use the bare node name when you want any traffic from that node's downstream networks. It doesn't cover what the node sends itself over the mesh: name that `HomeRouter.$node` (see below).

### Examples

```yaml
allowFrom: admin                          # everything tagged admin (cross-node)
allowFrom: HomeRouter                     # all of the node's zone subnets + its hub network
allowFrom: HomeRouter.lan                 # only the node's lan zone subnet
allowFrom: HomeRouter.Printer             # specific device's IP
allowFrom: HomeRouter.$hub                # the node's hub network
allowFrom: HomeRouter.lte-cam             # a hub client's IP
allowFrom: Phone                          # global client's IPs
allowFrom: [admin, HomeRouter.iot]        # admin-tagged things + the node's iot zone subnet
allowFrom: HomeRouter.$node               # the node itself: its meshIp and its address on each zone
allowFrom: $node                          # the node the rule is on, which needs no rule (see below)
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
- **Per-node-scoped implicit tags** (referenced as `{NodeName}.{LocalName}`): zones, zone devices, hub clients. The hub itself is `{NodeName}.$hub`.

The qualified `{NodeName}.{LocalName}` syntax is intentionally only **two levels deep** — the per-node namespace is flat. There is no `{NodeName}.{Zone}.{Device}` form; a device is referenced as `{NodeName}.{Device}` directly. This works because per-node names across all three categories are unique.

### A node itself: `{Node}.$node`

What a node sends itself, rather than forwards for a device behind it, leaves over the mesh from its `meshIp`: its resolver forwarding names to another node, a reverse proxy on it, its backups. `HomeRouter` (its networks) doesn't cover that address, so `allowFrom: HomeRouter` doesn't let it in. `HomeRouter.$node` names the node itself: its `meshIp`, and its own address on each of its `zones` (for a program bound to one).

```yaml
nodes:
  Cabin:
    services:
      dns:
        port: 53
        proto: [udp, tcp]
        allowFrom: Home.$node    # Home's resolver forwards Cabin's names here
```

Cabin lets it in from the mesh. Home itself gets no rule for it: what a node sends leaves through its output, which splot doesn't filter.

### `$node`

`$node` is a special context-dependent tag that resolves to the node currently being configured: the same addresses as `{Node}.$node` for that node. No firewall rule is generated for it: what the node itself sends leaves through its output, which splot doesn't filter.

### Allowed characters

Names must contain only alphanumeric characters, `-`, and `_`. Spaces, dots, and other special characters are forbidden — names are used as part of generated UCI section identifiers, and `.` is reserved as the qualified-reference separator.

A name splot hands out as a host name must also be one: a device with `macs` on a node whose DHCP splot manages, and a global client with `macs` and an address on such a node. Its static lease gives the device its name, so it takes letters, digits and hyphens, no hyphen at either end, at most 63 characters (`my_printer` is an error there; `my-printer` isn't). Case is kept as written; DNS ignores it.

### Names of splot's own

What splot itself names inside a node starts with `$`: `{NodeName}.$hub` (the hub network) and `{NodeName}.$node` (the node itself). A name can't hold a `$`, so they never clash with a zone, device, or hub client, and take no name from them: a zone may be called `hub`, and `HomeRouter.hub` is then that zone.

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
