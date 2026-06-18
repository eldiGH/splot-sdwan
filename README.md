# splot-sdwan

Declarative WireGuard mesh networking for OpenWRT routers. You describe your network — routers, zones, devices, services — in a single YAML file; splot translates it into OpenWRT `network`, `dhcp`, and `firewall` configuration via `uci`.

> **Status:** work in progress, hobby/learning project. The core pipeline works (config parsing, validation, UCI generation for network/DHCP/firewall), but there's no stable CLI yet and the config format may still change. Not production-ready — see [STATUS.md](STATUS.md) for what's done and [ROADMAP.md](ROADMAP.md) for what's next.

## What it does

- Builds a **WireGuard mesh** between your OpenWRT routers — interfaces, peers, and keys are generated from the config.
- **Zero-trust by default**: splot-managed firewall zones drop all input; access is granted only through explicit per-service rules. There is no broad zone-to-zone forwarding.
- **Tag-based access control**: every service declares `allowFrom` using tags or names (nodes, zones, devices, clients). Splot resolves these to IPs/subnets and emits scoped firewall rules.
- **Static DHCP leases** for devices and roaming clients with declared MACs.
- **WAN exposure** declared on the service itself — port forwards with optional CIDR allowlists, including cross-node forwarding over the mesh.
- One config file, synced across routers. Each router identifies itself by its WireGuard public key and applies only its own slice.

## Example config

```yaml
meshNetwork: 10.100.0.0/24

clients:
  Phone:
    publicKey: <wireguard-pubkey>
    meshIp: 10.100.0.100
    tags: admin
    macs: AA:BB:CC:DD:EE:01
    ips:
      Home:
        lan: 192.168.1.30

nodes:
  Home:
    publicKey: <wireguard-pubkey>
    endpoint: home.example.com
    listenPort: 51820
    meshIp: 10.100.0.1

    services:
      ssh:
        port: 22
        proto: tcp
        allowFrom: admin

    zones:
      lan:
        address: 192.168.1.1/24
        devices:
          printer:
            ip: 192.168.1.16
            macs: AA:BB:CC:DD:EE:02
            services:
              print:
                port: 9100
                proto: tcp
                allowFrom: admin

    vpnInterfaces:
      wg_guest:
        listenPort: 51821
        address: 10.8.6.1/24

  Cabin:
    publicKey: <wireguard-pubkey>
    endpoint: cabin.example.com
    listenPort: 51820
    meshIp: 10.100.0.2
    zones:
      lan:
        address: 192.168.2.1/24
```

With this config, `Phone` (tagged `admin`) can reach SSH on the `Home` router and the printer on its LAN — from anywhere in the mesh. Nothing else gets through.

## Concepts

| Concept | Meaning |
| --- | --- |
| **Node** | An OpenWRT router participating in the mesh |
| **Zone** | A downstream network the router serves (LAN, VLAN) — operator-managed, splot only references it |
| **VPN interface** | An extra WireGuard interface for external clients, fully managed by splot |
| **Device** | A fixed host inside a zone (static IP, optional DHCP lease) |
| **Client** | A roaming device (phone, laptop) known mesh-wide |
| **Service** | A port/protocol on any of the above, with `allowFrom` (mesh/LAN access) and/or `wan` (public exposure) |
| **Tag** | The access-control primitive; every named thing also acts as its own tag |

Full reference: [CONFIG.md](CONFIG.md).

## How it works

1. Parse `splot.yml` into typed structs (strict — unknown fields are errors).
2. Validate: name/tag uniqueness, identifier resolution, subnet overlaps, IP containment, port conflicts. Errors abort before anything is touched.
3. Identify the current node by matching the local WireGuard public key.
4. Generate UCI sections (network interfaces and peers, DHCP host leases, firewall zones and rules) for this node.
5. Apply as a single `uci batch` with per-file atomic commits.

## Running

Requires Rust (edition 2024), and on the target router: OpenWRT with `uci` and WireGuard tools (`wg`).

```sh
cargo build --release
# on the router, with splot.yml in the working directory:
./splot-sdwan
```

On first run splot generates a WireGuard keypair and stores it in its local state file. Add the resulting public key to your config as a node, then re-run.

For local development, `SPLOT_UCI_CONFIG_DIR` redirects UCI output to a directory of your choice instead of `/etc/config`.

## Documentation

- [CONFIG.md](CONFIG.md) — full config format reference and design rationale
- [STATUS.md](STATUS.md) — what's implemented today
- [ROADMAP.md](ROADMAP.md) — prioritized next steps
- [IDEAS.md](IDEAS.md) — longer-horizon ideas

## License

[MIT](LICENSE)
