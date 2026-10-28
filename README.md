# splot-sdwan

Declarative WireGuard mesh networking for OpenWRT routers. You describe your network — routers, zones, devices, services — in a single YAML file; splot translates it into OpenWRT `network`, `dhcp`, and `firewall` configuration via `uci`.

> **Status:** work in progress, hobby/learning project. The core pipeline works (config parsing, validation, UCI generation for network/DHCP/firewall) behind a small CLI (`check`, `apply --dry-run`), but the config format may still change. Not production-ready — see [STATUS.md](STATUS.md) for what's done and [ROADMAP.md](ROADMAP.md) for what's next.

## What it does

- Builds a **WireGuard mesh** between your OpenWRT routers — interfaces, peers, and keys are generated from the config.
- **Zero-trust by default**: splot-managed firewall zones drop all input; access is granted only through explicit per-service rules. There is no broad zone-to-zone forwarding.
- **Tag-based access control**: every service declares `allowFrom` using tags or names (nodes, zones, devices, clients). Splot resolves these to IPs/subnets and emits scoped firewall rules.
- **Static DHCP leases** for devices and roaming clients with declared MACs.
- **WAN exposure** declared on the service itself — port forwards with optional CIDR allowlists, including cross-node forwarding over the mesh.
- One config file, synced across routers. Each router is named with `--node`, checks its WireGuard key is that node's, and applies only its own slice.
- Each node says which software it runs (`platform`), and which concerns splot leaves to you (`none`).

## Example config

```yaml
meshNetwork: 10.100.0.0/16

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
    platform:
      os: openwrt
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

    hub:
      network: 10.100.10.0/24
      clients:
        lte-cam:
          publicKey: <wireguard-pubkey>
          ip: 10.100.10.10
          services:
            rtsp:
              port: 554
              proto: tcp
              allowFrom: admin

  Cabin:
    platform:
      os: openwrt
    publicKey: <wireguard-pubkey>
    endpoint: cabin.example.com
    listenPort: 51820
    meshIp: 10.100.0.2
    zones:
      lan:
        address: 192.168.2.1/24
```

With this config, `Phone` (tagged `admin`) can reach SSH on the `Home` router, the printer on its LAN, and the camera behind Home's hub — from anywhere in the mesh. Nothing else gets through.

## Concepts

| Concept | Meaning |
| --- | --- |
| **Node** | An OpenWRT router participating in the mesh |
| **Zone** | A downstream network the router serves (LAN, VLAN) — operator-managed, splot only references it |
| **Hub** | A network inside the mesh for devices that reach it through one node alone (e.g. behind NAT); its clients are peers on that node |
| **Device** | A fixed host inside a zone (static IP, optional DHCP lease) |
| **Client** | A roaming device (phone, laptop) known mesh-wide |
| **Service** | A port/protocol on any of the above, with `allowFrom` (mesh/LAN access) and/or `wan` (public exposure) |
| **Tag** | The access-control primitive; every named thing also acts as its own tag |

Full reference: [CONFIG.md](CONFIG.md).

## How it works

1. Parse `splot.yml` into typed structs (strict — unknown fields are errors).
2. Validate: name/tag uniqueness, identifier resolution, subnet overlaps, IP containment, port conflicts. Errors abort before anything is touched.
3. Take the node from `--node`, and check the router's WireGuard key is the one the config has for it.
4. Generate UCI sections (network interfaces and peers, DHCP host leases, firewall zones and rules) for this node.
5. Apply as a single `uci batch` with per-file atomic commits.

## Running

Requires Rust (edition 2024) to build, and on the node: OpenWrt with `uci` and WireGuard tools (`wg`), or Linux with systemd, wireguard-tools (`wg`, `wg-quick`), iproute2 and `ping` (iputils-ping: after a change, the node pings its peers to check its tunnels). On Linux splot manages only the WireGuard so far ([CONFIG.md → Linux](CONFIG.md#linux)).

splot runs on your machine and reaches each node over ssh, at the node's `platform.ssh` in the config (anything `ssh` takes: `root@router`, a host of your `~/.ssh/config`), or at `--ssh <destination>` for one command. It sends the node a small agent for its CPU, which does the work there and is gone afterwards: nothing is installed on the node, and its keys never leave it. With neither, or with `--local`, splot acts on the machine it runs on.

`splot apply` without `--node` is one run across the mesh: every node keeps the change, or every node puts back what it had. splot shows the plan for every node and asks first (`--yes` doesn't; without a terminal it needs `--yes`); then every node prepares, applies at once, checks that its peers still answer through the mesh, and is confirmed. A change that cuts a node off, or that splot can't confirm in time (`--confirm-within`, default 2 minutes), is put back everywhere, by each node itself if splot can't reach it.

```sh
scripts/dist.sh            # build target/dist/splot, carrying the agents (needs the Rust targets it names)
cd target/dist             # with splot.yml in the working directory:
./splot check              # validate the config, report errors and warnings
./splot init --node Cabin --ssh root@cabin   # a new router, not in the config yet: give it its WireGuard key; print its entry
./splot apply --dry-run    # show what every node would change (placeholders for the keys)
./splot apply              # make every node hold what the config says, or none: shows the plan, asks, applies
./splot apply --node Cabin --dry-run   # the same for Cabin alone, at its platform.ssh
./splot apply --node Cabin             # make Cabin alone hold what the config says
./splot psk set --node Cabin Home < home.psk  # store Cabin's preshared key with Home
```

`-c/--config <FILE>` overrides the config path (default: `splot.yml`). splot carries agents for aarch64, armv7 (with a floating-point unit), riscv64 and x86_64 (`splot --version` lists them); for another CPU, build the agent yourself and pass it with `--agent <FILE>`.

Start a new router with `splot init --node <Name>`. It generates the router's WireGuard key, only if it has none (a key is never replaced), and stores it in the router's key store, readable by root only: `/etc/config/splot` on OpenWrt, `/etc/splot/keys` on Linux. Which one is the OS the config gives the node; for a node the config doesn't have yet, the one `--os openwrt|linux` names, or else the one the peer runs (OpenWrt has `/etc/openwrt_release`; any other Linux is Linux). Every command that acts as a node refuses on a peer that isn't what the config or `--os` says. Then it holds the router's key against the config: the node is already initialised when the config has this key for it; for a node the config doesn't have yet, it prints its entry ready to paste under `nodes:`, with the public key and the lowest free mesh IP; for a key it just generated, it prints the key to set for the node. It refuses (exits non-zero) when the key is another node's or client's, naming where the config has it (a wrong `--node`), and when a key the router already had is nowhere in the config. `init` is the only command that writes the key: every other one, `--dry-run` included, asks for `init` on a router that has none. A node whose WireGuard you set up yourself (`wireguard: none`) needs no `init`: splot keeps no key there, and checks the node by its own WireGuard's key instead.

Every WireGuard pair uses a preshared key unless one end sets `psk: false`, and `apply` refuses until they're stored: generate one per pair (`wg genpsk`) and store the same key on both ends with `splot psk set --node <Name> <peer>`.

`--node` names the node a peer is; every command that acts as it (`apply`, `psk set`) first checks the peer's own key is the one the config has for that node, and refuses otherwise, writing nothing. See [CONFIG.md → Preshared keys](CONFIG.md#preshared-keys).

For local development, `SPLOT_UCI_CONFIG_DIR` redirects UCI output to a directory of your choice instead of `/etc/config`.

## Documentation

- [CONFIG.md](CONFIG.md) — full config format reference and design rationale
- [STATUS.md](STATUS.md) — what's implemented today
- [ROADMAP.md](ROADMAP.md) — prioritized next steps
- [IDEAS.md](IDEAS.md) — longer-horizon ideas

## License

[MIT](LICENSE)
