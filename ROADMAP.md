# Roadmap

Confirmed next implementation steps, in priority order.

---

## 1. Static DHCP leases (DhcpManager)

A new `DhcpManager` implementing `UciManager` that generates static DHCP lease entries for LAN devices that have a `mac` field.

- Config file: `dhcp`
- For each node's LAN device with a `mac` address: emit a `host` section binding that MAC to the device's IP
- Named section prefix: `spl_` (consistent with other managers)
- Devices without a `mac` field are skipped silently

---

## 2. Config validation

Validate `splot.json` before any UCI commands are generated. Fail early with clear error messages.

Rules to enforce (see CONFIG.md for full definitions):

- **Global name uniqueness** — node names, LAN device names, VPN interface names, and VPN client names must all be unique across the entire config
- **No name/tag collisions** — explicit tags must not duplicate any object name (they share the same namespace)
- **Valid characters in names** — alphanumeric, `-`, `_` only; no spaces or special characters
- **Subnet non-overlap** — `meshIp` prefixes, `lan.address` subnets, and VPN interface subnets must not overlap with each other across the entire mesh
- **Device IPs within LAN subnet** — each LAN device `ip` must fall within its node's `lan.address` subnet
- **VPN client IPs within interface subnet** — each VPN client `ip` must fall within its interface's `address` subnet
- **`allowFrom` references must exist** — every tag/name used in `allowFrom` must resolve to at least one known entity
