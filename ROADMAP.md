# Roadmap

Confirmed next implementation steps, in priority order.

---

## 1. Shared devices

A top-level `sharedDevices` section for devices that roam across multiple nodes (phones, laptops). Defined once, propagated to every node that lists an address for it.

**Config structure:**

```json
"sharedDevices": {
  "Phone": {
    "mac": ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"],
    "tags": "admin",
    "addresses": {
      "HomeRouter": "192.168.1.50",
      "OfficeRouter": "192.168.2.50"
    },
    "services": { ... }
  }
}
```

**Behavior:**

- Each node looks up its own name in `addresses` — if present, the device is treated exactly like a `lanDevice` on that node (static DHCP lease per MAC, firewall rules, tag resolution)
- Nodes not listed in `addresses` ignore the device entirely
- Multiple MACs map to the same IP — valid for devices with separate ethernet and WiFi interfaces (mutually exclusive interfaces only; simultaneous same-subnet use is not supported)
- `sharedDevices` names enter the global uniqueness namespace alongside all other names

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
