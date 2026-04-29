# Roadmap

Confirmed next implementation steps, in priority order.

---

## 1. Config validation

Validate `splot.json` before any UCI commands are generated. Fail early with clear error messages.

Rules to enforce (see CONFIG.md for full definitions):

- **Global name uniqueness** — node names, LAN device names, VPN interface names, and VPN client names must all be unique across the entire config
- **No name/tag collisions** — explicit tags must not duplicate any object name (they share the same namespace)
- **Valid characters in names** — alphanumeric, `-`, `_` only; no spaces or special characters
- **Subnet non-overlap** — `meshIp` prefixes, `lan.address` subnets, and VPN interface subnets must not overlap with each other across the entire mesh
- **Device IPs within LAN subnet** — each LAN device `ip` must fall within its node's `lan.address` subnet
- **VPN client IPs within interface subnet** — each VPN client `ip` must fall within its interface's `address` subnet
- **`allowFrom` references must exist** — every tag/name used in `allowFrom` must resolve to at least one known entity

---

## 2. CLI Interface

A proper CLI for interacting with splot on a router:

- `splot validate` — validate the local config file and report errors
- `splot dry-run` — generate and print all UCI commands that would be applied, without executing them
- `splot apply` — full pipeline: validate, generate, apply via uci, reload affected services

This is the first user-facing entry point and should land right after validation so the validator is reachable without a wrapper.

Implement structured logging (e.g. `tracing`) at the same time — not deferred. Each pipeline stage (load, validate, generate, apply) should emit actionable log output at appropriate levels (`info` for progress, `debug` for generated commands, `error` for failures). This makes `dry-run` and `apply` debuggable from day one.

---

## 3. Per-zone firewall rule generation (security hardening)

Generated traffic rules currently match on `src_ip` alone, without constraining which zone the packet entered from. Splitting each rule per source zone prevents a packet from one zone matching a rule intended for another (spoofed-source-IP scenarios).

When a rule's `allowFrom` resolves to IPs/subnets spanning multiple zones, emit one rule per zone — each scoped to its specific `src` zone in addition to `src_ip`. The `dest` zone is set from the zone the target IP belongs to. Local and remote sources stay symmetric in the config; only the generated UCI output gains the zone scoping.

Deferred to the end of the roadmap — purely a hardening pass on generated rules; does not affect mesh connectivity or behavior.
