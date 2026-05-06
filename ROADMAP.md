# Roadmap

Confirmed next implementation steps, in priority order.

---

## 1. Config validation

Validate `splot.yml` before any UCI commands are generated. Fail early with clear error messages.

Rules to enforce (see CONFIG.md for full definitions):

- **Global namespace uniqueness** — node names, global client names, and explicit tag names must all be unique within the global namespace; no collisions between any of them
- **Per-node namespace uniqueness** — within a single node, zone names, device names, VPN interface names, and VPN client names must all be unique among each other
- **Valid characters in names** — alphanumeric, `-`, `_` only; no spaces or special characters
- **Reserved prefixes for per-node-scoped names** — no zone, device, VPN interface, or VPN interface client name may start with `{NodeName}_` where `{NodeName}` is the name of any node in the config. Prevents collisions with generated qualified rule names (e.g. a literal `Jawo_printer` would clash with the qualified form of Jawo's `printer`).
- **Subnet non-overlap** — `meshIp` prefixes, zone `address` subnets, and VPN interface subnets must not overlap with each other across the entire mesh
- **Device IPs within zone subnet** — each device's `ip` must fall within its zone's `address` subnet
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

## 3. Per-zone src/dest scoping in generated rules

Generated rules currently set `src=*` and `dest=*`, matching only on `src_ip` / `dest_ip`. Replace `*` with computed zone names from the zone-aware tag resolution map.

When a rule's `allowFrom` resolves to source IPs across N zones, emit N rules — one per source zone, each with that zone's name in `src` and only that zone's IPs in `src_ip`. The `dest` zone is the zone the target IP belongs to (`device` if the target is `$node`, otherwise the matching zone). This naturally distinguishes input rules (router as destination) from forward rules (downstream destination) without separate code paths.

The same-network filter on the source IP set stays — it correctly skips rules that would never match because the traffic doesn't traverse the firewall (same-subnet, L2-bridged). It is not replaced with a same-zone filter — same-zone-different-subnet traffic is intra-zone forwarding and may legitimately need rules.

Tested end-to-end: rules in `/etc/config/firewall` show explicit src/dest zone names with no `*`, and access from a wrong-zone source is rejected.
