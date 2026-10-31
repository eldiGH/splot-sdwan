# splot-sdwan

## Project Purpose

A Rust tool that runs a WireGuard mesh between sites, and the access between the networks behind them. One `splot.yml` describes the whole network; splot works out what each node has to do and configures it: the mesh, the firewall, DHCP reservations and, later, DNS. Each node says what it runs: OpenWrt (configured through `uci`) or Linux (wg-quick, nftables, dnsmasq; in progress). OPNsense is planned.

## Goals

- One config for the whole mesh, validated before anything is touched
- A WireGuard mesh between sites, roaming clients (phones, laptops) and devices behind a site (hubs)
- Zero-trust access: each service says who may reach it, and nothing else gets through
- Per node, each concern managed with the software that node runs, or left to the operator
- Safe apply: only on the node it's meant for, staged, and (with the planned controller) confirmed on every node or rolled back

## Project Context

This is a hobby project that started as a way to learn Rust and systems programming. The goal now is a tool the owner actually runs on their network — while keeping full control over its architecture and direction.

**Collaboration style — the owner is the product manager, Claude is the engineer and its own reviewer (since 2026-10-31):**

- **The owner decides:** architecture, config shape, design decisions (tasks tagged `decision`), scope. When a task runs into a real design question, stop and ask (one batch of questions, each with a recommendation) — don't pick an answer silently.
- **Claude implements** the tasks on the board in order: tests first (watch them fail), then the change; `cargo test`, `cargo fmt --check` and `cargo clippy -- -D warnings` clean.
- **Claude reviews and commits:** before each commit, review the diff as a reviewer would (read it whole, try the mutations, run the container checks the change calls for), then commit with the task ID in the subject. The owner doesn't read the code. Keep commits single-purpose — formatting-only or mechanical changes separate from logic.
- **Every task ends with a short report for the owner:** what changed for the operator, the decisions made, what was verified (tests, mutations, container checks), and anything found along the way. Push only when asked.
- **A bigger task goes in steps**, each its own commit.
- **Every decision gets written down** where the next session reads it: design in this file (and CONFIG.md for the config), the task's notes, or the plan. A conversation ends; nothing that matters may live only in it.

---

## Design Decisions

### Config philosophy

`splot.yml` says what the network is and what the operator decided about it; splot works out what each node has to do.

- **The network** is written the way the operator thinks about it: nodes, zones, devices, clients, tags, and services that say what may reach what. Real network facts belong here when the operator needs to state them: subnets, addresses, endpoints, which nodes can be dialled.
- **The deployment** goes in each node's `platform` block: which OS the node runs, which program handles each concern, which concerns splot leaves alone (`none`), and where splot reaches it (`ssh`). These are the operator's choices and they change what the config can mean on that node, so `splot check` must see them for every node at once. They stay in that block, apart from the network.
- **splot's implementation stays out:** uci section types, the names splot gives what it generates, how a backend spells a rule.
- **Nothing is guessed.** Every node says what it runs. splot doesn't detect it and doesn't take a default from what one network happens to use; at most it checks that the node is what the config says. The only defaults are what a named OS ships with (on OpenWrt: netifd, fw4, dnsmasq).
- **The same config means the same thing on every platform.** splot never relies on a platform's own defaults. Where a node won't carry something out because splot doesn't manage that concern there, `splot check` says so.

### Top-level config shape

- `meshNetwork` — the whole WireGuard mesh address space: the nodes' and global clients' `meshIp`, and the nodes' hub networks
- `keepaliveInterval` — seconds between WireGuard keepalives, for the hosts that send them (see "Keepalive"); optional, default 25
- `nodes` — map of routers participating in the mesh
- `clients` — map of *global* clients: roaming things (phones, laptops) with optional MACs and per-node IPs, accessible across the mesh

Each node carries:

- `platform` — the OS it runs, the program behind each concern splot can manage there, or `none`, and where splot reaches it over ssh (see "Node platform")
- mesh metadata (`publicKey`, `endpoint` (optional, see "Endpoint"), `listenPort`, `meshIp`)
- `zones` — map of downstream networks the router serves (LAN, VLANs). The map key is the OpenWRT zone name on that router. Splot doesn't create these zones in OpenWRT — the operator configures them — it decides what may cross between them (see "Trust model").
- `hub` — a network inside `meshNetwork` for devices that reach the mesh through this node alone (hub clients). See "Hubs".
- `services` — services exposed by the router itself
- `wanZone` — name of the OpenWRT firewall zone that is WAN-facing (required where splot manages the node's firewall and either a service uses the node in `wan.via` or others dial it, see "Endpoint")
- `tags` — explicit tags on the node

### Node platform

Each node's `platform` says which OS it runs (`os: openwrt` or `linux`, required) and, per concern (`wireguard`, `firewall`, `dhcp`, `dns`), the program splot manages it with, or `none`.

- **Values are the programs:** on OpenWrt `netifd`, `fw4`, `dnsmasq` (DHCP and DNS); on Linux `wg-quick`, `nftables`, `dnsmasq`. Not one `uci` value: uci is how OpenWrt's settings are written, not what carries them out, and naming the program lets a backend check that program's limits.
- **`os` is required, with no default and no detection.** `splot check` works offline, for every node at once, and the config keeps one meaning when a node is reinstalled. Detecting the OS only checks the peer is what the config says: `init`, `apply` and `psk set` refuse a peer that runs another (OpenWrt is known by `/etc/openwrt_release`, any other Linux is Linux).
- **The key store follows the OS:** uci on OpenWrt, a file on Linux. For a node the config doesn't have yet, `init` takes the OS from `--os`, else from what the peer is; any two of the config, `--os` and the peer that disagree is an error.
- **Defaults come from the OS alone:** on OpenWrt a concern left out is managed with what OpenWrt ships; on Linux there's no usual setup to assume, so every concern is written out, `none` included. A program the OS doesn't have is an error. Platform defaults for every node at the top level are planned.
- **`dns`** is accepted, and does nothing until splot generates DNS config.
- **`ssh`** (optional) is where splot reaches the node: anything `ssh` takes, given to it as it is; never read as an option (no leading `-`), no spaces or control characters. A deployment fact like the programs, so `splot check` sees it for every node. Not the `meshIp` by default (it can't reach a node that isn't in the mesh yet, or whose tunnel is down), nor the node's name as an ssh alias.
- **`interfaces`** (decided) says which network interfaces each zone and the `wanZone` are on, for nftables, which tells zones apart by interface where fw4 has zones of its own. A deployment fact like `ssh`, so `splot check` sees it. With `firewall: nftables` every zone, and the `wanZone` when there is one, needs its interfaces (one name or a list); on OpenWrt the key is an error, since a zone there is the fw4 zone of the same name. Two declared zones can't share an interface (splot couldn't tell them apart); the WAN may come in on a zone's: a host that isn't its site's gateway, behind a port forward on the router in front of it. No zone is on `spl_mesh`.
  - Rejected: an `interface` key on each zone plus a `wanInterface` (a deployment fact in the network part); matching zones by subnet alone (a device can claim another zone's address, and the WAN has no subnet).
- **`none`** means splot leaves that concern alone: nothing generated, nothing touched there, its own old sections included. The plan has no section for it, and a backend renders no file for it.
- **`wireguard: none`** means the node is in the mesh with WireGuard set up by hand. splot keeps no key there; the key check uses the node's own WireGuard instead (one of its interfaces has the config's `publicKey`). Such a node has no hub (an error): hub clients are peers on splot's mesh interface; a WireGuard server of the operator's own, with its own subnet, is a zone. Its listen port is the operator's to let in from the WAN too: splot opens only its own interface's. How to confirm a node that has no WireGuard key at all is an open question.
- **Errors and warnings:** an error when the config doesn't make sense, or a concern splot manages lacks something it needs from the config (a `wan.via` node whose firewall splot manages needs a `wanZone`, and so does a node others dial; one that leaves its firewall alone doesn't); a warning when a node leaves part of a valid config undone because a concern is `none`, one per node and concern, saying what's left undone and what's the operator's to do. `allowFrom` that a firewall left alone won't enforce is a warning, not an error: `firewall: none` is written next to the services, and it's how a site moves to splot's firewall a step at a time.
- **No partially working state:** what splot renders for a concern it manages is complete for what it covers, and never points at something a `none` concern would have created. With `wireguard: none` and the firewall managed, for one, there's no mesh zone, no port forward to a host reached over the mesh (the forward would name the mesh zone), no rule for what crosses the mesh (it arrives in the operator's zone; the warning names those services), and no rule for the listen port.
- **What a platform can't do yet is refused, not half applied:** on Linux splot doesn't manage DHCP yet, so `apply` refuses a Linux node whose `dhcp` names a program until splot manages it there (`splot check` validates the node either way).

### Reaching a node: an agent per run

splot runs on the operator's machine and reaches a node over ssh, at `--ssh <destination>` when given, else at the node's `platform.ssh` (either given to the system `ssh` as it is, so `~/.ssh/config` and the operator's ssh agent apply). It sends the node `splot-agent`, which does everything there, runs it from `/tmp`, and the node removes it when it ends. Nothing is installed on the node: a router's flash stays as it is, and `sysupgrade` has nothing to wipe. With neither, or with `--local` (for a node that has `platform.ssh`), splot calls the agent's code in-process, on the machine it runs on: the key check refuses if that machine isn't the node.

- **The cut is the rendered config:** splot validates, plans and renders; the agent checks it runs the OS the config says and is the node, fills the secrets in from the node's key store, and applies. No secret leaves the node: a private key can't even be put in a message (no serde), and a preshared key travels once, to the node that keeps it.
- **One agent per CPU, in splot:** aarch64, armv7 (with a floating-point unit), riscv64, x86_64, static, under 1 MB each (it runs from a router's RAM). The node says its CPU first (`uname -m`, OpenWrt's `DISTRIB_ARCH`); a CPU splot has none for is refused, and `--agent <file>` sends one built by hand. MIPS later (Rust's tier 3).
- **The session** (`agent/session.rs`): the node runs a short sh bootstrap; splot sends the agent's size and bytes, waits for `ready` (busybox's `head -c` reads past what it's asked for, so nothing else may follow the bytes yet), then talks to the agent a JSON line each way. The first request is `Hello` with the protocol's version, whose shape never changes; an agent of another version refuses. An agent cut short in transit doesn't run.

### Applying safely: a run, confirmed or put back

A change splot applies is a run, in two steps. `Request::Prepare { rendered, run }` changes nothing: the agent works out what differs, keeps what the node has (the uci files that change; on Linux, for each concern that changes, splot's files, the wg-quick file or the nft file and its unit's, and whether its unit ran and was enabled) in `/tmp/splot/run/`, and starts a watchdog: the agent itself, started again, detached, which puts all of it back at the deadline unless the run is confirmed. `Request::Go`, over the same session (the agent holds what it prepared), applies it. Prepare answers with what the go will change exactly as the dry run shows it (`Changes`), so a run across nodes can tell that what each prepared is the plan the operator saw. A prepared run that never gets the go ends at its deadline with nothing to put back, and a run begins even when nothing changes (nothing to put back then), so that across nodes every one can be prepared first, and checked after. splot confirms only after reaching the node again with a new session (`--confirm-within`, default 2 minutes); a change that cuts splot off from the node is undone by the node itself.

- **Decided once:** the run's state is one marker, renamed, and whoever renames it first decides each step: `prepared` becomes `armed` at the go, then `confirmed` or `rolling-back` (asked for, or the watchdog at the deadline); a prepared run rolled back becomes `cancelled`. A rollback tries `prepared` before `armed`, so a go racing the deadline leaves the run either cancelled or applied and put back, never applied with nobody to put it back. A go or a confirm that comes too late is told so. A rollback asked again, or while the node puts the run back by itself, answers that it's put back (so splot can simply ask again); a confirmed run refuses it.
- **One run at a time:** the run's directory is the lock. A run that fails while it applies (a batch uci rejects, a failed commit or reload) is put back on the spot.
- **Live before the check** (decided): the go answers once its change is live, so the check sees it; a put-back too. On OpenWrt, `reload_config` tells procd which files changed, and procd reloads every service that reads one, but a second later: after a quick run's check and confirm. So the agent also runs the reloads itself: netifd's (`ubus call network reload`, then the mesh interface's renew, or down and up), fw4's (`/etc/init.d/firewall reload`, which returns once the ruleset is loaded) and dnsmasq's (its init script's reload, in which procd restarts it). procd reloads them again a second later, with the same files. `reload_config` stays first: other services read those files too (odhcpd, miniupnpd, mwan3), and an agent stopped halfway still leaves procd to reload the rest.
  - **A ruleset nft refuses is a failed reload:** fw4 keeps the old ruleset live then, and still exits 0. So `fw4 check` runs first, fw4 isn't reloaded when it fails, and the go puts back on the spot.
  - Rejected: waiting for procd's reloads (nothing says they ran, and procd ignores what they return); the reloads without `reload_config` (the other services that read those files wouldn't reload, until the next `reload_config` anyone runs).
- **What's healthy** (decided): splot reaches the node again, and every node peer that answered before the apply answers after: a ping to its mesh IP (every peer may ping a node, see "Zones"), which also brings the tunnel up. A peer whose preshared key changed gets a fresh session first, so the check proves the new key: WireGuard would keep the old session until its next rekey.
  - **Before the run** (decided), a node pings each node peer twice, a second each: an idle tunnel may take the first to come up. A peer that doesn't answer, but that the node holds a session with (a handshake under 3 minutes old, `wg show latest-handshakes`), gets up to 16 s more. The other end may have dropped that session (its interface restarted, a run put back): it doesn't answer what's sent into it, and WireGuard starts a new handshake only 15 s after the first packet that got no answer. A peer with no session gets no more: a ping starts its handshake, so the two pings are enough for one that works. A peer that's really down costs those 16 s only when it went down within the last 3 minutes.
  - **What the run doesn't check is said:** a peer that didn't answer before the run isn't checked after it, and the node's check line names it ("Checked Cabin: Home answers as before; not Lake, which didn't answer before the run"). splot works it out from the probes it sent and what the check answers.
  - Rejected: every peer that doesn't answer pinged for 16 s (a peer that's really down would cost that on every run, for each node, since they prepare one at a time); a fresh session at prepare for one that doesn't answer (the prepare would change the live interface, and on OpenWrt only netifd's renew, or a restart, adds the peer back).
- **Across the mesh** (`splot apply` without `--node`, `mesh_run.rs`): every node splot manages something on, each reached at its `platform.ssh` (a node without one is an error naming them all; a node where every concern is `none` is left out), all or nothing. **One node** (`--node X`) is the same run, on a mesh of one: reached at `--ssh`, else its `platform.ssh`, else in-process; where the mesh's messages say "every node", they name the node. One code path keeps or puts back a change, whatever the number of nodes. Each step on every node at once, in parallel, but the two that ping the peers, the prepare and the check, which go one node at a time, in the config's order:
  - **Plan:** each node's dry run, which also checks it's the node, and warns about the node's own settings that decide some of what splot does (on OpenWrt, the operator's sections where splot decides, see "Firewall default policy"); the combined plan, then "Apply this plan? [y/N]" (`--yes` skips it; without a terminal and without `--yes`, refused before any node is reached).
  - **Prepare** every node, one at a time (it notes which peers answer then); one that fails, or whose changes aren't the plan shown any more, stops the run: every prepared node is cancelled, nothing applied.
  - **Go** to every node at once (no order: if a node's change cuts splot's path to another before its go arrives, that one never applies, the check fails, every node puts back).
  - **Check** every node, changed or not, over a session of its own (the sessions open at once), one at a time; the first node that lost a peer, or that splot can't reach, ends the checks (the rest are named as not checked), and every node puts back.
    - One at a time (decided), because two ends that ping each other at once, neither with a session (a changed preshared key drops it, an idle one expires), both start a handshake: WireGuard keeps one per peer, so each drops the other's answer, and it tries again only after 5 s. On separate machines its jitter breaks the tie then; in containers sharing one kernel the retries fire in the same tick, again and again, past the check's time.
    - In turn, a node finds the sessions the nodes before it opened: of two nodes, the first in the config's order opens the one the check needs.
    - Rejected: each pair probed from one end only (when that end's probe misses before the run, nobody checks the pair, where the other end's would); the later end of each pair waiting before it probes (seconds on every run, and the protocol carrying the wait).
  - **Confirm** every node (each asked again over a new session while there's time); what isn't atomic is the moment between the last check and the last confirm: a node that misses its confirm puts back alone, and the report says to run again.
  - **Putting back** asks every node that may have the run; one splot can't reach is waited for until its deadline has passed, then asked again (it put back by itself, or is still unreachable). A rollback and a confirm asked again answer the same, so asking again is always safe.
- **Not yet:** a rollback that survives a reboot (the run lives in RAM).

### Linux: WireGuard with wg-quick

splot owns `/etc/wireguard/spl_mesh.conf` and runs it through systemd's `wg-quick@spl_mesh`; a Linux node needs systemd.

- **The keys are inside the file** (0600, rewritten whole: a new file renamed over it), never set by `PostUp`: `wg syncconf` with `wg-quick strip` would zero what a `PostUp` set.
- **Started and enabled** (`systemctl enable --now`) when it isn't running, so the mesh comes back after a reboot; enabled when it runs but isn't.
- **splot never sets an address or a route itself:** wg-quick sets them, and only when it starts. Apply compares what's live on `spl_mesh` (its address, its routes besides the kernel's own) with what wg-quick would set from the file: each peer's allowed IP that the address's network doesn't cover, i.e. the networks behind the other nodes. Different (a new node or zone, a changed `meshIp`): `systemctl restart`, saying why, and the tunnels drop for a moment. The same: `systemctl reload`, the unit's `wg syncconf`, and they stay up (a new client, a PSK, an endpoint).
  - So what's live is always wg-quick's own: a bug in splot's idea of the routes shows as a restart at every apply, never as a route that's missing until the next reboot.
  - Rejected: adding and removing routes by hand (no drop, but apply-time and boot-time routes could differ); restarting at every change (adding a phone would drop every tunnel).
- **An interface up some other way** (`wg-quick up` by hand) is refused: the unit couldn't start over it.

### Linux: the firewall with nftables

splot's firewall on a Linux node is a table of its own, `inet splot`, which it renders as one nft file (decided):

- **Its own table, its own base chains** (input, forward, output; nat prerouting and postrouting), each `policy accept`. On one hook every table's base chains see a packet: an `accept` ends only the chain it's in, a `drop` is final. So splot's chains let what isn't splot's pass by their policy, and end what is (see "Firewall default policy") in a verdict of splot's own rules: splot's drops hold whatever the operator's tables say (the host's own, Podman's netavark), and its accepts let through only what no other table drops. splot never touches another table, nor runs `flush ruleset`.
  - Rejected: chains in the operator's table that it jumps to (a jump can't leave its table): splot would edit a table it doesn't own, and the operator's file would fail to load without splot's chains, as it does after a `flush ruleset` (Debian's `nftables.service` reloads with one).
- **Replaced in one transaction:** the file makes the table if it isn't there, deletes it and writes it again (`table inet splot`, `delete table inet splot`, then the table), so `nft -f` swaps it whole, whether it was there or not.
- **A zone is its interfaces** (`platform.interfaces`), the mesh zone splot's mesh interface, matched by name (`iifname`, `oifname`), so the rules load before an interface is up. In the `inet` family, what's matched by interface alone (the mesh zone's input, the deny) covers IPv6 too.
- **What fw4 does, written out:** replies (`established,related`) accepted first; the peers' ping, the listen port and the rules to the node itself in input, then the mesh zone's drop; the rules through the node in forward, then the mesh zone's own drop and splot's deny, a rule for each crossing it covers; the mesh zone's output accept. One rule per protocol, TCP and UDP by port, ICMP whole, as fw4 takes a service's protocols. A set holds no address another of its addresses covers. No match is ever left out, which would match anything: an empty set is `{ }`, which nft refuses.
- **Port forwards:** DNAT from the WAN's interfaces, one rule whatever the number of `wan.sources` (nft takes a set), and an accept of each in forward (`ct status dnat`), which matters only where the WAN comes in on a zone's interface: there splot's deny would drop it. Into the mesh, the SNAT to the node's `meshIp` matches only what was forwarded (`ct status dnat`, which nft can match and fw4's uci can't), so the node's own networks keep their address.
  - Rejected: matching what fw4 matches, for the same side effect on both platforms.
- **Labels** are `#` comments in the file, in the config's notation (`in: Barn ssh, from spl_mesh`): nft's rule comments take at most 128 characters, and a name has no limit.
- **Loaded by a unit of splot's own** (decided), `splot-firewall.service`: oneshot, before `network-pre.target`, `nft -f /etc/splot/firewall.nft` to start and to reload; stopping it deletes splot's table alone. Started and enabled (`systemctl enable --now`) when it isn't running, so the table is back at boot before an interface is up; reloaded when the file changed, or when the table isn't loaded (a `flush ruleset` removed it), saying why. The same file with the table loaded changes nothing. `nft -c` checks the file at the dry run and at the prepare, so a file nft refuses stops the run before any go.
  - Rejected: the operator including the file (forgotten, the mesh comes back unfiltered, and splot can't tell).
- **A `flush ruleset` removes it too**, and Debian's `nftables.service` starts and reloads with one: splot's unit loads after that one, and is restarted and reloaded with it (`PartOf`, `ReloadPropagatedFrom`). Starting that one when it wasn't running (a start doesn't reach a unit that's running), or a file loaded by hand that flushes, leaves the node without splot's table until the next apply, or `systemctl reload splot-firewall`.
- **Live first, put back last:** the go loads the table before the WireGuard changes, so the mesh comes up, or changes, behind the rules meant for it. A run keeps both files and whether the unit ran and was enabled, and puts the WireGuard back first.
- **The dry run warns about other tables** whose base chains drop what they don't accept (`policy drop`, in the `ip`, `ip6` and `inet` families, from `nft -j list chains`): what splot accepts on that hook gets through only where that chain accepts it too (Docker's `FORWARD`, a host's own input chain). Warnings, not errors, as on OpenWrt.

### Tags

Tags are the sole access control abstraction. They appear in `allowFrom` on services. They can be applied to nodes, zones, devices, hubs, hub clients, and global clients.

### Implicit name-tags and uniqueness

Every named thing has an implicit tag equal to its name. The namespace scope depends on what kind of thing it is.

**Globally-scoped** (bare name in `allowFrom` works):

- Node names
- Global client names (`config.clients`)
- Explicit tag names

These three share one global namespace. Names must be unique across the entire config — no collisions between any of them.

**Per-node-scoped** (must be referenced as `{NodeName}.{LocalName}`):

- Zone names
- Device names
- Hub client names

All three share one flat per-node namespace — within a single node, names across all three kinds must be unique. They can recur freely across nodes (`Home` and `Cabin` can both have a `printer` and a `lan`). What splot itself names inside a node carries a `$`, which no name can hold, so it takes no name from the operator: `{NodeName}.$hub` (the node's hub network) and `{NodeName}.$node` (the node itself). `$` marks a word of splot's rather than a name the operator chose: the hub is written in the config (`hub:`), but splot names it, as it names the node itself.

A bare name in `allowFrom` resolves only against the global namespace. To reference anything inside a node, qualify it with the node name.

### Tag resolution

A reference in `allowFrom` is one of:

- **Bare name** — globally-scoped: explicit tag, node, or global client
- **Qualified `{NodeName}.{LocalName}`** — anything inside a node (zone, device, or hub client)
- **`{NodeName}.$hub`** — that node's hub network
- **`{NodeName}.$node`** — that node itself, named from anywhere
- **`$node`** — the node the rule is on; context-dependent (resolves differently per router being configured)

Resolution always produces a set of IPs or subnets — never zone names. Zone names are tracked separately on the resolved IPs and used to scope generated firewall rules.

| Reference                                | Resolves to                                                              |
| ---------------------------------------- | ------------------------------------------------------------------------ |
| Explicit tag (e.g. `admin`)              | All IPs/subnets of things tagged with it (across the whole config)       |
| Node name (e.g. `Home`)                  | Union of Home's `zones` subnets and its hub network                      |
| Global client name (e.g. `Pixel8`)       | All of the client's known IPs                                            |
| `{Node}.{Zone}` (e.g. `Home.lan`)        | That zone's subnet                                                       |
| `{Node}.{Device}` (e.g. `Home.printer`)  | The device's IP                                                          |
| `{Node}.$hub` (e.g. `Home.$hub`)         | The node's hub network                                                   |
| `{Node}.{HubClient}`                     | The hub client's IP                                                      |
| `{Node}.$node` (e.g. `Home.$node`)       | The node itself: its `meshIp` and its own address on each of its `zones` |
| `$node`                                  | The same, for the node the rule is on                                    |

**Subnets vs IPs.** Bare/qualified node-name forms (`Home`, `Home.lan`) resolve to *subnets* — broad, "any device on those networks." `Home.$node` and `$node` resolve to *IPs* — narrow, "the node itself as a host." These are complementary, not interchangeable.

**A node itself as a source** (decided):

- What a node sends itself, rather than forwards, leaves over the mesh from its `meshIp`: neither netifd nor wg-quick gives a route a preferred source. `Home`, its networks, doesn't cover that address. `Home.$node` does: the narrow form, for a flow like a reverse proxy on the node reaching one service elsewhere, or its DNS forwarding to another node's.
- It covers the node's address on each zone too, for a program bound to one: the same set `$node` names on that node.
- On the node itself it needs no rule: what a node sends leaves through its output, which splot doesn't filter. So `$node` gets no rule anywhere; elsewhere a node itself arrives from the mesh zone.
- `$` marks a keyword of splot's: a name can't hold one, so it can't clash with a zone or device, and nothing is reserved.
- Rejected:
  - `Home` covering its `meshIp`. It would grant nothing new (a node can already send from any address of its site, and WireGuard takes it), but `Home` would stop meaning the site's networks alone, and "only the node itself" couldn't be said.
  - A reserved local name (`Home.self`), which a device could already have.

### Zones

Zones are first-class in the config (under each node's `zones` map). They represent the downstream networks the router serves; the operator configures them in OpenWRT, and splot decides what may cross between them (see "Trust model").

Beyond user-declared zones, splot also creates and manages one zone of its own: the mesh interface's (`spl_mesh`). Everything that arrives over WireGuard is in it — other nodes, global clients, and hub clients. It defaults to `input` and `forward` `DROP` (and `output ACCEPT`); access is granted only via explicit service rules. One exception, by default: every WireGuard peer of the node (other nodes, global clients, hub clients) may ping the node's own mesh IP, echo request only, from the peer's own address, to the router itself and never forwarded. It's how the health check of an apply probes the peers.

Generated firewall rules are scoped per-zone in both `src` and `dest`: one rule per flow and zone its sources arrive in, with that zone in `src` and only that zone's IPs in `src_ip`. On a node a source is in one of its own zones, or else in the mesh zone: everything that comes over WireGuard (global clients, its hub, the networks behind other nodes). `dest` is the zone of the host the service is on, the mesh for a host behind another node or a global client's `meshIp`, or none for the router itself (its input). No rule for:

- sources in the destination's own zone: that traffic never passes the node (see "Trust model");
- the router's own zones toward the router itself: that input is the operator's, so `allowFrom` on a node's own service governs what comes over the mesh;
- `$node`, and a node itself on that node (`Home.$node` on Home): what the node sends leaves through its output, which splot doesn't filter (the mesh zone's output is ACCEPT).

### Trust model

splot manages **every routed access between zones**, at one site and over the mesh alike, through `services` and `allowFrom`. Whether a source is local or across the mesh changes where a rule goes, never what `allowFrom` means.

- Rejected: splot managing the mesh alone, with access between a site's own VLANs set by hand on its router. The policy would live in two places, and what `allowFrom` means would depend on where the source happens to be.
- **A zone is the smallest thing splot enforces.** A zone is one subnet, one L2 segment: inside it everything reaches everything, and that traffic never passes the router. So the sources in a destination's own zone get no rule, on purpose (it would never match). A device that needs protecting from its neighbours needs a zone of its own.
- **What splot controls must pass a box it manages.** Mesh traffic always does (it goes through the node's WireGuard), so splot enforces mesh access even on a node that isn't its site's gateway. Traffic between zones does only where the node is those zones' gateway: switches stay L2-only, never routing between VLANs.
- **Who owns what:**
  - The operator: VLANs, switch ports, access points; internet access per zone, NAT, PPPoE; DHCP pools; the WAN zone, zones `splot.yml` doesn't declare, and router input from its own zones (DHCP, DNS, LuCI, ssh from the LAN).
  - splot: access between its zones, local and over the mesh, **and the default deny between them**; the mesh (sites, global clients, hub clients); static leases; DNS records; port forwards.
  - Where the base policy between zones isn't a deny, `allowFrom` means nothing. That's why splot owns it instead of trusting the operator's setup.
- **No VLAN IDs in `splot.yml`:** nothing splot generates depends on one, and a VLAN ID is local to its site (zones are per node; zone `tags` group them across sites, `iot`). A zone's key is splot's name for it; the platform object it stands for goes with the node's platform: on OpenWrt the firewall zone of the same name, so it needs no mapping; on Linux the interfaces `platform.interfaces` names (see "Node platform"); for an OPNsense interface, where the mapping lives is open. Revisit only if splot ever creates networks: not planned, since an L2 mistake on a remote box loses access to it.
- **No L2 across the mesh:** splot routes between distinct subnets (subnets must be unique), never bridges one across.

### Firewall default policy

The same `splot.yml` must behave the same on every backend, so splot never relies on a platform's default (fw4's `defaults`, an nft base chain's policy, OPNsense's "allow LAN to any").

- **A node's splot zones:** the mesh zone, and every zone `splot.yml` declares for that node.
- **splot owns** the mesh zone entirely (input, output, forward), and forwarding between every pair of splot zones, both ways.
- **Every such packet ends in an explicit splot verdict:** accepted by a rule a service grants, else denied by splot's own deny. The plan's firewall section carries the node's splot zones and that verdict; each backend renders it as explicit rules: fw4 zone policies plus catch-all deny rules after splot's accepts (whatever leaves the mesh zone, and from each declared zone into the mesh and into every other declared zone); nftables chains that end in an explicit verdict; OPNsense block rules after splot's. The OPNsense backend warns about broad pass rules ("allow LAN to any").
- **The deny is DROP:** forbidden traffic gets no answer, so a compromised device can't sweep the network quickly. What REJECT would tell a debugging operator comes from logging splot's denies instead (planned; the deny action may become configurable there, DROP by default, the same on every backend). An audit mode (log and accept) is a variant of it.
- **Left alone:** traffic to or from the WAN zone or a zone `splot.yml` doesn't declare (internet access, NAT, guest networks kept outside splot), and router input from the operator's zones. The exceptions are splot's own: anything leaving the mesh zone (mesh → WAN included), the forwards `wan.via` asks for, and the WireGuard listen port on the WAN of a node others dial (it belongs to splot's interface, as a forward belongs to a service).
- **ICMP:**
  - Echo (ping) between splot zones is denied like any other flow: a ping sweep is how mapping a network starts, which is what DROP is meant to slow down.
  - Return traffic is accepted explicitly (`established,related`), so the ICMP errors of an allowed connection (path MTU's "fragmentation needed", "unreachable", traceroute's "time exceeded") always pass. fw4's base chains do it already; nftables and OPNsense get it written out, for determinism.
  - Allowed by default: every WireGuard peer of a node may ping the node's mesh IP (see "Zones").
  - Open: how to allow other pings. Not as services (a service without a port makes sense only for ICMP); a dedicated option, its shape undecided.
- **What follows:**
  - No internet through the mesh: mesh → WAN is denied. A declared exit for clients is planned.
  - The operator's fw4 `forwarding` sections between splot zones stop working: fw4 checks rules before forwardings, so splot's deny wins. The flows they carried become services (`allowFrom: Home.lan`, explicit accepts), never a deny left out.
  - The operator's rules there decide before splot's: fw4 takes the file's rules in order, and splot's come last. One that accepts lets through what no service grants; one that drops or rejects stops what a service grants. Either way they go, their flows declared as services.
  - The dry run warns about both (every apply's plan is one): the agent has only the node's own firewall, which `splot check` can't see.
  - Switching it on stops every undeclared flow at once: a site moves over with `firewall: none` first (see "Node platform"), later with splot's deny logs.
  - A node that isn't its zones' gateway enforces only what passes through it.
- **Where it stands (OpenWrt; on Linux see "Linux: the firewall with nftables"):** splot owns the mesh zone as zone policies (its input `DROP`, its output `ACCEPT`), accepts what services grant, and denies the rest with rules of its own:
  - fw4 applies a zone's `forward` policy only within the zone, so the deny is rules: one for whatever leaves the mesh zone (`dest '*'`, the WAN included), and one from each declared zone into the mesh and into every other declared zone. They match every protocol (`proto all`: without one fw4 matches TCP and UDP alone). fw4 puts each in its source zone's forward chain, in the file's order, and the agent keeps splot's sections in plan order, so they come after splot's accepts.
  - fw4's base chains accept `established,related` already.
  - Into the mesh from the WAN or an undeclared zone gets no deny ("Left alone"), and couldn't: fw4 accepts a zone's port forwards (`ct status dnat`) after the zone's rules, so a deny there would drop the forwards `wan.via` asks for.
  - The dry run warns about the operator's sections where splot decides. splot sends the agent what it owns (`Rendered.owned`, from the same list the deny rules come from): each crossing the deny drops, and the node's input from the mesh zone. The agent finds, in the node's firewall file, each of the operator's sections fw4 takes (`enabled`, as fw4 reads it) that overlaps one: a forwarding (from one zone, it forwards nothing there any more; from any zone, `*`, fw4 puts it in the forward chain ahead of every zone's, so it accepts first), and a rule with a verdict (`ACCEPT`, `DROP`, `REJECT`, read as fw4 reads a target; a rule without one only counts). Warnings, not errors, and apart from the changes: one added between the plan and the prepare doesn't stop the run. Not warned about: the operator's output rules toward the mesh zone, and redirects.

### Forwarding rules (forwardTo)

`forwardTo` was dropped entirely. It expressed broad zone-to-zone access, which is anti-zero-trust. All access control goes through `services` with explicit `allowFrom`, port, and protocol. No broad subnet or zone access is allowed by default.

### Services

The only mechanism for access control. Each service declares:

- `port` — port number or range (string). `"external:internal"` form translates ports for WAN forwards; bare `"22"` means same external/internal.
- `proto` — `tcp`, `udp`, or array (`OneOrMany`)
- `allowFrom` — optional; one or more tag/name references granting LAN/mesh access
- `wan` — optional; declares WAN exposure on listed routers (see below)

A service must grant access in at least one direction — either `allowFrom` or `wan` must be set. Otherwise the service declaration is operationally meaningless (a warning).

Services can be declared at multiple levels: on a node (router-hosted), on a device, on a hub client, or on a global client.

**A global client's services** (decided) are reached at its `meshIp` and at each of its zone IPs: away through its tunnel, at home (the tunnel off) on its zone.

- The `meshIp` is on no node. The client is a peer on every node, so each node sends what's behind it (its zones, its hub) straight there, and lets out those of them `allowFrom` names, over the mesh. No node lets anything in for it.
- So each node is the only gate between what's behind it and the client: a node that leaves its firewall or its WireGuard alone lets its sources through as the operator's own rules do, and its warning names every service at a client's `meshIp` that lets anyone in.
- Another global client has no path to it: a client's profile (planned) routes each node's own networks, so no node relays between clients, and none lets one out there.
- Rejected: the zone IPs alone (a client away from its zones couldn't be reached, though it sends keepalives so that it can be, and its WAN forwards go to its `meshIp`); the `meshIp` alone when it has one, as `wan.via` picks (at home with the tunnel off it couldn't be reached).

### WAN exposure

Port forwarding is expressed *on the service itself*, not as a separate top-level construct. The principle: a service is the single source of truth — port, protocol, and exposure decisions live in one place.

```yaml
wan:
  via: [HomeRouter]                       # list of routers that expose this service via their wanZone
  sources: ["1.2.3.4/32"]         # optional; CIDR-only allowlist. Empty/missing = publicly accessible
```

Key design points:

- **WAN is binary at the splot level**: either a service is publicly exposed (with optional CIDR restriction) or it isn't. There's no middle ground using splot identifiers, because no internal identifier has a meaningful WAN-side equivalent.
- **`sources` is CIDR-only**, not splot identifiers. Reason: splot identifiers resolve to internal addresses; nothing in the config has meaningful WAN-side semantics. Real WAN allowlists (office IP, partner CIDRs, webhook source ranges) are always arbitrary public CIDRs.
- **`allowFrom` and `wan.sources` serve different planes**: `allowFrom` controls LAN/mesh accept rules using splot identifiers; `wan.sources` restricts WAN-side sources using raw CIDRs. Distinct names so operators can't confuse the two.
- **`wan.via` takes explicit node names, never `$node` or other shortcuts**: the security cost of an operator misunderstanding a shortcut (and mass-exposing a service) outweighs the few characters saved. The one exception: for **global-client services**, an entry may be qualified as `{Node}.{Network}` to pick which of the client's networks on that node to forward to. The qualified form is client-only — using it on a node/device/hub-client service is a validation error, since those hosts have a single unambiguous address.
- **Cross-node WAN exposure**: any `wan.via` node can forward a service it reaches over the mesh (a device or a node at another site, a hub client, a global client's `meshIp`). No change to the host's own config.
- **A forward into the mesh goes as the entry node** (decided): to a host it reaches over the mesh, the entry node sends the forward from its own `meshIp`, and the host's node lets that address in: a rule of its own for each entry node (named after it, as `wan.via` does). A global client's `meshIp` has no node in between, nor has the entry node's own hub client: nothing to let in there.
  - Why: WireGuard takes from a peer only that peer's addresses, so the internet's address would be dropped at the far end of the tunnel; and the host would answer it by its own default route.
  - The cost: the host sees the entry node, not who's asking. Who may come is said on the WAN side, with `wan.sources`.
  - The host's node lets the forward in whatever the entry node's platform: the config says the service is forwarded there. Where the entry node leaves its firewall alone, the operator forwards it, from the `meshIp`; where the host's node leaves its firewall or WireGuard alone, its warning names the service.
  - On OpenWrt, a `nat` section beside each redirect, one per WAN source as the redirects are, in the mesh zone's srcnat chain. fw4 can't match only what it forwarded (a `nat` section has no `ct status` match, and no `extra`), so it matches what leaves through the mesh zone to the target's address and port, from the forward's WAN source. A forward from anywhere sends the entry node's own networks reaching that service over the mesh as the node too: the host sees the node for them as well, and the node's rules still decide whether they may go, so nothing new gets through. fw4's NAT reflection does the same for sources in the mesh.
  - Rejected: routing the replies back (policy routing): WireGuard drops the request before. A rule that marks the forward and a `nat` that matches the mark: exact, but it takes a mark bit mwan3 or pbr may use, and two sections per forward. A raw nft include matching `ct status dnat`: exact, but a file outside uci, which a run's backup and rollback don't cover.
- **Splot does not manage the WAN zone in OpenWRT** — the operator owns its declaration. Splot just references it by name via `node.wanZone`.
- **On OpenWrt, one redirect per source** (decided): fw4 takes a single `src_ip` on a redirect and skips a redirect that has a list, so a forward from several `sources` is a redirect for each, the source in its section name (adding one leaves the others as they are). fw4's NAT reflection doesn't read `src_ip`, so it repeats the same reflection rules for each source, which does no harm. The plan keeps the forward whole: how a backend matches several sources is its own business.
  - Rejected: an fw4 `ipset` the redirect matches. One redirect whatever the number of sources, but another section type, a set name in fw4's table, and on 24.10 fw4 drops a redirect's set match in one of its branches (a redirect with no address, which splot never writes), which would let anyone in.

### meshIp

Each node declares its mesh IP explicitly. This is intentional:

- Inserting a new node must not silently change existing nodes' IPs
- Mesh IPs are the addressing substrate the future distributed apply mechanism will run on — they must be stable across config updates
- Auto-assignment from node order in the file was considered and rejected for these reasons

### Hubs

A hub is a network inside `meshNetwork` that a node sets aside for devices reaching the mesh through it alone — typically something behind NAT that offers services (a camera on an LTE modem). Hub clients are peers on the node's mesh interface (same key, same port), not on a separate WireGuard interface. Hubs replaced per-node `vpnInterfaces`.

- **Why no separate interface:** WireGuard drops any packet whose source isn't in the sending peer's `AllowedIPs`, so on one interface the source IP identifies the peer, and splot's IP-based rules are as strong as per-interface zones — provided `AllowedIPs` never overlap.
- **One address, one path:** WireGuard sends to the peer with the longest matching prefix and doesn't check whether that peer is up. Every other node routes the whole hub network to the hub node (it's in that node's peer `AllowedIPs`, even while the hub is empty), so hub networks don't overlap and no `meshIp` lies inside one. A hub network lies inside `meshNetwork`: the mesh is one address space.
- **Hub client vs global client:** a hub client is a peer on its hub node only; a global client with `meshIp` is a peer on every node.
- **Firewall:** everything on a hub arrives over the mesh interface, so it's in splot's mesh zone; rules tell hub clients apart by source IP.
- **References:** hub clients join the node's namespace (`Home.camera`); `Home.$hub` and the hub's `tags` refer to the whole hub network, the way a zone's name and tags do; a bare node name includes it.

### Endpoint

A node's `endpoint` (an IPv4 address or a DNS name) is where the other peers dial it, and nothing else.

- **A node nobody can dial leaves it out:** behind NAT or CGNAT with no port forward, or a public address behind a firewall that drops what comes in. To WireGuard those are the same. Such a node dials the others; they learn its address from its handshake.
- **No security in it:** WireGuard accepts an authenticated packet from any address and moves the peer's endpoint there (roaming). The keys authenticate.
- **What follows:** at least one node needs an endpoint (an error otherwise); a node without one can't host a hub, since hub clients dial their hub node (an error); two nodes without one have no tunnel between them (a warning; relaying through a reachable node is future work).
- **Let in from the WAN:** a node with an endpoint, whose firewall and WireGuard splot manages, gets an input rule: UDP on its `listenPort`, from its `wanZone`, to the node itself, either IP family (whichever a peer dials by; WireGuard answers only a key it has). So such a node needs a `wanZone` (an error otherwise), as a `wan.via` node does. A node without an endpoint gets none: it only dials out, and the replies come back as established traffic.
  - One port, no `external:internal` form: translating on the node's own firewall gives nothing a different `listenPort` doesn't. Where the two differ for real (an upstream router forwarding another port to the node, two nodes behind one public address), peers dial a port that isn't `listenPort`: a property of the endpoint, which gets a port if that comes up.
  - Where splot leaves the firewall alone, the operator lets the port in, and the node's warning says so. With `wireguard: none` the interface and its port are the operator's: no rule, and no `wanZone` needed for it.
- **Names** must resolve through public DNS, never through the mesh. A peer name that doesn't resolve keeps the whole mesh interface down, every peer with it, on OpenWrt and with wg-quick alike.

### Keepalive

A WireGuard keepalive is sent by the host it's set on, to its peers. It keeps that host's NAT mapping open, so whoever connects to it gets through.

- **Off by default** on every node, global client and hub client. On a roaming device a keepalive wakes the radio (battery) and chases stale addresses. Site health is checked by pinging mesh IPs, not by "latest handshake".
- **On only for a host nobody can dial that others connect to**, every `keepaliveInterval` seconds (default 25; `0` turns none on). A host that only dials out needs none: replies to what it starts come back anyway.
  - A node without an `endpoint` always sends them: the other nodes ping its mesh IP (allowed by default), so others always connect to it. A router runs on mains power, so it costs nothing.
  - A global or hub client can't be dialled either; it sends them only if it offers services. That side applies once splot renders client profiles.
- **Only toward the peers a host dials**, the ones with an endpoint. A peer without one (a client, a node nobody can dial) never gets a keepalive in another host's config: it can't be sent to anyway, and that peer decides for itself.
- No per-host setting yet. One is planned for when client profiles exist, mainly to opt a host out.

### DHCP

Where splot manages a node's DHCP, it writes a static lease for each address a host with MACs has on the node's zones: its devices, and the global clients on them.

- **MACs where splot leases** (decided): a device on a node whose DHCP splot manages needs `macs`, and so does a global client with an address on one; a server with a static address too, so the reservation keeps the pool off it. Elsewhere `macs` are optional, and unused ones (`dhcp: none`, or a client on no such node) are a warning.
- **A lease hands out the host's name** as its host name (the name dnsmasq gives the device, and puts into DNS), never a label: the section's own name marks it as splot's.
- **So the name must be a host name** (decided): letters, digits and hyphens, no hyphen at either end, at most 63 characters, case as written. Anything else is a validation error where splot hands the name out (`my_printer` on a node whose DHCP it manages), not mapped: nothing is guessed, and a mapping could make two names one. dnsmasq accepts `_`, but RFC host names, Kea and many clients don't; a name dnsmasq refuses (`[SPLOT] printer` once was) stops its DHCP and DNS altogether.

### Preshared keys

A WireGuard pair can also share a preshared key (PSK). It adds nothing against today's attackers (the keys authenticate both ends), but protects recorded traffic against a future quantum computer breaking the key exchange.

- **On by default for every pair.** A pair has one only when both ends want it: `psk: false` on either end (a node, hub client or global client) turns it off for all of that host's pairs. A PSK must exist on both ends, so one end is enough. For WireGuard clients without a PSK field, or profiles typed in by hand.
- **The default was chosen once:** turning it on later would silently add PSKs to existing pairs, and each such tunnel would stay down until both ends held one.
- **One per pair, never derived from a single mesh secret:** one compromised node would give away every pair's PSK.
- **Kept on the nodes** (the key store, like the private key) and filled in at apply; the plan and what's rendered hold placeholders. Placed by hand at first (`splot psk set --node <Name> <peer>`, from stdin); later the controller generates a missing one and writes it to both ends in the same run.
- **Apply refuses when a pair needs a PSK the node doesn't have.** Rendering the peer without one breaks the promise (and won't handshake if the other end has one); leaving the peer out drops its routes, so that site's traffic would leave by the default route, unencrypted.

---

## Code conventions

- **A Cargo workspace:** each crate lives in `crates/<name>/`. `crates/splot` is splot itself (the binary `splot`): the config, validation, planning and rendering. `crates/splot-agent` is everything that runs on a node: the key stores, the node check, applying and reloading; splot calls it in-process for now. `crates/splot-core` is what they share: the checked types both read, uci's vocabulary, and the protocol between them (`Request`, `Reply`, the rendered payloads). The cut is the rendered config: splot renders, the agent applies, and no secret leaves the node. splot re-exports core's types where its own used to be (`types::identifier`, `model::host::HostRef`), so the config's types are still read from `src/types/`. A source path in this file (`src/types/`) is within its crate; `scripts/` and the docs are at the repository's root.
- **Parse, don't validate:** config values are checked types from `src/types/`, parsed where they enter; the model (`Network`) exists only through `model::validate`, so whatever reads it can rely on the checks.
- **Defaults the config takes** (a key left out) are constants in `src/consts.rs`; serde's default functions return them.
- **Errors** derive `thiserror::Error`; their messages are pinned by snapshot tests (`every_parse_error_message`, `every_error_message`). No panics in production code except `expect`s that can't fail.
- **Secrets** (`WgPrivateKey`, `WgPresharedKey`) are never shown: no `Display`, a redacted `Debug`, the text only through `expose()` where WireGuard needs it. A preshared key can be sent (serde), once: to the node that keeps it (`psk set`). A private key has no serde, so it can't be put in a message: it never leaves its node.
- **Messages to the user say "peer"** for the machine splot runs on, not "router": it runs on Linux hosts too.
- **Modules are private** unless something outside needs them, so dead code shows up as a warning.

---

## Testing

### Scope

Tests cover the **deterministic core**: type parsers (`src/types/`), config parsing (`src/config.rs`), all validator passes and the model they build (`src/model/`: hosts, reference resolution, WAN targets), the planners and the plan's plain-text view (`src/plan/`), the uci renderers (firewall zone/rules/redirects, network, dhcp), UCI command/builder rendering, the wg-quick and nftables renderers, the protocol (what's sent arrives as it was, and is checked again), and in the agent: the secrets filled in, the OS check, and the Linux apply's decisions (what's live, read from `ip -j`, against what wg-quick would set; what systemd does for splot's firewall, and the other tables the dry run warns about, read from `nft -j`). The process/IO layer (the agent's `uci` executor, `wg`, `ip`, `systemctl`, `env`, its `apply`, and splot's `main` and `commands`) is **out of scope** for now — it shells out and touches the filesystem; the container checks cover it. The key stores (the agent's `key_store`) are tested in their pure parts (reading the store, the commands that write it) and in the store file's mode, in a temporary directory. The process helper (the agent's `process`) is tested with standard programs (`cat`, `sh`), not the ones splot drives.

### Placement

Tests are inline `#[cfg(test)] mod tests { use super::*; ... }` modules, always the **last item in the file**. Inline (not a separate `tests/` dir) because this is a binary crate and tests need access to private / `pub(super)` items (validator passes, generator helpers, the `UciSectionBuilder`). Follow `src/types/mac.rs` as the style reference.

### Fixtures

- **Pure type parsers** are driven directly through `FromStr` with a small local `parse()` helper.
- **Config-level tests** build a `Config` from a YAML string via `serde_norway::from_str` — this mirrors real loading and exercises the serde layer too. Shared helpers live in `src/test_support.rs` (`#[cfg(test)]`-only, `pub(crate)`): `config()`, `report()`, `checked()` (a fixture that must pass validation, as the `Network` the generators take), and `has_error` / `has_warning` / `error_at` matchers. The matchers take closures because `ValidationError` / `ValidationWarning` don't derive `PartialEq` — match on the variant with `matches!(..)`.

### Snapshots

`example_config_snapshot` (in `src/backend/openwrt/mod.rs`) pins the complete uci output the OpenWrt backend renders for every node of `splot.example.yml`, and after it what splot owns in the firewall (where the dry run warns about the operator's sections), using [`insta`](https://insta.rs). Snapshot files live in `src/backend/openwrt/snapshots/` and are committed. They record what splot generates today, known-wrong parts included.

- **Any change to generator output fails this test on purpose.** Insta prints the line diff of the generated config; the diff is the review: "is this the config change I meant?"
- **Accept an intended change** with `cargo insta review` (needs `cargo install cargo-insta`), or `INSTA_UPDATE=always cargo test` and then review the `.snap` diff in git. Never accept a snapshot change you haven't read.
- **A change that touches generator output** comes with its snapshot diff in the same commit, so the commit shows what it does to the generated router config.
- Keep the example config representative: a new feature that generates config should appear in `splot.example.yml`, which puts it under the snapshot too.

`example_config_snapshot` in `src/backend/linux/mod.rs` does the same for the Linux backend: the wg-quick file of every Linux node of the example, secrets as placeholders, and its nft file. Its snapshots live in `src/backend/linux/snapshots/`.

`example_plan_snapshot` (in `src/plan/mod.rs`) pins the node plan, the platform-neutral layer between the model and the renderers, as its plain-text view, for every node of `splot.example.yml`. Its snapshots live in `src/plan/snapshots/`.

- **A planner change** (what a node should do) shows up in the plan snapshot and in the uci snapshot. Read the plan diff first: it says what was decided, in config notation.
- **A rendering-only change** (how uci spells it) leaves the plan snapshot untouched and shows up in the uci snapshot alone, which proves the decision didn't move.
- The view holds every piece of information the plan carries: a new plan field goes into it.

### Conventions

- **Iteration order is deterministic** — config collections are `BTreeMap`/`BTreeSet`, so walking the config (and with it validation output and generated UCI) happens in sorted key order, and tests may assert positional order. The `HashMap`/`HashSet` left in the validator are lookup-only; don't iterate them into output. Where order isn't what a test is about, a predicate-style assertion ("contains an item matching …") is still the sturdier choice. The builder sorts list values (`extend_list`), and an empty list emits no line — which is how "no `wan.sources` ⇒ public" is pinned down.
- **Sorted order can hide order-dependent bugs.** When a check compares items against each other (name collisions, shadowing, overlaps), a fixture that only works because of how its names sort proves nothing — cover both orderings (e.g. the conflicting name sorting before *and* after the thing it collides with).
- **A test must be able to fail.** Avoid fixtures where the asserted name/value can't occur — a check against something absent from the fixture passes vacuously and proves nothing. When a test guards a filter, assert both the positive (expected thing appears) and the negative (the wrong thing is absent), ideally in both generation directions.
- **Use generic placeholder names** in fixtures — `Home`, `Cabin`, `Phone`, and obviously-fake endpoints (`1.2.3.4`) and keys. Public keys are validated, so a fake must still be well-formed: 42 × one letter + `A=` (`AAAA…AAA=`, `BBBB…BBA=`), a different letter per entity since keys must be unique. Never real deployment names, keys, or endpoints; real config lives only in the git-ignored `splot.yml`.

### Verify

`cargo test`, `cargo fmt --check`, and `cargo clippy -- -D warnings` all stay clean. Sanity-check a new test by temporarily inverting the condition it guards — if it still passes, it isn't testing what it claims. `scripts/mutate.py FILE OLD NEW` does that one mutation at a time: it swaps one exact snippet, runs the tests, says which failed, and restores the file. A mutation no test fails on means a missing test; one that doesn't compile proves nothing, so rewrite it until it does.

**The agent per CPU:** `scripts/dist.sh` builds `splot-agent` for every CPU splot supports (the Rust targets it names, `rustup target add`), checks each stays under 1 MB and answers a request (under qemu-user for another CPU, when it's installed). Run it when a change touches the agent or its dependencies.

When dependencies change, `cargo audit` (RustSec advisory database) must report no advisories. It exits 0 even for "unsound"/"unmaintained" warnings, so read its output rather than the exit code.

**Against real OpenWrt:** unit tests check the generators against splot's own assumptions; `scripts/openwrt-check.sh [VERSION...]` checks them against OpenWrt. It boots an OpenWrt container per version (default: the versions in use) and runs splot here, as an operator would, carrying the x86_64 agent and reaching the router over ssh (dropbear, with a key and an ssh config of the check's own; it comes in on the router's loopback, which fw4 always lets in: pasta splices what this machine sends a published port) as node Home of `splot.example.yml`. It asks OpenWrt's own tools: `fw4 check` (every section accepted, not skipped), the live ruleset (each rule in the chain its zones put it in: the router's own in the mesh zone's input, what crosses it in its source zone's forward; splot's deny in each zone's forward chain, after its accepts, with the test router's second zone, `iot`; the WAN letting the listen port in; a port forward from each of its WAN sources, and from nowhere else; a forward into the mesh sent as the router's mesh IP, its SNAT in the mesh zone's srcnat chain), the dry run's warning about a forwarding `lan` → `spl_mesh` and a rule accepting `iot` → `lan` added by hand (and none about the router's stock sections), `dnsmasq --test` and dnsmasq running, WireGuard interfaces up with their peers and address, no errors in the log, a second apply that stages nothing, leaves the files untouched and begins no run (its dry run says so too), a peer change that stages only that peer, and the update reaching WireGuard (live where the version supports renew). Cut off after an apply (the ssh wrapper fails every later session), the router puts back what it had by itself at the deadline; splot waits for it, and, let in again, reaches it and says it put back by itself. A ruleset nft refuses (an include added by hand jumps from a filter chain to the WAN's dstnat chain, which nft refuses once splot's port forwards put their dnat there) fails the apply, and the router puts it back on the spot. The checks after a confirm don't wait: the go made the change live. For the key store: before `splot init` the dry run asks for it and writes nothing; `init` creates the key once, then finds the node initialised and refuses another node's key and a key the config doesn't have; a command as another node, or as one the config doesn't have, refuses and writes nothing; the store is readable by root only. For preshared keys: apply refuses before they're stored, `splot psk set` refuses what it must, WireGuard ends up with each pair's stored PSK, and a PSK change is staged alone, masked in the dry run. For concerns left alone: with `firewall: none` and `dhcp: none`, apply leaves both files untouched, splot's earlier sections included; with `wireguard: none`, apply refuses as a node whose key none of the interfaces has, and applies as the one whose key `spl_mesh` has, leaving the network file alone. Over ssh: what comes back here holds no key of the router's (the dry run shows placeholders), and no agent is left in the router's `/tmp`. Run it when a change touches generated config, the apply/reload path, the agent or the session. Needs podman, ssh, the Rust target `x86_64-unknown-linux-musl`, and the host's `wireguard` kernel module (`sudo modprobe wireguard`). The container workarounds (IPv4 package downloads, AppArmor, ujail, a DHCP WAN) and the router's `iot` zone are explained in `scripts/openwrt/prepare.sh`; the check brings the LAN up itself (its bridge's port isn't in the container), since fw4 takes a port forward's NAT reflection from the LAN's address.

**Across a mesh:** `scripts/mesh-check.sh [VERSION]` boots two OpenWrt routers, Home and Cabin (and later a Linux node, Barn), with a real tunnel between them (each publishes its WireGuard port on this machine's loopback, which the other reaches at its gateway's address: pasta's `--map-gw`; no rule of the check's own lets it in on the WAN, only splot's, though the tunnel doesn't depend on it: both routers dial, and each one's handshakes let the other's in as replies), and runs splot here over ssh to both, at their `platform.ssh`. It checks: both applied and confirmed, each answering the other's ping on its mesh IP; a change that keeps the tunnel (a new phone on Home) checked against Cabin and confirmed; a preshared key changed on Home's end only, which gets a fresh session that fails, so Home loses Cabin and puts back what it had by itself, and the tunnel works again. Across the mesh (both at once): without a terminal or `--yes` it refuses before anything; the dry run shows each router's plan; a preshared key changed on both ends in one run is confirmed, the tunnel up with it; a change that cuts the routers off from each other puts both back; a router that can't prepare (uncommitted uci changes) cancels the other, nothing applied; and when splot loses a router after the go (the ssh wrapper fails its later sessions), the other is put back, and the lost one, waited for until its deadline, has put back by itself. Then a Linux node, Barn (Debian with wg-quick, its firewall splot's nft table, reached over ssh too), joins: every node's peer list changes in one run, all three confirmed, each pair answering pings through Barn's firewall; and with Home and Cabin cut off from each other, every node is put back, Barn's wg-quick file too. Then a node itself as a source: Cabin drops Home's connection to its ssh, at its mesh IP, until a service lets in `Home.$node`, and then still drops Barn's; and Barn's nft table the same, Cabin's connection still dropped there. Then a session the other end dropped: Home's mesh interface restarts while Cabin holds a fresh session with it, and a run on Cabin alone still checks Home (its probe waits for WireGuard's new handshake). Last, a port forward from Home's WAN into the mesh: this machine logs in to Cabin's ssh at a port Home publishes (Home's pasta doesn't splice what this machine sends into the router's loopback, `--no-splice`, so it comes in on the WAN, as from the internet; Home's ssh too, which the test router's own WAN rule lets in), and Cabin sees Home's mesh IP as the client. Run it when a change touches the apply's checks, the run, or what a node needs from its peers.

**Against real Linux:** `scripts/linux-check.sh` does the same for the Linux backend. It boots a Debian container with systemd and sshd, and runs splot here, carrying the x86_64 agent and reaching the container over ssh at its `platform.ssh` (a key and an ssh config of the check's own), as node Barn of `splot.example.yml`, its DHCP set to `none` (its firewall too, until the firewall's own checks), and checks: apply refuses the DHCP splot can't manage there yet; before `init` the dry run asks for it and writes nothing; `init` as an OpenWrt node refuses; the key store and the wg-quick file are readable by root only, the keys in the file; apply refuses while PSKs are missing; the first apply starts and enables `wg-quick@spl_mesh`, with every peer, the address, each pair's PSK and wg-quick's routes; a second apply changes nothing; a peer change and a PSK change are reloaded live (the interface kept), and a new zone restarts it, saying why; cut off after an apply (the ssh wrapper fails every later session), the node puts back what it had by itself at the deadline, the unit running as before, and splot, waiting for the deadline and still cut off, says it's still unreachable; a stopped unit is started, a disabled one enabled, and an interface brought up by hand refused. Then the firewall, beside two tables of the operator's (one drops what it doesn't forward, as Docker's does): the dry run shows the nft file and the unit's start, warns about that table, and writes nothing; cut off after the first apply, the node puts back what it had, no table, unit or file of splot's; applied, the file (0600) and splot's unit are written, the unit started and enabled, the table loaded as nft makes it of the file (loaded again in a network namespace of its own to compare), the operator's tables untouched, handles included; a second apply changes nothing, the table not even loaded again; a changed service is loaded again, the WireGuard untouched; a table removed by hand is loaded again, the dry run saying why; cut off after a change, the node loads the table it had. splot on the node itself (`--local`, splot keeping the deadline) applies and confirms; after a reboot the mesh is back as splot left it, and splot's table too, loaded after `nftables.service`'s `flush ruleset`, and again when that one reloads; nothing logged as an error by either unit; no agent is left in the node's `/tmp`. Run it when a change touches the Linux backend, the agent or the run. It needs what the OpenWrt check needs.
