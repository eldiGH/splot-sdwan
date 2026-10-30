#!/usr/bin/env bash
# Checks splot across a mesh: two OpenWrt routers, Home and Cabin, in containers
# with a real WireGuard tunnel between them. splot runs here and reaches each
# over ssh. It checks that an apply is confirmed only while the other router
# still answers through the tunnel, and rolled back when the change cuts it off;
# then runs across the mesh, both routers at once: all or nothing; then a Linux
# node, Barn (Debian with wg-quick), joins, and runs across the three; then a
# router itself (`Home.$node`) is let in to a service on the other; a run on a
# node that holds a session the other end dropped still checks that peer; last,
# a port forward from Home's WAN reaches Cabin over the mesh.
#
#   scripts/mesh-check.sh [VERSION]     default: the newest version in use
#
# Needs what scripts/openwrt-check.sh needs. SPLOT_CHECK_KEEP=1 keeps the
# containers (`podman exec -it splot-openwrt-mesh-home sh`).
# Commands in single quotes run in a container; their $ expands there.
# shellcheck disable=SC2016
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION=${1:-25.12.2}
IMAGE=localhost/splot-openwrt:$VERSION
LINUX_IMAGE=localhost/splot-linux:trixie
TARGET=x86_64-unknown-linux-musl
BINARY=target/$TARGET/release/splot
# WireGuard's ports, one per node: published on this machine's loopback.
HOME_PORT=52820
CABIN_PORT=52821
BARN_PORT=52822
# A TCP port on Home's WAN, published like WireGuard's, for a port forward
# from the internet.
FORWARD_PORT=2222

failures=0
pass() { printf '  PASS  %s\n' "$1"; }
fail() {
	printf '  FAIL  %s\n' "$1"
	[ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/          /'
	failures=$((failures + 1))
}

if [ ! -d /sys/module/wireguard ]; then
	echo "The host's wireguard kernel module isn't loaded; run: sudo modprobe wireguard" >&2
	exit 2
fi

echo "Building splot for $TARGET, carrying the agent for it"
cargo build --quiet --package splot-agent --profile agent --target "$TARGET"
rm -rf target/check-agents
mkdir -p target/check-agents
cp "target/$TARGET/agent/splot-agent" target/check-agents/x86_64
SPLOT_AGENTS="$PWD/target/check-agents" cargo build --quiet --package splot --release --target "$TARGET"
podman build --quiet --build-arg "OPENWRT_VERSION=$VERSION" -t "$IMAGE" scripts/openwrt >/dev/null
podman build --quiet -t "$LINUX_IMAGE" scripts/linux >/dev/null

# splot reaches the routers at their platform.ssh, `home` and `cabin`: hosts of
# an ssh config of the check's own, with a key of its own, through an `ssh`
# first on its PATH. While $work/lose-<host> exists, splot loses that host after
# its first session: as if the change had cut it off.
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/bin"
ssh-keygen -q -t ed25519 -N '' -C splot-check -f "$work/key"
cat >"$work/bin/ssh" <<EOF
#!/bin/sh
for arg; do
	lose="$work/lose-\$arg"
	[ -e "\$lose" ] || continue
	sessions=\$(cat "\$lose")
	echo \$((sessions + 1)) >"\$lose"
	if [ "\$sessions" -ge 1 ]; then
		echo "ssh: lost \$arg (the check cuts it off)" >&2
		exit 255
	fi
done
exec $(command -v ssh) -F $work/ssh_config "\$@"
EOF
chmod +x "$work/bin/ssh"
: >"$work/ssh_config"

splot() { PATH="$work/bin:$PATH" "$BINARY" --config "$work/splot.yml" "$@"; }
# The container of node $1 (`home`, `cabin`, `barn`).
container() {
	case $1 in
	barn) echo splot-linux-mesh-barn ;;
	*) echo "splot-openwrt-mesh-$1" ;;
	esac
}
run() { podman exec "$(container "$1")" sh -c "$2"; }

# Lets the check in at node $1 over ssh: a host of its ssh config.
reachable() {
	cat >>"$work/ssh_config" <<EOF
Host $1
	HostName 127.0.0.1
	Port $(podman port "$(container "$1")" 22/tcp | sed 's/.*://')
	User root
	IdentityFile $work/key
	IdentitiesOnly yes
	StrictHostKeyChecking no
	UserKnownHostsFile /dev/null
	LogLevel ERROR

EOF
	for _ in $(seq 30); do
		PATH="$work/bin:$PATH" ssh "$1" true 2>/dev/null && return 0
		sleep 1
	done
	echo "$1: no ssh within 30 s" >&2
	return 1
}

# The names of the nodes' endpoints: this machine, at the container's
# gateway's address, where each node's WireGuard port is published.
ENDPOINTS='home.example.net cabin.example.net barn.example.net'

# Boots router $1 (`home`, `cabin`) with its WireGuard port $2, and lets the
# check in over ssh.
boot() {
	local name=$1 port=$2 container=splot-openwrt-mesh-$1
	podman rm --force --ignore --time 0 "$container" >/dev/null
	# --map-gw: the router reaches this machine's loopback at its gateway's
	# address, and through it the other router's published WireGuard port.
	local network=pasta:-I,eth1,--map-gw forward=()
	# Home takes a port forward on its WAN: what this machine sends its
	# published ports comes in there, from the gateway's address, as from the
	# internet (its ssh too, which prepare.sh's rule lets in). pasta would
	# otherwise splice it into the router's loopback, where no port forward
	# sees it.
	if [ "$name" = home ]; then
		network+=,--no-splice
		forward=(--publish "127.0.0.1::$FORWARD_PORT")
	fi
	podman run --detach --name "$container" --privileged --network "$network" \
		--publish 127.0.0.1::22 --publish "127.0.0.1:$port:$port/udp" "${forward[@]}" "$IMAGE" >/dev/null

	local up=
	for _ in $(seq 60); do
		if [ "$(run "$name" 'ifstatus wan 2>/dev/null | jsonfilter -e @.up' 2>/dev/null)" = true ]; then
			up=1
			break
		fi
		sleep 1
	done
	[ -n "$up" ] || {
		echo "$name: no WAN within 60 s" >&2
		return 1
	}

	podman cp "$work/key.pub" "$container:/etc/dropbear/authorized_keys"
	# The other router's endpoint name is this machine, at the gateway's
	# address. WireGuard's port comes in on the WAN, where only splot's rule
	# lets it in. The tunnel doesn't prove that rule: both routers dial, and
	# each one's handshakes let the other's in as replies.
	run "$name" "chmod 600 /etc/dropbear/authorized_keys
		gateway=\$(ip -4 route show default | awk '{ print \$3 }')
		echo \"\$gateway $ENDPOINTS\" >>/etc/hosts"
	reachable "$name"
}

# Boots Barn, the Linux node: Debian with systemd and wg-quick, its WireGuard
# port published like the routers'.
boot_barn() {
	podman rm --force --ignore --time 0 splot-linux-mesh-barn >/dev/null
	podman run --detach --name splot-linux-mesh-barn --privileged --systemd=always \
		--network pasta:--map-gw --publish 127.0.0.1::22 \
		--publish "127.0.0.1:$BARN_PORT:$BARN_PORT/udp" "$LINUX_IMAGE" >/dev/null

	local state
	for _ in $(seq 60); do
		state=$(run barn 'systemctl is-system-running 2>/dev/null' || true)
		case $state in running | degraded) break ;; esac
		sleep 1
	done
	podman cp "$work/key.pub" splot-linux-mesh-barn:/root/authorized_keys
	run barn "install -d -m 700 /root/.ssh && install -m 600 /root/authorized_keys /root/.ssh/authorized_keys
		gateway=\$(ip -4 route show default | awk '{ print \$3 }')
		echo \"\$gateway $ENDPOINTS\" >>/etc/hosts"
	reachable barn
}

# The mesh, with each router's public key ($1, $2).
mesh() {
	cat <<EOF
meshNetwork: 10.100.0.0/16
nodes:
  Home:
    platform:
      os: openwrt
      dhcp: none
      ssh: home
    publicKey: $1
    endpoint: home.example.net
    listenPort: $HOME_PORT
    meshIp: 10.100.0.1
    wanZone: wan
  Cabin:
    platform:
      os: openwrt
      dhcp: none
      ssh: cabin
    publicKey: $2
    endpoint: cabin.example.net
    listenPort: $CABIN_PORT
    meshIp: 10.100.0.2
    wanZone: wan
EOF
}

echo
echo "== OpenWrt $VERSION: Home and Cabin"
boot home "$HOME_PORT"
boot cabin "$CABIN_PORT"

# Each router gets its key; the pair, a preshared key on both ends.
mesh AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA= >"$work/splot.yml"
splot init --node Home >/dev/null
splot init --node Cabin >/dev/null
home_key=$(run home 'uci get splot.config.private_key | wg pubkey')
cabin_key=$(run cabin 'uci get splot.config.private_key | wg pubkey')
mesh "$home_key" "$cabin_key" >"$work/splot.yml"
psk=$(run home 'wg genpsk')
splot psk set --node Home Cabin <<<"$psk" >/dev/null
splot psk set --node Cabin Home <<<"$psk" >/dev/null

# Both applied: the tunnel comes up, and each router answers the other's ping.
output=$(splot apply --node Cabin --yes 2>&1) || true
output="$output"$'\n'$(splot apply --node Home --yes 2>&1) || true
if [ "$(grep -c '^Confirmed' <<<"$output")" = 2 ] &&
	run home 'ping -c 3 -W 2 10.100.0.2 >/dev/null' && run cabin 'ping -c 3 -W 2 10.100.0.1 >/dev/null'; then
	pass "both applied and confirmed: the tunnel is up, each answers the other's ping"
else
	fail "both applied and confirmed: the tunnel is up, each answers the other's ping" \
		"$output"$'\n'"$(run home 'wg show spl_mesh' 2>&1)"
fi

# A change that keeps the tunnel (a new phone, a peer of Home's): checked
# against Cabin, and confirmed.
cat >>"$work/splot.yml" <<'EOF'
clients:
  Phone:
    publicKey: PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPA=
    meshIp: 10.100.1.10
    psk: false
EOF
output=$(splot apply --node Home --yes 2>&1) || true
if grep -q '^Checked Home: Cabin answers as before$' <<<"$output" && grep -q '^Confirmed' <<<"$output"; then
	pass "a change that keeps the tunnel: Cabin checked, the change confirmed"
else
	fail "a change that keeps the tunnel: Cabin checked, the change confirmed" "$output"
fi

# A preshared key changed on Home's end only: Home's tunnel to Cabin takes a
# fresh session, which fails, so Home puts back what it had, and the tunnel
# works again.
before=$(run home 'md5sum /etc/config/network')
splot psk set --node Home Cabin <<<"$(run home 'wg genpsk')" >/dev/null
output=$(splot apply --node Home --yes 2>&1) && status=0 || status=$?
after=$(run home 'md5sum /etc/config/network')
last=$(run home 'cat /tmp/splot/last' 2>&1) || true
if [ "$status" -ne 0 ] && grep -q '^Checked Home: lost Cabin$' <<<"$output" &&
	grep -q '^  Home  put back$' <<<"$output" &&
	grep -q "the change cut Home off from Cabin, so Home didn't keep it" <<<"$output" &&
	[ "$after" = "$before" ] && grep -q "rolled back" <<<"$last" &&
	run home 'ping -c 3 -W 2 10.100.0.2 >/dev/null'; then
	pass "a preshared key changed on one end: Cabin lost, rolled back, the tunnel works again"
else
	fail "a preshared key changed on one end: Cabin lost, rolled back, the tunnel works again" \
		"exit $status: $output"$'\n'"last: $last"$'\n'"before: $before"$'\n'"after: $after"
fi

# Across the mesh: what each router holds, and whether a run is left there.
held() {
	local file=/etc/config/network
	[ "$1" != barn ] || file=/etc/wireguard/spl_mesh.conf
	run "$1" "md5sum $file; [ ! -e /tmp/splot/run ] || echo 'a run is left'"
}
last() { run "$1" 'cat /tmp/splot/last 2>/dev/null' || true; }

# Without a terminal to ask on, and without --yes, it refuses before it reaches
# any router.
before="$(held home)$(held cabin)"
output=$(splot apply </dev/null 2>&1) && status=0 || status=$?
if [ "$status" -ne 0 ] && grep -q "there's no terminal to ask on: give --yes" <<<"$output" &&
	[ "$(held home)$(held cabin)" = "$before" ]; then
	pass "across the mesh: without a terminal or --yes, refused before anything"
else
	fail "across the mesh: without a terminal or --yes, refused before anything" "exit $status: $output"
fi

# The dry run shows each router's plan: Home holds another preshared key for
# Cabin since the last check put its config back; Cabin doesn't have Phone yet,
# a global client, so a peer of every router.
output=$(splot apply --dry-run 2>&1) || true
if grep -q '^== Cabin: network, firewall$' <<<"$output" && grep -q '^== Home: network$' <<<"$output" &&
	grep -q '^set network.spl_wireguard_spl_mesh_Phone=' <<<"$output" &&
	grep -q "^set network.spl_wireguard_spl_mesh_Cabin.preshared_key='<preshared key>'$" <<<"$output" &&
	[ "$(held home)$(held cabin)" = "$before" ]; then
	pass "across the mesh: the dry run shows each router's plan, changing nothing"
else
	fail "across the mesh: the dry run shows each router's plan, changing nothing" "$output"
fi

# A preshared key changed on both ends: one router alone can't (the other would
# hold the old one), both in one run can.
psk=$(run home 'wg genpsk')
splot psk set --node Home Cabin <<<"$psk" >/dev/null
splot psk set --node Cabin Home <<<"$psk" >/dev/null
output=$(splot apply --yes 2>&1) && status=0 || status=$?
again=$(splot apply --yes 2>&1) || true
if [ "$status" -eq 0 ] && grep -q '^Applied: Cabin, Home$' <<<"$output" &&
	grep -q '^Checked Cabin: Home answers as before$' <<<"$output" &&
	grep -q '^Checked Home: Cabin answers as before$' <<<"$output" &&
	grep -q '^Confirmed: splot reached every node again, and each keeps the change.$' <<<"$output" &&
	[ "$(run home 'wg show spl_mesh preshared-keys' | awk -v peer="$cabin_key" '$1 == peer { print $2 }')" = "$psk" ] &&
	[ "$(run cabin 'wg show spl_mesh preshared-keys' | awk -v peer="$home_key" '$1 == peer { print $2 }')" = "$psk" ] &&
	run home 'ping -c 3 -W 2 10.100.0.2 >/dev/null' && [ "$(tail -1 <<<"$again")" = "Nothing to change." ]; then
	pass "across the mesh: a preshared key changed on both ends, both confirmed, the tunnel up with it"
else
	fail "across the mesh: a preshared key changed on both ends, both confirmed, the tunnel up with it" \
		"exit $status: $output"$'\n'"again: $again"
fi

# Each router dials the other where nothing answers: Cabin, checked first,
# loses Home, so the checks end there, both put back what they had, and the
# tunnel works again.
cp "$work/splot.yml" "$work/splot.yml.good"
sed -i 's/endpoint: home.example.net/endpoint: 192.0.2.1/; s/endpoint: cabin.example.net/endpoint: 192.0.2.2/' "$work/splot.yml"
before="$(held home)$(held cabin)"
output=$(splot apply --yes 2>&1) && status=0 || status=$?
cp "$work/splot.yml.good" "$work/splot.yml"
if [ "$status" -ne 0 ] && grep -q '^Checked Cabin: lost Home$' <<<"$output" &&
	grep -q "^Didn't check Home: no node keeps the change anyway$" <<<"$output" &&
	grep -q '^  Home   put back$' <<<"$output" && grep -q '^  Cabin  put back$' <<<"$output" &&
	grep -q 'the change cut Cabin off from Home, so no node kept it' <<<"$output" &&
	[ "$(held home)$(held cabin)" = "$before" ] &&
	grep -q "rolled back" <<<"$(last home)" && grep -q "rolled back" <<<"$(last cabin)" &&
	run home 'ping -c 3 -W 2 10.100.0.2 >/dev/null'; then
	pass "across the mesh: a change that cuts the routers off from each other, both put back"
else
	fail "across the mesh: a change that cuts the routers off from each other, both put back" \
		"exit $status: $output"$'\n'"home: $(last home)"$'\n'"cabin: $(last cabin)"
fi

# A new client on both; Cabin holds uncommitted uci changes, so it can't
# prepare: Home, prepared, is cancelled, and nothing is applied anywhere.
cat >>"$work/splot.yml" <<'EOF'
  Tablet:
    publicKey: TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTA=
    meshIp: 10.100.1.11
    psk: false
EOF
run cabin 'uci set network.splot_check=interface'
before="$(held home)$(held cabin)"
output=$(splot apply --yes 2>&1) && status=0 || status=$?
run cabin 'uci revert network'
if [ "$status" -ne 0 ] && grep -q "splot couldn't prepare every node as planned, so no node changed anything" <<<"$output" &&
	grep -q '^  Cabin: network already has uncommitted uci changes' <<<"$output" &&
	grep -q '^  Home   nothing applied$' <<<"$output" && grep -q '^  Cabin  nothing to put back$' <<<"$output" &&
	[ "$(held home)$(held cabin)" = "$before" ] && grep -q "cancelled" <<<"$(last home)"; then
	pass "across the mesh: a router that can't prepare, the other cancelled, nothing applied"
else
	fail "across the mesh: a router that can't prepare, the other cancelled, nothing applied" \
		"exit $status: $output"$'\n'"home: $(last home)"
fi

# splot loses Cabin after the go: Home is put back, and Cabin, waited for until
# its deadline, put back what it had by itself.
before_cabin=$(held cabin)
echo 0 >"$work/lose-cabin"
output=$(splot apply --yes --confirm-within 15 2>&1) && status=0 || status=$?
rm "$work/lose-cabin"
if [ "$status" -ne 0 ] && grep -q '^Applied: Cabin, Home$' <<<"$output" && grep -q "^Couldn't check Cabin: " <<<"$output" &&
	grep -q '^  Home   put back$' <<<"$output" &&
	grep -q '^  Cabin  unreachable: waiting for its deadline' <<<"$output" &&
	grep -q '^  Cabin  still unreachable: ' <<<"$output" &&
	[ "$(held cabin)" = "$before_cabin" ] && grep -q "rolled back" <<<"$(last cabin)"; then
	pass "across the mesh: splot loses a router after the go, the other put back, it puts back by itself"
else
	fail "across the mesh: splot loses a router after the go, the other put back, it puts back by itself" \
		"exit $status: $output"$'\n'"cabin: $(last cabin)"
fi

# A Linux node joins: Barn, with a key of its own and a preshared key with
# each router. Every node's peer list changes, in one run. A run checks only
# the tunnels that worked before it, so the new ones are pinged here.
barn() {
	cat <<EOF
  Barn:
    platform:
      os: linux
      wireguard: wg-quick
      firewall: none
      dhcp: none
      dns: none
      ssh: barn
    publicKey: $1
    endpoint: barn.example.net
    listenPort: $BARN_PORT
    meshIp: 10.100.0.4
EOF
}
# The mesh with Barn ($1 its key), and the clients the config has.
with_barn() {
	{
		mesh "$home_key" "$cabin_key"
		barn "$1"
		sed -n '/^clients:/,$p' "$work/splot.yml"
	} >"$work/splot.yml.new"
	mv "$work/splot.yml.new" "$work/splot.yml"
}
# Its setup without the config's warning (Barn leaves its firewall alone): a
# failure there shows in the check after it.
boot_barn
with_barn BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
splot init --node Barn >/dev/null 2>&1
with_barn "$(run barn 'sed -n "s/^private-key //p" /etc/splot/keys | wg pubkey')"
for router in Home Cabin; do
	psk=$(run home 'wg genpsk')
	splot psk set --node "$router" Barn <<<"$psk" >/dev/null 2>&1
	splot psk set --node Barn "$router" <<<"$psk" >/dev/null 2>&1
done
output=$(splot apply --yes 2>&1) && status=0 || status=$?
if [ "$status" -eq 0 ] && grep -q '^Applied: Barn, Cabin, Home$' <<<"$output" &&
	grep -q '^Confirmed: splot reached every node again, and each keeps the change.$' <<<"$output" &&
	run home 'ping -c 3 -W 2 10.100.0.4 >/dev/null' && run cabin 'ping -c 3 -W 2 10.100.0.4 >/dev/null' &&
	run barn 'ping -c 3 -W 2 10.100.0.1 >/dev/null && ping -c 3 -W 2 10.100.0.2 >/dev/null' &&
	run home 'ping -c 3 -W 2 10.100.0.2 >/dev/null'; then
	pass "a Linux node joins: every node's peers in one run, all confirmed, each pair answers"
else
	fail "a Linux node joins: every node's peers in one run, all confirmed, each pair answers" \
		"exit $status: $output"$'\n'"$(run barn 'wg show spl_mesh' 2>&1)"
fi

# Home and Cabin dial each other where nothing answers: Cabin loses Home, so
# every node puts back what it had, the Linux node too. Barn, checked first,
# dials them where nothing answers too, but still reaches both: each got
# Barn's answer to its probe before the run, so WireGuard sends Barn a
# keepalive 10 s later, from where it really is, and Barn's follows it there.
cp "$work/splot.yml" "$work/splot.yml.good"
sed -i 's/endpoint: home.example.net/endpoint: 192.0.2.1/; s/endpoint: cabin.example.net/endpoint: 192.0.2.2/' "$work/splot.yml"
before="$(held home)$(held cabin)$(held barn)"
output=$(splot apply --yes 2>&1) && status=0 || status=$?
cp "$work/splot.yml.good" "$work/splot.yml"
if [ "$status" -ne 0 ] && grep -q '^Checked Cabin: lost Home$' <<<"$output" &&
	grep -q "^Didn't check Home: no node keeps the change anyway$" <<<"$output" &&
	grep -q '^  Barn   put back$' <<<"$output" && grep -q '^  Cabin  put back$' <<<"$output" &&
	grep -q '^  Home   put back$' <<<"$output" &&
	[ "$(held home)$(held cabin)$(held barn)" = "$before" ] &&
	grep -q "rolled back" <<<"$(last barn)" &&
	run home 'ping -c 3 -W 2 10.100.0.2 >/dev/null' && run barn 'ping -c 3 -W 2 10.100.0.1 >/dev/null'; then
	pass "with a Linux node: Home and Cabin cut off from each other, every node put back, Barn too"
else
	fail "with a Linux node: Home and Cabin cut off from each other, every node put back, Barn too" \
		"exit $status: $output"$'\n'"barn: $(last barn)"
fi

# Whether node $1 reaches Cabin's ssh at its mesh IP: dropbear's banner.
# OpenWrt's nc has no timeout, and the router no `timeout`: the shell ends it.
probe_cabin() {
	case $1 in
	barn) run barn 'timeout 4 bash -c "exec 3<>/dev/tcp/10.100.0.2/22 && head -c 7 <&3"' ;;
	*) run "$1" 'sleep 2 | nc 10.100.0.2 22 >/tmp/probe 2>/dev/null & sleep 4; kill $! 2>/dev/null
		head -c 7 /tmp/probe; rm -f /tmp/probe' ;;
	esac
}
reaches_cabin() {
	local banner
	banner=$(probe_cabin "$1" 2>/dev/null) || true
	[[ $banner == SSH-* ]]
}
# A node itself over the mesh: what Home sends comes from its mesh IP, which
# only `Home.$node` names. Cabin drops Home's connection to its ssh until a
# service lets Home itself in, and then still drops Barn's.
dropped_before=
reaches_cabin home || dropped_before=1
sed -i '/^  Cabin:$/,/^  Barn:$/ s/^    wanZone: wan$/&\n    services:\n      ssh: { port: 22, proto: tcp, allowFrom: Home.$node }/' "$work/splot.yml"
output=$(splot apply --node Cabin --yes 2>&1) && status=0 || status=$?
if [ -n "$dropped_before" ] && [ "$status" -eq 0 ] && grep -q '^Confirmed' <<<"$output" &&
	reaches_cabin home && ! reaches_cabin barn; then
	pass "a node itself over the mesh: Home let in to Cabin's ssh as Home.\$node, Barn still dropped"
else
	fail "a node itself over the mesh: Home let in to Cabin's ssh as Home.\$node, Barn still dropped" \
		"dropped before: ${dropped_before:-no}; exit $status: $output"$'\n'"$(run cabin 'fw4 print | grep -i ssh' 2>&1)"$'\n'"home: $(probe_cabin home 2>&1)"$'\n'"barn: $(probe_cabin barn 2>&1)"
fi

# Node $1's latest handshake with the peer whose key is $2: seconds since the
# epoch, 0 for never.
handshake() {
	run "$1" "wg show spl_mesh latest-handshakes | awk -v key='$2' '\$1 == key { print \$2 }'"
}
# A session the other end dropped: Home's mesh interface restarts, as at a
# reboot, and Cabin keeps the session it had with Home, fresh from a ping. What
# Cabin sends into it goes unanswered until WireGuard starts a new handshake,
# 15 s on; Cabin's probe waits for that, so a run on Cabin alone (the service
# taken away again) still checks Home. Both sessions are looked at first: the
# step proves nothing without them.
run cabin 'ping -c 1 -W 2 10.100.0.1 >/dev/null' || true
run home 'old=$(cat /sys/class/net/spl_mesh/ifindex); ifup spl_mesh
	for i in $(seq 20); do
		sleep 1
		[ "$(cat /sys/class/net/spl_mesh/ifindex 2>/dev/null)" != "$old" ] &&
			ifstatus spl_mesh | grep -q "\"up\": true" && break
	done' || true
held_since=$(handshake cabin "$home_key") || true
held_for=$(($(run cabin 'date +%s') - ${held_since:-0}))
dropped=$(handshake home "$cabin_key") || true
cp "$work/splot.yml.good" "$work/splot.yml"
output=$(splot apply --node Cabin --yes 2>&1) && status=0 || status=$?
if [ "$held_for" -lt 120 ] && [ "$dropped" = 0 ] && [ "$status" -eq 0 ] &&
	grep -q '^Checked Cabin: Barn, Home answer as before$' <<<"$output" && grep -q '^Confirmed' <<<"$output"; then
	pass "a session the other end dropped: Cabin's probe waits for WireGuard, and its run checks Home"
else
	fail "a session the other end dropped: Cabin's probe waits for WireGuard, and its run checks Home" \
		"Cabin's session with Home ${held_for}s old, Home's last handshake with Cabin: ${dropped:-none}; exit $status: $output"
fi

# A port forward from Home's WAN into the mesh: Cabin's own ssh, at Home's
# port $FORWARD_PORT. What this machine sends there arrives on Home's WAN from
# an address WireGuard at Cabin wouldn't take from Home, and Cabin would answer
# it by its own route: Home sends it as itself, from its mesh IP, which Cabin
# lets in. So this machine logs in to Cabin through Home, and Cabin sees Home.
cat >>"$work/ssh_config" <<EOF
Host cabin-via-home
	HostName 127.0.0.1
	Port $(podman port splot-openwrt-mesh-home "$FORWARD_PORT/tcp" | sed 's/.*://')
	User root
	IdentityFile $work/key
	IdentitiesOnly yes
	StrictHostKeyChecking no
	UserKnownHostsFile /dev/null
	LogLevel ERROR
	ConnectTimeout 5

EOF
# Cabin's WireGuard key and the address its ssh sees, through Home's forward.
through_home() {
	PATH="$work/bin:$PATH" timeout 10 ssh cabin-via-home 'wg show spl_mesh public-key; echo "$SSH_CLIENT"' 2>&1
}
before=$(through_home) || true
sed -i "/^  Cabin:$/,/^  Barn:$/ s/^    wanZone: wan$/&\n    services:\n      ssh: { port: '$FORWARD_PORT:22', proto: tcp, wan: { via: Home } }/" "$work/splot.yml"
output=$(splot apply --yes 2>&1) && status=0 || status=$?
# fw4 takes the change when procd reloads it, a second or two after the run's
# go, which a quick run's checks and confirm don't wait for: the forward gets
# that long.
for _ in $(seq 15); do
	after=$(through_home) && [ "$(sed -n 1p <<<"$after")" = "$cabin_key" ] && break
	sleep 1
done
if ! grep -qF "$cabin_key" <<<"$before" && [ "$status" -eq 0 ] && grep -q '^Confirmed' <<<"$output" &&
	[ "$(sed -n 1p <<<"$after")" = "$cabin_key" ] && [[ $(sed -n 2p <<<"$after") == '10.100.0.1 '* ]]; then
	pass "a port forward from Home's WAN reaches Cabin over the mesh, as Home"
else
	fail "a port forward from Home's WAN reaches Cabin over the mesh, as Home" \
		"before: $before"$'\n'"exit $status: $output"$'\n'"after: $after"$'\n'"$(run home 'nft list chain inet fw4 srcnat_spl_mesh' 2>&1)"
fi

if [ "${SPLOT_CHECK_KEEP:-}" = 1 ]; then
	echo "  ----  kept: podman exec -it splot-openwrt-mesh-home sh"
else
	podman rm --force --time 0 splot-openwrt-mesh-home splot-openwrt-mesh-cabin splot-linux-mesh-barn >/dev/null
fi

echo
if [ "$failures" -eq 0 ]; then
	echo "All checks passed."
else
	echo "$failures check(s) failed."
	exit 1
fi
