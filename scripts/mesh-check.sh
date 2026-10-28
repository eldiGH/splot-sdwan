#!/usr/bin/env bash
# Checks splot across a mesh: two OpenWrt routers, Home and Cabin, in containers
# with a real WireGuard tunnel between them. splot runs here and reaches each
# over ssh. It checks that an apply is confirmed only while the other router
# still answers through the tunnel, and rolled back when the change cuts it off;
# then runs across the mesh, both routers at once: all or nothing.
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
TARGET=x86_64-unknown-linux-musl
BINARY=target/$TARGET/release/splot
# WireGuard's ports, one per router: published on this machine's loopback.
HOME_PORT=52820
CABIN_PORT=52821

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
run() { podman exec "splot-openwrt-mesh-$1" sh -c "$2"; }

# Boots router $1 (`home`, `cabin`) with its WireGuard port $2, and lets the
# check in over ssh.
boot() {
	local name=$1 port=$2 container=splot-openwrt-mesh-$1
	podman rm --force --ignore --time 0 "$container" >/dev/null
	# --map-gw: the router reaches this machine's loopback at its gateway's
	# address, and through it the other router's published WireGuard port.
	podman run --detach --name "$container" --privileged --network pasta:-I,eth1,--map-gw \
		--publish 127.0.0.1::22 --publish "127.0.0.1:$port:$port/udp" "$IMAGE" >/dev/null

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
	# address; WireGuard's ports are let in on the WAN, as an operator would.
	run "$name" "chmod 600 /etc/dropbear/authorized_keys
		gateway=\$(ip -4 route show default | awk '{ print \$3 }')
		echo \"\$gateway home.example.net cabin.example.net\" >>/etc/hosts
		uci add firewall rule >/dev/null
		uci set firewall.@rule[-1].name='Allow-WireGuard-for-splot-check'
		uci set firewall.@rule[-1].src=wan
		uci set firewall.@rule[-1].proto=udp
		uci set firewall.@rule[-1].dest_port='$HOME_PORT-$CABIN_PORT'
		uci set firewall.@rule[-1].target=ACCEPT
		uci commit firewall
		fw4 reload >/dev/null 2>&1"
	cat >>"$work/ssh_config" <<EOF
Host $name
	HostName 127.0.0.1
	Port $(podman port "$container" 22/tcp | sed 's/.*://')
	User root
	IdentityFile $work/key
	IdentitiesOnly yes
	StrictHostKeyChecking no
	UserKnownHostsFile /dev/null
	LogLevel ERROR

EOF
	for _ in $(seq 30); do
		PATH="$work/bin:$PATH" ssh "$name" true 2>/dev/null && return 0
		sleep 1
	done
	echo "$name: no ssh within 30 s" >&2
	return 1
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
  Cabin:
    platform:
      os: openwrt
      dhcp: none
      ssh: cabin
    publicKey: $2
    endpoint: cabin.example.net
    listenPort: $CABIN_PORT
    meshIp: 10.100.0.2
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
output=$(splot apply --node Cabin 2>&1) || true
output="$output"$'\n'$(splot apply --node Home 2>&1) || true
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
output=$(splot apply --node Home 2>&1) || true
if grep -q '^Checked: Cabin answers as before' <<<"$output" && grep -q '^Confirmed' <<<"$output"; then
	pass "a change that keeps the tunnel: Cabin checked, the change confirmed"
else
	fail "a change that keeps the tunnel: Cabin checked, the change confirmed" "$output"
fi

# A preshared key changed on Home's end only: Home's tunnel to Cabin takes a
# fresh session, which fails, so Home puts back what it had, and the tunnel
# works again.
before=$(run home 'md5sum /etc/config/network')
splot psk set --node Home Cabin <<<"$(run home 'wg genpsk')" >/dev/null
output=$(splot apply --node Home 2>&1) && status=0 || status=$?
after=$(run home 'md5sum /etc/config/network')
last=$(run home 'cat /tmp/splot/last' 2>&1) || true
if [ "$status" -ne 0 ] &&
	grep -q "the change cut Home off from Cabin, so splot didn't keep it: Home put back what it had" <<<"$output" &&
	[ "$after" = "$before" ] && grep -q "rolled back" <<<"$last" &&
	run home 'ping -c 3 -W 2 10.100.0.2 >/dev/null'; then
	pass "a preshared key changed on one end: Cabin lost, rolled back, the tunnel works again"
else
	fail "a preshared key changed on one end: Cabin lost, rolled back, the tunnel works again" \
		"exit $status: $output"$'\n'"last: $last"$'\n'"before: $before"$'\n'"after: $after"
fi

# Across the mesh: what each router holds, and whether a run is left there.
held() { run "$1" 'md5sum /etc/config/network; [ ! -e /tmp/splot/run ] || echo "a run is left"'; }
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

# Each router dials the other where nothing answers: both lose the other, so
# both put back what they had, and the tunnel works again.
cp "$work/splot.yml" "$work/splot.yml.good"
sed -i 's/endpoint: home.example.net/endpoint: 192.0.2.1/; s/endpoint: cabin.example.net/endpoint: 192.0.2.2/' "$work/splot.yml"
before="$(held home)$(held cabin)"
output=$(splot apply --yes 2>&1) && status=0 || status=$?
cp "$work/splot.yml.good" "$work/splot.yml"
if [ "$status" -ne 0 ] && grep -q '^Checked Home: lost Cabin$' <<<"$output" &&
	grep -q '^  Home   put back$' <<<"$output" && grep -q '^  Cabin  put back$' <<<"$output" &&
	grep -q 'the change cut Cabin off from Home, and Home off from Cabin, so no node kept it' <<<"$output" &&
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

if [ "${SPLOT_CHECK_KEEP:-}" = 1 ]; then
	echo "  ----  kept: podman exec -it splot-openwrt-mesh-home sh"
else
	podman rm --force --time 0 splot-openwrt-mesh-home splot-openwrt-mesh-cabin >/dev/null
fi

echo
if [ "$failures" -eq 0 ]; then
	echo "All checks passed."
else
	echo "$failures check(s) failed."
	exit 1
fi
