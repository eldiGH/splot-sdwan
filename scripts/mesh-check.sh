#!/usr/bin/env bash
# Checks splot across a mesh: two OpenWrt routers, Home and Cabin, in containers
# with a real WireGuard tunnel between them. splot runs here and reaches each
# over ssh. It checks that an apply is confirmed only while the other router
# still answers through the tunnel, and rolled back when the change cuts it off.
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
# first on its PATH.
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/bin"
ssh-keygen -q -t ed25519 -N '' -C splot-check -f "$work/key"
printf '#!/bin/sh\nexec %s -F %s "$@"\n' "$(command -v ssh)" "$work/ssh_config" >"$work/bin/ssh"
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
