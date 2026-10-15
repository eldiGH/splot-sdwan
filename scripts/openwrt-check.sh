#!/usr/bin/env bash
# Checks what splot generates against real OpenWrt: boots an OpenWrt container
# per version, runs `splot apply` there with splot.example.yml (as node Home),
# and asks OpenWrt's own tools whether the result works.
#
#   scripts/openwrt-check.sh [VERSION...]     default: the versions in use
#
# Needs podman, the Rust target x86_64-unknown-linux-musl, and the wireguard
# kernel module on the host (`sudo modprobe wireguard`): containers share the
# host's kernel. SPLOT_CHECK_KEEP=1 keeps the containers for a look around
# (`podman exec -it splot-openwrt-<version> sh`).
# Commands in single quotes run in the container; their $ expands there.
# shellcheck disable=SC2016
set -euo pipefail

cd "$(dirname "$0")/.."

# freya runs 24.10, thor 25.12; they differ in how WireGuard picks up peers.
DEFAULT_VERSIONS=(24.10.2 25.12.2)
VERSIONS=("${@:-${DEFAULT_VERSIONS[@]}}")
TARGET=x86_64-unknown-linux-musl
BINARY=target/$TARGET/release/splot-sdwan

# Cabin's endpoint in splot.example.yml; changed to test a live peer update.
CABIN_ENDPOINT=203.0.113.20

failures=0
pass() { printf '  PASS  %s\n' "$1"; }
info() { printf '  ----  %s\n' "$1"; }
fail() {
	printf '  FAIL  %s\n' "$1"
	[ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/          /'
	failures=$((failures + 1))
}

if [ ! -d /sys/module/wireguard ]; then
	echo "The host's wireguard kernel module isn't loaded; run: sudo modprobe wireguard" >&2
	exit 2
fi

echo "Building splot for $TARGET"
cargo build --quiet --release --target "$TARGET"

check_version() {
	local version=$1
	local image=localhost/splot-openwrt:$version
	local container=splot-openwrt-$version
	run() { podman exec "$container" sh -c "$1"; }

	echo
	echo "== OpenWrt $version"
	podman build --quiet --build-arg "OPENWRT_VERSION=$version" -t "$image" scripts/openwrt >/dev/null
	podman rm --force --ignore --time 0 "$container" >/dev/null
	# --privileged: rootless, so the extra capabilities apply inside the
	# container's own user namespace only. eth1: the WAN set up by prepare.sh.
	podman run --detach --name "$container" --privileged --network pasta:-I,eth1 "$image" >/dev/null

	local booted=
	for _ in $(seq 60); do
		if [ "$(run 'ifstatus wan 2>/dev/null | jsonfilter -e @.up' 2>/dev/null)" = true ]; then
			booted=1
			break
		fi
		sleep 1
	done
	if [ -z "$booted" ]; then
		fail "boot: WAN up within 60 s" "$(run 'logread | tail -20' 2>&1)"
		return
	fi

	# The node's key, and the example config with Home's public key filled in.
	podman cp "$BINARY" "$container:/usr/bin/splot"
	podman cp splot.example.yml "$container:/tmp/splot.example.yml"
	run '
		touch /etc/config/splot
		key=$(wg genkey)
		uci set splot.config=splot
		uci set splot.config.private_key="$key"
		uci commit splot
		pubkey=$(echo "$key" | wg pubkey)
		sed "s|ReplaceHomePublicKeyA*=|$pubkey|" /tmp/splot.example.yml >/tmp/splot.yml'

	local log_lines output
	log_lines=$(run 'logread | wc -l')
	if output=$(run 'splot --config /tmp/splot.yml apply' 2>&1); then
		pass "splot apply: $(printf '%s' "$output" | tail -1)"
	else
		fail "splot apply" "$output"
		return
	fi
	# procd runs the reloads that reload_config triggers a second later.
	sleep 3

	# fw4 skips a section it can't use with a "[!]" warning and still exits 0.
	output=$(run 'fw4 check 2>&1') || true
	if printf '%s' "$output" | grep -q '\[!\]' || ! printf '%s' "$output" | grep -q 'passes nftables check'; then
		fail "fw4 check: every section accepted" "$output"
	else
		pass "fw4 check: every section accepted"
	fi

	# The reload regenerated the live ruleset: splot's rules are in it.
	if [ "$(run 'nft list ruleset | grep -c "\[SPLOT\]"')" -gt 0 ]; then
		pass "fw4 reloaded: splot's rules are live"
	else
		fail "fw4 reloaded: splot's rules are live"
	fi

	if output=$(run 'for conf in /var/etc/dnsmasq.conf.*; do dnsmasq --test -C "$conf" 2>&1 || exit 1; done'); then
		pass "dnsmasq --test on the generated config"
	else
		fail "dnsmasq --test on the generated config" "$output"
	fi

	# The reload regenerated dnsmasq's config: every lease splot wrote is in it.
	output=$(run '
		for mac in $(uci show dhcp | sed -n "s/^dhcp\.spl_[A-Za-z0-9_]*\.mac=//p" | tr -d "'"'"'"); do
			grep -qi "dhcp-host=$mac" /var/etc/dnsmasq.conf.* || echo "missing lease for $mac"
		done')
	if [ -z "$output" ]; then
		pass "dnsmasq reloaded: splot's leases are in its config"
	else
		fail "dnsmasq reloaded: splot's leases are in its config" "$output"
	fi

	if [ "$(run '/etc/init.d/dnsmasq status')" = running ]; then
		pass "dnsmasq running"
	else
		fail "dnsmasq running"
	fi

	local interfaces interface
	interfaces=$(run "uci show network | sed -n \"s/^network\\.\\(spl_[A-Za-z0-9_]*\\)\\.proto='wireguard'\$/\\1/p\"")
	for interface in $interfaces; do
		output=$(run '
			i='"$interface"'
			problems=
			[ "$(ifstatus $i | jsonfilter -e @.up)" = true ] || problems="$problems not up;"
			want=$(uci show network | grep -c "=wireguard_$i\$")
			have=$(wg show $i peers 2>/dev/null | wc -l)
			[ "$want" = "$have" ] || problems="$problems $have of $want peers;"
			address=$(uci -q get network.$i.addresses || uci -q get network.$i.address)
			ip -4 -o addr show dev $i | grep -q " ${address%% *} " || problems="$problems no address ${address:-?};"
			echo "$problems"')
		if [ -z "$output" ]; then
			pass "WireGuard $interface: up, peers, address"
		else
			fail "WireGuard $interface: up, peers, address" "$output"
		fi
	done

	# Errors the daemons logged since the apply. A dnsmasq reload makes procd log
	# "Got unexpected signal 1" in this container even on a stock config, without
	# splot: not counted.
	output=$(run "logread | tail -n +$((log_lines + 1)) | grep -E '\\.(emerg|alert|crit|err) ' | grep -v 'procd: Got unexpected signal 1'") || true
	if [ -z "$output" ]; then
		pass "no errors logged since the apply"
	else
		# Each message once, without its timestamp and process ID.
		fail "no errors logged since the apply" \
			"$(printf '%s\n' "$output" | sed -E 's/^.{24} //; s/\[[0-9]+\]//' | sort -u | head -10)"
	fi

	output=$(run 'splot --config /tmp/splot.yml apply' 2>&1) || true
	if [ "$(printf '%s' "$output" | tail -1)" = "Nothing changed." ]; then
		pass "second apply changes nothing"
	else
		fail "second apply changes nothing" "$output"
	fi

	# A peer change: Cabin's endpoint moves. WireGuard must see it without a reboot.
	local renew before after
	renew=$(run 'ubus call network get_proto_handlers | jsonfilter -e @.wireguard.renew_available')
	before=$(run 'cat /sys/class/net/spl_mesh/ifindex 2>/dev/null') || true
	run "sed -i 's/$CABIN_ENDPOINT/203.0.113.21/' /tmp/splot.yml"
	if ! output=$(run 'splot --config /tmp/splot.yml apply' 2>&1); then
		fail "peer update: apply" "$output"
	else
		sleep 3
		if run 'wg show spl_mesh endpoints' | grep -q '203\.0\.113\.21:'; then
			pass "peer update reaches WireGuard (renew available: $renew)"
		else
			fail "peer update reaches WireGuard (renew available: $renew)" "$(run 'wg show spl_mesh endpoints' 2>&1)"
		fi
		after=$(run 'cat /sys/class/net/spl_mesh/ifindex 2>/dev/null') || true
		if [ "$renew" != true ]; then
			info "peer update restarted spl_mesh (no renew on this version)"
		elif [ -n "$before" ] && [ "$before" = "$after" ]; then
			pass "peer update is live (spl_mesh not recreated)"
		else
			fail "peer update is live (spl_mesh not recreated)" "ifindex $before -> $after"
		fi
	fi

	if [ "${SPLOT_CHECK_KEEP:-}" = 1 ]; then
		info "kept: podman exec -it $container sh"
	else
		podman rm --force --time 0 "$container" >/dev/null
	fi
}

for version in "${VERSIONS[@]}"; do
	check_version "$version"
done

echo
if [ "$failures" -eq 0 ]; then
	echo "All checks passed."
else
	echo "$failures check(s) failed."
	exit 1
fi
