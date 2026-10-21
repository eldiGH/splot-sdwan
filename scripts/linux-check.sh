#!/usr/bin/env bash
# Checks what splot does on a Linux node against real Linux: boots a Debian
# container with systemd, runs `splot` there with splot.example.yml as node
# Barn (its firewall and DHCP set to none: splot manages only a Linux node's
# WireGuard so far), and asks systemd, wg and ip whether the result works.
#
#   scripts/linux-check.sh
#
# Needs podman, the Rust target x86_64-unknown-linux-musl, and the wireguard
# kernel module on the host (`sudo modprobe wireguard`): containers share the
# host's kernel. SPLOT_CHECK_KEEP=1 keeps the container for a look around
# (`podman exec -it splot-linux bash`).
# Commands in single quotes run in the container; their $ expands there.
# shellcheck disable=SC2016
set -euo pipefail

cd "$(dirname "$0")/.."

TARGET=x86_64-unknown-linux-musl
BINARY=target/$TARGET/release/splot
IMAGE=localhost/splot-linux:trixie
CONTAINER=splot-linux

# Cabin's endpoint in splot.example.yml, a name, and the address the container
# resolves it to: a name that doesn't resolve keeps the whole interface down.
CABIN_ENDPOINT=cabin.example.net
CABIN_ADDRESS=203.0.113.20

S="splot --config /root/splot.yml"
CONF=/etc/wireguard/spl_mesh.conf
UNIT=wg-quick@spl_mesh

failures=0
pass() { printf '  PASS  %s\n' "$1"; }
info() { printf '  ----  %s\n' "$1"; }
fail() {
	printf '  FAIL  %s\n' "$1"
	[ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/          /'
	failures=$((failures + 1))
}
run() { podman exec "$CONTAINER" bash -c "$1"; }
# What splot printed, with its exit status when it failed. Without the config's
# warnings: Barn leaves its firewall to the operator.
splot() { run "$S $1 2>&1 | grep -v '^warning: '; exit \${PIPESTATUS[0]}" || echo "(exit $?)"; }

if [ ! -d /sys/module/wireguard ]; then
	echo "The host's wireguard kernel module isn't loaded; run: sudo modprobe wireguard" >&2
	exit 2
fi

echo "Building splot for $TARGET"
cargo build --quiet --release --target "$TARGET"

# Waits for systemd to finish booting the container.
booted() {
	local state
	for _ in $(seq 60); do
		state=$(run 'systemctl is-system-running 2>/dev/null' || true)
		case $state in running | degraded) return 0 ;; esac
		sleep 1
	done
	return 1
}

echo
echo "== Debian (systemd, wg-quick)"
podman build --quiet -t "$IMAGE" scripts/linux >/dev/null
podman rm --force --ignore --time 0 "$CONTAINER" >/dev/null
# --privileged: rootless, so the extra capabilities apply inside the
# container's own user namespace only (enough to make WireGuard interfaces).
podman run --detach --name "$CONTAINER" --privileged --systemd=always \
	--add-host "$CABIN_ENDPOINT:$CABIN_ADDRESS" "$IMAGE" >/dev/null
if ! booted; then
	fail "boot: systemd up within 60 s" "$(run 'systemctl --failed' 2>&1)"
	exit 1
fi

podman cp "$BINARY" "$CONTAINER:/usr/bin/splot"
podman cp splot.example.yml "$CONTAINER:/root/splot.example.yml"
run 'sed "s/firewall: nftables/firewall: none/; s/dhcp: dnsmasq/dhcp: none/" /root/splot.example.yml >/root/splot.yml'

# The example as it is asks splot for Barn's firewall and DHCP.
output=$(run 'splot --config /root/splot.example.yml apply --node Barn --dry-run 2>&1' || true)
if printf '%s' "$output" | grep -q "splot can't manage Barn's firewall (nftables) or dhcp (dnsmasq) on Linux yet"; then
	pass "apply refuses a firewall and DHCP splot can't manage on Linux yet"
else
	fail "apply refuses a firewall and DHCP splot can't manage on Linux yet" "$output"
fi

# Only init writes the key: until it has run, the dry run says so and creates
# nothing.
output=$(splot "apply --node Barn --dry-run")
if printf '%s' "$output" | grep -q 'run `splot init' && ! run "[ -e /etc/splot ] || [ -e $CONF ]"; then
	pass "before init, the dry run asks for it and writes nothing"
else
	fail "before init, the dry run asks for it and writes nothing" "$output"
fi

# Another node's OS: the config says Home runs OpenWrt.
output=$(splot "init --node Home")
if printf '%s' "$output" | grep -q "this peer runs linux, but the config says Home runs openwrt" &&
	! run '[ -e /etc/splot ]'; then
	pass "init as an OpenWrt node refuses, writing nothing"
else
	fail "init as an OpenWrt node refuses, writing nothing" "$output"
fi

output=$(splot "init --node Barn")
modes=$(run 'stat -c "%a %n" /etc/splot /etc/splot/keys' || true)
if printf '%s' "$output" | grep -q "Generated this peer's WireGuard key" &&
	[ "$modes" = "700 /etc/splot
600 /etc/splot/keys" ]; then
	pass "init: the key in /etc/splot/keys, readable by root only"
else
	fail "init: the key in /etc/splot/keys, readable by root only" "$output
$modes"
fi
run 'sed -i "s|ReplaceBarnPublicKeyAAAAAAAAAAAAAAAAAAAAAAA=|$(sed -n "s/^private-key //p" /etc/splot/keys | wg pubkey)|" /root/splot.yml'

output=$(splot "apply --node Barn")
if printf '%s' "$output" | grep -q 'no preshared key stored for Cabin, Home, Lake, Phone:' &&
	! run "[ -e $CONF ]"; then
	pass "apply refuses while PSKs are missing, writing nothing"
else
	fail "apply refuses while PSKs are missing, writing nothing" "$output"
fi
for peer in Cabin Home Lake Phone; do
	run "wg genpsk | $S psk set --node Barn $peer >/dev/null"
done

output=$(splot "apply --node Barn --dry-run")
private_key=$(run 'sed -n "s/^private-key //p" /etc/splot/keys')
if printf '%s' "$output" | grep -q "^# $CONF becomes:" &&
	printf '%s' "$output" | grep -q '^PrivateKey = <private key>$' &&
	printf '%s' "$output" | grep -q "^#   systemctl enable --now $UNIT$" &&
	! printf '%s' "$output" | grep -qF "$private_key" &&
	! run "[ -e $CONF ]"; then
	pass "dry run: the file with placeholders, then the start; writes nothing"
else
	fail "dry run: the file with placeholders, then the start; writes nothing" "$output"
fi

output=$(splot "apply --node Barn")
if [ "$output" = "Applied and reloaded: $CONF, $UNIT started and enabled" ] &&
	[ "$(run "stat -c %a $CONF")" = 600 ] &&
	run "grep -qxF 'PrivateKey = $private_key' $CONF" &&
	! run "grep -q '<' $CONF" &&
	run "systemctl is-active --quiet $UNIT && systemctl is-enabled --quiet $UNIT"; then
	pass "apply: $CONF written (0600, keys in), $UNIT started and enabled"
else
	fail "apply: $CONF written (0600, keys in), $UNIT started and enabled" "$output"
fi

# Every peer, the address, and each pair's stored PSK.
problems=$(run '
	[ "$(wg show spl_mesh peers | wc -l)" = 4 ] || echo "peers: $(wg show spl_mesh peers | wc -l);"
	ip -4 -o address show dev spl_mesh | grep -q " 10.100.0.4/16 " || echo "no address;"
	psks=$(wg show spl_mesh preshared-keys)
	for psk in $(sed -n "s/^psk [^ ]* //p" /etc/splot/keys); do
		printf "%s" "$psks" | grep -qF "$psk" || echo "a PSK missing;"
	done' || true)
if [ -z "$problems" ]; then
	pass "WireGuard spl_mesh: up, 4 peers, address, each pair's PSK"
else
	fail "WireGuard spl_mesh: up, 4 peers, address, each pair's PSK" "$problems"
fi

# wg-quick's routes: the networks behind the other nodes; the mesh's own
# addresses are on the interface's network.
routes() { run "ip -4 route show dev spl_mesh | grep -v 'proto kernel' | cut -d' ' -f1 | sort | paste -sd' '"; }
output=$(routes)
if [ "$output" = "192.168.1.0/24 192.168.2.0/24 192.168.3.0/24" ]; then
	pass "routes: the zones behind Home, Cabin and Lake, nothing else"
else
	fail "routes: the zones behind Home, Cabin and Lake, nothing else" "$output"
fi

file_state() { run "stat -c '%i %Y' $CONF"; }
before=$(file_state)
output=$(splot "apply --node Barn")
dry=$(splot "apply --node Barn --dry-run")
if [ "$output" = "Nothing changed." ] && [ "$dry" = "# Nothing to change." ] &&
	[ "$before" = "$(file_state)" ]; then
	pass "second apply changes nothing, file untouched; its dry run says so"
else
	fail "second apply changes nothing, file untouched; its dry run says so" "$output
$dry"
fi

# A peer's endpoint changes: WireGuard's own setting, so a reload; the
# interface stays (same index), and so do its tunnels.
ifindex() { run 'cat /sys/class/net/spl_mesh/ifindex'; }
index=$(ifindex)
run "sed -i 's/endpoint: $CABIN_ENDPOINT/endpoint: 203.0.113.21/' /root/splot.yml"
dry=$(splot "apply --node Barn --dry-run")
output=$(splot "apply --node Barn")
if printf '%s' "$dry" | grep -q "^#   systemctl reload $UNIT$" &&
	[ "$output" = "Applied and reloaded: $CONF, $UNIT reloaded" ] &&
	[ "$index" = "$(ifindex)" ] &&
	run 'wg show spl_mesh endpoints' | grep -q '203\.0\.113\.21:51820'; then
	pass "peer change: reloaded, live, the interface kept"
else
	fail "peer change: reloaded, live, the interface kept" "$dry
$output"
fi

# Cabin gets another zone: a route only a start sets, so a restart, saying why.
run "sed -i '/^  # Behind its ISP/i\\      guest:\\n        address: 192.168.5.1/24\\n' /root/splot.yml"
dry=$(splot "apply --node Barn --dry-run")
output=$(splot "apply --node Barn")
again=$(splot "apply --node Barn")
if printf '%s' "$dry" | grep -qF "#   systemctl restart $UNIT  (routes to add: 192.168.5.0/24)" &&
	[ "$output" = "Applied and reloaded: $CONF, $UNIT restarted (routes to add: 192.168.5.0/24)" ] &&
	[ "$(routes)" = "192.168.1.0/24 192.168.2.0/24 192.168.3.0/24 192.168.5.0/24" ] &&
	[ "$again" = "Nothing changed." ]; then
	pass "route change: restarted, saying why; the new route live; then nothing to do"
else
	fail "route change: restarted, saying why; the new route live; then nothing to do" "$dry
$output
$again
$(routes)"
fi

# A PSK changes: staged alone, masked in the dry run, live after a reload.
run "wg genpsk >/root/cabin.psk && $S psk set --node Barn Cabin </root/cabin.psk >/dev/null"
dry=$(splot "apply --node Barn --dry-run")
output=$(splot "apply --node Barn")
if ! printf '%s' "$dry" | grep -qF "$(run 'cat /root/cabin.psk')" &&
	printf '%s' "$dry" | grep -q "^#   systemctl reload $UNIT$" &&
	[ "$output" = "Applied and reloaded: $CONF, $UNIT reloaded" ] &&
	run 'wg show spl_mesh preshared-keys | grep -qF "$(cat /root/cabin.psk)"'; then
	pass "PSK change: masked in the dry run, live after a reload"
else
	fail "PSK change: masked in the dry run, live after a reload" "$dry
$output"
fi

run "systemctl stop $UNIT"
output=$(splot "apply --node Barn")
if [ "$output" = "Applied and reloaded: $UNIT started and enabled" ] &&
	run "systemctl is-active --quiet $UNIT"; then
	pass "stopped: apply starts it again"
else
	fail "stopped: apply starts it again" "$output"
fi

run "systemctl disable --quiet $UNIT"
output=$(splot "apply --node Barn")
if [ "$output" = "Applied and reloaded: $UNIT enabled" ] &&
	run "systemctl is-enabled --quiet $UNIT"; then
	pass "disabled: apply enables it, so it comes back after a reboot"
else
	fail "disabled: apply enables it, so it comes back after a reboot" "$output"
fi

# Brought up by hand instead: starting the unit would fail on it.
run "systemctl stop $UNIT && wg-quick up spl_mesh 2>/dev/null"
before=$(file_state)
output=$(splot "apply --node Barn")
run 'wg-quick down spl_mesh 2>/dev/null'
if printf '%s' "$output" | grep -q "spl_mesh is up, but not through $UNIT" &&
	[ "$before" = "$(file_state)" ]; then
	pass "up by hand: apply refuses, touching nothing"
else
	fail "up by hand: apply refuses, touching nothing" "$output"
fi
run "systemctl start $UNIT"

# The mesh comes back after a reboot, with its routes.
podman restart --time 5 "$CONTAINER" >/dev/null
booted || true
state=$(run "systemctl is-active $UNIT" || true)
output=$(splot "apply --node Barn")
if [ "$state" = active ] &&
	[ "$(routes)" = "192.168.1.0/24 192.168.2.0/24 192.168.3.0/24 192.168.5.0/24" ] &&
	[ "$output" = "Nothing changed." ]; then
	pass "reboot: the mesh comes back as splot left it"
else
	fail "reboot: the mesh comes back as splot left it" "$state; routes $(routes)
$output"
fi

output=$(run "journalctl -u $UNIT -p err --no-pager -q" || true)
if [ -z "$output" ]; then
	pass "no errors logged by $UNIT"
else
	fail "no errors logged by $UNIT" "$output"
fi

if [ "${SPLOT_CHECK_KEEP:-}" = 1 ]; then
	info "kept: podman exec -it $CONTAINER bash"
else
	podman rm --force --time 0 "$CONTAINER" >/dev/null
fi

echo
if [ "$failures" -eq 0 ]; then
	echo "All checks passed."
else
	echo "$failures check(s) failed."
	exit 1
fi
