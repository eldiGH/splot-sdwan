#!/usr/bin/env bash
# Checks what splot does on a Linux node against real Linux: boots a Debian
# container with systemd, and runs splot here, as an operator would, carrying
# the x86_64 agent and reaching the container over ssh at its platform.ssh, as
# node Barn of splot.example.yml (its firewall and DHCP set to none: splot
# doesn't manage a Linux node's DHCP yet, and its firewall isn't checked here
# yet). It asks systemd, wg and ip whether the result works.
#
#   scripts/linux-check.sh
#
# Needs podman, ssh, the Rust target x86_64-unknown-linux-musl, and the
# wireguard kernel module on the host (`sudo modprobe wireguard`): containers
# share the host's kernel. SPLOT_CHECK_KEEP=1 keeps the container for a look
# around (`podman exec -it splot-linux bash`).
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
# What apply says once it has reached the node again and confirmed the change.
CONFIRMED="Confirmed: splot reached Barn again, and it keeps the change."
# The plan of a node with nothing to change: the dry run and apply both end
# there.
NOTHING="== Barn: nothing to change"$'\n'"Nothing to change."
# Barn's node peers don't answer here: apply checks none, and says so.
UNCHECKED="Checked Barn: not Cabin, Home, Lake, which didn't answer before the run"
# Whether apply's output $1 is the plan for Barn changing $2 (the plan's
# summary), applied and confirmed.
applied() {
	[ "$(head -1 <<<"$1")" = "== Barn: $2" ] &&
		[ "$(tail -4 <<<"$1")" = "Prepared: Barn"$'\n'"Applied: Barn"$'\n'"$UNCHECKED"$'\n'"$CONFIRMED" ]
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

# splot reaches the node as `barn`, its platform.ssh here: a host of an ssh
# config of the check's own, with a key of its own, through an `ssh` first on
# its PATH. With $work/cut there, every session after the first fails, as if
# the node had gone out of reach.
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/bin"
ssh-keygen -q -t ed25519 -N '' -C splot-check -f "$work/key"
cat >"$work/bin/ssh" <<EOF
#!/bin/sh
if [ -f "$work/cut" ]; then
	n=\$(cat "$work/cut")
	echo \$((n + 1)) >"$work/cut"
	if [ "\$n" -ge 1 ]; then
		echo "ssh: barn: cut off by the check" >&2
		exit 255
	fi
fi
exec $(command -v ssh) -F "$work/ssh_config" "\$@"
EOF
chmod +x "$work/bin/ssh"
# The example with Barn's firewall and DHCP left alone, reached as `barn`.
sed 's/ssh: root@192.168.4.1/ssh: barn/' splot.example.yml >"$work/splot.example.yml"
sed 's/firewall: nftables/firewall: none/; s/dhcp: dnsmasq/dhcp: none/' "$work/splot.example.yml" >"$work/splot.yml"

# What splot printed, with its exit status when it failed. Without the config's
# warnings: Barn leaves its firewall to the operator. The config is
# $work/splot.yml, or $config when set.
splot() {
	local output status=0
	output=$(PATH="$work/bin:$PATH" "$BINARY" --config "${config:-$work/splot.yml}" "$@" 2>&1) || status=$?
	grep -v '^warning: ' <<<"$output" || true
	[ "$status" -eq 0 ] || echo "(exit $status)"
}

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

# Points `barn` at the port podman published for the container's sshd (it may
# change when the container restarts), and waits for it to answer.
reachable() {
	cat >"$work/ssh_config" <<EOF
Host barn
	HostName 127.0.0.1
	Port $(podman port "$CONTAINER" 22/tcp | sed 's/.*://')
	User root
	IdentityFile $work/key
	IdentitiesOnly yes
	StrictHostKeyChecking no
	UserKnownHostsFile /dev/null
	LogLevel ERROR
EOF
	for _ in $(seq 30); do
		ssh -F "$work/ssh_config" barn true 2>/dev/null && return 0
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
# Its ssh port is published on a free port of this machine's loopback.
podman run --detach --name "$CONTAINER" --privileged --systemd=always \
	--publish 127.0.0.1::22 --add-host "$CABIN_ENDPOINT:$CABIN_ADDRESS" "$IMAGE" >/dev/null
if ! booted; then
	fail "boot: systemd up within 60 s" "$(run 'systemctl --failed' 2>&1)"
	exit 1
fi
podman cp "$work/key.pub" "$CONTAINER:/root/authorized_keys"
run 'install -d -m 700 /root/.ssh && install -m 600 /root/authorized_keys /root/.ssh/authorized_keys'
if ! reachable; then
	fail "ssh: the node answers within 30 s" "$(run 'systemctl status ssh --no-pager' 2>&1)"
	exit 1
fi

# The example as it is asks splot for Barn's DHCP.
output=$(config=$work/splot.example.yml splot apply --node Barn --dry-run)
if printf '%s' "$output" | grep -q "splot can't manage Barn's dhcp (dnsmasq) on Linux yet"; then
	pass "apply refuses a DHCP splot can't manage on Linux yet"
else
	fail "apply refuses a DHCP splot can't manage on Linux yet" "$output"
fi

# Only init writes the key: until it has run, the dry run says so and creates
# nothing.
output=$(splot apply --node Barn --dry-run)
if printf '%s' "$output" | grep -q 'run `splot init' && ! run "[ -e /etc/splot ] || [ -e $CONF ]"; then
	pass "before init, the dry run asks for it and writes nothing"
else
	fail "before init, the dry run asks for it and writes nothing" "$output"
fi

# Another node's OS: the config says Home runs OpenWrt.
output=$(splot init --node Home --ssh barn)
if printf '%s' "$output" | grep -q "this peer runs linux, but the config says Home runs openwrt" &&
	! run '[ -e /etc/splot ]'; then
	pass "init as an OpenWrt node refuses, writing nothing"
else
	fail "init as an OpenWrt node refuses, writing nothing" "$output"
fi

output=$(splot init --node Barn)
modes=$(run 'stat -c "%a %n" /etc/splot /etc/splot/keys' || true)
if printf '%s' "$output" | grep -q "Generated this peer's WireGuard key" &&
	[ "$modes" = "700 /etc/splot
600 /etc/splot/keys" ]; then
	pass "init: the key in /etc/splot/keys, readable by root only"
else
	fail "init: the key in /etc/splot/keys, readable by root only" "$output
$modes"
fi
barn_key=$(run 'sed -n "s/^private-key //p" /etc/splot/keys | wg pubkey')
sed -i "s|ReplaceBarnPublicKeyAAAAAAAAAAAAAAAAAAAAAAA=|$barn_key|" "$work/splot.yml"

output=$(splot apply --node Barn --yes)
if printf '%s' "$output" | grep -q 'no preshared key stored for Cabin, Home, Lake, Phone:' &&
	! run "[ -e $CONF ]"; then
	pass "apply refuses while PSKs are missing, writing nothing"
else
	fail "apply refuses while PSKs are missing, writing nothing" "$output"
fi
# Given with <<<, not a pipe: splot may refuse before it reads its input, and
# the pipe's writer failing would then read as splot failing (pipefail).
for peer in Cabin Home Lake Phone; do
	splot psk set --node Barn "$peer" <<<"$(run 'wg genpsk')" >/dev/null
done

# The dry run here holds placeholders, never a key of the node's.
output=$(splot apply --node Barn --dry-run)
private_key=$(run 'sed -n "s/^private-key //p" /etc/splot/keys')
if printf '%s' "$output" | grep -q "^# $CONF becomes:" &&
	printf '%s' "$output" | grep -q '^PrivateKey = <private key>$' &&
	printf '%s' "$output" | grep -q "^#   systemctl enable --now $UNIT$" &&
	! printf '%s' "$output" | grep -qF "$private_key" &&
	! run "[ -e $CONF ]"; then
	pass "dry run, here: the file with placeholders, then the start; writes nothing"
else
	fail "dry run, here: the file with placeholders, then the start; writes nothing" "$output"
fi

output=$(splot apply --node Barn --yes)
if applied "$output" "$CONF, $UNIT started and enabled" &&
	[ "$(run "stat -c %a $CONF")" = 600 ] &&
	run "grep -qxF 'PrivateKey = $private_key' $CONF" &&
	! run "grep -q '<' $CONF" &&
	run "systemctl is-active --quiet $UNIT && systemctl is-enabled --quiet $UNIT" &&
	! run '[ -e /tmp/splot/run ]' && run 'grep -q confirmed /tmp/splot/last'; then
	pass "apply: $CONF written (0600, keys in), $UNIT started and enabled; confirmed, no run left"
else
	fail "apply: $CONF written (0600, keys in), $UNIT started and enabled; confirmed, no run left" "$output"
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
routes() { run "ip -4 route show dev spl_mesh | grep -v 'proto kernel' | cut -d' ' -f1 | LC_ALL=C sort | paste -sd' '"; }
output=$(routes)
if [ "$output" = "192.168.1.0/24 192.168.10.0/24 192.168.2.0/24 192.168.3.0/24" ]; then
	pass "routes: the zones behind Home, Cabin and Lake, nothing else"
else
	fail "routes: the zones behind Home, Cabin and Lake, nothing else" "$output"
fi

file_state() { run "stat -c '%i %Y' $CONF"; }
before=$(file_state)
output=$(splot apply --node Barn --yes)
dry=$(splot apply --node Barn --dry-run)
if [ "$output" = "$NOTHING" ] && [ "$dry" = "$NOTHING" ] &&
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
sed -i "s/endpoint: $CABIN_ENDPOINT/endpoint: 203.0.113.21/" "$work/splot.yml"
dry=$(splot apply --node Barn --dry-run)
output=$(splot apply --node Barn --yes)
if printf '%s' "$dry" | grep -q "^#   systemctl reload $UNIT$" &&
	applied "$output" "$CONF, $UNIT reloaded" &&
	[ "$index" = "$(ifindex)" ] &&
	run 'wg show spl_mesh endpoints' | grep -q '203\.0\.113\.21:51820'; then
	pass "peer change: reloaded, live, the interface kept"
else
	fail "peer change: reloaded, live, the interface kept" "$dry
$output"
fi

# Cabin gets another zone: a route only a start sets, so a restart, saying why.
sed -i '/^  # Behind its ISP/i\      guest:\n        address: 192.168.5.1/24\n' "$work/splot.yml"
dry=$(splot apply --node Barn --dry-run)
output=$(splot apply --node Barn --yes)
again=$(splot apply --node Barn --yes)
if printf '%s' "$dry" | grep -qF "#   systemctl restart $UNIT  (routes to add: 192.168.5.0/24)" &&
	applied "$output" "$CONF, $UNIT restarted (routes to add: 192.168.5.0/24)" &&
	[ "$(routes)" = "192.168.1.0/24 192.168.10.0/24 192.168.2.0/24 192.168.3.0/24 192.168.5.0/24" ] &&
	[ "$again" = "$NOTHING" ]; then
	pass "route change: restarted, saying why; the new route live; then nothing to do"
else
	fail "route change: restarted, saying why; the new route live; then nothing to do" "$dry
$output
$again
$(routes)"
fi

# A PSK changes: staged alone, masked in the dry run, live after a reload.
psk=$(run 'wg genpsk')
splot psk set --node Barn Cabin <<<"$psk" >/dev/null
dry=$(splot apply --node Barn --dry-run)
output=$(splot apply --node Barn --yes)
if ! printf '%s' "$dry" | grep -qF "$psk" &&
	printf '%s' "$dry" | grep -q "^#   systemctl reload $UNIT$" &&
	applied "$output" "$CONF, $UNIT reloaded" &&
	run 'wg show spl_mesh preshared-keys' | grep -qF "$psk"; then
	pass "PSK change: masked in the dry run, live after a reload"
else
	fail "PSK change: masked in the dry run, live after a reload" "$dry
$output"
fi

# The node keeps a change only once splot reaches it again: cut off after the
# apply, it puts back what it had by itself at the deadline, the unit running
# as it was. splot waits for the deadline (meanwhile the change is there), and
# asks again: still cut off, it says so.
sed -i 's/endpoint: 203.0.113.21/endpoint: 203.0.113.22/' "$work/splot.yml"
cut_before=$(run "md5sum $CONF")
echo 0 >"$work/cut"
PATH="$work/bin:$PATH" "$BINARY" --config "$work/splot.yml" apply --node Barn --yes --confirm-within 10 \
	>"$work/cut.out" 2>&1 &
waiting=$!
for _ in $(seq 40); do
	if grep -q 'waiting for its deadline' "$work/cut.out"; then break; fi
	sleep 0.5
done
cut_applied=$(run "md5sum $CONF")
wait "$waiting" && status=0 || status=$?
rm -f "$work/cut"
output=$(cat "$work/cut.out")
cut_after=$(run "md5sum $CONF")
last=$(run 'cat /tmp/splot/last 2>&1') || true
if [ "$status" -ne 0 ] && grep -q "^Couldn't check Barn: " <<<"$output" &&
	grep -q '^  Barn  unreachable: waiting for its deadline' <<<"$output" &&
	grep -q '^  Barn  still unreachable: ' <<<"$output" &&
	grep -q "splot couldn't check Barn, so Barn didn't keep it" <<<"$output" &&
	[ "$cut_applied" != "$cut_before" ] && [ "$cut_after" = "$cut_before" ] &&
	grep -q "rolled back" <<<"$last" && ! run '[ -e /tmp/splot/run ]' &&
	run "systemctl is-active --quiet $UNIT" && run 'wg show spl_mesh endpoints' | grep -q '203\.0\.113\.21:51820'; then
	pass "cut off before the confirm: the node put back what it had at the deadline, $UNIT running; splot waited"
else
	fail "cut off before the confirm: the node put back what it had at the deadline, $UNIT running; splot waited" \
		"exit $status: $output"$'\n'"last: $last"$'\n'"before: $cut_before"$'\n'"applied: $cut_applied"$'\n'"after: $cut_after"
fi
sed -i 's/endpoint: 203.0.113.22/endpoint: 203.0.113.21/' "$work/splot.yml"

run "systemctl stop $UNIT"
output=$(splot apply --node Barn --yes)
if applied "$output" "$UNIT started and enabled" &&
	run "systemctl is-active --quiet $UNIT"; then
	pass "stopped: apply starts it again"
else
	fail "stopped: apply starts it again" "$output"
fi

run "systemctl disable --quiet $UNIT"
output=$(splot apply --node Barn --yes)
if applied "$output" "$UNIT enabled" &&
	run "systemctl is-enabled --quiet $UNIT"; then
	pass "disabled: apply enables it, so it comes back after a reboot"
else
	fail "disabled: apply enables it, so it comes back after a reboot" "$output"
fi

# Brought up by hand instead: starting the unit would fail on it.
run "systemctl stop $UNIT && wg-quick up spl_mesh 2>/dev/null"
before=$(file_state)
output=$(splot apply --node Barn --yes)
run 'wg-quick down spl_mesh 2>/dev/null'
if printf '%s' "$output" | grep -q "spl_mesh is up, but not through $UNIT" &&
	[ "$before" = "$(file_state)" ]; then
	pass "up by hand: apply refuses, touching nothing"
else
	fail "up by hand: apply refuses, touching nothing" "$output"
fi
run "systemctl start $UNIT"

# splot on the node itself (--local): the agent's code in splot, and splot
# itself keeps the deadline. A peer's endpoint moves, and it's confirmed.
podman cp "$BINARY" "$CONTAINER:/usr/bin/splot"
sed 's/endpoint: 203.0.113.21/endpoint: 203.0.113.23/' "$work/splot.yml" >"$work/splot-local.yml"
podman cp "$work/splot-local.yml" "$CONTAINER:/root/splot.yml"
output=$(run 'splot --config /root/splot.yml apply --node Barn --local --yes 2>&1 | grep -v "^warning: "' || true)
if applied "$output" "$CONF, $UNIT reloaded" &&
	run 'wg show spl_mesh endpoints' | grep -q '203\.0\.113\.23:51820' &&
	! run '[ -e /tmp/splot/run ]' && run 'grep -q confirmed /tmp/splot/last'; then
	pass "on the node itself (--local): applied and confirmed, no run left"
else
	fail "on the node itself (--local): applied and confirmed, no run left" "$output"
fi
sed -i 's/endpoint: 203.0.113.21/endpoint: 203.0.113.23/' "$work/splot.yml"

# The mesh comes back after a reboot, with its routes.
podman restart --time 5 "$CONTAINER" >/dev/null
booted || true
reachable || true
state=$(run "systemctl is-active $UNIT" || true)
output=$(splot apply --node Barn --yes)
if [ "$state" = active ] &&
	[ "$(routes)" = "192.168.1.0/24 192.168.10.0/24 192.168.2.0/24 192.168.3.0/24 192.168.5.0/24" ] &&
	[ "$output" = "$NOTHING" ]; then
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

# Each agent splot sent removed itself when its session ended.
output=$(run 'ls /tmp/splot-agent.* 2>/dev/null' || true)
if [ -z "$output" ]; then
	pass "no agent left in the node's /tmp"
else
	fail "no agent left in the node's /tmp" "$output"
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
