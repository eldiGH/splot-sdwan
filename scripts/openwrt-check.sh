#!/usr/bin/env bash
# Checks what splot generates against real OpenWrt: boots an OpenWrt container
# per version, runs splot here, reaching the router over ssh as node Home of
# splot.example.yml, and asks OpenWrt's own tools whether the result works.
#
#   scripts/openwrt-check.sh [VERSION...]     default: the versions in use
#
# Needs podman, ssh, the Rust target x86_64-unknown-linux-musl, and the
# wireguard kernel module on the host (`sudo modprobe wireguard`): containers
# share the host's kernel. SPLOT_CHECK_KEEP=1 keeps the containers for a look
# around (`podman exec -it splot-openwrt-<version> sh`).
# Commands in single quotes run in the container; their $ expands there.
# shellcheck disable=SC2016
set -euo pipefail

cd "$(dirname "$0")/.."

DEFAULT_VERSIONS=(24.10.2 25.12.2)
VERSIONS=("${@:-${DEFAULT_VERSIONS[@]}}")
TARGET=x86_64-unknown-linux-musl
BINARY=target/$TARGET/release/splot

# Cabin's endpoint in splot.example.yml, a name, and the address the container
# resolves it to. The name is changed to an address to test a live peer update.
CABIN_ENDPOINT=cabin.example.net
CABIN_ADDRESS=203.0.113.20

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

# splot carries the agent for the routers here (x86_64), as scripts/dist.sh
# builds it, and nothing else.
echo "Building splot for $TARGET, carrying the agent for it"
cargo build --quiet --package splot-agent --profile agent --target "$TARGET"
rm -rf target/check-agents
mkdir -p target/check-agents
cp "target/$TARGET/agent/splot-agent" target/check-agents/x86_64
SPLOT_AGENTS="$PWD/target/check-agents" cargo build --quiet --package splot --release --target "$TARGET"

# splot reaches the router as `router`: a host of an ssh config of the check's
# own, with a key of its own, through an `ssh` first on splot's PATH.
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/bin"
ssh-keygen -q -t ed25519 -N '' -C splot-check -f "$work/key"
# With $work/cut there, every session after the first fails, as if the router
# had gone out of reach: `cut`.
cat >"$work/bin/ssh" <<EOF
#!/bin/sh
if [ -f "$work/cut" ]; then
	n=\$(cat "$work/cut")
	echo \$((n + 1)) >"$work/cut"
	if [ "\$n" -ge 1 ]; then
		echo "ssh: router: cut off by the check" >&2
		exit 255
	fi
fi
exec $(command -v ssh) -F "$work/ssh_config" "\$@"
EOF
chmod +x "$work/bin/ssh"
cp splot.example.yml "$work/splot.example.yml"

# splot, as the operator runs it: here, reaching the router over ssh.
splot() { PATH="$work/bin:$PATH" "$BINARY" "$@" --ssh router; }
# Whether splot, run with the arguments after $1, says what $1 matches; it may
# fail doing so. Its output is read whole: `splot | grep -q` would read as
# failing under pipefail whenever splot does.
says() {
	local pattern=$1 output
	shift
	output=$(splot "$@" 2>&1) || true
	grep -q -- "$pattern" <<<"$output"
}

check_version() {
	local version=$1
	local image=localhost/splot-openwrt:$version
	local container=splot-openwrt-$version
	run() { podman exec "$container" sh -c "$1"; }
	# A preshared key, as `wg genpsk` makes one on the router. Given to splot
	# with <<<, not a pipe: splot may refuse before it reads its input, and the
	# pipe's writer failing would then read as splot failing (pipefail).
	psk() { run 'wg genpsk'; }

	echo
	echo "== OpenWrt $version"
	podman build --quiet --build-arg "OPENWRT_VERSION=$version" -t "$image" scripts/openwrt >/dev/null
	podman rm --force --ignore --time 0 "$container" >/dev/null
	# --privileged: rootless, so the extra capabilities apply inside the
	# container's own user namespace only. eth1: the WAN set up by prepare.sh.
	# Its ssh port is published on a free port of this machine's loopback.
	podman run --detach --name "$container" --privileged --network pasta:-I,eth1 \
		--publish 127.0.0.1::22 "$image" >/dev/null

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

	# The check's key may log in as root (dropbear), on the published port.
	podman cp "$work/key.pub" "$container:/etc/dropbear/authorized_keys"
	run 'chmod 600 /etc/dropbear/authorized_keys'
	cat >"$work/ssh_config" <<EOF
Host router
	HostName 127.0.0.1
	Port $(podman port "$container" 22/tcp | sed 's/.*://')
	User root
	IdentityFile $work/key
	IdentitiesOnly yes
	StrictHostKeyChecking no
	UserKnownHostsFile /dev/null
	LogLevel ERROR
EOF
	local reached=
	for _ in $(seq 30); do
		if PATH="$work/bin:$PATH" ssh router true 2>/dev/null; then
			reached=1
			break
		fi
		sleep 1
	done
	if [ -z "$reached" ]; then
		fail "ssh: the router lets the check in within 30 s" "$(run 'logread | grep -i dropbear | tail -10' 2>&1)"
		return
	fi

	# The example's endpoint name resolves through /etc/hosts: there's no public
	# DNS for it, and a name that doesn't resolve keeps the mesh interface down.
	run "echo '$CABIN_ADDRESS $CABIN_ENDPOINT' >>/etc/hosts"

	local log_lines output
	# Only init writes the router's key: until it has run, the dry run says so
	# and creates nothing.
	output=$(splot --config "$work/splot.example.yml" apply --node Home --dry-run 2>&1) || true
	if grep -q 'run `splot init' <<<"$output" && ! run '[ -e /etc/config/splot ]'; then
		pass "before init, the dry run asks for it and writes nothing"
	else
		fail "before init, the dry run asks for it and writes nothing" "$output"
	fi

	# init creates the key and says what to set for Home (the example has a
	# placeholder key). With this router's key put in, Home is initialised; as
	# Cabin, the key is someone else's (an error); with the placeholder back, the
	# key is in the config nowhere (an error too, now that it isn't new).
	local first initialised wrong stale pubkey
	first=$(splot --config "$work/splot.example.yml" init --node Home 2>&1) || true
	pubkey=$(run 'uci get splot.config.private_key | wg pubkey')
	sed "s|ReplaceHomePublicKeyA*=|$pubkey|" "$work/splot.example.yml" >"$work/splot.yml"
	initialised=$(splot --config "$work/splot.yml" init --node Home 2>&1) || true
	wrong=$(splot --config "$work/splot.yml" init --node Cabin 2>&1; echo "exit $?") || true
	stale=$(splot --config "$work/splot.example.yml" init --node Home 2>&1; echo "exit $?") || true
	if grep -q "Generated this peer's WireGuard key" <<<"$first" &&
		grep -qF "$pubkey" <<<"$first" &&
		grep -q "Home is already initialised" <<<"$initialised" &&
		grep -q "the one at nodes.Home.publicKey, so this peer isn't Cabin" <<<"$wrong" &&
		grep -q "exit 1" <<<"$wrong" &&
		grep -q "isn't in the config" <<<"$stale" &&
		grep -q "exit 1" <<<"$stale"; then
		pass "init: creates the key once; Home initialised; another node's key and an unknown key refused"
	else
		fail "init: creates the key once; Home initialised; another node's key and an unknown key refused" \
			"first: $first"$'\n'"initialised: $initialised"$'\n'"wrong: $wrong"$'\n'"stale: $stale"
	fi

	# A command acts as the node --node names once it has checked this peer is
	# that node: as Cabin, or as a node the config doesn't have, it refuses and
	# writes nothing.
	output=
	says "isn.t the one the config has for Cabin" --config "$work/splot.yml" apply --node Cabin --dry-run ||
		output="$output apply as Cabin;"
	says "isn.t the one the config has for Cabin" --config "$work/splot.yml" psk set --node Cabin Home <<<"$(psk)" ||
		output="$output psk set as Cabin;"
	says "no node Pond in the config; its nodes are Barn, Cabin, Home, Lake" \
		--config "$work/splot.yml" apply --node Pond --dry-run || output="$output apply as Pond;"
	if grep -q spl_psk_ <<<"$(run 'uci show splot')"; then output="$output stored a PSK anyway;"; fi
	if [ -n "$(run 'uci changes')" ]; then output="$output staged changes;"; fi
	if [ -z "$output" ]; then
		pass "as another node or one the config doesn't have, commands refuse"
	else
		fail "as another node or one the config doesn't have, commands refuse" "$output"
	fi

	# Every pair uses a preshared key unless an end turns it off (the example's
	# lte-cam does). Until they're stored, apply refuses, names the peers and
	# touches nothing.
	if output=$(splot --config "$work/splot.yml" apply --node Home --yes 2>&1); then
		fail "apply refuses while PSKs are missing" "$output"
	elif grep -q 'no preshared key stored for Barn, Cabin, Lake, Phone:' <<<"$output" &&
		[ "$(run 'uci show network | grep -c spl_')" = 0 ]; then
		pass "apply refuses while PSKs are missing"
	else
		fail "apply refuses while PSKs are missing" "$output"
	fi
	# psk set stores nothing for a name that isn't Home's peer, a pair with psk
	# turned off, or input that isn't a key.
	output=
	says "isn.t a peer of Home" --config "$work/splot.yml" psk set --node Home Cabin.camera <<<"$(psk)" ||
		output="$output not a peer;"
	says "uses no preshared key" --config "$work/splot.yml" psk set --node Home Home.lte-cam <<<"$(psk)" ||
		output="$output psk: false;"
	says "not a preshared key" --config "$work/splot.yml" psk set --node Home Cabin <<<"not a key" ||
		output="$output not a key;"
	if grep -q spl_psk_ <<<"$(run 'uci show splot')"; then output="$output stored one anyway;"; fi
	if [ -z "$output" ]; then
		pass "psk set refuses a non-peer, a pair without a PSK, and a non-key"
	else
		fail "psk set refuses a non-peer, a pair without a PSK, and a non-key" "$output"
	fi
	# One key per pair. The peers' ends aren't in this container. The key store
	# holds the private key and the PSKs, so only root may read it: init creates
	# it that way, and storing a PSK tightens one an older splot left readable.
	local store_created store_after peer
	store_created=$(run 'ls -l /etc/config/splot | cut -c1-10')
	run 'chmod 644 /etc/config/splot'
	for peer in Barn Cabin Lake Phone; do
		if ! output=$(splot --config "$work/splot.yml" psk set --node Home "$peer" <<<"$(psk)" 2>&1); then
			fail "psk set: Home's pair with $peer" "$output"
			return
		fi
	done
	store_after=$(run 'ls -l /etc/config/splot | cut -c1-10')
	if [ "$store_created" = "-rw-------" ] && [ "$store_after" = "-rw-------" ]; then
		pass "key store readable by root only (created so; tightened again from 644)"
	else
		fail "key store readable by root only" "created: $store_created, after psk set: $store_after"
	fi

	# What comes back to this machine holds no key from the router's key store:
	# the dry run shows each as its placeholder.
	output=$(splot --config "$work/splot.yml" apply --node Home --dry-run 2>&1) || true
	local key leaked=
	for key in $(run 'uci show splot' | cut -s -d"'" -f2); do
		grep -qF -- "$key" <<<"$output" && leaked="$leaked ${key:0:4}…;"
	done
	if [ -z "$leaked" ] && grep -q "private_key='<private key>'" <<<"$output"; then
		pass "the dry run, here, holds no key of the router's: placeholders only"
	else
		fail "the dry run, here, holds no key of the router's: placeholders only" "leaked:$leaked"$'\n'"$output"
	fi

	log_lines=$(run 'logread | wc -l')
	if output=$(splot --config "$work/splot.yml" apply --node Home --yes 2>&1); then
		pass "splot apply over ssh: $(sed -n 's/^== Home: //p' <<<"$output")"
	else
		fail "splot apply over ssh" "$output"
		return
	fi
	# splot reached the router again and confirmed: the run is over, and the
	# router keeps the change.
	if grep -q "^Confirmed: splot reached Home again" <<<"$output" &&
		! run '[ -e /tmp/splot/run ]' && run 'grep -q confirmed /tmp/splot/last'; then
		pass "the change is confirmed: no run left on the router"
	else
		fail "the change is confirmed: no run left on the router" "$output"$'\n'"$(run 'ls -l /tmp/splot; cat /tmp/splot/last' 2>&1)"
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

	# Every peer may ping the router on its mesh IP: fw4 takes the rule, and
	# it's live.
	output=$(run 'fw4 check 2>&1') || true
	if ! grep -q spl_rule_ping <<<"$output" && grep -q 'ping from its peers' <<<"$(run 'nft list ruleset')"; then
		pass "fw4 takes the peers' ping rule, and it's live"
	else
		fail "fw4 takes the peers' ping rule, and it's live" "$output"
	fi

	# Others dial the router (the example's Home has an endpoint): fw4 takes the
	# rule for its listen port, and the WAN lets the port in to the router.
	output=$(run 'fw4 check 2>&1') || true
	if ! grep -q spl_rule_listen_port <<<"$output" &&
		grep -q 'udp dport 51820 .*WireGuard listen port' <<<"$(run 'nft list chain inet fw4 input_wan')"; then
		pass "fw4 takes the listen port rule, and the WAN lets the port in"
	else
		fail "fw4 takes the listen port rule, and the WAN lets the port in" \
			"$output"$'\n'"$(run 'nft list chain inet fw4 input_wan' 2>&1)"
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
			address=$(uci -q get network.$i.addresses)
			ip -4 -o addr show dev $i | grep -q " ${address%% *} " || problems="$problems no address ${address:-?};"
			echo "$problems"')
		if [ -z "$output" ]; then
			pass "WireGuard $interface: up, peers, address"
		else
			fail "WireGuard $interface: up, peers, address" "$output"
		fi
	done

	# Cabin is dialled by name: WireGuard got the address the name resolves to.
	if run 'wg show spl_mesh endpoints' | grep -qF "$CABIN_ADDRESS:"; then
		pass "WireGuard dials a peer by name (resolved to $CABIN_ADDRESS)"
	else
		fail "WireGuard dials a peer by name (resolved to $CABIN_ADDRESS)" "$(run 'wg show spl_mesh endpoints' 2>&1)"
	fi

	# Each pair's preshared key in WireGuard is the stored one; the camera's pair
	# has none.
	output=$(run '
		psk_of() {
			key=$(uci -q get network.spl_wireguard_spl_mesh_$1.public_key)
			wg show spl_mesh preshared-keys | awk -v k="$key" "\$1 == k { print \$2 }"
		}
		problems=
		for peer in Barn Cabin Lake Phone; do
			want=$(uci -q get splot.spl_psk_$peer.key)
			[ -n "$want" ] && [ "$(psk_of $peer)" = "$want" ] || problems="$problems $peer;"
		done
		[ "$(psk_of lte_cam)" = "(none)" ] || problems="$problems lte-cam;"
		echo "$problems"')
	if [ -z "$output" ]; then
		pass "WireGuard pairs have their stored PSKs (none where turned off)"
	else
		fail "WireGuard pairs have their stored PSKs (none where turned off)" "wrong:$output"
	fi

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

	local before after nothing
	# The plan of a node with nothing to change: the dry run and apply both end
	# there.
	nothing="== Home: nothing to change"$'\n'"Nothing to change."
	# Applying an unchanged config stages nothing, so uci rewrites no file.
	# stdout only: the log goes to stderr.
	output=$(splot --config "$work/splot.yml" apply --node Home --dry-run 2>/dev/null) || true
	if [ "$output" = "$nothing" ]; then
		pass "dry run of an unchanged node stages nothing"
	else
		fail "dry run of an unchanged node stages nothing" "$output"
	fi

	# A commit writes a new file over the old one: its inode changes. (BusyBox
	# here has no stat.) With nothing to apply, no run begins: the last run is
	# still the one before.
	local files='/etc/config/network /etc/config/firewall /etc/config/dhcp'
	before=$(run "ls -i $files; md5sum $files; cat /tmp/splot/last")
	output=$(splot --config "$work/splot.yml" apply --node Home --yes 2>&1) || true
	after=$(run "ls -i $files; md5sum $files; cat /tmp/splot/last")
	if [ "$(printf '%s' "$output" | tail -2)" = "$nothing" ] && [ "$before" = "$after" ] &&
		! run '[ -e /tmp/splot/run ]'; then
		pass "second apply changes nothing, files untouched, no run begun"
	else
		fail "second apply changes nothing, files untouched, no run begun" \
			"$output"$'\n'"before: $before"$'\n'"after: $after"$'\n'"$(run 'ls /tmp/splot' 2>&1)"
	fi

	# A peer change: Cabin's endpoint moves. WireGuard must see it without a reboot.
	local renew
	renew=$(run 'ubus call network get_proto_handlers | jsonfilter -e @.wireguard.renew_available')
	before=$(run 'cat /sys/class/net/spl_mesh/ifindex 2>/dev/null') || true
	sed -i "s/$CABIN_ENDPOINT/203.0.113.21/" "$work/splot.yml"
	# Only that peer's endpoint is staged, then the network file is committed.
	output=$(splot --config "$work/splot.yml" apply --node Home --dry-run 2>/dev/null | grep -v '^#') || true
	expected="== Home: network"$'\n'"set network.spl_wireguard_spl_mesh_Cabin.endpoint_host='203.0.113.21'"$'\n'"commit network"
	if [ "$output" = "$expected" ]; then
		pass "peer change stages only that peer"
	else
		fail "peer change stages only that peer" "$output"
	fi
	if ! output=$(splot --config "$work/splot.yml" apply --node Home --yes 2>&1); then
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

	# A PSK change: Cabin's pair gets a new key. Only that option is staged, the
	# dry run shows its placeholder, and WireGuard gets the new key.
	splot --config "$work/splot.yml" psk set --node Home Cabin <<<"$(psk)" >/dev/null
	output=$(splot --config "$work/splot.yml" apply --node Home --dry-run 2>/dev/null | grep -v '^#') || true
	expected="== Home: network"$'\n'"set network.spl_wireguard_spl_mesh_Cabin.preshared_key='<preshared key>'"$'\n'"commit network"
	if [ "$output" = "$expected" ]; then
		pass "PSK change stages only that key, shown as its placeholder"
	else
		fail "PSK change stages only that key, shown as its placeholder" "$output"
	fi
	if ! output=$(splot --config "$work/splot.yml" apply --node Home --yes 2>&1); then
		fail "PSK update: apply" "$output"
	else
		sleep 3
		if run 'wg show spl_mesh preshared-keys | grep -qF "$(uci get splot.spl_psk_Cabin.key)"'; then
			pass "PSK update reaches WireGuard"
		else
			fail "PSK update reaches WireGuard"
		fi
	fi

	# The router keeps a change only once splot reaches it again: cut off after
	# the apply, it puts back what it had by itself at the deadline. splot waits
	# for the deadline; meanwhile the change is there, and the router is let in
	# again, so splot, asking after the deadline, finds it put back.
	local cut_before cut_applied cut_after status last waiting
	sed 's/port: 22$/port: 2222/' "$work/splot.yml" >"$work/splot-cut.yml"
	cut_before=$(run "md5sum $files")
	echo 0 >"$work/cut"
	splot --config "$work/splot-cut.yml" apply --node Home --yes --confirm-within 10 >"$work/cut.out" 2>&1 &
	waiting=$!
	for _ in $(seq 40); do
		if grep -q 'waiting for its deadline' "$work/cut.out"; then break; fi
		sleep 0.5
	done
	cut_applied=$(run "md5sum $files")
	rm -f "$work/cut"
	wait "$waiting" && status=0 || status=$?
	output=$(cat "$work/cut.out")
	cut_after=$(run "md5sum $files")
	last=$(run 'cat /tmp/splot/last 2>&1') || true
	if [ "$status" -ne 0 ] && grep -q "^Couldn't check Home: " <<<"$output" &&
		grep -q '^  Home  unreachable: waiting for its deadline' <<<"$output" &&
		grep -q '^  Home  put back by itself$' <<<"$output" &&
		grep -q "splot couldn't check Home, so Home didn't keep it" <<<"$output" &&
		[ "$cut_applied" != "$cut_before" ] && [ "$cut_after" = "$cut_before" ] &&
		grep -q "rolled back" <<<"$last" && ! run '[ -e /tmp/splot/run ]'; then
		pass "cut off before the confirm: the router put back what it had at the deadline, splot waited and saw it"
	else
		fail "cut off before the confirm: the router put back what it had at the deadline, splot waited and saw it" \
			"exit $status: $output"$'\n'"last: $last"$'\n'"before: $cut_before"$'\n'"applied: $cut_applied"$'\n'"after: $cut_after"
	fi
	sleep 3

	# Concerns left alone: with `firewall: none` and `dhcp: none` on Home, splot
	# renders neither file, so it stages, deletes, commits and reloads nothing
	# there, though the config changes what both would hold (the ssh port, the
	# printer's MAC). Its sections from before stay as they were.
	awk '!done && /^      os: openwrt$/ { print; print "      firewall: none"; print "      dhcp: none"; done = 1; next } 1' \
		"$work/splot.yml" | sed 's/port: 22$/port: 2222/; s/aa:bb:cc:00:00:02/aa:bb:cc:00:00:12/' >"$work/splot-none.yml"
	local left_alone='/etc/config/firewall /etc/config/dhcp'
	before=$(run "ls -i $left_alone; md5sum $left_alone")
	local sections dry_run
	sections=$(run "uci show firewall | grep -c '^firewall\.spl_[^.]*='; uci show dhcp | grep -c '^dhcp\.spl_[^.]*='" | paste -sd' ')
	dry_run=$(splot --config "$work/splot-none.yml" apply --node Home --dry-run 2>/dev/null) || true
	output=$(splot --config "$work/splot-none.yml" apply --node Home --yes 2>&1) || true
	after=$(run "ls -i $left_alone; md5sum $left_alone")
	if [ "$dry_run" = "$nothing" ] && [ "$(printf '%s' "$output" | tail -2)" = "$nothing" ] &&
		[ "$before" = "$after" ] && ! printf '%s' "$sections" | grep -qw 0; then
		pass "concerns left alone (none): their files untouched, splot's sections kept ($sections)"
	else
		fail "concerns left alone (none): their files untouched" "dry run: $dry_run"$'\n'"$output"$'\n'"sections: $sections"$'\n'"before: $before"$'\n'"after: $after"
	fi

	# A node whose WireGuard splot leaves alone (`wireguard: none`, so no hub) is
	# known by its own WireGuard. As Cabin, no interface here has Cabin's key:
	# apply refuses and writes nothing. As Home, spl_mesh has Home's key: apply
	# runs, and leaves the network file alone. init has nothing to create.
	awk '/^      os: openwrt$/ && n++ < 2 { print; print "      wireguard: none"; next }
		/^    hub:$/ { skip = 1 } skip && /^$/ { skip = 0 } !skip' "$work/splot.yml" >"$work/splot-own-wg.yml"
	local all_files='/etc/config/network /etc/config/firewall /etc/config/dhcp'
	local network_before refused_before refused_after
	network_before=$(run 'ls -i /etc/config/network; md5sum /etc/config/network')
	refused_before=$(run "ls -i $all_files; md5sum $all_files")
	output=$(says "none of this peer.s WireGuard interfaces has the key the config has for Cabin" \
		--config "$work/splot-own-wg.yml" apply --node Cabin --yes || echo "as Cabin: not refused;")
	refused_after=$(run "ls -i $all_files; md5sum $all_files")
	splot --config "$work/splot-own-wg.yml" apply --node Home --yes >/dev/null 2>&1 || output="$output as Home: refused;"
	says "nothing to initialise" --config "$work/splot-own-wg.yml" init --node Home || output="$output init;"
	if [ -z "$output" ] && [ "$refused_before" = "$refused_after" ] &&
		[ "$network_before" = "$(run 'ls -i /etc/config/network; md5sum /etc/config/network')" ]; then
		pass "WireGuard left alone: the node is known by its own interface's key (as Cabin refused, as Home applied, network untouched)"
	else
		fail "WireGuard left alone: the node is known by its own interface's key" "$output"
	fi

	# The node removed the agent each time the session ended.
	output=$(run 'ls /tmp/splot-agent.* 2>/dev/null') || true
	if [ -z "$output" ]; then
		pass "no agent left in the router's /tmp"
	else
		fail "no agent left in the router's /tmp" "$output"
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
