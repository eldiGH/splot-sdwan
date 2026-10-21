#!/usr/bin/env bash
# Builds splot's agent for every CPU it supports, small enough to run from a
# router's RAM. splot will carry them, and copy each node the one it needs.
#
#   scripts/dist.sh        → target/agents/<cpu>
#
# Needs the Rust targets below: rustup target add <target>. The agent is pure
# Rust, statically linked against the musl Rust ships, so Rust's own linker
# (rust-lld) links it for every CPU: no cross toolchains.
set -euo pipefail

cd "$(dirname "$0")/.."

# The CPU an agent runs on, as splot names it, its Rust target, and what runs
# it here: qemu-user for another CPU, if it's installed (just a smoke test).
AGENTS=(
	"aarch64 aarch64-unknown-linux-musl qemu-aarch64"
	"armv7 armv7-unknown-linux-musleabihf qemu-arm"
	"riscv64 riscv64gc-unknown-linux-musl qemu-riscv64"
	"x86_64 x86_64-unknown-linux-musl"
)
# The agent runs from a router's RAM (/tmp): it has to stay small.
LIMIT=$((1024 * 1024))

rm -rf target/agents
mkdir -p target/agents
echo "Agents (profile agent):"
for agent in "${AGENTS[@]}"; do
	read -r cpu target runner <<<"$agent"
	prefix=CARGO_TARGET_$(echo "$target" | tr 'a-z-' 'A-Z_')
	# Static on every target: riscv64's links dynamically by default.
	env "${prefix}_LINKER=rust-lld" "${prefix}_RUSTFLAGS=-C target-feature=+crt-static" \
		cargo build --quiet --package splot-agent --profile agent --target "$target"
	cp "target/$target/agent/splot-agent" "target/agents/$cpu"
	size=$(stat -c %s "target/agents/$cpu")
	# It answers a request: built right for its CPU, statically linked.
	if [ -z "${runner:-}" ] || command -v "$runner" >/dev/null; then
		answer=$(echo '"Os"' | ${runner:-} "target/agents/$cpu")
		if [ "$answer" != '{"Os":"linux"}' ]; then
			echo "The $cpu agent doesn't answer: $answer" >&2
			exit 1
		fi
		ran=", answers"
	else
		ran=" (no $runner here to run it)"
	fi
	printf '  %-8s %8d bytes%s\n' "$cpu" "$size" "$ran"
	if [ "$size" -gt "$LIMIT" ]; then
		echo "The $cpu agent is over 1 MB." >&2
		exit 1
	fi
done
