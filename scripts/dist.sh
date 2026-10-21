#!/usr/bin/env bash
# Builds splot for release: its agent for every CPU it supports, small enough
# to run from a router's RAM, then splot itself (static, x86_64) carrying them,
# so it's one file that sends each node it reaches over ssh the agent it needs.
#
#   scripts/dist.sh        → target/dist/splot (and target/agents/<cpu>)
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

SPLOT_AGENTS="$PWD/target/agents" \
	cargo build --quiet --package splot --release --target x86_64-unknown-linux-musl
mkdir -p target/dist
cp target/x86_64-unknown-linux-musl/release/splot target/dist/splot
# Every agent is inside, byte for byte: the linker drops what nothing uses.
python3 -c '
import sys
splot = open(sys.argv[1], "rb").read()
missing = [path for path in sys.argv[2:] if open(path, "rb").read() not in splot]
sys.exit("Not inside splot: " + ", ".join(missing) if missing else 0)
' target/dist/splot target/agents/*
echo "splot:     $(stat -c %s target/dist/splot) bytes, target/dist/splot"
target/dist/splot --version
