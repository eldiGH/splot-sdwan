#!/bin/sh
# Turns an OpenWrt rootfs image into a test router for scripts/openwrt-check.sh.
# Runs once, inside the image, while it is built.
set -e

# WireGuard tools. OpenWrt 25.12+ uses apk, older releases opkg. opkg's
# downloader (uclient-fetch) tries IPv6 first and doesn't fall back when the
# container has no IPv6 route, so it's forced to IPv4 for the install.
if command -v apk >/dev/null; then
	apk update
	apk add wireguard-tools
else
	mkdir -p /var/lock
	mv /usr/bin/wget /usr/bin/wget.orig
	printf '#!/bin/sh\nexec uclient-fetch -4 "$@"\n' >/usr/bin/wget
	chmod +x /usr/bin/wget
	opkg update
	opkg install wireguard-tools
	rm /usr/bin/wget
	mv /usr/bin/wget.orig /usr/bin/wget
fi

# AppArmor matches profiles by executable path, and the host's profile for
# /usr/sbin/dnsmasq (if it has one) confines the container's dnsmasq too: it may
# then read only the host's usual config paths. Running it from another path
# keeps it out of that profile.
mv /usr/sbin/dnsmasq /usr/lib/dnsmasq-bin
ln -s /usr/lib/dnsmasq-bin /usr/sbin/dnsmasq

# procd sandboxes some services (dnsmasq among them) with ujail, which needs
# device nodes that a rootless container can't create. Without ujail, procd runs
# them unsandboxed.
rm -f /sbin/ujail

# A WAN with a default route, as on a real router: netifd brings a WireGuard
# interface up only once it has a route to every peer endpoint. The container's
# network interface is named eth1 (see openwrt-check.sh), and podman's network
# (pasta) answers DHCP on it. uci-defaults run at first boot, after OpenWrt has
# generated its default network config.
cat >/etc/uci-defaults/99-splot-test-wan <<'EOF'
uci set network.wan=interface
uci set network.wan.device=eth1
uci set network.wan.proto=dhcp
uci commit network
EOF
