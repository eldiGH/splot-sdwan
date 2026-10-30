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

# A second zone of the operator's, as splot.example.yml's Home has: a network on
# a bridge with no ports (it comes up all the same), and its firewall zone.
cat >/etc/uci-defaults/99-splot-test-iot <<'EOF'
uci set network.br_iot=device
uci set network.br_iot.type=bridge
uci set network.br_iot.name=br-iot
uci set network.br_iot.bridge_empty=1
uci set network.iot=interface
uci set network.iot.device=br-iot
uci set network.iot.proto=static
uci set network.iot.ipaddr=192.168.10.1
uci set network.iot.netmask=255.255.255.0
uci commit network
uci add firewall zone
uci set firewall.@zone[-1].name=iot
uci set firewall.@zone[-1].input=REJECT
uci set firewall.@zone[-1].output=ACCEPT
uci set firewall.@zone[-1].forward=REJECT
uci add_list firewall.@zone[-1].network=iot
uci commit firewall
EOF

# splot reaches the router over ssh (dropbear), at a port podman publishes on
# this machine's loopback. pasta splices such a connection: it makes one of its
# own to the port, inside the router, which comes in on the router's loopback,
# and fw4 lets in whatever does. A router whose pasta doesn't splice
# (mesh-check.sh's Home) gets it on the WAN, from the gateway's address: let it
# in there, as an operator's own rule.
cat >/etc/uci-defaults/99-splot-test-ssh <<'EOF'
uci add firewall rule
uci set firewall.@rule[-1].name='Allow-SSH-for-splot-check'
uci set firewall.@rule[-1].src='wan'
uci set firewall.@rule[-1].proto='tcp'
uci set firewall.@rule[-1].dest_port='22'
uci set firewall.@rule[-1].target='ACCEPT'
uci commit firewall
EOF
