use std::net::Ipv4Addr;

use crate::{
    config::{Config, Service},
    managers::{UciSectionBuilder, firewall::consts::FIREWALL_FILE_NAME},
    naming,
    protocol::Protocols,
    types::{
        identifier::Identifier, ip::Ipv4Network, port::PortOrRange, wan_via_target::WanViaTarget,
        zone_ref::ZoneRef,
    },
    uci::UciBatchCommand,
};

pub struct FirewallRedirect {
    pub name: String,
    pub proto: Protocols,
    pub src: ZoneRef,
    pub src_dport: PortOrRange,
    pub src_ip: Vec<Ipv4Network>,
    pub dest_ip: Ipv4Addr,
    pub dest_port: PortOrRange,
    pub dest: ZoneRef,
}

impl FirewallRedirect {
    pub fn to_uci_commands(&self) -> Vec<UciBatchCommand> {
        UciSectionBuilder::new(FIREWALL_FILE_NAME, &self.name, "redirect")
            .set("name", naming::name_prefixed(&self.name))
            .set("target", "DNAT")
            .set("src", self.src.to_string())
            .set("src_dport", self.src_dport.to_string())
            .extend_list("src_ip", &self.src_ip)
            .set("dest", self.dest.to_string())
            .set("dest_ip", self.dest_ip.to_string())
            .set("dest_port", self.dest_port.to_string())
            .extend_list("proto", &self.proto)
            .build()
    }
}

struct RedirectBuilder<'a> {
    config: &'a Config,
    own_name: &'a Identifier,
    wan_zone: &'a ZoneRef,
}

impl RedirectBuilder<'_> {
    fn local_service_redirect(
        &self,
        service_name: &Identifier,
        service: &Service,
        dest_zone: ZoneRef,
        dest_ip: Ipv4Addr,
        owner_name: &Identifier,
        node_name: &Identifier,
    ) -> Option<FirewallRedirect> {
        let wan = service.wan.as_ref()?;

        if !wan
            .via
            .iter()
            .any(|via| matches!(via, WanViaTarget::Bare(node) if node == self.own_name))
        {
            return None;
        }

        let name = if node_name == owner_name {
            format!("{owner_name}_{service_name}_redirect")
        } else {
            format!("{node_name}_{owner_name}_{service_name}_redirect")
        };

        Some(FirewallRedirect {
            name,
            dest: dest_zone,
            dest_ip,
            dest_port: service.port.internal(),
            proto: service.proto.clone().into(),
            src: self.wan_zone.clone(),
            src_dport: service.port.external(),
            src_ip: wan.sources.iter().cloned().collect(),
        })
    }

    fn local_redirects(&self, redirects: &mut Vec<FirewallRedirect>) {
        for (node_name, node) in &self.config.nodes {
            for (service_name, service) in &node.services {
                redirects.extend(self.local_service_redirect(
                    service_name,
                    service,
                    ZoneRef::Mesh,
                    node.mesh_ip,
                    node_name,
                    node_name,
                ))
            }

            for (zone_name, zone) in &node.zones {
                for (device_name, device) in &zone.devices {
                    for (service_name, service) in &device.services {
                        redirects.extend(self.local_service_redirect(
                            service_name,
                            service,
                            ZoneRef::Named(zone_name.clone()),
                            device.ip,
                            device_name,
                            node_name,
                        ));
                    }
                }
            }

            for (vpn_interface_name, vpn_interface) in &node.vpn_interfaces {
                for (client_name, client) in &vpn_interface.clients {
                    for (service_name, service) in &client.services {
                        redirects.extend(self.local_service_redirect(
                            service_name,
                            service,
                            ZoneRef::Named(vpn_interface_name.clone()),
                            client.ip,
                            client_name,
                            node_name,
                        ))
                    }
                }
            }
        }
    }

    fn client_redirects(&self, redirects: &mut Vec<FirewallRedirect>) {
        let node = self
            .config
            .nodes
            .get(self.own_name)
            .expect("own node not found — config should be validated before calling managers");

        for (client_name, client) in &self.config.clients {
            for (service_name, service) in &client.services {
                let Some(wan) = &service.wan else { continue };

                for via in &wan.via {
                    if via.node() != self.own_name {
                        continue;
                    }

                    let Ok(resolution) = client.resolve_wan_target(via, node) else {
                        continue;
                    };

                    redirects.push(FirewallRedirect {
                        name: format!("{client_name}_{service_name}_redirect"),
                        proto: service.proto.clone().into(),
                        src: self.wan_zone.clone(),
                        src_dport: service.port.external(),
                        src_ip: wan.sources.iter().cloned().collect(),
                        dest: resolution.dest_zone,
                        dest_ip: resolution.dest_ip,
                        dest_port: service.port.internal(),
                    })
                }
            }
        }
    }
}

pub fn get_firewall_redirects(config: &Config, own_name: &Identifier) -> Vec<FirewallRedirect> {
    let mut redirects: Vec<FirewallRedirect> = vec![];

    let Some(wan_zone) = config
        .nodes
        .get(own_name)
        .and_then(|node| node.wan_zone.as_ref())
        .map(|id| ZoneRef::Named(id.clone()))
    else {
        return redirects;
    };

    let builder = RedirectBuilder {
        config,
        own_name,
        wan_zone: &wan_zone,
    };

    builder.local_redirects(&mut redirects);
    builder.client_redirects(&mut redirects);

    redirects
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::config;

    // Home: wanZone=wan, meshIp=10.100.0.1
    //   services: ssh(22/tcp via Home), restricted(8443/tcp via Home, sources=[1.2.3.0/24,5.6.0.0/16]), translated(8080:80/tcp via Home)
    //   zone lan (192.168.1.1/24) → device printer(192.168.1.50) → service print(9100/tcp via Home)
    //   vpnInterface vpn_a(10.8.1.1/24) → client alice(10.8.1.10) → service vnc(5900/tcp via Home)
    // Cabin: no wanZone, meshIp=10.100.0.2
    //   services: ssh(22/tcp via Home) ← regression test target
    // Phone: meshIp=10.100.0.100
    //   services: http(80/tcp via Home)
    const FIXTURE: &str = "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    publicKey: AAAA
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    wanZone: wan
    zones:
      lan:
        address: 192.168.1.1/24
        devices:
          printer:
            ip: 192.168.1.50
            macs: AA:BB:CC:DD:EE:FF
            services:
              print:
                port: 9100
                proto: tcp
                wan:
                  via: Home
    vpnInterfaces:
      vpn_a:
        listenPort: 51821
        address: 10.8.1.1/24
        clients:
          alice:
            publicKey: BBBB
            ip: 10.8.1.10
            services:
              vnc:
                port: 5900
                proto: tcp
                wan:
                  via: Home
    services:
      ssh:
        port: 22
        proto: tcp
        wan:
          via: Home
      restricted:
        port: 8443
        proto: tcp
        wan:
          via: Home
          sources:
            - 1.2.3.0/24
            - 5.6.0.0/16
      translated:
        port: \"8080:80\"
        proto: tcp
        wan:
          via: Home
  Cabin:
    publicKey: CCCC
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
    services:
      ssh:
        port: 22
        proto: tcp
        wan:
          via: Home
clients:
  Phone:
    publicKey: DDDD
    meshIp: 10.100.0.100
    services:
      http:
        port: 80
        proto: tcp
        wan:
          via: Home
";

    fn id(s: &str) -> Identifier {
        s.parse().unwrap()
    }

    fn redirects_for(own: &str) -> Vec<FirewallRedirect> {
        let cfg = config(FIXTURE);
        get_firewall_redirects(&cfg, &id(own))
    }

    fn find<'a>(rs: &'a [FirewallRedirect], name: &str) -> Option<&'a FirewallRedirect> {
        rs.iter().find(|r| r.name == name)
    }

    fn has_uci(r: &FirewallRedirect, s: &str) -> bool {
        r.to_uci_commands()
            .iter()
            .any(|c| c.to_string().contains(s))
    }

    #[test]
    fn no_wan_zone_returns_empty() {
        // Cabin has no wanZone → no redirects generated.
        assert!(redirects_for("Cabin").is_empty());
    }

    #[test]
    fn node_service_redirect_name_dest_and_src() {
        let rs = redirects_for("Home");
        let r = find(&rs, "Home_ssh_redirect").expect("Home_ssh_redirect missing");
        assert_eq!(r.dest_ip.to_string(), "10.100.0.1");
        assert_eq!(r.dest, ZoneRef::Mesh);
        assert_eq!(r.src, ZoneRef::Named(id("wan")));
    }

    #[test]
    fn device_service_redirect() {
        let rs = redirects_for("Home");
        let r = find(&rs, "Home_printer_print_redirect").expect("printer redirect missing");
        assert_eq!(r.dest_ip.to_string(), "192.168.1.50");
        assert_eq!(r.dest, ZoneRef::Named(id("lan")));
    }

    #[test]
    fn vpn_client_service_redirect() {
        let rs = redirects_for("Home");
        let r = find(&rs, "Home_alice_vnc_redirect").expect("alice vpn redirect missing");
        assert_eq!(r.dest_ip.to_string(), "10.8.1.10");
        assert_eq!(r.dest, ZoneRef::Named(id("vpn_a")));
    }

    #[test]
    fn cross_node_naming_regression() {
        // Cabin hosts a service exposed via Home. Generating for Home should produce
        // "Cabin_ssh_redirect" — NOT "Cabin_Home_ssh_redirect" (the old owner_name bug).
        let rs = redirects_for("Home");
        assert!(
            find(&rs, "Cabin_ssh_redirect").is_some(),
            "correct name missing"
        );
        assert!(
            find(&rs, "Cabin_Home_ssh_redirect").is_none(),
            "buggy name must not appear"
        );
        let r = find(&rs, "Cabin_ssh_redirect").unwrap();
        assert_eq!(r.dest_ip.to_string(), "10.100.0.2");
        assert_eq!(r.dest, ZoneRef::Mesh);
    }

    #[test]
    fn global_client_redirect() {
        let rs = redirects_for("Home");
        let r = find(&rs, "Phone_http_redirect").expect("Phone redirect missing");
        assert_eq!(r.dest_ip.to_string(), "10.100.0.100");
        assert_eq!(r.dest, ZoneRef::Mesh);
    }

    #[test]
    fn sources_empty_no_src_ip_in_uci() {
        // ssh has no wan.sources → publicly reachable → no src_ip line.
        let rs = redirects_for("Home");
        let r = find(&rs, "Home_ssh_redirect").unwrap();
        assert!(
            !has_uci(r, "src_ip"),
            "unexpected src_ip in public redirect"
        );
    }

    #[test]
    fn sources_set_appear_sorted_in_uci() {
        let rs = redirects_for("Home");
        let r = find(&rs, "Home_restricted_redirect").expect("restricted redirect missing");
        let cmds: Vec<String> = r.to_uci_commands().iter().map(|c| c.to_string()).collect();
        let src_ips: Vec<&str> = cmds
            .iter()
            .filter(|c| c.contains("src_ip"))
            .map(|s| s.as_str())
            .collect();
        assert_eq!(src_ips.len(), 2, "expected 2 src_ip entries");
        // sorted lexicographically: "1.2.3.0/24" < "5.6.0.0/16"
        assert!(src_ips[0].contains("1.2.3.0/24"));
        assert!(src_ips[1].contains("5.6.0.0/16"));
    }

    #[test]
    fn port_translation_external_internal() {
        // "8080:80" → src_dport=8080 (external), dest_port=80 (internal)
        let rs = redirects_for("Home");
        let r = find(&rs, "Home_translated_redirect").expect("translated redirect missing");
        assert!(has_uci(r, "src_dport='8080'"));
        assert!(has_uci(r, "dest_port='80'"));
    }

    #[test]
    fn service_via_other_node_skipped_here() {
        // Edge hosts `ssh` exposed via Gate (not Edge). The redirect belongs on Gate,
        // never on Edge — this exercises the `via.node() == own_name` filter directly.
        let cfg = config(
            "
meshNetwork: 10.100.0.0/24
nodes:
  Edge:
    publicKey: AAAA
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    wanZone: wan
    services:
      ssh:
        port: 22
        proto: tcp
        wan:
          via: Gate
  Gate:
    publicKey: BBBB
    endpoint: 5.6.7.8
    listenPort: 51820
    meshIp: 10.100.0.2
    wanZone: wan
",
        );

        // Generating for Edge: ssh is via Gate, so nothing is emitted on Edge.
        assert!(
            get_firewall_redirects(&cfg, &id("Edge"))
                .iter()
                .all(|r| !r.name.contains("ssh")),
            "service via Gate must not produce a redirect on Edge"
        );

        // Generating for Gate: the redirect appears, pointing at Edge over the mesh.
        let on_gate = get_firewall_redirects(&cfg, &id("Gate"));
        let r = find(&on_gate, "Edge_ssh_redirect").expect("Edge_ssh_redirect missing on Gate");
        assert_eq!(r.dest, ZoneRef::Mesh);
        assert_eq!(r.dest_ip.to_string(), "10.100.0.1");
    }
}
