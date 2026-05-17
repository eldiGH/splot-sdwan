use std::collections::HashMap;

use crate::{
    config::Config,
    validator::types::{ConfigPath, ValidationError, ValidationReport},
};

pub(super) fn check_ports(config: &Config, report: &mut ValidationReport) {
    for (node_name, node) in &config.nodes {
        let make_path = || ConfigPath::new(["nodes", node_name]);

        let mut ports = HashMap::new();
        ports.insert(node.listen_port, make_path().extend(["listenPort"]));

        for (vpn_interface_name, vpn_interface) in &node.vpn_interfaces {
            let make_path =
                || make_path().extend(["vpnInterfaces", vpn_interface_name, "listenPort"]);

            if let Some(other_path) = ports.get(&vpn_interface.listen_port) {
                report.errors.push(ValidationError::PortCollision {
                    port: vpn_interface.listen_port,
                    at: make_path(),
                    with: other_path.clone(),
                })
            } else {
                ports.insert(vpn_interface.listen_port, make_path());
            }
        }
    }
}
