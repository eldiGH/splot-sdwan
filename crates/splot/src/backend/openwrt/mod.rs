//! OpenWrt: the plan as uci config, file by file. The agent on the node stages
//! and commits it with uci, and reloads the services.

mod dhcp;
mod firewall;
mod naming;
mod network;
mod section;

use log::info;
use splot_core::protocol::openwrt::Rendered;

use crate::plan::NodePlan;

/// The plan as uci sections, file by file in the order they're committed, with
/// placeholders where its secrets go. Only the files of the concerns splot
/// manages on the node: one it leaves alone keeps its file as it is, splot's
/// own old sections included.
pub fn render(plan: &NodePlan) -> Rendered {
    info!("Rendering the uci config of node '{}'", plan.node);
    let mut files = Vec::new();
    let mut secrets = Vec::new();

    if let Some(wireguard) = &plan.wireguard {
        let (network, slots) = network::render(wireguard);
        files.push((network::FILE.to_owned(), network));
        secrets = slots;
    }
    if let Some(firewall) = &plan.firewall {
        files.push((firewall::FILE.to_owned(), firewall::render(firewall)));
    }
    if let Some(dhcp) = &plan.dhcp {
        files.push((dhcp::FILE.to_owned(), dhcp::render(dhcp)));
    }

    Rendered {
        node: plan.node.clone(),
        public_key: plan.public_key.clone(),
        wireguard: plan.wireguard.is_some(),
        files,
        secrets,
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write;

    use splot_core::uci::{
        export,
        section::{Section, Value},
    };

    use super::*;
    use crate::{
        model::{Network, node::Node},
        plan, test_support,
        types::platform::Os,
    };

    /// The example config, and its nodes that run OpenWrt: the ones this
    /// backend renders.
    fn example() -> Network {
        test_support::checked(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../splot.example.yml"
        )))
    }

    fn openwrt_nodes(network: &Network) -> impl Iterator<Item = &Node> {
        network
            .nodes()
            .filter(|node| node.platform().os() == Os::OpenWrt)
    }

    // ── Snapshot of everything generated for the example config ────────────
    //
    // Pins the complete uci output for every node of `splot.example.yml`, so any
    // change to what's planned or how it's rendered shows up as a reviewable diff
    // of the generated router config (`cargo insta review`). It records today's
    // output as-is, known-wrong parts included: a fix shows up as a snapshot diff.
    // Keys are fakes; the delete/commit lines need uci and are not part of it.

    #[test]
    fn a_concern_splot_leaves_alone_has_no_file() {
        // Nothing rendered for it means nothing staged, deleted, committed or
        // reloaded there: apply works through the rendered files only.
        let rendered = |platform: &str| {
            let network = test_support::checked(&format!(
                "
meshNetwork: 10.100.0.0/16
nodes:
  Home:
    platform:
      os: openwrt
{platform}
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
"
            ));
            let plan = plan::plan(&network, &"Home".parse().unwrap()).unwrap();
            render(&plan)
        };

        let all = rendered("");
        assert_eq!(all.files(), ["network", "firewall", "dhcp"]);
        assert_eq!(all.secrets.len(), 1);
        assert!(all.wireguard);

        let network_only = rendered("      firewall: none\n      dhcp: none");
        assert_eq!(network_only.files(), ["network"]);
        assert_eq!(network_only.secrets.len(), 1);
        assert_eq!(
            rendered("      firewall: none").files(),
            ["network", "dhcp"]
        );
        assert_eq!(
            rendered("      dhcp: none").files(),
            ["network", "firewall"]
        );

        // Without WireGuard, no key to fill in either, and the node's own
        // WireGuard says it's this peer.
        let no_wireguard = rendered("      wireguard: none");
        assert_eq!(no_wireguard.files(), ["firewall", "dhcp"]);
        assert!(no_wireguard.secrets.is_empty());
        assert!(!no_wireguard.wireguard);
        assert_eq!(
            no_wireguard.public_key.as_str(),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        );
    }

    #[test]
    fn every_slot_holds_its_placeholder_and_every_placeholder_has_a_slot() {
        let network = example();

        for node in openwrt_nodes(&network) {
            let rendered = render(&plan::plan(&network, node.name()).unwrap());
            assert!(!rendered.secrets.is_empty());

            let mut placeholders = 0;
            for (file, sections) in &rendered.files {
                for section in sections {
                    for (option, value) in &section.options {
                        let slot = rendered.secrets.iter().find(|slot| {
                            slot.file == *file
                                && slot.section == section.name
                                && slot.option == *option
                        });
                        let is_placeholder = |value: &str| {
                            rendered
                                .secrets
                                .iter()
                                .any(|slot| slot.secret.placeholder() == value)
                        };
                        match (slot, value) {
                            (Some(slot), Value::Single(value)) => {
                                assert_eq!(value, slot.secret.placeholder());
                                placeholders += 1;
                            }
                            (Some(slot), Value::List(_)) => panic!("{slot:?} is a list"),
                            (None, Value::Single(value)) => {
                                assert!(!is_placeholder(value), "{file}.{}.{option}", section.name)
                            }
                            (None, Value::List(values)) => assert!(
                                !values.iter().any(|value| is_placeholder(value)),
                                "{file}.{}.{option}",
                                section.name
                            ),
                        }
                    }
                }
            }
            assert_eq!(placeholders, rendered.secrets.len(), "{}", node.name());
        }
    }

    /// `sections` the way `uci export` prints them.
    fn exported(sections: &[Section]) -> String {
        let quote = |value: &str| format!("'{}'", value.replace('\'', "'\\''"));
        let mut text = String::from("package file\n");

        for section in sections {
            writeln!(
                text,
                "\nconfig {} {}",
                section.section_type,
                quote(&section.name)
            )
            .unwrap();
            for (option, value) in &section.options {
                match value {
                    Value::Single(value) => writeln!(text, "\toption {option} {}", quote(value)),
                    Value::List(values) => values
                        .iter()
                        .try_for_each(|value| writeln!(text, "\tlist {option} {}", quote(value))),
                }
                .unwrap();
            }
        }

        text
    }

    #[test]
    fn what_splot_wrote_reads_back_as_nothing_to_change() {
        // Once the rendered config is in uci, it reads back as it was rendered:
        // the agent's next apply finds nothing to stage.
        let network = example();

        for node in openwrt_nodes(&network) {
            let plan = plan::plan(&network, node.name()).unwrap();
            for (file, sections) in &render(&plan).files {
                let read_back = export::parse(&exported(sections)).unwrap();
                assert_eq!(read_back, *sections, "{} {file}", node.name());
            }
        }
    }

    #[test]
    fn example_config_snapshot() {
        let network = example();

        for node in openwrt_nodes(&network) {
            let plan = plan::plan(&network, node.name()).unwrap();

            let mut output = String::new();
            for (file, sections) in &render(&plan).files {
                writeln!(output, "# {file}").unwrap();
                for command in sections.iter().flat_map(|section| section.commands(file)) {
                    writeln!(output, "{command}").unwrap();
                }
            }

            insta::assert_snapshot!(format!("example_{}", node.name()), output);
        }
    }

    #[test]
    fn hyphen_and_underscore_names_clash_in_real_output() {
        // `my-printer` and `my_printer` are distinct identifiers, but both map to
        // the uci section `spl_host_my_printer`. The guard must catch what the
        // generators produce, not just hand-built commands.
        let rendered = render(
            &plan::plan(
                &test_support::checked(
                    "
meshNetwork: 10.100.0.0/24
nodes:
  Home:
    platform:
      os: openwrt
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    listenPort: 51820
    meshIp: 10.100.0.1
    zones:
      lan:
        address: 192.168.1.1/24
        devices:
          my-printer:
            ip: 192.168.1.20
            macs: AA:BB:CC:DD:EE:01
          my_printer:
            ip: 192.168.1.21
            macs: AA:BB:CC:DD:EE:02
",
                ),
                &"Home".parse().unwrap(),
            )
            .unwrap(),
        );
        assert_eq!(
            splot_agent::openwrt::find_duplicate_sections(&rendered),
            ["dhcp.spl_host_my_printer"]
        );
    }
}
