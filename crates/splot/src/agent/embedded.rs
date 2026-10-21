//! The agents splot carries for the nodes it reaches over ssh, one per CPU:
//! built by `scripts/dist.sh`, embedded by `build.rs`.

use std::sync::LazyLock;

// `AGENTS`: each CPU, and its agent.
include!(concat!(env!("OUT_DIR"), "/agents.rs"));

/// splot's version, and the CPUs it carries agents for: what `--version` says.
pub static VERSION: LazyLock<String> = LazyLock::new(|| version(env!("CARGO_PKG_VERSION"), AGENTS));

fn version(version: &str, agents: &[(&str, &[u8])]) -> String {
    let cpus: Vec<&str> = agents.iter().map(|(cpu, _)| *cpu).collect();
    let cpus = if cpus.is_empty() {
        "none (built without scripts/dist.sh)".to_owned()
    } else {
        cpus.join(", ")
    };

    format!("{version} (agents for: {cpus})")
}

/// The CPU whose agent runs on a node that says it's `machine` (`uname -m`)
/// and, on OpenWrt, builds its packages for `arch` (`DISTRIB_ARCH`; empty
/// elsewhere). None for one splot has no agent for.
fn cpu(machine: &str, arch: &str) -> Option<&'static str> {
    match machine {
        "aarch64" | "arm64" => Some("aarch64"),
        "x86_64" | "amd64" => Some("x86_64"),
        "riscv64" => Some("riscv64"),
        // The armv7 agent uses the floating-point unit: OpenWrt names it in the
        // architecture (`arm_cortex-a7_neon-vfpv4`); a Linux distribution for
        // armv7 (armhf) needs one anyway.
        "armv7l" | "armv7" if arch.is_empty() || arch.contains("vfp") || arch.contains("neon") => {
            Some("armv7")
        }
        _ => None,
    }
}

/// Why splot can't send a node an agent.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum NoAgent {
    #[error(
        "splot has no agent for this peer's CPU ({machine}{}): build one for it, and name it with --agent",
        if arch.is_empty() { String::new() } else { format!(", {arch}") }
    )]
    OtherCpu { machine: String, arch: String },
    #[error(
        "this splot carries no agent for {cpu}: build splot with scripts/dist.sh, or name an agent with --agent"
    )]
    NotCarried { cpu: &'static str },
}

/// The agent for a node that says it's `machine` and `arch` (see `cpu`).
pub fn for_node(machine: &str, arch: &str) -> Result<&'static [u8], NoAgent> {
    find(AGENTS, machine, arch)
}

fn find<'a>(agents: &[(&str, &'a [u8])], machine: &str, arch: &str) -> Result<&'a [u8], NoAgent> {
    let cpu = cpu(machine, arch).ok_or_else(|| NoAgent::OtherCpu {
        machine: machine.to_owned(),
        arch: arch.to_owned(),
    })?;

    agents
        .iter()
        .find(|(name, _)| *name == cpu)
        .map(|(_, agent)| *agent)
        .ok_or(NoAgent::NotCarried { cpu })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_node_gets_the_agent_for_its_cpu() {
        for (machine, arch, agent) in [
            ("aarch64", "aarch64_cortex-a53", "aarch64"),
            ("aarch64", "", "aarch64"),
            ("x86_64", "x86_64", "x86_64"),
            ("riscv64", "riscv64_riscv64", "riscv64"),
            ("armv7l", "arm_cortex-a7_neon-vfpv4", "armv7"),
            ("armv7l", "arm_cortex-a9_vfpv3-d16", "armv7"),
            // A Raspberry Pi with a 32-bit Linux.
            ("armv7l", "", "armv7"),
        ] {
            assert_eq!(cpu(machine, arch), Some(agent), "{machine} {arch}");
        }

        // No floating-point unit; MIPS; nothing at all.
        for (machine, arch) in [
            ("armv7l", "arm_cortex-a9"),
            ("mips", "mipsel_24kc"),
            ("", ""),
        ] {
            assert_eq!(cpu(machine, arch), None, "{machine} {arch}");
        }
    }

    #[test]
    fn splot_sends_the_agent_it_carries_for_the_cpu_or_says_why_it_cant() {
        let agents: &[(&str, &[u8])] = &[("aarch64", b"arm agent"), ("x86_64", b"x86 agent")];

        assert_eq!(
            find(agents, "aarch64", "aarch64_cortex-a53"),
            Ok(&b"arm agent"[..])
        );
        assert_eq!(find(agents, "x86_64", ""), Ok(&b"x86 agent"[..]));

        let err = find(agents, "riscv64", "").unwrap_err();
        assert_eq!(
            err.to_string(),
            "this splot carries no agent for riscv64: build splot with scripts/dist.sh, or name an agent with --agent"
        );
        let err = find(agents, "mips", "mipsel_24kc").unwrap_err();
        assert_eq!(
            err.to_string(),
            "splot has no agent for this peer's CPU (mips, mipsel_24kc): build one for it, and name it with --agent"
        );
    }

    #[test]
    fn the_version_names_the_cpus_splot_carries_agents_for() {
        assert_eq!(
            version("0.1.0", &[("aarch64", b"agent"), ("x86_64", b"agent")]),
            "0.1.0 (agents for: aarch64, x86_64)"
        );
        assert_eq!(
            version("0.1.0", &[]),
            "0.1.0 (agents for: none (built without scripts/dist.sh))"
        );
    }
}
