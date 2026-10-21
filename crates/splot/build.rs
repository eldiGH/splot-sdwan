//! Embeds the agents `scripts/dist.sh` built into splot: `SPLOT_AGENTS` names a
//! directory with one per CPU, named after the CPU. Without it (a plain `cargo
//! build`) splot carries none, and acts only on the machine it runs on.

use std::{env, fs, path::Path};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=SPLOT_AGENTS");

    let mut agents = Vec::new();
    match env::var("SPLOT_AGENTS") {
        Ok(dir) => {
            println!("cargo:rerun-if-changed={dir}");
            for entry in fs::read_dir(&dir).expect("SPLOT_AGENTS is a directory") {
                let path = entry.expect("SPLOT_AGENTS can be read").path();
                let cpu = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .expect("an agent is named after its CPU")
                    .to_owned();
                agents.push((cpu, path));
            }
            agents.sort();
        }
        Err(_) if env::var("PROFILE").as_deref() == Ok("release") => println!(
            "cargo:warning=this splot carries no agents, so it can't reach a node over ssh: build a release with scripts/dist.sh"
        ),
        Err(_) => {}
    }

    let table: String = agents
        .iter()
        .map(|(cpu, path)| format!("    ({cpu:?}, include_bytes!({path:?})),\n"))
        .collect();
    let out = env::var("OUT_DIR").expect("cargo sets OUT_DIR");
    fs::write(
        Path::new(&out).join("agents.rs"),
        format!("pub static AGENTS: &[(&str, &[u8])] = &[\n{table}];\n"),
    )
    .expect("OUT_DIR can be written");
}
