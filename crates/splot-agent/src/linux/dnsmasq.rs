//! Applying the DHCP on Linux: splot's own dnsmasq file, which the operator's
//! dnsmasq reads (`conf-file=/etc/splot/dnsmasq.conf` in its config). dnsmasq
//! reads a config file only when it starts, as root, so a changed file is a
//! restart of its unit, `dnsmasq`; it keeps its leases in its lease file across
//! one. dnsmasq checks the file before the run begins, and the dry run warns
//! when its config doesn't seem to read it. dnsmasq itself is the operator's:
//! splot never starts, stops or enables it.

use std::{fs, path::Path, process::Command};

use serde::{Deserialize, Serialize};

use splot_core::{consts::DNSMASQ_PATH as PATH, protocol::Changes};

use super::{
    apply::{Error, current, put_back, run, succeeds},
    file,
};
use crate::process;

/// The operator's dnsmasq.
const UNIT: &str = "dnsmasq";
/// Where the operator's config usually is: Debian's file, and the directory
/// its unit reads too.
const CONFIG: &str = "/etc/dnsmasq.conf";
const CONFIG_DIR: &str = "/etc/dnsmasq.d";

/// Has dnsmasq check `text` as a config file of its own, changing nothing.
fn check(text: &str) -> Result<(), Error> {
    let mut command = Command::new("dnsmasq");
    command.args(["--test", "--conf-file=-"]);
    let output = process::run(command, Some(text.as_bytes())).map_err(|cause| Error::Run {
        command: "dnsmasq --test --conf-file=-".to_owned(),
        cause,
    })?;

    if output.status.success() {
        Ok(())
    } else {
        Err(Error::DnsmasqRefused(
            String::from_utf8_lossy(&output.stderr)
                .trim_end()
                .to_owned(),
        ))
    }
}

/// Whether one of `configs` (each a file's text) reads splot's file.
fn reads_splots(configs: &[String]) -> bool {
    configs.iter().flat_map(|text| text.lines()).any(|line| {
        line.split_once('=')
            .is_some_and(|(key, value)| key.trim() == "conf-file" && value.trim() == PATH)
    })
}

/// The texts of the operator's config files where they usually are: the main
/// file, and each in the directory but the hidden ones, which dnsmasq skips.
fn configs() -> Vec<String> {
    let in_dir = fs::read_dir(CONFIG_DIR)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| !entry.file_name().to_string_lossy().starts_with('.'))
        .map(|entry| entry.path());

    std::iter::once(Path::new(CONFIG).to_owned())
        .chain(in_dir)
        .filter_map(|path| fs::read_to_string(path).ok())
        .collect()
}

/// What the dry run warns about: dnsmasq's config doesn't seem to read
/// splot's file, so the leases and routes in it wouldn't be handed out.
pub(super) fn warnings() -> Vec<String> {
    if reads_splots(&configs()) {
        return Vec::new();
    }

    vec![format!(
        "dnsmasq's config ({CONFIG}, {CONFIG_DIR}) doesn't read splot's file: add `conf-file={PATH}` to it, or what splot writes there isn't handed out."
    )]
}

/// What the node had of the DHCP before a run: splot's file (none: there was
/// none). dnsmasq ran, as a run needs it to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Kept {
    pub(crate) file: Option<String>,
}

/// What a run prepared: the file its go writes, then restarts dnsmasq.
pub(super) struct Prepared {
    text: String,
    /// What the go changes, as the dry run shows it.
    pub(super) changes: Changes,
    /// What the node has, for the run to put back.
    pub(super) kept: Kept,
}

/// The file the node has, once dnsmasq has checked `text`.
fn planned(text: &str) -> Result<Option<String>, Error> {
    check(text)?;

    current(PATH)
}

/// Works out what writing `text` changes, once dnsmasq has checked it,
/// changing nothing yet: none when the file is as it is. dnsmasq has to run:
/// splot can't make its file live otherwise.
pub(super) fn prepare(text: &str) -> Result<Option<Prepared>, Error> {
    let file = planned(text)?;
    if file.as_deref() == Some(text) {
        return Ok(None);
    }
    if !succeeds("systemctl", &["is-active", "--quiet", UNIT])? {
        return Err(Error::DnsmasqNotRunning);
    }

    Ok(Some(Prepared {
        text: text.to_owned(),
        changes: described(text, true),
        kept: Kept { file },
    }))
}

/// Writes the file, then restarts dnsmasq, which reads it. A file dnsmasq
/// refuses fails the restart, so the go.
pub(super) fn go(prepared: &Prepared) -> Result<(), Error> {
    file::write_private(Path::new(PATH), &prepared.text).map_err(|err| Error::Write(PATH, err))?;
    run("systemctl", &["restart", UNIT]).map(drop)
}

/// What a run puts back where the node had no file: one with nothing in it.
/// dnsmasq doesn't start when a `conf-file` its config names is missing, and
/// the operator may have added that line already.
const EMPTY: &str = "# splot's DHCP: nothing yet. Written by splot: don't edit.\n";

/// Puts the file back as it was (empty where there was none), and dnsmasq
/// reading it.
pub(super) fn restore(kept: &Kept) -> Result<(), Error> {
    let text = kept.file.as_deref().unwrap_or(EMPTY);
    put_back(PATH, Some(text), file::write_private)?;
    run("systemctl", &["restart", UNIT]).map(drop)
}

/// What `go` would do, as the dry run shows it.
pub(super) fn print(text: &str) -> Result<Changes, Error> {
    let file = planned(text)?;

    Ok(described(text, file.as_deref() != Some(text)))
}

/// What writing the file and restarting dnsmasq change, when the file does: in
/// a few words, as the go reports it, and as the dry run shows it.
fn described(text: &str, changed: bool) -> Changes {
    if !changed {
        return Changes::none();
    }

    Changes {
        summary: vec![PATH.to_owned(), format!("{UNIT} restarted")],
        text: format!(
            "# {PATH} becomes:\n{text}# Then splot runs:\n#   systemctl restart {UNIT}\n"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_config_reads_splots_file_where_a_line_says_so() {
        let reads = |lines: &[&str]| {
            reads_splots(
                &lines
                    .iter()
                    .map(|line| line.to_string())
                    .collect::<Vec<_>>(),
            )
        };

        assert!(reads(&["port=1053", "conf-file=/etc/splot/dnsmasq.conf"]));
        assert!(reads(&["", " conf-file = /etc/splot/dnsmasq.conf "]));
        assert!(!reads(&["port=1053"]));
        assert!(!reads(&["#conf-file=/etc/splot/dnsmasq.conf"]));
        assert!(!reads(&["conf-file=/etc/splot/dnsmasq.conf.bak"]));
        assert!(!reads(&[]));
    }

    #[test]
    fn a_changed_file_is_written_and_dnsmasq_restarted() {
        let changes = described("dhcp-host=aa:bb:cc:00:00:07,192.168.4.10,nvr\n", true);
        assert_eq!(
            changes.summary,
            ["/etc/splot/dnsmasq.conf", "dnsmasq restarted"]
        );
        assert_eq!(
            changes.text,
            "# /etc/splot/dnsmasq.conf becomes:\n\
             dhcp-host=aa:bb:cc:00:00:07,192.168.4.10,nvr\n\
             # Then splot runs:\n\
             #   systemctl restart dnsmasq\n"
        );
        assert!(described("", false).is_empty());
    }
}
