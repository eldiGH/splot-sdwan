//! splot's agent: everything splot does on a node. splot validates the config,
//! plans each node and renders what it should hold; the agent, on the node,
//! checks it's the node the config is for, fills the secrets in from the
//! node's key store, and makes the node hold it. No secret leaves the node.

mod env;
mod key_store;
mod linux;
mod node;
pub mod openwrt;
mod probe;
mod process;
mod run;
mod secret;
#[cfg(test)]
mod test_support;
mod wg;

use splot_core::{
    host::HostRef,
    identifier::Identifier,
    os::Os,
    protocol::{Changes, Failure, PROTOCOL, Rendered, Reply, Request, Run},
    wg_key::{WgPresharedKey, WgPublicKey},
};

use std::io::{self, BufRead, Write};

use key_store::{KeyStore, KeyStoreError};
use linux::key_store::FileKeyStore;
use openwrt::key_store::UciKeyStore;

type Error = Box<dyn std::error::Error + Send + Sync>;

/// Answers each request in `input` on `output`, until `input` ends: a request
/// a line, its reply a line, each one JSON value. A line that isn't a request
/// is answered with a failure saying so.
pub fn serve(input: impl BufRead, mut output: impl Write) -> io::Result<()> {
    let mut agent = Agent::default();
    for line in input.lines() {
        let reply = match serde_json::from_str(&line?) {
            Ok(request) => agent.handle(request),
            Err(error) => Reply::Failed(Failure::of(&NotARequest(error))),
        };
        let reply = serde_json::to_string(&reply).map_err(io::Error::other)?;
        writeln!(output, "{reply}")?;
        output.flush()?;
    }

    Ok(())
}

/// A line the agent was sent that isn't a request it knows.
#[derive(Debug, thiserror::Error)]
#[error("the agent got what isn't a request it knows - is it as new as splot?")]
struct NotARequest(#[source] serde_json::Error);

/// The agent: does what each request asks, on this peer. It holds what a run
/// prepared until the go, which comes over the same session.
#[derive(Default)]
pub struct Agent {
    prepared: Option<(String, Prepared)>,
}

/// What a run prepared on this peer, for the OS it runs.
enum Prepared {
    OpenWrt(openwrt::Prepared),
    Linux(linux::Prepared),
}

impl Prepared {
    /// What the go will change.
    fn changes(&self) -> &Changes {
        match self {
            Self::OpenWrt(prepared) => prepared.changes(),
            Self::Linux(prepared) => prepared.changes(),
        }
    }
}

/// A go for a run this agent hasn't prepared.
#[derive(Debug, thiserror::Error)]
#[error("this agent prepared no run {id}: the go comes over the session that prepared it")]
struct NotPreparedHere {
    id: String,
}

impl Agent {
    /// Does what `request` asks, on this peer.
    pub fn handle(&mut self, request: Request) -> Reply {
        let result = match request {
            Request::Hello { protocol } => hello(protocol),
            Request::Os => Ok(Reply::Os(node::detect_os())),
            Request::Init { os } => init(os),
            Request::StorePsk {
                node,
                public_key,
                os,
                peer,
                key,
            } => store_psk(&node, &public_key, os, &peer, &key),
            Request::DryRun { rendered } => dry_run(&rendered),
            Request::Prepare { rendered, run } => self.prepare(&rendered, &run),
            Request::Go { run } => self.go(&run),
            Request::Check { run } => run::check(&run)
                .map(|(still, lost)| Reply::Checked { still, lost })
                .map_err(Error::from),
            Request::Confirm { run } => run::confirm(&run)
                .map(|()| Reply::Confirmed)
                .map_err(Error::from),
            Request::Rollback { run } => run::rollback(&run)
                .map(|()| Reply::RolledBack)
                .map_err(Error::from),
        };

        result.unwrap_or_else(|error| Reply::Failed(Failure::of(error.as_ref())))
    }

    /// Begins `run` to make this peer hold `rendered`, changing nothing yet.
    fn prepare(&mut self, rendered: &Rendered, run: &Run) -> Result<Reply, Error> {
        check_os(rendered)?;

        let prepared = match rendered {
            Rendered::OpenWrt(rendered) => Prepared::OpenWrt(openwrt::prepare(rendered, run)?),
            Rendered::Linux(rendered) => Prepared::Linux(linux::prepare(rendered, run)?),
        };
        let changes = prepared.changes().clone();
        self.prepared = Some((run.id.clone(), prepared));

        Ok(Reply::Prepared(changes))
    }

    /// Applies what run `id` prepared.
    fn go(&mut self, id: &str) -> Result<Reply, Error> {
        let prepared = match self.prepared.take() {
            Some((prepared_id, prepared)) if prepared_id == id => prepared,
            other => {
                self.prepared = other;
                return Err(NotPreparedHere { id: id.to_owned() }.into());
            }
        };

        Ok(Reply::Applied(match &prepared {
            Prepared::OpenWrt(prepared) => openwrt::go(prepared, id)?,
            Prepared::Linux(prepared) => linux::go(prepared, id)?,
        }))
    }
}

/// splot speaks another protocol than this agent.
#[derive(Debug, thiserror::Error)]
#[error(
    "this agent speaks protocol {PROTOCOL}, and splot {splot}: use the agent that comes with this splot"
)]
struct OtherProtocol {
    splot: u32,
}

/// Answers splot's hello with this agent's protocol, when it's splot's.
fn hello(protocol: u32) -> Result<Reply, Error> {
    if protocol == PROTOCOL {
        Ok(Reply::Hello { protocol })
    } else {
        Err(OtherProtocol { splot: protocol }.into())
    }
}

/// Gives this peer its WireGuard key in the key store of `os`, unless it has
/// one: a key is never replaced.
fn init(os: Os) -> Result<Reply, Error> {
    match os {
        Os::OpenWrt => init_with::<UciKeyStore>(),
        Os::Linux => init_with::<FileKeyStore>(),
    }
}

fn init_with<S: KeyStore>() -> Result<Reply, Error> {
    let (store, created) = match S::load() {
        Ok(store) => (store, false),
        Err(KeyStoreError::NotInitialised) => {
            S::create_private_key()?;
            (S::load()?, true)
        }
        Err(err) => return Err(err.into()),
    };
    let public_key = wg::get_pubkey(store.private_key()).map_err(KeyStoreError::Wg)?;

    Ok(Reply::Initialised {
        public_key,
        created,
    })
}

/// Stores `key` as the preshared key of the pair of `node` with `peer`, once
/// it's checked this peer runs `os` and is `node`, whose key the config has as
/// `public_key`.
fn store_psk(
    node: &Identifier,
    public_key: &WgPublicKey,
    os: Os,
    peer: &HostRef,
    key: &WgPresharedKey,
) -> Result<Reply, Error> {
    node::check_os(node, os)?;

    match os {
        Os::OpenWrt => store_psk_with::<UciKeyStore>(node, public_key, peer, key)?,
        Os::Linux => store_psk_with::<FileKeyStore>(node, public_key, peer, key)?,
    }

    Ok(Reply::Stored)
}

fn store_psk_with<S: KeyStore>(
    node: &Identifier,
    public_key: &WgPublicKey,
    peer: &HostRef,
    key: &WgPresharedKey,
) -> Result<(), KeyStoreError> {
    S::load()?.check_node(node, public_key)?;
    S::store_psk(peer, key)
}

/// Checks this peer runs the OS `rendered` is for: the node it names runs it.
fn check_os(rendered: &Rendered) -> Result<(), Error> {
    let (node, os) = match rendered {
        Rendered::OpenWrt(rendered) => (&rendered.node, Os::OpenWrt),
        Rendered::Linux(rendered) => (&rendered.node, Os::Linux),
    };

    Ok(node::check_os(node, os)?)
}

/// What making this peer hold `rendered` would change, and what of the
/// peer's own config decides some of what splot does.
fn dry_run(rendered: &Rendered) -> Result<Reply, Error> {
    check_os(rendered)?;

    let (changes, warnings) = match rendered {
        Rendered::OpenWrt(rendered) => openwrt::dry_run(rendered)?,
        Rendered::Linux(rendered) => (linux::dry_run(rendered)?, Vec::new()),
    };

    Ok(Reply::DryRun { changes, warnings })
}

/// When this process was started to keep a run's deadline, keeps it and ends
/// the process: the first thing a program that may run as the agent does.
pub use run::watch_if_asked;

#[cfg(test)]
mod tests {
    use splot_core::protocol::{linux as linux_protocol, openwrt as openwrt_protocol};

    use super::*;

    /// What `serve` answers to `input`, a reply a line.
    fn served(input: &str) -> Vec<Reply> {
        let mut output = Vec::new();
        serve(input.as_bytes(), &mut output).unwrap();

        String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    fn each_request_on_its_line_gets_its_reply_on_one() {
        let request = serde_json::to_string(&Request::Os).unwrap();
        assert_eq!(
            served(&format!("{request}\n{request}\n")),
            [Reply::Os(node::detect_os()), Reply::Os(node::detect_os())]
        );
        assert!(served("").is_empty());
    }

    #[test]
    fn a_line_that_isnt_a_request_is_answered_with_why() {
        let request = serde_json::to_string(&Request::Os).unwrap();
        let replies = served(&format!("{{\"Reboot\":null}}\n{request}\n"));

        let Reply::Failed(Failure(messages)) = &replies[0] else {
            panic!("{replies:?}");
        };
        assert_eq!(
            messages[0],
            "the agent got what isn't a request it knows - is it as new as splot?"
        );
        // The next one is answered all the same.
        assert_eq!(replies[1], Reply::Os(node::detect_os()));
    }

    fn handled(request: Request) -> Reply {
        Agent::default().handle(request)
    }

    #[test]
    fn the_agent_talks_to_a_splot_of_its_own_protocol_only() {
        assert_eq!(
            handled(Request::Hello { protocol: PROTOCOL }),
            Reply::Hello { protocol: PROTOCOL }
        );
        assert_eq!(
            handled(Request::Hello {
                protocol: PROTOCOL + 1
            }),
            Reply::Failed(Failure(vec![format!(
                "this agent speaks protocol {PROTOCOL}, and splot {}: use the agent that comes with this splot",
                PROTOCOL + 1
            )]))
        );
    }

    #[test]
    fn a_go_comes_after_its_prepare_over_the_same_session() {
        let not_prepared = |id: &str| {
            Reply::Failed(Failure(vec![format!(
                "this agent prepared no run {id}: the go comes over the session that prepared it"
            )]))
        };
        let mut agent = Agent::default();
        assert_eq!(
            agent.handle(Request::Go {
                run: "r1".to_owned()
            }),
            not_prepared("r1")
        );

        // Held for its own run only, and kept for it.
        agent.prepared = Some(("r1".to_owned(), Prepared::Linux(linux::Prepared::nothing())));
        assert_eq!(
            agent.handle(Request::Go {
                run: "r2".to_owned()
            }),
            not_prepared("r2")
        );
        assert!(matches!(&agent.prepared, Some((id, _)) if id == "r1"));
    }

    #[test]
    fn every_error_is_a_std_error() {
        // Fails to compile, not to run, when one isn't: an error crosses to
        // splot as its message and its causes'.
        fn is_error<E: std::error::Error + Send + Sync + 'static>() {}

        is_error::<process::Error>();
        is_error::<wg::Error>();
        is_error::<KeyStoreError>();
        is_error::<node::NotConfirmed>();
        is_error::<node::WrongOs>();
        is_error::<secret::MissingPsks>();
        is_error::<crate::openwrt::Error>();
        is_error::<crate::linux::Error>();
        is_error::<run::Error>();
        is_error::<probe::Error>();
        is_error::<NotPreparedHere>();
    }

    #[test]
    fn a_config_for_another_os_than_this_peers_is_refused_before_anything_else() {
        // Where the tests run, the OS splot detects; the config says the other.
        let Some(found) = node::detect_os() else {
            return;
        };
        let (node, public_key) = (
            "Home".parse().unwrap(),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                .parse()
                .unwrap(),
        );
        let rendered = match found {
            Os::Linux => Rendered::OpenWrt(openwrt_protocol::Rendered {
                node,
                public_key,
                wireguard: true,
                files: Vec::new(),
                secrets: Vec::new(),
                owned: Vec::new(),
            }),
            Os::OpenWrt => Rendered::Linux(linux_protocol::Rendered {
                node,
                public_key,
                wireguard: None,
                firewall: None,
            }),
        };
        let os = match found {
            Os::Linux => Os::OpenWrt,
            Os::OpenWrt => Os::Linux,
        };

        let run = Run {
            id: "r1".to_owned(),
            confirm_within: 120,
            probes: Vec::new(),
        };
        for request in [
            Request::DryRun {
                rendered: rendered.clone(),
            },
            Request::Prepare {
                rendered: rendered.clone(),
                run,
            },
        ] {
            let reply = handled(request);
            assert_eq!(
                reply,
                Reply::Failed(Failure(vec![format!(
                    "this peer runs {found}, but the config says Home runs {os}"
                )]))
            );
        }
    }
}
