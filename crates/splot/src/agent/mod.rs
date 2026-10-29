//! The agent splot asks to act on a node: the one in splot itself, for the
//! machine splot runs on, or one splot sends a node over ssh.

mod embedded;
mod session;

use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use splot_core::protocol::{Failure, Reply, Request};

use crate::types::ssh::SshDestination;
pub use embedded::VERSION;
use session::Session;

/// Where the agent splot asks is.
pub enum Agent {
    /// In splot: it acts on the machine splot runs on.
    Local(splot_agent::Agent),
    /// On the node at `destination`, reached over ssh: it gets `agent`, or the
    /// one splot carries for its CPU. The session opens at the first request,
    /// or at `connect`.
    Remote {
        destination: SshDestination,
        agent: Option<PathBuf>,
        session: Option<Session>,
    },
}

impl Agent {
    /// The agent on the node at `ssh`, given `agent` if any; without `ssh`, the
    /// one in splot.
    pub fn new(ssh: Option<SshDestination>, agent: Option<PathBuf>) -> Self {
        match ssh {
            None => Self::Local(splot_agent::Agent::default()),
            Some(destination) => Self::Remote {
                destination,
                agent,
                session: None,
            },
        }
    }

    /// Ends the session, if there's one: the next request opens a new one.
    pub fn reconnect(&mut self) {
        if let Self::Remote { session, .. } = self {
            *session = None;
        }
    }

    /// Opens the session, if there's none: the next request goes over it.
    pub fn connect(&mut self) -> anyhow::Result<()> {
        if let Self::Remote {
            destination,
            agent,
            session: session @ None,
        } = self
        {
            *session = Some(Session::open(destination.as_str(), agent.as_deref())?);
        }

        Ok(())
    }

    /// The agent's answer to `request`; its failure as an error.
    pub fn ask(&mut self, request: Request) -> anyhow::Result<Reply> {
        self.connect()?;
        let reply = match self {
            Self::Local(agent) => agent.handle(request),
            Self::Remote { session, .. } => session
                .as_mut()
                .expect("connect opened the session")
                .ask(&request)?,
        };

        match reply {
            Reply::Failed(failure) => Err(error(failure)),
            reply => Ok(reply),
        }
    }
}

/// A new run's ID: when it began, and by which splot.
pub fn run_id() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_millis());

    format!("{millis}-{}", std::process::id())
}

/// What the agent reported as an error: its message, and its causes as the
/// error's chain, the way they'd show had the error happened here.
fn error(Failure(messages): Failure) -> anyhow::Error {
    let mut messages = messages.into_iter().rev();
    let mut error = anyhow::anyhow!("{}", messages.next().unwrap_or_default());
    for message in messages {
        error = error.context(message);
    }

    error
}

/// Whether `error` is splot losing the node (ssh, the session) rather than the
/// agent refusing what it was asked: when it is, what was asked may be done.
pub fn lost(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| cause.is::<session::Error>())
}

/// The agent's answer wasn't one to what splot asked.
pub fn unexpected(reply: Reply) -> anyhow::Error {
    anyhow::anyhow!("the agent answered what splot didn't ask: {reply:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lost_session_is_told_from_the_agents_refusal() {
        let ended = anyhow::Error::from(session::Error::Ended {
            destination: "cabin".to_owned(),
            when: "before it answered",
            code: Some(255),
        });
        assert!(lost(&ended));
        assert!(lost(&ended.context("splot couldn't confirm Cabin")));

        let refused = error(Failure(vec!["too late".to_owned()]));
        assert!(!lost(&refused));
        assert!(!lost(&unexpected(Reply::Stored)));
    }

    #[test]
    fn an_agents_failure_reads_as_its_error_with_its_causes() {
        let error = error(Failure(vec![
            "can't read the key store".to_owned(),
            "uci failed".to_owned(),
            "Entry not found".to_owned(),
        ]));

        assert_eq!(error.to_string(), "can't read the key store");
        let chain: Vec<String> = error.chain().map(ToString::to_string).collect();
        assert_eq!(
            chain,
            ["can't read the key store", "uci failed", "Entry not found"]
        );
    }
}
