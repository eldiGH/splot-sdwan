//! A session with the agent on a node over ssh: splot sends the node the agent
//! for its CPU, runs it there, and asks it, a JSON line each way.

use std::{
    borrow::Cow,
    fs,
    io::{self, BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

use splot_core::protocol::{Failure, PROTOCOL, Reply, Request};

use super::embedded::{self, NoAgent};

/// The command the node runs: it says its CPU (`uname -m`, then OpenWrt's
/// `DISTRIB_ARCH`, empty elsewhere), takes the agent (its size on a line, then
/// its bytes) into a file of its own in `/tmp`, says `ready`, and runs it. The
/// file goes when the agent ends; one that arrived cut short doesn't run.
///
/// splot sends nothing after the agent until `ready`: busybox's `head -c` reads
/// past the bytes it's asked for, and would take the first request with them.
const BOOTSTRAP: &str = r#"exec sh -c 'uname -m
DISTRIB_ARCH=
[ -f /etc/openwrt_release ] && . /etc/openwrt_release
echo "$DISTRIB_ARCH"
read -r size || exit 1
f=$(mktemp /tmp/splot-agent.XXXXXX) || exit 1
trap "rm -f $f" EXIT
head -c "$size" >"$f"
[ "$(($(wc -c <"$f")))" -eq "$size" ] && chmod 700 "$f" || exit 1
echo ready
"$f"'"#;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("can't run ssh - is OpenSSH installed?")]
    Spawn(#[source] io::Error),
    #[error("can't read the agent {}", path.display())]
    ReadAgent {
        path: PathBuf,
        #[source]
        cause: io::Error,
    },
    #[error(transparent)]
    NoAgent(#[from] NoAgent),
    #[error("lost the session with {destination}")]
    Io {
        destination: String,
        #[source]
        cause: io::Error,
    },
    #[error("the session with {destination} ended {when}{}", exit(*code))]
    Ended {
        destination: String,
        when: &'static str,
        code: Option<i32>,
    },
    #[error("{destination} answered what splot doesn't expect: {line}")]
    Unexpected { destination: String, line: String },
    #[error("the agent on {destination} won't talk to this splot: {}", .failure.0.join(": "))]
    Refused {
        destination: String,
        failure: Failure,
    },
}

/// What ssh's exit code says, as the end of a message.
fn exit(code: Option<i32>) -> String {
    match code {
        // ssh's own: it couldn't connect or log in, and said why above.
        Some(255) => " (ssh couldn't reach it)".to_owned(),
        Some(code) => format!(" (exit code {code})"),
        None => String::new(),
    }
}

pub struct Session {
    destination: String,
    child: Child,
    /// Closed (none) when the session ends: the agent's end of input.
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
}

impl Session {
    /// A session with the agent on `destination` (anything `ssh` takes:
    /// `root@router`, a host of `~/.ssh/config`), which gets `agent` if it's
    /// given, else the one splot carries for its CPU.
    pub fn open(destination: &str, agent: Option<&Path>) -> Result<Self, Error> {
        let mut ssh = Command::new("ssh");
        ssh.args(["-T", "--", destination, BOOTSTRAP]);

        Self::start(ssh, destination, agent)
    }

    /// The session `command` starts: anything that runs `BOOTSTRAP` on the node.
    fn start(mut command: Command, destination: &str, agent: Option<&Path>) -> Result<Self, Error> {
        // ssh asks for a password or about a host key on the terminal, and
        // says why it failed on stderr: the person running splot sees it.
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(Error::Spawn)?;
        let stdin = child.stdin.take().expect("stdin is piped");
        let stdout = BufReader::new(child.stdout.take().expect("stdout is piped"));
        let mut session = Self {
            destination: destination.to_owned(),
            child,
            stdin: Some(stdin),
            stdout,
        };

        let before = "before the agent started";
        let machine = session.line(before)?;
        let arch = session.line(before)?;
        let agent: Cow<[u8]> = match agent {
            Some(path) => Cow::Owned(fs::read(path).map_err(|cause| Error::ReadAgent {
                path: path.to_owned(),
                cause,
            })?),
            None => Cow::Borrowed(embedded::for_node(&machine, &arch)?),
        };
        session.send(format!("{}\n", agent.len()).as_bytes())?;
        session.send(&agent)?;

        match session.line(before)?.as_str() {
            "ready" => {}
            line => return Err(session.unexpected(line)),
        }

        match session.ask(&Request::Hello { protocol: PROTOCOL })? {
            Reply::Hello { protocol } if protocol == PROTOCOL => Ok(session),
            Reply::Failed(failure) => Err(Error::Refused {
                destination: session.destination.clone(),
                failure,
            }),
            reply => Err(session.unexpected(&format!("{reply:?}"))),
        }
    }

    /// The agent's answer to `request`.
    pub fn ask(&mut self, request: &Request) -> Result<Reply, Error> {
        let line = serde_json::to_string(request).expect("a request is JSON");
        self.send(format!("{line}\n").as_bytes())?;

        let line = self.line("while the agent answered")?;
        serde_json::from_str(&line).map_err(|_| self.unexpected(&line))
    }

    fn send(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let stdin = self.stdin.as_mut().expect("the session is open");

        stdin
            .write_all(bytes)
            .and_then(|()| stdin.flush())
            .map_err(|cause| self.io(cause))
    }

    /// The next line from the node, without its end; when there's none, the
    /// session ended `when`.
    fn line(&mut self, when: &'static str) -> Result<String, Error> {
        let mut line = String::new();
        match self.stdout.read_line(&mut line) {
            Ok(0) => Err(self.ended(when)),
            Ok(_) => Ok(line.trim_end_matches('\n').to_owned()),
            Err(cause) => Err(self.io(cause)),
        }
    }

    fn ended(&mut self, when: &'static str) -> Error {
        self.stdin = None;
        let code = self.child.wait().ok().and_then(|status| status.code());

        Error::Ended {
            destination: self.destination.clone(),
            when,
            code,
        }
    }

    fn io(&self, cause: io::Error) -> Error {
        Error::Io {
            destination: self.destination.clone(),
            cause,
        }
    }

    fn unexpected(&self, line: &str) -> Error {
        Error::Unexpected {
            destination: self.destination.clone(),
            line: line.to_owned(),
        }
    }
}

/// Ends the session: the agent's input ends, so it does, and the node removes
/// it.
impl Drop for Session {
    fn drop(&mut self) {
        self.stdin = None;
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::Read,
        os::unix::fs::PermissionsExt,
        process::{Command, Stdio},
    };

    use super::*;
    use crate::test_support::TempDir;

    /// The bootstrap, run here by `sh` instead of on a node by ssh.
    fn here() -> Command {
        let mut sh = Command::new("sh");
        sh.args(["-c", BOOTSTRAP]);
        sh
    }

    /// A stand-in for the agent, in `dir`: a script that answers hello with
    /// `hello`, and any other request with where it runs from.
    fn fake_agent(dir: &TempDir, hello: &str) -> PathBuf {
        let path = dir.0.join("agent");
        fs::write(
            &path,
            format!(
                r#"#!/bin/sh
while IFS= read -r line; do
    case $line in
    '{{"Hello"'*) echo '{hello}' ;;
    *) printf '{{"DryRun":"%s"}}\n' "$0" ;;
    esac
done
"#
            ),
        )
        .unwrap();
        path
    }

    fn hello() -> String {
        format!(r#"{{"Hello":{{"protocol":{PROTOCOL}}}}}"#)
    }

    #[test]
    fn a_session_sends_the_agent_runs_it_and_removes_it_after() {
        let dir = TempDir::new("session-agent");
        let agent = fake_agent(&dir, &hello());

        let mut session = Session::start(here(), "here", Some(&agent)).unwrap();
        let Reply::DryRun(ran_from) = session.ask(&Request::Os).unwrap() else {
            panic!("not the fake agent's answer");
        };

        // A copy of its own in /tmp, which only its owner may run or read.
        let ran_from = PathBuf::from(ran_from);
        assert!(ran_from.starts_with("/tmp"), "{}", ran_from.display());
        assert!(
            ran_from
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("splot-agent.")
        );
        assert_eq!(fs::read(&ran_from).unwrap(), fs::read(&agent).unwrap());
        assert_eq!(
            fs::metadata(&ran_from).unwrap().permissions().mode() & 0o777,
            0o700
        );
        // It answers each request in turn.
        assert!(matches!(
            session.ask(&Request::Os).unwrap(),
            Reply::DryRun(_)
        ));

        drop(session);
        assert!(!ran_from.exists(), "{} is still there", ran_from.display());
    }

    #[test]
    fn an_agent_of_another_protocol_is_refused() {
        let dir = TempDir::new("session-protocol");
        let agent = fake_agent(
            &dir,
            r#"{"Failed":["this agent speaks protocol 0, and splot 1: use the agent that comes with this splot"]}"#,
        );

        let err = Session::start(here(), "router", Some(&agent))
            .err()
            .unwrap();
        assert_eq!(
            err.to_string(),
            "the agent on router won't talk to this splot: this agent speaks protocol 0, and splot 1: use the agent that comes with this splot"
        );
    }

    #[test]
    fn a_session_that_ends_says_when_and_how() {
        let mut ends = Command::new("sh");
        ends.args(["-c", "exit 7"]);
        let err = Session::start(ends, "router", None).err().unwrap();
        assert_eq!(
            err.to_string(),
            "the session with router ended before the agent started (exit code 7)"
        );

        // ssh's own failure: it said why on stderr.
        let mut ends = Command::new("sh");
        ends.args(["-c", "exit 255"]);
        let err = Session::start(ends, "router", None).err().unwrap();
        assert_eq!(
            err.to_string(),
            "the session with router ended before the agent started (ssh couldn't reach it)"
        );
    }

    #[test]
    fn without_an_agent_for_the_nodes_cpu_nothing_is_sent() {
        // Tests are built without agents: splot carries none for this machine.
        let err = Session::start(here(), "here", None).err().unwrap();
        assert!(
            matches!(err, Error::NoAgent(NoAgent::NotCarried { .. })),
            "{err}"
        );
    }

    #[test]
    fn an_agent_that_arrives_cut_short_doesnt_run() {
        // It says it's 100 bytes, sends 10, and the session's input ends.
        let mut sh = here()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        sh.stdin
            .take()
            .unwrap()
            .write_all(b"100\n#!/bin/sh\nx")
            .unwrap();
        let mut output = String::new();
        sh.stdout
            .take()
            .unwrap()
            .read_to_string(&mut output)
            .unwrap();

        assert!(!sh.wait().unwrap().success());
        assert!(!output.contains("ready"), "{output}");
        // It said the CPU, and nothing after.
        assert_eq!(output.lines().count(), 2, "{output}");
    }
}
