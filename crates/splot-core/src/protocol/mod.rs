//! What splot asks of the agent on a node, and what the agent answers: the
//! config splot rendered for the node, and what became of it.

pub mod linux;
pub mod openwrt;

use std::{error::Error, net::Ipv4Addr};

use serde::{Deserialize, Serialize};

use crate::{
    host::HostRef,
    identifier::Identifier,
    os::Os,
    wg_key::{WgPresharedKey, WgPublicKey},
};

/// The protocol's version: splot and an agent talk only when theirs are the
/// same. A change to a request or a reply bumps it.
pub const PROTOCOL: u32 = 5;

/// What splot asks of the agent.
#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    /// The first request over a session, saying splot's protocol: `Hello` with
    /// the agent's, which refuses another. Its shape never changes, so an agent
    /// of any version reads it.
    Hello { protocol: u32 },
    /// Which OS the node runs: `Os`.
    Os,
    /// Give the node its WireGuard key, in the key store of `os`, unless it has
    /// one: `Initialised`. A key is never replaced.
    Init { os: Os },
    /// Store `key` as the preshared key of the pair of `node` (whose key the
    /// config has as `public_key`, and its OS as `os`) with `peer`, once it's
    /// checked to be that node: `Stored`.
    StorePsk {
        node: Identifier,
        public_key: WgPublicKey,
        os: Os,
        peer: HostRef,
        key: WgPresharedKey,
    },
    /// What making the node hold `rendered` would change, changing nothing:
    /// `DryRun`, as `Prepare` would find it.
    DryRun { rendered: Rendered },
    /// Begin `run` to make the node hold `rendered`, changing nothing yet: the
    /// node keeps what it had, notes which peers answer, and puts it back by
    /// itself unless the run is confirmed in time. `Prepared`, with what the go
    /// will change, as the dry run shows it; a run begins even when that's
    /// nothing.
    Prepare { rendered: Rendered, run: Run },
    /// Apply what the run prepared, over the same session: `Applied`.
    Go { run: String },
    /// Whether the node's peers that answered before the run still do:
    /// `Checked`.
    Check { run: String },
    /// Keep what the run applied: `Confirmed`. Too late once the node has
    /// rolled back.
    Confirm { run: String },
    /// Put back what the node had before the run (nothing, before the go):
    /// `RolledBack`, also when it's put back already. Refused once it's
    /// confirmed.
    Rollback { run: String },
}

/// A change splot applies on a node: the node puts back what it had unless
/// splot confirms it within `confirm_within` seconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Run {
    /// Which run it is: a node answers for its own run only.
    pub id: String,
    pub confirm_within: u32,
    /// The node's peers to check: those that answer before the run must
    /// answer after it.
    pub probes: Vec<Probe>,
}

/// A peer the node pings to see its tunnel works: its name, and its mesh IP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Probe {
    pub peer: String,
    pub address: Ipv4Addr,
}

/// What the agent answers.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reply {
    /// The agent's protocol, the same as splot's.
    Hello {
        protocol: u32,
    },
    /// The OS the node runs, as far as the agent can tell: OpenWrt by its
    /// release file, any other Linux as Linux, none for anything else.
    Os(Option<Os>),
    /// The public half of the node's private key, and whether it was made just
    /// now.
    Initialised {
        public_key: WgPublicKey,
        created: bool,
    },
    Stored,
    /// What the go will change; nothing when the node holds the config already.
    Prepared(Changes),
    /// What changed.
    Applied(Vec<String>),
    /// Of the peers that answered before the run, those that still do, and
    /// those that don't.
    Checked {
        still: Vec<String>,
        lost: Vec<String>,
    },
    Confirmed,
    RolledBack,
    /// What apply would change.
    DryRun(Changes),
    /// Why the agent didn't do what it was asked.
    Failed(Failure),
}

/// What making a node hold its rendered config changes there: each change in a
/// few words (a file, what systemd does), as apply reports it, and in full, as
/// the dry run shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Changes {
    pub summary: Vec<String>,
    pub text: String,
}

impl Changes {
    /// Nothing changes.
    pub fn none() -> Self {
        Self {
            summary: Vec::new(),
            text: "# Nothing to change.\n".to_owned(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.summary.is_empty()
    }
}

/// The config splot rendered for a node, for the platform it runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Rendered {
    OpenWrt(openwrt::Rendered),
    Linux(linux::Rendered),
}

/// An error as the agent reports it: what went wrong, then each cause, the way
/// the error's chain of sources says them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Failure(pub Vec<String>);

impl Failure {
    pub fn of(error: &dyn Error) -> Self {
        let mut messages = vec![error.to_string()];
        let mut source = error.source();
        while let Some(cause) = source {
            messages.push(cause.to_string());
            source = cause.source();
        }

        Self(messages)
    }
}

#[cfg(test)]
mod tests {
    use std::fmt;

    use super::*;
    use crate::{
        host::HostRef,
        secret::Secret,
        uci::{
            section::{Section, Value},
            slot::Slot,
        },
    };

    fn openwrt() -> Rendered {
        Rendered::OpenWrt(openwrt::Rendered {
            node: "Home".parse().unwrap(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                .parse()
                .unwrap(),
            wireguard: true,
            files: vec![(
                "network".to_owned(),
                vec![Section {
                    name: "spl_wireguard_spl_mesh_Cabin".to_owned(),
                    section_type: "wireguard_spl_mesh".to_owned(),
                    options: vec![
                        (
                            "preshared_key".to_owned(),
                            Value::Single("<preshared key>".to_owned()),
                        ),
                        (
                            "allowed_ips".to_owned(),
                            Value::List(vec!["10.100.0.2/32".to_owned()]),
                        ),
                    ],
                }],
            )],
            secrets: vec![Slot {
                file: "network".to_owned(),
                section: "spl_wireguard_spl_mesh_Cabin".to_owned(),
                option: "preshared_key".to_owned(),
                secret: Secret::Psk(HostRef::Node("Cabin".parse().unwrap())),
            }],
        })
    }

    fn linux() -> Rendered {
        Rendered::Linux(linux::Rendered {
            node: "Barn".parse().unwrap(),
            public_key: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA="
                .parse()
                .unwrap(),
            wireguard: Some(linux::WgQuickConfig {
                lines: vec![
                    linux::Line::Text("[Interface]".to_owned()),
                    linux::Line::Secret {
                        key: "PrivateKey".to_owned(),
                        secret: Secret::PrivateKey,
                    },
                ],
                address: "10.100.0.4/16".to_owned(),
                routes: ["192.168.2.0/24".to_owned()].into(),
            }),
        })
    }

    /// `value` sent as JSON and read back.
    fn sent<T: Serialize + for<'de> Deserialize<'de>>(value: &T) -> T {
        serde_json::from_str(&serde_json::to_string(value).unwrap()).unwrap()
    }

    const PSK: &str = "KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKA=";

    fn store_psk() -> Request {
        Request::StorePsk {
            node: "Home".parse().unwrap(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                .parse()
                .unwrap(),
            os: Os::OpenWrt,
            peer: HostRef::Local {
                node: "Home".parse().unwrap(),
                name: "camera".parse().unwrap(),
            },
            key: PSK.parse().unwrap(),
        }
    }

    #[test]
    fn a_request_arrives_as_it_was_sent() {
        let requests = [
            Request::Hello { protocol: PROTOCOL },
            Request::Os,
            Request::Init { os: Os::Linux },
            store_psk(),
            Request::DryRun {
                rendered: openwrt(),
            },
            Request::Prepare {
                rendered: linux(),
                run: Run {
                    id: "1729500000-42".to_owned(),
                    confirm_within: 120,
                    probes: vec![Probe {
                        peer: "Cabin".to_owned(),
                        address: Ipv4Addr::new(10, 100, 0, 2),
                    }],
                },
            },
            Request::Go {
                run: "1729500000-42".to_owned(),
            },
            Request::Check {
                run: "1729500000-42".to_owned(),
            },
            Request::Confirm {
                run: "1729500000-42".to_owned(),
            },
            Request::Rollback {
                run: "1729500000-42".to_owned(),
            },
        ];
        for request in requests {
            // Its parts don't compare: what it says does.
            assert_eq!(format!("{:?}", sent(&request)), format!("{request:?}"));
        }
    }

    #[test]
    fn a_preshared_key_arrives_as_it_was_sent_and_never_shows() {
        let Request::StorePsk { key, .. } = sent(&store_psk()) else {
            panic!("not the request sent");
        };
        assert_eq!(key.expose(), PSK);
        assert!(!format!("{:?}", store_psk()).contains(PSK));

        // One that isn't a key is refused as it arrives.
        let json = serde_json::to_string(&store_psk())
            .unwrap()
            .replace(PSK, "KKKK");
        assert!(serde_json::from_str::<Request>(&json).is_err());
    }

    #[test]
    fn a_reply_arrives_as_it_was_sent() {
        for reply in [
            Reply::Hello { protocol: PROTOCOL },
            Reply::Os(Some(Os::OpenWrt)),
            Reply::Os(None),
            Reply::Initialised {
                public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                    .parse()
                    .unwrap(),
                created: true,
            },
            Reply::Stored,
            Reply::Checked {
                still: vec!["Cabin".to_owned()],
                lost: vec!["Lake".to_owned()],
            },
            Reply::Confirmed,
            Reply::RolledBack,
            Reply::Prepared(Changes {
                summary: vec!["network".to_owned()],
                text: "set network.spl_mesh=interface\n".to_owned(),
            }),
            Reply::Applied(vec!["network".to_owned()]),
            Reply::DryRun(Changes::none()),
            Reply::Failed(Failure(vec!["it failed".to_owned(), "because".to_owned()])),
        ] {
            assert_eq!(sent(&reply), reply);
        }
    }

    #[test]
    fn what_arrives_is_checked_again() {
        // A name or a key that isn't one is refused where it's read, as when the
        // config is.
        let json = serde_json::to_string(&openwrt())
            .unwrap()
            .replace("Home", "spl_Home");
        assert!(serde_json::from_str::<Rendered>(&json).is_err());
        let json = serde_json::to_string(&openwrt())
            .unwrap()
            .replace("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "AAAA");
        assert!(serde_json::from_str::<Rendered>(&json).is_err());
    }

    #[derive(Debug)]
    struct Chained(&'static str, Option<Box<Chained>>);

    impl fmt::Display for Chained {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
    }

    impl Error for Chained {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            self.1.as_deref().map(|cause| cause as &dyn Error)
        }
    }

    #[test]
    fn a_failure_says_the_error_then_each_cause() {
        let error = Chained(
            "can't read the key store",
            Some(Box::new(Chained(
                "uci failed",
                Some(Box::new(Chained("Entry not found", None))),
            ))),
        );
        assert_eq!(
            Failure::of(&error).0,
            ["can't read the key store", "uci failed", "Entry not found"]
        );
    }
}
