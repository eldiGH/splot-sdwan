//! What splot asks of the agent on a node, and what the agent answers: the
//! config splot rendered for the node, and what became of it.

pub mod linux;
pub mod openwrt;

use std::error::Error;

use serde::{Deserialize, Serialize};

/// What splot asks of the agent.
#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    /// Make the node hold `rendered`; for a dry run, say what that would
    /// change, changing nothing.
    Apply { rendered: Rendered, dry_run: bool },
}

/// What the agent answers.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reply {
    /// What changed; nothing when the node held the config already.
    Applied(Vec<String>),
    /// What apply would change, as the dry run shows it.
    DryRun(String),
    /// Why the agent didn't do what it was asked.
    Failed(Failure),
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

    #[test]
    fn a_request_arrives_as_it_was_sent() {
        for rendered in [openwrt(), linux()] {
            let request = Request::Apply {
                rendered,
                dry_run: true,
            };
            // Its parts don't compare: what it says does.
            assert_eq!(format!("{:?}", sent(&request)), format!("{request:?}"));
        }
    }

    #[test]
    fn a_reply_arrives_as_it_was_sent() {
        for reply in [
            Reply::Applied(vec!["network".to_owned()]),
            Reply::DryRun("# Nothing to change.\n".to_owned()),
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
