//! Whether a peer's tunnel works: it answers a ping to its mesh IP. Every peer
//! may ping a node there (splot's firewall), and the ping brings the tunnel up
//! when it's idle.

use std::{
    net::Ipv4Addr,
    path::Path,
    process::Command,
    thread,
    time::{Duration, Instant},
};

use splot_core::{protocol::Probe, wg_key::WgPublicKey};

use crate::{process, run, wg};

/// How long WireGuard sends into a session: 3 minutes from the handshake that
/// began it (`REJECT_AFTER_TIME`).
const SESSION_LIFETIME: u64 = 180;
/// How long a peer this node holds a session with gets to answer, once its two
/// pings went unanswered. The other end may have dropped the session (its
/// interface restarted, a run put back): it doesn't answer what's sent into it,
/// and WireGuard starts a new handshake only 15 s after the first packet that
/// got no answer (`KEEPALIVE_TIMEOUT` plus `REKEY_TIMEOUT`, and up to a third
/// of a second).
const STALE_SESSION_FOR: Duration = Duration::from_secs(16);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(
        "can't check the peers' tunnels: ping can't run here - install it (iputils-ping on Debian)"
    )]
    NoPing(#[source] process::Error),
    #[error(
        "can't check the peers' tunnels: wg can't say which peers this node has a session with"
    )]
    Sessions(#[source] wg::Error),
}

/// Whether `address` answers a ping within a second.
fn answers(address: Ipv4Addr) -> Result<bool, Error> {
    let mut ping = Command::new("ping");
    ping.args(["-c", "1", "-W", "1", &address.to_string()]);

    Ok(process::run(ping, None)
        .map_err(Error::NoPing)?
        .status
        .success())
}

/// Of `probes`, peers on this node's WireGuard interface `interface`, those
/// that answer now: before a run, so that only what worked is checked after it.
pub fn answering(probes: &[Probe], interface: &str) -> Result<Vec<Probe>, Error> {
    answering_with(
        probes,
        answers,
        || sessions(interface),
        || rounds_until(Instant::now() + STALE_SESSION_FOR),
    )
}

/// A peer that doesn't answer the first ping gets a second: an idle tunnel
/// may take the first to come up. One that doesn't answer either, but that
/// this node holds a session with (`in_session`), gets the rounds
/// `stale_rounds` gives: the time WireGuard takes to leave a session the other
/// end dropped.
fn answering_with<W: FnMut() -> bool>(
    probes: &[Probe],
    answers: impl Fn(Ipv4Addr) -> Result<bool, Error>,
    in_session: impl FnOnce() -> Result<Vec<WgPublicKey>, Error>,
    stale_rounds: impl FnOnce() -> W,
) -> Result<Vec<Probe>, Error> {
    let mut answering = Vec::new();
    let mut missed = Vec::new();
    for probe in probes {
        if answers(probe.address)? || answers(probe.address)? {
            answering.push(probe.peer.clone());
        } else {
            missed.push(probe.clone());
        }
    }
    if !missed.is_empty() {
        let sessions = in_session()?;
        missed.retain(|probe| sessions.contains(&probe.public_key));
        answering.extend(check_with(&missed, &answers, stale_rounds())?.0);
    }

    Ok(probes
        .iter()
        .filter(|probe| answering.contains(&probe.peer))
        .cloned()
        .collect())
}

/// The peers of `interface` this node holds a session with: none while it
/// isn't up.
fn sessions(interface: &str) -> Result<Vec<WgPublicKey>, Error> {
    if !Path::new("/sys/class/net").join(interface).exists() {
        return Ok(Vec::new());
    }

    let now = run::now();
    Ok(wg::latest_handshakes(interface)
        .map_err(Error::Sessions)?
        .into_iter()
        .filter(|&(_, at)| session_at(at, now))
        .map(|(key, _)| key)
        .collect())
}

/// Whether a handshake at `at` (0, the epoch: never) gives a session at
/// `now`.
fn session_at(at: u64, now: u64) -> bool {
    now.saturating_sub(at) < SESSION_LIFETIME
}

/// Of `probes`, which still answer and which don't, by name. Each is pinged
/// again, a second apart, until it answers or `within` has passed: a tunnel may
/// need a moment after a reload.
pub fn check(probes: &[Probe], within: Duration) -> Result<(Vec<String>, Vec<String>), Error> {
    check_with(probes, answers, rounds_until(Instant::now() + within))
}

/// Whether there's time for another round before `deadline`, waiting a second
/// for it.
fn rounds_until(deadline: Instant) -> impl FnMut() -> bool {
    move || {
        let more = Instant::now() < deadline;
        if more {
            thread::sleep(Duration::from_secs(1));
        }
        more
    }
}

/// `again` says whether there's time for another round (and waits for it).
fn check_with(
    probes: &[Probe],
    answers: impl Fn(Ipv4Addr) -> Result<bool, Error>,
    mut again: impl FnMut() -> bool,
) -> Result<(Vec<String>, Vec<String>), Error> {
    let mut still = Vec::new();
    let mut waiting: Vec<&Probe> = probes.iter().collect();

    loop {
        let mut lost = Vec::new();
        for probe in waiting {
            if answers(probe.address)? {
                still.push(probe.peer.clone());
            } else {
                lost.push(probe);
            }
        }
        waiting = lost;
        if waiting.is_empty() || !again() {
            break;
        }
    }

    Ok((
        still,
        waiting.iter().map(|probe| probe.peer.clone()).collect(),
    ))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    /// The peer at 10.100.0.`last`, its key a letter of its own.
    fn probe(peer: &str, last: u8) -> Probe {
        Probe {
            peer: peer.to_owned(),
            public_key: key(last),
            address: Ipv4Addr::new(10, 100, 0, last),
        }
    }

    fn key(last: u8) -> WgPublicKey {
        let letter = char::from(b'A' + last - 1).to_string();
        format!("{}A=", letter.repeat(42)).parse().unwrap()
    }

    fn names(probes: &[Probe]) -> Vec<&str> {
        probes.iter().map(|probe| probe.peer.as_str()).collect()
    }

    #[test]
    fn before_a_run_a_peer_that_answers_is_kept_a_second_ping_for_an_idle_tunnel() {
        // Cabin answers at once, Lake on the second ping, Barn not at all.
        let pinged = RefCell::new(Vec::new());
        let answering = answering_with(
            &[probe("Cabin", 2), probe("Lake", 3), probe("Barn", 4)],
            |address| {
                let mut pinged = pinged.borrow_mut();
                pinged.push(address.octets()[3]);
                Ok(match address.octets()[3] {
                    2 => true,
                    3 => pinged.iter().filter(|&&last| last == 3).count() == 2,
                    _ => false,
                })
            },
            || Ok(Vec::new()),
            || || panic!("waited for a peer without a session"),
        )
        .unwrap();

        assert_eq!(names(&answering), ["Cabin", "Lake"]);
        assert_eq!(*pinged.borrow(), [2, 3, 3, 4, 4]);
    }

    #[test]
    fn a_peer_in_a_session_gets_the_time_a_stale_one_needs() {
        // Cabin and Barn hold a session with this node, Lake doesn't; Cabin
        // answers from its fourth ping, Lake and Barn never, Home at once.
        // Four rounds of time.
        let pinged = RefCell::new(Vec::new());
        let rounds = RefCell::new(0);
        let answering = answering_with(
            &[
                probe("Cabin", 2),
                probe("Lake", 3),
                probe("Barn", 4),
                probe("Home", 1),
            ],
            |address| {
                let mut pinged = pinged.borrow_mut();
                pinged.push(address.octets()[3]);
                Ok(match address.octets()[3] {
                    1 => true,
                    2 => pinged.iter().filter(|&&last| last == 2).count() >= 4,
                    _ => false,
                })
            },
            || Ok(vec![key(4), key(2)]),
            || {
                || {
                    let mut rounds = rounds.borrow_mut();
                    *rounds += 1;
                    *rounds < 4
                }
            },
        )
        .unwrap();

        // In the probes' order, though Cabin answered after Home.
        assert_eq!(names(&answering), ["Cabin", "Home"]);
        let pinged = pinged.borrow();
        let times = |last: u8| pinged.iter().filter(|&&pinged| pinged == last).count();
        // Lake, without a session, only gets its two pings; Barn every round.
        assert_eq!(times(3), 2);
        assert_eq!(times(4), 2 + 4);
        assert_eq!(times(2), 4);
        assert_eq!(times(1), 1);
    }

    #[test]
    fn when_every_peer_answers_at_once_nobody_asks_about_sessions() {
        let answering = answering_with(
            &[probe("Cabin", 2)],
            |_| Ok(true),
            || panic!("asked about sessions"),
            || || panic!("waited"),
        )
        .unwrap();
        assert_eq!(names(&answering), ["Cabin"]);
    }

    #[test]
    fn a_handshake_gives_a_session_for_three_minutes() {
        let now = 1_729_500_000;
        assert!(session_at(now, now));
        assert!(session_at(now - 179, now));
        assert!(!session_at(now - 180, now));
        // Never.
        assert!(!session_at(0, now));
        // A clock set back since: as fresh as can be.
        assert!(session_at(now + 5, now));
    }

    #[test]
    fn after_a_run_each_peer_gets_until_the_time_is_up_to_answer() {
        // Cabin answers at once; Lake from the third round; Barn never. Four
        // rounds of time.
        let rounds = RefCell::new(1);
        let (still, lost) = check_with(
            &[probe("Cabin", 2), probe("Lake", 3), probe("Barn", 4)],
            |address| {
                Ok(match address.octets()[3] {
                    2 => true,
                    3 => *rounds.borrow() >= 3,
                    _ => false,
                })
            },
            || {
                let mut rounds = rounds.borrow_mut();
                *rounds += 1;
                *rounds <= 4
            },
        )
        .unwrap();

        assert_eq!(still, ["Cabin", "Lake"]);
        assert_eq!(lost, ["Barn"]);
    }

    #[test]
    fn once_every_peer_answers_the_check_ends() {
        let (still, lost) =
            check_with(&[probe("Cabin", 2)], |_| Ok(true), || panic!("waited")).unwrap();
        assert_eq!(still, ["Cabin"]);
        assert!(lost.is_empty());
        // Nothing to check: nothing pinged, no waiting.
        let (still, lost) = check_with(&[], |_| panic!("pinged"), || panic!("waited")).unwrap();
        assert!(still.is_empty() && lost.is_empty());
    }
}
