//! Whether a peer's tunnel works: it answers a ping to its mesh IP. Every peer
//! may ping a node there (splot's firewall), and the ping brings the tunnel up
//! when it's idle.

use std::{
    net::Ipv4Addr,
    process::Command,
    thread,
    time::{Duration, Instant},
};

use splot_core::protocol::Probe;

use crate::process;

#[derive(Debug, thiserror::Error)]
#[error(
    "can't check the peers' tunnels: ping can't run here - install it (iputils-ping on Debian)"
)]
pub struct NoPing(#[source] process::Error);

/// Whether `address` answers a ping within a second.
fn answers(address: Ipv4Addr) -> Result<bool, NoPing> {
    let mut ping = Command::new("ping");
    ping.args(["-c", "1", "-W", "1", &address.to_string()]);

    Ok(process::run(ping, None).map_err(NoPing)?.status.success())
}

/// Of `probes`, those that answer now: before a run, so that only what worked
/// is checked after it.
pub fn answering(probes: &[Probe]) -> Result<Vec<Probe>, NoPing> {
    answering_with(probes, answers)
}

/// A peer that doesn't answer the first ping gets a second: an idle tunnel
/// may take the first to come up.
fn answering_with(
    probes: &[Probe],
    answers: impl Fn(Ipv4Addr) -> Result<bool, NoPing>,
) -> Result<Vec<Probe>, NoPing> {
    let mut answering = Vec::new();
    for probe in probes {
        if answers(probe.address)? || answers(probe.address)? {
            answering.push(probe.clone());
        }
    }

    Ok(answering)
}

/// Of `probes`, which still answer and which don't, by name. Each is pinged
/// again, a second apart, until it answers or `within` has passed: a tunnel may
/// need a moment after a reload.
pub fn check(probes: &[Probe], within: Duration) -> Result<(Vec<String>, Vec<String>), NoPing> {
    let deadline = Instant::now() + within;
    check_with(probes, answers, || {
        let more = Instant::now() < deadline;
        if more {
            thread::sleep(Duration::from_secs(1));
        }
        more
    })
}

/// `again` says whether there's time for another round (and waits for it).
fn check_with(
    probes: &[Probe],
    answers: impl Fn(Ipv4Addr) -> Result<bool, NoPing>,
    mut again: impl FnMut() -> bool,
) -> Result<(Vec<String>, Vec<String>), NoPing> {
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

    fn probe(peer: &str, last: u8) -> Probe {
        Probe {
            peer: peer.to_owned(),
            address: Ipv4Addr::new(10, 100, 0, last),
        }
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
        )
        .unwrap();

        let names: Vec<&str> = answering.iter().map(|probe| probe.peer.as_str()).collect();
        assert_eq!(names, ["Cabin", "Lake"]);
        assert_eq!(*pinged.borrow(), [2, 3, 3, 4, 4]);
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
