//! A run, all or nothing: across the mesh (`splot apply`), every node splot
//! manages, each reached at its platform.ssh; on one node (`--node`), the same
//! run on a mesh of one. splot plans every node and asks before it applies
//! anything. Then it prepares every node, one at a time (each keeps what it has
//! and starts its own rollback timer), and once all are prepared, gives each
//! the go, all at once. It reaches every node again and has each check its
//! peers, one at a time: when all still answer, every node is confirmed;
//! anything else, every node puts back what it had.

use std::{
    io::{self, IsTerminal, Write},
    mem, thread,
    time::{Duration, Instant},
};

use anyhow::{Context, bail};
use splot_core::protocol::{Changes, Probe, Rendered, Reply, Request, Run};

use crate::{
    agent::{self, Agent},
    backend, commands,
    model::Network,
    types::identifier::Identifier,
};

/// How long after a node's deadline splot looks at it again: the time its
/// watchdog takes to notice, and to put back what the node had.
const AFTER_DEADLINE: Duration = Duration::from_secs(10);
/// Between two tries to reach a node again to confirm it.
const RETRY: Duration = Duration::from_secs(2);

/// A node in the run: what splot asks of it.
struct Member {
    name: Identifier,
    rendered: Rendered,
    probes: Vec<Probe>,
}

/// How far a node may have got in the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Nothing of the run there.
    Untouched,
    /// Prepared: it has the run, nothing applied.
    Prepared,
    /// Given the go: what it prepared may be applied.
    Applied,
}

/// `splot apply` without `--node`: makes every node splot manages hold what the
/// config says, or none of them.
pub fn apply(
    network: &Network,
    dry_run: bool,
    confirm_within: u32,
    yes: bool,
) -> anyhow::Result<()> {
    let members = members(network)?;
    if members.is_empty() {
        println!("splot manages nothing on any node.");
        return Ok(());
    }

    run(Mesh::new(members), dry_run, confirm_within, yes)
}

/// `splot apply --node`: the same run, on `node` alone, reached through
/// `agent`.
pub fn apply_node(
    network: &Network,
    node: &Identifier,
    agent: Agent,
    dry_run: bool,
    confirm_within: u32,
    yes: bool,
) -> anyhow::Result<()> {
    let Some(member) = member(network, node)? else {
        println!("splot manages nothing on {node}.");
        return Ok(());
    };
    let mesh = Mesh::new(vec![(member, agent)]);

    run(mesh, dry_run, confirm_within, yes)
}

/// The run on every node of `mesh`: each holds what the config says, or none
/// does.
fn run(mut mesh: Mesh, dry_run: bool, confirm_within: u32, yes: bool) -> anyhow::Result<()> {
    if !dry_run && !yes && !io::stdin().is_terminal() {
        bail!(
            "splot asks before it applies, and there's no terminal to ask on: give --yes to apply without asking"
        );
    }

    // Every node reached, checked to be the node, and asked what it would
    // change, before anything changes.
    let planned = mesh.each(|_, member, agent| {
        match agent.ask(Request::DryRun {
            rendered: member.rendered.clone(),
        })? {
            Reply::DryRun { changes, warnings } => Ok((changes, warnings)),
            reply => Err(agent::unexpected(reply)),
        }
    });
    let (planned, warnings): (Vec<Changes>, Vec<Vec<String>>) = mesh
        .all(
            planned,
            &mesh.worded(
                |node| format!("splot couldn't plan {node}, so it changed nothing"),
                "splot couldn't plan every node, so it changed nothing",
            ),
        )?
        .into_iter()
        .unzip();

    print!("{}", plan_view(&mesh.members, &planned));
    // What each node's own config decides of what splot does: the operator's
    // to look at before agreeing, so after the plan.
    for (member, warnings) in mesh.members.iter().zip(&warnings) {
        for warning in warnings {
            eprintln!("warning: {}: {warning}", member.name);
        }
    }
    if planned.iter().all(Changes::is_empty) {
        println!("Nothing to change.");
        return Ok(());
    }
    if dry_run {
        return Ok(());
    }
    if !yes && !agreed()? {
        println!("Nothing applied.");
        return Ok(());
    }

    let id = agent::run_id();
    let deadline = Instant::now() + Duration::from_secs(confirm_within.into());
    let mut stages = vec![Stage::Untouched; mesh.members.len()];

    // Prepare every node, one at a time, since each pings its peers then (see
    // the check): each keeps what it has, and puts it back by itself unless
    // confirmed in time. Nothing is applied until all are.
    let prepared = mesh.in_turn(
        |_, member, agent| match agent.ask(Request::Prepare {
            rendered: member.rendered.clone(),
            run: Run {
                id: id.clone(),
                confirm_within,
                probes: member.probes.clone(),
            },
        })? {
            Reply::Prepared(changes) => Ok(changes),
            reply => Err(agent::unexpected(reply)),
        },
        |_| false,
    );
    let mut problems = Vec::new();
    for (index, result) in prepared.into_iter().enumerate() {
        match result {
            Ok(changes) => {
                stages[index] = Stage::Prepared;
                if changes != planned[index] {
                    problems.push((
                        index,
                        "what it would change isn't the plan any more".to_owned(),
                    ));
                }
            }
            Err(err) => {
                // Lost on the way: it may have the run.
                if agent::lost(&err) {
                    stages[index] = Stage::Prepared;
                }
                problems.push((index, format!("{err:#}")));
            }
        }
    }
    if !problems.is_empty() {
        mesh.put_back(&id, &stages, &planned, deadline);
        bail!(mesh.listed(
            &mesh.worded(
                |node| format!("splot couldn't prepare {node} as planned, so it changed nothing"),
                "splot couldn't prepare every node as planned, so no node changed anything",
            ),
            &problems
        ));
    }
    println!("Prepared: {}", mesh.names(|_| true));

    // The go, to every node at once.
    let gone = mesh.each(
        |_, _, agent| match agent.ask(Request::Go { run: id.clone() })? {
            Reply::Applied(changed) => Ok(changed),
            reply => Err(agent::unexpected(reply)),
        },
    );
    stages.fill(Stage::Applied);
    let problems = errors(&gone);
    if !problems.is_empty() {
        mesh.put_back(&id, &stages, &planned, deadline);
        bail!(mesh.listed(
            &mesh.worded(
                |node| format!("applying failed on {node}, so it didn't keep the change"),
                "applying failed on a node, so no node kept the change",
            ),
            &problems
        ));
    }
    println!(
        "Applied: {}",
        mesh.names(|index| !planned[index].is_empty())
    );

    // Each node reached again, over a session of its own, all at once; then
    // its peers checked, one node at a time. Two ends that ping each other at
    // once, neither with a session (a changed preshared key drops it), both
    // start a handshake, and WireGuard, which keeps one per peer, drops both
    // answers and tries again only seconds later. One at a time, a node finds
    // the session the nodes before it opened. The first node that isn't
    // healthy ends the checks: no node keeps the change then.
    mesh.reconnect();
    let mut connected = mesh.each(|_, _, agent| agent.connect());
    let checked = mesh.in_turn(
        |index, _, agent| {
            mem::replace(&mut connected[index], Ok(()))?;
            match agent.ask(Request::Check { run: id.clone() })? {
                Reply::Checked { still, lost } => Ok((still, lost)),
                reply => Err(agent::unexpected(reply)),
            }
        },
        |checked| !matches!(checked, Ok((_, lost)) if lost.is_empty()),
    );
    let mut cut = Vec::new();
    let mut unchecked = Vec::new();
    for (result, member) in checked.iter().zip(&mesh.members) {
        let name = &member.name;
        match result {
            Ok((still, lost)) => {
                let unanswered = unanswered(&member.probes, still, lost);
                if let Some(line) = as_before(name, still, &unanswered) {
                    println!("{line}");
                }
                if !lost.is_empty() {
                    println!("Checked {name}: lost {}", lost.join(", "));
                    cut.push(format!("{name} off from {}", lost.join(", ")));
                }
            }
            Err(err) => {
                println!("Couldn't check {name}: {err:#}");
                unchecked.push(name.to_string());
            }
        }
    }
    if checked.len() < mesh.members.len() {
        println!(
            "Didn't check {}: no node keeps the change anyway",
            mesh.names(|index| index >= checked.len())
        );
    }
    if !cut.is_empty() || !unchecked.is_empty() {
        mesh.put_back(&id, &stages, &planned, deadline);
        bail!(
            "{}, so {}",
            unhealthy(&cut, &unchecked),
            mesh.worded(|node| format!("{node} didn't keep it"), "no node kept it")
        );
    }

    // Every node confirmed.
    let confirmed = mesh.each(|_, _, agent| confirm(agent, &id, deadline));
    if confirmed.iter().all(Result::is_ok) {
        println!(
            "{}",
            mesh.worded(
                |node| format!("Confirmed: splot reached {node} again, and it keeps the change."),
                "Confirmed: splot reached every node again, and each keeps the change.",
            )
        );
        return Ok(());
    }
    mesh.unconfirmed(&id, confirmed, deadline)
}

/// Every node splot manages something on, in the config's order, with the
/// agent at its platform.ssh. Refused when one has no platform.ssh (naming
/// each), or splot can't apply it yet.
fn members(network: &Network) -> anyhow::Result<Vec<(Member, Agent)>> {
    let mut members = Vec::new();
    let mut unreachable = Vec::new();

    for node in network.nodes() {
        let Some(member) = member(network, node.name())? else {
            continue;
        };
        let Some(destination) = node.platform().ssh() else {
            unreachable.push(member.name.to_string());
            continue;
        };
        members.push((member, Agent::new(Some(destination.clone()), None)));
    }

    if !unreachable.is_empty() {
        bail!(
            "splot reaches every node it manages over ssh, at its platform.ssh, and the config gives {} none: add one, or apply each node alone with --node",
            unreachable.join(", ")
        );
    }

    Ok(members)
}

/// What the run asks of `node`; none when splot manages nothing there. Refused
/// when the config has no such node, or splot can't apply it yet.
fn member(network: &Network, node: &Identifier) -> anyhow::Result<Option<Member>> {
    let plan = commands::node_plan(network, node)?;
    if plan.wireguard.is_none() && plan.firewall.is_none() && plan.dhcp.is_none() {
        return Ok(None);
    }
    commands::check_applicable(network, node)?;

    Ok(Some(Member {
        name: node.clone(),
        rendered: backend::render(&plan, commands::node_platform(network, node)),
        probes: commands::probes(&plan),
    }))
}

/// Every node and its agent.
struct Mesh {
    members: Vec<Member>,
    agents: Vec<Agent>,
}

impl Mesh {
    fn new(members: Vec<(Member, Agent)>) -> Self {
        let (members, agents) = members.into_iter().unzip();

        Self { members, agents }
    }

    /// What the run says: `several`, of every node; in a run of one, `one`, of
    /// its node.
    fn worded(&self, one: impl FnOnce(&Identifier) -> String, several: &str) -> String {
        match self.members.as_slice() {
            [member] => one(&member.name),
            _ => several.to_owned(),
        }
    }

    /// `f` on every node at once, each with its index and agent; the results in
    /// the nodes' order.
    fn each<T: Send>(&mut self, f: impl Fn(usize, &Member, &mut Agent) -> T + Sync) -> Vec<T> {
        let f = &f;
        thread::scope(|scope| {
            let threads: Vec<_> = self
                .members
                .iter()
                .zip(&mut self.agents)
                .enumerate()
                .map(|(index, (member, agent))| scope.spawn(move || f(index, member, agent)))
                .collect();

            threads
                .into_iter()
                .map(|thread| {
                    thread
                        .join()
                        .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
                })
                .collect()
        })
    }

    /// `f` on one node at a time, in the nodes' order, until `stop` says so of
    /// a result: the results so far, in that order.
    fn in_turn<T>(
        &mut self,
        mut f: impl FnMut(usize, &Member, &mut Agent) -> T,
        stop: impl Fn(&T) -> bool,
    ) -> Vec<T> {
        let mut results = Vec::new();
        for (index, (member, agent)) in self.members.iter().zip(&mut self.agents).enumerate() {
            let result = f(index, member, agent);
            let stopped = stop(&result);
            results.push(result);
            if stopped {
                break;
            }
        }

        results
    }

    /// Every node's result, or an error naming each node that failed and why.
    fn all<T>(&self, results: Vec<anyhow::Result<T>>, what: &str) -> anyhow::Result<Vec<T>> {
        let problems = errors(&results);
        if !problems.is_empty() {
            bail!(self.listed(what, &problems));
        }

        Ok(results.into_iter().flatten().collect())
    }

    /// `what`, then why on each node (`problems`, by index), a line each after
    /// its name; in a run of one, which `what` names, why on the same line.
    fn listed(&self, what: &str, problems: &[(usize, String)]) -> String {
        if let ([_], [(_, why)]) = (self.members.as_slice(), problems) {
            return format!("{what}: {why}");
        }
        let lines: Vec<String> = problems
            .iter()
            .map(|(index, why)| format!("{}: {why}", self.members[*index].name))
            .collect();

        format!("{what}:\n  {}", lines.join("\n  "))
    }

    /// The names of the nodes `pick` picks, by index.
    fn names(&self, pick: impl Fn(usize) -> bool) -> String {
        let names: Vec<&str> = self
            .members
            .iter()
            .enumerate()
            .filter(|(index, _)| pick(*index))
            .map(|(_, member)| member.name.as_ref())
            .collect();

        names.join(", ")
    }

    /// Ends every session: the next request opens a new one.
    fn reconnect(&mut self) {
        for agent in &mut self.agents {
            agent.reconnect();
        }
    }

    /// The width of the widest name, to line up what follows them.
    fn width(&self) -> usize {
        self.members
            .iter()
            .map(|member| member.name.as_ref().len())
            .max()
            .unwrap_or_default()
    }

    /// Puts back what every node that may have run `id` (`stages`) had, all at
    /// once, and says how each ended. One splot can't reach is waited for until
    /// its deadline has passed, then asked again: it put back by itself.
    fn put_back(&mut self, id: &str, stages: &[Stage], planned: &[Changes], deadline: Instant) {
        println!(
            "Putting back {}:",
            self.worded(ToString::to_string, "every node")
        );
        let width = self.width();
        let put_back = self.each(|index, _, agent| {
            (stages[index] != Stage::Untouched).then(|| roll_back(agent, id))
        });

        let mut waiting = Vec::new();
        for (index, result) in put_back.iter().enumerate() {
            let name = &self.members[index].name;
            let changed = !planned[index].is_empty();
            match result {
                None | Some(Ok(())) => println!(
                    "  {name:width$}  {}",
                    put_back_label(stages[index], changed, false)
                ),
                Some(Err(err)) if agent::lost(err) => {
                    waiting.push(index);
                    println!(
                        "  {name:width$}  unreachable: waiting for its deadline ({} s)...",
                        until(deadline).as_secs()
                    );
                }
                Some(Err(err)) => println!("  {name:width$}  couldn't put back: {err:#}"),
            }
        }

        let looked = self.after_deadline(&waiting, deadline, |agent| roll_back(agent, id));
        for (index, result) in looked {
            let name = &self.members[index].name;
            let changed = !planned[index].is_empty();
            match result {
                Ok(()) => println!(
                    "  {name:width$}  {}",
                    put_back_label(stages[index], changed, true)
                ),
                Err(err) if agent::lost(&err) => {
                    println!("  {name:width$}  still unreachable: {err:#}");
                }
                Err(err) => println!("  {name:width$}  couldn't put back: {err:#}"),
            }
        }
    }

    /// When the nodes `waiting` (by index) are there, waits until their deadline
    /// has passed, then asks each again, over a new session, with `ask`.
    fn after_deadline(
        &mut self,
        waiting: &[usize],
        deadline: Instant,
        ask: impl Fn(&mut Agent) -> anyhow::Result<()> + Sync,
    ) -> Vec<(usize, anyhow::Result<()>)> {
        if waiting.is_empty() {
            return Vec::new();
        }
        thread::sleep(until(deadline) + AFTER_DEADLINE);

        let asked = self.each(|index, _, agent| {
            waiting.contains(&index).then(|| {
                agent.reconnect();
                ask(agent)
            })
        });

        asked
            .into_iter()
            .enumerate()
            .filter_map(|(index, result)| Some((index, result?)))
            .collect()
    }

    /// Reports the nodes whose confirm failed (`confirmed`), each that splot
    /// lost asked again after its deadline: it kept the change, or put back what
    /// it had by itself. The error saying which nodes didn't keep it.
    fn unconfirmed(
        &mut self,
        id: &str,
        confirmed: Vec<anyhow::Result<()>>,
        deadline: Instant,
    ) -> anyhow::Result<()> {
        let width = self.width();
        let kept = self.names(|index| confirmed[index].is_ok());
        if !kept.is_empty() {
            println!("Confirmed: {kept}");
        }

        let mut waiting = Vec::new();
        let mut failed = Vec::new();
        for (index, result) in confirmed.iter().enumerate() {
            let Err(err) = result else { continue };
            let name = &self.members[index].name;
            if agent::lost(err) {
                waiting.push(index);
                println!(
                    "  {name:width$}  unreachable: waiting for its deadline ({} s)...",
                    until(deadline).as_secs()
                );
            } else {
                failed.push(name.to_string());
                println!("  {name:width$}  couldn't confirm: {err:#}");
            }
        }

        let looked = self.after_deadline(&waiting, deadline, |agent| confirm_once(agent, id));
        for (index, result) in looked {
            let name = &self.members[index].name;
            match result {
                Ok(()) => println!("  {name:width$}  kept the change"),
                Err(err) => {
                    failed.push(name.to_string());
                    println!("  {name:width$}  {err:#}");
                }
            }
        }

        if failed.is_empty() {
            return Ok(());
        }
        let others = if failed.len() < self.members.len() {
            ", the other nodes did"
        } else {
            ""
        };
        bail!(
            "{} didn't keep the change{others}: {}",
            failed.join(", "),
            self.worded(
                |node| format!("run splot apply --node {node} again"),
                "run splot apply again"
            )
        )
    }
}

/// Each node's error among `results`, by index.
fn errors<T>(results: &[anyhow::Result<T>]) -> Vec<(usize, String)> {
    results
        .iter()
        .enumerate()
        .filter_map(|(index, result)| Some((index, format!("{:#}", result.as_ref().err()?))))
        .collect()
}

/// Puts back what the node had before run `id`; asked once more over a new
/// session when splot lost the node.
fn roll_back(agent: &mut Agent, id: &str) -> anyhow::Result<()> {
    let ask = |agent: &mut Agent| match agent.ask(Request::Rollback { run: id.to_owned() })? {
        Reply::RolledBack => Ok(()),
        reply => Err(agent::unexpected(reply)),
    };

    match ask(agent) {
        Err(err) if agent::lost(&err) => {
            agent.reconnect();
            ask(agent)
        }
        result => result,
    }
}

/// Confirms run `id` on the node, asking again over a new session while splot
/// can't reach it and there's time before the deadline.
fn confirm(agent: &mut Agent, id: &str, deadline: Instant) -> anyhow::Result<()> {
    loop {
        match confirm_once(agent, id) {
            Err(err) if agent::lost(&err) && Instant::now() + RETRY < deadline => {
                agent.reconnect();
                thread::sleep(RETRY);
            }
            result => return result,
        }
    }
}

fn confirm_once(agent: &mut Agent, id: &str) -> anyhow::Result<()> {
    match agent.ask(Request::Confirm { run: id.to_owned() })? {
        Reply::Confirmed => Ok(()),
        reply => Err(agent::unexpected(reply)),
    }
}

/// How long until `deadline`; nothing once it has passed.
fn until(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

/// How a node ended up once put back, given how far it got (`stage`), whether
/// its plan changed anything, and whether it did so `by_itself`, at its
/// deadline.
fn put_back_label(stage: Stage, changed: bool, by_itself: bool) -> &'static str {
    match (stage, changed) {
        (Stage::Untouched, _) | (_, false) => "nothing to put back",
        (Stage::Prepared, true) => "nothing applied",
        (Stage::Applied, true) if by_itself => "put back by itself",
        (Stage::Applied, true) => "put back",
    }
}

/// The plan, node by node: what each would change, as its dry run shows it.
fn plan_view(members: &[Member], planned: &[Changes]) -> String {
    let mut view = String::new();
    for (member, changes) in members.iter().zip(planned) {
        if changes.is_empty() {
            view.push_str(&format!("== {}: nothing to change\n", member.name));
        } else {
            view.push_str(&format!(
                "== {}: {}\n{}",
                member.name,
                changes.summary.join(", "),
                changes.text
            ));
        }
    }

    view
}

/// Why the change can't be kept: the nodes it cut off from peers (`cut`: "Home
/// off from Cabin"), and those splot couldn't check.
fn unhealthy(cut: &[String], unchecked: &[String]) -> String {
    let mut why = Vec::new();
    if !cut.is_empty() {
        why.push(format!("the change cut {}", cut.join(", and ")));
    }
    if !unchecked.is_empty() {
        why.push(format!("splot couldn't check {}", unchecked.join(", ")));
    }

    why.join("; ")
}

/// Of a node's `probes`, the peers its check left out: those that didn't
/// answer before the run, so neither answer `still` nor were `lost`.
fn unanswered(probes: &[Probe], still: &[String], lost: &[String]) -> Vec<String> {
    probes
        .iter()
        .map(|probe| &probe.peer)
        .filter(|peer| !still.contains(peer) && !lost.contains(peer))
        .cloned()
        .collect()
}

/// What `node`'s check found as it was before the run: the peers that `still`
/// answer, and those it didn't check, since they didn't answer then
/// (`unanswered`). None when there are neither.
fn as_before(node: &Identifier, still: &[String], unanswered: &[String]) -> Option<String> {
    let mut found = Vec::new();
    if !still.is_empty() {
        found.push(format!("{} as before", answer(still)));
    }
    if !unanswered.is_empty() {
        found.push(format!(
            "not {}, which didn't answer before the run",
            unanswered.join(", ")
        ));
    }

    (!found.is_empty()).then(|| format!("Checked {node}: {}", found.join("; ")))
}

/// `peers` and the verb that goes with them: "Cabin answers", "Cabin, Lake
/// answer".
fn answer(peers: &[String]) -> String {
    let verb = if peers.len() == 1 {
        "answers"
    } else {
        "answer"
    };
    format!("{} {verb}", peers.join(", "))
}

/// Asks the operator whether to apply the plan: only yes does.
fn agreed() -> anyhow::Result<bool> {
    print!("Apply this plan? [y/N] ");
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .context("can't read the answer")?;

    Ok(is_yes(&answer))
}

fn is_yes(answer: &str) -> bool {
    matches!(answer.trim().to_lowercase().as_str(), "y" | "yes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::checked;

    /// Home and Cabin, each with `home` and `cabin` as its platform block's
    /// extra lines; Lake, where splot manages nothing.
    fn mesh(home: &str, cabin: &str) -> Network {
        checked(&format!(
            "
meshNetwork: 10.100.0.0/16
nodes:
  Home:
    platform:
      os: openwrt
{home}
    publicKey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    endpoint: 1.2.3.4
    wanZone: wan
    listenPort: 51820
    meshIp: 10.100.0.1
  Cabin:
    platform:
{cabin}
    publicKey: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA=
    endpoint: 5.6.7.8
    wanZone: wan
    listenPort: 51820
    meshIp: 10.100.0.2
  Lake:
    platform:
      os: openwrt
      wireguard: none
      firewall: none
      dhcp: none
    publicKey: LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLA=
    listenPort: 51820
    meshIp: 10.100.0.3
"
        ))
    }

    const HOME_SSH: &str = "      ssh: root@192.168.1.1";
    const CABIN: &str = "      os: openwrt\n      ssh: cabin";

    fn name(name: &str) -> Identifier {
        name.parse().unwrap()
    }

    /// Where `agent` reaches its node.
    fn destination(agent: &Agent) -> &str {
        match agent {
            Agent::Remote { destination, .. } => destination.as_str(),
            Agent::Local(_) => "here",
        }
    }

    fn peers(member: &Member) -> Vec<&str> {
        member
            .probes
            .iter()
            .map(|probe| probe.peer.as_str())
            .collect()
    }

    #[test]
    fn every_node_splot_manages_takes_part_reached_at_its_platform_ssh() {
        let members = members(&mesh(HOME_SSH, CABIN)).unwrap();

        // Lake, where splot manages nothing, needs no ssh and isn't asked.
        let names: Vec<&str> = members.iter().map(|(m, _)| m.name.as_ref()).collect();
        assert_eq!(names, ["Cabin", "Home"]);
        let destinations: Vec<&str> = members.iter().map(|(_, a)| destination(a)).collect();
        assert_eq!(destinations, ["cabin", "root@192.168.1.1"]);
        // Each checks its node peers after the change, Lake included: it's in
        // the mesh, its WireGuard set up by hand.
        assert_eq!(peers(&members[1].0), ["Cabin", "Lake"]);
    }

    #[test]
    fn a_run_on_one_node_is_that_node_alone_wherever_it_is_reached() {
        // No platform.ssh needed: the command says where it is.
        let network = mesh("", "      os: openwrt");

        let home = member(&network, &name("Home")).unwrap().unwrap();
        assert_eq!(home.name.as_ref(), "Home");
        assert_eq!(peers(&home), ["Cabin", "Lake"]);

        // Where splot manages nothing, there's no run.
        assert!(member(&network, &name("Lake")).unwrap().is_none());
        let err = member(&network, &name("Pond")).err().unwrap();
        assert_eq!(
            err.to_string(),
            "there's no node Pond in the config; its nodes are Cabin, Home, Lake"
        );
    }

    #[test]
    fn a_node_where_splot_manages_one_concern_takes_part() {
        for alone in ["firewall", "dhcp"] {
            let other = if alone == "firewall" {
                "dhcp"
            } else {
                "firewall"
            };
            let cabin = format!(
                "      os: openwrt
      wireguard: none
      {other}: none
      ssh: cabin"
            );
            let network = mesh(HOME_SSH, &cabin);
            let members = members(&network).unwrap();

            let names: Vec<&str> = members.iter().map(|(m, _)| m.name.as_ref()).collect();
            assert_eq!(names, ["Cabin", "Home"], "{alone} alone");
            // No WireGuard of splot's there: no peers to check.
            assert!(members[0].0.probes.is_empty());
            assert!(member(&network, &name("Cabin")).unwrap().is_some());
        }
    }

    #[test]
    fn a_node_splot_manages_without_platform_ssh_is_named() {
        let err = members(&mesh("", "      os: openwrt")).err().unwrap();
        assert_eq!(
            err.to_string(),
            "splot reaches every node it manages over ssh, at its platform.ssh, and the config gives Cabin, Home none: add one, or apply each node alone with --node"
        );
    }

    #[test]
    fn a_node_splot_cant_apply_yet_stops_the_run_before_it_starts() {
        let barn = "      os: linux
      wireguard: wg-quick
      firewall: nftables
      dhcp: dnsmasq
      dns: none
      ssh: barn
      interfaces: { wan: eth0 }";
        let network = mesh(HOME_SSH, barn);
        for err in [
            members(&network).err().unwrap(),
            member(&network, &name("Cabin")).err().unwrap(),
        ] {
            assert!(
                err.to_string()
                    .starts_with("splot can't manage Cabin's dhcp (dnsmasq) on Linux yet"),
                "{err}"
            );
        }
    }

    /// The run across `network`, and the one on Home alone.
    fn runs(network: &Network) -> (Mesh, Mesh) {
        let home = member(network, &name("Home")).unwrap().unwrap();
        let alone = Agent::new(Some("home".parse().unwrap()), None);

        (
            Mesh::new(members(network).unwrap()),
            Mesh::new(vec![(home, alone)]),
        )
    }

    #[test]
    fn in_turn_asks_one_node_after_another_until_a_result_stops_it() {
        let (mut several, _) = runs(&mesh(HOME_SSH, CABIN));

        let mut asked = Vec::new();
        let results = several.in_turn(
            |index, member, _| {
                asked.push(member.name.to_string());
                index
            },
            |_| false,
        );
        assert_eq!(results, [0, 1]);
        assert_eq!(asked, ["Cabin", "Home"]);

        // The node whose result stops it is the last one asked.
        let results = several.in_turn(|index, _, _| index, |&index| index == 0);
        assert_eq!(results, [0]);
        let results = several.in_turn(|index, _, _| index, |&index| index == 1);
        assert_eq!(results, [0, 1]);
    }

    #[test]
    fn a_run_of_one_names_its_node_where_a_mesh_says_every_node() {
        let (several, one) = runs(&mesh(HOME_SSH, CABIN));
        let kept =
            |mesh: &Mesh| mesh.worded(|node| format!("{node} didn't keep it"), "no node kept it");

        assert_eq!(kept(&several), "no node kept it");
        assert_eq!(kept(&one), "Home didn't keep it");
    }

    #[test]
    fn why_each_node_failed_is_listed_after_its_name_in_a_run_of_one_after_what() {
        let (several, one) = runs(&mesh(HOME_SSH, CABIN));
        let refused = |index| (index, "refused".to_owned());

        assert_eq!(
            several.listed("splot couldn't plan every node", &[refused(0), refused(1)]),
            "splot couldn't plan every node:\n  Cabin: refused\n  Home: refused"
        );
        // One node failing of several is still named.
        assert_eq!(
            several.listed("splot couldn't plan every node", &[refused(1)]),
            "splot couldn't plan every node:\n  Home: refused"
        );
        assert_eq!(
            one.listed("splot couldn't plan Home", &[refused(0)]),
            "splot couldn't plan Home: refused"
        );
    }

    #[test]
    fn a_failed_confirm_names_the_nodes_that_didnt_keep_the_change() {
        let (mut several, mut one) = runs(&mesh(HOME_SSH, CABIN));
        // Refused, not lost: nothing to wait for.
        let refused = || -> anyhow::Result<()> { Err(anyhow::anyhow!("too late")) };
        let unconfirmed = |mesh: &mut Mesh, confirmed: Vec<anyhow::Result<()>>| {
            mesh.unconfirmed("r1", confirmed, Instant::now())
                .unwrap_err()
                .to_string()
        };

        assert_eq!(
            unconfirmed(&mut several, vec![refused(), Ok(())]),
            "Cabin didn't keep the change, the other nodes did: run splot apply again"
        );
        assert_eq!(
            unconfirmed(&mut several, vec![refused(), refused()]),
            "Cabin, Home didn't keep the change: run splot apply again"
        );
        assert_eq!(
            unconfirmed(&mut one, vec![refused()]),
            "Home didn't keep the change: run splot apply --node Home again"
        );
    }

    #[test]
    fn the_plan_shows_each_node_with_what_it_would_change() {
        let members: Vec<Member> = members(&mesh(HOME_SSH, CABIN))
            .unwrap()
            .into_iter()
            .map(|(member, _)| member)
            .collect();
        let planned = [
            Changes::none(),
            Changes {
                summary: vec!["network".to_owned(), "firewall".to_owned()],
                text: "set network.spl_mesh=interface\n".to_owned(),
            },
        ];

        assert_eq!(
            plan_view(&members, &planned),
            "== Cabin: nothing to change\n== Home: network, firewall\nset network.spl_mesh=interface\n"
        );
    }

    #[test]
    fn each_node_put_back_says_what_that_meant_for_it() {
        use Stage::*;

        assert_eq!(
            put_back_label(Untouched, true, false),
            "nothing to put back"
        );
        assert_eq!(put_back_label(Applied, false, false), "nothing to put back");
        assert_eq!(put_back_label(Applied, false, true), "nothing to put back");
        assert_eq!(put_back_label(Prepared, true, false), "nothing applied");
        assert_eq!(put_back_label(Applied, true, false), "put back");
        assert_eq!(put_back_label(Applied, true, true), "put back by itself");
    }

    #[test]
    fn only_yes_applies() {
        for yes in ["y\n", "Y\n", "yes\n", " YES \n"] {
            assert!(is_yes(yes), "{yes:?}");
        }
        for no in ["\n", "n\n", "no\n", "yess\n", ""] {
            assert!(!is_yes(no), "{no:?}");
        }
    }

    #[test]
    fn why_no_node_kept_the_change() {
        let cut = [
            "Cabin off from Home".to_owned(),
            "Home off from Cabin, Lake".to_owned(),
        ];
        let unchecked = ["Lake".to_owned()];

        assert_eq!(
            unhealthy(&cut, &[]),
            "the change cut Cabin off from Home, and Home off from Cabin, Lake"
        );
        assert_eq!(unhealthy(&[], &unchecked), "splot couldn't check Lake");
        assert_eq!(
            unhealthy(&cut[..1], &unchecked),
            "the change cut Cabin off from Home; splot couldn't check Lake"
        );
    }

    #[test]
    fn the_peers_a_check_left_out_are_those_neither_still_answering_nor_lost() {
        let probes: Vec<Probe> = ["Cabin", "Lake", "Barn"]
            .into_iter()
            .zip(1..)
            .map(|(peer, last)| Probe {
                peer: peer.to_owned(),
                public_key: format!("{}A=", char::from(b'A' + last).to_string().repeat(42))
                    .parse()
                    .unwrap(),
                address: format!("10.100.0.{last}").parse().unwrap(),
            })
            .collect();
        let named =
            |peers: &[&str]| -> Vec<String> { peers.iter().map(|&peer| peer.to_owned()).collect() };

        assert_eq!(
            unanswered(&probes, &named(&["Cabin"]), &named(&["Barn"])),
            ["Lake"]
        );
        assert!(unanswered(&probes, &named(&["Cabin", "Lake"]), &named(&["Barn"])).is_empty());
        assert_eq!(unanswered(&probes, &[], &[]), ["Cabin", "Lake", "Barn"]);
    }

    #[test]
    fn a_check_says_which_peers_answer_as_before_and_which_it_left_out() {
        let (cabin, lake) = (vec!["Cabin".to_owned()], vec!["Lake".to_owned()]);
        let home = name("Home");

        assert_eq!(
            as_before(&home, &cabin, &lake).as_deref(),
            Some(
                "Checked Home: Cabin answers as before; not Lake, which didn't answer before the run"
            )
        );
        assert_eq!(
            as_before(&home, &cabin, &[]).as_deref(),
            Some("Checked Home: Cabin answers as before")
        );
        assert_eq!(
            as_before(&home, &[], &[lake[0].clone(), "Barn".to_owned()]).as_deref(),
            Some("Checked Home: not Lake, Barn, which didn't answer before the run")
        );
        assert_eq!(as_before(&home, &[], &[]), None);
    }

    #[test]
    fn one_peer_answers_several_answer() {
        assert_eq!(answer(&["Cabin".to_owned()]), "Cabin answers");
        assert_eq!(
            answer(&["Cabin".to_owned(), "Lake".to_owned()]),
            "Cabin, Lake answer"
        );
    }
}
