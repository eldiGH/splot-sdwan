//! The secrets a rendered config needs. What's rendered holds a placeholder in
//! each one's place and records where it is (its slot): apply fills the secrets
//! in from the node's key store, and the dry run shows the placeholders again.
//! Only the recorded places are filled in or masked, so neither depends on what a
//! value looks like.

use super::uci::UciBatchCommand;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Secret {
    /// The node's private key.
    PrivateKey,
}

impl Secret {
    /// What the rendered config holds in its place. Not a valid key, so it can't
    /// pass for one.
    pub(super) fn placeholder(&self) -> &'static str {
        match self {
            Self::PrivateKey => "<private key>",
        }
    }
}

/// Where a secret goes: one option of one section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Slot {
    pub(super) file: &'static str,
    pub(super) section: String,
    pub(super) option: &'static str,
    pub(super) secret: Secret,
}

impl Slot {
    /// Its option's uci path, the way `set` names it.
    fn path(&self) -> String {
        format!("{}.{}.{}", self.file, self.section, self.option)
    }
}

/// `command` as the dry run shows it: a `set` of a slot shows the secret's
/// placeholder.
pub(super) fn masked(command: UciBatchCommand, slots: &[Slot]) -> UciBatchCommand {
    if let UciBatchCommand::Set(path, _) = &command
        && let Some(slot) = slots.iter().find(|slot| slot.path() == *path)
    {
        return UciBatchCommand::set(path, slot.secret.placeholder());
    }

    command
}

#[cfg(test)]
mod tests {
    use super::*;

    fn private_key_slot() -> Slot {
        Slot {
            file: "network",
            section: "spl_mesh".to_owned(),
            option: "private_key",
            secret: Secret::PrivateKey,
        }
    }

    #[test]
    fn the_dry_run_shows_a_slot_by_its_placeholder() {
        let slots = [private_key_slot()];

        assert_eq!(
            masked(
                UciBatchCommand::set("network.spl_mesh.private_key", "REAL_KEY"),
                &slots
            )
            .to_string(),
            "set network.spl_mesh.private_key='<private key>'"
        );
        // Anywhere else, the value shows as it is.
        assert_eq!(
            masked(
                UciBatchCommand::set("network.spl_mesh.proto", "REAL_KEY"),
                &slots
            )
            .to_string(),
            "set network.spl_mesh.proto='REAL_KEY'"
        );
        assert_eq!(
            masked(
                UciBatchCommand::set("network.spl_other.private_key", "REAL_KEY"),
                &slots
            )
            .to_string(),
            "set network.spl_other.private_key='REAL_KEY'"
        );
    }
}
