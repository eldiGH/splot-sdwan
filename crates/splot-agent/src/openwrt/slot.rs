//! The dry run shows the secrets apply fills in as their placeholders again:
//! at their slots alone, so that doesn't depend on what a value looks like.

use splot_core::uci::slot::Slot;

use super::uci::UciBatchCommand;

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
    use splot_core::secret::Secret;

    use super::*;

    fn private_key_slot() -> Slot {
        Slot {
            file: "network".to_owned(),
            section: "spl_mesh".to_owned(),
            option: "private_key".to_owned(),
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
