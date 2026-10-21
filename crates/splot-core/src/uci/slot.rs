//! Where the secrets go in the uci config: what's rendered records each one's
//! place (its slot) and holds its placeholder there. The node fills the secrets
//! in at those places alone, so that doesn't depend on what a value looks like.

use serde::{Deserialize, Serialize};

use crate::secret::Secret;

/// Where a secret goes: one option of one section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Slot {
    pub file: String,
    pub section: String,
    pub option: String,
    pub secret: Secret,
}

impl Slot {
    /// Its option's uci path, the way `set` names it.
    pub fn path(&self) -> String {
        format!("{}.{}.{}", self.file, self.section, self.option)
    }
}
