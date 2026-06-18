use std::{
    collections::{self, HashSet},
    hash::Hash,
    ops::Deref,
};

use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct OneOrManyUnique<T>(pub HashSet<T>);

impl<T> Default for OneOrManyUnique<T> {
    fn default() -> Self {
        Self(HashSet::new())
    }
}

impl<T> From<OneOrManyUnique<T>> for HashSet<T> {
    fn from(value: OneOrManyUnique<T>) -> Self {
        value.0
    }
}

impl<T> Deref for OneOrManyUnique<T> {
    type Target = HashSet<T>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a, T> IntoIterator for &'a OneOrManyUnique<T> {
    type Item = &'a T;
    type IntoIter = collections::hash_set::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'de, T: Deserialize<'de> + Hash + Eq> Deserialize<'de> for OneOrManyUnique<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        #[serde(bound = "T: Deserialize<'de> + Hash + Eq")]
        enum Helper<T> {
            One(T),
            Many(HashSet<T>),
        }

        Helper::deserialize(deserializer).map(|h| match h {
            Helper::One(x) => OneOrManyUnique(HashSet::from([x])),
            Helper::Many(xs) => OneOrManyUnique(xs),
        })
    }
}
