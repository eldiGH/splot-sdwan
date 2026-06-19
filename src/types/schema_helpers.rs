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

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Wrapper {
        #[serde(default)]
        values: OneOrManyUnique<String>,
    }

    fn parse(yaml: &str) -> OneOrManyUnique<String> {
        serde_yml::from_str::<Wrapper>(yaml).unwrap().values
    }

    #[test]
    fn single_scalar_becomes_set_of_one() {
        let omu = parse("values: hello");
        assert_eq!(omu.len(), 1);
        assert!(omu.contains("hello"));
    }

    #[test]
    fn list_becomes_set() {
        let omu = parse("values:\n  - alpha\n  - beta");
        assert_eq!(omu.len(), 2);
        assert!(omu.contains("alpha"));
        assert!(omu.contains("beta"));
    }

    #[test]
    fn duplicates_are_deduped() {
        let omu = parse("values:\n  - same\n  - same");
        assert_eq!(omu.len(), 1);
    }

    #[test]
    fn default_is_empty() {
        let omu = parse("{}");
        assert!(omu.is_empty());
    }

    #[test]
    fn deref_gives_hashset() {
        let omu = parse("values: hello");
        // Deref to HashSet lets us call HashSet methods directly
        assert!(omu.contains("hello"));
    }

    #[test]
    fn into_iter_yields_all_items() {
        let omu = parse("values:\n  - a\n  - b");
        let collected: HashSet<&String> = omu.iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn into_hashset_conversion() {
        let omu = parse("values:\n  - x\n  - y");
        let set: HashSet<String> = omu.into();
        assert!(set.contains("x"));
        assert!(set.contains("y"));
    }
}
