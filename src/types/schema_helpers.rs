use std::{
    collections::{self, BTreeSet},
    ops::Deref,
};

use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct OneOrManyUnique<T>(pub BTreeSet<T>);

impl<T> Default for OneOrManyUnique<T> {
    fn default() -> Self {
        Self(BTreeSet::new())
    }
}

impl<T> From<OneOrManyUnique<T>> for BTreeSet<T> {
    fn from(value: OneOrManyUnique<T>) -> Self {
        value.0
    }
}

impl<T> Deref for OneOrManyUnique<T> {
    type Target = BTreeSet<T>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a, T> IntoIterator for &'a OneOrManyUnique<T> {
    type Item = &'a T;
    type IntoIter = collections::btree_set::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'de, T: Deserialize<'de> + Ord> Deserialize<'de> for OneOrManyUnique<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        #[serde(bound = "T: Deserialize<'de> + Ord")]
        enum Helper<T> {
            One(T),
            Many(BTreeSet<T>),
        }

        Helper::deserialize(deserializer).map(|h| match h {
            Helper::One(x) => OneOrManyUnique(BTreeSet::from([x])),
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
    fn deref_gives_btreeset() {
        let omu = parse("values: hello");
        // Deref to BTreeSet lets us call BTreeSet methods directly
        assert!(omu.contains("hello"));
    }

    #[test]
    fn into_iter_yields_all_items() {
        let omu = parse("values:\n  - a\n  - b");
        let collected: BTreeSet<&String> = omu.iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn iterates_in_sorted_order_regardless_of_input_order() {
        // The whole point of BTreeSet: output order is deterministic.
        let omu = parse("values:\n  - charlie\n  - alpha\n  - bravo");
        let items: Vec<&str> = omu.iter().map(String::as_str).collect();
        assert_eq!(items, ["alpha", "bravo", "charlie"]);
    }

    #[test]
    fn into_btreeset_conversion() {
        let omu = parse("values:\n  - x\n  - y");
        let set: BTreeSet<String> = omu.into();
        assert!(set.contains("x"));
        assert!(set.contains("y"));
    }
}
