//! Writing the files splot owns on a Linux node, which hold secrets: whole,
//! and readable by root only.

use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
};

/// Only root may read or write them, or list the directory splot makes for them.
const FILE_MODE: u32 = 0o600;
const DIR_MODE: u32 = 0o700;

/// Writes `text` to `path` so that it's never seen half-written, nor readable
/// by anyone but root at any point: into a new file beside it, private from the
/// start, then renamed over it. The directory is made, private, if it's missing.
pub(super) fn write_private(path: &Path, text: &str) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::other("a file's path names its directory"))?;
    DirBuilder::new()
        .recursive(true)
        .mode(DIR_MODE)
        .create(dir)?;

    let mut name = path.file_name().unwrap_or_default().to_owned();
    name.push(".splot-new");
    let new = dir.join(name);
    // One a run that died left behind.
    match fs::remove_file(&new) {
        Err(err) if err.kind() != io::ErrorKind::NotFound => return Err(err),
        _ => {}
    }

    // The umask can only take bits away from the mode: never more than 0600.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .open(&new)?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;

    fs::rename(&new, path)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::test_support::{TempDir, mode};

    /// The names of the files in `dir`.
    fn files(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn a_new_file_is_readable_by_root_only_in_a_private_directory() {
        let temp = TempDir::new("write-new");
        let dir = temp.0.join("splot");
        let path = dir.join("keys");

        write_private(&path, "secret\n").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "secret\n");
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(&dir), 0o700);
        // Nothing else left beside it.
        assert_eq!(files(&dir), ["keys"]);
    }

    #[test]
    fn a_file_others_could_read_is_replaced_by_a_private_one() {
        let temp = TempDir::new("write-replace");
        let path = temp.0.join("keys");
        fs::write(&path, "old\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        // And a leftover from a run that died.
        fs::write(temp.0.join("keys.splot-new"), "half").unwrap();

        write_private(&path, "new\n").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "new\n");
        assert_eq!(mode(&path), 0o600);
        assert_eq!(files(&temp.0), ["keys"]);
    }

    #[test]
    fn an_existing_directory_keeps_its_mode() {
        // It may be the operator's, holding more than splot's files.
        let temp = TempDir::new("write-dir");
        fs::set_permissions(&temp.0, fs::Permissions::from_mode(0o755)).unwrap();

        write_private(&temp.0.join("keys"), "secret\n").unwrap();
        assert_eq!(mode(&temp.0), 0o755);
    }
}
