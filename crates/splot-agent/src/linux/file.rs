//! Writing the files splot owns on a Linux node: whole, and those that hold
//! secrets readable by root only.

use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

/// Only root may read or write them, or list the directory splot makes for them.
const FILE_MODE: u32 = 0o600;
const DIR_MODE: u32 = 0o700;
/// Anyone may read it, as systemd's units are.
const PUBLIC_MODE: u32 = 0o644;

/// Writes `text` to `path` so that it's never seen half-written, nor readable
/// by anyone but root at any point: into a new file beside it, private from the
/// start, then renamed over it. The directory is made, private, if it's missing.
pub(super) fn write_private(path: &Path, text: &str) -> io::Result<()> {
    DirBuilder::new()
        .recursive(true)
        .mode(DIR_MODE)
        .create(dir(path)?)?;

    replace(path, text, FILE_MODE)
}

/// Writes `text` to `path`, in a directory that's there, readable by anyone,
/// never seen half-written.
pub(super) fn write_public(path: &Path, text: &str) -> io::Result<()> {
    replace(path, text, PUBLIC_MODE)
}

fn dir(path: &Path) -> io::Result<&Path> {
    path.parent()
        .ok_or_else(|| io::Error::other("a file's path names its directory"))
}

/// Writes `text` into a new file beside `path`, `mode` from the start, then
/// renames it over `path`.
fn replace(path: &Path, text: &str, mode: u32) -> io::Result<()> {
    let dir = dir(path)?;
    let mut name = path.file_name().unwrap_or_default().to_owned();
    name.push(".splot-new");
    let new = dir.join(name);
    // One a run that died left behind.
    match fs::remove_file(&new) {
        Err(err) if err.kind() != io::ErrorKind::NotFound => return Err(err),
        _ => {}
    }

    // Never more open than `mode`, from the start; set again after, since the
    // umask may have taken bits away from it.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&new)?;
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;

    fs::rename(&new, path)
}

#[cfg(test)]
mod tests {
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
    fn a_public_file_is_readable_by_anyone() {
        let temp = TempDir::new("write-public");
        let path = temp.0.join("splot-firewall.service");
        fs::write(&path, "old\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        write_public(&path, "new\n").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "new\n");
        assert_eq!(mode(&path), 0o644);
        assert_eq!(files(&temp.0), ["splot-firewall.service"]);
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
