use crate::{
    config::Config,
    model::{
        self, Network,
        validator::types::{ValidationError, ValidationReport, ValidationWarning},
    },
};

pub(crate) fn config(yaml: &str) -> Config {
    serde_norway::from_str(yaml).expect("test fixture YAML failed to parse")
}

pub(crate) fn report(yaml: &str) -> ValidationReport {
    match model::validate(&config(yaml)) {
        Ok(validated) => ValidationReport {
            errors: Vec::new(),
            warnings: validated.warnings,
        },
        Err(report) => report,
    }
}

/// A fixture that must pass validation, as the network it describes.
pub(crate) fn checked(yaml: &str) -> Network {
    match model::validate(&config(yaml)) {
        Ok(validated) => validated.network,
        Err(report) => panic!(
            "test fixture doesn't validate: {:?}",
            report
                .errors
                .iter()
                .map(|error| error.to_string())
                .collect::<Vec<_>>()
        ),
    }
}

pub(crate) fn has_error(report: &ValidationReport, f: impl Fn(&ValidationError) -> bool) -> bool {
    report.errors.iter().any(f)
}

pub(crate) fn has_warning(
    report: &ValidationReport,
    f: impl Fn(&ValidationWarning) -> bool,
) -> bool {
    report.warnings.iter().any(f)
}

/// Like `has_error`, but also requires the matching error's location (`at`) to
/// render exactly to `path`. Use this to pin down *where* a diagnostic points,
/// not just that it fired — the typed `ConfigLocation` can hold a valid-but-wrong
/// variant that only a location assertion catches.
pub(crate) fn error_at(
    report: &ValidationReport,
    path: &str,
    f: impl Fn(&ValidationError) -> bool,
) -> bool {
    report
        .errors
        .iter()
        .any(|e| e.path().to_string() == path && f(e))
}

/// `has_warning` counterpart of [`error_at`].
pub(crate) fn warning_at(
    report: &ValidationReport,
    path: &str,
    f: impl Fn(&ValidationWarning) -> bool,
) -> bool {
    report
        .warnings
        .iter()
        .any(|w| w.path().to_string() == path && f(w))
}

/// A directory of its own under the system's temp dir, gone when dropped.
pub(crate) struct TempDir(pub(crate) std::path::PathBuf);

impl TempDir {
    pub(crate) fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("splot-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
