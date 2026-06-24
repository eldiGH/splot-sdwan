use crate::{
    config::Config,
    validator::{
        self,
        types::{ValidationError, ValidationReport, ValidationWarning},
    },
};

pub(crate) fn config(yaml: &str) -> Config {
    serde_yml::from_str(yaml).expect("test fixture YAML failed to parse")
}

pub(crate) fn report(yaml: &str) -> ValidationReport {
    let cfg = config(yaml);
    validator::validate_config(&cfg)
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
