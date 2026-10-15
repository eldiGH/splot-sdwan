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

/// A fixture that must pass validation: its config, and the network it describes.
pub(crate) fn checked(yaml: &str) -> (Config, Network) {
    let config = config(yaml);

    match model::validate(&config) {
        Ok(validated) => (config, validated.network),
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
