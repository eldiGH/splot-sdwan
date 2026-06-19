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

pub(crate) fn error_at(report: &ValidationReport, path_substr: &str) -> bool {
    report
        .errors
        .iter()
        .any(|e| e.path().to_string().contains(path_substr))
}
