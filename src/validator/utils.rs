pub(super) fn is_valid_identifier(identifier: &str) -> bool {
    let mut chars = identifier.chars();
    match chars.next() {
        None => false,
        Some(first) => {
            first.is_alphanumeric() && chars.all(|c| c.is_alphanumeric() || c == '_' || c == '-')
        }
    }
}
