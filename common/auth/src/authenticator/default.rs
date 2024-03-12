use std::collections::HashMap;

/// Default scope mappings (in a `const` form).
///
/// See [`default_scope_mappings`] for a `HashMap` form.
///
/// This should be aligned with the default Keycloak configuration we use for local deployments.
/// It can be overridden by configuration.
pub const DEFAULT_SCOPE_MAPPINGS: &[(&str, &[&str])] = &[
    (
        "create:document",
        &["create.sbom", "create.vex", "create.vulnerability"],
    ),
    ("read:document", &["read.sbom", "read.vex"]),
    ("update:document", &["update.sbom", "update.vex"]),
    ("delete:document", &["delete.sbom", "delete.vex"]),
];

/// A convenience function to get the default scopes in an allocated form.
pub fn default_scope_mappings() -> HashMap<String, Vec<String>> {
    DEFAULT_SCOPE_MAPPINGS
        .iter()
        .map(|(k, v)| (k.to_string(), v.iter().map(ToString::to_string).collect()))
        .collect()
}
