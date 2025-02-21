pub mod endpoints;

pub mod model;

pub mod service;

pub fn get_sanitize_filename(sbom_name: String) -> String {
    let options = sanitize_filename::Options {
        truncate: true,
        windows: true,
        replacement: "_",
    };
    sanitize_filename::sanitize_with_options(sbom_name, options)
}
