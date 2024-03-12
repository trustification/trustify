/// The default issuer when using `--devmode`.
const ISSUER_URL: &str = "http://localhost:8090/realms/chicken";

/// The clients which will be accepted by services when running with `--devmode`.
///
/// This also includes the "testing" clients, as this allows running the testsuite against an
/// already spun-up set of services.
pub const CLIENT_IDS: &[&str] = &["frontend", "walker", "testing-user", "testing-manager"];

/// The default "service" client ID for devmode
pub const SERVICE_CLIENT_ID: &str = "testing-manager";

pub const SWAGGER_UI_CLIENT_ID: &str = "frontend";

/// Static client secret for testing, configured in `deploy/compose/container_files/init-sso/data/client-*.json`.
///
/// This is not a secret. Don't use this in production.
pub const SSO_CLIENT_SECRET: &str = "R8A6KFeyxJsMDBhjfHbpZTIF0GWt43HP";

/// Get the issuer URL for `--devmode`.
///
/// This can be either the value of [`ISSUER_URL`], or it can be overridden using the environment
/// variable `ISSUER_URL`.
pub fn issuer_url() -> String {
    std::env::var("ISSUER_URL").unwrap_or_else(|_| ISSUER_URL.to_string())
}
