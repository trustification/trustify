use trustify_auth::auth::AuthConfig;

fn main() -> anyhow::Result<()> {
    let schema = schemars::schema_for!(AuthConfig);
    let path = "common/auth/schema/auth.json";
    {
        let file = std::fs::File::create(path)?;
        serde_json::to_writer_pretty(file, &schema)?;
    }
    println!("Wrote schema to: {path}");

    Ok(())
}
