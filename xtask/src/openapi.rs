use anyhow::{anyhow, Context};
use clap::Parser;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};
use trustify_server::openapi::openapi;

#[derive(Debug, Parser)]
pub struct Validate {
    /// should the openapi.yaml be exported too?
    #[arg(short, long, default_value = "false")]
    export: bool,
}

impl Validate {
    pub fn run(self) -> anyhow::Result<()> {
        let command = if command_exists("podman") {
            "podman"
        } else if command_exists("docker") {
            "docker"
        } else {
            return Err(anyhow!(
                "This task requires podman or docker to be installed."
            ));
        };

        let out_dir = env::temp_dir();
        let openapi_yaml = Path::new(&out_dir).join("openapi.yaml");

        let doc = openapi()
            .to_yaml()
            .map_err(|_| anyhow!("Failed to convert openapi spec to yaml"))?;

        if self.export {
            println!("Writing openapi.yaml to {:?}", "openapi_yaml");
            write_openapi(None)?;
        }

        println!("Writing openapi.yaml to {:?}", openapi_yaml);
        fs::write(openapi_yaml, doc).map_err(|_| anyhow!("Failed to write openapi spec"))?;

        // run the openapi generator validator container
        if Command::new(command)
            .args([
                "run",
                "--rm",
                "-v",
                ".:/src",
                "--security-opt",
                "label=disable",
                "docker.io/openapitools/openapi-generator-cli:v7.7.0",
                "validate",
                "-i",
                "/src/openapi.yaml",
            ])
            .current_dir(out_dir.to_str().unwrap())
            .status()
            .map_err(|_| anyhow!("Failed to validate openapi.yaml"))?
            .success()
        {
            Ok(())
        } else {
            Err(anyhow!("Failed to validate openapi.yaml"))
        }
    }
}

fn command_exists(cmd: &str) -> bool {
    match Command::new("which").arg(cmd).output() {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}

pub fn write_openapi(base: Option<&Path>) -> anyhow::Result<()> {
    let doc = openapi()
        .to_yaml()
        .context("Failed to convert openapi spec to yaml")?;

    let mut path = PathBuf::from("openapi.yaml");
    if let Some(base) = base {
        path = base.join(path);
    }

    fs::write(path, doc).context("Failed to write openapi spec")?;

    Ok(())
}
