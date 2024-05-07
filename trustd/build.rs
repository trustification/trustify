use std::path::Path;
use std::process::{Command, ExitStatus};
use std::{fs, io};

static UI_DIR: &str = "../ui";
static UI_DIR_SRC: &str = "../ui/src";
static UI_DIST_DIR: &str = "../ui/client/dist";
static STATIC_DIR: &str = "../static";

#[cfg(windows)]
static GIT_CMD: &str = "git.cmd";
#[cfg(not(windows))]
static GIT_CMD: &str = "git";

#[cfg(windows)]
static NPM_CMD: &str = "npm.cmd";
#[cfg(not(windows))]
static NPM_CMD: &str = "npm";

fn main() {
    println!("Build Trustify - build.rs!");

    println!("cargo:rerun-if-changed={}", UI_DIR_SRC);

    let build_ui_status = clone_ui()
        .and_then(|_| install_ui_deps())
        .and_then(|_| build_ui())
        .and_then(|_| copy_dir_all(UI_DIST_DIR, STATIC_DIR));

    match build_ui_status {
        Ok(_) => println!("UI built successfully"),
        Err(_) => println!("Error while building UI"),
    }
}

fn clone_ui() -> io::Result<ExitStatus> {
    Command::new(GIT_CMD)
        .args(["submodule", "update", "--init", "--recursive"])
        .status()
}

fn install_ui_deps() -> io::Result<ExitStatus> {
    if !Path::new("../ui/node_modules").exists() {
        println!("Installing node dependencies...");
        Command::new(NPM_CMD)
            .args(["clean-install", "--ignore-scripts"])
            .current_dir(UI_DIR)
            .status()
    } else {
        Ok(ExitStatus::default())
    }
}

fn build_ui() -> io::Result<ExitStatus> {
    if !Path::new(STATIC_DIR).exists() || Path::new(STATIC_DIR).read_dir()?.next().is_none() {
        println!("Building UI...");
        Command::new(NPM_CMD)
            .args(["run", "build"])
            .current_dir(UI_DIR)
            .status()
    } else {
        Ok(ExitStatus::default())
    }
}

fn copy_dir_all(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> io::Result<()> {
    fs::create_dir_all(&dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(entry.path(), dst.as_ref().join(entry.file_name()))?;
        } else {
            fs::copy(entry.path(), dst.as_ref().join(entry.file_name()))?;
        }
    }
    Ok(())
}
