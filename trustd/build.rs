use std::path::Path;
use std::process::Command;
use std::{fs, io};

static UI_DIR: &str = "../ui";
static UI_DIR_SRC: &str = "../ui/src";
static UI_DIST_DIR: &str = "../ui/client/dist";
static STATIC_DIR: &str = "../static";

#[cfg(windows)]
static NPM_CMD: &str = "npm.cmd";
#[cfg(not(windows))]
static NPM_CMD: &str = "npm";

fn main() {
    println!("Build Trustify - build.rs!");

    println!("cargo:rerun-if-changed={}", UI_DIR_SRC);

    install_ui_deps();
    build_ui();
    copy_dir_all(UI_DIST_DIR, STATIC_DIR).unwrap();
}

fn install_ui_deps() {
    if !Path::new("./ui/node_modules").exists() {
        println!("Installing node dependencies...");
        Command::new(NPM_CMD)
            .args(["clean-install", "--ignore-scripts"])
            .current_dir(UI_DIR)
            .status()
            .unwrap();
    }
}

fn build_ui() {
    if !Path::new(STATIC_DIR).exists() {
        println!("Building UI...");
        Command::new(NPM_CMD)
            .args(["run", "build"])
            .current_dir(UI_DIR)
            .status()
            .unwrap();
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
