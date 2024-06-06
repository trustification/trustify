use super::{Continuation, Error, GitWalker, Handler, WorkingDirectory};
use std::{collections::HashSet, fs, path::Path};
use tracing::instrument;
use xshell::{cmd, Shell};

impl<H, T> GitWalker<H, T>
where
    H: Handler,
    T: WorkingDirectory + Send + 'static,
{
    /// Sync version, as all git functions are sync
    #[instrument(skip(self), ret)]
    pub(super) fn run_sync(mut self) -> Result<Continuation, Error> {
        log::debug!("Starting run for: {}", self.source);

        let working_dir = self
            .working_dir
            .create()
            .map_err(|err| Error::WorkingDir(Box::new(err)))?;

        let path = working_dir.as_ref();
        fs::create_dir_all(path).map_err(|err| Error::WorkingDir(Box::new(err)))?;

        log::info!("Cloning {} into {}", self.source, path.display());

        let source = &self.source;

        let sh = Shell::new()?;
        sh.change_dir(&path);

        if path.join(".git").exists() {
            cmd!(sh, "git pull").run()?;
        } else {
            cmd!(sh, "git clone {source} .").run()?;
        }

        log::debug!("Repository cloned or updated");

        // discover files between "then" and now

        let changes = match &self.continuation.0 {
            Some(commit) => {
                log::info!("Continuing from: {commit}");

                let files = cmd!(sh, "git diff --name-only {commit} HEAD")
                    .read()?
                    .lines()
                    .filter_map(|path| {
                        let path = Path::new(&path);

                        match &self.path {
                            // files are relative to the base dir
                            Some(base) => match path.strip_prefix(base) {
                                Ok(path) => Some(path.to_path_buf()),
                                Err(..) => None,
                            },
                            // files are relative to the repo
                            None => Some(path.to_path_buf()),
                        }
                    })
                    .collect::<HashSet<_>>();

                log::info!("Detected {} changed files", files.len());

                Some(files)
            }
            _ => {
                log::debug!("Ingesting all files");
                None
            }
        };

        // discover and process files

        self.walk(&path, &changes)?;

        let commit = cmd!(sh, "git rev-parse HEAD").read()?;

        log::info!("Most recent commit: {commit}");

        // only drop when we are done, as this might delete the working directory

        drop(working_dir);

        // return result

        Ok(Continuation(Some(commit.to_string())))
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::super::Continuation;
    use std::path::Path;
    use xshell::{cmd, Shell};

    /// reset a git repository to the spec and return the commit as continuation
    pub(crate) fn git_reset(path: &Path, spec: &str) -> anyhow::Result<Continuation> {
        let sh = Shell::new()?;
        sh.change_dir(path);

        cmd!(sh, "git reset --hard {spec}").run()?;
        let commit = cmd!(sh, "git rev-parse HEAD").read()?;

        Ok(Continuation(Some(commit)))
    }
}
