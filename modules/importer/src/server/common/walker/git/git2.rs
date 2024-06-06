use super::{Continuation, Error, GitWalker, Handler};
use crate::server::common::walker::WorkingDirectory;
use git2::{
    build::RepoBuilder, ErrorClass, ErrorCode, FetchOptions, RemoteCallbacks, Repository, ResetType,
};
use std::collections::HashSet;
use tracing::{info_span, instrument};

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

        log::info!("Cloning {} into {}", self.source, path.display());

        let mut cb = RemoteCallbacks::new();
        cb.transfer_progress(|progress| {
            let received = progress.received_objects();
            let total = progress.total_objects();
            let bytes = progress.received_bytes();

            log::trace!("Progress - objects: {received} of {total}, bytes: {bytes}");

            true
        });
        cb.update_tips(|refname, a, b| {
            if a.is_zero() {
                log::debug!("[new]     {:20} {}", b, refname);
            } else {
                log::debug!("[updated] {:10}..{:10} {}", a, b, refname);
            }
            true
        });

        let mut fo = FetchOptions::new();
        fo.remote_callbacks(cb);

        // clone or open repository

        let result = info_span!("clone repository").in_scope(|| {
            RepoBuilder::new()
                .fetch_options(fo)
                .clone(&self.source, path)
        });

        let repo = match result {
            Ok(repo) => repo,
            Err(err) if err.code() == ErrorCode::Exists && err.class() == ErrorClass::Invalid => {
                log::info!("Already exists, opening ...");
                let repo = info_span!("open repository").in_scope(|| Repository::open(path))?;

                info_span!("fetching updates").in_scope(|| {
                    log::debug!("Fetching updates");
                    let mut remote = repo.find_remote("origin")?;
                    remote.fetch(&[] as &[&str], None, None)?;
                    remote.disconnect()?;

                    let head = repo.find_reference("FETCH_HEAD")?;
                    let head = head.peel_to_commit()?;

                    // reset to the most recent commit
                    repo.reset(head.as_object(), ResetType::Hard, None)?;

                    Ok::<_, Error>(())
                })?;

                repo
            }
            Err(err) => {
                log::info!(
                    "Clone failed - code: {:?}, class: {:?}",
                    err.code(),
                    err.class()
                );
                return Err(err.into());
            }
        };

        log::debug!("Repository cloned or updated");

        // discover files between "then" and now

        let changes = match &self.continuation.0 {
            Some(commit) => {
                log::info!("Continuing from: {commit}");

                let files = info_span!("continue from", commit).in_scope(|| {
                    let start = repo.find_commit(repo.revparse_single(commit)?.id())?;
                    let end = repo.head()?.peel_to_commit()?;

                    let start = start.tree()?;
                    let end = end.tree()?;

                    let diff = repo.diff_tree_to_tree(Some(&start), Some(&end), None)?;

                    let mut files = HashSet::with_capacity(diff.deltas().len());

                    for delta in diff.deltas() {
                        if let Some(path) = delta.new_file().path() {
                            let path = match &self.path {
                                // files are relative to the base dir
                                Some(base) => match path.strip_prefix(base) {
                                    Ok(path) => Some(path.to_path_buf()),
                                    Err(..) => None,
                                },
                                // files are relative to the repo
                                None => Some(path.to_path_buf()),
                            };

                            if let Some(path) = path {
                                log::debug!("Record {} as changed file", path.display());
                                files.insert(path);
                            }
                        }
                    }

                    Ok::<_, Error>(files)
                })?;

                log::info!("Detected {} changed files", files.len());

                Some(files)
            }
            _ => {
                log::debug!("Ingesting all files");
                None
            }
        };

        // discover and process files

        self.walk(path, &changes)?;

        let head = repo.head()?;
        let commit = head.peel_to_commit()?.id();
        log::info!("Most recent commit: {commit}");

        // only drop when we are done, as this might delete the working directory

        drop(working_dir);

        // return result

        Ok(Continuation(Some(commit.to_string())))
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::Continuation;
    use git2::{Repository, ResetType};
    use std::path::Path;

    /// reset a git repository to the spec and return the commit as continuation
    pub(crate) fn git_reset(path: &Path, spec: &str) -> anyhow::Result<Continuation> {
        let repo = Repository::open(path)?;

        let r#ref = repo.revparse_single(spec)?;
        repo.reset(&r#ref, ResetType::Hard, None)?;

        let commit = r#ref.peel_to_commit()?.id().to_string();

        Ok(Continuation(Some(commit)))
    }
}
