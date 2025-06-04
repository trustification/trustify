use std::{
    io::{Cursor, Write},
    path::Path,
};
use zip::write::FileOptions;

pub fn create_zip(base: impl AsRef<Path>) -> anyhow::Result<Vec<u8>> {
    let mut data = vec![];

    let base = base.as_ref();

    let mut dataset = zip::write::ZipWriter::new(Cursor::new(&mut data));
    for entry in walkdir::WalkDir::new(base) {
        let entry = entry?;
        let Ok(path) = entry.path().strip_prefix(base) else {
            continue;
        };

        if entry.file_type().is_file() {
            log::debug!("adding file: {}", path.display());
            dataset.start_file_from_path(path, FileOptions::<()>::default())?;
            dataset.write_all(&(std::fs::read(entry.path())?))?;
        } else if entry.file_type().is_dir() {
            dataset.add_directory_from_path(path, FileOptions::<()>::default())?;
        }
    }
    dataset.finish()?;

    Ok(data)
}
