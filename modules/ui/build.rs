use static_files::resource_dir;
use std::path::Path;

static STATIC_DIR: &str = "../../static";
static STATIC_LOCAL_DIR: &str = "../../static-local";

pub fn main() {
    if Path::new(STATIC_DIR).exists() {
        resource_dir(STATIC_DIR).build().unwrap();
    } else {
        resource_dir(STATIC_LOCAL_DIR).build().unwrap();
    }
}
