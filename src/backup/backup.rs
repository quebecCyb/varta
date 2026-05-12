use std::path::PathBuf;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct Backup {
    path: PathBuf,
}

impl Backup {

}
