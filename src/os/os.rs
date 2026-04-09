
#[derive(PartialEq)]
pub enum Os {
    Mac,
    Windows,
    Linux,
}

pub fn get_os() -> Os {
    let os = std::env::consts::OS;
    match os {
        "macos" => Os::Mac,
        "windows" => Os::Windows,
        "linux" => Os::Linux,
        _ => panic!("Unsupported OS"),
    }
}
