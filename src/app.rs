pub enum AppCommands {
    Check,
    Install,
    Uninstall,
}

impl AppCommands {
    pub fn from_str(s: &str) -> AppCommands {
        match s {
            "check" => AppCommands::Check,
            "install" => AppCommands::Install,
            "uninstall" => AppCommands::Uninstall,
            _ => AppCommands::Check
        }
    }
}
