pub const LABEL: &str = "com.foctal.chmod-bpf";
pub const SERVICE: &str = "system/com.foctal.chmod-bpf";
pub const CHMOD_BPF_PLIST_PATH: &str = "/Library/LaunchDaemons/com.foctal.chmod-bpf.plist";
pub const CHMOD_BPF_PLIST: &str = include_str!("../resources/com.foctal.chmod-bpf.plist");
pub const CHMOD_BPF_SCRIPT_DIR_PATH: &str = "/Library/Application Support/Foctal/chmod-bpf";
pub const CHMOD_BPF_SCRIPT_PATH: &str =
    "/Library/Application Support/Foctal/chmod-bpf/chmod-bpf.sh";
pub const CHMOD_BPF_SCRIPT: &str = include_str!("../scripts/chmod-bpf.sh");
pub const OTHER_DAEMONS: [(&str, &str); 2] = [
    (
        "org.wireshark.ChmodBPF",
        "/Library/LaunchDaemons/org.wireshark.ChmodBPF.plist",
    ),
    (
        "org.macports.wireshark.ChmodBPF",
        "/Library/LaunchDaemons/org.macports.wireshark.ChmodBPF.plist",
    ),
];

pub const CHMOD_BPF_LOCK_PATH: &str = "/Library/Application Support/Foctal/.chmod-bpf.lock";
