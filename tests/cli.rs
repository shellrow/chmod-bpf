use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_chmod-bpf"))
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .unwrap()
}

#[test]
fn help_and_version_do_not_require_privileges() {
    for args in [
        vec!["--help"],
        vec!["--version"],
        vec!["install", "--help"],
        vec!["uninstall", "--help"],
    ] {
        let result = run(&args);
        assert!(result.status.success());
        assert!(!result.stdout.is_empty());
        assert!(result.stderr.is_empty());
    }
}

#[test]
fn completions_cover_every_command() {
    for shell in ["bash", "zsh", "fish", "elvish", "powershell"] {
        let result = run(&["completions", shell]);
        assert!(result.status.success());
        let text = String::from_utf8(result.stdout).unwrap();
        for name in ["check", "install", "uninstall", "grant", "revoke"] {
            assert!(text.contains(name));
        }
    }
}

#[test]
fn usage_errors_exit_two() {
    for args in [
        vec![],
        vec!["not-a-command"],
        vec!["grant"],
        vec!["check", "--yes"],
    ] {
        assert_eq!(run(&args).status.code(), Some(2));
    }
}

#[cfg(target_os = "macos")]
#[test]
fn invalid_identity_still_produces_machine_readable_failure() {
    let result = run(&["check", "--json", "--user", "invalid/account"]);
    assert_eq!(result.status.code(), Some(1));
    assert!(result.stderr.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["healthy"], false);
    assert!(
        report["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| issue.as_str().unwrap().contains("Invalid account name"))
    );
    assert!(!result.stdout.contains(&0x1b));
}

#[cfg(target_os = "macos")]
#[test]
fn uninstall_preview_is_safe_without_sudo() {
    let result = run(&["uninstall", "--dry-run"]);
    // An unsafe pre-existing installation can correctly block the preview.
    // Either way, it must not try to acquire a lock or request root privileges.
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(text.contains("Uninstall plan"));
    assert!(!text.contains("requires root"));
    assert!(!text.contains("Apply this plan?"));
}

#[cfg(not(target_os = "macos"))]
#[test]
fn unsupported_platform_fails_before_system_operations() {
    for args in [
        vec!["check"],
        vec!["install", "--yes"],
        vec!["uninstall", "--yes"],
    ] {
        let result = run(&args);
        assert_eq!(result.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&result.stderr).contains("macOS only"));
    }
}

#[cfg(target_os = "macos")]
#[test]
fn unprivileged_sudo_environment_cannot_select_another_audit_identity() {
    if uzers::get_effective_uid() == 0 {
        return;
    }
    let result = Command::new(env!("CARGO_BIN_EXE_chmod-bpf"))
        .args(["check", "--json"])
        .env("SUDO_USER", "invalid/account")
        .env("SUDO_UID", "0")
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(result.stderr.is_empty());
    assert_eq!(
        result.status.code(),
        Some(if report["healthy"] == true { 0 } else { 1 })
    );
    assert_eq!(report["schema_version"], 1);
    assert!(report["devices"].is_array());
    assert!(report["daemons"].is_array());
    assert_eq!(report["uid"], uzers::get_current_uid());
    assert_eq!(report["access_evaluation"], "current_process_access");
}
