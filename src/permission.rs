use anyhow::Result;
use std::process::Command;

use crate::command;

/// Sets the read/write permissions for the specified path.
pub fn set_read_write_permissions(path: &str) -> Result<()> {
    let mut command = Command::new("chmod");
    command.arg("u=rw,g=r,o=r").arg(path);
    command::run(
        &mut command,
        &format!("set read/write permissions for {path}"),
    )
}

/// Sets the owner and group for the specified path.
pub fn set_owner_group(path: &str) -> Result<()> {
    let mut command = Command::new("chown");
    command.arg("root:wheel").arg(path);
    command::run(&mut command, &format!("set owner and group for {path}"))
}

/// Sets the read/execute permissions for the specified path recursively.
pub fn set_read_execute_permissions_recursive(path: &str) -> Result<()> {
    let mut command = Command::new("chmod");
    command.arg("-R").arg("a+rX,go-w").arg(path);
    command::run(
        &mut command,
        &format!("set recursive read/execute permissions for {path}"),
    )
}

/// Sets the owner and group for the specified path recursively.
pub fn set_owner_group_recursive(path: &str) -> Result<()> {
    let mut command = Command::new("chown");
    command.arg("-R").arg("root:wheel").arg(path);
    command::run(
        &mut command,
        &format!("set recursive owner and group for {path}"),
    )
}
