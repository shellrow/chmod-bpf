use std::{error::Error, process::Command};

/// Sets the read/write permissions for the specified path.
pub fn set_read_write_permissions(path: &str) -> Result<(), Box<dyn Error>> {
    Command::new("chmod")
        .arg("u=rw,g=r,o=r")
        .arg(path)
        .status()?;
    Ok(())
}

/// Sets the owner and group for the specified path.
/// The owner is set to root and the group is set to wheel.
pub fn set_owner_group(path: &str) -> Result<(), Box<dyn Error>> {
    Command::new("chown")
        .arg("root:wheel")
        .arg(path)
        .status()?;
    Ok(())
}

/// Sets the read/execute permissions for the specified path recursively.
pub fn set_read_execute_permissions_recursive(path: &str) -> Result<(), Box<dyn Error>> {
    Command::new("chmod")
        .arg("-R")
        .arg("a+rX,go-w")
        .arg(path)
        .status()?;
    Ok(())
}

/// Sets the owner and group for the specified path recursively.
pub fn set_owner_group_recursive(path: &str) -> Result<(), Box<dyn Error>> {
    Command::new("chown")
        .arg("-R")
        .arg("root:wheel")
        .arg(path)
        .status()?;
    Ok(())
}
