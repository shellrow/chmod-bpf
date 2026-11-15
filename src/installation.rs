use anyhow::{Context, Result, bail};

/// Separates the failure/recovery sequence from privileged system operations.
pub trait Deployment {
    fn stop(&mut self) -> Result<()>;
    fn stage_and_apply(&mut self) -> Result<()>;
    fn start(&mut self) -> Result<()>;
    fn restore_assets(&mut self) -> Result<()>;
}

pub fn deploy(deployment: &mut impl Deployment, was_registered: bool) -> Result<()> {
    deployment
        .stop()
        .context("Cannot stop the existing service; installed assets were not changed")?;
    let result = deployment
        .stage_and_apply()
        .and_then(|()| deployment.start());
    if let Err(error) = result {
        // Do not replace executable assets while a service we cannot stop may
        // still be executing them. Keep the failed state reviewable for repair.
        let rollback = deployment
            .stop()
            .and_then(|()| deployment.restore_assets())
            .and_then(|()| {
                if was_registered {
                    deployment.start()
                } else {
                    Ok(())
                }
            });
        let rollback = match rollback {
            Ok(()) => "completed".to_owned(),
            Err(error) => format!("incomplete: {error:#}"),
        };
        bail!(
            "Installation failed: {error:#}. Asset/service rollback: {rollback}. The shared group and any device permissions already applied are retained; review check and retry install or uninstall --revoke-access."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake {
        calls: Vec<&'static str>,
        failures: Vec<usize>,
    }

    impl Fake {
        fn call(&mut self, action: &'static str) -> Result<()> {
            self.calls.push(action);
            if self.failures.contains(&self.calls.len()) {
                bail!("injected {action} failure");
            }
            Ok(())
        }
    }
    impl Deployment for Fake {
        fn stop(&mut self) -> Result<()> {
            self.call("stop")
        }
        fn stage_and_apply(&mut self) -> Result<()> {
            self.call("apply")
        }
        fn start(&mut self) -> Result<()> {
            self.call("start")
        }
        fn restore_assets(&mut self) -> Result<()> {
            self.call("restore")
        }
    }

    #[test]
    fn successful_deployment_never_rolls_back() {
        let mut fake = Fake {
            calls: vec![],
            failures: vec![],
        };
        deploy(&mut fake, true).unwrap();
        assert_eq!(fake.calls, ["stop", "apply", "start"]);
    }

    #[test]
    fn failure_to_stop_never_modifies_assets() {
        let mut fake = Fake {
            calls: vec![],
            failures: vec![1],
        };
        assert!(deploy(&mut fake, true).is_err());
        assert_eq!(fake.calls, ["stop"]);
    }

    #[test]
    fn failed_apply_restores_previous_service() {
        let mut fake = Fake {
            calls: vec![],
            failures: vec![2],
        };
        let error = deploy(&mut fake, true).unwrap_err();
        assert_eq!(fake.calls, ["stop", "apply", "stop", "restore", "start"]);
        assert!(error.to_string().contains("rollback: completed"));
    }

    #[test]
    fn failed_start_removes_fresh_install_without_starting_a_service() {
        let mut fake = Fake {
            calls: vec![],
            failures: vec![3],
        };
        assert!(deploy(&mut fake, false).is_err());
        assert_eq!(fake.calls, ["stop", "apply", "start", "stop", "restore"]);
    }

    #[test]
    fn rollback_does_not_replace_files_when_stop_fails() {
        let mut fake = Fake {
            calls: vec![],
            failures: vec![3, 4],
        };
        let error = deploy(&mut fake, true).unwrap_err();
        assert_eq!(fake.calls, ["stop", "apply", "start", "stop"]);
        assert!(error.to_string().contains("rollback: incomplete"));
    }

    #[test]
    fn rollback_does_not_start_after_restore_failure() {
        let mut fake = Fake {
            calls: vec![],
            failures: vec![2, 4],
        };
        assert!(deploy(&mut fake, true).is_err());
        assert_eq!(fake.calls, ["stop", "apply", "stop", "restore"]);
    }
}
