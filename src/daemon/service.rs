//! User service: launchd on macOS, `systemd --user` on Linux.

use crate::paths::{ENV_CONFIG_DIR, ENV_STATE_DIR, Paths};
use service_manager::{
    RestartPolicy, ServiceInstallCtx, ServiceLabel, ServiceLevel, ServiceManager, ServiceStartCtx,
    ServiceStatus, ServiceStatusCtx, ServiceStopCtx, ServiceUninstallCtx,
};
use std::io;
use std::path::Path;
use std::str::FromStr;

/// launchd label and systemd unit name.
pub const LABEL: &str = "dev.fauxy.daemon";

/// Restart delay requested from systemd (launchd applies its own throttle).
const RESTART_DELAY_SECS: u32 = 5;

pub fn label() -> io::Result<ServiceLabel> {
    ServiceLabel::from_str(LABEL)
}

/// Runs `fauxy run` at login and restarts it when it exits with an error. A
/// clean exit (`fauxy stop`) leaves it stopped.
pub fn install_ctx(
    exe: &Path,
    paths: &Paths,
    config_file: Option<&Path>,
) -> io::Result<ServiceInstallCtx> {
    Ok(ServiceInstallCtx {
        label: label()?,
        program: exe.to_path_buf(),
        args: super::process::run_args(config_file, &paths.log_file()),
        contents: None,
        username: None,
        working_directory: Some(paths.state_dir.clone()),
        environment: Some(vec![
            (
                ENV_CONFIG_DIR.to_owned(),
                paths.config_dir.display().to_string(),
            ),
            (
                ENV_STATE_DIR.to_owned(),
                paths.state_dir.display().to_string(),
            ),
        ]),
        autostart: true,
        restart_policy: RestartPolicy::OnFailure {
            delay_secs: Some(RESTART_DELAY_SECS),
            max_retries: None,
            reset_after_secs: None,
        },
    })
}

fn manager() -> io::Result<Box<dyn ServiceManager>> {
    let unavailable = || {
        let message = "no supported service manager found (launchd on macOS, systemd on Linux)";
        io::Error::new(io::ErrorKind::Unsupported, message)
    };
    // On Linux `native` already fails without systemd/OpenRC; on macOS it
    // always returns launchd, which may still be missing from the PATH.
    let mut manager = <dyn ServiceManager>::native().map_err(|_| unavailable())?;
    manager.set_level(ServiceLevel::User)?;
    manager
        .available()?
        .then_some(manager)
        .ok_or_else(unavailable)
}

/// Installs and starts the user service.
pub fn install(exe: &Path, paths: &Paths, config_file: Option<&Path>) -> io::Result<()> {
    paths.ensure_state_dir()?;
    let ctx = install_ctx(exe, paths, config_file)?;
    #[cfg(target_os = "linux")]
    check_unit_values(&ctx)?;
    let manager = manager()?;
    manager.install(ctx)?;
    manager.start(ServiceStartCtx { label: label()? })
}

/// service-manager writes systemd units without escaping, so values that
/// systemd would split or expand are refused.
#[cfg(target_os = "linux")]
fn check_unit_values(ctx: &ServiceInstallCtx) -> io::Result<()> {
    let environment = ctx.environment.iter().flatten();
    let values = std::iter::once(ctx.program.as_os_str())
        .chain(ctx.args.iter().map(|arg| arg.as_os_str()))
        .chain(ctx.working_directory.iter().map(|dir| dir.as_os_str()))
        .chain(environment.map(|(_, value)| std::ffi::OsStr::new(value)));
    let forbidden = [' ', '\t', '\n', '"', '\'', '\\', '%', '$'];
    match values
        .map(|v| v.to_string_lossy())
        .find(|v| v.contains(forbidden))
    {
        Some(value) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "cannot write a systemd unit for '{value}': whitespace, quotes, '%' and '$' are not supported"
            ),
        )),
        None => Ok(()),
    }
}

/// Stops and removes the user service.
pub fn uninstall() -> io::Result<()> {
    let manager = manager()?;
    let _ = manager.stop(ServiceStopCtx { label: label()? });
    manager.uninstall(ServiceUninstallCtx { label: label()? })
}

pub fn status() -> io::Result<ServiceStatus> {
    manager()?.status(ServiceStatusCtx { label: label()? })
}

pub fn describe(status: &ServiceStatus) -> String {
    match status {
        ServiceStatus::NotInstalled => "not installed".to_owned(),
        ServiceStatus::Running => "installed and running".to_owned(),
        ServiceStatus::Stopped(None) => "installed, stopped".to_owned(),
        ServiceStatus::Stopped(Some(reason)) => format!("installed, stopped ({reason})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_is_valid() {
        assert_eq!(label().unwrap().to_qualified_name(), LABEL);
    }

    #[test]
    fn install_context_runs_the_daemon_with_resolved_dirs() {
        let paths = Paths {
            config_dir: "/c".into(),
            state_dir: "/s".into(),
        };
        let ctx = install_ctx(Path::new("/bin/fauxy"), &paths, Some(Path::new("/p.yaml"))).unwrap();
        assert_eq!(ctx.program, Path::new("/bin/fauxy"));
        assert_eq!(
            ctx.args,
            vec!["run", "--log-file", "/s/fauxy.log", "--config", "/p.yaml"]
        );
        assert!(ctx.autostart);
        assert_eq!(ctx.working_directory.as_deref(), Some(Path::new("/s")));
        assert_eq!(
            ctx.environment.unwrap(),
            vec![
                (ENV_CONFIG_DIR.to_owned(), "/c".to_owned()),
                (ENV_STATE_DIR.to_owned(), "/s".to_owned()),
            ]
        );
        assert!(matches!(
            ctx.restart_policy,
            RestartPolicy::OnFailure {
                delay_secs: Some(RESTART_DELAY_SECS),
                ..
            }
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn systemd_units_refuse_values_systemd_would_reinterpret() {
        let paths = |state: &str| Paths {
            config_dir: "/c".into(),
            state_dir: state.into(),
        };
        let ctx = install_ctx(Path::new("/bin/fauxy"), &paths("/s"), None).unwrap();
        check_unit_values(&ctx).unwrap();
        for state in ["/home/a b/s", "/s/$HOME", "/s/100%"] {
            let ctx = install_ctx(Path::new("/bin/fauxy"), &paths(state), None).unwrap();
            let err = check_unit_values(&ctx).unwrap_err();
            assert!(
                err.to_string().starts_with("cannot write a systemd unit"),
                "{state}: {err}"
            );
        }
    }

    #[test]
    fn status_descriptions() {
        assert_eq!(describe(&ServiceStatus::NotInstalled), "not installed");
        assert_eq!(describe(&ServiceStatus::Running), "installed and running");
        assert_eq!(
            describe(&ServiceStatus::Stopped(None)),
            "installed, stopped"
        );
        assert_eq!(
            describe(&ServiceStatus::Stopped(Some("x".into()))),
            "installed, stopped (x)"
        );
    }
}
