#![deny(warnings)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

//! Windows Service binary for rust_http_proxy
//!
//! This binary allows rust_http_proxy to run as a Windows Service.
//! Install and manage using Windows Service Control Manager (sc.exe):
//!
//! ```powershell
//! # Install service
//! sc.exe create rust_http_proxy binPath= "C:\path\to\winservice.exe -p 3128"
//!
//! # Start service
//! sc.exe start rust_http_proxy
//!
//! # Stop service
//! sc.exe stop rust_http_proxy
//!
//! # Delete service
//! sc.exe delete rust_http_proxy
//! ```

use std::{ffi::OsString, time::Duration};

use clap::Parser;
use log::{error, warn};
use rust_http_proxy::{config::Param, create_futures};
use tokio::sync::oneshot;
use windows_service::{
    define_windows_service,
    service::{ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType},
    service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
    service_dispatcher,
};

const SERVICE_NAME: &str = "rust_http_proxy";
const SERVICE_EXIT_CODE_ARGUMENT_ERROR: u32 = 100;
const SERVICE_EXIT_CODE_EXITED_UNEXPECTEDLY: u32 = 101;
const SERVICE_EXIT_CODE_CREATE_FAILED: u32 = 102;
const SERVICE_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(20);
const SERVICE_STOP_WAIT_HINT: Duration = Duration::from_secs(25);
const RUNTIME_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn run_service(
    status_handle: ServiceStatusHandle, param: Param, stop_receiver: oneshot::Receiver<()>,
) -> Result<(), windows_service::Error> {
    #[allow(clippy::expect_used)]
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime");
    let create_service_result = {
        let _guard = runtime.enter();
        create_futures(param)
    };
    match create_service_result {
        Ok((service_future, shutdown_tx)) => {
            // Report running state
            set_service_status(&status_handle, ServiceState::Running, ServiceExitCode::Win32(0), Duration::default())?;

            let (results, stop_requested) = runtime.block_on(async move {
                tokio::pin!(service_future);
                tokio::select! {
                    results = &mut service_future => (Some(results), false),
                    _ = stop_receiver => {
                        // Acknowledge the stop before waiting for active HTTP/SSE connections.
                        if let Err(status_error) = set_service_status(
                            &status_handle,
                            ServiceState::StopPending,
                            ServiceExitCode::Win32(0),
                            SERVICE_STOP_WAIT_HINT,
                        ) {
                            error!("Failed to report Windows service stop-pending state: {status_error}");
                        }
                        let _ = shutdown_tx.send(());
                        match tokio::time::timeout(SERVICE_SHUTDOWN_TIMEOUT, &mut service_future).await {
                            Ok(results) => (Some(results), true),
                            Err(_) => {
                                warn!(
                                    "Windows service graceful shutdown exceeded {SERVICE_SHUTDOWN_TIMEOUT:?}; aborting remaining tasks"
                                );
                                (None, true)
                            }
                        }
                    }
                }
            });
            let mut exited_cleanly = true;
            if let Some(results) = results {
                for result in results {
                    if let Err(run_error) = result {
                        exited_cleanly = false;
                        if stop_requested {
                            warn!("HTTP Proxy server exited with error while stopping: {run_error:?}");
                        } else {
                            error!("HTTP Proxy server exited unexpectedly: {run_error:?}");
                        }
                    }
                }
            }
            // Abort any detached connection tasks before SCM observes the stable Stopped state.
            runtime.shutdown_timeout(RUNTIME_SHUTDOWN_TIMEOUT);

            // Report stopped state
            set_service_status(
                &status_handle,
                ServiceState::Stopped,
                if stop_requested || exited_cleanly {
                    ServiceExitCode::Win32(0)
                } else {
                    ServiceExitCode::ServiceSpecific(SERVICE_EXIT_CODE_EXITED_UNEXPECTEDLY)
                },
                Duration::default(),
            )?;
        }
        Err(err) => {
            error!("Failed to create service: {:?}", err);
            runtime.shutdown_timeout(RUNTIME_SHUTDOWN_TIMEOUT);

            // Report stopped state with error
            set_service_status(
                &status_handle,
                ServiceState::Stopped,
                ServiceExitCode::ServiceSpecific(SERVICE_EXIT_CODE_CREATE_FAILED),
                Duration::default(),
            )?;
        }
    }

    Ok(())
}

fn service_main(arguments: Vec<OsString>) -> Result<(), windows_service::Error> {
    // Create a oneshot channel for receiving Stop event
    let (stop_sender, stop_receiver) = oneshot::channel();

    let mut stop_sender_opt = Some(stop_sender);
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                if let Some(stop_sender) = stop_sender_opt.take() {
                    let _ = stop_sender.send(());
                }
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    // Register system service event handler
    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    // Report SERVICE_START_PENDING
    set_service_status(&status_handle, ServiceState::StartPending, ServiceExitCode::Win32(0), Duration::from_secs(30))?;

    // Parse command line arguments
    let param = if arguments.len() <= 1 {
        // use std::env::args_os()
        match Param::try_parse() {
            Ok(p) => p,
            Err(err) => {
                error!("Failed to parse command line arguments: {}", err);
                set_service_status(
                    &status_handle,
                    ServiceState::Stopped,
                    ServiceExitCode::ServiceSpecific(SERVICE_EXIT_CODE_ARGUMENT_ERROR),
                    Duration::default(),
                )?;
                return Err(windows_service::Error::LaunchArgumentsNotSupported);
            }
        }
    } else {
        // Parse from provided arguments
        match Param::try_parse_from(&arguments) {
            Ok(p) => p,
            Err(err) => {
                error!("Failed to parse command line arguments: {}", err);
                set_service_status(
                    &status_handle,
                    ServiceState::Stopped,
                    ServiceExitCode::ServiceSpecific(SERVICE_EXIT_CODE_ARGUMENT_ERROR),
                    Duration::default(),
                )?;
                return Err(windows_service::Error::LaunchArgumentsNotSupported);
            }
        }
    };
    if let Err(log_init_error) = log_x::init_log(&param.log_dir, &param.log_file, "info") {
        error!("Failed to initialize log: {}", log_init_error);
        set_service_status(
            &status_handle,
            ServiceState::Stopped,
            ServiceExitCode::ServiceSpecific(SERVICE_EXIT_CODE_ARGUMENT_ERROR),
            Duration::default(),
        )?;
        return Err(windows_service::Error::LaunchArgumentsNotSupported);
    }
    log::info!("Service starting with arguments: {:?}", arguments);
    log::info!("Service starting with std::env::args_os(): {:?}", std::env::args_os());

    run_service(status_handle, param, stop_receiver)
}

#[inline]
fn set_service_status(
    handle: &ServiceStatusHandle, current_state: ServiceState, exit_code: ServiceExitCode, wait_hint: Duration,
) -> Result<(), windows_service::Error> {
    handle.set_service_status(build_service_status(current_state, exit_code, wait_hint))
}

fn build_service_status(current_state: ServiceState, exit_code: ServiceExitCode, wait_hint: Duration) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state,
        controls_accepted: if current_state == ServiceState::Running {
            ServiceControlAccept::STOP
        } else {
            ServiceControlAccept::empty()
        },
        exit_code,
        checkpoint: if matches!(current_state, ServiceState::StartPending | ServiceState::StopPending) {
            1
        } else {
            0
        },
        wait_hint,
        process_id: None,
    }
}

fn service_entry(arguments: Vec<OsString>) {
    if let Err(err) = service_main(arguments) {
        error!("Service main exited with error: {}", err);
    }
}

define_windows_service!(ffi_service_entry, service_entry);

fn main() -> Result<(), windows_service::Error> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_entry)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_status_accepts_stop_without_a_checkpoint() {
        let status = build_service_status(ServiceState::Running, ServiceExitCode::Win32(0), Duration::default());
        assert_eq!(status.controls_accepted, ServiceControlAccept::STOP);
        assert_eq!(status.checkpoint, 0);
        assert_eq!(status.wait_hint, Duration::default());
    }

    #[test]
    fn stop_pending_status_has_wait_hint_and_rejects_new_controls() {
        let status = build_service_status(ServiceState::StopPending, ServiceExitCode::Win32(0), SERVICE_STOP_WAIT_HINT);
        assert_eq!(status.controls_accepted, ServiceControlAccept::empty());
        assert_eq!(status.checkpoint, 1);
        assert_eq!(status.wait_hint, SERVICE_STOP_WAIT_HINT);
    }

    #[test]
    fn stopped_status_is_stable_and_rejects_controls() {
        let status = build_service_status(ServiceState::Stopped, ServiceExitCode::Win32(0), Duration::default());
        assert_eq!(status.controls_accepted, ServiceControlAccept::empty());
        assert_eq!(status.checkpoint, 0);
        assert_eq!(status.wait_hint, Duration::default());
    }
}
