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

use std::{
    ffi::OsString,
    future::Future,
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

use clap::Parser;
use log::{error, info};
use rust_http_proxy::{config::Param, create_futures, DynError};
use tokio::sync::{mpsc::Sender, oneshot};
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

#[inline]
fn set_service_status(
    handle: &ServiceStatusHandle, current_state: ServiceState, exit_code: ServiceExitCode, wait_hint: Duration,
) -> Result<(), windows_service::Error> {
    static SERVICE_STATE_CHECKPOINT: AtomicU32 = AtomicU32::new(0);

    let next_status = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state,
        controls_accepted: if current_state == ServiceState::StartPending {
            ServiceControlAccept::empty()
        } else {
            ServiceControlAccept::STOP
        },
        exit_code,
        checkpoint: if matches!(current_state, ServiceState::Running | ServiceState::Stopped) {
            SERVICE_STATE_CHECKPOINT.fetch_add(1, Ordering::AcqRel)
        } else {
            0
        },
        wait_hint,
        process_id: None,
    };
    handle.set_service_status(next_status)
}

fn handle_create_service_result(
    status_handle: ServiceStatusHandle,
    create_service_result: Result<(impl Future<Output = Vec<Result<(), std::io::Error>>>, Vec<Sender<()>>), DynError>,
    stop_receiver: oneshot::Receiver<()>,
) -> Result<(), windows_service::Error> {
    match create_service_result {
        Ok((service_future, shutdown_tx)) => {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("failed to create tokio runtime");
            // Report running state
            set_service_status(&status_handle, ServiceState::Running, ServiceExitCode::Win32(0), Duration::default())?;

            runtime.spawn(async move {
                // Wait for stop signal
                let _ = stop_receiver.await;
                // Send shutdown signal to all server tasks
                for tx in shutdown_tx {
                    let _ = tx.send(()).await;
                }
            });
            // Run it right now.
            let results = runtime.block_on(service_future);
            let exited_by_ctrl = results.iter().all(|res| res.is_ok());

            // Report stopped state
            set_service_status(
                &status_handle,
                ServiceState::Stopped,
                if exited_by_ctrl {
                    ServiceExitCode::Win32(0)
                } else {
                    ServiceExitCode::ServiceSpecific(SERVICE_EXIT_CODE_EXITED_UNEXPECTEDLY)
                },
                Duration::default(),
            )?;
        }
        Err(err) => {
            error!("Failed to create service: {:?}", err);

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
    // Windows Service passes arguments through the arguments vector
    let param = if arguments.len() <= 1 {
        // No arguments passed, use default
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

    handle_create_service_result(status_handle, create_futures(param), stop_receiver)
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
