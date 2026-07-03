#![windows_subsystem = "windows"]

mod db;
mod ipc;
mod logger;
mod network;
mod process;

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::Services::*;

const SDDL_REVISION_1: u32 = 1;

#[allow(non_camel_case_types)]
type SC_HANDLE = isize;

// Global service status handle and status
static mut SERVICE_STATUS_HANDLE: SERVICE_STATUS_HANDLE = 0;
static mut SERVICE_STATUS: SERVICE_STATUS = SERVICE_STATUS {
    dwServiceType: SERVICE_WIN32_OWN_PROCESS,
    dwCurrentState: SERVICE_START_PENDING,
    dwControlsAccepted: 0,
    dwWin32ExitCode: 0,
    dwServiceSpecificExitCode: 0,
    dwCheckPoint: 0,
    dwWaitHint: 0,
};

static SHUTDOWN_TX: Mutex<Option<oneshot::Sender<()>>> = Mutex::new(None);

// Global suspension flag
pub static SUSPENDED: AtomicBool = AtomicBool::new(false);

lazy_static::lazy_static! {
    pub static ref NETWORK_MANAGER: network::NetworkManager = network::NetworkManager::new();
}

fn to_wide_string(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

// Struct to build a secure DACL on Named Pipes using SDDL
pub struct SecureSecurityAttributes {
    attrs: SECURITY_ATTRIBUTES,
    sd_ptr: *mut std::ffi::c_void,
}

impl SecureSecurityAttributes {
    pub fn new() -> Result<Self, anyhow::Error> {
        // SDDL Configuration:
        // D: -> DACL
        // (A;;GA;;;SY) -> Allow Generic All to SYSTEM
        // (A;;GA;;;BA) -> Allow Generic All to Built-in Administrators
        let sddl = to_wide_string("D:(A;;GA;;;SY)(A;;GA;;;BA)");
        let mut sd_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut sd_size: u32 = 0;

        unsafe {
            let res = ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd_ptr,
                &mut sd_size,
            );
            if res == 0 {
                return Err(anyhow::anyhow!(
                    "Failed to convert SDDL to security descriptor: {}",
                    GetLastError()
                ));
            }
        }

        let attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd_ptr,
            bInheritHandle: 0,
        };

        Ok(Self { attrs, sd_ptr })
    }

    pub fn as_mut_ptr(&mut self) -> *mut SECURITY_ATTRIBUTES {
        &mut self.attrs
    }
}

impl Drop for SecureSecurityAttributes {
    fn drop(&mut self) {
        if !self.sd_ptr.is_null() {
            unsafe {
                LocalFree(self.sd_ptr);
            }
        }
    }
}

unsafe fn update_service_status(
    current_state: u32,
    exit_code: u32,
    service_specific_exit_code: u32,
    check_point: u32,
    wait_hint: u32,
) {
    if SERVICE_STATUS_HANDLE == 0 {
        return;
    }

    SERVICE_STATUS.dwCurrentState = current_state;
    SERVICE_STATUS.dwWin32ExitCode = exit_code;
    SERVICE_STATUS.dwServiceSpecificExitCode = service_specific_exit_code;
    SERVICE_STATUS.dwCheckPoint = check_point;
    SERVICE_STATUS.dwWaitHint = wait_hint;

    if current_state == SERVICE_RUNNING {
        SERVICE_STATUS.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    } else {
        SERVICE_STATUS.dwControlsAccepted = 0;
    }

    SetServiceStatus(SERVICE_STATUS_HANDLE, std::ptr::addr_of!(SERVICE_STATUS));
}

unsafe extern "system" fn service_ctrl_handler(
    dw_control: u32,
    _dw_event_type: u32,
    _lp_event_data: *mut std::ffi::c_void,
    _lp_context: *mut std::ffi::c_void,
) -> u32 {
    match dw_control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            update_service_status(SERVICE_STOP_PENDING, NO_ERROR, 0, 1, 3000);

            if let Ok(mut guard) = SHUTDOWN_TX.lock() {
                if let Some(tx) = guard.take() {
                    let _ = tx.send(());
                }
            }
            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR,
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

unsafe extern "system" fn service_main(
    _dw_num_services_args: u32,
    _lp_service_arg_vectors: *mut *mut u16,
) {
    let service_name = to_wide_string("CoreService");

    SERVICE_STATUS_HANDLE = RegisterServiceCtrlHandlerExW(
        service_name.as_ptr(),
        Some(service_ctrl_handler),
        ptr::null(),
    );

    if SERVICE_STATUS_HANDLE == 0 {
        return;
    }

    update_service_status(SERVICE_START_PENDING, NO_ERROR, 0, 1, 3000);

    match run_core_app() {
        Ok(_) => {
            update_service_status(SERVICE_STOPPED, NO_ERROR, 0, 0, 0);
        }
        Err(e) => {
            tracing::error!(category = "service_error", "Service failed: {}", e);
            update_service_status(SERVICE_STOPPED, ERROR_PROCESS_ABORTED, 0, 0, 0);
        }
    }
}

fn run_core_app() -> Result<(), anyhow::Error> {
    // Initialize standard tracing logger
    logger::init_logger()?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        let (tx, rx) = oneshot::channel::<()>();
        if let Ok(mut guard) = SHUTDOWN_TX.lock() {
            *guard = Some(tx);
        }
        
        // Initialize parental control database
        let db = match db::Db::new() {
            Ok(database) => Arc::new(database),
            Err(e) => {
                tracing::error!(category = "database_error", "Failed to initialize database: {}", e);
                return;
            }
        };
        
        // Spawn master password override named pipe listener
        tokio::spawn(ipc::check_master_password_override(db.clone()));
        
        // Spawn process blocking monitor loop
        let db_for_block = db.clone();
        tokio::spawn(async move {
            loop {
                process::check_and_block_processes(&db_for_block);
                tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
            }
        });
        
        unsafe {
            update_service_status(SERVICE_RUNNING, NO_ERROR, 0, 0, 0);
        }
        
        tracing::info!(category = "process_lifecycle", "CoreService started successfully.");
        
        tokio::select! {
            _ = ipc::run_health_pipe_server() => {},
            _ = rx => {
                tracing::info!(category = "process_lifecycle", "CoreService shutdown signal received.");
            }
        }
    });

    Ok(())
}

unsafe fn set_service_recovery_options(service_handle: SC_HANDLE) -> Result<(), anyhow::Error> {
    let mut actions = [
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: 5000,
        },
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: 10000,
        },
        SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: 20000,
        },
    ];

    let mut failure_actions = SERVICE_FAILURE_ACTIONSW {
        dwResetPeriod: 86400,
        lpRebootMsg: ptr::null_mut(),
        lpCommand: ptr::null_mut(),
        cActions: actions.len() as u32,
        lpsaActions: actions.as_mut_ptr(),
    };

    let res = ChangeServiceConfig2W(
        service_handle,
        SERVICE_CONFIG_FAILURE_ACTIONS,
        &mut failure_actions as *mut SERVICE_FAILURE_ACTIONSW as *mut std::ffi::c_void,
    );

    if res == 0 {
        return Err(anyhow::anyhow!(
            "Failed to set failure actions: {}",
            GetLastError()
        ));
    }

    Ok(())
}

fn install_service() -> Result<(), anyhow::Error> {
    let service_name = to_wide_string("CoreService");
    let display_name = to_wide_string("Core Background Monitoring Service");

    let exe_path = std::env::current_exe()?;
    let exe_path_str = exe_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid executable path"))?;
    let binary_path = to_wide_string(&format!("\"{}\"", exe_path_str));

    unsafe {
        let sc_manager = OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_ALL_ACCESS);
        if sc_manager == 0 {
            return Err(anyhow::anyhow!(
                "Failed to open SC Manager: {}",
                GetLastError()
            ));
        }

        let service = CreateServiceW(
            sc_manager,
            service_name.as_ptr(),
            display_name.as_ptr(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            binary_path.as_ptr(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
        );

        if service == 0 {
            let err = GetLastError();
            CloseServiceHandle(sc_manager);
            if err == ERROR_SERVICE_EXISTS {
                return Err(anyhow::anyhow!("Service already exists."));
            }
            return Err(anyhow::anyhow!("Failed to create service: {}", err));
        }

        println!("Service installed successfully.");

        if let Err(e) = set_service_recovery_options(service) {
            println!(
                "Warning: failed to configure service recovery options: {}",
                e
            );
        } else {
            println!("Service recovery options configured successfully (Auto-Restart on failure).");
        }

        CloseServiceHandle(service);
        CloseServiceHandle(sc_manager);
    }

    Ok(())
}

fn uninstall_service() -> Result<(), anyhow::Error> {
    let service_name = to_wide_string("CoreService");

    unsafe {
        let sc_manager = OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_ALL_ACCESS);
        if sc_manager == 0 {
            return Err(anyhow::anyhow!(
                "Failed to open SC Manager: {}",
                GetLastError()
            ));
        }

        let service = OpenServiceW(sc_manager, service_name.as_ptr(), SERVICE_ALL_ACCESS);
        if service == 0 {
            CloseServiceHandle(sc_manager);
            return Err(anyhow::anyhow!("Service is not installed."));
        }

        let mut status: SERVICE_STATUS = std::mem::zeroed();
        let _ = ControlService(service, SERVICE_CONTROL_STOP, &mut status);

        let res = DeleteService(service);
        let err = GetLastError();

        CloseServiceHandle(service);
        CloseServiceHandle(sc_manager);

        if res == 0 {
            return Err(anyhow::anyhow!("Failed to delete service: {}", err));
        }

        println!("Service deleted successfully.");
    }

    Ok(())
}

fn configure_service_recovery_only() -> Result<(), anyhow::Error> {
    let service_name = to_wide_string("CoreService");

    unsafe {
        let sc_manager = OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_ALL_ACCESS);
        if sc_manager == 0 {
            return Err(anyhow::anyhow!(
                "Failed to open SC Manager: {}",
                GetLastError()
            ));
        }

        let service = OpenServiceW(sc_manager, service_name.as_ptr(), SERVICE_ALL_ACCESS);
        if service == 0 {
            let err = GetLastError();
            CloseServiceHandle(sc_manager);
            return Err(anyhow::anyhow!("Failed to open service: {}", err));
        }

        set_service_recovery_options(service)?;
        println!("Service recovery options configured successfully.");

        CloseServiceHandle(service);
        CloseServiceHandle(sc_manager);
    }

    Ok(())
}

fn set_password_in_db(password: &str) -> Result<(), anyhow::Error> {
    let database = db::Db::new()?;
    database.set_master_password(password)?;
    println!("Master password updated successfully.");
    Ok(())
}

fn main() -> Result<(), anyhow::Error> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 {
        match args[1].as_str() {
            "--install" => {
                install_service()?;
                return Ok(());
            }
            "--uninstall" => {
                uninstall_service()?;
                return Ok(());
            }
            "--configure-recovery" => {
                configure_service_recovery_only()?;
                return Ok(());
            }
            "--set-password" => {
                if args.len() < 3 {
                    println!("Usage: core-service.exe --set-password <password>");
                    return Ok(());
                }
                set_password_in_db(&args[2])?;
                return Ok(());
            }
            _ => {
                println!("Usage: core-service.exe [--install | --uninstall | --configure-recovery | --set-password <password>]");
                return Ok(());
            }
        }
    }

    let service_name = to_wide_string("CoreService");
    let service_table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: service_name.as_ptr() as *mut u16,
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: ptr::null_mut(),
            lpServiceProc: None,
        },
    ];

    unsafe {
        if StartServiceCtrlDispatcherW(service_table.as_ptr()) == 0 {
            let err = GetLastError();
            if err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT {
                run_core_app()?;
            } else {
                return Err(anyhow::anyhow!("Failed to start service: {}", err));
            }
        }
    }

    Ok(())
}
