#![windows_subsystem = "windows"]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use std::sync::Mutex;
use tokio::sync::oneshot;
use chrono::Local;
use std::fs::OpenOptions;
use std::io::Write;
use tokio::net::windows::named_pipe::ClientOptions;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::time::{timeout, Duration};

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Services::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, TerminateProcess, PROCESS_TERMINATE
};

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

fn to_wide_string(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

fn log_to_file(message: &str) {
    let dir = r"C:\ProgramData\MonitoringControl";
    let _ = std::fs::create_dir_all(dir);
    let path = format!(r"{}\watchdog-utility.log", dir);
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open(&path)
    {
        let time_str = Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
        let _ = writeln!(file, "[{}] {}", time_str, message);
    }
}

use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
static LAST_RESTART: AtomicU64 = AtomicU64::new(0);

fn log_event(level: &str, category: &str, message: &str) {
    let dir = r"C:\ProgramData\MonitoringControl";
    let _ = std::fs::create_dir_all(dir);
    let path = format!(r"{}\events.jsonl", dir);
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open(&path)
    {
        let time_str = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let log_line = format!(
            "{{\"timestamp\":\"{}\",\"level\":\"{}\",\"fields\":{{\"category\":\"{}\",\"message\":\"{}\"}}}}\n",
            time_str, level, category, message
        );
        let _ = file.write_all(log_line.as_bytes());
    }
}

fn kill_core_process() {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return;
        }
        
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        
        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
                let exe_name = String::from_utf16_lossy(&entry.szExeFile[..len]);
                if exe_name.to_lowercase() == "core-service.exe" {
                    let process_handle = OpenProcess(PROCESS_TERMINATE, 0, entry.th32ProcessID);
                    if process_handle != 0 {
                        let _ = TerminateProcess(process_handle, 1);
                        CloseHandle(process_handle);
                    }
                }
                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
    }
}

fn restart_core_service() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    
    let last = LAST_RESTART.load(AtomicOrdering::SeqCst);
    if now - last < 8 {
        return;
    }
    LAST_RESTART.store(now, AtomicOrdering::SeqCst);

    log_to_file("Watchdog triggered: CoreService stopped responding. Attempting restart...");
    log_event(
        "WARN",
        "watchdog_event",
        "Watchdog triggered: CoreService stopped responding. Attempting restart..."
    );

    // 1. Terminate any stuck core processes first
    kill_core_process();

    // 2. Try to restart via SCM
    unsafe {
        let sc_manager = OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT);
        if sc_manager != 0 {
            let service_name = to_wide_string("CoreService");
            let service = OpenServiceW(sc_manager, service_name.as_ptr(), SERVICE_START);
            if service != 0 {
                if StartServiceW(service, 0, ptr::null()) != 0 {
                    log_to_file("CoreService successfully restarted via Service Control Manager.");
                    CloseServiceHandle(service);
                    CloseServiceHandle(sc_manager);
                    return;
                }
                CloseServiceHandle(service);
            }
            CloseServiceHandle(sc_manager);
        }
    }

    // 3. Fallback: Spawn executable directly (for local testing/non-service runs)
    if let Ok(mut exe_path) = std::env::current_exe() {
        exe_path.pop(); // Remove watchdog-utility.exe
        exe_path.push("core-service.exe");
        if exe_path.exists() {
            match std::process::Command::new(&exe_path).spawn() {
                Ok(_) => {
                    log_to_file("CoreService spawned directly from executable.");
                }
                Err(e) => {
                    log_to_file(&format!("Failed to spawn core-service.exe: {}", e));
                }
            }
        } else {
            log_to_file("core-service.exe not found in watchdog directory.");
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
    let service_name = to_wide_string("WatchdogService");
    
    SERVICE_STATUS_HANDLE = RegisterServiceCtrlHandlerExW(
        service_name.as_ptr(),
        Some(service_ctrl_handler),
        ptr::null(),
    );
    
    if SERVICE_STATUS_HANDLE == 0 {
        log_to_file("Failed to register service control handler.");
        return;
    }
    
    update_service_status(SERVICE_START_PENDING, NO_ERROR, 0, 1, 3000);
    
    match run_watchdog_app() {
        Ok(_) => {
            update_service_status(SERVICE_STOPPED, NO_ERROR, 0, 0, 0);
        }
        Err(e) => {
            log_to_file(&format!("Watchdog Service error: {}", e));
            update_service_status(SERVICE_STOPPED, ERROR_PROCESS_ABORTED, 0, 0, 0);
        }
    }
}

fn run_watchdog_app() -> Result<(), anyhow::Error> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
        
    rt.block_on(async {
        let (tx, rx) = oneshot::channel::<()>();
        if let Ok(mut guard) = SHUTDOWN_TX.lock() {
            *guard = Some(tx);
        }
        
        unsafe {
            update_service_status(SERVICE_RUNNING, NO_ERROR, 0, 0, 0);
        }
        
        log_to_file("Watchdog service started successfully.");
        
        let watchdog_loop = async {
            let pipe_name = r"\\.\pipe\CoreServiceHealthPipe";
            loop {
                // Attempt to connect to the named pipe
                let client = match ClientOptions::new().open(pipe_name) {
                    Ok(c) => c,
                    Err(e) => {
                        log_to_file(&format!("Failed to connect to named pipe: {}. CoreService may be stopped or crashed.", e));
                        restart_core_service();
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        continue;
                    }
                };
                
                log_to_file("Successfully connected to CoreService named pipe.");
                
                let mut reader = BufReader::new(client);
                let mut line = String::new();
                
                loop {
                    line.clear();
                    // Wait for a heartbeat with a 2-second timeout
                    let read_result = timeout(Duration::from_secs(2), reader.read_line(&mut line)).await;
                    
                    match read_result {
                        Ok(Ok(0)) => {
                            log_to_file("Connection to CoreService named pipe closed (EOF). Service may have terminated.");
                            restart_core_service();
                            break;
                        }
                        Ok(Ok(_bytes_read)) => {
                            let trimmed = line.trim();
                            if trimmed.starts_with("HEARTBEAT") {
                                log_to_file(&format!("Watchdog verified: {}", trimmed));
                            } else {
                                log_to_file(&format!("Received unexpected message from pipe: {}", trimmed));
                            }
                        }
                        Ok(Err(e)) => {
                            log_to_file(&format!("Error reading from named pipe: {}. Connection broken.", e));
                            restart_core_service();
                            break;
                        }
                        Err(_) => {
                            log_to_file("TIMEOUT: No heartbeat received from CoreService for 2 seconds. Service is unresponsive.");
                            restart_core_service();
                            break;
                        }
                    }
                }
                
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        };
        
        tokio::select! {
            _ = watchdog_loop => {},
            _ = rx => {
                log_to_file("Watchdog service shutdown signal received.");
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
        return Err(anyhow::anyhow!("Failed to set failure actions: {}", GetLastError()));
    }
    
    Ok(())
}

fn install_service() -> Result<(), anyhow::Error> {
    let service_name = to_wide_string("WatchdogService");
    let display_name = to_wide_string("Watchdog Background Health-Checker Service");
    
    let exe_path = std::env::current_exe()?;
    let exe_path_str = exe_path.to_str().ok_or_else(|| anyhow::anyhow!("Invalid executable path"))?;
    let binary_path = to_wide_string(&format!("\"{}\"", exe_path_str));

    unsafe {
        let sc_manager = OpenSCManagerW(
            ptr::null(),
            ptr::null(),
            SC_MANAGER_ALL_ACCESS,
        );
        if sc_manager == 0 {
            return Err(anyhow::anyhow!("Failed to open SC Manager: {}", GetLastError()));
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
            println!("Warning: failed to configure service recovery options: {}", e);
        } else {
            println!("Service recovery options configured successfully (Auto-Restart on failure).");
        }
        
        CloseServiceHandle(service);
        CloseServiceHandle(sc_manager);
    }
    
    Ok(())
}

fn uninstall_service() -> Result<(), anyhow::Error> {
    let service_name = to_wide_string("WatchdogService");
    
    unsafe {
        let sc_manager = OpenSCManagerW(
            ptr::null(),
            ptr::null(),
            SC_MANAGER_ALL_ACCESS,
        );
        if sc_manager == 0 {
            return Err(anyhow::anyhow!("Failed to open SC Manager: {}", GetLastError()));
        }
        
        let service = OpenServiceW(
            sc_manager,
            service_name.as_ptr(),
            SERVICE_ALL_ACCESS,
        );
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
            _ => {
                println!("Usage: watchdog-utility.exe [--install | --uninstall]");
                return Ok(());
            }
        }
    }
    
    let service_name = to_wide_string("WatchdogService");
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
                run_watchdog_app()?;
            } else {
                log_to_file(&format!("Failed to start service control dispatcher: {}.", err));
                return Err(anyhow::anyhow!("Failed to start service: {}", err));
            }
        }
    }
    
    Ok(())
}
