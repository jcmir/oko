use chrono::Local;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

use crate::db::Db;
use crate::{network, to_wide_string, NETWORK_MANAGER, SUSPENDED};

const SDDL_REVISION_1: u32 = 1;

pub struct SecureSecurityAttributes {
    attrs: SECURITY_ATTRIBUTES,
    sd_ptr: *mut std::ffi::c_void,
}

impl SecureSecurityAttributes {
    pub fn new() -> Result<Self, anyhow::Error> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_security_attributes() {
        let sa_result = SecureSecurityAttributes::new();
        // Just verify that we don't panic and we can generate a valid SDDL descriptor.
        // It relies on underlying Windows API, so if it passes, the descriptor logic is correct.
        assert!(sa_result.is_ok(), "Failed to create security attributes");
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

pub async fn check_master_password_override(db: Arc<Db>) {
    let pipe_name = r"\\.\pipe\CoreAdminPipe";

    loop {
        let server_res = {
            match SecureSecurityAttributes::new() {
                Ok(mut sa) => {
                    let mut server_options = tokio::net::windows::named_pipe::ServerOptions::new();
                    server_options.first_pipe_instance(true);
                    server_options.reject_remote_clients(true);

                    unsafe {
                        server_options.create_with_security_attributes_raw(
                            pipe_name,
                            sa.as_mut_ptr() as *mut std::ffi::c_void,
                        )
                    }
                }
                Err(e) => {
                    tracing::error!(
                        category = "security_error",
                        "Failed to generate security attributes for Admin Pipe: {}",
                        e
                    );
                    Err(std::io::Error::other(e.to_string()))
                }
            }
        };

        let server = match server_res {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    category = "ipc_error",
                    "Failed to create Admin Named Pipe: {}. Retrying in 2 seconds...",
                    e
                );
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                continue;
            }
        };

        if server.connect().await.is_err() {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            continue;
        }

        let mut reader = tokio::io::BufReader::new(server);
        let mut line = String::new();

        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

        match reader.read_line(&mut line).await {
            Ok(0) => {}
            Ok(_) => {
                let input = line.trim();
                if input == "STATUS" {
                    let state_str = if SUSPENDED.load(Ordering::SeqCst) {
                        "Suspended"
                    } else {
                        "Active"
                    };
                    let response = format!("STATE: {}\n", state_str);
                    let _ = reader.get_mut().write_all(response.as_bytes()).await;
                } else if let Some(password) = input.strip_prefix("SUSPEND ") {
                    if db.verify_password(password) {
                        SUSPENDED.store(true, Ordering::SeqCst);
                        tracing::warn!(
                            category = "system_override",
                            "System SUSPENDED via Admin pipe."
                        );
                        let _ = reader.get_mut().write_all(b"OK\n").await;
                    } else {
                        tracing::error!(
                            category = "unauthorized_access",
                            "Invalid password for SUSPEND command."
                        );
                        let _ = reader
                            .get_mut()
                            .write_all(b"ERROR: Invalid password\n")
                            .await;
                    }
                } else if let Some(password) = input.strip_prefix("RESUME ") {
                    if db.verify_password(password) {
                        SUSPENDED.store(false, Ordering::SeqCst);
                        tracing::info!(
                            category = "system_override",
                            "System RESUMED via Admin pipe."
                        );
                        let _ = reader.get_mut().write_all(b"OK\n").await;
                    } else {
                        tracing::error!(
                            category = "unauthorized_access",
                            "Invalid password for RESUME command."
                        );
                        let _ = reader
                            .get_mut()
                            .write_all(b"ERROR: Invalid password\n")
                            .await;
                    }
                } else if let Some(rem) = input.strip_prefix("ADD_BLOCK ") {
                    let parts: Vec<&str> = rem.splitn(2, ' ').collect();
                    if parts.len() == 2 {
                        let password = parts[0];
                        let process_name = parts[1].trim();
                        if db.verify_password(password) {
                            match db.add_blocked_process(process_name) {
                                Ok(_) => {
                                    tracing::warn!(
                                        category = "system_override",
                                        "Added dynamic block: {}",
                                        process_name
                                    );
                                    let _ = reader.get_mut().write_all(b"OK\n").await;
                                }
                                Err(e) => {
                                    let err_msg = format!("ERROR: Database error: {}\n", e);
                                    let _ = reader.get_mut().write_all(err_msg.as_bytes()).await;
                                }
                            }
                        } else {
                            tracing::error!(
                                category = "unauthorized_access",
                                "Invalid password for ADD_BLOCK command."
                            );
                            let _ = reader
                                .get_mut()
                                .write_all(b"ERROR: Invalid password\n")
                                .await;
                        }
                    } else {
                        let _ = reader.get_mut().write_all(b"ERROR: Invalid format. Expected: ADD_BLOCK <password> <process_name>\n").await;
                    }
                } else if let Some(rem) = input.strip_prefix("REMOVE_BLOCK ") {
                    let parts: Vec<&str> = rem.splitn(2, ' ').collect();
                    if parts.len() == 2 {
                        let password = parts[0];
                        let process_name = parts[1].trim();
                        if db.verify_password(password) {
                            match db.remove_blocked_process(process_name) {
                                Ok(_) => {
                                    tracing::warn!(
                                        category = "system_override",
                                        "Removed dynamic block: {}",
                                        process_name
                                    );
                                    let _ = reader.get_mut().write_all(b"OK\n").await;
                                }
                                Err(e) => {
                                    let err_msg = format!("ERROR: Database error: {}\n", e);
                                    let _ = reader.get_mut().write_all(err_msg.as_bytes()).await;
                                }
                            }
                        } else {
                            tracing::error!(
                                category = "unauthorized_access",
                                "Invalid password for REMOVE_BLOCK command."
                            );
                            let _ = reader
                                .get_mut()
                                .write_all(b"ERROR: Invalid password\n")
                                .await;
                        }
                    } else {
                        let _ = reader.get_mut().write_all(b"ERROR: Invalid format. Expected: REMOVE_BLOCK <password> <process_name>\n").await;
                    }
                } else {
                    let _ = reader
                        .get_mut()
                        .write_all(b"ERROR: Unknown command\n")
                        .await;
                }
            }
            Err(e) => {
                tracing::error!(
                    category = "ipc_error",
                    "Error reading from Admin Named Pipe: {}",
                    e
                );
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    }
}

pub async fn run_health_pipe_server() {
    let pipe_name = r"\\.\pipe\CoreServiceHealthPipe";
    loop {
        let server_res = {
            match SecureSecurityAttributes::new() {
                Ok(mut sa) => {
                    let mut server_options = tokio::net::windows::named_pipe::ServerOptions::new();
                    server_options.first_pipe_instance(true);
                    server_options.reject_remote_clients(true);

                    unsafe {
                        server_options.create_with_security_attributes_raw(
                            pipe_name,
                            sa.as_mut_ptr() as *mut std::ffi::c_void,
                        )
                    }
                }
                Err(e) => {
                    tracing::error!(
                        category = "security_error",
                        "Error generating security attributes: {}",
                        e
                    );
                    Err(std::io::Error::other(e.to_string()))
                }
            }
        };

        let mut server = match server_res {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(
                    category = "ipc_error",
                    "Error creating secure named pipe: {}",
                    e
                );
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                continue;
            }
        };

        if server.connect().await.is_err() {
            tracing::error!(category = "ipc_error", "Watchdog connection failed");
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            continue;
        }

        tracing::info!(
            category = "ipc_event",
            "Watchdog connected via Secure Named Pipe."
        );

        loop {
            use tokio::io::AsyncWriteExt;

            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
            let current_state = NETWORK_MANAGER.get_state();
            let state_str = match current_state {
                network::NetworkState::Green => "GREEN",
                network::NetworkState::Yellow => "YELLOW",
                network::NetworkState::Red => "RED",
            };

            let signal = format!("HEARTBEAT {} STATUS:{}\n", timestamp, state_str);

            if server.write_all(signal.as_bytes()).await.is_err() {
                tracing::warn!(
                    category = "ipc_event",
                    "Failed to write heartbeat to pipe (Watchdog disconnected)"
                );
                break;
            }

            if SUSPENDED.load(Ordering::SeqCst) {
                tracing::info!(
                    category = "system_status",
                    "System is suspended. Blocking logic inactive."
                );
            } else {
                tracing::info!(category = "heartbeat", "Heartbeat sent: {}", timestamp);
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }
    }
}
