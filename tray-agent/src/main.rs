#![windows_subsystem = "windows"]

mod client;
mod dialog;
mod tray;

use crate::client::{CoreClient, SystemStatus};
use crate::tray::SystemTray;
use anyhow::Result;
use std::path::Path;
use tray_icon::menu::MenuEvent;
use widestring::U16CString;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    MessageBoxW, MB_ICONERROR, MB_ICONINFORMATION, MB_OK,
};

fn get_or_create_machine_id() -> String {
    let path = Path::new(r"C:\ProgramData\MonitoringControl\machine_id.txt");
    if path.exists() {
        if let Ok(content) = std::fs::read_to_string(path) {
            let trimmed = content.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }

    // Generate a random ID
    let mut id = String::new();
    use rand::Rng;
    let mut rng = rand::thread_rng();
    for _ in 0..8 {
        id.push(rng.sample(rand::distributions::Alphanumeric) as char);
    }
    let full_id = format!("OKO-{}", id.to_uppercase());

    let _ = std::fs::create_dir_all(r"C:\ProgramData\MonitoringControl");
    let _ = std::fs::write(path, &full_id);

    full_id
}

fn show_info_box(title: &str, message: &str) {
    unsafe {
        let title_w = U16CString::from_str(title).unwrap();
        let message_w = U16CString::from_str(message).unwrap();
        MessageBoxW(
            0,
            message_w.as_ptr(),
            title_w.as_ptr(),
            MB_OK | MB_ICONINFORMATION,
        );
    }
}

fn show_error_box(title: &str, message: &str) {
    unsafe {
        let title_w = U16CString::from_str(title).unwrap();
        let message_w = U16CString::from_str(message).unwrap();
        MessageBoxW(
            0,
            message_w.as_ptr(),
            title_w.as_ptr(),
            MB_OK | MB_ICONERROR,
        );
    }
}

fn main() -> Result<()> {
    let machine_id = get_or_create_machine_id();
    let client = CoreClient::new();
    let tray = SystemTray::new(&machine_id);

    // Create a local single-threaded Tokio runtime
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut last_poll = std::time::Instant::now() - std::time::Duration::from_secs(5);
    let mut current_status = SystemStatus::Disconnected;

    // Run custom event loop for menu events (using non-blocking poll with timeout)
    let receiver = MenuEvent::receiver();
    loop {
        // Poll for menu events
        if let Ok(event) = receiver.recv_timeout(std::time::Duration::from_millis(50)) {
            if tray.is_suspend_click(&event.id) {
                if let Some(pwd) =
                    dialog::show_password_dialog("Приостановка Защиты", "Введите Мастер-Пароль:")
                {
                    match rt.block_on(client.send_suspend(&pwd)) {
                        Ok(_) => {
                            show_info_box("Успех", "Защита системы успешно приостановлена.");
                            current_status = SystemStatus::Suspended;
                            tray.update_status(SystemStatus::Suspended);
                        }
                        Err(e) => {
                            show_error_box(
                                "Ошибка",
                                &format!("Не удалось приостановить защиту:\n{}", e),
                            );
                        }
                    }
                }
            } else if tray.is_resume_click(&event.id) {
                if let Some(pwd) =
                    dialog::show_password_dialog("Возобновление Защиты", "Введите Мастер-Пароль:")
                {
                    match rt.block_on(client.send_resume(&pwd)) {
                        Ok(_) => {
                            show_info_box("Успех", "Защита системы успешно возобновлена.");
                            current_status = SystemStatus::Active;
                            tray.update_status(SystemStatus::Active);
                        }
                        Err(e) => {
                            show_error_box(
                                "Ошибка",
                                &format!("Не удалось возобновить защиту:\n{}", e),
                            );
                        }
                    }
                }
            } else if tray.is_quit_click(&event.id) {
                break;
            }
        }

        // Periodic status update check
        if last_poll.elapsed() >= std::time::Duration::from_secs(2) {
            last_poll = std::time::Instant::now();
            let new_status = match rt.block_on(client.query_status()) {
                Ok(s) => s,
                Err(_) => SystemStatus::Disconnected,
            };
            if new_status != current_status {
                current_status = new_status;
                tray.update_status(current_status);
            }
        }
    }

    Ok(())
}
