use std::sync::atomic::Ordering;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

use crate::db::Db;
use crate::SUSPENDED;

pub fn check_and_block_processes(db: &Db) {
    if SUSPENDED.load(Ordering::SeqCst) {
        return;
    }

    let blocked_names = match db.get_blocked_processes() {
        Ok(list) => list,
        Err(e) => {
            tracing::error!(
                category = "database_error",
                "Failed to query blocked processes: {}",
                e
            );
            vec![
                "calc.exe".to_string(),
                "notepad.exe".to_string(),
                "mspaint.exe".to_string(),
            ]
        }
    };

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return;
        }

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let len = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let exe_name = String::from_utf16_lossy(&entry.szExeFile[..len]);
                let exe_name_lower = exe_name.to_lowercase();

                for blocked in &blocked_names {
                    if exe_name_lower == *blocked {
                        let process_handle = OpenProcess(PROCESS_TERMINATE, 0, entry.th32ProcessID);
                        if process_handle != 0 {
                            if TerminateProcess(process_handle, 1) != 0 {
                                tracing::warn!(
                                    category = "process_blocked",
                                    "Blocked forbidden process: {} (PID: {})",
                                    exe_name,
                                    entry.th32ProcessID
                                );
                            }
                            CloseHandle(process_handle);
                        }
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
