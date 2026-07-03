use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fs;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::sync::Mutex;

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::{SetFileSecurityW, DACL_SECURITY_INFORMATION};

const SDDL_REVISION_1: u32 = 1;

fn to_wide_string(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

pub fn secure_directory_acl(path: &str) -> Result<(), anyhow::Error> {
    let wide_path = to_wide_string(path);

    // SDDL Configuration with inheritance:
    // D: -> DACL header
    // (A;OICI;GA;;;SY) -> Allow Generic All (GA) to SYSTEM (SY), Object Inherit (OI), Container Inherit (CI)
    // (A;OICI;GA;;;BA) -> Allow Generic All (GA) to Built-in Administrators (BA), Object Inherit (OI), Container Inherit (CI)
    let sddl = to_wide_string("D:(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)");
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

        let security_info = DACL_SECURITY_INFORMATION;
        let set_res = SetFileSecurityW(wide_path.as_ptr(), security_info, sd_ptr);

        LocalFree(sd_ptr);

        if set_res == 0 {
            return Err(anyhow::anyhow!(
                "Failed to set directory security descriptor: {}",
                GetLastError()
            ));
        }
    }

    Ok(())
}

pub struct Db {
    conn: Mutex<Connection>,
}

impl Db {
    pub fn new() -> Result<Self, anyhow::Error> {
        let dir = r"C:\ProgramData\MonitoringControl";

        // If directory does not exist, create it and secure it
        if !Path::new(dir).exists() {
            fs::create_dir_all(dir)?;
            if let Err(e) = secure_directory_acl(dir) {
                eprintln!("Warning: failed to secure directory ACL: {}", e);
            }
        }

        let db_path = format!(r"{}\parental_control.db", dir);

        // Open or create database (it will inherit the parent directory's DACL)
        let conn = Connection::open(&db_path)?;

        let db = Db {
            conn: Mutex::new(conn),
        };
        db.init()?;

        Ok(db)
    }

    fn init(&self) -> Result<(), anyhow::Error> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow::anyhow!("DB lock error: {}", e))?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )",
            [],
        )?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS blocked_processes (
                name TEXT PRIMARY KEY
            )",
            [],
        )?;

        let count: i64 = conn.query_row("SELECT COUNT(*) FROM blocked_processes", [], |row| {
            row.get(0)
        })?;
        if count == 0 {
            for default_proc in &["calc.exe", "notepad.exe", "mspaint.exe"] {
                conn.execute(
                    "INSERT INTO blocked_processes (name) VALUES (?1)",
                    [default_proc],
                )?;
            }
        }
        Ok(())
    }

    pub fn add_blocked_process(&self, name: &str) -> Result<(), anyhow::Error> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow::anyhow!("DB lock error: {}", e))?;
        conn.execute(
            "INSERT OR IGNORE INTO blocked_processes (name) VALUES (?1)",
            [name],
        )?;
        Ok(())
    }

    pub fn remove_blocked_process(&self, name: &str) -> Result<(), anyhow::Error> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow::anyhow!("DB lock error: {}", e))?;
        conn.execute("DELETE FROM blocked_processes WHERE name = ?1", [name])?;
        Ok(())
    }

    pub fn get_blocked_processes(&self) -> Result<Vec<String>, anyhow::Error> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow::anyhow!("DB lock error: {}", e))?;
        let mut stmt = conn.prepare("SELECT name FROM blocked_processes")?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        let mut list = Vec::new();
        for name in rows.flatten() {
            list.push(name);
        }
        Ok(list)
    }

    pub fn set_master_password(&self, password: &str) -> Result<(), anyhow::Error> {
        let hash = self.hash_password(password);
        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow::anyhow!("DB lock error: {}", e))?;
        conn.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES ('master_password', ?1)",
            params![hash],
        )?;
        Ok(())
    }

    pub fn verify_password(&self, password: &str) -> bool {
        let hash = self.hash_password(password);
        let conn_guard = match self.conn.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        let stored_hash: Result<String, _> = conn_guard.query_row(
            "SELECT value FROM config WHERE key = 'master_password'",
            [],
            |row| row.get(0),
        );

        match stored_hash {
            Ok(stored) => stored == hash,
            Err(_) => false,
        }
    }

    #[allow(dead_code)]
    pub fn verify_hash(&self, hash_to_check: &str) -> bool {
        let conn_guard = match self.conn.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        let stored_hash: Result<String, _> = conn_guard.query_row(
            "SELECT value FROM config WHERE key = 'master_password'",
            [],
            |row| row.get(0),
        );

        match stored_hash {
            Ok(stored) => stored.trim().eq_ignore_ascii_case(hash_to_check.trim()),
            Err(_) => false,
        }
    }

    fn hash_password(&self, password: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let result = hasher.finalize();
        format!("{:x}", result)
    }

    /// Creates a new in-memory database for testing purposes.
    #[cfg(test)]
    pub fn new_in_memory() -> Result<Self, anyhow::Error> {
        let conn = Connection::open_in_memory()?;
        let db = Db {
            conn: Mutex::new(conn),
        };
        db.init()?;
        Ok(db)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_initialization() {
        let db = Db::new_in_memory().expect("Failed to create in-memory db");
        let blocked = db
            .get_blocked_processes()
            .expect("Failed to get blocked processes");
        assert_eq!(blocked.len(), 3);
        assert!(blocked.contains(&"calc.exe".to_string()));
    }

    #[test]
    fn test_password_verification() {
        let db = Db::new_in_memory().expect("Failed to create in-memory db");
        db.set_master_password("my_secret_pin")
            .expect("Failed to set password");

        assert!(db.verify_password("my_secret_pin"));
        assert!(!db.verify_password("wrong_pin"));
    }

    #[test]
    fn test_blocked_processes_management() {
        let db = Db::new_in_memory().expect("Failed to create in-memory db");

        db.add_blocked_process("game.exe")
            .expect("Failed to add process");
        let blocked = db.get_blocked_processes().expect("Failed to get processes");
        assert!(blocked.contains(&"game.exe".to_string()));

        db.remove_blocked_process("game.exe")
            .expect("Failed to remove process");
        let blocked_after = db.get_blocked_processes().expect("Failed to get processes");
        assert!(!blocked_after.contains(&"game.exe".to_string()));
    }
}
