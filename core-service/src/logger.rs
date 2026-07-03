use std::fs::{self, OpenOptions};
use std::sync::Arc;
use std::path::Path;
use tracing_subscriber::{fmt, prelude::*, Registry};
use tracing_subscriber::filter::LevelFilter;
use crate::db::secure_directory_acl;

pub fn init_logger() -> Result<(), anyhow::Error> {
    let dir = r"C:\ProgramData\MonitoringControl";
    
    // Create directory and secure it if it doesn't exist yet
    if !Path::new(dir).exists() {
        fs::create_dir_all(dir)?;
        if let Err(e) = secure_directory_acl(dir) {
            eprintln!("Warning: failed to secure directory ACL: {}", e);
        }
    }
    
    let log_path = format!(r"{}\events.jsonl", dir);
    
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open(&log_path)?;
        
    let json_layer = fmt::layer()
        .json()
        .with_writer(Arc::new(file))
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_line_number(false)
        .with_file(false);
        
    let subscriber = Registry::default()
        .with(LevelFilter::INFO)
        .with(json_layer);
        
    tracing::subscriber::set_global_default(subscriber)?;
    
    Ok(())
}
