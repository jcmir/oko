use tokio::net::windows::named_pipe::ClientOptions;
use tokio::io::{AsyncWriteExt, AsyncBufReadExt, BufReader};
use anyhow::{Result, anyhow};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemStatus {
    Active,
    Suspended,
    Disconnected,
}

impl SystemStatus {
    pub fn to_string_ru(&self) -> &'static str {
        match self {
            SystemStatus::Active => "АКТИВЕН",
            SystemStatus::Suspended => "ПРИОСТАНОВЛЕН",
            SystemStatus::Disconnected => "ОТКЛЮЧЕН",
        }
    }
}

pub struct CoreClient {
    pipe_path: String,
}

impl CoreClient {
    pub fn new() -> Self {
        Self {
            pipe_path: r"\\.\pipe\CoreAdminPipe".to_string(),
        }
    }

    pub async fn query_status(&self) -> Result<SystemStatus> {
        let client = ClientOptions::new().open(&self.pipe_path)?;
        let mut reader = BufReader::new(client);
        
        reader.get_mut().write_all(b"STATUS\n").await?;
        reader.get_mut().flush().await?;
        
        let mut response = String::new();
        reader.read_line(&mut response).await?;
        
        let trimmed = response.trim();
        if trimmed.starts_with("STATE: ") {
            let state = &trimmed["STATE: ".len()..];
            if state.eq_ignore_ascii_case("Suspended") {
                Ok(SystemStatus::Suspended)
            } else {
                Ok(SystemStatus::Active)
            }
        } else {
            Err(anyhow!("Неверный ответ статуса: {}", trimmed))
        }
    }

    pub async fn send_suspend(&self, password: &str) -> Result<()> {
        let client = ClientOptions::new().open(&self.pipe_path)?;
        let mut reader = BufReader::new(client);
        
        let cmd = format!("SUSPEND {}\n", password);
        reader.get_mut().write_all(cmd.as_bytes()).await?;
        reader.get_mut().flush().await?;
        
        let mut response = String::new();
        reader.read_line(&mut response).await?;
        
        let trimmed = response.trim();
        if trimmed == "OK" {
            Ok(())
        } else {
            let clean_err = trimmed
                .replace("ERROR: ", "")
                .replace("Invalid password", "Неверный мастер-пароль");
            Err(anyhow!(clean_err))
        }
    }

    pub async fn send_resume(&self, password: &str) -> Result<()> {
        let client = ClientOptions::new().open(&self.pipe_path)?;
        let mut reader = BufReader::new(client);
        
        let cmd = format!("RESUME {}\n", password);
        reader.get_mut().write_all(cmd.as_bytes()).await?;
        reader.get_mut().flush().await?;
        
        let mut response = String::new();
        reader.read_line(&mut response).await?;
        
        let trimmed = response.trim();
        if trimmed == "OK" {
            Ok(())
        } else {
            let clean_err = trimmed
                .replace("ERROR: ", "")
                .replace("Invalid password", "Неверный мастер-пароль");
            Err(anyhow!(clean_err))
        }
    }
}
