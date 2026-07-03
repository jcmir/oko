use std::fs::File;
use std::io::{BufRead, BufReader as StdBufReader, Seek, SeekFrom};
use std::path::Path;
use std::sync::mpsc::channel;
use std::time::Duration;

use anyhow::Result;
use chrono::DateTime;
use crossterm::event::{self, Event as CEvent, KeyCode};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Row, Table};
use ratatui::Terminal;
use serde::Deserialize;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::net::windows::named_pipe::ClientOptions;

use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_MANAGER_CONNECT,
    SC_STATUS_PROCESS_INFO, SERVICE_PAUSED, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
    SERVICE_START_PENDING, SERVICE_STATUS_PROCESS, SERVICE_STOPPED, SERVICE_STOP_PENDING,
};

#[derive(Deserialize, Clone, Debug)]
struct TracingEvent {
    timestamp: String,
    level: String,
    fields: TracingFields,
}

#[derive(Deserialize, Clone, Debug)]
struct TracingFields {
    category: Option<String>,
    message: Option<String>,
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
enum InputMode {
    Normal,
    PromptingSuspend,
    PromptingResume,
    PromptingAddBlockName,
    PromptingAddBlockPassword,
    PromptingRemoveBlockName,
    PromptingRemoveBlockPassword,
}

struct AppState {
    events: Vec<TracingEvent>,
    max_events: usize,
    file_offset: u64,
    log_path: String,
    core_status: String,
    watchdog_status: String,
    suspended_status: String,
    input_mode: InputMode,
    password_input: String,
    process_input: String,
    feedback_message: Option<(String, bool)>, // (message, is_success)
    feedback_timeout: Option<std::time::Instant>,
}

impl AppState {
    fn new(log_path: &str) -> Self {
        Self {
            events: Vec::new(),
            max_events: 50,
            file_offset: 0,
            log_path: log_path.to_string(),
            core_status: "UNKNOWN".to_string(),
            watchdog_status: "UNKNOWN".to_string(),
            suspended_status: "UNKNOWN".to_string(),
            input_mode: InputMode::Normal,
            password_input: String::new(),
            process_input: String::new(),
            feedback_message: None,
            feedback_timeout: None,
        }
    }

    async fn update_system_state(&mut self) {
        self.core_status = get_service_status("CoreService");
        self.watchdog_status = get_service_status("WatchdogService");

        // Query the live state of the Core Service via the admin pipe
        match query_live_status().await {
            Ok(status) => {
                self.suspended_status = status;
            }
            Err(_) => {
                // Fallback to checking the log events if the admin pipe is unreachable
                let is_suspended = self.events.iter().rev().any(|e| {
                    if let Some(cat) = &e.fields.category {
                        if cat == "system_override" || cat == "system_status" {
                            if let Some(msg) = &e.fields.message {
                                if msg.contains("suspended") || msg.contains("Suspended") {
                                    return true;
                                }
                            }
                        }
                    }
                    false
                });
                self.suspended_status = if is_suspended {
                    "SUSPENDED".to_string()
                } else {
                    "ACTIVE".to_string()
                };
            }
        }
    }

    fn read_new_logs(&mut self) -> Result<()> {
        let path = Path::new(&self.log_path);
        if !path.exists() {
            return Ok(());
        }

        let mut file = File::open(path)?;
        let file_len = file.metadata()?.len();

        if file_len < self.file_offset {
            self.file_offset = 0;
            self.events.clear();
        }

        file.seek(SeekFrom::Start(self.file_offset))?;
        let reader = StdBufReader::new(file);

        for line_res in reader.lines() {
            let line = line_res?;
            if let Ok(event) = serde_json::from_str::<TracingEvent>(&line) {
                self.events.push(event);
            }
        }

        if self.events.len() > self.max_events {
            let drain_count = self.events.len() - self.max_events;
            self.events.drain(0..drain_count);
        }

        self.file_offset = file_len;
        Ok(())
    }

    fn set_feedback(&mut self, message: &str, is_success: bool) {
        self.feedback_message = Some((message.to_string(), is_success));
        self.feedback_timeout = Some(std::time::Instant::now() + Duration::from_secs(4));
    }

    fn check_feedback_expiry(&mut self) {
        if let Some(timeout) = self.feedback_timeout {
            if std::time::Instant::now() > timeout {
                self.feedback_message = None;
                self.feedback_timeout = None;
            }
        }
    }
}

fn get_service_status(service_name: &str) -> String {
    let wide_name: Vec<u16> = service_name.encode_utf16().chain(Some(0)).collect();
    unsafe {
        let sc_manager = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
        if sc_manager == 0 {
            return "UNKNOWN (SCM Error)".to_string();
        }

        let service = OpenServiceW(sc_manager, wide_name.as_ptr(), SERVICE_QUERY_STATUS);
        if service == 0 {
            CloseServiceHandle(sc_manager);
            return "NOT INSTALLED".to_string();
        }

        let mut status_process: SERVICE_STATUS_PROCESS = std::mem::zeroed();
        let mut bytes_needed = 0;
        let res = QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            &mut status_process as *mut _ as *mut u8,
            std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut bytes_needed,
        );

        CloseServiceHandle(service);
        CloseServiceHandle(sc_manager);

        if res == 0 {
            return "UNKNOWN".to_string();
        }

        match status_process.dwCurrentState {
            SERVICE_RUNNING => "RUNNING".to_string(),
            SERVICE_STOPPED => "STOPPED".to_string(),
            SERVICE_PAUSED => "PAUSED".to_string(),
            SERVICE_START_PENDING => "STARTING".to_string(),
            SERVICE_STOP_PENDING => "STOPPING".to_string(),
            _ => format!("STATE ({})", status_process.dwCurrentState),
        }
    }
}

async fn query_live_status() -> Result<String> {
    let pipe_name = r"\\.\pipe\CoreAdminPipe";
    let client = ClientOptions::new().open(pipe_name)?;
    let mut reader = TokioBufReader::new(client);

    reader.get_mut().write_all(b"STATUS\n").await?;
    reader.get_mut().flush().await?;

    let mut response = String::new();
    reader.read_line(&mut response).await?;

    let trimmed = response.trim();
    if trimmed.starts_with("STATE: ") {
        Ok(trimmed["STATE: ".len()..].to_uppercase())
    } else {
        Err(anyhow::anyhow!("Invalid status response"))
    }
}

async fn send_suspend_command(password: &str) -> Result<String> {
    let pipe_name = r"\\.\pipe\CoreAdminPipe";
    let client = ClientOptions::new().open(pipe_name)?;
    let mut reader = TokioBufReader::new(client);

    let cmd = format!("SUSPEND {}\n", password);
    reader.get_mut().write_all(cmd.as_bytes()).await?;
    reader.get_mut().flush().await?;

    let mut response = String::new();
    reader.read_line(&mut response).await?;
    Ok(response.trim().to_string())
}

async fn send_resume_command(password: &str) -> Result<String> {
    let pipe_name = r"\\.\pipe\CoreAdminPipe";
    let client = ClientOptions::new().open(pipe_name)?;
    let mut reader = TokioBufReader::new(client);

    let cmd = format!("RESUME {}\n", password);
    reader.get_mut().write_all(cmd.as_bytes()).await?;
    reader.get_mut().flush().await?;

    let mut response = String::new();
    reader.read_line(&mut response).await?;
    Ok(response.trim().to_string())
}

async fn send_add_block_command(password: &str, process_name: &str) -> Result<String> {
    let pipe_name = r"\\.\pipe\CoreAdminPipe";
    let client = ClientOptions::new().open(pipe_name)?;
    let mut reader = TokioBufReader::new(client);

    let cmd = format!("ADD_BLOCK {} {}\n", password, process_name);
    reader.get_mut().write_all(cmd.as_bytes()).await?;
    reader.get_mut().flush().await?;

    let mut response = String::new();
    reader.read_line(&mut response).await?;
    Ok(response.trim().to_string())
}

async fn send_remove_block_command(password: &str, process_name: &str) -> Result<String> {
    let pipe_name = r"\\.\pipe\CoreAdminPipe";
    let client = ClientOptions::new().open(pipe_name)?;
    let mut reader = TokioBufReader::new(client);

    let cmd = format!("REMOVE_BLOCK {} {}\n", password, process_name);
    reader.get_mut().write_all(cmd.as_bytes()).await?;
    reader.get_mut().flush().await?;

    let mut response = String::new();
    reader.read_line(&mut response).await?;
    Ok(response.trim().to_string())
}

fn translate_status(status: &str) -> String {
    match status {
        "RUNNING" => "ЗАПУЩЕНО".to_string(),
        "STOPPED" => "ОСТАНОВЛЕНО".to_string(),
        "NOT INSTALLED" => "НЕ УСТАНОВЛЕНА".to_string(),
        "STARTING" => "ЗАПУСКАЕТСЯ".to_string(),
        "STOPPING" => "ОСТАНАВЛИВАЕТСЯ".to_string(),
        "PAUSED" => "ПАУЗА".to_string(),
        "ACTIVE" => "АКТИВЕН".to_string(),
        "SUSPENDED" => "ПРИОСТАНОВЛЕН".to_string(),
        _ => status.to_string(),
    }
}

fn translate_event(category: &str, message: &str) -> (String, String) {
    let cat_ru = match category {
        "process_blocked" => "Блокировка",
        "system_override" | "system_status" => "Управление",
        "watchdog_event" => "Контроль",
        "process_lifecycle" => "Система",
        "ipc_command" | "admin_action" | "ipc" => "Администрирование",
        "db" | "database" => "База Данных",
        _ => "Общее",
    };

    let msg_ru = if category == "process_blocked" {
        if let Some(pos) = message.find("Blocked process: ") {
            format!(
                "Заблокирован запуск процесса: {}",
                &message[pos + "Blocked process: ".len()..]
            )
        } else if let Some(pos) = message.find("Blocked process ") {
            format!(
                "Заблокирован запуск процесса: {}",
                &message[pos + "Blocked process ".len()..]
            )
        } else {
            message.to_string()
        }
    } else if category == "watchdog_event" {
        if message.contains("CoreService stopped responding") {
            "Обнаружено зависание Ядра! Выполняется экстренный перезапуск...".to_string()
        } else if message.contains("Successfully restarted") {
            "Служба Ядра успешно перезапущена силами Watchdog".to_string()
        } else if message.contains("Failed to restart") {
            "Критическая ошибка: Watchdog не смог перезапустить службу Ядра".to_string()
        } else {
            message.to_string()
        }
    } else if category == "system_override" || category == "system_status" {
        if message.contains("suspended") || message.contains("Suspended") {
            "Режим защиты ПРИОСТАНОВЛЕН администратором".to_string()
        } else if message.contains("resumed") || message.contains("Resumed") {
            "Режим защиты ВОЗОБНОВЛЕН (активен)".to_string()
        } else {
            message.to_string()
        }
    } else if category == "process_lifecycle" {
        if message.contains("started") || message.contains("Started") {
            "Служба Ядра успешно запущена и контролирует систему".to_string()
        } else if message.contains("stopped") || message.contains("Stopped") {
            "Служба Ядра остановлена".to_string()
        } else {
            message.to_string()
        }
    } else if message.starts_with("ADD_BLOCK command received for: ") {
        format!(
            "Добавлен в список блокировки: {}",
            &message["ADD_BLOCK command received for: ".len()..]
        )
    } else if message.starts_with("REMOVE_BLOCK command received for: ") {
        format!(
            "Удален из списка блокировки: {}",
            &message["REMOVE_BLOCK command received for: ".len()..]
        )
    } else {
        message
            .replace("Core Service started", "Служба Ядра запущена")
            .replace("Core Service stopped", "Служба Ядра остановлена")
            .replace(
                "Admin command received: SUSPEND",
                "Получена команда: ПРИОСТАНОВИТЬ ЗАЩИТУ",
            )
            .replace(
                "Admin command received: RESUME",
                "Получена команда: АКТИВИРОВАТЬ ЗАЩИТУ",
            )
            .replace(
                "Database initialized",
                "База данных успешно инициализирована",
            )
    };

    (cat_ru.to_string(), msg_ru)
}

fn format_timestamp(ts: &str) -> String {
    if let Ok(dt) = DateTime::parse_from_rfc3339(ts) {
        dt.with_timezone(&chrono::Local)
            .format("%H:%M:%S")
            .to_string()
    } else {
        ts.to_string()
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Percentage((100 - percent_y) / 2),
                Constraint::Percentage(percent_y),
                Constraint::Percentage((100 - percent_y) / 2),
            ]
            .as_ref(),
        )
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Percentage((100 - percent_x) / 2),
                Constraint::Percentage(percent_x),
                Constraint::Percentage((100 - percent_x) / 2),
            ]
            .as_ref(),
        )
        .split(popup_layout[1])[1]
}

#[tokio::main]
async fn main() -> Result<()> {
    let log_path = r"C:\ProgramData\MonitoringControl\events.jsonl";

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    crossterm::execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut state = AppState::new(log_path);
    let _ = state.read_new_logs();
    state.update_system_state().await;

    // Setup file watcher channel
    let (tx, rx) = channel();
    let mut watcher = RecommendedWatcher::new(tx, Config::default())?;
    let log_dir = r"C:\ProgramData\MonitoringControl";
    if Path::new(log_dir).exists() {
        watcher.watch(Path::new(log_dir), RecursiveMode::NonRecursive)?;
    }

    // Input loop channel
    let (input_tx, mut input_rx) = tokio::sync::mpsc::channel::<crossterm::event::KeyEvent>(100);

    // Spawn input polling task
    tokio::task::spawn_blocking(move || loop {
        if event::poll(Duration::from_millis(50)).unwrap_or(false) {
            if let Ok(CEvent::Key(key)) = event::read() {
                if key.kind == crossterm::event::KeyEventKind::Press {
                    let _ = input_tx.blocking_send(key);
                }
            }
        }
    });

    let mut tick_interval = tokio::time::interval(Duration::from_millis(500));

    loop {
        // Handle input events
        tokio::select! {
            _ = tick_interval.tick() => {
                state.update_system_state().await;
                let _ = state.read_new_logs();
                state.check_feedback_expiry();
            }
            maybe_key = input_rx.recv() => {
                if let Some(key) = maybe_key {
                    match state.input_mode {
                        InputMode::Normal => {
                            match key.code {
                                KeyCode::Char('q') => {
                                    break;
                                }
                                KeyCode::Char('1') => {
                                    state.input_mode = InputMode::PromptingSuspend;
                                    state.password_input.clear();
                                    state.feedback_message = None;
                                }
                                KeyCode::Char('2') => {
                                    state.input_mode = InputMode::PromptingResume;
                                    state.password_input.clear();
                                    state.feedback_message = None;
                                }
                                KeyCode::Char('3') => {
                                    state.input_mode = InputMode::PromptingAddBlockName;
                                    state.process_input.clear();
                                    state.password_input.clear();
                                    state.feedback_message = None;
                                }
                                KeyCode::Char('4') => {
                                    state.input_mode = InputMode::PromptingRemoveBlockName;
                                    state.process_input.clear();
                                    state.password_input.clear();
                                    state.feedback_message = None;
                                }
                                _ => {}
                            }
                        }
                        InputMode::PromptingSuspend | InputMode::PromptingResume => {
                            match key.code {
                                KeyCode::Enter => {
                                    let pwd = state.password_input.clone();
                                    let mode = state.input_mode;
                                    state.input_mode = InputMode::Normal;
                                    state.password_input.clear();

                                    if mode == InputMode::PromptingSuspend {
                                        match send_suspend_command(&pwd).await {
                                            Ok(res) => {
                                                if res == "OK" {
                                                    state.set_feedback("УСПЕШНО: Защита приостановлена.", true);
                                                } else {
                                                    let err_msg = res.replace("Invalid password", "Неверный пароль");
                                                    state.set_feedback(&format!("ОШИБКА: {}", err_msg), false);
                                                }
                                            }
                                            Err(e) => {
                                                state.set_feedback(&format!("Ошибка связи: {}", e), false);
                                            }
                                        }
                                    } else {
                                        match send_resume_command(&pwd).await {
                                            Ok(res) => {
                                                if res == "OK" {
                                                    state.set_feedback("УСПЕШНО: Защита активирована.", true);
                                                } else {
                                                    let err_msg = res.replace("Invalid password", "Неверный пароль");
                                                    state.set_feedback(&format!("ОШИБКА: {}", err_msg), false);
                                                }
                                            }
                                            Err(e) => {
                                                state.set_feedback(&format!("Ошибка связи: {}", e), false);
                                            }
                                        }
                                    }
                                    state.update_system_state().await;
                                    let _ = state.read_new_logs();
                                }
                                KeyCode::Esc => {
                                    state.input_mode = InputMode::Normal;
                                    state.password_input.clear();
                                }
                                KeyCode::Backspace => {
                                    state.password_input.pop();
                                }
                                KeyCode::Char(c) => {
                                    state.password_input.push(c);
                                }
                                _ => {}
                            }
                        }
                        InputMode::PromptingAddBlockName => {
                            match key.code {
                                KeyCode::Enter => {
                                    if !state.process_input.trim().is_empty() {
                                        state.input_mode = InputMode::PromptingAddBlockPassword;
                                    }
                                }
                                KeyCode::Esc => {
                                    state.input_mode = InputMode::Normal;
                                    state.process_input.clear();
                                }
                                KeyCode::Backspace => {
                                    state.process_input.pop();
                                }
                                KeyCode::Char(c) => {
                                    state.process_input.push(c);
                                }
                                _ => {}
                            }
                        }
                        InputMode::PromptingAddBlockPassword => {
                            match key.code {
                                KeyCode::Enter => {
                                    let pwd = state.password_input.clone();
                                    let proc = state.process_input.clone();
                                    state.input_mode = InputMode::Normal;
                                    state.password_input.clear();
                                    state.process_input.clear();

                                    match send_add_block_command(&pwd, &proc).await {
                                        Ok(res) => {
                                            if res == "OK" {
                                                state.set_feedback(&format!("УСПЕШНО: Процесс '{}' заблокирован.", proc), true);
                                            } else {
                                                let err_msg = res
                                                    .replace("Invalid password", "Неверный пароль")
                                                    .replace("Process already blocked", "Процесс уже заблокирован");
                                                state.set_feedback(&format!("ОШИБКА: {}", err_msg), false);
                                            }
                                        }
                                        Err(e) => {
                                            state.set_feedback(&format!("Ошибка связи: {}", e), false);
                                        }
                                    }
                                    state.update_system_state().await;
                                    let _ = state.read_new_logs();
                                }
                                KeyCode::Esc => {
                                    state.input_mode = InputMode::Normal;
                                    state.password_input.clear();
                                    state.process_input.clear();
                                }
                                KeyCode::Backspace => {
                                    state.password_input.pop();
                                }
                                KeyCode::Char(c) => {
                                    state.password_input.push(c);
                                }
                                _ => {}
                            }
                        }
                        InputMode::PromptingRemoveBlockName => {
                            match key.code {
                                KeyCode::Enter => {
                                    if !state.process_input.trim().is_empty() {
                                        state.input_mode = InputMode::PromptingRemoveBlockPassword;
                                    }
                                }
                                KeyCode::Esc => {
                                    state.input_mode = InputMode::Normal;
                                    state.process_input.clear();
                                }
                                KeyCode::Backspace => {
                                    state.process_input.pop();
                                }
                                KeyCode::Char(c) => {
                                    state.process_input.push(c);
                                }
                                _ => {}
                            }
                        }
                        InputMode::PromptingRemoveBlockPassword => {
                            match key.code {
                                KeyCode::Enter => {
                                    let pwd = state.password_input.clone();
                                    let proc = state.process_input.clone();
                                    state.input_mode = InputMode::Normal;
                                    state.password_input.clear();
                                    state.process_input.clear();

                                    match send_remove_block_command(&pwd, &proc).await {
                                        Ok(res) => {
                                            if res == "OK" {
                                                state.set_feedback(&format!("УСПЕШНО: Блокировка с '{}' снята.", proc), true);
                                            } else {
                                                let err_msg = res
                                                    .replace("Invalid password", "Неверный пароль")
                                                    .replace("Process not found", "Процесс не найден в списке");
                                                state.set_feedback(&format!("ОШИБКА: {}", err_msg), false);
                                            }
                                        }
                                        Err(e) => {
                                            state.set_feedback(&format!("Ошибка связи: {}", e), false);
                                        }
                                    }
                                    state.update_system_state().await;
                                    let _ = state.read_new_logs();
                                }
                                KeyCode::Esc => {
                                    state.input_mode = InputMode::Normal;
                                    state.password_input.clear();
                                    state.process_input.clear();
                                }
                                KeyCode::Backspace => {
                                    state.password_input.pop();
                                }
                                KeyCode::Char(c) => {
                                    state.password_input.push(c);
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }

        // Read watch notify events if any
        if let Ok(_notify_event) = rx.try_recv() {
            let _ = state.read_new_logs();
        }

        // Draw TUI
        terminal.draw(|f| {
            let size = f.size();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints(
                    [
                        Constraint::Length(5), // Status bar
                        Constraint::Min(5),    // Table
                        Constraint::Length(3), // Footer
                    ]
                    .as_ref(),
                )
                .split(size);

            // Status Bar colors
            let core_color = match state.core_status.as_str() {
                "RUNNING" => Color::Green,
                "NOT INSTALLED" => Color::DarkGray,
                _ => Color::Red,
            };

            let wd_color = match state.watchdog_status.as_str() {
                "RUNNING" => Color::Green,
                "NOT INSTALLED" => Color::DarkGray,
                _ => Color::Red,
            };

            let susp_color = match state.suspended_status.as_str() {
                "ACTIVE" => Color::Green,
                "SUSPENDED" => Color::Red,
                _ => Color::Yellow,
            };

            let feedback_span = if let Some((msg, is_ok)) = &state.feedback_message {
                let color = if *is_ok { Color::Green } else { Color::Red };
                ratatui::text::Span::styled(format!("   [ {} ]", msg), Style::default().fg(color).add_modifier(Modifier::BOLD))
            } else {
                ratatui::text::Span::raw("")
            };

            let core_status_ru = translate_status(&state.core_status);
            let watchdog_status_ru = translate_status(&state.watchdog_status);
            let suspended_status_ru = translate_status(&state.suspended_status);

            let status_paragraph = Paragraph::new(vec![
                ratatui::text::Line::from(vec![
                    ratatui::text::Span::raw(" Служба Ядра: "),
                    ratatui::text::Span::styled(core_status_ru, Style::default().fg(core_color).add_modifier(Modifier::BOLD)),
                    ratatui::text::Span::raw("   |   Служба Контроля (Watchdog): "),
                    ratatui::text::Span::styled(watchdog_status_ru, Style::default().fg(wd_color).add_modifier(Modifier::BOLD)),
                    ratatui::text::Span::raw("   |   Режим защиты: "),
                    ratatui::text::Span::styled(suspended_status_ru, Style::default().fg(susp_color).add_modifier(Modifier::BOLD)),
                    feedback_span,
                ]),
                ratatui::text::Line::from(format!(
                    " Журнал событий: C:\\ProgramData\\MonitoringControl\\events.jsonl ({:.1} КБ)",
                    state.file_offset as f64 / 1024.0
                )),
            ])
            .block(Block::default().title(" Состояние системы мониторинга OKO ").borders(Borders::ALL));
            
            f.render_widget(status_paragraph, chunks[0]);

            // Table
            let header_cells = ["Время", "Уровень", "Категория", "Событие"]
                .iter()
                .map(|h| ratatui::text::Span::styled(*h, Style::default().add_modifier(Modifier::BOLD)));
            let header = Row::new(header_cells)
                .style(Style::default().bg(Color::DarkGray))
                .height(1);

            let rows = state.events.iter().map(|event| {
                let level_color = match event.level.as_str() {
                    "ERROR" | "FATAL" => Color::Red,
                    "WARN" => Color::Yellow,
                    "INFO" => Color::Green,
                    _ => Color::White,
                };
                let level_ru = match event.level.as_str() {
                    "ERROR" | "FATAL" => "ОШИБКА",
                    "WARN" => "ПРЕДУПР",
                    "INFO" => "ИНФО",
                    _ => &event.level,
                };

                let category = event.fields.category.clone().unwrap_or_else(|| "default".to_string());
                let message = event.fields.message.clone().unwrap_or_else(|| "".to_string());
                let (category_ru, message_ru) = translate_event(&category, &message);

                Row::new(vec![
                    ratatui::text::Span::raw(format_timestamp(&event.timestamp)),
                    ratatui::text::Span::styled(level_ru, Style::default().fg(level_color).add_modifier(Modifier::BOLD)),
                    ratatui::text::Span::styled(category_ru, Style::default().fg(Color::Cyan)),
                    ratatui::text::Span::raw(message_ru),
                ])
            });

            let table = Table::new(
                rows,
                [
                    Constraint::Length(10), // Timestamp
                    Constraint::Length(10), // Level
                    Constraint::Length(20), // Category
                    Constraint::Min(20),    // Message
                ]
            )
            .header(header)
            .block(Block::default().title(" Журнал событий ").borders(Borders::ALL));

            f.render_widget(table, chunks[1]);

            // Footer
            let footer = Paragraph::new("Клавиши: [1] ПРИОСТАНОВИТЬ ЗАЩИТУ | [2] АКТИВИРОВАТЬ | [3] БЛОКИРОВАТЬ | [4] РАЗБЛОКИРОВАТЬ | [Q] Выйти")
                .block(Block::default().borders(Borders::ALL));
            f.render_widget(footer, chunks[2]);

            // Input Popup Dialog if prompting
            if state.input_mode != InputMode::Normal {
                let (prompt_title, prompt_label, input_to_display) = match state.input_mode {
                    InputMode::PromptingSuspend => (
                        " ДЕЙСТВИЕ: ПРИОСТАНОВКА ЗАЩИТЫ ",
                        "Введите Мастер-Пароль для подтверждения приостановки защиты:".to_string(),
                        "*".repeat(state.password_input.len()),
                    ),
                    InputMode::PromptingResume => (
                        " ДЕЙСТВИЕ: АКТИВАЦИЯ ЗАЩИТЫ ",
                        "Введите Мастер-Пароль для подтверждения активации защиты:".to_string(),
                        "*".repeat(state.password_input.len()),
                    ),
                    InputMode::PromptingAddBlockName => (
                        " ДЕЙСТВИЕ: БЛОКИРОВКА ПРОЦЕССА ",
                        "Введите имя исполняемого файла для блокировки (например, game.exe):".to_string(),
                        state.process_input.clone(),
                    ),
                    InputMode::PromptingAddBlockPassword => (
                        " ДЕЙСТВИЕ: БЛОКИРОВКА ПРОЦЕССА ",
                        format!("Блокировка '{}'. Введите Мастер-Пароль:", state.process_input),
                        "*".repeat(state.password_input.len()),
                    ),
                    InputMode::PromptingRemoveBlockName => (
                        " ДЕЙСТВИЕ: СНЯТИЕ БЛОКИРОВКИ ",
                        "Введите имя исполняемого файла для разблокировки (например, game.exe):".to_string(),
                        state.process_input.clone(),
                    ),
                    InputMode::PromptingRemoveBlockPassword => (
                        " ДЕЙСТВИЕ: СНЯТИЕ БЛОКИРОВКИ ",
                        format!("Разблокировка '{}'. Введите Мастер-Пароль:", state.process_input),
                        "*".repeat(state.password_input.len()),
                    ),
                    InputMode::Normal => unreachable!(),
                };

                let popup_area = centered_rect(60, 25, size);
                f.render_widget(Clear, popup_area); // Clear background behind popup

                let popup_text = vec![
                    ratatui::text::Line::from(prompt_label),
                    ratatui::text::Line::from(vec![
                        ratatui::text::Span::raw(" > "),
                        ratatui::text::Span::styled(input_to_display, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                    ]),
                    ratatui::text::Line::from(""),
                    ratatui::text::Line::from(vec![
                        ratatui::text::Span::styled(" [ Enter ] ", Style::default().bg(Color::White).fg(Color::Black)),
                        ratatui::text::Span::raw(" Подтвердить   "),
                        ratatui::text::Span::styled(" [ Esc ] ", Style::default().bg(Color::White).fg(Color::Black)),
                        ratatui::text::Span::raw(" Отмена"),
                    ]),
                ];

                let popup_paragraph = Paragraph::new(popup_text)
                    .block(Block::default().title(prompt_title).borders(Borders::ALL).border_style(Style::default().fg(Color::Yellow)))
                    .alignment(ratatui::layout::Alignment::Center);

                f.render_widget(popup_paragraph, popup_area);
            }
        })?;
    }

    // Restore terminal
    disable_raw_mode()?;
    crossterm::execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
