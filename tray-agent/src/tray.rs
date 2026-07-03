use tray_icon::{
    menu::{Menu, MenuItem, PredefinedMenuItem, MenuId},
    TrayIcon, TrayIconBuilder, Icon,
};

pub struct SystemTray {
    _tray_icon: TrayIcon,
    status_item: MenuItem,
    suspend_id: MenuId,
    resume_id: MenuId,
    quit_id: MenuId,
}

impl SystemTray {
    pub fn new(machine_id: &str) -> Self {
        let menu = Menu::new();
        
        let status_item = MenuItem::new("Статус: Подключение...", false, None);
        let machine_item = MenuItem::new(format!("ID Машины: {}", machine_id), false, None);
        
        let suspend_item = MenuItem::new("Приостановить защиту", true, None);
        let resume_item = MenuItem::new("Возобновить защиту", true, None);
        let quit_item = MenuItem::new("Выйти", true, None);
        
        let suspend_id = suspend_item.id().clone();
        let resume_id = resume_item.id().clone();
        let quit_id = quit_item.id().clone();
        
        menu.append_items(&[
            &status_item,
            &machine_item,
            &PredefinedMenuItem::separator(),
            &suspend_item,
            &resume_item,
            &PredefinedMenuItem::separator(),
            &quit_item,
        ]).unwrap();
        
        let initial_icon = Self::create_colored_icon(230, 50, 50); // Red / disconnected
        
        let tray_icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("Система защиты OKO")
            .with_icon(initial_icon)
            .build()
            .unwrap();
            
        Self {
            _tray_icon: tray_icon,
            status_item,
            suspend_id,
            resume_id,
            quit_id,
        }
    }
    
    pub fn update_status(&self, status: crate::client::SystemStatus) {
        use crate::client::SystemStatus;
        
        let text = format!("Статус: {}", status.to_string_ru());
        let _ = self.status_item.set_text(&text);
        
        let icon = match status {
            SystemStatus::Active => Self::create_colored_icon(0, 200, 80),      // Green
            SystemStatus::Suspended => Self::create_colored_icon(240, 190, 0),  // Yellow
            SystemStatus::Disconnected => Self::create_colored_icon(230, 50, 50), // Red
        };
        let _ = self._tray_icon.set_icon(Some(icon));
    }
    
    pub fn is_suspend_click(&self, id: &MenuId) -> bool {
        *id == self.suspend_id
    }
    
    pub fn is_resume_click(&self, id: &MenuId) -> bool {
        *id == self.resume_id
    }
    
    pub fn is_quit_click(&self, id: &MenuId) -> bool {
        *id == self.quit_id
    }

    fn create_colored_icon(r: u8, g: u8, b: u8) -> Icon {
        let width = 16;
        let height = 16;
        let mut rgba = vec![0u8; width * height * 4];
        
        for y in 0..height {
            for x in 0..width {
                let dx = (x as f32) - 7.5;
                let dy = (y as f32) - 7.5;
                let dist = (dx * dx + dy * dy).sqrt();
                
                let idx = (y * width + x) * 4;
                if dist <= 6.5 {
                    // Inside circle
                    rgba[idx] = r;
                    rgba[idx + 1] = g;
                    rgba[idx + 2] = b;
                    rgba[idx + 3] = 255;
                } else if dist <= 7.5 {
                    // Anti-aliased border
                    let alpha = ((7.5 - dist) * 255.0).clamp(0.0, 255.0) as u8;
                    rgba[idx] = r;
                    rgba[idx + 1] = g;
                    rgba[idx + 2] = b;
                    rgba[idx + 3] = alpha;
                } else {
                    // Transparent
                    rgba[idx] = 0;
                    rgba[idx + 1] = 0;
                    rgba[idx + 2] = 0;
                    rgba[idx + 3] = 0;
                }
            }
        }
        
        Icon::from_rgba(rgba, width as u32, height as u32).unwrap()
    }
}
