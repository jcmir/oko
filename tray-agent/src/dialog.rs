use std::ptr::null_mut;
use widestring::U16CString;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::UI::WindowsAndMessaging::*;
use windows_sys::Win32::Graphics::Gdi::{GetStockObject, DEFAULT_GUI_FONT, HBRUSH};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

const SS_LEFT: u32 = 0x00000000;
const COLOR_BTNFACE: u32 = 15;
const ES_PASSWORD: u32 = 0x0020;
const ES_AUTOHSCROLL: u32 = 0x0080;
const BS_DEFPUSHBUTTON: u32 = 0x0001;
const BS_PUSHBUTTON: u32 = 0x0000;

extern "system" {
    pub fn SetFocus(hwnd: HWND) -> HWND;
    pub fn UpdateWindow(hwnd: HWND) -> BOOL;
}

static mut PASSWORD_RESULT: Option<String> = None;
static mut IS_CONFIRMED: bool = false;

unsafe extern "system" fn dialog_window_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_CREATE => {
            let hinstance = GetWindowLongPtrW(hwnd, GWLP_HINSTANCE) as HINSTANCE;
            let hfont = GetStockObject(DEFAULT_GUI_FONT as i32) as WPARAM;

            // Static prompt
            let static_hwnd = CreateWindowExW(
                0,
                U16CString::from_str("STATIC").unwrap().as_ptr(),
                null_mut(),
                WS_CHILD | WS_VISIBLE | SS_LEFT,
                20, 20, 310, 20,
                hwnd,
                100,
                hinstance,
                null_mut(),
            );
            SendMessageW(static_hwnd, WM_SETFONT, hfont, 1);
            
            // Edit control (password field)
            let edit_hwnd = CreateWindowExW(
                WS_EX_CLIENTEDGE,
                U16CString::from_str("EDIT").unwrap().as_ptr(),
                null_mut(),
                WS_CHILD | WS_VISIBLE | ES_PASSWORD | ES_AUTOHSCROLL,
                20, 45, 310, 24,
                hwnd,
                101,
                hinstance,
                null_mut(),
            );
            SendMessageW(edit_hwnd, WM_SETFONT, hfont, 1);
            
            // OK button
            let ok_hwnd = CreateWindowExW(
                0,
                U16CString::from_str("BUTTON").unwrap().as_ptr(),
                U16CString::from_str("Подтвердить").unwrap().as_ptr(),
                WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                120, 85, 100, 28,
                hwnd,
                1, // ID_OK
                hinstance,
                null_mut(),
            );
            SendMessageW(ok_hwnd, WM_SETFONT, hfont, 1);
            
            // Cancel button
            let cancel_hwnd = CreateWindowExW(
                0,
                U16CString::from_str("BUTTON").unwrap().as_ptr(),
                U16CString::from_str("Отмена").unwrap().as_ptr(),
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                230, 85, 100, 28,
                hwnd,
                2, // ID_CANCEL
                hinstance,
                null_mut(),
            );
            SendMessageW(cancel_hwnd, WM_SETFONT, hfont, 1);
        }
        WM_COMMAND => {
            let id = wparam as u16;
            if id == 1 {
                // OK clicked
                let edit_hwnd = GetDlgItem(hwnd, 101);
                let mut buffer = vec![0u16; 256];
                let len = GetWindowTextW(edit_hwnd, buffer.as_mut_ptr(), 256);
                if len > 0 {
                    buffer.truncate(len as usize);
                    if let Ok(pwd) = String::from_utf16(&buffer) {
                        PASSWORD_RESULT = Some(pwd);
                        IS_CONFIRMED = true;
                    }
                } else {
                    PASSWORD_RESULT = Some(String::new());
                    IS_CONFIRMED = true;
                }
                DestroyWindow(hwnd);
            } else if id == 2 {
                // Cancel clicked
                DestroyWindow(hwnd);
            }
        }
        WM_CLOSE => {
            DestroyWindow(hwnd);
        }
        WM_DESTROY => {
            PostQuitMessage(0);
        }
        _ => return DefWindowProcW(hwnd, msg, wparam, lparam),
    }
    0
}

pub fn show_password_dialog(title: &str, prompt: &str) -> Option<String> {
    unsafe {
        PASSWORD_RESULT = None;
        IS_CONFIRMED = false;
        
        let hinstance = GetModuleHandleW(null_mut());
        
        let class_name = U16CString::from_str("OkoPasswordDialogClass").unwrap();
        let wnd_class = WNDCLASSW {
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(dialog_window_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: hinstance,
            hIcon: 0,
            hCursor: LoadCursorW(0, IDC_ARROW),
            hbrBackground: (COLOR_BTNFACE + 1) as HBRUSH,
            lpszMenuName: null_mut(),
            lpszClassName: class_name.as_ptr(),
        };
        
        RegisterClassW(&wnd_class);
        
        // Calculate centered position on screen
        let screen_width = GetSystemMetrics(SM_CXSCREEN);
        let screen_height = GetSystemMetrics(SM_CYSCREEN);
        let width = 366;
        let height = 160;
        let x = (screen_width - width) / 2;
        let y = (screen_height - height) / 2;
        
        let hwnd = CreateWindowExW(
            WS_EX_DLGMODALFRAME | WS_EX_TOPMOST,
            class_name.as_ptr(),
            U16CString::from_str(title).unwrap().as_ptr(),
            WS_POPUPWINDOW | WS_CAPTION | WS_VISIBLE,
            x, y, width, height,
            0,
            0,
            hinstance,
            null_mut(),
        );
        
        if hwnd == 0 {
            return None;
        }
        
        // Set prompt text
        let prompt_hwnd = GetDlgItem(hwnd, 100);
        SetWindowTextW(prompt_hwnd, U16CString::from_str(prompt).unwrap().as_ptr());
        
        // Focus the edit control
        let edit_hwnd = GetDlgItem(hwnd, 101);
        SetFocus(edit_hwnd);
        
        // Show and update
        ShowWindow(hwnd, SW_SHOW);
        UpdateWindow(hwnd);
        
        // Message loop
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, 0, 0, 0) != 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        
        if IS_CONFIRMED {
            PASSWORD_RESULT.clone()
        } else {
            None
        }
    }
}
