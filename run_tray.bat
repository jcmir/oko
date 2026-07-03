@echo off
echo =======================================================
echo Запуск Tray Agent (Пользовательский интерфейс)
echo =======================================================

cd /d "%~dp0"

IF NOT EXIST "target\x86_64-pc-windows-gnu\debug\tray-agent.exe" (
    echo [ERROR] Скомпилированный файл Трей-агента не найден. 
    echo Пожалуйста, выполните cargo build --target x86_64-pc-windows-gnu
    pause
    exit /b 1
)

echo Запуск tray-agent.exe в фоновом режиме...
start "" "target\x86_64-pc-windows-gnu\debug\tray-agent.exe"
exit
