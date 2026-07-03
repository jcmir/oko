@echo off
echo =======================================================
echo Запуск Tray Agent (Пользовательский интерфейс)
echo =======================================================

cd /d "%~dp0"

IF NOT EXIST "target\debug\tray-agent.exe" (
    echo [ERROR] Скомпилированный файл Трей-агента не найден. 
    echo Пожалуйста, выполните команду: cargo build
    pause
    exit /b 1
)

echo Запуск tray-agent.exe в фоновом режиме...
start "" "target\debug\tray-agent.exe"
exit
