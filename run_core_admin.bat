@echo off
echo =======================================================
echo Запуск Core Service (Ядра)
echo ВНИМАНИЕ: Запускать строго от имени Администратора!
echo =======================================================

cd /d "%~dp0"

IF NOT EXIST "target\x86_64-pc-windows-gnu\debug\core-service.exe" (
    echo [ERROR] Скомпилированный файл Ядра не найден. 
    echo Пожалуйста, выполните cargo build --target x86_64-pc-windows-gnu
    pause
    exit /b 1
)

echo Запуск core-service.exe...
target\x86_64-pc-windows-gnu\debug\core-service.exe
pause
