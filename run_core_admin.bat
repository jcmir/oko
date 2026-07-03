@echo off
echo =======================================================
echo Запуск Core Service (Ядра)
echo ВНИМАНИЕ: Запускать строго от имени Администратора!
echo =======================================================

cd /d "%~dp0"

IF NOT EXIST "target\debug\core-service.exe" (
    echo [ERROR] Скомпилированный файл Ядра не найден. 
    echo Пожалуйста, выполните команду: cargo build
    pause
    exit /b 1
)

echo Запуск core-service.exe...
target\debug\core-service.exe
pause
