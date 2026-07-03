@echo off
echo ====================================================
echo   Starting Monitoring Control System (oko)
echo ====================================================

echo 1. Stopping existing instances...
taskkill /F /IM core-service.exe >nul 2>&1
taskkill /F /IM watchdog-utility.exe >nul 2>&1

echo 2. Starting Core Service (Background)...
start "" "%~dp0target\release\core-service.exe"

echo 3. Starting Watchdog Utility (Background)...
start "" "%~dp0target\release\watchdog-utility.exe"

echo 4. Launching Real-time TUI Monitor...
"%~dp0target\release\monitor-cli.exe"

echo ====================================================
echo   TUI Monitor Closed. Stopping background services...
echo ====================================================
taskkill /F /IM core-service.exe >nul 2>&1
taskkill /F /IM watchdog-utility.exe >nul 2>&1
echo Done.
