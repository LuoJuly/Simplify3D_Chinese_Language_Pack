@echo off
cd /d "%~dp0"
where pythonw >nul 2>&1
if %errorlevel%==0 (
    start "" pythonw "%~dp0launch_zh.py"
) else (
    python "%~dp0launch_zh.py"
    if errorlevel 1 pause
)
