@echo off
cd /d "%~dp0"
if exist "%~dp0Simplify3D-语言.exe" (
    start "" "%~dp0Simplify3D-语言.exe"
    exit /b 0
)
where pythonw >nul 2>&1
if %errorlevel%==0 (
    start "" pythonw "%~dp0launch_zh.py"
) else (
    python "%~dp0launch_zh.py"
    if errorlevel 1 pause
)
