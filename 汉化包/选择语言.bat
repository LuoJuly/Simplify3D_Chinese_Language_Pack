@echo off
cd /d "%~dp0"
if exist "%~dp0Simplify3D-CN.exe" (
    start "" "%~dp0Simplify3D-CN.exe" --choose
    exit /b 0
)
where pythonw >nul 2>&1
if %errorlevel%==0 (
    start "" pythonw "%~dp0launch_zh.py" --choose
) else (
    python "%~dp0launch_zh.py" --choose
    if errorlevel 1 pause
)
