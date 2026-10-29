@echo off
cd /d "%~dp0"
if exist "%~dp0Simplify3D-CN.exe" (
    start "" "%~dp0Simplify3D-CN.exe" --zh
    exit /b 0
)
where pythonw >nul 2>&1
if %errorlevel%==0 (
    start "" pythonw "%~dp0launch_zh.py" --zh
) else (
    python "%~dp0launch_zh.py" --zh
    if errorlevel 1 pause
)
