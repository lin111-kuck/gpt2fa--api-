@echo off
setlocal
cd /d "%~dp0"
if exist "%~dp0.venv\Scripts\pythonw.exe" (
    start "" "%~dp0.venv\Scripts\pythonw.exe" -B "%~dp0batch_login_gui.py"
    exit /b
)
where pythonw.exe >nul 2>&1
if not errorlevel 1 (
    start "" pythonw.exe -B "%~dp0batch_login_gui.py"
    exit /b
)
where pyw.exe >nul 2>&1
if not errorlevel 1 (
    start "" pyw.exe -3 -B "%~dp0batch_login_gui.py"
    exit /b
)
echo Python 3 with Tkinter is required. Run: python batch_login_gui.py
pause
