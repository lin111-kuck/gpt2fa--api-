@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" python -m venv .venv
if not exist ".venv\Scripts\python.exe" exit /b 1
".venv\Scripts\python.exe" -m pip install -r requirements-local.txt
if errorlevel 1 exit /b 1
node --version
if errorlevel 1 (
    echo Install Node.js, then restart the workbench.
    exit /b 1
)
echo Local protocol login is ready. Run start_gui.cmd.
pause
