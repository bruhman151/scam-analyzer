@echo off
setlocal
cd /d "%~dp0"
set "PYTHON_EXE=%LOCALAPPDATA%\Python\bin\python.exe"
if not exist "%PYTHON_EXE%" set "PYTHON_EXE=python"
"%PYTHON_EXE%" -c "import flask" >nul 2>&1
if errorlevel 1 (
  echo Python or Flask is not ready. See README.md for setup.
  pause
  exit /b 1
)
echo Open http://127.0.0.1:5000 in your browser.
echo Press Ctrl+C in this window to stop the service.
"%PYTHON_EXE%" app.py

