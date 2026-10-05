@echo off
setlocal
cd /d "%~dp0"
set "PYTHON_EXE=%LOCALAPPDATA%\Python\bin\python.exe"
if not exist "%PYTHON_EXE%" set "PYTHON_EXE=python"
"%PYTHON_EXE%" -c "import sys; assert sys.version_info >= (3,12)" >nul 2>&1
if errorlevel 1 (
  echo Install Python 3.12 or newer, then rerun setup.cmd.
  exit /b 1
)
if not exist ".venv\Scripts\python.exe" "%PYTHON_EXE%" -m venv .venv
if errorlevel 1 exit /b 1
".venv\Scripts\python.exe" -m pip install --no-cache-dir -r requirements-lock.txt
if errorlevel 1 (
  echo Dependency installation failed. Check network access and retry.
  exit /b 1
)
".venv\Scripts\python.exe" scripts\setup_ocr.py
if errorlevel 1 (
  echo Text and URL modes are ready. See README for OCR setup.
) else (
  echo All modes are ready.
)
echo Run run.cmd to start.
