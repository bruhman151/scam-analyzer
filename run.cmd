@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Run setup.cmd first.
  exit /b 1
)
".venv\Scripts\python.exe" -c "import flask,waitress,PIL" >nul 2>&1
if errorlevel 1 (
  echo Dependencies missing. Run setup.cmd.
  exit /b 1
)
echo Open http://127.0.0.1:5000/ in your browser. Press Ctrl+C to stop.
".venv\Scripts\python.exe" app.py
