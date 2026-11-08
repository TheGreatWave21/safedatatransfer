@echo off
rem sdt launcher: needs only Python. Everything else goes into .\.venv (nothing system-wide).
rem   sdt              -> interactive UI
rem   sdt usb list     -> any CLI command
setlocal
set "ROOT=%~dp0"
set "VENV=%ROOT%.venv"
set "PY=%VENV%\Scripts\python.exe"

if exist "%PY%" goto :check

echo [sdt] First run: creating a private Python environment in .venv ...
where py >nul 2>nul
if %errorlevel%==0 (
    py -3 -I -m venv "%VENV%"
) else (
    python -I -m venv "%VENV%"
)
if not exist "%PY%" goto :nopython

:check
"%PY%" -I -c "import sys; sys.exit(sys.version_info < (3, 11))" >nul 2>nul
if errorlevel 1 goto :oldpython
"%PY%" -I -c "import importlib.util as u, sys; sys.exit(any(u.find_spec(m) is None for m in ('safedatatransfer', 'textual', 'cryptography', 'spake2')))" >nul 2>nul
if %errorlevel%==0 goto :run

echo [sdt] Installing dependencies into .venv only ...
rem Exact versions from constraints.txt; wheels only, so no third-party build scripts run.
"%PY%" -I -m pip install --disable-pip-version-check --quiet --only-binary=:all: -c "%ROOT%constraints.txt" -e "%ROOT%."
if errorlevel 1 (
    echo [sdt] Installing dependencies failed. Check your internet connection and try again.
    exit /b 1
)

:run
"%PY%" -I -m safedatatransfer %*
exit /b %errorlevel%

:oldpython
echo [sdt] .venv was made with a Python older than 3.11. Install a newer Python, delete
echo       the .venv folder, and start sdt again.
exit /b 1

:nopython
echo [sdt] Python 3.11 or newer is needed and was not found.
echo       Install it from https://www.python.org/downloads/  or run:  winget install Python.Python.3.13
exit /b 1
