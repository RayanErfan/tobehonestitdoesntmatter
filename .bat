@echo off
setlocal

:: Define Python version and installation URL
set PY_VERSION=3.11.0
set PY_DIR=%LocalAppData%\Programs\Python\Python311
set INSTALLER_URL=https://www.python.org/ftp/python/%PY_VERSION%/python-%PY_VERSION%-amd64.exe
set INSTALLER=python-installer.exe

:: Check if Python is installed (basic check using where)
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo Python not found. Installing Python %PY_VERSION%...

    :: Download the installer
    powershell -Command "Invoke-WebRequest -Uri '%INSTALLER_URL%' -OutFile '%INSTALLER%'"

    :: Install Python silently and add to PATH
    start /wait "" %INSTALLER% /quiet InstallAllUsers=1 PrependPath=1 Include_pip=1

    :: Clean up installer
    del /f /q %INSTALLER%
) else (
    echo Python found!
)

:: Confirm pip is available
where pip >nul 2>&1
if %errorlevel% neq 0 (
    echo pip not found. Exiting...
    exit /b 1
)

:: Install required Python packages
echo Installing required packages...
pip install Flask Werkzeug cryptography PyJWT psutil

:: Change directory to the project
cd /d C:\project

:: Start your script in the background minimized
start /B /MIN "" pythonw myscript.py

exit
