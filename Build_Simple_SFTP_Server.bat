@echo off
REM ============================================================
REM Build script for Simple SFTP Server - standalone Windows app
REM Author: JDE-Projects
REM ============================================================
REM Installs the pinned deps from requirements.txt (pywebview + PySide6,
REM paramiko + crypto stack), then builds a standalone --onedir app. The
REM resulting dist\ folder runs on any Windows PC with no Python or other
REM software installed.
REM
REM Qt binding: PySide6 (LGPL), NOT PyQt6 (GPL). QT_API=pyside6 makes any
REM qtpy import bind PySide6. --onedir keeps the bundled LGPL Qt replaceable.
REM ============================================================
cd /d "%~dp0"

REM --- skip interactive pauses when running in CI (GitHub Actions sets CI) ---
set "PAUSE=pause"
if defined CI set "PAUSE="

REM --- force the LGPL Qt binding for any qtpy import during the build ---
set QT_API=pyside6

echo.
echo ============================================================
echo   Simple SFTP Server - Standalone App Builder
echo ============================================================
echo.

REM --- check Python ---
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH.
    echo Install Python 3 from https://python.org and tick "Add Python to PATH".
    %PAUSE%
    exit /b 1
)

echo [1/3] Installing pinned dependencies from requirements.txt ...
python -m pip install --upgrade pip >nul
python -m pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: Failed to install dependencies from requirements.txt.
    %PAUSE%
    exit /b 1
)

REM --- clean previous output for a fresh build ---
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist "Simple SFTP Server.spec" del /q "Simple SFTP Server.spec"

echo [2/3] Building standalone app (--onedir) ... this may take a few minutes.
python -m PyInstaller --noconfirm --onedir --windowed --name "Simple SFTP Server" ^
    --icon "simple_sftp_server.ico" ^
    --splash "simple_sftp_server-splash.png" ^
    --add-data "simple_sftp_server-UI.html;." ^
    --add-data "simple_sftp_server.png;." ^
    --add-data "fonts;fonts" ^
    --collect-all PySide6 ^
    --collect-all qtpy ^
    --collect-all webview ^
    simple_sftp_server.py
if errorlevel 1 (
    echo ERROR: Build failed. Read the last lines above for the cause.
    %PAUSE%
    exit /b 1
)

echo [3/3] Done.
echo.
echo ============================================================
echo   BUILD SUCCESSFUL!
echo ============================================================
echo.
echo   dist\Simple SFTP Server\Simple SFTP Server.exe
echo.
echo Distribute the WHOLE "Simple SFTP Server" folder (zip it).
echo ============================================================
echo.
%PAUSE%
