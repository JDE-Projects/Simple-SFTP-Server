@echo off
echo =====================================================
echo  Simple SFTP Server - Build Script
echo =====================================================
echo.
echo Ensuring PySide6 is the bundled Qt binding (not PyQt6)...
set QT_API=pyside6
pip uninstall -y PyQt6 PyQt6-WebEngine >nul 2>&1
echo.
echo Installing build + runtime dependencies...
pip install pyinstaller pywebview PySide6 paramiko
echo.
echo Building executable...
pyinstaller --onefile --windowed --name "Simple SFTP Server" ^
  --icon "simple_sftp_server.ico" ^
  --splash "simple_sftp_server-splash.png" ^
  --add-data "simple_sftp_server-UI.html;." ^
  --add-data "simple_sftp_server.png;." ^
  --add-data "fonts;fonts" ^
  --collect-all PySide6 ^
  --collect-all qtpy ^
  simple_sftp_server.py
echo.
echo =====================================================
echo  Done. Your build is in:  dist\Simple SFTP Server.exe
echo  Run it, then keep server_config.json and the host
echo  key file beside it (both are created on first run).
echo =====================================================
echo.
pause
