@echo off
setlocal

set REPO=QEDProtocol/psy-benchmark-verifier
set INSTALL_DIR=%USERPROFILE%\.psy
set VERSION=
set PSY_DATA_URL=https://psy-benchmark-round1-data.psy-protocol.xyz

if "%PROOF_ID%"=="" (
    echo [ERROR] PROOF_ID environment variable is required
    exit /b 1
)

:: Trim leading/trailing spaces (use PowerShell as CMD for /f may not work properly)
for /f "tokens=*" %%i in ('powershell -c "'%PROOF_ID%'.Trim()"') do set "PROOF_ID=%%i"

echo [DEBUG] PROOF_ID=[%PROOF_ID%]

echo [INFO] Installing psy_prover_cli from %REPO%
echo [INFO] Platform: windows/amd64

:: Get latest version
if "%VERSION%"=="" (
    echo [INFO] Fetching latest version...
    for /f "tokens=*" %%v in ('powershell -c "try { (Invoke-WebRequest -Uri 'https://api.github.com/repos/%REPO%/releases/latest' -UseBasicParsing).Content | ConvertFrom-Json | Select-Object -ExpandProperty tag_name } catch { Write-Output 'v1.0.0' }" 2^>nul') do set "VERSION=%%v"
)
if "%VERSION%"=="" set VERSION=v1.0.0
echo [INFO] Version: %VERSION%

:: Create install directory
if not exist "%INSTALL_DIR%" (
    echo [INFO] Creating: %INSTALL_DIR%
    mkdir "%INSTALL_DIR%" 2>nul
)

set FINAL_PATH=%INSTALL_DIR%\psy_prover_cli.exe

:: Check if already installed
if exist "%FINAL_PATH%" (
    echo [INFO] Binary already installed: %FINAL_PATH%
    echo [OK] Done!
    goto run_fetch_job
)

:: Download binary
set ASSET_NAME=psy_prover_cli_windows_x64.exe
set DOWNLOAD_URL=https://github.com/%REPO%/releases/download/%VERSION%/%ASSET_NAME%
set DOWNLOAD_PATH=%TEMP%\%ASSET_NAME%

echo [INFO] Downloading: %ASSET_NAME%
echo [DEBUG] URL: %DOWNLOAD_URL%

:: Remove existing temp file
if exist "%DOWNLOAD_PATH%" del "%DOWNLOAD_PATH%" >nul 2>&1

:: Try curl first, then powershell
powershell -c "try { Invoke-WebRequest -Uri '%DOWNLOAD_URL%' -OutFile '%DOWNLOAD_PATH%' -UseBasicParsing } catch { exit 1 }" >nul 2>&1
if not exist "%DOWNLOAD_PATH%" (
    echo [ERROR] Download failed - binary not found for windows/amd64
    exit /b 1
)

echo [OK] Downloaded: %DOWNLOAD_PATH%

:: Copy binary
if exist "%FINAL_PATH%" del "%FINAL_PATH%" >nul 2>&1
copy /Y "%DOWNLOAD_PATH%" "%FINAL_PATH%" >nul
if errorlevel 1 (
    echo [ERROR] Failed to copy binary to %FINAL_PATH%
    exit /b 1
)

:: Cleanup temp
del "%DOWNLOAD_PATH%" >nul 2>&1

echo [OK] Installed: %FINAL_PATH%
echo [OK] Done!

:run_fetch_job
set RUN_CMD=%FINAL_PATH% fetch-job -b "%PSY_DATA_URL%" -p "%PROOF_ID%"
echo [INFO] Running: %RUN_CMD%
%RUN_CMD%

endlocal
