@echo off
REM HTTP Request Smuggling Scanner - Local Runner with Ollama
REM Run this from the smuggler directory

echo.
echo ============================================================
echo HTTP Request Smuggling Scanner - Local Test with Ollama
echo ============================================================
echo.

REM Check if binary exists
if not exist "bin\smuggler.exe" (
    echo [!] Binary not found. Building...
    go build -o bin\smuggler.exe .\cmd\main.go
    if %ERRORLEVEL% neq 0 (
        echo [!] Build failed!
        exit /b 1
    )
)

echo [+] Scanner binary ready: bin\smuggler.exe
echo [+] Ollama models configured:
echo     - xploiter/pentester:latest (recommended)
echo     - WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest
echo     - deepseek-coder:1.3b
echo.

REM Get URL from command line or use default
if "%1"=="" (
    set TARGET=example.com
    set PORT=80
    set HTTPS=
    echo [*] No target specified. Using default: example.com
    echo.
    echo Usage: run.bat [url] [model]
    echo Example: run.bat "example.com" "xploiter/pentester:latest"
    echo.
) else (
    set TARGET=%1
    set PORT=443
    set HTTPS=-https -insecure
    echo [+] Target: %TARGET%
    echo.
)

REM Get model or use default
if "%2"=="" (
    set MODEL=xploiter/pentester:latest
) else (
    set MODEL=%2
)

echo [+] Using model: %MODEL%
echo.
echo ============================================================
echo Starting scan...
echo ============================================================
echo.

REM Run the scanner
bin\smuggler.exe ^
    -target %TARGET% ^
    -port %PORT% ^
    %HTTPS% ^
    -ai ^
    -ai-backend ollama ^
    -ollama-model "%MODEL%" ^
    -v

echo.
echo ============================================================
echo Scan complete!
echo ============================================================
