@echo off
title GoodbyeDPI Turkey v2
cd /d "%~dp0"

:: Check for admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo.
echo ╔═══════════════════════════════════════════════════════╗
echo ║  GoodbyeDPI Turkey v2.0 - Rust Edition                ║
echo ║  Discord, YouTube ve diger siteleri ac                ║
echo ╚═══════════════════════════════════════════════════════╝
echo.

:: Check if executable exists
if not exist "target\release\goodbyedpi.exe" (
    echo [ERROR] goodbyedpi.exe bulunamadi!
    echo Once "cargo build --release" calistirin.
    pause
    exit /b 1
)

echo [*] GoodbyeDPI baslatiliyor...
echo [*] Durdurmak icin Ctrl+C basin
echo.

target\release\goodbyedpi.exe run --profile turkey

pause
