@echo off
title GoodbyeDPI Turkey - Stop
echo Stopping GoodbyeDPI...
taskkill /F /IM goodbyedpi.exe >nul 2>&1
echo Done.
timeout /t 2
