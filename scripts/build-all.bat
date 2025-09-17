@echo off
setlocal
where powershell >nul 2>&1
if %ERRORLEVEL%==0 (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build-all.ps1"
  exit /b %ERRORLEVEL%
)
echo PowerShell is required to run scripts\build-all.ps1 for cross-platform build.
echo Falling back to single-platform build...
call "%~dp0build.bat"
exit /b %ERRORLEVEL%

