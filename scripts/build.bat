@echo off
setlocal
REM GenCert Windows 单平台构建脚本（PowerShell 不可用时兜底）

set "SCRIPT_DIR=%~dp0"
pushd "%SCRIPT_DIR%.." >nul

REM 版本信息
for /f "delims=" %%v in ('go run ./scripts/version') do set "VERSION=%%v"
if not defined VERSION set "VERSION=dev"
for /f "delims=" %%h in ('git rev-parse --short HEAD 2^>nul') do set "COMMIT_HASH=%%h"
if not defined COMMIT_HASH set "COMMIT_HASH=unknown"
where powershell >nul 2>&1
if %ERRORLEVEL%==0 (
  for /f "delims=" %%t in ('powershell -NoProfile -Command "Get-Date -Format ''yyyy-MM-dd_HH:mm:ss''"') do set "BUILD_TIME=%%t"
) else (
  set "BUILD_TIME=%date:~0,4%-%date:~5,2%-%date:~8,2%_%time:~0,2%:%time:~3,2%:%time:~6,2%"
  set "BUILD_TIME=%BUILD_TIME: =0%"
)

REM 识别架构
set "ARCH=amd64"
if /I "%PROCESSOR_ARCHITECTURE%"=="ARM64" set "ARCH=arm64"
if /I "%PROCESSOR_ARCHITECTURE%"=="x86" set "ARCH=386"

set "OUTPUT_DIR=bin"
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

echo GenCert 单平台构建
echo 版本: %VERSION%
echo 构建时间: %BUILD_TIME%
echo 提交哈希: %COMMIT_HASH%
echo 目标: windows/%ARCH%
echo =====================

set "GOOS=windows"
set "GOARCH=%ARCH%"
set "CGO_ENABLED=0"

set "OUT=%OUTPUT_DIR%\gencert-windows-%ARCH%.exe"
go build -ldflags="-X github.com/formzs/gencert/internal/version.Version=%VERSION% -X github.com/formzs/gencert/internal/version.BuildTime=%BUILD_TIME% -X github.com/formzs/gencert/internal/version.CommitHash=%COMMIT_HASH%" -o "%OUT%" ./cmd/gencert
if errorlevel 1 (
  echo 构建失败
  popd >nul & exit /b 1
)

echo ✓ 构建完成: %OUT%
popd >nul & exit /b 0

