:: 用途:
:: - 调用 analyze_app_maps.ps1，抓取指定进程的 maps/smaps/smaps_rollup/hidumper，并分析动态库物理内存占用。
:: 参数:
:: - 第一个参数可以是 PID，也可以是已经抓好的目录；如果不传则会提示输入。
@echo off
setlocal EnableDelayedExpansion

set "SCRIPT_DIR=%~dp0"
set "PS_SCRIPT=%SCRIPT_DIR%analyze_app_maps.ps1"

if not exist "%PS_SCRIPT%" (
  echo analyze_app_maps.ps1 not found: %PS_SCRIPT%
  exit /b 1
)

if "%~1"=="" (
  set /p USER_INPUT=Please enter PID or SOURCE_DIR: 
  if "!USER_INPUT!"=="" (
    echo No PID or SOURCE_DIR provided.
    exit /b 1
  )
  set "ARG1=!USER_INPUT!"
) else (
  set "ARG1=%~1"
)

if exist "%ARG1%\\smaps" (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%" -SourceDir "%ARG1%"
) else (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%" -TargetPid %ARG1%
)

exit /b %errorlevel%
