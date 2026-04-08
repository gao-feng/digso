:: 用途:
:: - 调用 analyze_app_maps.ps1，抓取指定进程的 maps/smaps/smaps_rollup/hidumper，并分析动态库物理内存占用。
:: 参数:
:: - 第一个参数可以是 PID，也可以是已经抓好的目录；如果不传则会提示输入。
@echo off
setlocal EnableDelayedExpansion

set "SCRIPT_DIR=%~dp0"
set "PY_SCRIPT=%SCRIPT_DIR%digso.py"

if not exist "%PY_SCRIPT%" (
  echo digso.py not found: %PY_SCRIPT%
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
  python "%PY_SCRIPT%" analyze-app-maps --source-dir "%ARG1%"
) else (
  python "%PY_SCRIPT%" analyze-app-maps --target-pid %ARG1%
)

exit /b %errorlevel%
