:: 用途:
:: - 调用 compare_so_snapshots.ps1，比较两个抓取目录中动态库物理内存占用的变化。
:: 参数:
:: - 第一个参数是 BEFORE 目录，第二个参数是 AFTER 目录；如果不传则会提示输入。
@echo off
setlocal EnableDelayedExpansion

set "SCRIPT_DIR=%~dp0"
set "PS_SCRIPT=%SCRIPT_DIR%compare_so_snapshots.ps1"

if not exist "%PS_SCRIPT%" (
  echo compare_so_snapshots.ps1 not found: %PS_SCRIPT%
  exit /b 1
)

if "%~1"=="" (
  set /p BEFORE_DIR=Please enter BEFORE snapshot directory: 
  if "!BEFORE_DIR!"=="" (
    echo BEFORE snapshot directory not provided.
    exit /b 1
  )
  set "ARG1=!BEFORE_DIR!"
) else (
  set "ARG1=%~1"
)

if "%~2"=="" (
  set /p AFTER_DIR=Please enter AFTER snapshot directory: 
  if "!AFTER_DIR!"=="" (
    echo AFTER snapshot directory not provided.
    exit /b 1
  )
  set "ARG2=!AFTER_DIR!"
) else (
  set "ARG2=%~2"
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%" "%ARG1%" "%ARG2%"

exit /b %errorlevel%
