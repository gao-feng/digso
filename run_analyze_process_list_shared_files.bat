:: 用途:
:: - 调用 analyze_process_list_shared_files.ps1，从进程名列表文件出发分析这些进程使用的动态库，以及系统中哪些进程也在使用这些库。
:: 参数:
:: - 第一个参数是进程名列表文件路径；如果不传则会提示输入。
@echo off
setlocal EnableDelayedExpansion

set "SCRIPT_DIR=%~dp0"
set "PS_SCRIPT=%SCRIPT_DIR%analyze_process_list_shared_files.ps1"

if not exist "%PS_SCRIPT%" (
  echo analyze_process_list_shared_files.ps1 not found: %PS_SCRIPT%
  exit /b 1
)

if "%~1"=="" (
  set /p LIST_FILE=Please enter process-list file path: 
  if "!LIST_FILE!"=="" (
    echo Process-list file path not provided.
    exit /b 1
  )
  set "ARG1=!LIST_FILE!"
) else (
  set "ARG1=%~1"
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%" "%ARG1%"

exit /b %errorlevel%
