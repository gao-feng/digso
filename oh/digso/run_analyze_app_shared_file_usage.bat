:: 用途:
:: - 调用 analyze_app_shared_file_usage.ps1，从单个 PID 出发分析其使用的库/文件，以及系统中哪些进程也在共享这些文件页。
:: 参数:
:: - 第一个参数是目标 PID；如果不传则会提示输入。
@echo off
setlocal EnableDelayedExpansion

set "SCRIPT_DIR=%~dp0"
set "PY_SCRIPT=%SCRIPT_DIR%digso.py"

if not exist "%PY_SCRIPT%" (
  echo digso.py not found: %PY_SCRIPT%
  exit /b 1
)

if "%~1"=="" (
  set /p USER_PID=Please enter PID: 
  if "!USER_PID!"=="" (
    echo PID not provided.
    exit /b 1
  )
  set "TARGET_PID=!USER_PID!"
) else (
  set "TARGET_PID=%~1"
)

python "%PY_SCRIPT%" analyze-app-shared-file-usage %TARGET_PID%

exit /b %errorlevel%
