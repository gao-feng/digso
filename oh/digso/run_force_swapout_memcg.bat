:: 用途:
:: - 调用 force_swapout_memcg.ps1，根据 PID 解析进程名和 UID，并执行 memcg 强制 shrink/swapout/reclaim 命令。
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

python "%PY_SCRIPT%" force-swapout-memcg %TARGET_PID%

exit /b %errorlevel%
