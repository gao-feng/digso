:: 用途:
:: - 调用 list_zero_delta_filepss.ps1，从 compare 目录里找出 DeltaPssKB=0 的库，再去普通内存目录里查这些库的 FilePssKB。
:: 参数:
:: - 第一个参数是 compare 目录，第二个参数是普通内存目录；如果不传则会提示输入。
@echo off
setlocal EnableDelayedExpansion

set "SCRIPT_DIR=%~dp0"
set "PY_SCRIPT=%SCRIPT_DIR%digso.py"

if not exist "%PY_SCRIPT%" (
  echo digso.py not found: %PY_SCRIPT%
  exit /b 1
)

if "%~1"=="" (
  set /p COMPARE_DIR=Please enter compare directory: 
  if "!COMPARE_DIR!"=="" (
    echo Compare directory not provided.
    exit /b 1
  )
  set "ARG1=!COMPARE_DIR!"
) else (
  set "ARG1=%~1"
)

if "%~2"=="" (
  set /p MEMORY_DIR=Please enter memory directory: 
  if "!MEMORY_DIR!"=="" (
    echo Memory directory not provided.
    exit /b 1
  )
  set "ARG2=!MEMORY_DIR!"
) else (
  set "ARG2=%~2"
)

python "%PY_SCRIPT%" list-zero-delta-filepss "%ARG1%" "%ARG2%"

exit /b %errorlevel%
