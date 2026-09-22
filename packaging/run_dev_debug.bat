@echo off
rem ============================================================
rem  run_dev_debug.bat  --  带控制台的调试启动
rem
rem  与 run_dev.bat 的区别：保留黑窗，stdout/stderr 全部看得见。
rem  界面起不来 / 报错但没提示时，用这个跑，traceback 会直接打在窗口里。
rem ============================================================
setlocal
cd /d "%~dp0.."

set "PY=%~dp0..\.venv\Scripts\python.exe"
if not exist "%PY%" set "PY=python"

echo === 启动 帮帮AD域管理工具（调试模式，关掉本窗口即退出）===
echo.
"%PY%" "%~dp0..\src\main.py"
set "RC=%ERRORLEVEL%"
echo.
echo === 进程已退出，返回码 %RC% ===
echo    0  = 正常关闭
echo    非0 = 异常，往上翻看 traceback
echo.
pause
endlocal
