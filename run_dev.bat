@echo off
rem ============================================================
rem  run_dev.bat  --  开发期启动脚本（源码直跑，1~2 秒反馈）
rem
rem  改完代码直接双击本文件即可，不要用打包后的 exe 调试。
rem  详见 Obsidian: 07-迭代与打包策略
rem
rem  为什么这么啰嗦：
rem     pythonw.exe 会把**所有** stderr 吞掉。以前版本的 bat 直接
rem     start "" pythonw main.py，一旦依赖缺失或代码有语法错，
rem     表现就是「双击了，什么也没发生」—— 完全无从下手。
rem     所以这里先做三道自检，把错误显示在控制台里再退出。
rem ============================================================
setlocal
cd /d "%~dp0"

set "PY=%~dp0.venv\Scripts\python.exe"
set "PYW=%~dp0.venv\Scripts\pythonw.exe"

rem ---------- 自检 1：虚拟环境 ----------
if not exist "%PY%" (
    echo.
    echo [x] 找不到虚拟环境：%PY%
    echo.
    echo     先建环境再装依赖：
    echo         python -m venv .venv
    echo         .venv\Scripts\pip install -r requirements.txt
    echo.
    pause
    exit /b 1
)

rem ---------- 自检 2：依赖能否导入 ----------
"%PY%" -c "import PyQt6, ldap3, qdarktheme, win32api" 2>nul
if errorlevel 1 (
    echo.
    echo [x] 依赖导入失败，缺少下面某个包：
    echo         PyQt6 / ldap3 / pyqtdarktheme-fork / pywin32
    echo.
    echo     pip 会告诉你到底缺什么：
    "%PY%" -c "import PyQt6, ldap3, qdarktheme, win32api"
    echo.
    echo     修复：
    echo         .venv\Scripts\pip install -r requirements.txt
    echo.
    pause
    exit /b 1
)

rem ---------- 自检 3：语法 ----------
"%PY%" -m py_compile "%~dp0main.py" 2>nul
if errorlevel 1 (
    echo.
    echo [x] main.py 语法有错：
    echo.
    "%PY%" -m py_compile "%~dp0main.py"
    echo.
    pause
    exit /b 1
)

rem ---------- 启动 ----------
rem pythonw 启动，不留黑窗；崩溃会由 main.py 自己弹 QMessageBox
rem 并落一份启动失败日志
start "" "%PYW%" "%~dp0main.py"
endlocal
