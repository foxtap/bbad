@echo off
rem ============================================================
rem  build.bat  --  交付打包（给没装 Python 的机器用）
rem
rem  产物：dist\bbad\bbad.exe（onedir）/ dist\bbad.exe（onefile）
rem  规格文件：bbad.spec
rem
rem  开发期请用 run_dev.bat（源码直跑，1~2 秒），不要用本脚本。
rem
rem  用法：
rem      build.bat            出 onedir（默认，推荐：启动快，整体拷文件夹）
rem      build.bat onefile    出单文件（发邮件/网盘用，启动慢 3~6 秒）
rem ============================================================
setlocal
cd /d "%~dp0"

set "PY=%~dp0.venv\Scripts\python.exe"

rem ---------- 自检 1：虚拟环境 ----------
if not exist "%PY%" (
    echo.
    echo [x] 找不到虚拟环境：%PY%
    echo     先建环境：python -m venv .venv
    echo               .venv\Scripts\pip install -r requirements.txt
    echo.
    pause
    exit /b 1
)

rem ---------- 自检 2：依赖能否导入 ----------
"%PY%" -c "import PyQt6, ldap3, qdarktheme, win32api, Crypto" 2>nul
if errorlevel 1 (
    echo.
    echo [x] 依赖导入失败，缺下面某个包：
    echo         PyQt6 / ldap3 / pyqtdarktheme-fork / pywin32 / pycryptodome
    echo.
    "%PY%" -c "import PyQt6, ldap3, qdarktheme, win32api, Crypto"
    echo.
    echo     修复：.venv\Scripts\pip install -r requirements.txt
    echo.
    pause
    exit /b 1
)

rem ---------- 自检 3：PyInstaller ----------
"%PY%" -c "import PyInstaller" 2>nul
if errorlevel 1 (
    echo.
    echo [x] 没装 PyInstaller：
    echo         .venv\Scripts\pip install pyinstaller
    echo.
    pause
    exit /b 1
)

rem ---------- 自检 4：语法 ----------
"%PY%" -m compileall -q main.py 2>nul
if errorlevel 1 (
    echo.
    echo [x] main.py 语法有错，先修再打包：
    echo.
    "%PY%" -m compileall main.py
    echo.
    pause
    exit /b 1
)

rem ---------- 打包 ----------
if /i "%~1"=="onefile" (
    echo [i] 形态：单文件 onefile（启动 3~6 秒，用于发邮件/网盘/U盘）
    set "ADPKG_ONEFILE=1"
) else (
    echo [i] 形态：onedir（启动 1 秒内，用于自己用/内网整体拷文件夹）
    set "ADPKG_ONEFILE="
)

echo [i] 首次 30~60 秒；之后只重编译改动过的文件（所以别加 --clean）
"%PY%" -m PyInstaller --noconfirm --distpath dist --workpath build "bbad.spec"
if errorlevel 1 (
    echo.
    echo [x] 打包失败，看上面 PyInstaller 的输出
    echo.
    pause
    exit /b 1
)

rem ---------- 自检 5：产物是否真的存在 ----------
rem  PyInstaller 偶发"退出码 0 但没产物"，所以不许只看退出码
if /i "%~1"=="onefile" (
    set "OUT=dist\bbad.exe"
) else (
    set "OUT=dist\bbad\bbad.exe"
)

if not exist "%OUT%" (
    echo.
    echo [x] 打包命令没报错，但产物不存在：%OUT%
    echo     去看 build\bbad\warn-bbad.txt
    echo.
    pause
    exit /b 1
)

echo.
echo [√] 完成：%OUT%
echo.
echo     下一步（别跳过）：把产物拷到一台**没装 Python 的**机器上双击，
echo     确认能打开连接页、能进"演示模式"。自己这台机器跑得起来不算证据。
rem  注意：数据目录仍是「AD域管理工具」，**别跟着 bbad 改名** —— 见 bbad.spec 里的说明。
echo     日志：%%APPDATA%%\AD域管理工具\logs\
echo.
pause
