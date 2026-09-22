# -*- mode: python ; coding: utf-8 -*-
"""bbad.spec —— 帮帮AD域管理工具 的 PyInstaller 打包配置（产物：bbad.exe）

打包要点：

  * **用 .spec 而不是纯命令行** —— 复用 `build/` 缓存，只重编译改动的 .py。
    不要每次都 `--clean`（只有依赖变了或诡异报错时才清）。
  * **默认出 onedir**（内网分发，启动 <1 秒，整体拷文件夹）。
    要单文件设环境变量 `ADPKG_ONEFILE=1`（发邮件/网盘/U盘时用，启动 3~6 秒）。
  * **排除本项目完全不用的 PyQt6 大模块** —— QtWebEngine 一类动辄几十 MB。
  * **关 UPX**（省时间，且压过的 exe 容易被杀软误报）。

用法::

    .venv\\Scripts\\pyinstaller --noconfirm bbad.spec      # 出 onedir
    set ADPKG_ONEFILE=1 && .venv\\Scripts\\pyinstaller --noconfirm bbad.spec

或直接双击 `build.bat`（带依赖自检 + 产物自检）。
"""

import os

ONEFILE = os.environ.get("ADPKG_ONEFILE") == "1"

#: 产物名 = `bbad.exe`（2026-09-22 定名）。
#:
#: 🔴 **只有这一处跟着改** —— 不要顺手把 `config.APP_DIR_NAME` 也改成 bbad：
#:    配置与日志目录是 `%APPDATA%\\AD域管理工具\\`，那是**已缓存的 AD 连接信息**
#:    的存放处。改了它 = 程序换个新目录启动 = 他存的那些连接**一条都看不见了**。
#:    （同理 `main.py` 的 `setApplicationName` / 启动失败文件名也不动。）
#:    两个名字管两件事：**产物名**对外，**数据目录名**对内且要向后兼容。
APP_NAME = "bbad"


# 本项目完全不用的 Qt 大模块：每排除一个，体积与打包时间都下来
excludes = [
    "tkinter",
    "PyQt6.QtWebEngineCore", "PyQt6.QtWebEngineWidgets", "PyQt6.QtWebEngineQuick",
    "PyQt6.Qt3DCore", "PyQt6.Qt3DRender", "PyQt6.Qt3DExtras", "PyQt6.Qt3DAnimation",
    "PyQt6.Qt3DInput", "PyQt6.Qt3DLogic",
    "PyQt6.QtQuick", "PyQt6.QtQml", "PyQt6.QtQuickWidgets", "PyQt6.QtQuick3D",
    "PyQt6.QtMultimedia", "PyQt6.QtMultimediaWidgets",
    "PyQt6.QtCharts", "PyQt6.QtDataVisualization", "PyQt6.QtGraphs",
    "PyQt6.QtBluetooth", "PyQt6.QtNfc", "PyQt6.QtPositioning", "PyQt6.QtLocation",
    "PyQt6.QtNetworkAuth", "PyQt6.QtDesigner", "PyQt6.QtHelp",
    "PyQt6.QtSql", "PyQt6.QtTest", "PyQt6.QtWebChannel", "PyQt6.QtWebSockets",
    # 打包期 / 测试期的东西，别混进交付包
    "pyinstaller", "pytest", "pydoc", "doctest",
]

# ⚠️ pywin32 的坑：`win32com.client` 会在**运行期懒加载** `win32timezone`
#    （不是字面 import，PyInstaller 静态分析抓不到）⇒ 必须显式点名，
#    否则 exe 里一点「改密」就 ModuleNotFoundError: win32timezone。
#    `pythoncom`/`pywintypes` 同理（COM 初始化与类型对象）。
hiddenimports = [
    "win32timezone", "win32com.client", "win32com.adsi", "win32com.shell",
    "pythoncom", "pywintypes", "win32api", "win32security", "win32crypt",
    # Crypto.Hash.MD4 —— NTLMv2 要用的 MD4，Python 3.13 内置库已移除，
    # 全靠 pycryptodome 提供（ldap3 是**按名字**找 Crypto.Hash.MD4 的）
    "Crypto.Hash.MD4",
]

a = Analysis(
    ["main.py"],
    pathex=[SPECPATH],                  # 本项目所有模块都是顶层平铺 import
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

if ONEFILE:
    exe = EXE(
        pyz, a.scripts, a.binaries, a.datas,
        [],
        name=APP_NAME,
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,                       # 见文件头：省时间 + 少被杀软误报
        runtime_tmpdir=None,
        console=False,                   # 无黑窗；启动失败由 main.py 自己弹框
        disable_windowed_traceback=False,
    )
else:
    exe = EXE(
        pyz, a.scripts,
        [],
        exclude_binaries=True,           # onedir：二进制交给下面 COLLECT
        name=APP_NAME,
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        console=False,
        disable_windowed_traceback=False,
    )

    coll = COLLECT(
        exe,
        a.binaries,
        a.datas,
        strip=False,
        upx=False,
        upx_exclude=[],
        name=APP_NAME,
    )
