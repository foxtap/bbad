# -*- coding: utf-8 -*-
"""
main.py —— 应用入口

⚠️ 这个文件有个特殊职责：**在没有控制台的情况下也要能告诉你出了什么事**。

`run_dev.bat` 用的是 `pythonw.exe`（无黑窗），打包后也是 `--windowed`。
这两个形态下，任何启动期异常（少装了依赖、语法错误、配置损坏）
都表现为「双击了，什么都没发生」—— 完全无法排障。

所以这里做了三层兜底：
  1. `faulthandler` 把解释器级崩溃（段错误）写进 ``logs/crash.log``
  2. `sys.excepthook` 把未捕获异常写进日志
  3. 启动失败时**弹一个消息框**告诉你去看哪个日志文件
"""

from __future__ import annotations

import os
import sys
import traceback
import warnings

# ldap3 2.9.1 依赖的 pyasn1 会抛 DeprecationWarning: tagMap is deprecated。
# 已确认无害（不是我们的用法问题），在日志里刷屏会淹没真正的问题。
warnings.filterwarnings("ignore", category=DeprecationWarning,
                        module=r"pyasn1.*")

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)


def _bootstrap_logging():
    """尽早建立日志目录，这样后面任何一步失败都有地方可写。

    实现在 :func:`utils.bootstrap_logging` —— `tools/` 下的排障脚本走的是
    **同一个**函数、写**同一个** ``app.log``（曾经它们各写各的，脚本的日志
    根本不落盘）。这里保留这个名字，是因为 `main()` 有两处调用点、且
    `tests/test_main_entry.py` 已经钉住了它；它只转发，不含逻辑。
    """
    from utils import bootstrap_logging

    return bootstrap_logging()


def _install_crash_guards(log_path: str) -> None:
    """装好崩溃兜底：段错误 + 未捕获异常。"""
    import faulthandler

    try:
        from config import logs_dir

        crash_file = open(os.path.join(logs_dir(), "crash.log"), "a",
                          encoding="utf-8")          # noqa: SIM115 - 进程生命周期内常开
        # ⚠️ crash.log 是**追加**的，且 faulthandler 的 dump 不带 pid/时间。
        #    没有这行分隔，多次启动的 dump 会混在一起没法归属
        #    （0x8001010d 悬案的教训：6 段 dump 分不清是 6 个进程还是 1 个进程崩 6 次）。
        import time
        crash_file.write(
            f"\n===== 进程启动 pid={os.getpid()} "
            f"ts={time.strftime('%Y-%m-%d %H:%M:%S')} "
            f"python={sys.version.split()[0]} =====\n")
        crash_file.flush()
        faulthandler.enable(crash_file)
    except Exception:                                # noqa: BLE001
        pass

    def hook(exc_type, exc_value, exc_tb):
        text = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        print(text, file=sys.stderr)
        try:
            from utils import get_logger
            get_logger("main").critical("未捕获异常：\n%s", text)
        except Exception:                            # noqa: BLE001
            pass

    sys.excepthook = hook


def _fatal(title: str, message: str, log_path: str = "") -> None:
    """启动失败时的最后一道提示。

    能在无控制台环境里把「为什么打不开」讲清楚，是这个函数存在的全部意义。
    """
    detail = message
    if log_path:
        detail += f"\n\n详细日志：\n{log_path}"

    print(f"[FATAL] {title}\n{message}", file=sys.stderr)
    try:
        from PyQt6.QtWidgets import QApplication, QMessageBox

        app = QApplication.instance() or QApplication(sys.argv)
        QMessageBox.critical(None, title, detail)
    except Exception:                                # noqa: BLE001
        # 连 Qt 都起不来（比如没装 PyQt6）—— 至少往桌面写一个文件
        try:
            fallback = os.path.join(os.path.expanduser("~"), "AD域管理工具-启动失败.txt")
            with open(fallback, "w", encoding="utf-8") as fh:
                fh.write(f"{title}\n\n{message}\n")
            print(f"[FATAL] 已写入 {fallback}", file=sys.stderr)
        except OSError:
            pass


def main() -> int:
    log_path = _bootstrap_logging()
    _install_crash_guards(log_path)

    from PyQt6.QtCore import Qt
    from PyQt6.QtWidgets import QApplication

    # 高分屏：用整数倍缩放，避免 125% 缩放下文字发虚
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)

    app = QApplication(sys.argv)
    app.setApplicationName("AD域管理工具")
    # 对外显示名 —— 它会被 Qt **追加**到窗口标题后面（`标题 - 显示名`），
    # 所以：显示名与 `ui_main.MainWindow.setWindowTitle()` **必须一字不差**，
    # 否则标题栏会读成「帮帮AD域管理工具 - AD 域管理工具」这种自相矛盾的两截。
    # 2026-09-22 实测（EnumWindows 读 OS 标题）：显示名 == 窗口标题 ⇒ 不追加，只显示一个。
    app.setApplicationDisplayName("帮帮AD域管理工具")
    app.setOrganizationName("foxtap")

    from audit import AuditLog, APP_VERSION
    from config import ConfigStore, logs_dir
    from ui_main import MainWindow
    from utils import get_logger
    from workers import TaskRunner

    import diag

    log = get_logger("main")
    log.info("=" * 60)
    log.info("启动 帮帮AD域管理工具 v%s（Python %s）", APP_VERSION,
             sys.version.split()[0])
    # 环境快照：这不是"好看"，是排障的第一眼 —— 用户报"连不上"时，
    # 先要能回答"在什么机器、什么形态、依赖是不是齐的"。
    log.info("日志文件：%s", log_path or "（不可用）")
    diag.log_env(log)

    store = ConfigStore()
    store.load()

    audit = AuditLog(logs_dir(), keep_days=store.app.audit_keep_days)
    removed = audit.purge_old()
    if removed:
        log.info("已清理 %d 个过期审计日志文件", removed)

    # 工作线程与应用同生共死；启动一次，全程复用
    runner = TaskRunner()
    runner.start()

    window = MainWindow(app, store, audit, runner)
    window.show()
    window.start()

    try:
        return app.exec()
    finally:
        # 收尾放在 finally：即使 exec 抛异常也要把线程停掉，
        # 否则解释器退出时会因为线程还在跑而直接段错误。
        runner.shutdown(wait_ms=4000)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except BaseException:                            # noqa: BLE001
        _fatal("AD 域管理工具启动失败",
               "".join(traceback.format_exception(*sys.exc_info())),
               _bootstrap_logging())
        sys.exit(1)
