# -*- coding: utf-8 -*-
"""
ui_tasks.py —— 把 `TaskRunner` 接成「一次调用一个回调」的桥

`TaskRunner` 用**任务名**标识结果，但 UI 里同一个操作会被触发很多次
（点两次「解锁」就有两个同名任务）。如果直接按名字分发，
后完成的那次会去覆盖前一次的回调 —— 表现为「点了没反应」或「跳错结果」。

所以这里给每次提交生成唯一键 ``label#序号``，把回调存进字典，
完成时取出并调用。UI 侧只关心 ``on_ok`` / ``on_fail``，不碰信号。
"""

from __future__ import annotations

from typing import Callable

from workers import TaskRunner

__all__ = ["TaskBridge"]

#: 回调签名：``fn(result)`` / ``fn(message, code)``
OnOk = Callable[[object], None]
OnFail = Callable[[str, str], None]


class TaskBridge:
    """任务提交门面。

    用法::

        tasks = TaskBridge(runner)
        tasks.submit("列出用户", client.list_users, on_ok, on_fail, ou_dn)
        tasks.submit("批量改密", batch_reset_password, on_ok, on_fail,
                     client, rows, pwd, with_progress=True)
    """

    def __init__(self, runner: TaskRunner):
        self.runner = runner
        self._seq = 0
        self._pending: dict[str, tuple[str, OnOk | None, OnFail | None]] = {}
        #: 任务开始/结束的回调，由窗口接上（显示忙碌态）
        self.on_started: Callable[[str], None] | None = None
        self.on_finished: Callable[[str], None] | None = None

        runner.task_succeeded.connect(self._on_succeeded)
        runner.task_failed.connect(self._on_failed)
        runner.task_started.connect(self._on_started)
        runner.task_finished.connect(self._on_finished)

    # ---------------- 提交 ----------------

    def submit(self, label: str, fn: Callable, on_ok: OnOk | None = None,
               on_fail: OnFail | None = None, *args,
               with_progress: bool = False, **kwargs) -> str:
        self._seq += 1
        key = f"{label}#{self._seq}"
        self._pending[key] = (label, on_ok, on_fail)

        if with_progress:
            from workers import bind_progress
            self.runner.submit(key, bind_progress(self.runner, fn), *args, **kwargs)
        else:
            self.runner.submit(key, fn, *args, **kwargs)
        return key

    def cancel(self) -> None:
        self.runner.cancel()

    def is_busy(self) -> bool:
        return self.runner.is_busy()

    # ⚠️ 2026-09-17 删掉了 `pending_count()`：**零调用点**（本文件里没人问，
    #    页面也没接过）。要问队列长度请看 `runner.pending()` —— 那个有调用者。
    #    按铁律「零调用点 = 死代码要删」处理。

    # ---------------- 信号处理 ----------------

    def _take(self, key: str):
        return self._pending.pop(key, None)

    @staticmethod
    def _label_of(key: str) -> str:
        return key.rsplit("#", 1)[0]

    def _on_succeeded(self, key: str, result: object) -> None:
        entry = self._take(key)
        if entry is None:
            return
        name, on_ok, _on_fail = entry
        if on_ok is not None:
            self._safe_call(on_ok, result, context=name)

    def _on_failed(self, key: str, message: str, code: str) -> None:
        entry = self._take(key)
        if entry is None:
            return
        name, _on_ok, on_fail = entry
        if on_fail is not None:
            self._safe_call(on_fail, message, code, context=name)

    def _on_started(self, key: str) -> None:
        if self.on_started is not None:
            self._safe_call(self.on_started, self._label_of(key), context="on_started")

    def _on_finished(self, key: str) -> None:
        if self.on_finished is not None:
            self._safe_call(self.on_finished, self._label_of(key), context="on_finished")

    @staticmethod
    def _safe_call(fn: Callable, *args, context: str = "") -> None:
        """回调里抛异常不能把工作线程或信号循环带崩。

        实际发生过的场景：回调里刷新表格时，表格已经被窗口销毁了
        （使用者关了窗口但任务还在跑），抛 RuntimeError。

        ⚠️ ``context`` 只用于日志，**不能**混进 ``*args`` ——
        否则回调会收到多余的参数而抛 TypeError（这个坑踩过一次了）。
        """
        import traceback

        from utils import get_logger

        try:
            fn(*args)
        except RuntimeError as exc:
            get_logger("ui_tasks").warning("回调时控件已销毁，忽略（%s）：%s",
                                           context, exc)
        except Exception:                            # noqa: BLE001
            get_logger("ui_tasks").error(
                "任务回调抛出异常（%s）：\n%s", context, traceback.format_exc())
