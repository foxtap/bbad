# -*- coding: utf-8 -*-
"""
com_env.py —— 工作线程的 COM 公寓管理（Windows + pywin32）

本模块只回答一个问题：**非主线程要调 COM（ADSI / LogonUser）时，公寓怎么开。**

## 为什么不是「每次调用 CoInitialize / CoUninitialize 配对」

那是教科书写法，但它有一个致命的时间差：

撤销公寓会让该公寓里的 COM 对象**全部悬空**。而对象什么时候真的被释放，
不由你说了算 —— 异常 traceback 会把栈帧多留一会儿，栈帧里恰好存着 ADSI 对象。
悬空引用一旦被 Release，坏掉的是**整个进程**的 OLE 状态：之后 Qt 的剪贴板、
拖放、原生文件对话框会报 ``0x8001010d``（RPC_E_CANTCALLOUT_ININPUTSYNCCALL）
并**直接把进程带走** —— 用户看到的是「用着用着窗口突然没了」，
而崩溃日志里的堆栈全是正常代码。

批量改密还会对同一个线程反复开 / 关公寓，每次都开一个悬空窗口。

## 为什么是 MTA 而不是 pywin32 默认的 STA

1. **STA 线程必须自己派发消息泵**才能收到跨公寓调用，而我们的工作线程是一个
   死循环队列 —— 没有消息泵。
2. ``RPC_E_CANTCALLOUT_ININPUTSYNCCALL`` **只可能出现在 STA 的「输入同步调用」
   上下文里**。选 MTA 是从原理上绕开这一类崩溃，而不是把它调得"不容易触发"。

公寓跟着线程活，线程退出由系统回收（也提供 :func:`release_apartment` 显式收尾）。
对一个长期存活的工作线程来说，占着一个公寓是零成本。

## 边界

* 非 Windows / 没装 pywin32 → 所有函数安全降级（返回 False，不打异常）。
  本工具在没有 pywin32 的机器上只有改密/建号通道不可用，其余照常。
* 不负责导入 pywin32 之外的任何东西，也不碰 ADSI 本身。
"""

from __future__ import annotations

import threading

from utils import get_logger

__all__ = ["ensure_apartment", "release_apartment", "reset_for_tests"]

_log = get_logger("com")

#: 每线程一次的标记。
#: 公寓是**线程属性**，所以这里必须是 ``threading.local`` 而不是模块级布尔 ——
#: 用全局布尔的话，主线程初始化过就会让工作线程误以为自己也初始化了。
_local = threading.local()


def ensure_apartment() -> bool:
    """确保**当前线程**已进入 COM 公寓（MTA）。

    幂等：每个线程只真正初始化一次，且**永不撤销**（理由见模块说明）。
    返回 True 表示本次真的初始化了。
    """
    if getattr(_local, "ready", False):
        return False
    # 先置位再尝试：即使下面失败也不再重试，避免每次调用都刷一条日志
    _local.ready = True

    try:
        import pythoncom
    except ImportError:
        _log.info("pythoncom 不可用（非 Windows 或未装 pywin32），改密通道将不可用")
        return False

    try:
        pythoncom.CoInitializeEx(pythoncom.COINIT_MULTITHREADED)
    except Exception as exc:              # noqa: BLE001
        # 线程已经进了别的公寓（外部脚本或某个库替我们初始化过）——
        # 典型的 RPC_E_CHANGED_MODE。将就着用，别把功能弄挂。
        _log.info("COM 公寓已由其它代码初始化，沿用：%s", exc)
        return False

    _log.debug("线程已进入 COM 多线程公寓（MTA）")
    return True


def release_apartment() -> None:
    """线程收尾时撤销公寓。

    ⚠️ 只应在**线程即将结束**时调用，且调用前必须确认本线程已不再持有任何
    COM 对象 —— 这正是本模块存在的意义（见模块说明）。
    正常路径下不调也行：线程退出时系统会回收公寓。
    """
    if not getattr(_local, "ready", False):
        return
    _local.ready = False
    try:
        import pythoncom
    except ImportError:
        return
    try:
        pythoncom.CoUninitialize()
    except Exception:                     # noqa: BLE001
        pass


def reset_for_tests() -> None:
    """测试专用：清掉本线程的标记，让下一次 :func:`ensure_apartment` 重走一遍。

    不清的话，第一个测试初始化过，后面的测试就全变成「幂等命中」，
    断言 `CoInitializeEx` 被调用的用例会随机变红。
    """
    _local.ready = False
