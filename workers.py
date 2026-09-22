# -*- coding: utf-8 -*-
"""
workers.py —— 线程层（T10b）

把阻塞的 LDAP / RPC 调用搬离 UI 线程，并提供一个「单飞」任务队列。

🔒 为什么必须是**单飞**（一次只跑一个任务，不能并发）：

  1. **ldap3 的 `Connection` 不是线程安全的。**
     默认 `SyncStrategy.thread_safe == False`，两个线程同时 search/modify
     会互相踩响应缓冲区，表现为「随机拿到别人的查询结果」——
     这种 bug 在测试环境几乎复现不出来，到了生产会改错人。

  2. **`ImpersonateLoggedOnUser` 是线程级状态。**
     改密后端把令牌挂在**当前线程**上，并发跑批量改密会出现
     「A 的密码用 B 的权限去改」。

  所以本模块用一条**常驻线程 + 队列**串行执行，不是性能妥协，是正确性要求。

🔒 为什么用常驻线程而不是每个操作 new 一个 QThread：

  PyQt 的经典崩溃 —— `QThread: Destroyed while thread is still running`。
  Python 侧一旦没有引用，QThread 对象会被 GC 掉，而底层线程还在跑，
  进程直接 segmentation fault。常驻线程从根上避开这个坑。
"""

from __future__ import annotations

import queue
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from functools import lru_cache as _lru_cache
from typing import Callable

from PyQt6.QtCore import QObject, QThread, pyqtSignal

from admx_backend import load_catalog as _admx_load_catalog
from com_env import ensure_apartment, release_apartment
# ⚠️ 下游后端一律用**下划线别名**。
#    为什么：`vars(workers)` 是活的（元级守卫靠它枚举"模块级 worker"），
#    而 `from x import f` 会把 `f` 塞进本模块的 globals —— **它不是 worker，
#    却会长着一张 worker 的脸**（`inspect.isfunction` 判定为真）。
#    对账一旦按这张名单走，就是把别人的函数算成自己的。
#    下划线前缀把这个事实写进名字里：它们只是实现细节，不是本模块的出口。
from gpo_backend import GpoInfo, GpoLink, SomInfo
from gpo_backend import (
    engine_status as _gpo_engine_status,
    generate_report as _gpo_generate_report,
    links_of_som as _gpo_links_of_som,
    open_session as _gpo_open_session,
    soms_linking_gpo as _gpo_soms_linking_gpo,
)
# ⚠️ 2026-09-17：`list_gpos` / `search_gpos` 这两条**生产路径改走 LDAP**
#    （`gpo_ldap.py`，不需要 RSAT）。原来那两个别名（`_gpo_list_gpos` /
#    `_gpo_search_gpos`，走 GPMC COM）已随之下线 —— **不要加回来**：
#    GPMC 那份现在的角色只是判决装置里的**对照尺**，直接调 `gpo_backend`。
#    裁定与理由见 `gpo_ldap.py` 的模块说明（只保留一份读实现）。
from gpo_ldap import list_gpos as _ldap_list_gpos
from gpo_ldap import search_gpos as _ldap_search_gpos
from gpo_settings import GpoSettings
from gpo_settings import read_gpo_settings as _read_gpo_settings
from gpo_settings import sysvol_gpo_dir as _sysvol_gpo_dir
# ⚠️ 安全策略（`GptTmpl.inf`）的**读** —— 与「改过哪些设置」同一条自包含路线：
#    自己按协议算路径 ＋ 自己解字节，**不经过 GPMC**。
#    🔴 它**只读**：2026-09-18 主理人裁定「组策略不做编辑，只做看得见」，
#    写侧已整体移出仓库归档 —— 别照着旧设计稿把 `patch` / `apply` 加回来。
from gpo_security import GpoSecurity
from gpo_security import read_gpo_security as _read_gpo_security
from models import BatchItemResult, BatchResult, UserRow
from password_backend import (impersonate as _impersonate,
                              parse_bind_user as _parse_bind_user)
# ⚠️ 用下划线别名（理由见上面那段）：这些是**实现细节**，不是本模块的出口。
#    `SyncOutcome` 是 dataclass、不是函数，所以不加下划线 —— 元级守卫按
#    `inspect.isfunction` 枚举 worker，类不会被算进去（`GrantOutcome` 同理）。
#    原因码有一组（`REASON_*`）且还在长，所以整模块引进来用 `_replication.REASON_*`，
#    比逐个 from-import 好维护。
import replication as _replication
from replication import SyncOutcome
from replication import resolve_dc_name as _resolve_dc_name
from replication import sync_all as _sync_all
# ⚠️ 2026-09-16：这里原有两组共享盘后端的 import（`from share_backend import …` ×2
#    与 `from share_editor import …` ×5）—— 随「操作共享盘」功能整体删除，
#    连同 `share_backend.py` / `share_editor.py` / `ui_share.py` 一起销掉。
#    **不要照着旧版加回来。**
from utils import AdToolError, get_logger, translate_error

__all__ = [
    "Progress",
    "TaskRunner",
    "batch_reset_password",
    "batch_set_enabled",
    "batch_unlock",
    "batch_delete",
    "batch_move",
    # ⚠️ 2026-09-16：这里原有 8 个共享盘 worker（`share_identity_of` /
    #    `open_share_in_editor` / `list_share_folders` / `grant_share_layer` /
    #    `grant_share_layer_sid` / `list_server_shares` / `create_server_share`
    #    等）—— 随「操作共享盘」功能整体删除。**不要加回来。**
    "GpoListResult",
    "gpo_engine_available",
    "gpo_identity_of",
    "list_gpos",
    "search_gpos",
    "gpo_linked_soms",
    "som_linked_gpos",
    "gpo_report",
    "GpoSettingsResult",
    "gpo_settings",
    "GpoSecurityResult",
    "gpo_security",
    "sync_replication",
]

_log = get_logger("workers")


# ============================================================================
# 协作式取消 + 进度上报
# ============================================================================

class Progress:
    """把「进度」和「取消」传给正在跑的任务函数。

    取消是**协作式**的：不打断正在进行的单次 LDAP 调用（那会留下
    「改了一半」的不确定状态），而是在每一项之间检查一次 —— 边界清晰。
    """

    def __init__(self, emit: Callable[[int, int, str], None],
                 is_cancelled: Callable[[], bool]):
        self._emit_fn = emit
        self._is_cancelled = is_cancelled
        self.done = 0
        self.total = 0

    # ---------- 给任务函数用 ----------

    def start(self, total: int, label: str = "") -> None:
        self.total = max(0, int(total))
        self.done = 0
        self._emit("")

    def step(self, label: str = "") -> bool:
        """前进一步。返回 ``False`` 表示使用者要求中止，调用方应立即 break。"""
        self.done += 1
        self._emit(label)
        return not self.cancelled

    # ⚠️ 2026-09-17 删掉了 `note(label)`：它**零调用点**（"只更新文案、不推进进度"
    #    这一档没有任何任务函数用过 —— 需要这一档时 `step` 与 `start` 已经够用）。
    #    按铁律「零调用点 = 死代码要删」处理。

    @property
    def cancelled(self) -> bool:
        return self._is_cancelled()

    def _emit(self, label: str) -> None:
        try:
            self._emit_fn(self.done, self.total, label)
        except RuntimeError:
            # 窗口已经销毁，信号接收者没了 —— 不能因此把任务搞崩
            pass


class _Job:
    __slots__ = ("name", "fn", "args", "kwargs")

    def __init__(self, name: str, fn: Callable, args: tuple, kwargs: dict):
        self.name = name
        self.fn = fn
        self.args = args
        self.kwargs = kwargs


# ============================================================================
# 单飞任务执行器
# ============================================================================

class TaskRunner(QThread):
    """常驻工作线程 + 串行队列。

    用法::

        runner = TaskRunner()
        runner.succeeded.connect(on_ok)
        runner.failed.connect(on_fail)
        runner.start()                     # 应用启动时起一次，全程复用
        runner.submit("列出用户", client.list_users, ou_dn)
        ...
        runner.shutdown()                  # 退出时收尾

    信号：
      * ``task_started(name)``              任务开始（UI 置忙状态）
      * ``task_succeeded(name, result)``    任务成功，result 是函数返回值
      * ``task_failed(name, message, code)`` 任务失败，message 已是中文
      * ``progress(done, total, label)``    进度（total=0 表示不确定进度）
      * ``task_finished(name)``             无论成败都会发（UI 解除忙状态）

    ⚠️ 2026-09-17 删掉了 ``pending_changed(count)``：它**有 emit、零 connect**
    （文档却写"队列长度会通过它显示"），属于"名字承诺了一个从未实现的显示"。
    按铁律「零调用点 = 死代码要删」处理。队列长度仍可随时用 ``pending()`` 问。
    """

    task_started = pyqtSignal(str)
    task_succeeded = pyqtSignal(str, object)
    task_failed = pyqtSignal(str, str, str)
    progress = pyqtSignal(int, int, str)
    task_finished = pyqtSignal(str)

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self._queue: queue.Queue[_Job | None] = queue.Queue()
        self._cancel = threading.Event()
        self._stopping = False
        #: 已投递但还没跑完的任务数。
        #:
        #: 🔒 为什么不用 ``qsize()`` 拼：``qsize()`` 只数**还没被取走**的任务，
        #: 正在跑的那个不在里面 —— 拿它当"忙不忙"的依据，跑最后一个任务时
        #: ``is_busy()`` 会**假报空闲**，使用者就能在操作进行中点「断开」。
        #: 这个计数器在 ``submit`` 时自增、``finally`` 里自减，全程由锁保护，
        #: 不存在"取走了但还没开始跑"的空档。
        #:
        #: ⚠️ 2026-09-17：原文还写着"不用 ``qsize()`` + ``_in_flight`` 拼"，
        #:    而 ``_in_flight`` 是个**只写不读**的残留属性，已一并删除
        #:    （它就是上面那个空档问题的旧解，被计数器取代了）。
        self._outstanding = 0
        self._lock = threading.Lock()

    # ---------------- 对外 ----------------

    def submit(self, name: str, fn: Callable, *args, **kwargs) -> bool:
        """投递一个任务。永远成功投递（队列无上限），返回是否新任务。

        不提供「上一批没跑完就拒绝」——使用者点了按钮就该被执行，
        排队比弹窗拒绝更符合直觉。
        """
        if self._stopping:
            _log.warning("TaskRunner 已停止，拒绝任务 %s", name)
            return False
        with self._lock:
            self._outstanding += 1
        self._queue.put(_Job(name, fn, args, kwargs))
        return True

    def cancel(self) -> None:
        """请求中止当前任务（协作式：当前单项跑完后停止）。"""
        self._cancel.set()
        _log.info("已请求取消当前任务")

    def is_cancelled(self) -> bool:
        return self._cancel.is_set()

    def clear_cancel(self) -> None:
        self._cancel.clear()

    def pending(self) -> int:
        """待处理任务数（含正在执行的那个）。"""
        with self._lock:
            return self._outstanding

    def is_busy(self) -> bool:
        """是否有任务在处理。**这是判断"能不能安全断开"的唯一依据。**"""
        with self._lock:
            outstanding = self._outstanding
        return self.isRunning() and outstanding > 0

    def shutdown(self, wait_ms: int = 3000) -> None:
        """收尾：置停止标志、唤醒队列、等待线程结束。

        ⚠️ 必须在窗口 closeEvent 里调用。不等线程结束就退出进程，
        仍是那个 `QThread: Destroyed while thread is still running`。
        """
        self._stopping = True
        self._cancel.set()
        self._queue.put(None)                  # 唤醒阻塞在 get() 的线程
        if self.isRunning():
            if not self.wait(wait_ms):
                _log.warning("工作线程未在 %dms 内结束，强制继续退出", wait_ms)

    def run(self) -> None:                     # noqa: D102 - Qt 回调
        # 工作线程必须先进 COM 公寓：ADSI / LogonUser 都要求所在线程已初始化公寓，
        # 而 QThread 的线程 pywin32 不会替它做（主线程才有那待遇）。
        #
        # 公寓**跟线程同生共死**，不是每个任务开关一次 —— 撤销公寓会让还在
        # traceback 里活着的 ADSI 对象悬空，坏掉进程的 OLE 状态，之后 Qt 会报
        # 0x8001010d 并直接把进程带走。完整理由见 com_env 的模块说明。
        ensure_apartment()
        try:
            self._loop()
        finally:
            release_apartment()

    def _loop(self) -> None:
        """任务取用循环（单独拆出来，只为让 COM 收尾有地方写）。"""
        while True:
            try:
                job = self._queue.get(timeout=0.2)
            except queue.Empty:
                if self._stopping:
                    break
                continue

            if job is None:                    # 关闭信号
                break
            if self._stopping:
                self._release()
                continue

            self._run_one(job)

    def _release(self) -> None:
        with self._lock:
            self._outstanding = max(0, self._outstanding - 1)

    def _run_one(self, job: _Job) -> None:
        self._cancel.clear()                   # 新任务开始 → 清掉上次的取消
        self.task_started.emit(job.name)
        self.progress.emit(0, 0, "")

        try:
            result = job.fn(*job.args, **job.kwargs)
        except AdToolError as exc:
            _log.warning("任务 %s 失败：%s", job.name, exc.message)
            self.task_failed.emit(job.name, exc.message, exc.code or "")
        except Exception as exc:               # noqa: BLE001
            # 任何未预期异常都不能让工作线程死掉 —— 它要活到应用退出
            err = translate_error(exc, context=job.name)
            _log.exception("任务 %s 抛出未预期异常", job.name)
            self.task_failed.emit(job.name, err.message, err.code or "")
        else:
            self.task_succeeded.emit(job.name, result)
        finally:
            self._release()                    # 必须在发 finished 之前减，
                                               # 否则接收方看到的还是"忙"
            self.progress.emit(0, 0, "")       # 复位进度条
            self.task_finished.emit(job.name)

    # ---------------- 供任务函数使用的 Progress ----------------

    def make_progress(self) -> Progress:
        """造一个绑定到本 runner 的进度对象（任务函数里调用）。"""
        return Progress(lambda d, t, s: self.progress.emit(d, t, s),
                        self.is_cancelled)


def bind_progress(runner: TaskRunner, fn: Callable) -> Callable:
    """把一个「接受 progress 参数」的函数适配成可直接 submit 的任务。

    用法::

        runner.submit("批量重置密码", bind_progress(runner, batch_reset_password),
                      client, rows, "NewP@ss", True)
    """
    def wrapper(*args, **kwargs):
        # ⚠️ 2026-09-17：原来这里 `kwargs.pop("_progress_total", None)`，
        #    那是 `TaskRunner.submit_progress` 的搭档；`submit_progress` 已因
        #    **零调用点**删除 ⇒ 再没人能塞进这个键，这行成了死代码，一并删掉。
        #    要预先声明总数仍可走 `Progress.start(total)`（任务函数内部调用）。
        return fn(*args, progress=runner.make_progress(), **kwargs)
    wrapper.__name__ = getattr(fn, "__name__", "task")
    return wrapper


# ============================================================================
# 批量操作
# ============================================================================
#
# 三条批量语义（统一遵守）：
#   1. **单条失败不中止整批** —— 50 个人里 1 个密码不合策略，不该让另外 49 个白改
#   2. **每条失败都能追到人** —— BatchItemResult 带 sam + 中文原因
#   3. **连接断了必须整批停** —— 继续跑只会产生 50 条一模一样的网络错误
#
# 判定「连接级致命错误」的错误码，命中就中止整批。
#
# ⚠️ **与 ldap3 有关的那些必须派生，不许手抄**（2026-09-14 实测抓到漏项）：
# `translate_error` 给 ldap3 异常打的 `code` 就是**类名**（兜底分支
# `code=type(exc).__name__`），所以口径是"类名对账"。手抄版当时只有
# `LDAPSocketOpenError / Receive / Send` 三个，漏了：
#
#   * `LDAPSocketCloseError` —— 协议层 socket 被关掉，**就是"连接断了"**。
#     漏它的后果不是"报个错"那么轻：批量跑到一半连接断掉时整批**不会中止**，
#     剩下的行一条条撞同一堵墙，最后甩给使用者 N 条一模一样的网络错误 ——
#     而本文件开头第 3 条语义写的就是「**连接断了必须整批停**」。
#   * `LDAPCommunicationError` 基类本身、`LDAPUnknownRequestError`、
#     `LDAPUnknownResponseError`、`LDAPReferralError`。
#
# 现在判据落在**基类**上（见 `_fatal_codes`）：ldap3 以后新增通信层子类自动纳入。

#: 与 ldap3 无关、由 `translate_error` 派生的连接级错误码。
#: `LDAPResponseTimeoutError` 不在通信层里（ldap3 自己的分类如此），单列。
_FATAL_CODES = frozenset({
    "timeout", "network", "encoding", "LDAPResponseTimeoutError",
})


def _fatal_codes() -> frozenset[str]:
    """「连接级故障」错误码全集 = 固定码 + **ldap3 通信层的全部类名**。

    名单当场从 `LDAPCommunicationError` 递归派生，所以不需要谁记得加名字。
    ldap3 没装时退回固定码（本工具的纯逻辑不该因为缺 ldap3 就跑不起来）。
    """
    try:
        from ldap3.core.exceptions import LDAPCommunicationError
    except ImportError:                          # pragma: no cover
        return _FATAL_CODES
    seen: set[type] = set()
    names: set[str] = set()
    stack: list[type] = [LDAPCommunicationError]
    while stack:
        cls = stack.pop()
        if cls in seen:
            continue
        seen.add(cls)
        names.add(cls.__name__)
        stack.extend(cls.__subclasses__())
    return frozenset(_FATAL_CODES | names)


def _is_fatal(exc: AdToolError) -> bool:
    """这条错误是不是「再跑下去也没意义」的连接级故障。"""
    if exc.code in _fatal_codes():
        return True
    # LDAP 结果码 52=服务不可用，81=服务器忙
    if isinstance(exc.code, str) and exc.code.isdigit():
        return int(exc.code) in (52, 81)
    return False


def _run_batch(op_label: str, rows: list[UserRow], progress: Progress,
               one: Callable[[UserRow], str | None]) -> BatchResult:
    """批量执行骨架：进度、取消、逐条记账、致命错误中止。

    ``one`` 可以返回一个字符串（成功后的新 DN，目前只有批量移动用）——
    骨架把它记进 `BatchItemResult.new_dn`，界面靠它在树上做「删旧插新」
    的精确局部刷新，不用整层重拉。
    """
    result = BatchResult(op_label=op_label)
    progress.start(len(rows))

    for row in rows:
        if progress.cancelled:
            result.cancelled = True
            _log.info("%s 被使用者中止，已处理 %d/%d", op_label,
                      len(result.items), len(rows))
            break
        try:
            new_dn = one(row)
        except AdToolError as exc:
            result.items.append(BatchItemResult(
                sam=row.sam, dn=row.dn, ok=False, message=exc.message))
            if _is_fatal(exc):
                result.aborted_reason = exc.message
                _log.error("%s 因连接级故障中止：%s", op_label, exc.message)
                break
        except Exception as exc:               # noqa: BLE001
            err = translate_error(exc)
            result.items.append(BatchItemResult(
                sam=row.sam, dn=row.dn, ok=False, message=err.message))
            if _is_fatal(err):
                result.aborted_reason = err.message
                break
        else:
            result.items.append(BatchItemResult(
                sam=row.sam, dn=row.dn, ok=True, message="",
                new_dn=new_dn or ""))
        finally:
            progress.step(row.sam)

    return result


def batch_reset_password(client, rows: list[UserRow], new_password: str,
                         must_change: bool = True,
                         progress: Progress | None = None) -> BatchResult:
    """批量重置密码。

    ⚠️ 同一个新密码发给所有人 —— 这是重置（帮人救急/入职批量开号）的语义，
    不是"给每个人设他自己的密码"。使用者应在确认框里看到这句话。
    """
    progress = progress or Progress(lambda *a: None, lambda: False)

    def one(row: UserRow) -> None:
        client.reset_password(row.dn, new_password, sam=row.sam,
                              must_change=must_change)

    return _run_batch("批量重置密码", rows, progress, one)


def batch_set_enabled(client, rows: list[UserRow], enabled: bool,
                      progress: Progress | None = None) -> BatchResult:
    """批量启用 / 禁用。"""
    progress = progress or Progress(lambda *a: None, lambda: False)
    label = "批量启用账号" if enabled else "批量禁用账号"

    def one(row: UserRow) -> None:
        client.set_enabled(row.dn, enabled, sam=row.sam)

    return _run_batch(label, rows, progress, one)


def batch_unlock(client, rows: list[UserRow],
                 progress: Progress | None = None) -> BatchResult:
    """批量解锁。"""
    progress = progress or Progress(lambda *a: None, lambda: False)

    def one(row: UserRow) -> None:
        client.unlock(row.dn, sam=row.sam)

    return _run_batch("批量解锁账号", rows, progress, one)


def batch_delete(client, rows, progress: Progress | None = None) -> BatchResult:
    """批量删除对象（用户 / 组 / 计算机 / 联系人 / OU）。

    ⚠️ 每一项仍走 `delete_object` —— 它内部会重新计算删除计划并做
    保护检查（域根 / 受保护容器 / 域控会被单项拒绝），所以批量删除
    不会绕过任何单条删除的安全网。

    行对象只要带 ``sam`` / ``dn`` 就能跑（``_run_batch`` 只用这两个字段
    记账），``DirObject`` 与 ``UserRow`` 都满足。
    """
    progress = progress or Progress(lambda *a: None, lambda: False)

    def one(row) -> None:
        client.delete_object(row.dn, getattr(row, "kind", ""),
                             getattr(row, "title", "") or row.sam or row.dn,
                             row.sam)

    return _run_batch("批量删除", rows, progress, one)


def batch_move(client, rows, new_parent_dn: str,
               progress: Progress | None = None) -> BatchResult:
    """批量移动对象到同一个目标容器。

    ⚠️ `move_object` 返回的新 DN 必须一路记进 `BatchItemResult.new_dn`：
    界面靠它在树上「删旧插新」，丢了就只能整层重拉。
    """
    progress = progress or Progress(lambda *a: None, lambda: False)

    def one(row) -> str:
        return client.move_object(row.dn, new_parent_dn, sam=row.sam,
                                  label=getattr(row, "title", "") or row.dn)

    return _run_batch("批量移动", rows, progress, one)


# ============================================================================
# 共享盘 —— **本模块已彻底移除**（2026-09-16）
# ============================================================================
#
# ⚠️ 主理人拍板：「把操作共享盘这个功能，**全部删除掉**，不要这个功能了，我直接
#    远程文件服务器来加权限。」⇒ 本模块原先这一整块（取身份 / 打开编辑器 /
#    列一层目录 / 列服务器共享 / 新建共享 / 共享层授权，共 9 个 worker +
#    2 个私有助手）以及 `share_backend.py` / `share_editor.py` / `ui_share.py`
#    三个模块**一起删除**。
#
# ⚠️ 因此：**不要照着旧版把它们加回来**。这里留一段空说明而不是一片空白，是为了
#    下一个读代码的人知道"这里曾经有东西、它是被主理人有意识地拿掉的"，而不是
#    以为漏写。
#
# ⚠️ 与它同时消失的还有「服务器类型闸」（原 `share_backend.py` 第 7 节，
#    D-07）。那个闸的**唯一用途**就是"写共享 ACL 之前挡一下 NAS"；写 ACL 的路
#    没了，它就没有任何生产调用点 —— 按本项目铁律「零调用点 = 死代码，删」一并
#    销掉。被删掉的那份实现与它的实测结论都在快照与 Obsidian 归档里，**代码不保留**。


# ============================================================================
# 组策略（只读）—— 走 GPMC 的 COM 引擎
# ============================================================================
#
# ⚠️ 本模块的身份通道只有**一条**：组策略走 DCOM/RPC ⇒ 用的是**线程令牌**
#     ⇒ 只能 `password_backend.impersonate`，不能"顺手都加上"。
#
#     （2026-09-16 之前还有第二条：共享盘走 SMB ⇒ `net use` 给网络位置带凭据、
#     进程令牌不变。那条路连同 `share_backend.py` 已随「操作共享盘」功能整体
#     删除。两组凭据通道**语义不同、不可互换** —— 这条结论本身仍然成立，
#     写在这里备查。）
#
# ⚠️ 两个 `domain` 语义不同，**别混**：
#     `impersonate` 要 **NetBIOS 域**（`parse_bind_user` 归一化后给的），
#     而 GPMC 的 `GetDomain` 要 **DNS 域名**（`client.domain`）。
#     把 DNS 域名塞进 `LogonUser` 会报成"用户名或密码错误"，把人往错方向带。

@dataclass
class GpoListResult:
    """一次 GPO 列举的结果。

    ⚠️ `gpos` 为空是**合法结果**（域里可能真没有 GPO），**不是失败** ——
    界面必须把"空"和"错"显示成两回事（09-15 真域上修过同一类问题）。
    """

    domain: str = ""
    dc: str = ""
    gpos: list[GpoInfo] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.gpos)


def gpo_engine_available() -> tuple[bool, str]:
    """本机能不能读组策略（GPMC 引擎装没装）。**不需要**先连上域控。

    界面在打开面板前调它 —— 没装 RSAT 就直接说清楚，别让人点了才发现。
    """
    return _gpo_engine_status()


def gpo_identity_of(client) -> tuple[str, str, str]:
    r"""取「用连接域控的账号跑组策略」所需的 ``(用户, NetBIOS域, 口令)``。

    复用 `password_backend.parse_bind_user` 做归一化 —— **不要在这里自己拆
    ``域\用户``**：域名三种写法（NetBIOS / DNS / 纯用户名）怎么归一，只有那一处
    实现；再拆一遍必然分叉，而分叉的表现是"报用户名或密码错误"这种误导性错误。
    """
    cfg = getattr(client, "cfg", None)
    if cfg is None:
        raise AdToolError(
            "演示模式没有真实凭据，不能用域账号去读组策略。\n"
            "请改用当前 Windows 身份（需要本机已加域且当前账号有权限）。")
    domain, user = _parse_bind_user(getattr(cfg, "bind_user", "") or "",
                                   getattr(client, "domain", "") or "")
    password = getattr(cfg, "password", "") or ""
    if not user or not password:
        raise AdToolError(
            "连接配置里没有可用的账号 / 口令，无法用它读组策略。\n"
            "请断开后重新连接域控（连接时的口令只在内存里保留这一次会话）。")
    return user, domain, password


def _gpo_dc(client) -> str:
    """用哪个域控。留空 ⇒ 让 GPMC 自己挑（`UseAnyDC`）。

    ⚠️ **未加域的机器**通常必须给 —— 它多半解析不到域的 DNS 名。
    """
    return getattr(getattr(client, "cfg", None), "dc_ip", "") or ""


@contextmanager
def _gpo_session(client, use_bind_identity: bool):
    """打开 GPMC 会话，按需套一层身份。

    ⚠️ 退出顺序是**内层会话先关、外层身份后还原** ——
    「先放掉 COM 对象，再 `RevertToSelf`」是硬要求：带着别人的令牌去释放本机
    COM 对象，坏掉的是**整个进程**的 OLE 状态（见 `com_env` 模块说明）。
    `with` 的嵌套天然给出这个顺序，**不要**改成手写 try/finally。
    """
    domain = getattr(client, "domain", "") or ""
    if not domain:
        raise AdToolError(
            "还不知道域名（由 RootDSE 反查），无法读组策略。请先连接域控。")
    dc = _gpo_dc(client)

    if use_bind_identity:
        user, netbios, password = gpo_identity_of(client)
        with _impersonate(user, netbios, password):
            with _gpo_open_session(domain, dc) as session:
                yield session
    else:
        with _gpo_open_session(domain, dc) as session:
            yield session


def list_gpos(client) -> GpoListResult:
    """列出域内**全部** GPO（含没有被链接的）。**只读。**

    🔴 走的是 **LDAP**（`gpo_ldap.py`），**不开口 GPMC 会话** ——
    这条是本轮最要紧的一点：GPMC 要装 RSAT，而「不依赖 RSAT」正是这条
    功能线存在的理由。开着 GPMC 去列，"没装 RSAT 的机器"上连列表都拿不到，
    面板打不开 ⇒ 后面那条自包含的「读设置」在它本该服务的机器上照样够不到。

    ⇒ 也**没有** `use_bind_identity` 这个参数了：LDAP 用的是**已经建好的
    那条连接**，它的身份就是连接域控用的身份，不需要再挂一次凭据。
    （原来那个参数是给 GPMC 用的 —— 它走 DCOM，必须真挂线程令牌。）
    """
    return GpoListResult(domain=getattr(client, "domain", "") or "",
                         dc=_gpo_dc(client),
                         gpos=_ldap_list_gpos(client))


def search_gpos(client, text: str) -> GpoListResult:
    """按显示名模糊搜 GPO。空关键词 = 全部。**只读。**（同样走 LDAP。）"""
    return GpoListResult(domain=getattr(client, "domain", "") or "",
                         dc=_gpo_dc(client),
                         gpos=_ldap_search_gpos(client, text))


def gpo_linked_soms(client, guid: str,
                    use_bind_identity: bool = True) -> list[SomInfo]:
    """某个 GPO **链在哪些位置**（OU / 域 / 站点）。**只读。**

    ⚠️ 方向是反的：`IGPMGPO` 上**没有** `GetGPOLinks`（类型库实测，36 项里没有），
    所以只能拿 GPO 对象去 `SearchSOMs` 反查。
    """
    with _gpo_session(client, use_bind_identity) as session:
        return _gpo_soms_linking_gpo(session, guid)


def som_linked_gpos(client, som_path: str, kind_name: str = "somOU",
                    inherited: bool = False,
                    use_bind_identity: bool = True) -> list[GpoLink]:
    """某个 OU（或域 / 站点）**套了哪些 GPO**，按链接顺序。**只读。**

    ``kind_name``：``"somOU"``（默认）/ ``"somDomain"`` / ``"somSite"`` ——
    用**名字**而不是 `0/1/2`：那些数字是类型库里的值，写死在界面里就等于
    把"它们恰好是这三个数"当成前提，而没有任何东西守着这个前提。

    ``inherited=True`` 时含从上层继承来的 —— 回答"这台机器为什么会应用这条策略"
    要用后者。
    """
    with _gpo_session(client, use_bind_identity) as session:
        return _gpo_links_of_som(session, som_path, kind_name, inherited)


def gpo_report(client, guid: str, fmt: str = "html",
               use_bind_identity: bool = True) -> str:
    """取 GPO 的**设置摘要**（HTML / XML）。**只读。**

    ⚠️ 这一步要读域控的 **SYSVOL（445）** —— 比列 GPO / 看链接更挑网络环境。
    """
    with _gpo_session(client, use_bind_identity) as session:
        return _gpo_generate_report(session, guid, fmt)


@dataclass
class GpoSettingsResult:
    """一次「这个 GPO 改过哪些设置」的结果。

    ⚠️ 下面几件事必须**各自**能看出来，不能混成一句「没读到」——
    它们在界面上长得越像，使用者越会得出相反的结论：

    * `settings.items` 为空 ＋ `settings.empty_files` 非空 ⇒ **确实没配过**（合法结果）；
    * `settings.failed` 非空 ⇒ 某个作用域的文件**读不动**（不是"没配过"）；
    * `admx_policies == 0` ⇒ **ADMX 对照不可用**。那时每条记录都会显示
      "找不到归属"，很容易被读成"这些是第三方设置" ——
      真相是**我们没原料**，不是域里没有。（目录整个不存在会在更早一步
      抛 `AdToolError`，见 `admx_backend.load_catalog`。）
    """

    guid: str = ""
    display_name: str = ""
    domain: str = ""
    gpo_dir: str = ""
    settings: GpoSettings | None = None
    admx_directory: str = ""
    admx_language: str = ""
    admx_policies: int = 0
    admx_failed: int = 0

    @property
    def count(self) -> int:
        """盘上读到的记录条数（**不是**"解释成功"的条数 —— 一条都不能少报）。"""
        return len(self.settings.items) if self.settings is not None else 0

    @property
    def admx_available(self) -> bool:
        """ADMX 对照能不能用。`False` ⇒ 不该拿"找不到归属"下结论。"""
        return self.admx_policies > 0


@_lru_cache(maxsize=4)
def _admx_catalog(directory: str | None, language: str):
    """读 ADMX 目录（带缓存）。

    ⚠️ 原来每点一次要重读 224 个文件（实测 0.28s）—— 磁盘上的 ADMX 是一次
    会话内不会变的本机资料，缓存住没有陈旧风险，`lru_cache` 是标准库。
    目录不存在时 `load_catalog` 会**抛**，异常不进缓存，所以"没装 ADMX"
    每次都能如实报出来（不是第一次报了、后面就静默了）。
    """
    return _admx_load_catalog(directory, language)


@contextmanager
def _gpo_identity(client, use_bind_identity: bool):
    """**只套身份，不开 COM 会话。**

    🔒 这是「改过哪些设置」与其它 GPO 入口的**根本区别**：它读的是 SYSVOL
    里的 `Registry.pol`，**不需要 GPMC、也就不需要 RSAT**。若图省事套用
    `_gpo_session`，就在**没装 RSAT 的机器上凭空多出一个失败点** ——
    而那条路本来正是为了"不依赖 RSAT 也能用"才存在。
    身份仍要套：SYSVOL 是 445 上的共享，匿名连不上。
    """
    if use_bind_identity:
        user, netbios, password = gpo_identity_of(client)
        with _impersonate(user, netbios, password):
            yield
    else:
        yield


def gpo_settings(client, guid: str, label: str = "",
                 admx_directory: str | None = None, language: str = "zh-CN",
                 use_bind_identity: bool = True) -> GpoSettingsResult:
    """读某个 GPO **改过哪些设置**（记录 ＋ 值 ＋ 它属于哪条 ADMX 策略）。**只读。**

    三步，**都不经过 GPMC**：① 域名 × GUID ⇒ 算出 SYSVOL 里的 GPO 目录
    （`gpo_settings.sysvol_gpo_dir`）② 自己按 `[MS-GPREG]` 字节格式解
    `Machine\\Registry.pol` 与 `User\\Registry.pol` ③ 拿本机 ADMX 目录把每条
    记录对回「哪条策略、什么状态」。

    ⚠️ **方向是"从记录出发"**：盘上有什么就报什么，**一条不丢**。对不上 ADMX
    归属的记录**照样列出**并标记"找不到归属" —— 过滤掉才是真的丢数据。

    ⚠️ 仍要读域控的 **SYSVOL（445）**：比列 GPO / 看链接挑网络环境，
    但**不比 `gpo_report` 更挑**（少一个 COM 依赖）。
    """
    domain = getattr(client, "domain", "") or ""
    if not domain:
        raise AdToolError(
            "还不知道域名（由 RootDSE 反查），算不出 SYSVOL 路径。请先连接域控。")
    if not guid:
        raise AdToolError("这条组策略没有 GUID，定位不到它在 SYSVOL 里的目录。")

    # 先算路径：GUID 格式不对会在这一步当场抛，不必等网络超时。
    # ⚠️ `client.sysvol_root` **直接取**，不给 `getattr(..., "")` 兜底：
    #    真身与演示域**都有**这个属性（真域恒为空串 = 按 UNC 约定算）。
    #    兜底的话，"演示域忘了给根目录"会静默退回 UNC，
    #    而那种失败在界面上长得像**权限问题** —— 正是本项目最忌讳的静默。
    gpo_dir = _sysvol_gpo_dir(domain, guid, client.sysvol_root)
    catalog = _admx_catalog(admx_directory, language)

    with _gpo_identity(client, use_bind_identity):
        settings = _read_gpo_settings(catalog, gpo_dir, label)

    return GpoSettingsResult(
        guid=guid, display_name=label, domain=domain, gpo_dir=gpo_dir,
        settings=settings, admx_directory=catalog.directory,
        admx_language=catalog.language, admx_policies=len(catalog.policies),
        admx_failed=len(catalog.failed))


@dataclass
class GpoSecurityResult:
    """一次「这个 GPO 的安全策略长什么样」的结果。

    ⚠️ 三件事必须**各自**看得出来，界面才不会被读反：

    * `security.missing_files` 非空 ⇒ 这条 GPO **没配安全策略**（最常见、
      正常结果，别显示成"读失败"）；
    * `security.failed` 非空 ⇒ 文件**在但读不动**（越权 / 0 字节 / 解析不了）
      ⇒ 那次是「我们什么都没看到」，**不许**显示成"没配过"；
    * `security.cse` ⇒ 这份模板**会不会生效**（`present` / `absent` /
      `unknown`）。`absent` 是一句**别处看不到**的话：文件在、版本号也涨了，
      但 GPC 没登记安全扩展 ⇒ 策略被完全忽略。`unknown` 时不许多说一个字。

    ⚠️ `machine_extension_names` 原样留一份：界面/诊断包要能看见
    「我们是拿哪段属性原文下的结论」，否则无法独立复核。
    """

    guid: str = ""
    display_name: str = ""
    domain: str = ""
    gpo_dir: str = ""
    security: GpoSecurity | None = None
    #: 传给判据的那个 AD 属性原文（`None` = 这次没拿它 ⇒ 结论必为"说不清"）。
    machine_extension_names: str | None = None

    @property
    def count(self) -> int:
        """盘上读到的条目数（**段头 / 注释 / 空行不算** —— 一条都不能少报）。"""
        return self.security.entry_count if self.security is not None else 0


def gpo_security(client, guid: str, label: str = "",
                 machine_extension_names: str | None = None,
                 use_bind_identity: bool = True) -> GpoSecurityResult:
    """读某个 GPO 的**安全策略**（`GptTmpl.inf`：密码 / 锁定 / 审核 / 权限）。**只读。**

    三步，**都不经过 GPMC**（与 `gpo_settings` 同一条路）：
    ① 域名 × GUID ⇒ SYSVOL 里的 GPO 目录 ② 按协议拼
    `MACHINE\\microsoft\\windows nt\\SecEdit\\GptTmpl.inf`（**只有这一条，
    没有用户侧** —— 安全策略是计算机侧扩展）③ 自己解 INF 字节。

    🔴 ``machine_extension_names`` 是 AD 属性 `gPCMachineExtensionNames` 的原文，
    决定「这份模板到底会不会生效」。**默认 `None` ⇒ 结论"说不清"**，
    这是**刻意的保守默认**：读不到就绝不说"你的策略是废的"。
    要拿到确切结论，调用方得把 `GpoInfo.machine_extension_names` 传进来
    （`gpo_ldap` 那条路给的是 `""` 或属性原文；GPMC 那条对照尺给的是 `None`）。

    ⚠️ 仍要读域控的 **SYSVOL（445）**：与 `gpo_settings` 同等挑网络环境。
    """
    domain = getattr(client, "domain", "") or ""
    if not domain:
        raise AdToolError(
            "还不知道域名（由 RootDSE 反查），算不出 SYSVOL 路径。请先连接域控。")
    if not guid:
        raise AdToolError("这条组策略没有 GUID，定位不到它在 SYSVOL 里的目录。")

    # 先算路径：GUID 格式不对会在这一步当场抛，不必等网络超时。
    # ⚠️ `client.sysvol_root` **直接取**（理由同 `gpo_settings`：兜底会把
    #    "演示域忘了给根目录"静默退回 UNC，而那种失败长得像权限问题）。
    gpo_dir = _sysvol_gpo_dir(domain, guid, client.sysvol_root)

    # 🔒 **只套身份、不开 COM 会话** —— 读的是 SYSVOL 上的文件，不需要 RSAT。
    #    套 `_gpo_session` 会在没装 RSAT 的机器上凭空多出一个失败点，
    #    而这条路存在的全部理由就是"不依赖 RSAT 也能用"。
    with _gpo_identity(client, use_bind_identity):
        security = _read_gpo_security(gpo_dir, label, machine_extension_names)

    return GpoSecurityResult(
        guid=guid, display_name=label, domain=domain, gpo_dir=gpo_dir,
        security=security, machine_extension_names=machine_extension_names)


# ============================================================================
# 强制 AD 复制同步 —— 让"刚写的改动"立刻能被别处搜到
# ============================================================================
#
# 症状：新建的用户在**当前操作的域控**上马上能查到，但已加域的文件服务器在
#      「安全 → 选择用户或组」里要等约一小时才搜得到；删除同理（删完短时间
#      内还能搜到 —— 那是**软删除**：对象进了 Deleted Objects，复制到位前
#      GC 上那个对象还在）。详见 `replication.py` 的模块头。
#
# 🔒 为什么放在**任务层**，而不是塞进 `ad_client.create_user` / `delete_object`：
#    同步的粒度是「**一次使用者可见的操作**」，不是「一个对象」。
#    批量删 20 个对象只需要推 **1** 次；挂进 ad_client 会推 **20** 次，
#    而每一次都是几十秒的全域复制流量。所以它必须待在「知道这一整次操作
#    什么时候结束」的那一层，而不是「只知道单个对象」的那一层。
#
# 🔒 为什么不直接写在 `ui_browser` 里：还要读 `client.cfg` / `client.info`
#    （域控名从哪儿来）并落日志，界面层不该碰这些。界面只负责调一次、
#    把结果说出来。

def sync_replication(client) -> SyncOutcome:
    """把这台域控刚写完的改动**立刻推**给它的复制伙伴。**永不抛异常。**

    执行的是 ``repadmin /syncall <域控的DNS名> /AdeP``（开关含义见 `replication`）。

    ⚠️ **三种"没执行"都会如实报出来，不会假装成功**（下一步动作各不相同）：

      * 演示模式 / 已断开（`client.cfg is None`）—— 没有真实域控可推；
      * 本机没装 `repadmin.exe`（RSAT / AD DS 工具）；
      * 拿不到 `repadmin` **认**的域控名 —— 本工具主用例是填 **IP**，而
        `repadmin` **不接受 IP 形式的域控名**（实测一律报「参数错误」）。
        这里会改用 RootDSE 反查到的 `dnsHostName`，再退一步才 PTR 反查；
        都拿不到就**宁可不跑**，也不发一条注定失败的命令。

    ⚠️ **演示模式绝不执行这条命令。** `MockAdClient.IS_MOCK` 是既有的判别旗标
       （`mock_client.py:779`，`tests/test_ui_smoke.py:361` 已经在盯它）。
       为什么不能靠 `cfg is None` 判：演示域 `connect()` 之后
       `cfg` 是**真的 `ConnConfig`**、`info.dns_host_name` 是
       `dc01.<演示域名>`（`mock_client.py:893-896`）—— 两个都拦不住，
       于是演示模式会真的去跑一次 `repadmin`。外部命令有真实副作用，
       宁可不跑。

    ⚠️ 域控名取自 `client.info.dns_host_name`（连接时 RootDSE 反查的结果），
       **不是** `cfg.dc_ip` —— 后者是个 IP，`repadmin` 不认。
    """
    if getattr(client, "IS_MOCK", False):
        detail = "演示模式没有真实域控，不执行 repadmin（外部命令有真实副作用）。"
        _log.info("未执行强制 AD 复制同步：%s", detail)
        return SyncOutcome(reason=_replication.REASON_DEMO, detail=detail)

    cfg = getattr(client, "cfg", None)
    if cfg is None:
        # 「已断开」会落到这里（演示模式已被上面那条拦掉）。不编造具体原因。
        detail = "当前没有已建立的域控连接，不执行复制同步。"
        _log.info("未执行强制 AD 复制同步：%s", detail)
        return SyncOutcome(reason=_replication.REASON_NOT_CONNECTED, detail=detail)

    info = getattr(client, "info", None)
    name, why = _resolve_dc_name(getattr(info, "dns_host_name", "") or "",
                                 getattr(cfg, "dc_ip", "") or "")
    if not name:
        _log.warning("未执行强制 AD 复制同步：%s", why)
        return SyncOutcome(reason=_replication.REASON_NO_NAME, detail=why)

    try:
        outcome = _sync_all(name)
    except Exception as exc:                 # noqa: BLE001
        # ⚠️ 这是"**不许抛**"这个承诺的兑现处，不是兜底盖问题：
        #    `replication.sync_all` 本身设计成永不抛，但它下面还压着
        #    `subprocess`、找不到的 exe、被安全软件拦下的进程 —— 任何一层
        #    出意外都不该把"账号已经建好了"这个事实打断。所以照样**如实报**
        #    （异常类型 + 文案都进 detail 和日志），只是换一条路返回。
        _log.warning("强制 AD 复制同步出现意外错误 dc=%s：%s: %s",
                     name, type(exc).__name__, exc)
        return SyncOutcome(ran=True, dc_name=name, reason=_replication.REASON_ERROR,
                           detail=f"同步时出现意外错误：{type(exc).__name__}: {exc}")

    if outcome.ok:
        _log.info("强制 AD 复制同步成功 dc=%s rc=%s", name, outcome.returncode)
    elif outcome.ran:
        # 🔒 需求点名要求：同步失败必须**留下返回码**，事后才追得动。
        _log.warning("强制 AD 复制同步失败 dc=%s rc=%s 超时=%s 详情=%s 输出=%s",
                     name, outcome.returncode, outcome.timed_out, outcome.detail,
                     outcome.output[:600] or "（空）")
    else:
        _log.warning("未执行强制 AD 复制同步 dc=%s：%s", name, outcome.detail)
    return outcome
