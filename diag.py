# -*- coding: utf-8 -*-
"""diag.py —— 排障采集：让日志**自己能把现场说清楚**

为什么单独一个模块
------------------
使用者连真实域报错时，排障的人**只能看日志**（拿不到屏幕、也问不到现场）。
所以日志必须自己回答四个问题：

  1. **什么环境** —— 工具版本 / Python / 关键依赖 / 是不是打包后的 exe /
     本机是否在域内（这一条决定了「网络到底通不通」的可能性）；
  2. **什么参数** —— IP / 端口 / 是否 SSL / 账号写法 / **归一后的 NTLM 绑定身份**
     （身份写错时会表现成「密码错误」，不记下来就永远在猜）；
  3. **卡在哪一步** —— 端口可达性 → RootDSE 反查 → NTLM 绑定，各步结果与耗时；
  4. **服务端说了什么** —— ldap3 的 code / description / diagnosticMessage、
     Win32 的 HRESULT、异常类型名与堆栈。

本模块**只采集不判断**（判断留在 discovery / ad_client / `utils.translate_error`），
并且**零 Qt 依赖、ldap3 只在函数内惰性导入** —— 保证它在前几步就失败时仍然可用。

两条纪律
--------
* **绝不采集口令**：连长度都不记。日志落盘前另有 `utils._RedactFilter` 兜底，
  但兜底靠的是形态匹配，不是保证 —— 所以源头就不给。
* **不碰本机身份 API**（`win32api.GetUserName` / `GetComputerName`）：
  本项目有一条哨兵测试专门监视这两个调用（历史上有人拿它们冒充绑定身份，
  真域上表现为「密码错误」）。判断本机是否在域内改用**环境变量**。
"""

from __future__ import annotations

import itertools
import os
import platform
import socket
import sys
import threading
import time
from typing import Any, Iterable, NamedTuple

#: 连接排障时最该看的一串端口。
#: 389 LDAP（必需）、636 LDAPS（改密降级用）、135/445 RPC（WinNT 改密通道）、
#: 88 Kerberos（顺带看，能证明它确实是个域控）。
DEFAULT_PORTS: tuple[int, ...] = (389, 636, 135, 445, 88)

_PORT_LABEL = {
    389: "LDAP",
    636: "LDAPS",
    135: "RPC-EPM",
    445: "SMB",
    88: "Kerberos",
}

#: 连接失败后那张端口表的单端口超时。
#: 1.5 秒是"够判断 TIMEOUT"与"别让用户干等"之间的折中：
#: 网段不通时 SYN 会被丢弃，只有超时能判出来，所以不能设得太短。
PORT_PROBE_TIMEOUT = 1.5

_ops = itertools.count(1)
_ops_lock = threading.Lock()


# ============================================================================
# 1. 操作关联号
# ============================================================================

def new_op_id() -> str:
    """给一次操作（连接 / 改密 / 批量）发一个短编号，形如 ``op03``。

    为什么需要：一次连接会写十几行日志，中间还夹着别的线程的输出；
    没有编号就只能靠时间戳猜哪几行属于同一次尝试。

    **不用全局状态绑定归属** —— 编号由调用方自己拿着往下传，
    这也正好符合本项目的纪律（异步回调必须绑定发起请求时的归属，
    禁止读「现在是什么状态」）。
    """
    with _ops_lock:
        n = next(_ops)
    return f"op{n:02d}"


# ============================================================================
# 2. 环境快照
# ============================================================================

def _module_version(dist_name: str) -> str:
    """取已安装发行版版本号；取不到返回 ``"（未装）"``。

    用 importlib.metadata 按**发行版名**取，而不是 import 模块再看 ``__version__``：
    项目里就有过"优先用官方实现但那条路根本不存在"的先例（`ldap3.utils.conv.
    generalized_time_to_datetime`），能导入不等于拿得到版本。
    """
    try:
        from importlib.metadata import PackageNotFoundError, version
        try:
            return version(dist_name)
        except PackageNotFoundError:
            return "（未装）"
    except Exception:                                # noqa: BLE001
        return "?"


def _app_version() -> str:
    try:
        from audit import APP_VERSION
        return APP_VERSION
    except Exception:                                # noqa: BLE001
        return "?"


def _domain_membership() -> str:
    """本机是否在域内 —— **只用环境变量**，不碰 win32api 身份 API。

    ``USERDNSDOMAIN`` 只有加域机器才有；``USERDOMAIN`` 在未加域时等于本机名。
    这条信息直接决定「连不上」的排查方向（域内机器连不上 → 查网络/防火墙；
    域外机器连不上 → 先查是不是压根不在同一个网）。
    """
    dns_domain = (os.environ.get("USERDNSDOMAIN") or "").strip()
    user_domain = (os.environ.get("USERDOMAIN") or "").strip()
    computer = (os.environ.get("COMPUTERNAME") or "").strip()
    if dns_domain:
        return f"已加域（{dns_domain}）"
    if user_domain and user_domain.upper() != computer.upper():
        return f"已加域（{user_domain}，NetBIOS 名）"
    return "未加域（或读不到域环境变量）"


def md4_status() -> str:
    """NTLM 的**硬前提**：MD4 到底能不能算出来。

    为什么值得单独一条进环境快照：ldap3 算 NTLMv2 响应必须有 MD4，它先找
    ``Crypto.Hash.MD4``（pycryptodome），找不到就回落 ``hashlib.new('MD4')`` ——
    而 **Python 3.13 / OpenSSL 3 已经把 MD4 移出内置库**。缺了它，真域上必然报

        ValueError: unsupported hash type MD4

    而**所有用替身的测试都不会红**（假 ldap3 从不真算 NTLM）⇒ 这个依赖是
    "只有真域才能发现"的那一类。所以启动时就把结论记进日志，别等现场猜。

    判据是**真的算一次**，不是读版本号：装着 pycryptodome 但 MD4 被 FIPS
    策略禁掉的情况也是有的。
    """
    try:
        from Crypto.Hash import MD4
        MD4.new(b"").hexdigest()
        return "可用（pycryptodome）"
    except ImportError:
        pass
    except Exception as exc:                         # noqa: BLE001
        return f"装了 pycryptodome 但算不出来：{type(exc).__name__}"
    try:
        import hashlib
        hashlib.new("MD4", b"")
        return "可用（Python 内置 hashlib）"
    except Exception:                                # noqa: BLE001
        return "不可用 ⇒ NTLM 绑定必然失败（修：pip install pycryptodome）"


def env_snapshot() -> dict[str, str]:
    """给排障用的环境快照（纯字符串，**不含任何凭据**）。"""
    frozen = bool(getattr(sys, "frozen", False))
    return {
        "工具版本": _app_version(),
        "运行形态": "打包 exe" if frozen else "源码直跑",
        "程序路径": sys.executable,
        "Python": platform.python_version(),
        "操作系统": f"{platform.system()} {platform.release()} ({platform.version()})",
        "本机名": os.environ.get("COMPUTERNAME") or "（未知）",
        "本机域状态": _domain_membership(),
        "PyQt6": _module_version("PyQt6"),
        "pyqtdarktheme-fork": _module_version("pyqtdarktheme-fork"),
        "ldap3": _module_version("ldap3"),
        "pycryptodome": _module_version("pycryptodome"),
        "pywin32": _module_version("pywin32"),
        "MD4": md4_status(),
    }


def format_env(snap: dict[str, str] | None = None) -> str:
    """把快照压成**一行**（多行会把 app.log 撑得很散，反而不好扫）。"""
    data = snap if snap is not None else env_snapshot()
    return " ".join(f"{k}={v}" for k, v in data.items())


# ============================================================================
# 3. 端口可达性
# ============================================================================

class PortResult(NamedTuple):
    port: int
    ok: bool
    detail: str           # OPEN / REFUSED / TIMEOUT / 其他异常名
    ms: int

    def render(self) -> str:
        label = _PORT_LABEL.get(self.port, "")
        return f"{self.port}({label})={self.detail}/{self.ms}ms"


def probe_port(host: str, port: int, timeout: float | None = None) -> PortResult:
    """单个端口的 TCP 可达性 + 耗时。

    ``REFUSED`` 与 ``TIMEOUT`` 要**分开报**，因为排查方向不同：
      * REFUSED  → 包到了、主机活着、那个端口没人听（服务没起 / 服务换了端口）；
      * TIMEOUT  → 包大概被丢了（网段不通 / 防火墙 DROP / 域控不在线）。
    两者都写「连不上」，等于把一条关键线索扔掉。

    ``timeout=None`` ⇒ 用 `PORT_PROBE_TIMEOUT` 的当前值（见 `probe_ports` 的说明）。
    """
    timeout = PORT_PROBE_TIMEOUT if timeout is None else timeout
    started = time.perf_counter()
    sock = socket.socket()
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        return PortResult(port, True, "OPEN", int((time.perf_counter() - started) * 1000))
    except ConnectionRefusedError:
        return PortResult(port, False, "REFUSED", int((time.perf_counter() - started) * 1000))
    except (TimeoutError, socket.timeout):
        return PortResult(port, False, "TIMEOUT", int((time.perf_counter() - started) * 1000))
    except OSError as exc:
        return PortResult(port, False, type(exc).__name__.upper()[:12],
                          int((time.perf_counter() - started) * 1000))
    finally:
        sock.close()


def probe_ports(host: str, ports: Iterable[int] = DEFAULT_PORTS,
                timeout: float | None = None) -> list[PortResult]:
    """一串端口的可达性（**并行**，结果顺序与入参一致）。

    为什么并行：本函数只在**连接已经失败之后**跑，是给使用者"马上看出方向"
    用的。串行探 6 个端口 × 每个超时 = 最坏 9 秒白等，比不探更让人难受。
    并行后总耗时 ≈ 单个超时，而每个端口的结果与耗时照记不误。

    线程只做阻塞 connect、写完就退（daemon），不共享任何状态，除了那把
    往结果字典里塞值的小锁 —— 不值得为它引入并发抽象。

    ⚠️ `timeout=None` 表示"用 `PORT_PROBE_TIMEOUT` 的**当前值**"，
    而不是把它写进默认参数 —— 默认参数在 `def` 那一刻就求值固定了，
    测试里再改模块常量会**静默失效**（套件白慢两分钟，且一条用例都不会红）。
    这条由 `tests/test_diag.py::TestProbeTimeoutCalibration` 钉住。
    """
    timeout = PORT_PROBE_TIMEOUT if timeout is None else timeout
    wanted = list(dict.fromkeys(ports))
    results: dict[int, PortResult] = {}
    lock = threading.Lock()

    def work(port: int) -> None:
        result = probe_port(host, port, timeout)
        with lock:
            results[port] = result

    threads = [threading.Thread(target=work, args=(p,), daemon=True)
               for p in wanted]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout + 2.0)

    # 兜底：万一某个线程没在预算内回来（socket 超时理论上不会发生），
    # 也要在表里留一行 —— **静默少一行**会让人误以为那个端口没探过。
    return [results.get(p, PortResult(p, False, "NO-REPLY", int(timeout * 1000)))
            for p in wanted]


def format_ports(results: Iterable[PortResult]) -> str:
    """压成一行，形如 ``389(LDAP)=OPEN/12ms 636(LDAPS)=TIMEOUT/2001ms …``。"""
    return " ".join(r.render() for r in results)


def summarize_ports(results: list[PortResult]) -> str:
    """给出一句**结论**（哪一类问题），因为一行数字还要人去读一遍太慢。

    只看 LDAP 那两个端口：它们是本工具的命门。
    """
    ledger = {r.port: r for r in results}
    ldap = [ledger.get(389), ledger.get(636)]
    if all(r is not None and r.ok for r in ldap):
        return "389/636 都通 → 网络层没问题，问题在账号/域名/域策略"
    if all(r is not None and not r.ok and r.detail == "REFUSED" for r in ldap):
        return "389/636 都被拒绝 → 主机活着但 LDAP 服务没在听（换了端口？服务没起？）"
    if any(r is not None and r.ok for r in ldap):
        return "至少一个 LDAP 端口通 → 优先怀疑账号写法/密码/域策略"
    return "389/636 都不通 → 先解决网络（域网络 / VPN / 防火墙），别去查账号"


# ============================================================================
# 4. 异常描述
# ============================================================================

def _flatten(text: Any, limit: int = 300) -> str:
    return " ".join(str(text).split())[:limit]


def describe_exception(exc: BaseException) -> str:
    """把异常里**能用于定位**的部分一次性摊平：

      * 类型名（ldap3 靠类型名区分"连不上 / 绑定被拒 / 超时"）；
      * ldap3 的 ``result`` 字典 —— ``code`` / ``description`` / ``message``
        （真实拒绝原因在这里，异常字符串里往往只有一句泛泛的话）；
      * Win32 的 HRESULT（改密 RPC 通道的错在 ``hresult`` 属性上）；
      * 原始文案 / errno（压平换行、截断）。

    ⚠️ **同一条文案只许出现一次**。踩过：先把 ``args[0]`` 标成 ``args=…``、
    又把 ``str(exc)`` 标成 ``raw=…`` —— 同一条中文长文案在日志里出现两遍，
    一行日志翻倍长，读的人还会以为"失败了两次"。

    ⚠️ **标签必须准确**：``hresult=`` 只给真的有 ``hresult`` 属性的异常
    （pywintypes 的 ``com_error``）；普通 ``OSError`` 的 ``args[0]`` 是 errno，
    标成 hresult 就是把人往错的方向引 —— 本项目的核心教训是
    **宁可少一个字段，也不给会误导方向的标签**。
    反向同理：``com_error`` 的 ``args[0]`` 就是那个 hresult，再标一次
    ``errno=`` 属于「同一个数印两遍 + 名字是错的」，所以有 hresult 时不再出 errno。
    """
    parts = [type(exc).__name__]

    result = getattr(exc, "result", None)
    if isinstance(result, dict):
        for key in ("code", "description", "message", "dn", "type"):
            value = result.get(key)
            if value not in (None, "", 0):
                parts.append(f"{key}={_flatten(value, 120)}")

    # 我们自己那类异常（`utils.AdToolError`）把 LDAP 错误码放在 `.code` 上。
    # ⚠️ **没码时一个字都不写**：踩过 `code=%s` 打出 `code=None` —— 纯噪声，
    #    读日志的人还得停下来判断"这个 None 是没拿到、还是根本拿不到"。
    # ⚠️ 有 `result` 字典时跳过（那份已经报过 code 了；同一个数出现两遍会让人
    #    以为失败了两次）。**两条通道（connect / test_connection）共用这一份。**
    own_code = getattr(exc, "code", None)
    if own_code not in (None, "", 0) and not isinstance(result, dict):
        parts.append(f"code={_flatten(own_code, 60)}")

    args = getattr(exc, "args", ())
    hresult = getattr(exc, "hresult", None)
    has_hresult = isinstance(hresult, int)
    if has_hresult:
        parts.append(f"hresult=0x{hresult & 0xFFFFFFFF:08X}")
    if args and isinstance(args[0], int):
        # ⚠️ 有 hresult 属性的异常（`pywintypes.com_error`）**args[0] 就是那个
        #    hresult 本身**（实测 `exc.hresult == exc.args[0]`）—— 再标一遍
        #    `errno=` 既重复、又错得厉害：读的人会以为另有一个 errno，
        #    而且那个数是负的（-2147022651），像坏掉的数据。
        if not has_hresult:
            parts.append(f"errno={args[0]}")
        if len(args) > 1 and args[1]:
            parts.append(f"text={_flatten(args[1], 160)}")
    elif args:
        text = _flatten(exc, 300)
        if text:
            parts.append(f"raw={text}")

    return " | ".join(parts)


def log_env(logger: Any, tag: str = "启动") -> None:
    """把环境快照写进日志（启动时一条，排障时最先看它）。"""
    logger.info("[%s] 环境 %s", tag, format_env())


# ============================================================================
# 5. 诊断包（一键采集 —— 给「报错了让 AI 看日志」这个闭环用）
# ============================================================================

#: 诊断包里每段取多少行。这些数是**推出来的，不是拍的**：
#:   * app.log 400 行 —— 一次"启动 → 连接 → 做错一件事"大约 60~120 行；
#:     400 行足够覆盖最近两三次尝试，又不会把 5MB 的滚动日志整个塞进来
#:     （整个塞进来，读的人反而找不到重点）。
#:   * crash.log 200 行 —— faulthandler 一份 dump 约 30~60 行，200 行够分辨
#:     "一个进程崩了"还是"崩了好几次"。
#:   * 审计 30 行 —— 审计是**每行一个 JSON**，30 行足够看到最近那几次操作；
#:     它另有专门的查看器（`ui_audit`），包里只做"看得到"。
DIAG_APP_LOG_TAIL = 400
DIAG_CRASH_LOG_TAIL = 200
DIAG_AUDIT_TAIL = 30

#: 审计日志的文件名形态：``audit-YYYY-MM.jsonl``（见 `audit.AuditLog._path`）。
#: 名字里带年月 ⇒ **名字序就是时间序**，不需要 stat 去比 mtime。
_AUDIT_PREFIX = "audit-"
_AUDIT_SUFFIX = ".jsonl"

#: 「使用者看到过的提示」的落盘前缀 —— 与 `ui_widgets.NOTIFY_LOG_PREFIX` **必须一致**。
#: ⚠️ 这里再写一遍字面量是**刻意的**：`diag.py` 是零 Qt 模块，`ui_widgets` 一 import
#:    就会把 PyQt6 拖进来（而诊断包恰恰要在"Qt 都起不来"的场景下可用）。
#:    一致性由 `tests/test_diag_package.py` 钉住（拿两边的常量比一次），
#:    而不是靠"我记得别改"。
_NOTIFY_PREFIX = "[提示]"


def _read_tail_lines(path: str, lines: int) -> list[str]:
    """读**文本**文件尾部若干行。读不到（不存在 / 无权限 / 编码坏）⇒ 返回空表。

    ⚠️ 刻意**不抛异常**：诊断包是在"已经出事了"的时候才生成的 ——
       它自己再因为某个文件读不到而失败，等于把唯一的证据来源也弄没了。
       ``errors="replace"`` 同理：宁可留下 `?`，也要把出错处的上下文读出来。
    """
    if not path or not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return [ln.rstrip("\n") for ln in fh.readlines()[-lines:]]
    except OSError:
        return []


def _notify_lines(app_log_lines: list[str], limit: int = 60) -> list[str]:
    """从 ``app.log`` 的行里抽出「使用者看到过的提示」。

    为什么单独抽成一节：排障时**先对齐现场** —— 使用者说的"它弹了个红的、
    写着 xxx"，必须能在包里一眼找到；埋在 400 行里靠肉眼翻，等于没有。
    """
    return [ln for ln in app_log_lines if _NOTIFY_PREFIX in ln][-limit:]


def _audit_files(audit_dir: str) -> list[str]:
    """审计日志文件的**完整路径**列表（按名字排序 = 按时间排序）。"""
    if not audit_dir or not os.path.isdir(audit_dir):
        return []
    names = [n for n in os.listdir(audit_dir)
             if n.startswith(_AUDIT_PREFIX) and n.endswith(_AUDIT_SUFFIX)]
    return [os.path.join(audit_dir, n) for n in sorted(names)]


def collect_diagnostics(*, log_path: str = "", audit_dir: str = "",
                        app_tail: int = DIAG_APP_LOG_TAIL,
                        crash_tail: int = DIAG_CRASH_LOG_TAIL,
                        audit_tail: int = DIAG_AUDIT_TAIL,
                        now: str | None = None) -> str:
    """把「排障要看的东西」装进**一个文本包**（返回字符串，不写文件）。

    它解决的是这个具体困境：
        使用者在真域里测，出了错，**只能靠文字描述**（拿不到他的屏幕）。
        描述往往不准（"它说我没权限" vs 日志里的 `LDAP_UNWILLING_TO_PERFORM(80)`），
        于是排障变成来回猜。⇒ 让他**点一下**，把可诊断的东西一次性产出来。

    ⚠️ **只采集不判断**（与 `diag` 的其余部分同一条纪律）：包里不放结论，
        因为结论会随现场变，而采集到的事实不会。

    ⚠️ **末尾整包过一次脱敏**（`utils.redact`）：`app.log` 写入时已过
        `_RedactFilter`、审计写入时也脱敏过，这里是**第三道**。
        为什么还做：这个包会被**发出去**（贴给人看、发邮件），
        它是本项目唯一一个"整包离开本机"的东西 ⇒ 多过一道不亏。

    ⚠️ 缺文件**不算失败**：`crash.log` 不存在是**好事**（没崩过），
        包里要写清"这是没有，不是没读到"。
    """
    stamp = now or time.strftime("%Y-%m-%d %H:%M:%S")
    app_lines = _read_tail_lines(log_path, app_tail)
    crash_path = os.path.join(os.path.dirname(log_path), "crash.log") if log_path else ""
    crash_lines = _read_tail_lines(crash_path, crash_tail)

    out: list[str] = []
    add = out.append

    add("=" * 70)
    add("AD 域管理工具 · 诊断包")
    add("=" * 70)
    add(f"生成时间 : {stamp}")
    add(f"程序版本 : {_app_version()}")
    add(f"进程 pid : {os.getpid()}")
    add(f"日志文件 : {log_path or '（不可用）'}")
    add(f"日志目录 : {os.path.dirname(log_path) or '（不可用）'}")
    add("")

    add("----- [1] 环境快照（「先看这一段」）-----")
    for key, value in env_snapshot().items():
        add(f"  {key} = {value}")
    add("")

    add(f"----- [2] 使用者看到过的提示（最近 60 条）-----")
    notify_lines = _notify_lines(app_lines)
    if notify_lines:
        out.extend(notify_lines)
    else:
        add("  （本次运行没有提示行 —— 要么还没点过任何操作，")
        add("    要么报错发生在「更早的一次运行」里，见 [3] 的尾部）")
    add("")

    add(f"----- [3] app.log 尾部（{app_tail} 行）-----")
    if app_lines:
        out.extend(app_lines)
    else:
        add(f"  （读不到 {log_path or '日志文件'}）")
    add("")

    add(f"----- [4] 崩溃记录 crash.log 尾部（{crash_tail} 行）-----")
    if crash_lines:
        out.extend(crash_lines)
    else:
        add("  （没有 crash.log，或它为空 —— 这是【没有崩溃记录】，不是【没读到】）")
    add("")

    add("----- [5] 审计日志 -----")
    files = _audit_files(audit_dir)
    if not files:
        add(f"  （{audit_dir or '（未指定目录）'} 下没有 audit-*.jsonl）")
    else:
        add(f"  目录：{audit_dir}")
        for path in files:
            try:
                size = os.path.getsize(path)
            except OSError:
                size = -1
            add(f"  · {os.path.basename(path)}  {size} 字节")
        latest = files[-1]
        add(f"  最近一份（{os.path.basename(latest)}）的尾部 {audit_tail} 行：")
        out.extend("  " + ln for ln in _read_tail_lines(latest, audit_tail))
    add("")

    add("----- [6] 怎么读这份包 -----")
    add("  1) [1] 的「MD4」不是「可用」⇒ NTLM 绑定必然失败，后面不用看了；")
    add("  2) [1] 的「本机域状态」若是「未加域」⇒ 先确认是不是同一个网段/VPN；")
    add("  3) [3] 里从「最后往前」找「ERROR」—— 第一次出现的那个通常就是现场；")
    add("  4) [2] 用来把「使用者说的那句话」与日志里的行「对齐」；")
    add("  5) [4] 非空说明是「解释器级」崩溃，光看 [3] 是看不出来的。")

    text = "\n".join(out)

    # 第三道脱敏（前两道：写 app.log 时的 `_RedactFilter`、写审计时的 redact）
    try:
        from utils import redact
        text = redact(text)
    except Exception:                                # noqa: BLE001
        # 脱敏拿不到就**别把包发出去**，但也不能让"生成诊断包"这件事失败 ——
        # 在开头加一行显式警告，由人来决定要不要发。
        text = ("⚠️ 本次未能应用脱敏（utils.redact 不可用）—— "
                "发出去之前请自己扫一遍口令。\n" + text)
    return text


def write_diagnostics(dest_dir: str, *, log_path: str = "", audit_dir: str = "",
                      now: str | None = None) -> str:
    """把诊断包写进 ``dest_dir``，返回**完整文件路径**。

    文件名形如 ``诊断包-20260916-103045.txt``：**前缀固定 + 时间到秒**，
    这样"最近一份"按名字排序就能拿到（不依赖 mtime —— 复制粘贴会改 mtime）。

    ⚠️ 这个函数**会抛**（磁盘满 / 无权限）：调用方要给使用者看得见的失败提示。
        与 `collect_diagnostics` 的"不抛"不矛盾 —— 那个是在采集，
        这个是**使用者在场的一个动作**，静默失败比抛更难查。
    """
    os.makedirs(dest_dir, exist_ok=True)
    name = f"诊断包-{time.strftime('%Y%m%d-%H%M%S')}.txt"
    path = os.path.join(dest_dir, name)
    text = collect_diagnostics(log_path=log_path, audit_dir=audit_dir, now=now)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    return path
