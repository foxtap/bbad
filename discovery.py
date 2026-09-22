# -*- coding: utf-8 -*-
"""
discovery.py —— 零先验知识自动发现（T04b）

目标：**使用者只填 IP + 账号 + 密码，工具自己搞清"这是哪个域"。**

机制：AD 默认允许**匿名读取 RootDSE**（任何域都能读）。先不凭据地探一次，
      拿到 ``defaultNamingContext`` / ``dnsHostName`` 等，反推出域名与 BaseDN。

⚠️ ldap3 是**惰性导入**的：本模块的纯函数（域名推导、账号归一化）在没装 ldap3
   的环境里也能 import 和单测。
"""

from __future__ import annotations

from typing import Any

import diag
from models import DomainInfo
from utils import AdToolError, get_logger

__all__ = [
    "domain_from_base_dn",
    "domain_from_host",
    "looks_like_ip",
    "probe",
    "DEFAULT_TIMEOUT",
]

_log = get_logger("discovery")

DEFAULT_TIMEOUT = 5          # 秒

#: 约定走 TLS 的端口。**只用于「给定了端口、没给定协议」时推导 use_ssl。**
#: 绝不能反过来"没给协议就当明文" —— 那会把调用方漏传协议这件事
#: 静默翻译成"用明文去打 TLS-only 端口"，然后按网络层失败给排查方向。
_SSL_PORTS = (636, 3269)
_ROOT_DSE_KEYS = (
    "defaultNamingContext",
    "rootDomainNamingContext",
    "configurationNamingContext",
    "schemaNamingContext",
    "dnsHostName",
    "domainFunctionality",
    "supportedSASLMechanisms",
)


# ============================================================================
# 纯函数（可单测，不需要 ldap3）
# ============================================================================

def looks_like_ip(text: str) -> bool:
    """粗略判断是不是 IP 字面量（IPv4）。

    本工具**只接受 IP**，不接受域名 —— 这样才彻底摆脱 DNS 依赖。
    """
    s = (text or "").strip()
    parts = s.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or not 0 <= int(part) <= 255:
            return False
    return True


def domain_from_base_dn(base_dn: str | None) -> str | None:
    """``DC=corp,DC=example,DC=com`` → ``corp.example.com``

    ⚠️ **只认紧凑形式**（逗号后无空格）。这不是偷懒：本函数的输入**只有**
    `_probe_once` 从 RootDSE 拿到的 `defaultNamingContext`，而真域返回的
    就是紧凑形式。手写风格的 ``DC=corp, DC=example`` 走不到这里 ——
    手填 BaseDN 时域名由使用者直接填进「域名」输入框（`cfg.domain` 优先）。

    账号归一化那条链路在 `password_backend`（`parse_bind_user` /
    `ntlm_bind_identity`），本模块**不再**留同名能力的第二份实现。
    """
    if not base_dn:
        return None
    parts = [
        piece.split("=", 1)[1]
        for piece in str(base_dn).split(",")
        if piece.upper().startswith("DC=") and "=" in piece
    ]
    joined = ".".join(p for p in parts if p).lower()
    return joined or None


def domain_from_host(dns_host_name: str | None) -> str | None:
    """``dc01.corp.example.com`` → ``corp.example.com``（去掉第一个标签）"""
    if not dns_host_name:
        return None
    host = str(dns_host_name).strip().rstrip(".")
    if "." not in host:
        return None
    return host.split(".", 1)[1].lower() or None


# ============================================================================
# 探测
# ============================================================================

def _first(mapping: dict[str, Any], key: str) -> Any:
    """ldap3 的 RootDSE 属性统一是 list，取第一个。"""
    value = (mapping or {}).get(key)
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


def _ldap_communication_errors() -> tuple[type[BaseException], ...]:
    """ldap3 的**通信层**异常族（``LDAPCommunicationError`` 及其全部子类）。

    **只拿基类这一条判据，不抄子类名单**：ldap3 把 socket 层的四种失败
    （open / send / receive / close）全挂在 ``LDAPCommunicationError`` 下面。
    抄名单一定会漏 —— 而漏掉的那个恰恰是命门：``LDAPSocketOpenError``
    **不是** ``OSError`` 的子类（ldap3 2.9.1 实测），而"网络不通"在真域上
    恰恰只会以它的形态出现。所以判据要落在**基类**上，而不是四个类名上。

    ⚠️ 相邻但**不属于**通信层的两个（ldap3 自己的分类如此，不是漏了）：
    ``LDAPResponseTimeoutError``（等回应超时）、``LDAPStartTLSError``。
    本路径也产生不了这两个：连接超时由 ``connect_timeout`` 管，
    走的是 ``LDAPSocketOpenError``；本模块用的是隐式 SSL，不跑 StartTLS。
    """
    try:
        from ldap3.core.exceptions import LDAPCommunicationError
    except ImportError:                              # pragma: no cover
        return ()
    return (LDAPCommunicationError,)


def _is_unreachable(exc: BaseException) -> bool:
    """这个异常说明「**根本没连上**」，而不是「连上了但对方不配合」。

    ============================ 为什么必须区分 ============================
    2026-09-14 实测：域控网络不通（五端口全 timeout）时，旧实现把
    `LDAPSocketOpenError` 也吞掉，于是 `server.info` 仍是 None，最终报出

        「<域控IP>:389 → 可连接但未返回 defaultNamingContext」

    **这句话是假的** —— 一个字节都没连上。更要命的是它给出的出路是
    「若该域禁用了匿名 RootDSE，请手动填写域名与 BaseDN」，于是使用者会去
    手填 BaseDN、怀疑域策略，而真正要查的是**网络/VPN/防火墙**。

    这正是本项目一开始要绕开的那种误诊（ADUC 的「指定的域不存在，或无法联系」）。
    =======================================================================

    判据只有两条，都是**派生**的、不维护名单：

      * ``OSError`` 一族（``ConnectionError`` / ``TimeoutError`` / ``socket``
        的历史别名都是它的子类）—— 裸 socket 层失败；
      * ldap3 的通信层基类（见 `_ldap_communication_errors`）—— ldap3 会把
        socket 失败再包一层，包出来的类型**未必**仍是 ``OSError``。

    判据自检见 ``tests/test_discovery.py::TestUnreachableClassification``：
    逐条遍历 ldap3 里所有 ``*Socket*Error``（动态派生，不手抄），
    并钉住「绑定被拒 / 凭据错」**不算**连不上。
    """
    if isinstance(exc, OSError):
        return True
    return isinstance(exc, _ldap_communication_errors())


def _describe_attempt(exc: BaseException) -> str:
    """把一次探测失败翻译成**可行动**的中文（拿不到原因时才退回异常名）。"""
    if _is_unreachable(exc):
        return "连不上（网络不可达 / 超时 / 防火墙拦截）"
    return type(exc).__name__


#: `_is_unreachable` 的公开别名。
#:
#: `ad_client` 判定「连接失败后要不要补端口表」用的是**同一条判据**，
#: 所以必须有唯一出口 —— 抄一份出来必然分叉（本项目在错误码名单上踩过：
#: 手抄的那份当下是对的，所以行为测试测不出来）。
is_unreachable = _is_unreachable


def bind_rejection_types() -> tuple[type[BaseException], ...]:
    """ldap3 里**「绑定被域控拒绝」**一族（**从模块动态派生，不手抄名单**）。

    为什么单独需要它：这一族的出现**已经证明 TCP 是通的** ——
    连接建立了、请求发出去了、服务器答复了"不接受"。所以此时再去探一遍端口
    纯属白干（还要白等 1.5 秒），而正确的方向是**查账号写法 / 密码 / 域策略**。

    派生判据按类名（ldap3 的命名规律固定）：
      * ``LDAPBind*`` —— ``LDAPBindError`` / ``LDAPBindResponseError`` …
      * ``LDAPInvalid*`` —— ``LDAPInvalidCredentialsResult`` …
      * 含 ``Credential`` 的。

    ⚠️ 与 `_is_unreachable` 是**互斥**关系：socket 层失败由后者负责，
      它们的类名里没有上面的片段，所以不会被误判成"域控拒绝"。
      判据自检见 ``tests/test_diag.py::TestBindRejectionClassification``。
    """
    try:
        from ldap3.core import exceptions as _exceptions
    except ImportError:                                  # pragma: no cover
        return ()
    found = []
    for name, obj in vars(_exceptions).items():
        if not isinstance(obj, type) or not issubclass(obj, BaseException):
            continue
        if name.startswith("LDAPBind") or name.startswith("LDAPInvalid") \
                or "Credential" in name:
            found.append(obj)
    return tuple(found)


def is_bind_rejection(exc: BaseException) -> bool:
    """这次失败是不是「连上了、但域控不接受这次绑定」。"""
    return isinstance(exc, bind_rejection_types())


def _read_rootdse(server) -> None:
    """建立一次**匿名**连接，好让 ldap3 把 RootDSE 填进 ``server.info``。

    ========================== 这个函数为什么必须存在 ==========================
    ldap3 的 ``get_info=DSA`` 是**惰性**的：``Server.__init__`` 只记下"要读 DSA
    信息"，**真正去读**发生在建立 ``Connection`` 的时候。所以——

        server = Server(ip, get_info=DSA)
        server.info          # ← 永远是 None，哪怕域控完全允许匿名读

    **真域实测（2026-09-12，某生产域的一台域控）**：匿名 RootDSE 完全可读，
    一次就拿到了 ``defaultNamingContext``（形状如 ``DC=corp,DC=example,DC=com``）；而"建了 Server 就读 info"
    的旧写法报的是「可连接但未返回 defaultNamingContext」——
    于是**任何域**都反查不到域名/BaseDN，「输入 IP 自动认域」这条核心能力
    在真域上一次都没生效过。

    **为什么测试全绿**：本地 fake 的 ``_FakeServer`` 直接把 ``info`` 给了出来，
    没有模拟这个惰性 —— 典型的「假连接路径」（见 SKILL: ldap-behavioral-test-double）。
    现在 fake 有了 ``lazy=True`` 模式专门复现它。
    ==========================================================================

    * **网络层失败必须往外抛**（见 `_is_unreachable`）：吞掉它会把
      「连不上」伪装成「可连接但未返回 defaultNamingContext」，给出错误的排查方向。
    * 匿名被禁（少部分域）**不在这里抛**：留给调用方按「手动填写域名/BaseDN」处理，
      错误提示里已经写了这条出路。
    * **必须 unbind**：不关就每探一次漏一个 socket（LDAPS StartTLS 那次的教训）。
    """
    from ldap3 import Connection

    conn = None
    try:
        conn = Connection(server, auto_bind=True)
    except Exception as exc:                     # noqa: BLE001
        # ⚠️ 原来这里只记 `type(exc).__name__` —— 那等于把最有用的一半扔掉：
        #    同样是 LDAPSocketOpenError，"timed out"（包被丢，网段/防火墙）
        #    与 "Connection refused"（主机活着、服务没听）的排查方向完全不同。
        #    所以要用 diag.describe_exception 把 args 原文一起记下来。
        if _is_unreachable(exc):
            _log.info("连接域控失败（网络层，一个字节都没连上）：%s",
                      diag.describe_exception(exc))
            raise
        _log.info("匿名绑定未成功，将按「手动填写域名/BaseDN」处理：%s",
                  diag.describe_exception(exc))
    finally:
        if conn is not None:
            try:
                conn.unbind()
            except Exception:                    # noqa: BLE001
                pass


def _probe_once(dc_ip: str, port: int, use_ssl: bool, timeout: int) -> DomainInfo:
    """单次探测。ldap3 惰性导入，未安装时给出中文提示。"""
    try:
        from ldap3 import DSA, Server
    except ImportError as exc:  # pragma: no cover
        raise AdToolError("缺少 ldap3 依赖，请先执行 pip install ldap3。") from exc

    server = Server(
        dc_ip,
        port=port,
        use_ssl=use_ssl,
        get_info=DSA,                    # 只取 RootDSE，不拉 schema（快）
        connect_timeout=timeout,
    )
    # 🔒 光建 Server 不够：`get_info=DSA` 是惰性的，必须真的连一次
    #    （否则 info 恒为 None，真域上任何域都反查不到 —— 详见函数注释）
    _read_rootdse(server)

    info = getattr(server, "info", None)
    if info is None:
        return DomainInfo(dc_ip=dc_ip, use_ssl=use_ssl)

    other = getattr(info, "other", None) or {}
    base_dn = _first(other, "defaultNamingContext")
    host = _first(other, "dnsHostName")

    return DomainInfo(
        dc_ip=dc_ip,
        base_dn=base_dn,
        dns_host_name=host,
        dns_domain=domain_from_base_dn(base_dn) or domain_from_host(host),
        config_dn=_first(other, "configurationNamingContext"),
        schema_dn=_first(other, "schemaNamingContext"),
        root_domain_dn=_first(other, "rootDomainNamingContext"),
        supported_sasl=list(other.get("supportedSASLMechanisms") or []),
        functional_level=str(_first(other, "domainFunctionality") or "") or None,
        use_ssl=use_ssl,
    )


def probe(dc_ip: str, port: int | None = None, use_ssl: bool | None = None,
          timeout: int = DEFAULT_TIMEOUT) -> DomainInfo:
    """**无需凭据**探测域信息。

    策略：
      1. 显式给了 ``port`` → 只试那一种；**协议没给就按端口推**（``636``/``3269`` = TLS，
         其余按明文）—— 推错的代价是"静默走错协议"，所以不推给"明文"这个默认值；
      2. 只给了 ``use_ssl`` → 按协议选默认端口（``636`` / ``389``），只试那一种；
      3. 两者都没给 → 先试 ``389``（明文），失败再试 ``636``（SSL）。
      4. 全部失败 → 抛中文 ``AdToolError``，**且按失败性质给不同的排查方向**：

         | 失败性质 | 文案指向 |
         |---|---|
         | 每次都是**网络层**（一个字节没连上） | 网络 / VPN / 域控在线 / 防火墙 |
         | 连上了但拿不到 RootDSE | 匿名 RootDSE 被禁 → 手动填写域名与 BaseDN |

         ⚠️ 这两类的排查方向相反，**不许混成一条**（2026-09-14 实测踩过：
         网络不通却提示"请手动填写 BaseDN"，把人引向域策略，白跑一趟）。

    典型返回：``DomainInfo(dc_ip='192.0.2.10', base_dn='DC=corp,DC=example,DC=com',
    dns_domain='corp.example.com', dns_host_name='dc01.corp.example.com')``

    ⚠️ 若某域禁用了匿名 RootDSE（极少见），本函数会抛异常；
       调用方应据此把「域名」「BaseDN」两个输入框从只读切换为可填写。
    """
    target = (dc_ip or "").strip()
    if not target:
        raise AdToolError("请填写域控 IP。")
    if not looks_like_ip(target):
        raise AdToolError(
            f"「{target}」不是合法的 IP 地址。本工具只接受 IP，不接受域名"
            "（这样才能完全摆脱 DNS 依赖）。"
        )

    if port is not None:
        # ⚠️ 给定了端口却没给定协议时，**按端口推**，绝不默认成明文。
        #    旧写法是 `bool(use_ssl)` 一走了之 —— 调用方漏传协议时 `bool(None)` 恒为
        #    False ⇒ 勾了 SSL 也会**明文打 636**，反查必失败，然后按"一个字节都没连上"
        #    给排查方向（叫人去查防火墙与域策略）。**方向错的诊断比不报更坏**，
        #    而且这种失败看起来完全像网络问题，能骗很久。
        if use_ssl is None:
            use_ssl = port in _SSL_PORTS
        attempts = [(port, bool(use_ssl))]
    elif use_ssl is not None:
        # 只给了协议、没给端口 ⇒ 按协议选默认端口（别退回"两种都试"）
        attempts = [(636, True)] if use_ssl else [(389, False)]
    else:
        attempts = [(389, False), (636, True)]

    errors: list[str] = []
    #: 每一次尝试都死于**网络层**吗？（"一个字节都没连上"）
    #: 判据取「失败原因」而不是「结果对不对」—— 见 `_describe_attempt`。
    all_unreachable = True
    for attempt_port, attempt_ssl in attempts:
        label = f"{target}:{attempt_port}{' (SSL)' if attempt_ssl else ''}"
        try:
            result = _probe_once(target, attempt_port, attempt_ssl, timeout)
        except AdToolError:
            raise
        except Exception as exc:                     # ldap3 异常种类繁多，统一收口
            reason = _describe_attempt(exc)
            all_unreachable = all_unreachable and _is_unreachable(exc)
            errors.append(f"{label} → {reason}")
            # 用户看到的是 `reason`（中文短语）；日志里额外留**原始异常**
            # （socket 的 timed out / refused 原文），否则排障时只剩一句
            # "网络不可达/超时/防火墙拦截"，等于没说是哪一种。
            _log.info("探测失败 %s：%s ｜ %s", label, reason,
                      diag.describe_exception(exc))
            continue

        if result.ok:
            _log.info("探测成功 %s：domain=%s base_dn=%s",
                      label, result.dns_domain, result.base_dn)
            return result
        all_unreachable = False
        errors.append(f"{label} → 可连接但未返回 defaultNamingContext")

    detail = "；".join(errors) if errors else "无"
    # ⚠️ 两类失败的**排查方向完全相反**，所以文案必须分开（2026-09-14 实测踩过）：
    #    网络不通却提示「请手动填写 BaseDN」→ 使用者去怀疑域策略，白跑一趟。
    if all_unreachable:
        raise AdToolError(
            f"连不上 {target}（已尝试：{detail}）。\n"
            "这不是账号或域名的问题 —— 一个字节都没发到域控。请按顺序确认：\n"
            "① 本机是否在域网络内（VPN 是否连上、网段是否放通）；\n"
            "② 域控 IP 是否填错、域控是否在线；\n"
            "③ 本机到域控的 389 / 636 端口是否被防火墙拦截。"
        )
    raise AdToolError(
        f"无法从 {target} 反查域信息（已尝试：{detail}）。\n"
        "请确认：① IP 是否为域控而非成员服务器；② 389 或 636 端口是否放通；\n"
        "③ 若该域禁用了匿名 RootDSE，请在下方手动填写「域名」与「BaseDN」。"
    )
