# -*- coding: utf-8 -*-
"""
password_backend.py —— 改密后端（决策 Q1：双后端可切换）

背景（为什么需要两个后端）：

  * **明文 389 改不了密码。** 写 `unicodePwd` 必须走 128 位 TLS/SSL
    （ldap3 文档 + 微软 KB269190），否则报 `0x80072035 LDAP_UNWILLING_TO_PERFORM`。
  * **RPC 通道**（`WinNT://` + SAMR）不需要证书，走 135/445。
    但 `WinNT://` provider **不支持传凭据**（不像 `LDAP://` 有 OpenDSObject），
    所以本机未加入域时，**必须先 LogonUser 模拟身份**才能操作。
  * 因此：RPC 为主（明文环境唯一出路），LDAPS 为备（域控只开 636 时用），
    失败自动降级。

不造轮子：
  * 身份模拟用 pywin32 **官方文档的标准模式**（LogonUser + ImpersonateLoggedOnUser + RevertToSelf）
  * LDAPS 改密用 **`conn.extend.microsoft.modify_password()`** —— 不手写 unicodePwd 编码
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Protocol

from com_env import ensure_apartment
from utils import (
    LDAP_AUTH_CODES,
    AdToolError,
    get_logger,
    hresult_from_ldap_code,
    translate_error,
    translate_ldap_code,
)

__all__ = [
    "BACKEND_RPC",
    "BACKEND_LDAPS",
    "PasswordBackend",
    "RpcPasswordBackend",
    "LdapsPasswordBackend",
    "PasswordBackendChain",
    "parse_bind_user",
    "ntlm_bind_identity",
    "netbios_hint",
    "impersonate",
    "LOGON32_LOGON_NEW_CREDENTIALS",
]

_log = get_logger("password")

BACKEND_RPC = "rpc"
BACKEND_LDAPS = "ldaps"

BACKEND_LABELS = {
    BACKEND_RPC: "RPC（WinNT:// + 身份模拟）",
    BACKEND_LDAPS: "LDAPS（636 + unicodePwd）",
}

#: 只提供"对外网络凭据"，不做本地登录策略校验、不加载用户配置
#: ⚠️ 不要用 INTERACTIVE(2) —— 本机未加域时极易报 0x80070569 ERROR_LOGON_TYPE_NOT_GRANTED
LOGON32_LOGON_NEW_CREDENTIALS = 9
LOGON32_PROVIDER_DEFAULT = 0


def parse_bind_user(bind_user: str, discovered_domain: str = "") -> tuple[str, str]:
    """把三种账号写法拆成 ``(domain, user)``。

    ========================  =============================================
    ``DOMAIN\\user``           ``('DOMAIN', 'user')``   ← NetBIOS 名
    ``user@corp.example.com``  ``('corp.example.com', 'user')``
    ``user``                   ``(discovered_domain, 'user')``  ← 靠反查补齐
    ========================  =============================================
    """
    value = (bind_user or "").strip()
    if not value:
        raise AdToolError("请填写绑定账号。")

    if "\\" in value:
        dom, _, user = value.partition("\\")
        if not dom or not user:
            raise AdToolError("账号格式不正确，应为「域名\\用户名」。")
        return dom, user

    if "@" in value:
        user, _, dom = value.partition("@")
        if not user or not dom:
            raise AdToolError("账号格式不正确，应为「用户名@域名」。")
        return dom, user

    if not discovered_domain:
        raise AdToolError(
            "未能从域控反查域名，无法补全账号。"
            "请把账号写成「域名\\用户名」或「用户名@域名」的形式。"
        )
    return discovered_domain, value


def ntlm_bind_identity(bind_user: str, discovered_domain: str = "") -> str:
    r"""把三种账号写法归一成 **ldap3 NTLM 绑定所要求的** ``域\用户``。

    ========================  =============================================
    ``DOMAIN\user``           原样 —— 域部分由使用者给，按 NetBIOS 名解释
    ``user@corp.example.com`` ``corp.example.com\user``
    ``user``                  ``<反查到的域名>\user``
    ========================  =============================================

    ⚠️⚠️ **必须带反斜杠 —— UPN 形式在 NTLM 下根本走不通。**
    ldap3 的 NTLM 分支有一道硬门禁，账号里没有反斜杠就直接在**客户端**被拦下：

        connection.py:624   if self.user and self.password and len(self.user.split('\\')) == 2:
        connection.py:632       raise LDAPUnknownAuthenticationMethodError('NTLM needs domain\username and a password')
        connection.py:1365  domain_name, user_name = self.user.split('\\', 1)

    也就是 `user@domain` 这样的账号**连一个字节都发不到域控**。
    判决性取证：``tools/probe_ntlm_account_contract.py``。

    ⚠️ 反过来说，`DOMAIN\user` 里的 `DOMAIN` **首选 NetBIOS 名**：
    微软《Network access validation algorithms》写明 NTLMv2 的 salt 带着客户端
    报的域名字符串，域控若不认识这个域名就换用自己的库名算 salt，hash 对不上，
    失败现象是「未知用户名或密码错误」——看起来像密码错，其实错在域名字符串。
    另外两种写法只能拿**反查到的 DNS 域名**顶替（RootDSE 里没有 NetBIOS 名），
    多数域认，万一不认，提示语会引导使用者改填 NetBIOS 形式（见 `netbios_hint`）。
    """
    domain, user = parse_bind_user(bind_user, discovered_domain)
    return f"{domain}\\{user}"


def netbios_hint(bind_user: str) -> str:
    """账号里没写「域\\用户名」时给一句**可执行**的补救提示；写了就返回空串。

    只在绑定失败后追加到错误提示里 —— 成功路径一个字符都不加。
    """
    if "\\" in (bind_user or ""):
        return ""
    return (
        "\n提示：本工具用 NTLM 绑定，客户端要求账号写成「域\\用户名」的形式"
        "（例如 CORP\\zhangsan）。你这儿没写反斜杠，工具已用反查到的域名替你补全；"
        "如果域控不认这个域名（NTLM 会把它报成密码错误），"
        "请改填 NetBIOS 域名的写法。"
    )


# ============================================================================
# 后端接口
# ============================================================================

class PasswordBackend(Protocol):
    """改密后端契约。"""

    name: str
    label: str

    def is_available(self) -> tuple[bool, str]:
        """当前环境/参数下是否可用。返回 ``(可用, 不可用原因)``。"""
        ...

    def set_password(self, sam: str, dn: str, new_password: str) -> None:
        """设置密码。失败抛中文 ``AdToolError``。"""
        ...

    def close(self) -> None:
        ...


# ============================================================================
# 身份模拟装置（改密 与 组策略 两条线共用同一份）
# ⚠️ 2026-09-16：原先这里写的是「改密 与 共享盘 ACL 共用」—— 共享盘那条路已随
#    「操作共享盘」功能整体删除，现在**唯一的落点就是改密**（`RpcPasswordBackend`）。
#    "只有一份实现"这条不变式不变：它是**先有共用者才抽出来的**，共用者走了，
#    抽象留在原地仍然是本模块的资产（别因为"只有一个使用者"就把它拆回去）。
# ============================================================================

def _logon(user: str, domain: str, password: str):
    """`LogonUser`：拿一个域账号令牌。

    **不挂到线程上** —— 挂与不挂是两件事，时机由调用方定（见 `impersonate` 的说明）。
    """
    import win32security  # noqa: PLC0415

    return win32security.LogonUser(
        user, domain, password,
        LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT)


def _revert(token) -> None:
    """还原身份 + 关令牌。

    ⚠️ 调用方有**顺序**责任：**先放掉 COM 对象，再调它**。
    带着别人的令牌去释放本机 ADSI 对象，坏掉的是**整个进程**的 OLE 状态
    （Qt 随后报 `0x8001010d` 并终止进程，详见 `com_env` 的模块说明）。
    """
    import win32security  # noqa: PLC0415

    try:
        win32security.RevertToSelf()
    except Exception:                                  # noqa: BLE001
        _log.warning("RevertToSelf 失败（后续操作可能带着他人令牌）")
    if token is not None:
        try:
            token.Close()
        except Exception:                              # noqa: BLE001
            pass


@contextmanager
def impersonate(user: str, domain: str, password: str):
    """以指定域账号身份执行一段代码。

    **未加入域的本机去碰远程资源**（本工具现存的只有改密一条）必须先把域账号
    令牌挂到当前线程上。这套装置原先**内嵌**在 `RpcPasswordBackend.set_password`
    里；后来要有第二个使用者（原「共享盘 ACL」，2026-09-16 已随功能删除）就得
    复制一份 ⇒ 违反「只有一份实现」，于是抽成了 `_logon` / `_revert`。
    现在共用者只剩改密一个，但**抽出来的形态保留**（它守的是"别复制第二份"，
    不是"必须同时有两个使用者"）。

    ⚠️ **不做串行化**：`ImpersonateLoggedOnUser` 影响的是**当前线程**的令牌。
    可能被多线程并发调用的地方（如批量改密）必须**自己加锁** ——
    `RpcPasswordBackend.set_password` 就是自己 `with self._lock` 的。

    ⚠️ 为什么 `set_password` **不用**这个 `with`：它还有 COM 对象要收尾，
    而顺序必须是「**先放掉 ADSI 对象引用 → 再 `RevertToSelf`**」。
    用 `with` 的话上下文先退出（身份已还原），COM 对象才被回收 —— **顺序反了**。
    """
    token = _logon(user, domain, password)
    try:
        yield
    finally:
        _revert(token)


# ============================================================================
# 后端 A：RPC（WinNT:// + LogonUser 身份模拟）
# ============================================================================

class RpcPasswordBackend:
    """走 SAMR/RPC，**不需要域控证书**，但需要 135/445 可达。

    实现要点：
      1. `LogonUser` 用 `LOGON32_LOGON_NEW_CREDENTIALS` 拿域账号令牌
      2. `ImpersonateLoggedOnUser` 把令牌挂到当前线程
      3. `ADsGetObject("WinNT://<dc_ip>/<sam>,user")` → `SetPassword()`
      4. ``finally`` 里先放掉 ADSI 对象引用，再 `RevertToSelf` + 关句柄。
         **公寓不在这里撤销** —— 它由工作线程持有（见 `com_env`）：撤销会让
         traceback 里还活着的 ADSI 对象悬空，坏掉进程的 OLE 状态，
         后续 Qt 的剪贴板 / 原生对话框报 `0x8001010d` 并直接终止进程
    """

    name = BACKEND_RPC
    label = BACKEND_LABELS[BACKEND_RPC]

    def __init__(self, dc_ip: str, bind_user: str, bind_password: str,
                 domain: str = "", timeout: int = 15):
        self.dc_ip = (dc_ip or "").strip()
        self.bind_user = bind_user
        self.bind_password = bind_password
        self.domain = domain
        self.timeout = timeout
        #: LogonUser/Impersonate 是**进程级、线程级**状态，批量并发时必须串行
        self._lock = threading.RLock()

    def is_available(self) -> tuple[bool, str]:
        if not self.dc_ip:
            return False, "未填写域控 IP"
        try:
            import win32com.adsi  # noqa: F401
            import win32security  # noqa: F401
        except ImportError:
            return False, "RPC 通道需要 pywin32（仅 Windows 可用）"
        try:
            parse_bind_user(self.bind_user, self.domain)
        except AdToolError as exc:
            return False, str(exc)
        if not self.bind_password:
            return False, "未提供绑定账号密码"
        return True, ""

    def set_password(self, sam: str, dn: str, new_password: str) -> None:
        ok, why = self.is_available()
        if not ok:
            raise AdToolError(f"RPC 改密通道不可用：{why}")

        import win32com.adsi  # noqa: PLC0415
        import win32security  # noqa: PLC0415

        domain, user = parse_bind_user(self.bind_user, self.domain)
        token = None
        obj = None          # 提前声明：finally 里要能引用到它

        # 串行化：ImpersonateLoggedOnUser 影响的是**当前线程的令牌**，
        # 多线程并发会互相踩（批量重置密码场景必须加锁）。
        with self._lock:
            # 🔒 公寓由**线程**持有，这里既不 CoInitialize 也不 CoUninitialize。
            #    教科书式的「每次配对开关公寓」会留下一个悬空窗口：撤销之后，
            #    traceback 里还活着的 ADSI 对象一旦被 Release，坏掉的是**整个进程**
            #    的 OLE 状态（Qt 随后报 0x8001010d 并直接终止进程）。
            #    完整理由见 com_env 的模块说明。
            ensure_apartment()
            try:
                token = _logon(user, domain, self.bind_password)
                win32security.ImpersonateLoggedOnUser(token)

                obj = _ads_get_object(f"WinNT://{self.dc_ip}/{sam},user")
                obj.SetPassword(new_password)   # 走 SAMR/RPC，无需 636 证书
                _log.info("RPC 改密成功 sam=%s", sam)
            except AdToolError:
                raise
            except Exception as exc:            # noqa: BLE001
                # 把密码从错误上下文里抹掉，避免泄漏到日志/提示
                err = translate_error(exc, context="重置密码")
                # 顺手**断开 traceback**：异常链握着栈帧，而 `SetPassword` 那一帧的
                # `self` 正是我们的 ADSI COM 对象。断开能让它立刻被回收，而不是
                # 挂到异常对象被 GC 为止（COM 资源早一点还回去总没坏处）。
                exc.__traceback__ = None
                raise err
            finally:
                # 收尾顺序：先放掉 ADSI 对象，再还原身份、关令牌。
                # `obj = None` 改的是**栈帧里的槽位**，而异常 traceback 引用的正是
                # 同一个栈帧对象 —— 所以这一句真的能让 COM 对象立刻释放，
                # 哪怕刚才是带着异常跳到 finally 的。
                try:
                    obj = None
                except Exception:               # noqa: BLE001
                    pass
                # ⚠️ 顺序不可换：**先放掉 ADSI 对象，再还原身份 / 关令牌**。
                #    这里刻意**不用** `with impersonate(...)` —— 那个上下文的
                #    `finally` 会在上面那句 `obj = None` **之前**跑，顺序就反了。
                #    两处调的是同一份 `_logon` / `_revert`，不算第二份实现。
                _revert(token)

    def close(self) -> None:
        pass


def _ads_get_object(path: str):
    """取 ADSI 对象。

    优先用 pywin32 的官方 helper ``win32com.adsi.ADsGetObject``；
    它在老版本上偶尔不稳定，回落到 ``win32com.client.GetObject``。
    """
    try:
        import win32com.adsi
        return win32com.adsi.ADsGetObject(path)
    except Exception:                            # noqa: BLE001
        import win32com.client
        return win32com.client.GetObject(path)


# ============================================================================
# 后端 B：LDAPS（636 + unicodePwd）
# ============================================================================

class LdapsPasswordBackend:
    """走 LDAP over SSL 写 ``unicodePwd``。需要域控有可用证书且 636 放通。

    ⚠️ 明文 389 一定失败（`0x80072035`），所以这里必须是 SSL 或 StartTLS。
    """

    name = BACKEND_LDAPS
    label = BACKEND_LABELS[BACKEND_LDAPS]

    def __init__(self, dc_ip: str, bind_user: str, bind_password: str,
                 domain: str = "", port: int = 636, start_tls: bool = False,
                 timeout: int = 15):
        self.dc_ip = (dc_ip or "").strip()
        self.bind_user = bind_user
        self.bind_password = bind_password
        self.domain = domain
        self.port = port
        self.start_tls = start_tls
        self.timeout = timeout
        self._conn = None

    # ---------- 连接 ----------

    def _connect(self):
        if self._conn is not None:
            return self._conn
        try:
            from ldap3 import NTLM, Server, Connection
        except ImportError as exc:
            raise AdToolError("LDAPS 通道需要 ldap3 依赖。") from exc

        # ⚠️ NTLM 要求「域\用户」形式（UPN 会被 ldap3 在客户端拦下），见
        #    `ntlm_bind_identity` 的说明。这里**不能**拼 UPN。
        identity = ntlm_bind_identity(self.bind_user, self.domain)

        server = Server(
            self.dc_ip, port=self.port,
            use_ssl=not self.start_tls,
            get_info=None,
            connect_timeout=self.timeout,
        )
        # ⚠️ 这条 `Connection(...)` **必须包起来**。它是「底层异常唯一出口」
        #    （`utils.translate_error` 的纪律）在改密后端上最容易漏的一处：
        #    `auto_bind=True` 会在**构造里就真去绑定**，绑定失败抛的是
        #    `LDAPBindError` / `LDAPSocketOpenError` —— 两者**都不是** `AdToolError`。
        #
        #    漏掉的代价不止"多一种异常类型"：`PasswordBackendChain.set_password`
        #    与 `ad_client.create_user` 的步骤②**都只捕 `AdToolError`**
        #    ⇒ 一次绑定失败会**整条绕过建号回滚**，在 AD 里留下一个
        #    「已建、禁用、没密码」的对象，而且**审计里一条记录都没有**
        #    （审计是 `_rollback_user` 写的，它压根没被调用）。
        #    2026-09-17 审查实测：这就是 P0-2 的根因。
        try:
            self._conn = Connection(
                server, user=identity, password=self.bind_password,
                authentication=NTLM, auto_bind=True,
                receive_timeout=self.timeout,
            )
        except AdToolError:
            raise
        except Exception as exc:                  # noqa: BLE001
            # 绑定失败时 ldap3 自己会 unbind 再抛，这里只需**别把它缓存下来**
            # —— 缓存一条坏连接，下一次改密会撞上一个更难懂的错。
            self._conn = None
            raise translate_error(exc, context="建立 LDAPS 连接") from exc
        if self.start_tls:
            try:
                self._conn.start_tls()
            except Exception as exc:              # noqa: BLE001
                # ⚠️ 升级失败时**必须**放弃这条连接：它是「已绑定但仍明文」
                #    的半升级状态 —— 缓存下来复用，下一次改密会撞
                #    0x80072035（明文不允许改密），把真正的证书问题埋掉；
                #    而且没人 close 它，还漏一个 socket。
                try:
                    self._conn.unbind()
                except Exception:                 # noqa: BLE001
                    pass
                self._conn = None
                raise translate_error(
                    exc, context="建立 LDAPS 连接（StartTLS）") from exc
        return self._conn

    def is_available(self) -> tuple[bool, str]:
        if not self.dc_ip:
            return False, "未填写域控 IP"
        try:
            import ldap3  # noqa: F401
        except ImportError:
            return False, "LDAPS 通道需要 ldap3 依赖"
        if not self.bind_password:
            return False, "未提供绑定账号密码"
        return True, ""

    # ---------- 改密 ----------

    def set_password(self, sam: str, dn: str, new_password: str) -> None:
        ok, why = self.is_available()
        if not ok:
            raise AdToolError(f"LDAPS 改密通道不可用：{why}")
        if not dn:
            raise AdToolError("缺少目标对象的 DN，无法通过 LDAPS 改密。")

        conn = self._connect()
        try:
            # ✅ ldap3 官方封装：内部已正确处理「双引号 + UTF-16-LE 编码」
            #    不传 old_password → 走管理员重置（单次 replace）
            result = conn.extend.microsoft.modify_password(dn, new_password)
        except Exception as exc:                 # noqa: BLE001
            raise translate_error(exc, context="重置密码") from exc

        if result is not True:
            # 失败时 ldap3 返回 result 字典（未开启 raise_exceptions）
            code = result.get("result") if isinstance(result, dict) else None
            message = result.get("message") if isinstance(result, dict) else None
            if code is not None:
                # ⚠️ 必须带上同口径的 code：链上靠它判断「认证类错误不降级」。
                #    不带就等于让 LDAPS 的错误一律被当成通道故障去白试下一个后端。
                raise AdToolError(translate_ldap_code(code),
                                  code=hresult_from_ldap_code(code))
            raise AdToolError(f"重置密码失败：{message or result}")
        _log.info("LDAPS 改密成功 sam=%s", sam)

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.unbind()
            except Exception:                    # noqa: BLE001
                pass
            self._conn = None


# ============================================================================
# 后端链（自动降级）
# ============================================================================

class PasswordBackendChain:
    """按顺序尝试多个后端，**主后端失败自动降级**（决策 Q1）。

    :param backends: 有序的后端列表，前者优先
    :param auto_fallback: 是否允许自动降级；False 时只用第一个

    设计约束：
      * **认证类错误不降级**（密码错、账号被锁）—— 换个通道也是一样的错，
        降级只会浪费时间且掩盖真实原因。
      * **通道类错误才降级**（端口不通、协议拒绝、证书问题）。
    """

    #: 这些错误码代表"换个通道也没用"，直接抛给用户。
    #:
    #: 分两部分：**Win32/SAM 侧**手写（下面这几个），**LDAP 侧**由
    #: `utils.LDAP_AUTH_CODES` 换算派生 —— 不这么做就一定会漏，事实上就漏过：
    #: LDAP 19（密码不合策略）长期不在名单里，导致同一个错走 RPC 时正确停下、
    #: 走 LDAPS 时却白跑另一个通道，最后糊成"所有改密通道均失败"。
    _NO_FALLBACK_CODES = {
        "0x800708C5",   # 密码不符合策略（LDAP 侧同义码是 19，见下）
        "0x8007052E",   # 用户名或密码错误
        "0x80072031",   # LDAP 凭据无效
        "0x80070775",   # 账号被锁定
        "0x80072032",   # 权限不足
        "0x80070569",   # 未授予登录类型（配置问题，不是通道问题）
    } | {hresult_from_ldap_code(code) for code in LDAP_AUTH_CODES}

    def __init__(self, backends: list, auto_fallback: bool = True):
        self.backends = list(backends)
        self.auto_fallback = auto_fallback
        self.last_used: str = ""

    @property
    def label(self) -> str:
        return " → ".join(b.label for b in self.backends) or "（无可用后端）"

    def set_password(self, sam: str, dn: str, new_password: str,
                     on_switch=None) -> str:
        """设置密码。返回实际成功使用的后端名。

        :param on_switch: 可选回调 ``fn(from_label, to_label, reason)``，
                          UI 用它提示「已自动切换通道」。
        """
        candidates = self.backends if self.auto_fallback else self.backends[:1]
        if not candidates:
            raise AdToolError("没有配置任何改密通道。")

        errors: list[str] = []
        for index, backend in enumerate(candidates):
            ok, why = backend.is_available()
            if not ok:
                errors.append(f"{backend.label}：{why}")
                continue
            try:
                backend.set_password(sam, dn, new_password)
                self.last_used = backend.name
                if index > 0 and on_switch is not None:
                    on_switch(candidates[index - 1].label, backend.label,
                              errors[-1] if errors else "")
                return backend.name
            except AdToolError as exc:
                if exc.code in self._NO_FALLBACK_CODES:
                    raise                       # 认证/策略类错误，换通道无意义
                errors.append(f"{backend.label}：{exc.message}")
                _log.warning("后端 %s 失败，准备降级：%s", backend.name, exc.message)

        detail = "；".join(errors) if errors else "没有可用的改密通道"
        raise AdToolError(
            f"所有改密通道均失败：{detail}\n"
            "请确认：① 域控 135/445（RPC）或 636（LDAPS）是否放通；"
            "② 绑定账号是否有「重置密码」权限。"
        )

    def close(self) -> None:
        for backend in self.backends:
            try:
                backend.close()
            except Exception:                    # noqa: BLE001
                pass


def build_default_chain(cfg, *, prefer: str = BACKEND_RPC,
                        auto_fallback: bool = True) -> PasswordBackendChain:
    """按连接配置装配默认后端链。

    :param cfg: ``models.ConnConfig``
    :param prefer: 优先使用的通道（``"rpc"`` 或 ``"ldaps"``）
    """
    rpc = RpcPasswordBackend(cfg.dc_ip, cfg.bind_user, cfg.password, cfg.domain)
    ldaps = LdapsPasswordBackend(
        cfg.dc_ip, cfg.bind_user, cfg.password, cfg.domain,
        port=636 if cfg.port == 389 else cfg.port,
        start_tls=(cfg.port == 389 and cfg.use_ssl),
    )
    order = [rpc, ldaps] if prefer == BACKEND_RPC else [ldaps, rpc]
    return PasswordBackendChain(order, auto_fallback=auto_fallback)
