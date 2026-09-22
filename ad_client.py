# -*- coding: utf-8 -*-
"""
ad_client.py —— 核心业务层（T07 / T10d / T11 / T12b）

铁律：
  * 本文件**不含任何 UI 代码**。
  * 对外只抛 `AdToolError`，message 必须已是中文。
  * 所有修改类操作**必写审计日志**（含 before / after）。

不造轮子：
  * 解锁     → `conn.extend.microsoft.unlock_account()`
  * DN 转义  → `ldap3.utils.dn.escape_rdn()`
  * 过滤器转义 → `ldap3.utils.conv.escape_filter_chars()`
  * 改密     → 交给 `password_backend`（RPC / LDAPS 双后端）
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any, Iterable

import diag
from audit import (
    OP_ADD_MEMBER,
    OP_CREATE_COMPUTER,
    OP_CREATE_CONTACT,
    OP_CREATE_GROUP,
    OP_CREATE_OU,
    OP_CREATE_USER,
    OP_DELETE,
    OP_DISABLE,
    OP_ENABLE,
    OP_MOVE,
    OP_REMOVE_MEMBER,
    OP_RENAME,
    OP_RESET_COMPUTER,
    OP_RESET_PASSWORD,
    OP_UNLOCK,
    OP_UPDATE,
    AuditLog,
)
from models import (
    KIND_FILTERS,
    PROTECTED_CONTAINERS,
    AttributeChange,
    ConnConfig,
    DeletePlan,
    DirObject,
    DomainInfo,
    ModifyResult,
    ObjectKind,
    OuNode,
    UserRow,
    UserSpec,
    is_attribute_writable,
    verify_changes,
)
from password_backend import (
    BACKEND_RPC,
    PasswordBackendChain,
    build_default_chain,
)
from utils import (
    AdToolError,
    GROUP_SCOPE,
    GROUP_SECURITY_ENABLED,
    LOGON_HOURS_BYTES,
    UF_ACCOUNTDISABLE,
    UF_DONT_EXPIRE_PASSWORD,
    UF_LOCKOUT,
    UF_PASSWD_NOTREQD,
    UF_SERVER_TRUST_ACCOUNT,
    UF_WORKSTATION_TRUST_ACCOUNT,
    USER_UAC_DISABLED,
    USER_UAC_ENABLED,
    ad_filetime_to_dt,
    ad_generalized_time_to_dt,
    datetime_to_ad_filetime,
    dn_depth,
    escape_dn_value,
    first_value,
    format_attr_value,
    get_logger,
    group_type_value,
    has_uac_flag,
    int_bytes_to_int,
    is_descendant_dn,
    normalize_attr,
    parent_of_dn,
    rdn_of,
    set_uac_flag,
    sid_bytes_to_string,
    translate_ldap_code,
    translate_error,
)

def _escape_rdn(value: Any) -> str:
    """转义 DN 里的 RDN 值。

    **不造轮子**：优先用 ``ldap3.utils.dn.escape_rdn``（官方实现）。
    只有在无 ldap3 的环境（离线单测）才回落到 ``utils.escape_dn_value``
    —— 两者由 ``tests/test_utils.py::TestLdap3Parity`` 逐字符比对保证等价。

    为什么必须自己转义：本项目的连接是 ``check_names=False``
    （为了兼容任意域的非标准 schema），此时 ldap3 **不会**自动做
    ``safe_dn`` 净化，不转义就会被 ``LDAP_INVALID_DN_SYNTAX(34)`` 拒绝。
    """
    try:
        from ldap3.utils.dn import escape_rdn
        return escape_rdn("" if value is None else str(value))
    except ImportError:                          # pragma: no cover - 离线环境
        return escape_dn_value(value)

__all__ = ["AdClient", "USER_ATTRIBUTES", "OU_ATTRIBUTES", "USER_FILTER",
           "OBJECT_ATTRIBUTES", "DELETE_SCAN_ATTRIBUTES"]

_log = get_logger("ad_client")

#: 用户列表要拉的属性
USER_ATTRIBUTES = [
    "sAMAccountName",
    "displayName",
    "cn",
    "userAccountControl",
    "msDS-User-Account-Control-Computed",   # 权威的锁定状态（构造属性，LDAP 名带连字符）
    "lockoutTime",
    "pwdLastSet",
    "msDS-UserPasswordExpiryTimeComputed",  # 密码过期时间（AD 算好的，涵盖 PSO）
    "accountExpires",
    "lastLogonTimestamp",
    "distinguishedName",
]

OU_ATTRIBUTES = ["name", "ou", "distinguishedName", "description"]

#: 用户搜索过滤器
#: 用 objectCategory=person 而不是 objectClass=user —— 前者是索引化的单值属性，
#: 大域上快一个量级，且天然排除计算机账号。
USER_FILTER = "(&(objectCategory=person)(objectClass=user))"

#: LDAP 分页大小（AD 默认单次上限 1000）
PAGE_SIZE = 1000

#: 各类对象在列表页要拉的属性。
#:
#: 分类拉而不是用一个万能属性表：组要 `groupType` 才知道作用域，计算机要
#: `dNSHostName`/`operatingSystem`，这些属性对用户是空的 —— 全都要会白白
#: 拉回一堆空值，还会让域控多做无用的 schema 解析。
OBJECT_ATTRIBUTES: dict[str, list[str]] = {
    ObjectKind.USER: USER_ATTRIBUTES + [
        "mail", "description", "whenCreated", "whenChanged",
    ],
    ObjectKind.GROUP: [
        "cn", "sAMAccountName", "description", "groupType",
        "distinguishedName", "whenCreated", "whenChanged", "managedBy",
    ],
    ObjectKind.COMPUTER: [
        "cn", "sAMAccountName", "displayName", "description",
        "userAccountControl", "dNSHostName", "operatingSystem",
        "operatingSystemVersion", "location", "managedBy",
        "lastLogonTimestamp", "whenCreated", "whenChanged",
        "distinguishedName",
    ],
    ObjectKind.CONTACT: [
        "cn", "displayName", "givenName", "sn", "mail", "description",
        "telephoneNumber", "title", "department", "company",
        "distinguishedName", "whenCreated", "whenChanged",
    ],
}

#: 算删除计划时扫描子树要拉的属性（要够判断类型和名字，但不需要业务字段）。
DELETE_SCAN_ATTRIBUTES = [
    "distinguishedName", "cn", "ou", "sAMAccountName", "displayName",
    "objectClass", "userAccountControl", "groupType",
]

# 受保护容器表已挪到 `models.PROTECTED_CONTAINERS` —— 演示域要用同一份，
# 否则会出现"演示里能删、上真域删不掉"的假象。


class AdClient:
    """AD 操作门面。一个实例持有一条连接 + 一个改密后端链。"""

    def __init__(self, audit: AuditLog | None = None,
                 prefer_backend: str = BACKEND_RPC,
                 auto_fallback: bool = True):
        self.audit = audit
        self.prefer_backend = prefer_backend
        self.auto_fallback = auto_fallback

        self.cfg: ConnConfig | None = None
        self.info: DomainInfo | None = None
        self._conn = None
        self._pwd_chain: PasswordBackendChain | None = None
        #: OU 展开箭头探测结果缓存（dn → 是否有子节点）。
        #: 树节点反复折叠展开时不重复打域控 —— 每次探测都是一次 LDAP 往返。
        self._children_cache: dict[str, bool] = {}

        #: SYSVOL 的**根**。
        #:
        #: 真域恒为**空串** —— 空串的含义是"按 UNC 约定算"
        #: （`gpo_settings.sysvol_gpo_dir()` 拼 ``\\<域名>\SYSVOL``）。
        #: 演示域给的是一个**本地目录**（影子 SYSVOL），这样组策略的
        #: 读 / 写 / 版本号整条链在演示模式下走的是同一份实现，
        #: 只差传输介质（本地文件 vs SMB）。
        #:
        #: ⚠️ 真身这里**永远不许**填非空值：填了就意味着这台机器
        #: 把"策略内容"读到了别的地方 —— 那是另一回事，不是本工具该做的。
        self.sysvol_root: str = ""

    # ==================================================================
    # 属性
    # ==================================================================

    @property
    def connected(self) -> bool:
        return self._conn is not None and getattr(self._conn, "bound", False)

    @property
    def base_dn(self) -> str:
        if self.info and self.info.base_dn:
            return self.info.base_dn
        if self.cfg and self.cfg.base_dn:
            return self.cfg.base_dn
        raise AdToolError("尚未确定 BaseDN，请先连接域控。")

    @property
    def domain(self) -> str:
        for source in (self.cfg.domain if self.cfg else "",
                       self.info.dns_domain if self.info else ""):
            if source:
                return source
        return ""

    @property
    def bind_identity(self) -> str:
        r"""实际发给 ldap3 的绑定身份，形如 ``CORP\zhangsan``。

        ⚠️ 是**带反斜杠**的「域\用户」而不是 UPN —— NTLM 的硬要求，
        写成 UPN 会被 ldap3 在客户端直接拦下（见 `ntlm_bind_identity`）。
        """
        from password_backend import ntlm_bind_identity
        return ntlm_bind_identity(self.cfg.bind_user, self.domain)

    # ==================================================================
    # 探测与连接
    # ==================================================================

    @staticmethod
    def probe(dc_ip: str, port: int | None = None, use_ssl: bool | None = None,
              timeout: int = 5) -> DomainInfo:
        """匿名反查域信息（不需要凭据）。见 discovery.py。

        ⚠️ ``use_ssl`` **必须一路转发到 ``discovery.probe``**。这里漏传过一次：
        调用方明明给了 ``port=636``，本函数只转 ``port`` ⇒ ``discovery.probe`` 的
        ``use_ssl`` 恒为 None ⇒ 按端口推之前的老实现把它当明文
        ⇒ **勾了「使用 SSL(636)」却用明文打 TLS-only 端口**，反查必失败，
        然后按"一个字节都没连上"给排查方向（叫人去查防火墙与域策略 —— 方向反了）。
        """
        from discovery import probe
        return probe(dc_ip, port=port, use_ssl=use_ssl, timeout=timeout)

    def test_connection(self, cfg: ConnConfig) -> tuple[bool, str]:
        """连接测试。返回 ``(是否成功, 中文提示)``，**不抛异常**。

        ⚠️ 本方法**不抛异常**，所以失败原因如果只往返回值里塞，日志上就什么都没
        留下 —— 而使用者报"连不上"时，排障的人只有日志可看。因此每条 return
        之前都必须先往日志写一份**带原因**的记录（见 `_log_bind_failure`）。
        """
        from password_backend import netbios_hint
        op = diag.new_op_id()
        _log.info("[%s] 连接测试开始 dc=%s port=%s ssl=%s user=%s（原写法）",
                  op, cfg.dc_ip or "（空）", cfg.port, cfg.use_ssl,
                  cfg.bind_user or "（空）")

        try:
            info = self.probe(cfg.dc_ip,
                              port=cfg.port if cfg.use_ssl else None,
                              # ⚠️ 不勾 SSL 时**传 None，不传 False**：None 走
                              #    "先 389 再 636" 的自动回退（既有行为，保住"只输 IP 也能用"）；
                              #    传 False 会锁死只试明文。勾了就传 True ⇒ 只试 (636, SSL)。
                              use_ssl=True if cfg.use_ssl else None)
        except AdToolError as exc:
            # ⚠️ 与 `connect` 用**同一份** `diag.describe_exception` ——
            #    两条通道各写一种格式的话，同一个错误会在两处显示得不一样，
            #    而排障的人不知道该信哪一条（本项目踩过同类的"两条通道不对等"）。
            #    它也顺手解决了 `code=%s` 打出 `code=None` 这种噪声。
            _log.warning("[%s] 连接测试：RootDSE 反查失败 %s", op,
                         diag.describe_exception(exc))
            return False, exc.message
        except Exception as exc:                 # noqa: BLE001
            _log.error("[%s] 连接测试：反查阶段未预期异常：%s",
                       op, diag.describe_exception(exc), exc_info=True)
            return False, translate_error(exc, context="连接测试").message

        base_dn = cfg.base_dn or info.base_dn
        domain = cfg.domain or info.dns_domain or ""
        if not base_dn:
            _log.warning("[%s] 连接测试：反查不到 BaseDN 且未手填（该域可能禁用匿名 "
                         "RootDSE）", op)
            return False, "未能确定 BaseDN，请在连接设置里手动填写。"

        # ⚠️ 身份**在 try 外面**算：`identity` 在 except 里要用，
        #    如果它是在 try 内、且在此之前就抛了（例如 ldap3 没装），
        #    except 自己会先炸成 NameError，把真正的原因盖掉。
        #    ⚠️ 但"挪出来"会**改变异常路径**：`parse_bind_user` 在这里会抛
        #    「账号里没有域名前缀」（账号既没写域名、反查也没拿到域名）——
        #    原来它被下面的 except 包成 message + NetBIOS 提示，挪出来就裸抛了。
        #    ⇒ 这里必须**原样复刻**旧行为，不能顺手省掉。
        from password_backend import netbios_hint, ntlm_bind_identity
        try:
            identity = ntlm_bind_identity(cfg.bind_user, domain)
        except AdToolError as exc:
            _log.error("[%s] 连接测试：无法确定绑定身份：%s", op, exc.message)
            return False, exc.message + netbios_hint(cfg.bind_user)
        _log.info("[%s] 连接测试绑定身份 identity=%s", op, identity)

        try:
            from ldap3 import Connection, NTLM, Server
            # ⚠️ NTLM 要求「域\用户」（UPN 会被 ldap3 在客户端拦下），见 ntlm_bind_identity
            started = time.perf_counter()
            server = Server(cfg.dc_ip, port=cfg.port, use_ssl=cfg.use_ssl,
                            get_info=None, connect_timeout=5)
            conn = Connection(server, user=identity, password=cfg.password,
                              authentication=NTLM, auto_bind=True,
                              check_names=False, auto_referrals=False,
                              receive_timeout=10)
            conn.unbind()
            _log.info("[%s] 连接测试通过（凭证校验 %.2fs）domain=%s base_dn=%s",
                      op, time.perf_counter() - started, domain, base_dn)
        except AdToolError as exc:
            _log.warning("[%s] 连接测试：绑定阶段 AdToolError %s", op,
                         diag.describe_exception(exc))
            return False, exc.message + netbios_hint(cfg.bind_user)
        except Exception as exc:                 # noqa: BLE001
            self._log_bind_failure(op, cfg, identity, exc, None)
            return False, (translate_error(exc, context="连接测试").message
                           + netbios_hint(cfg.bind_user))

        return True, f"连接成功。域：{domain or '（未知）'}　BaseDN：{base_dn}"

    def _log_bind_failure(self, op: str, cfg: ConnConfig, identity: str,
                          exc: BaseException, elapsed: float | None) -> None:
        """把一次**绑定失败**的现场写全：异常类型/错误码/原文 + 端口可达性 + 堆栈。

        ==================== 端口表为什么必须有 ====================
        没有它，「网络不通」和「凭据被拒」在日志上长得**一模一样**（都是一句
        `LDAPBindError` 或一个超时），而两者的排查方向完全相反：

          * 网络不通 → 查 VPN / 网段 / 防火墙，跟账号没关系；
          * 凭据被拒 → 查账号写法 / 密码 / 域策略。

        2026-09-14 实测踩过这个坑：域控五端口全 timeout，工具却提示
        「请手动填写 BaseDN」，把人引向域策略白跑一趟。端口表让这条判据
        在日志里**自带证据**，不依赖任何人的猜测。
        ==========================================================

        ``identity`` 也一定记下来：NTLM 的 salt 带域名字符串，
        **认错域名会被域控报成「密码错误」** —— 日志里没有归一后的身份，
        这个陷阱永远查不出来。
        """
        when = f"（{elapsed:.2f}s）" if elapsed is not None else ""
        _log.error("[%s] NTLM 绑定失败%s：%s", op, when, diag.describe_exception(exc))
        _log.error("[%s] 本次绑定身份 identity=%s（原写法 user=%s）",
                   op, identity, cfg.bind_user or "（空）")
        self._log_direction(op, cfg, exc)
        _log.error("[%s] 绑定异常堆栈：", op, exc_info=True)

    @staticmethod
    def _ports_for(cfg: ConnConfig) -> tuple[int, ...]:
        """要探的端口：**使用者配置的那个排在最前**（可能是非标准端口，
        先看它），后面接标准五连；重复的去掉。
        """
        return tuple(dict.fromkeys((cfg.port,) + diag.DEFAULT_PORTS))

    def _log_direction(self, op: str, cfg: ConnConfig, exc: BaseException) -> None:
        """写一条「**往哪个方向查**」，并把证据一起留下。

        三级判据，从"不用探"到"必须探"：

          1. **绑定被拒**（`discovery.is_bind_rejection`）—— 请求已经打到域控并被
             答复 ⇒ TCP 是通的。此时**不去探端口**（白等 1.5 秒、也拿不到新信息），
             直接指出方向：查账号写法 / 密码 / 域策略。这一步省掉的是使用者
             连接失败后**最想快点看到答案**的那几秒。
          2. **网络层失败**（`discovery.is_unreachable`）—— 一个字节没连上，
             探端口表把「主机活着但服务没听（REFUSED）」和「包被丢（TIMEOUT）」
             分开，这两种的出路完全不同。
          3. **认不出来**（既不是绑定被拒、也不是网络层，例如替身/第三方抛的
             普通异常）—— 也探一次：信息不足时，宁可多花 1.5 秒也别少一条证据。

        判据用 `discovery` 的公开函数，**不在这里另抄一份名单** —— 同一条纪律
        在两处各写一遍，早晚会分叉。
        """
        from discovery import is_bind_rejection, is_unreachable

        if is_bind_rejection(exc):
            _log.error("[%s] 方向：TCP 已连通、由域控拒绝绑定 ⇒ 查账号写法/密码/域策略，"
                       "不必查网络（故不探端口）", op)
            return

        why = "网络层失败" if is_unreachable(exc) else "失败性质不明"
        try:
            results = diag.probe_ports(cfg.dc_ip, ports=self._ports_for(cfg))
        except Exception as port_exc:            # noqa: BLE001
            _log.warning("[%s] 端口可达性探测自身失败：%s",
                         op, type(port_exc).__name__)
        else:
            _log.error("[%s] 方向：%s ⇒ 端口可达性 %s ⇒ %s",
                       op, why, diag.format_ports(results),
                       diag.summarize_ports(results))

    @staticmethod
    def _no_base_dn_message(probe_failure: AdToolError | None) -> str:
        """反查不到 BaseDN 时给使用者看的话 —— **两种成因的出路完全相反，不许混。**

        ============================ 踩过两次 ============================
        2026-09-14：域控五端口全 timeout，`probe` 已经给出正确方向
        （「这不是账号或域名的问题 —— 一个字节都没发到域控，先查网络」），
        但 `connect` 把这条信息**丢掉**，换成

            「无法自动反查 BaseDN（该域可能禁用了匿名 RootDSE）」……

        使用者于是去怀疑域策略、手填 BaseDN —— 白跑一趟。09-14 只修了
        `discovery` 那一层；这一层是 2026-09-15 用真实现场（本机连不上域控）
        复现演练时才发现的 ⇒ **同一条纪律要在每一层上对等，别只修看得见的那层。**

        ⇒ 判据只有一条：**`probe` 失败过就沿用它的原因**（它做过网络/绑定的分级）；
          只有「`probe` 成功却没返回 defaultNamingContext」才提匿名 RootDSE。
        ==================================================================

        ⚠️ **本方法必须留在类级别。** 它一度被插进 `connect()` 的函数体中间
        （`@staticmethod` 那行缩进 4 格 ⇒ 其后整个 `connect` 的剩余部分都变成
        本方法里 `return` 之后的死代码，`connect` 探完 RootDSE 就返回 `None`，
        **一个连接都不建**，而 `compileall` 照样通过）。
        这条由 `tests/test_source_hygiene.py` 静态钉住：任何函数体里
        **无条件 `return`/`raise` 之后还有同级语句**一律判违规。
        """
        if probe_failure is not None:
            return (probe_failure.message
                    + "\n\n（若网络与账号都已确认无误，也可以在下方手动填写"
                      "「域名」与「BaseDN」后重试。）")
        return ("无法自动反查 BaseDN（该域可能禁用了匿名 RootDSE）。"
                "请在连接设置里手动填写「域名」与「BaseDN」。")

    def connect(self, cfg: ConnConfig) -> DomainInfo:
        """建立长期连接。返回探测到的域信息。

        ==================== 日志纪律（排障靠它，不许省） ====================
        使用者连真实域失败时，**现场只有日志**。所以本方法逐步留痕，且都带同一个
        ``op`` 编号便于把十几行串成一次尝试：

          1. **连接开始** —— IP / 端口 / SSL / 账号**原写法** / 手填的域名与 BaseDN；
          2. **RootDSE 反查** —— 成功（域名 + BaseDN + 功能级别 + 耗时）或失败原因。
             ⚠️ 反查失败**不致命**（允许手填继续），所以旧实现用的是
             `except AdToolError: info = DomainInfo(...)` —— 静默兜底，
             日志里**一个字都没有** ⇒「为什么反查不到」无从判断；
          3. **NTLM 绑定** —— 归一后的绑定身份（`域\\用户`）+ 耗时；
          4. **失败时**补一张端口可达性表（见 `_log_bind_failure`）。

        🔒 **口令一个字都不进日志**（连长度都不记）。日志落盘前另有
        `utils._RedactFilter` 兜底，但那是形态匹配、不是保证 ⇒ 源头就不给。
        ===================================================================
        """
        op = diag.new_op_id()
        started = time.perf_counter()
        _log.info("[%s] 连接开始 dc=%s port=%s ssl=%s user=%s（原写法）"
                  " 手填 domain=%s base_dn=%s",
                  op, cfg.dc_ip or "（空）", cfg.port, cfg.use_ssl,
                  cfg.bind_user or "（空）",
                  cfg.domain or "（留空→自动反查）",
                  cfg.base_dn or "（留空→自动反查）")

        self.disconnect()
        if not cfg.dc_ip:
            _log.warning("[%s] 中止：未填写域控 IP", op)
            raise AdToolError("请填写域控 IP。")
        if not cfg.bind_user:
            _log.warning("[%s] 中止：未填写绑定账号", op)
            raise AdToolError("请填写绑定账号。")
        if not cfg.password:
            _log.warning("[%s] 中止：未填写绑定账号密码", op)
            raise AdToolError("请填写绑定账号密码。")

        # 1) 先探测，补全域名与 BaseDN（「只输 IP」的关键）
        probe_failure: AdToolError | None = None
        probe_started = time.perf_counter()
        try:
            info = self.probe(cfg.dc_ip,
                              port=cfg.port if cfg.use_ssl else None,
                              # ⚠️ 不勾 SSL 时**传 None，不传 False**：None 走
                              #    "先 389 再 636" 的自动回退（既有行为，保住"只输 IP 也能用"）；
                              #    传 False 会锁死只试明文。勾了就传 True ⇒ 只试 (636, SSL)。
                              use_ssl=True if cfg.use_ssl else None)
        except AdToolError as exc:
            # 探测失败不致命：允许使用者手填 base_dn / domain 继续。
            # ⚠️ 但不能静默 —— 失败原因必须落进日志（网络不通 / 匿名被禁 的出路相反）。
            #    code 只在有值时才写：`code=None` 纯属噪声。
            probe_failure = exc
            info = DomainInfo(dc_ip=cfg.dc_ip)
            _log.warning("[%s] RootDSE 反查失败（%.2fs）%s", op,
                         time.perf_counter() - probe_started,
                         diag.describe_exception(exc))
        else:
            _log.info("[%s] RootDSE 反查成功（%.2fs）host=%s domain=%s base_dn=%s "
                      "功能级别=%s",
                      op, time.perf_counter() - probe_started, info.dns_host_name,
                      info.dns_domain, info.base_dn, info.functional_level)

        if cfg.base_dn:
            info.base_dn = cfg.base_dn
        if cfg.domain:
            info.dns_domain = cfg.domain
        if not info.base_dn:
            ports = None
            try:
                ports = diag.probe_ports(cfg.dc_ip, ports=self._ports_for(cfg))
            except Exception:                     # noqa: BLE001
                pass
            if ports is not None:
                _log.error("[%s] 中止：反查不到 BaseDN 且未手填。端口可达性 %s ⇒ %s",
                           op, diag.format_ports(ports), diag.summarize_ports(ports))
            else:
                _log.error("[%s] 中止：反查不到 BaseDN 且未手填", op)
            raise AdToolError(
                self._no_base_dn_message(probe_failure),
                code=(probe_failure.code if probe_failure is not None else ""),
            )

        # 2) 建连接
        # ⚠️ import 与「绑定身份」都放在 try **外面**：
        #    它们在 except 里要用（兜底文案要拼 netbios_hint、日志要报 identity）。
        #    原来 import 在 try 内 ⇒ 「ldap3 没装」时 except 里那句
        #    `netbios_hint(...)` 先抛 NameError，真正的"缺少依赖"被自己的兜底
        #    盖掉 —— 正是本项目最忌讳的那类兜底。
        from password_backend import netbios_hint, ntlm_bind_identity
        # ⚠️ NTLM 要求「域\用户」，**不能**拼 UPN：ldap3 有硬门禁
        #    （connection.py:624 `len(self.user.split('\\')) == 2`），
        #    账号里没有反斜杠就在客户端被拦下，一个字节都发不到域控。
        #    详见 password_backend.ntlm_bind_identity。
        #    ⚠️ 这里抛的 AdToolError（「账号里没有域名前缀」）**必须原样包上
        #    NetBIOS 提示再往外抛** —— 旧实现是在下面的 except 里做的；
        #    把身份挪到 try 外面时如果忘了复刻，异常路径就悄悄变了。
        try:
            identity = ntlm_bind_identity(cfg.bind_user, info.dns_domain or "")
        except AdToolError as exc:
            _log.error("[%s] 中止：无法确定绑定身份：%s", op, exc.message)
            raise AdToolError(exc.message + netbios_hint(cfg.bind_user),
                              code=exc.code) from exc
        # 记下**归一后的身份**：NTLM 的 salt 带域名字符串，**认错域名会被域控
        # 报成「密码错误」** —— 日志里没有这一行，这个陷阱在真域上永远查不出来。
        # ⚠️ 只罗列事实（最终身份 / 原写法 / 反查到的域名），**不写"域名字符串
        #    来自哪里"这种推断** —— 来源由账号写法决定（`域\用户` 原样、
        #    `用户@域` 取后缀、纯用户名才用反查的域名），推断句一旦写错，
        #    日志就会把人引向错误方向，比不写更糟。
        _log.info("[%s] NTLM 绑定身份 identity=%s（原写法 user=%s；"
                  "反查到的域名=%s）",
                  op, identity, cfg.bind_user or "（空）",
                  info.dns_domain or "（无）")
        bind_started = time.perf_counter()
        try:
            from ldap3 import Connection, NTLM, Server
            server = Server(cfg.dc_ip, port=cfg.port, use_ssl=cfg.use_ssl,
                            get_info=None, connect_timeout=10)
            conn = Connection(
                server, user=identity, password=cfg.password,
                authentication=NTLM, auto_bind=True,
                # check_names=False：任意域（含老域/非标准 schema）都能跑，
                # 属性值我们自己用 utils 做防御性转换。
                check_names=False,
                auto_referrals=False,          # 单域环境不追引用
                receive_timeout=30,
                raise_exceptions=False,
            )
        except Exception as exc:                 # noqa: BLE001
            self._log_bind_failure(op, cfg, identity, exc,
                                   time.perf_counter() - bind_started)
            err = translate_error(exc, context="连接")
            raise AdToolError(err.message + netbios_hint(cfg.bind_user)) from exc

        self._conn = conn
        self.cfg = cfg
        self.info = info
        self._children_cache.clear()
        self.cfg.domain = self.cfg.domain or (info.dns_domain or "")
        self.cfg.base_dn = self.cfg.base_dn or (info.base_dn or "")

        # 3) 装配改密后端链
        self._pwd_chain = build_default_chain(
            cfg, prefer=self.prefer_backend, auto_fallback=self.auto_fallback)
        _log.info("[%s] 改密后端链已装配 prefer=%s auto_fallback=%s",
                  op, self.prefer_backend, self.auto_fallback)

        # 4) 审计上下文（多域通用工具，必须记清操作的是哪台域控）
        if self.audit is not None:
            self.audit.bind_context(dc_ip=cfg.dc_ip, domain=self.domain,
                                    operator=self.bind_identity)

        _log.info("[%s] 已连接 dc=%s domain=%s base_dn=%s（合计 %.2fs）",
                  op, cfg.dc_ip, self.domain, info.base_dn,
                  time.perf_counter() - started)
        return info

    def disconnect(self) -> None:
        dc = ""
        if self.cfg is not None:
            dc = self.cfg.dc_ip or ""
        if self._pwd_chain is not None:
            self._pwd_chain.close()
            self._pwd_chain = None
        if self._conn is not None:
            try:
                self._conn.unbind()
            except Exception:                    # noqa: BLE001
                pass
            self._conn = None
        self._children_cache.clear()
        self.info = None
        self.cfg = None
        if dc:
            # 记一条断开（排障时用来切分"哪一段是上一次连接"）
            _log.info("已断开连接 dc=%s", dc)

    def _ensure(self) -> None:
        if self._conn is None:
            raise AdToolError("尚未连接域控，请先建立连接。")

    # ==================================================================
    # 底层搜索
    # ==================================================================

    def _paged_search(self, base: str, search_filter: str, scope: str,
                      attributes: Iterable[str],
                      limit: int | None = None) -> list[dict[str, Any]]:
        """带分页的搜索，返回原始 response 条目列表。

        为什么读原始 response 而不是 `conn.entries`：
          任意域的 schema 差异大，`entries` 会做 schema 校验并可能静默丢属性；
          原始条目 + `utils.normalize_attr` 的防御性转换更稳。

        ``limit`` 会在攒够条数后**提前跳出分页循环** —— 不是为了省内存，
        而是为了不再向域控要后续页：一个几万人的域，把子树搜索结果全拉回来
        会白白压满连接和内存，而界面只需要前面这些。
        """
        self._ensure()
        from ldap3 import LEVEL, SUBTREE

        scope_map = {"LEVEL": LEVEL, "SUBTREE": SUBTREE}
        results: list[dict[str, Any]] = []
        cookie: bytes | None = None
        guard = 0

        while True:
            guard += 1
            if guard > 1000:                     # 防御死循环
                _log.warning("分页搜索超过 1000 轮，强制中断")
                break
            ok = self._conn.search(
                search_base=base, search_filter=search_filter,
                search_scope=scope_map.get(scope, LEVEL),
                attributes=list(attributes),
                paged_size=PAGE_SIZE, paged_cookie=cookie,
            )
            # ⚠️ 不能写 `if not ok: raise` —— 空结果时 ldap3 也返回 False。
            #    判据交给 `_report_search`（按结果码判）。
            self._report_search(ok, "查询")
            for item in (self._conn.response or []):
                if item.get("type") == "searchResEntry":
                    results.append(item)
                    if limit is not None and len(results) >= limit:
                        return results

            cookie = self._extract_cookie()
            if not cookie:
                break
        return results

    def _extract_cookie(self) -> bytes | None:
        try:
            controls = (self._conn.result or {}).get("controls") or {}
            paged = controls.get("1.2.840.113556.1.4.319") or {}
            value = paged.get("value") or {}
            return value.get("cookie") or None
        except (AttributeError, TypeError):
            return None

    def _raise_from_result(self, context: str) -> None:
        """按 ``conn.result`` 抛错。

        ⚠️ 实现**委托**给 `_result_error`，别在这里重写一遍 ——
        同一件事写两份的结果是：一份带 ``code``、一份不带，于是
        「连接级故障（52/81）要立即中止批量」这条纪律只在部分入口生效。
        这里原来就是丢码的那一份。
        """
        raise _result_error(self._conn, context)

    def _report_search(self, ok: bool, context: str) -> None:
        """``conn.search()`` 返回 ``False`` 时，判断**该不该**当成失败抛错。

        ⚠️ **ldap3 的 ``search()`` 在「一条都没命中」时也返回 ``False``** ——
        ``core/connection.py:861`` 的判定是::

            return_value = True if self.result['type'] == 'searchResDone' \\
                                 and len(response) > 0 else False

        而这时 ``result['result']`` 仍然是 ``0``（``LDAP_SUCCESS``）。

        后果（**真域实测**，2026-09-15）：所有「空容器 / 空部门 / 没有匹配对象」的
        搜索都被当成失败，报出 **「LDAP 操作失败（结果码 0）」** —— 一句
        **自相矛盾**的文案（0 就是成功），把真正原因整个藏起来。
        使用者看到的现象是「点开部门看不到人，只看到报错」。

        ⇒ **判据只能是结果码**，不是 ``search()`` 的返回值。
        全局唯一判据，所有 ``conn.search(...)`` 调用点共用（只改一处等于没改）。
        `tools/probe_ldap3_empty_search.py` 是这条结论的判决实验。
        """
        if ok:
            return
        result = getattr(self._conn, "result", None) or {}
        try:
            code = int(result.get("result"))
        except (TypeError, ValueError):
            code = None
        if code != 0:                      # 拿不到结果码(None)也按失败处理，保守
            self._raise_from_result(context)

    def _get_attribute(self, dn: str, attribute: str) -> str | None:
        """按 DN 读单个属性（BASE 搜索），返回**文本视图**；属性缺失 ⇒ ``None``。

        用于取操作前的 before 值。

        ⚠️ 走 `_attr_text`（即优先 `raw_attributes`）而不是裸读 `attributes`：
        这里的值会被 `_safe_int` 拿去算 `userAccountControl` / `lockoutTime`
        的新值 —— **读错一个数就会写坏账号**（详见 `_raw_first` 的说明）。
        返回**文本**而不是裸 `bytes`，是为了让审计里的 ``before`` 直接可读。
        """
        self._ensure()
        from ldap3 import BASE
        ok = self._conn.search(search_base=dn, search_filter="(objectClass=*)",
                               search_scope=BASE, attributes=[attribute])
        self._report_search(ok, "读取属性")
        if not self._conn.response:
            raise AdToolError("对象不存在或已被删除，请刷新后重试。")
        return _attr_text(self._conn.response[0], attribute)

    # ==================================================================
    # 浏览：OU 树与用户列表
    # ==================================================================

    def list_child_ous(self, parent_dn: str) -> list[OuNode]:
        """列出一级子 OU（懒加载用，不要 SUBTREE）。"""
        raw = self._paged_search(parent_dn, "(objectClass=organizationalUnit)",
                                 "LEVEL", OU_ATTRIBUTES)
        nodes: list[OuNode] = []
        for entry in raw:
            attrs = entry.get("attributes") or {}
            dn = entry.get("dn") or normalize_attr(attrs.get("distinguishedName"))
            name = normalize_attr(attrs.get("ou")) or normalize_attr(attrs.get("name"))
            nodes.append(OuNode(
                name=name or dn,
                dn=dn,
                has_children=self._ou_has_children(dn),
                description=normalize_attr(attrs.get("description")),
            ))
        nodes.sort(key=lambda n: n.name.lower())
        return nodes

    def _ou_has_children(self, dn: str) -> bool:
        """探测是否有子对象（决定树节点是否显示展开箭头）。

        代价：每个 OU 一次 LDAP 往返。已加缓存，折叠/展开不重复打域控。
        """
        cached = self._children_cache.get(dn)
        if cached is not None:
            return cached
        result = False
        try:
            from ldap3 import LEVEL
            ok = self._conn.search(
                search_base=dn,
                # 四类业务对象 + OU 都算"有子节点"。
                # ⚠️ 不能只写 objectCategory=person —— 计算机的
                # objectCategory=computer，纯计算机的 OU（如「工作站」）
                # 会没有展开箭头，点进去却有数据，看着像工具坏了。
                search_filter="(|(objectClass=organizationalUnit)"
                              "(objectCategory=person)"
                              "(objectClass=group)"
                              "(objectClass=computer))",
                search_scope=LEVEL, attributes=["distinguishedName"],
                size_limit=1)
            # ⚠️ 这里**故意**直接用 `ok`：ldap3 在「一条都没命中」时返回 False，
            #    而"没有子节点"本来就应该给出 False ⇒ 这个用法**恰好是对的**，
            #    不要去套 `_report_search`（那样反而会把"空"当失败抛错）。
            #    真失败（结果码非 0）同样落到 False，而 `has_children` 只用来
            #    决定要不要画展开箭头 ⇒ 保守取 False 无害。
            result = bool(ok and self._conn.response)
        except Exception:                        # noqa: BLE001
            result = False
        self._children_cache[dn] = result
        return result

    def invalidate_tree_cache(self) -> None:
        """新建 OU / 用户后调用，让树重新探测展开箭头。"""
        self._children_cache.clear()

    def list_users(self, ou_dn: str, subtree: bool = False,
                   limit: int | None = None) -> list[UserRow]:
        """列出该容器下的用户。

        ``subtree=False``（默认）只列**本容器直属**用户，不含子 OU ——
        与 ADUC 点开一个 OU 看到的一致。
        ``subtree=True`` 递归整个子树，用于「整个域 / 某部门及其下级」这种
        想一次看全的场景。此时建议同时给 ``limit``，避免大域拉回几万条。
        """
        raw = self._paged_search(ou_dn, USER_FILTER,
                                 "SUBTREE" if subtree else "LEVEL",
                                 USER_ATTRIBUTES, limit=limit)
        return [self._to_user_row(entry) for entry in raw]

    def search_users(self, keyword: str, base_dn: str | None = None,
                     limit: int = 500) -> list[UserRow]:
        """按关键字全目录搜用户（账号名/显示名/姓名）。"""
        from ldap3.utils.conv import escape_filter_chars
        key = escape_filter_chars((keyword or "").strip())
        if not key:
            return []
        pattern = f"(|(sAMAccountName=*{key}*)(displayName=*{key}*)"
        pattern += f"(cn=*{key}*)(mail=*{key}*))"
        raw = self._paged_search(base_dn or self.base_dn,
                                 f"(&{USER_FILTER}{pattern})", "SUBTREE",
                                 USER_ATTRIBUTES)
        return [self._to_user_row(e) for e in raw[:limit]]

    @staticmethod
    def _to_user_row(entry: dict[str, Any]) -> UserRow:
        attrs = entry.get("attributes") or {}
        # ⚠️ 整数 / FILETIME 类属性**必须**走 `_attr_text`（优先 `raw_attributes`）：
        #    直接读 `attrs` 会拿到 ldap3 已经解过一遍的 `str`（`'\x00\x02\x00\x00'`），
        #    `_safe_int` 认不出 ⇒ 列表里每个人都显示成"已启用"、锁定与待改密
        #    判定全错，而且**一条报错都没有**。详见 `_raw_first` 的说明。
        #    纯文本属性（cn / displayName / sAMAccountName / distinguishedName）
        #    在两处的取值相同，仍走 `attrs`。
        #
        # ⚠️ 读不到 ⇒ `None`，**不许** `or 0`（2026-09-17 改）。
        #    旧写法 `or 0` 给的理由是"否则 has_uac_flag(None, ...) 会抛 TypeError，
        #    整张用户列表都刷不出来"—— 那个顾虑是真的，但**代价付错了方向**：
        #    它把"读不到"翻译成 `uac=0`，而 0 里 `UF_ACCOUNTDISABLE`(0x2) 是**关**的
        #    ⇒ **每个人都显示成"已启用"**，而且一条报错都没有。
        #    现在让"读不到"一路传到显示层（`models.account_state_label` 显示
        #    「未知」）；写入侧本来就已在 `_uac_of_now` 中止 —— 两侧终于同口径。
        uac = _safe_int(_attr_text(entry, "userAccountControl"))
        computed = _safe_int(
            _attr_text(entry, "msDS-User-Account-Control-Computed")) or 0

        # 锁定状态：优先用 computed 属性的 UF_LOCKOUT 位（AD 实时计算，
        # 已考虑 lockoutDuration），lockoutTime>0 只作为兜底。
        locked = has_uac_flag(computed, UF_LOCKOUT) if computed else False
        if not locked:
            locked = (_safe_int(_attr_text(entry, "lockoutTime")) or 0) > 0

        display = (normalize_attr(attrs.get("displayName"))
                   or normalize_attr(attrs.get("cn"))
                   or normalize_attr(attrs.get("sAMAccountName")))

        raw_pwd_last_set = _attr_text(entry, "pwdLastSet")
        raw_pwd_expiry = _attr_text(entry, "msDS-UserPasswordExpiryTimeComputed")

        # 「下次登录必须改密码」：AD 在这两个属性上都会给 0。
        # 必须用 _is_zero 而不是 `not _safe_int(...)` —— 后者会把
        # "属性没读到" 也当成 True，凭空给每个人扣一顶待改密的帽子。
        must_change = _is_zero(raw_pwd_last_set) or _is_zero(raw_pwd_expiry)

        return UserRow(
            sam=normalize_attr(attrs.get("sAMAccountName")),
            display_name=display,
            enabled=None if uac is None else not has_uac_flag(uac, UF_ACCOUNTDISABLE),
            locked=locked,
            pwd_expire_at=ad_filetime_to_dt(raw_pwd_expiry),
            pwd_must_change=must_change,
            acct_expire_at=ad_filetime_to_dt(_attr_text(entry, "accountExpires")),
            pwd_last_set=ad_filetime_to_dt(raw_pwd_last_set),
            last_logon=ad_filetime_to_dt(_attr_text(entry, "lastLogonTimestamp")),
            uac=uac,
            dn=entry.get("dn") or normalize_attr(attrs.get("distinguishedName")),
        )

    # 🔴 `get_user_attributes()` 已于 2026-09-18 删除（主理人拍板 · 拍板项 `G-06`）。
    #    三条理由（都现算过，不是印象）：
    #      * **生产零调用点** —— UI 读属性一律走 `read_attributes`
    #        （`ui_browser.py` 的「读取属性」/「读取模板属性」两处），
    #        演示侧也一样；全仓只剩 `tests/` 在调它。
    #      * 它是**第三条自己写的属性转换** —— 自己一份
    #        `{k: format_attr_value(k, v) for ...}` 推导，**不走 `_attrs_to_text`**
    #        ⇒ 与 `read_attributes` 构成「同一个对象显示成两个值」的分叉源。
    #      * 它的 docstring 说「供详情面板展示」，而**详情面板并不调它**。
    #    ⚠️ 原文快照：`桌面/AD域管理工具-快照/pre-delete-get-user-attributes-20260918-1330/`。
    #    这个名字在本仓库里已经不存在了 —— 谁再看到它，那是过期的指路牌。

    # ==================================================================
    # 账号操作
    # ==================================================================

    def unlock(self, dn: str, sam: str = "") -> None:
        """解锁账号。用 ldap3 官方封装（内部即 `lockoutTime = 0`）。"""
        self._ensure()
        before = _safe_int(self._get_attribute(dn, "lockoutTime"))
        try:
            result = self._conn.extend.microsoft.unlock_account(dn)
        except Exception as exc:                 # noqa: BLE001
            self._audit_failure(OP_UNLOCK, sam, dn, exc)
            raise translate_error(exc, context="解锁账号") from exc

        if result is not True:
            # ⚠️ 走 `_result_error`：它会带上 LDAP 结果码，而解锁是**批量操作**，
            #    `workers._is_fatal` 靠这个码判断「连接级故障要立即整批中止」。
            #    自己拼一遍就丢码 —— 域控不可用时会变成"逐条失败到底"。
            err = _result_error(self._conn, "解锁账号")
            self._audit_failure(OP_UNLOCK, sam, dn, err)
            raise err

        self._audit_success(OP_UNLOCK, sam, dn,
                            before={"lockoutTime": before},
                            after={"lockoutTime": 0})

    def set_enabled(self, dn: str, enabled: bool, sam: str = "") -> None:
        """启用 / 禁用账号。

        🔒 **必须位运算**：读取当前 UAC，只翻转 `0x0002`，其余位原样保留。

        ⚠️ 「读不到当前 UAC」时**中止**，不当成 0 —— 见 `_uac_of_now`。
        """
        self._ensure()
        old_uac = _uac_of_now(self._get_attribute(dn, "userAccountControl"),
                              "启用/禁用")
        new_uac = set_uac_flag(old_uac, UF_ACCOUNTDISABLE, not enabled)
        op = OP_ENABLE if enabled else OP_DISABLE

        ok = self._conn.modify(dn, {"userAccountControl":
                                    [(_modify_replace(), [str(new_uac)])]})
        if not ok:
            err = _result_error(self._conn, "启用/禁用账号")
            self._audit_failure(op, sam, dn, err,
                                before={"userAccountControl": f"0x{old_uac:X}"})
            raise err

        _log.info("%s sam=%s uac 0x%X -> 0x%X", op, sam, old_uac, new_uac)
        self._audit_success(op, sam, dn,
                            before={"userAccountControl": f"0x{old_uac:X}"},
                            after={"userAccountControl": f"0x{new_uac:X}"})

    def reset_password(self, dn: str, new_password: str, sam: str = "",
                       must_change: bool = False) -> str:
        """重置密码。返回实际使用的通道名。

        双通道（决策 Q1）：
          1. 改密码走 `password_backend`（RPC 优先，失败降级 LDAPS）
          2. 【下次登录必须修改】→ 走 LDAP 写 `pwdLastSet = 0`
             （`WinNT://` provider 没有这个属性，只能走 LDAP）
        """
        self._ensure()
        if not new_password:
            raise AdToolError("请填写新密码。")
        if self._pwd_chain is None:
            raise AdToolError("尚未建立改密通道，请重新连接。")

        before = self._get_attribute(dn, "pwdLastSet")

        def _on_switch(from_label: str, to_label: str, reason: str) -> None:
            _log.warning("改密通道自动降级：%s → %s（原因：%s）",
                         from_label, to_label, reason)

        try:
            used = self._pwd_chain.set_password(sam, dn, new_password,
                                                on_switch=_on_switch)
        except AdToolError as exc:
            self._audit_failure(OP_RESET_PASSWORD, sam, dn, exc,
                                secrets=(new_password,))
            raise

        after: dict[str, Any] = {"channel": used}
        if must_change:
            ok = self._conn.modify(dn, {"pwdLastSet":
                                        [(_modify_replace(), ["0"])]})
            if not ok:
                # 密码已经改成功了，但"强制改密"没设上 —— 必须如实告知
                warning = _result_error(self._conn, "设置「下次登录必须修改」").message
                self._audit_success(
                    OP_RESET_PASSWORD, sam, dn,
                    detail=f"密码已重置（通道 {used}），但设置「下次登录必须修改」失败：{warning}",
                    before={"pwdLastSet": normalize_attr(before)},
                    after={"channel": used, "pwdLastSet": "设置失败"},
                    secrets=(new_password,))
                raise AdToolError(
                    f"密码已重置成功（通道：{used}），但「下次登录必须修改密码」设置失败：{warning}")
            after["pwdLastSet"] = "0"

        self._audit_success(
            OP_RESET_PASSWORD, sam, dn,
            detail=f"通道：{used}；下次登录必须修改：{'是' if must_change else '否'}",
            before={"pwdLastSet": normalize_attr(before)}, after=after,
            secrets=(new_password,))
        return used

    # ==================================================================
    # 新建对象
    # ==================================================================

    def sam_exists(self, sam: str) -> bool:
        """检查 sAMAccountName 是否已存在。"""
        from ldap3.utils.conv import escape_filter_chars
        if not sam:
            return False
        try:
            raw = self._paged_search(
                self.base_dn,
                f"(&(objectCategory=person)(objectClass=user)"
                f"(sAMAccountName={escape_filter_chars(sam)}))",
                "SUBTREE", ["distinguishedName"])
            return bool(raw)
        except AdToolError:
            return False

    def suggest_sam(self, base: str, limit: int = 20) -> str:
        """撞名时给一个可用的建议账号名，如 ``zhangsan`` → ``zhangsan2``。"""
        root = (base or "").strip()[:18] or "user"
        if not self.sam_exists(root):
            return root
        for i in range(2, limit + 1):
            candidate = f"{root}{i}"
            if not self.sam_exists(candidate):
                return candidate
        return f"{root}{datetime.now():%H%M%S}"

    def create_user(self, parent_dn: str, spec: UserSpec) -> str:
        """新建用户。**AD 特有的三步流程**，失败会回滚。

        ① 禁用态创建（UAC=514）→ ② 设密码（RPC/LDAPS）→ ③ 启用（UAC=512）

        为什么不一步到位：AD 不允许创建"启用态但无密码"的可用账号，
        而密码又必须通过加密通道或 RPC 设置 —— 所以必须分三步。
        """
        self._ensure()
        spec.validate()
        # 🔒 前置条件一次查完再动域控：没有改密通道就建不出可用账号，
        #    而「先 add 再发现没通道去回滚」要多付一次 add + 一次 delete，
        #    且**回滚本身也可能失败** —— 那就在 AD 里留下一个无密码的禁用
        #    账号（正是 `_rollback_user` 要防的残留）。与 `reset_password`
        #    的检查时机保持一致。
        if self._pwd_chain is None:
            raise AdToolError("尚未建立改密通道，请重新连接。")

        sam = spec.sam.strip()
        if self.sam_exists(sam):
            suggestion = self.suggest_sam(sam)
            raise AdToolError(f"登录名「{sam}」已存在，建议改用「{suggestion}」。")

        cn = (spec.display_name.strip()
              or f"{spec.given_name}{spec.surname}".strip() or sam)
        new_dn = f"CN={_escape_rdn(cn)},{parent_dn}"

        # ---- ① 禁用态创建 ----
        attributes: dict[str, Any] = {
            "sAMAccountName": sam,
            "userAccountControl": str(USER_UAC_DISABLED),
            "cn": cn,
        }
        if self.domain:
            attributes["userPrincipalName"] = f"{sam}@{self.domain}"
        if spec.display_name:
            attributes["displayName"] = spec.display_name
        if spec.given_name:
            attributes["givenName"] = spec.given_name
        if spec.surname:
            attributes["sn"] = spec.surname
        attributes.update({k: v for k, v in (spec.extra or {}).items() if v})

        ok = self._conn.add(
            new_dn,
            object_class=["top", "person", "organizationalPerson", "user"],
            attributes=attributes,
        )
        if not ok:
            err = _result_error(self._conn, "新建用户")
            self._audit_failure(OP_CREATE_USER, sam, new_dn, err)
            raise err

        # ---- ② 设密码（必须走改密后端）----
        # （改密通道的存在性已在方法开头查过，这里不重复判断）
        try:
            self._pwd_chain.set_password(sam, new_dn, spec.init_password)
        except Exception as exc:                 # noqa: BLE001
            # ⚠️ 这里**不能**只捕 `AdToolError`。留下"有账号没密码"的半成品，
            #    正是本方法开头那段前置检查点名要防的残留 —— 而回滚必须对
            #    **任何**异常生效：只要有一条异常绕过它，AD 里就多一个僵尸对象，
            #    而且**审计里什么都没有**（审计是由 `_rollback_user` 写的，
            #    它压根没被调用）。
            #
            #    2026-09-17 审查实测的绕过路径：`LdapsPasswordBackend._connect`
            #    里的 `Connection(auto_bind=True)` 没包 try ⇒ 绑定失败抛的是
            #    `LDAPBindError` / `LDAPSocketOpenError`，**都不是** `AdToolError`。
            #    那一处已按"底层异常唯一出口"补上（`translate_error`）；
            #    这里同时放宽，作为**第二道** —— 换任何后端都不许绕过回滚。
            self._rollback_user(new_dn, sam, exc,
                                secrets=(spec.init_password,))
            raise

        # ---- ③ 启用 + 可选强制改密 ----
        # ⚠️ 这里**必须逐个检查返回值**。连接是 raise_exceptions=False，
        #    失败时 modify() 返回 False 而**不抛异常** —— 只写 try/except
        #    会把「启用失败」吞掉，然后报告"已创建并启用"（假成功）。
        try:
            if not spec.keep_disabled:
                if not self._conn.modify(new_dn, {"userAccountControl":
                                                  [(_modify_replace(),
                                                    [str(USER_UAC_ENABLED)])]}):
                    raise _result_error(self._conn, "启用账号")
            if spec.must_change:
                if not self._conn.modify(new_dn, {"pwdLastSet":
                                                  [(_modify_replace(), ["0"])]}):
                    raise _result_error(self._conn, "设置「下次登录必须修改」")
        except Exception as exc:                 # noqa: BLE001
            # 账号与密码都已就绪，只是启用/强制改密没设上 —— 不回滚，如实告知
            reason = (exc.message if isinstance(exc, AdToolError)
                      else translate_error(exc).message)
            self._audit_success(
                OP_CREATE_USER, sam, new_dn,
                detail=f"账号已创建且密码已设置，但后续属性设置失败：{reason}",
                before=None,
                after={"distinguishedName": new_dn,
                       "state": "已创建/已设密码/启用或强制改密失败"},
                secrets=(spec.init_password,))
            raise AdToolError(
                f"账号「{sam}」已创建且密码已设置，但启用或「下次登录必须修改」设置失败："
                f"{reason}。请在列表里手动启用。") from exc

        self._audit_success(
            OP_CREATE_USER, sam, new_dn,
            detail=("已创建并启用" if not spec.keep_disabled else "已创建（保持禁用）")
                   + ("；下次登录必须修改密码" if spec.must_change else ""),
            before=None,
            after={"distinguishedName": new_dn,
                   "userAccountControl": str(USER_UAC_ENABLED if not spec.keep_disabled
                                             else USER_UAC_DISABLED),
                   "pwdLastSet": "0" if spec.must_change else None},
            secrets=(spec.init_password,))
        _log.info("已创建用户 sam=%s dn=%s", sam, new_dn)
        self._children_cache.pop(parent_dn, None)
        return new_dn

    def _rollback_user(self, dn: str, sam: str, cause: Exception,
                       secrets: tuple = ()) -> None:
        """步骤②失败 → 删掉刚建的半成品，避免 AD 里留下"有账号没密码"的僵尸。

        ``secrets`` 必须把初始密码带进来：这条 detail 是**异常文案**，
        而异常文案里出现密码是常有的事（"密码 xxx 不满足策略"），
        脱敏不做在这里就等于把口令写进审计日志。
        """
        # ⚠️ 先把 cause **归一成 `AdToolError`** —— 这一步不能省。
        #    调用点已放宽到捕一切异常，所以传进来的可能是 ldap3 原生异常
        #    （`LDAPSocketOpenError` 之类，**没有 `.message`**），而下面
        #    `_audit_failure` 与本方法的异常文案都要读 `.message`
        #    ⇒ 不归一就会在这里 `AttributeError`：一个**已经成功回滚**的失败，
        #    会变成"回滚过程中自己报错"，使用者看到一句完全不相关的错误，
        #    而且审计照样没写成 —— 两个目的同时落空。
        cause = translate_error(cause, context="新建用户")
        try:
            deleted = self._conn.delete(dn)
        except Exception:                        # noqa: BLE001
            deleted = False

        detail = (f"创建用户失败并已自动回滚（{cause.message}）" if deleted
                  else f"创建用户失败且自动清理失败：{cause.message}")
        self._audit_failure(OP_CREATE_USER, sam, dn, cause,
                            detail=detail, secrets=secrets)
        if deleted:
            raise AdToolError(f"新建用户失败：{cause.message}（已自动清理，未留下残留账号）")
        raise AdToolError(
            f"新建用户失败：{cause.message}\n"
            f"⚠️ 无法自动清理已生成的账号「{sam}」（当前为禁用态且无可用密码）。"
            f"请手工删除，或在列表中为它重新设置密码。")

    def create_ou(self, parent_dn: str, name: str, description: str = "") -> str:
        """新建组织单位。"""
        self._ensure()
        name = (name or "").strip()
        if not name:
            raise AdToolError("请填写组织单位名称。")
        dn = f"OU={_escape_rdn(name)},{parent_dn}"
        attributes: dict[str, Any] = {"ou": name}
        if description:
            attributes["description"] = description

        ok = self._conn.add(dn, object_class=["top", "organizationalUnit"],
                            attributes=attributes)
        if not ok:
            err = _result_error(self._conn, "新建组织单位")
            self._audit_failure(OP_CREATE_OU, name, dn, err)
            raise err

        self._audit_success(OP_CREATE_OU, name, dn, before=None,
                            after={"distinguishedName": dn, "description": description})
        self._children_cache.pop(parent_dn, None)
        return dn

    def create_group(self, parent_dn: str, name: str, scope: str = "global",
                     category: str = "security", description: str = "") -> str:
        """新建组。`scope`：global / domainlocal / universal。"""
        self._ensure()
        name = (name or "").strip()
        if not name:
            raise AdToolError("请填写组名。")
        gtype = group_type_value(scope, category)     # 已处理"位组合 + 负数坑"
        dn = f"CN={_escape_rdn(name)},{parent_dn}"
        attributes: dict[str, Any] = {
            "sAMAccountName": name,
            "groupType": str(gtype),                  # 按无符号十进制写
        }
        if description:
            attributes["description"] = description

        ok = self._conn.add(dn, object_class=["top", "group"], attributes=attributes)
        if not ok:
            err = _result_error(self._conn, "新建组")
            self._audit_failure(OP_CREATE_GROUP, name, dn, err)
            raise err

        self._audit_success(OP_CREATE_GROUP, name, dn, before=None,
                            after={"distinguishedName": dn, "groupType": gtype})
        return dn

    # ==================================================================
    # 组成员管理（F06）
    # ==================================================================

    #: 读组成员时统一拉的属性。成员可以是用户/组/计算机/联系人任意一种，
    #: 所以合并四类的关键字段，用 ``objectClass`` 自动判型 ——
    #: 每个成员单独按类型查一遍要多打 N 倍的 LDAP 往返。
    MEMBER_FETCH_ATTRIBUTES = [
        "objectClass", "cn", "sAMAccountName", "displayName", "description",
        "userAccountControl", "groupType", "mail", "dNSHostName",
        "operatingSystem", "operatingSystemVersion", "location",
        "givenName", "sn", "telephoneNumber", "title", "department",
        "company", "lastLogonTimestamp", "pwdLastSet", "lockoutTime",
        "msDS-User-Account-Control-Computed",
        "msDS-UserPasswordExpiryTimeComputed", "accountExpires",
        "whenCreated", "whenChanged", "distinguishedName",
    ]

    def list_group_members(self, group_dn: str, limit: int = 500,
                           ) -> list[DirObject]:
        """列出组的直接成员（用户 / 组 / 计算机 / 联系人混排）。

        实现：先读组的 ``member`` 属性拿 DN 清单，再按 **40 个一批**用
        ``(|(distinguishedName=…)(…)…)`` 批量回查对象 —— 逐个 BASE 读
        在「Domain Users」这种几百人的组上是几百次往返，不可接受。

        ⚠️ 只返回**直接成员**。主要组成员（`primaryGroupID` 指过来的）
        不在 ``member`` 属性里，天然不会被列出来 —— 这与 ADUC 的
        「成员」页行为一致。
        """
        self._ensure()
        group_dn = (group_dn or "").strip()
        if not group_dn:
            raise AdToolError("未指定组。")
        limit = int(limit) if limit else 500       # None/0 防御：min(len, None) 会 TypeError

        member_dns = self.read_attributes(group_dn, ["member"]).get("member", [])
        if not member_dns:
            return []

        from ldap3.utils.conv import escape_filter_chars

        out: list[DirObject] = []
        CHUNK = 40
        for start in range(0, min(len(member_dns), limit), CHUNK):
            chunk = member_dns[start:start + CHUNK]
            clause = "".join(
                f"(distinguishedName={escape_filter_chars(d)})" for d in chunk)
            raw = self._paged_search(
                self.base_dn, f"(|{clause})", "SUBTREE",
                self.MEMBER_FETCH_ATTRIBUTES)
            for entry in raw:
                out.append(self._to_dir_object(entry))
        out.sort(key=lambda o: ((o.cn or o.sam or o.dn or "").casefold(), o.kind))
        return out

    def add_to_group(self, member_dns: Iterable[str], group_dn: str,
                     sam: str = "") -> int:
        """把一个或多个对象加入组。返回实际加入的个数。

        不造轮子：用 ``conn.extend.microsoft.add_members_to_groups``。
        ⚠️ 必须回读校验 —— ldap3 对「已是成员」「主要组」这类情况可能
        返回成功但什么都没做（与「假成功」同类问题）。
        """
        self._ensure()
        group_dn = (group_dn or "").strip()
        members = [d.strip() for d in (member_dns or []) if d and d.strip()]
        if not group_dn:
            raise AdToolError("未指定目标组。")
        if not members:
            raise AdToolError("未选择要加入组的对象。")

        # ---- 前置去重：已在成员列表里的直接剔除（全重复则明确报错）----
        # 真 AD 对重复添加会报 entryAlreadyExists，这里提前给出可读的中文提示，
        # 并让「部分重复」的批量添加只提交新成员。
        current = {d.casefold() for d in
                   self.read_attributes(group_dn, ["member"]).get("member", [])}
        fresh = [d for d in members if d.casefold() not in current]
        skipped = len(members) - len(fresh)
        if not fresh:
            err = AdToolError("所选对象已经是该组的成员，无需重复添加。")
            self._audit_failure(OP_ADD_MEMBER, sam, group_dn, err)
            raise err
        members = fresh

        try:
            result = self._conn.extend.microsoft.add_members_to_groups(
                members, group_dn)
        except Exception as exc:                 # noqa: BLE001
            self._audit_failure(OP_ADD_MEMBER, sam, group_dn,
                                translate_error(exc, context="加入组"))
            raise translate_error(exc, context="加入组") from exc
        if result is not True:
            err = _result_error(self._conn, "加入组")
            self._audit_failure(OP_ADD_MEMBER, sam, group_dn, err)
            raise err

        # ---- 回读校验（假成功防线）----
        actual = {d.casefold() for d in
                  self.read_attributes(group_dn, ["member"]).get("member", [])}
        missing = [d for d in members if d.casefold() not in actual]
        if missing:
            err = AdToolError(
                f"域控返回成功，但 {len(missing)} 个对象没有出现在成员列表里"
                "（常见原因：该对象的「主要组」必须先更换才能从这里移出，"
                "或你没有修改该组成员的权限）。")
            self._audit_failure(OP_ADD_MEMBER, sam, group_dn, err,
                                detail=f"未生效：{missing}")
            raise err

        self._audit_success(
            OP_ADD_MEMBER, sam, group_dn,
            detail=f"加入 {len(members)} 个成员"
                   + (f"（跳过 {skipped} 个已是成员）" if skipped else ""),
            after={"member": members})
        _log.info("已把 %d 个对象加入组 %s", len(members), group_dn)
        return len(members)

    def remove_from_group(self, member_dns: Iterable[str], group_dn: str,
                          sam: str = "") -> int:
        """把一个或多个对象移出组。返回实际移除的个数。

        ⚠️ **主要组成员移不掉**：主要组关系存 `primaryGroupID`，不在
        ``member`` 里。ldap3 对它可能返回成功但实际没生效 ——
        靠回读校验抓出来并明确告知（ADUC 同样不支持直接移除主要组）。
        """
        self._ensure()
        group_dn = (group_dn or "").strip()
        members = [d.strip() for d in (member_dns or []) if d and d.strip()]
        if not group_dn:
            raise AdToolError("未指定组。")
        if not members:
            raise AdToolError("未选择要移出的成员。")

        before = {d.casefold() for d in
                  self.read_attributes(group_dn, ["member"]).get("member", [])}
        absent = [d for d in members if d.casefold() not in before]
        if absent:
            err = AdToolError(
                "以下对象不是该组的直接成员（很可能是它的「主要组」 —— "
                "主要组不能直接移除，必须先把用户的「主要组」换成别的组）：\n· "
                + "\n· ".join(absent))
            self._audit_failure(OP_REMOVE_MEMBER, sam, group_dn, err)
            raise err

        try:
            result = self._conn.extend.microsoft.remove_members_from_groups(
                members, group_dn)
        except Exception as exc:                 # noqa: BLE001
            self._audit_failure(OP_REMOVE_MEMBER, sam, group_dn,
                                translate_error(exc, context="移出组"))
            raise translate_error(exc, context="移出组") from exc
        if result is not True:
            err = _result_error(self._conn, "移出组")
            self._audit_failure(OP_REMOVE_MEMBER, sam, group_dn, err)
            raise err

        after = {d.casefold() for d in
                 self.read_attributes(group_dn, ["member"]).get("member", [])}
        stuck = [d for d in members if d.casefold() in after]
        if stuck:
            err = AdToolError(
                f"域控返回成功，但 {len(stuck)} 个对象仍在成员列表里"
                "（常见原因：权限不足或组被复制延迟，请刷新后重试）。")
            self._audit_failure(OP_REMOVE_MEMBER, sam, group_dn, err,
                                detail=f"未生效：{stuck}")
            raise err

        self._audit_success(
            OP_REMOVE_MEMBER, sam, group_dn,
            detail=f"移出 {len(members)} 个成员",
            before={"member": members}, after={"member": []})
        _log.info("已把 %d 个对象移出组 %s", len(members), group_dn)
        return len(members)

    # ==================================================================
    # 计算机账号 / 联系人（F07 / F08）
    # ==================================================================

    #: 预创建计算机账号的默认 UAC：
    #: ``WORKSTATION_TRUST_ACCOUNT(0x1000) | PASSWD_NOTREQD(0x0020)`` = 4128。
    #: 与 ADUC「新建计算机」落库的值一致 —— 密码由加域过程自己协商，
    #: 所以要带 PASSWD_NOTREQD。
    COMPUTER_UAC_PRECREATE = UF_WORKSTATION_TRUST_ACCOUNT | UF_PASSWD_NOTREQD

    def create_computer(self, parent_dn: str, name: str,
                        description: str = "") -> str:
        """预创建计算机账号（用于「先建号、后加域」流程）。

        ⚠️ ``sAMAccountName`` **必须以 ``$`` 结尾**，否则 AD 拒绝 ——
        这里自动补，界面不用让使用者猜。创建时账号是"待加域"状态，
        机器完成加域后密码与 DNS 名由它自己注册。
        """
        self._ensure()
        name = (name or "").strip()
        if not name:
            raise AdToolError("请填写计算机名。")
        if any(ch in name for ch in '\\/[]:;|=,+*?<>"'):
            raise AdToolError(f"计算机名「{name}」含有 AD 不允许的字符。")
        if len(name) > 15:
            raise AdToolError(
                f"计算机名「{name}」超过 15 个字符 —— NetBIOS 名上限 15，"
                "加域会被拒。")
        sam = name if name.endswith("$") else f"{name}$"

        new_dn = f"CN={_escape_rdn(name)},{parent_dn}"
        attributes: dict[str, Any] = {
            "sAMAccountName": sam,
            "userAccountControl": str(self.COMPUTER_UAC_PRECREATE),
        }
        if description:
            attributes["description"] = description

        ok = self._conn.add(
            new_dn,
            object_class=["top", "person", "organizationalPerson",
                          "user", "computer"],
            attributes=attributes)
        if not ok:
            err = _result_error(self._conn, "新建计算机账号")
            self._audit_failure(OP_CREATE_COMPUTER, sam, new_dn, err)
            raise err

        self._audit_success(OP_CREATE_COMPUTER, sam, new_dn,
                            detail="预创建（待加域）",
                            after={"distinguishedName": new_dn,
                                   "userAccountControl":
                                       str(self.COMPUTER_UAC_PRECREATE)})
        _log.info("已预创建计算机 sam=%s dn=%s", sam, new_dn)
        self._children_cache.pop(parent_dn, None)
        return new_dn

    def reset_computer_account(self, dn: str, sam: str = "") -> str:
        """重置计算机账号（随机化其机器密码）。

        后果必须讲清楚（界面文案负责）：该机器**下次连域会认证失败**，
        需要重新加域（或本地重新入域）才能恢复。用于「机器失联后
        强制重新入域」或「账号疑似被冒用」的场景。
        """
        self._ensure()
        dn = (dn or "").strip()
        if not dn:
            raise AdToolError("未指定计算机账号。")
        if self._pwd_chain is None:
            raise AdToolError("尚未建立改密通道，请重新连接。")

        # 64 位随机密码：不进审计日志（含 secrets 脱敏），也不回显
        from utils import generate_password
        new_password = generate_password(64)
        try:
            used = self._pwd_chain.set_password(sam, dn, new_password)
        except AdToolError as exc:
            self._audit_failure(OP_RESET_COMPUTER, sam, dn, exc,
                                secrets=(new_password,))
            raise
        self._audit_success(OP_RESET_COMPUTER, sam, dn,
                            detail=f"机器密码已随机化（通道：{used}）；"
                                   "该机器需重新加入域",
                            after={"channel": used},
                            secrets=(new_password,))
        return used

    def create_contact(self, parent_dn: str, name: str, mail: str = "",
                       description: str = "") -> str:
        """新建联系人（Exchange 通讯组的外部收件人等场景）。"""
        self._ensure()
        name = (name or "").strip()
        if not name:
            raise AdToolError("请填写联系人名称。")
        new_dn = f"CN={_escape_rdn(name)},{parent_dn}"
        attributes: dict[str, Any] = {"cn": name}
        if mail:
            attributes["mail"] = mail.strip()
        if description:
            attributes["description"] = description

        ok = self._conn.add(
            new_dn,
            object_class=["top", "person", "organizationalPerson", "contact"],
            attributes=attributes)
        if not ok:
            err = _result_error(self._conn, "新建联系人")
            self._audit_failure(OP_CREATE_CONTACT, name, new_dn, err)
            raise err

        self._audit_success(OP_CREATE_CONTACT, name, new_dn, before=None,
                            after={"distinguishedName": new_dn,
                                   "mail": mail})
        return new_dn

    # ==================================================================
    # 账户页专用操作（对齐 ADUC「帐户」选项卡）
    # ==================================================================

    def set_uac_single_flag(self, dn: str, flag: int, enabled: bool,
                            sam: str = "") -> None:
        """翻转 UAC 的**一个位**（如「密码永不过期」= 0x10000）。

        🔒 必须走位运算（铁律 3）：整值覆盖会把其它位（禁用、智能卡等）
        全部冲掉。

        ⚠️ 「读不到当前 UAC」时**中止**，不当成 0 —— 见 `_uac_of_now`。
        """
        self._ensure()
        old_uac = _uac_of_now(self._get_attribute(dn, "userAccountControl"),
                              "修改账户选项")
        new_uac = set_uac_flag(old_uac, flag, enabled)

        ok = self._conn.modify(dn, {"userAccountControl":
                                    [(_modify_replace(), [str(new_uac)])]})
        if not ok:
            err = _result_error(self._conn, "修改账户选项")
            self._audit_failure(OP_UPDATE, sam, dn, err,
                                before={"userAccountControl": f"0x{old_uac:X}"})
            raise err
        self._audit_success(OP_UPDATE, sam, dn,
                            detail=f"UAC 位 0x{flag:X} {'置 1' if enabled else '清 0'}",
                            before={"userAccountControl": f"0x{old_uac:X}"},
                            after={"userAccountControl": f"0x{new_uac:X}"})

    def set_account_expiry(self, dn: str, when: datetime | None,
                           sam: str = "") -> None:
        """设置账户过期时间。``None`` = 永不过期。

        ⚠️ ``accountExpires`` 的 ``0`` 与 ``0x7FFFFFFFFFFFFFFF`` 都是
        "永不过期"哨兵 —— 写 0 即可（与 ADUC「从不」一致）。
        """
        self._ensure()
        old = first_value(self.read_attributes(dn, ["accountExpires"]),
                          "accountExpires")
        value = "0" if when is None else str(datetime_to_ad_filetime(when))
        ok = self._conn.modify(dn, {"accountExpires":
                                    [(_modify_replace(), [value])]})
        if not ok:
            err = _result_error(self._conn, "设置账户过期时间")
            self._audit_failure(OP_UPDATE, sam, dn, err,
                                before={"accountExpires": old})
            raise err
        self._audit_success(OP_UPDATE, sam, dn,
                            detail="账户过期：永不过期" if when is None
                            else f"账户过期：{when:%Y-%m-%d %H:%M}",
                            before={"accountExpires": old},
                            after={"accountExpires": value})

    def set_must_change_password(self, dn: str, must: bool = True,
                                 sam: str = "") -> None:
        """设置/取消「下次登录必须修改密码」（写 ``pwdLastSet``）。

        ⚠️ ``pwdLastSet = 0`` 是"必须改"，``-1`` 是"恢复正常"
        （写 1 会被解释成 1601 年的乱时间）。与「重置密码」共用同一语义
        但**不重置密码本身**。
        """
        self._ensure()
        old = first_value(self.read_attributes(dn, ["pwdLastSet"]), "pwdLastSet")
        value = "0" if must else "-1"
        ok = self._conn.modify(dn, {"pwdLastSet": [(_modify_replace(), [value])]})
        if not ok:
            err = _result_error(self._conn, "设置下次登录改密")
            self._audit_failure(OP_RESET_PASSWORD, sam, dn, err,
                                before={"pwdLastSet": old})
            raise err
        self._audit_success(
            OP_RESET_PASSWORD, sam, dn,
            detail=("下次登录必须修改密码" if must else "已取消「下次登录必须修改密码」"),
            before={"pwdLastSet": old}, after={"pwdLastSet": value})

    # ==================================================================
    # 登录时间 / 工作站限制 / 拨入（F13 / F14 / F15）
    # ==================================================================

    def get_logon_hours(self, dn: str) -> bytes | None:
        """读 ``logonHours`` 原始位图。``None`` = 未限制（等价全允许）。

        ⚠️ **必须裸读，不能走 `read_attributes`**：那条路会经过
        `_as_list` 的 UTF-8 解码，把 21 字节位图毁成乱码 —— 位图是
        二进制值，逐字节比对的校验会因此永远失败（或更糟：假通过）。

        ⚠️ 而且要从 `raw_attributes` 取（`_raw_first`）：`attributes` 那侧的值
        **一律已被解成 `str`**（快解码器 + latin-1 兜底，见 `utils.py` §6.1）——
        全 `00`×21（一小时都不允许）会变成一串控制字符，
        `FF`×21（全天允许）会变成 latin-1 乱码，**两种都不是 bytes**
        ⇒ 下面的 `isinstance` 判据失效 ⇒ 返回 `None` ⇒ 界面显示「未限制」
        ⇒ **把「一小时都不允许」显示成「允许全部」**，方向正好相反。
        """
        self._ensure()
        from ldap3 import BASE
        ok = self._conn.search(search_base=dn, search_filter="(objectClass=*)",
                               search_scope=BASE, attributes=["logonHours"])
        self._report_search(ok, "读取登录时间")
        if not self._conn.response:
            return None
        raw = _raw_first(self._conn.response[0], "logonHours")
        if raw is None:
            return None
        return bytes(raw) if isinstance(raw, (bytes, bytearray)) else None

    def set_logon_hours(self, dn: str, hours: bytes | None,
                        sam: str = "") -> None:
        """写登录时间位图。``None`` = 清除限制（全时允许）。

        ⚠️ 必须**逐字节回读比对**（不走 `verify_changes`）：
        ``logonHours`` 是二进制属性，通用校验里 ``str.casefold()`` 对
        bytes 会直接 TypeError；而位图恰恰**需要**逐字节相等 ——
        错一位就是"多允许了一个小时"，这类差异不能当作"规范化差异"放过。
        """
        self._ensure()
        old = self.get_logon_hours(dn)
        if hours is None:
            ok = self._conn.modify(dn, {"logonHours":
                                        [(_modify_delete(), [])]})
        else:
            data = bytes(hours)
            if len(data) != LOGON_HOURS_BYTES:
                raise AdToolError(
                    f"登录时间位图必须是 {LOGON_HOURS_BYTES} 字节"
                    f"（当前 {len(data)} 字节）—— 界面数据异常，已拒绝写入。")
            ok = self._conn.modify(dn, {"logonHours":
                                        [(_modify_replace(), [data])]})
        if not ok:
            err = _result_error(self._conn, "设置登录时间")
            self._audit_failure(OP_UPDATE, sam, dn, err,
                                before={"logonHours": _logon_hours_brief(old)})
            raise err

        # ---- 逐字节回读（二进制属性的唯一可信校验）----
        actual = self.get_logon_hours(dn)
        if hours is None:
            verified = actual is None
        else:
            verified = actual is not None and bytes(actual) == bytes(hours)
        if not verified:
            expect_brief = ("（未限制）" if hours is None
                            else _logon_hours_brief(bytes(hours)))
            err = AdToolError(
                "域控返回成功，但登录时间回读不一致 —— 位图未按预期落库，"
                "请刷新后重新设置（未生效的写入已记入审计日志）。")
            self._audit_failure(
                OP_UPDATE, sam, dn, err,
                detail=f"期望 {expect_brief}，实际 {_logon_hours_brief(actual)}")
            raise err

        self._audit_success(
            OP_UPDATE, sam, dn,
            detail="登录时间：清除限制（全时允许）" if hours is None
            else "登录时间已更新（按位图写入并逐字节回读确认）",
            before={"logonHours": _logon_hours_brief(old)},
            after={"logonHours": "（未限制）" if hours is None
                   else _logon_hours_brief(bytes(hours))})

    def get_logon_workstations(self, dn: str) -> list[str]:
        """读「登录到」工作站名单。空列表 = 不限制。"""
        raw = first_value(self.read_attributes(dn, ["userWorkstations"]),
                          "userWorkstations")
        if raw is None:
            return []
        text = normalize_attr(raw)
        return [p.strip() for p in text.split(",") if p.strip()]

    def set_logon_workstations(self, dn: str, names: list[str] | None,
                               sam: str = "") -> None:
        """写「登录到」工作站限制。``None`` / 空列表 = 清除限制（到处可登录）。

        ⚠️ 语义必须讲清楚（界面文案负责）：这个限制**只管 NTLM/Kerberos
        的交互式登录**，很多网络访问（如 Exchange、SMB）不受它约束 ——
        它不是"把账号锁死在某几台机器上"的绝对手段。
        """
        self._ensure()
        clean: list[str] = []
        for name in (names or []):
            name = (name or "").strip()
            if name and name not in clean:
                clean.append(name)
        old = self.get_logon_workstations(dn)

        if clean:
            value = ",".join(clean)
            op = [(_modify_replace(), [value])]
        else:
            value = ""
            op = [(_modify_delete(), [])]
        ok = self._conn.modify(dn, {"userWorkstations": op})
        if not ok:
            err = _result_error(self._conn, "设置登录工作站限制")
            self._audit_failure(OP_UPDATE, sam, dn, err,
                                before={"userWorkstations": old})
            raise err

        after_names = self.get_logon_workstations(dn)
        verified = (after_names == clean) if clean else (not after_names)
        if not verified:
            err = AdToolError(
                "域控返回成功，但工作站限制回读不一致，请刷新后重试。")
            self._audit_failure(OP_UPDATE, sam, dn, err,
                                detail=f"期望 {clean}，实际 {after_names}")
            raise err

        self._audit_success(
            OP_UPDATE, sam, dn,
            detail="登录工作站：清除限制（所有工作站可登录）" if not clean
            else f"登录工作站：{value}",
            before={"userWorkstations": old},
            after={"userWorkstations": clean or "（未限制）"})

    def get_dialin(self, dn: str) -> dict[str, Any]:
        """读拨入状态。返回::

            {"allow": True|False|None,   # None = 由 NPS 网络策略控制
             "callback": str}            # 回拨号码，"" = 不回拨
        """
        attrs = self.read_attributes(dn, ["msNPAllowDialin",
                                          "msRADIUSCallbackNumber"])
        raw_allow = first_value(attrs, "msNPAllowDialin")
        allow: bool | None
        if raw_allow is None:
            allow = None
        elif isinstance(raw_allow, bool):
            allow = raw_allow
        else:
            allow = str(raw_allow).strip().upper() == "TRUE"
        callback = normalize_attr(first_value(attrs, "msRADIUSCallbackNumber"))
        return {"allow": allow, "callback": callback}

    def set_dialin(self, dn: str, allow: bool | None,
                   callback: str = "", sam: str = "") -> None:
        """写拨入设置。

        ``allow``：``True``=允许访问，``False``=拒绝访问，``None``=由 NPS
        网络策略控制（删除 ``msNPAllowDialin``）。
        ``callback``：空串 = 不回拨；非空 = 总是回拨到该号码
        （同时写 ``msRADIUSCallbackNumber`` 与 ``msRASSavedCallbackNumber``
        —— ADSI 与 RRAS 管理工具读的是后者）。
        """
        self._ensure()
        old = self.get_dialin(dn)
        operations: dict[str, Any] = {}
        if allow is None:
            operations["msNPAllowDialin"] = [(_modify_delete(), [])]
        else:
            operations["msNPAllowDialin"] = [
                (_modify_replace(), ["TRUE" if allow else "FALSE"])]

        callback = (callback or "").strip()
        if callback:
            operations["msRADIUSCallbackNumber"] = [
                (_modify_replace(), [callback])]
            operations["msRASSavedCallbackNumber"] = [
                (_modify_replace(), [callback])]
        elif old["callback"]:
            # 原来"总是回拨"，现在改成不回拨 → 两个回拨属性都要删干净
            operations["msRADIUSCallbackNumber"] = [(_modify_delete(), [])]
            operations["msRASSavedCallbackNumber"] = [(_modify_delete(), [])]

        if not self._conn.modify(dn, operations):
            err = _result_error(self._conn, "设置拨入属性")
            self._audit_failure(OP_UPDATE, sam, dn, err, before=old)
            raise err

        after = self.get_dialin(dn)
        if after["allow"] != allow or after["callback"] != callback:
            err = AdToolError(
                "域控返回成功，但拨入设置回读不一致，请刷新后重试。")
            self._audit_failure(OP_UPDATE, sam, dn, err,
                                detail=f"期望 allow={allow} callback={callback!r}，"
                                       f"实际 {after}")
            raise err

        self._audit_success(
            OP_UPDATE, sam, dn,
            detail=f"拨入：{'允许' if allow else '拒绝' if allow is False else '由 NPS 策略控制'}；"
                   f"回拨：{callback or '不回拨'}",
            before=old, after=after)

    # ==================================================================
    # 内置容器（F10：树里显示 Users / Computers / Builtin）
    # ==================================================================

    #: 域根下的知名 CN 容器。ADUC 默认视图就显示这几个
    #: （System 等系统容器要开「高级功能」才显示，本工具暂不显示）。
    WELL_KNOWN_CONTAINERS = ("CN=Users", "CN=Computers", "CN=Builtin")

    def list_well_known_containers(self, base_dn: str) -> list[OuNode]:
        """探测域根下的内置 CN 容器（存在才返回，缺失静默跳过）。

        为什么用探测而不是搜 ``objectClass=container``：这三个容器
        在**任何** AD 域都存在且名字固定，三次 BASE 读稳定又便宜；
        搜索反而会把 System、LostAndFound 这类不想显示的也带回来。
        """
        self._ensure()
        base_dn = (base_dn or self.base_dn).strip()
        nodes: list[OuNode] = []
        for rdn in self.WELL_KNOWN_CONTAINERS:
            dn = f"{rdn},{base_dn}"
            try:
                attrs = self.read_attributes(dn, ["cn"])
            except AdToolError:
                continue                        # 域里真没有（如迁移过的域）
            name = normalize_attr(first_value(attrs, "cn")) or rdn.split("=")[1]
            nodes.append(OuNode(name=name, dn=dn, has_children=True))
        return nodes

    # ==================================================================
    # 多类型对象浏览（ADUC 对齐）
    # ==================================================================

    def list_objects(self, base_dn: str, kinds: Iterable[str] | None = None,
                     scope: str = "LEVEL", keyword: str = "",
                     limit: int | None = None) -> list[DirObject]:
        """列出容器内的用户 / 组 / 计算机 / 联系人（可一次要多种类型）。

        ADUC 打开一个 OU，右窗格就是这四类**混在一起**列的，所以这里一次
        要多种类型，用 `DirObject.kind` 打标区分显示。

        为什么分类搜索而不是拼一个大过滤器：
          * 每类要拉的属性不一样（组要 groupType、计算机要 dNSHostName）
          * 失败提示能指明是「查组」还是「查计算机」挂的
          * `contact` 与 `user` 同属 `person`，混在一个过滤器里极易互相带出

        ``kinds`` 的三种输入 —— **后两种别搞混**（判据见 `tests/test_ad_client.py`）：
          * ``None``：默认视图（四类业务对象 ``ObjectKind.ALL``）；
          * ``[]``：⚠️ 空列表是 **falsy** ⇒ 下面那句 ``kinds or ObjectKind.ALL``
            会把它**回落成「全部类型」**。这是**刻意**的（ADUC 打开一个容器时
            右窗格默认就列全四类），它**不等于**"什么都不要"；
          * 非空但全不认识：过滤后为空 ⇒ 直接返回 ``[]``、**一个查询都不发**。
            少了这一条就会退化成「没有 ``objectCategory`` 的宽过滤器」，
            把整个目录都捞回来 —— 那是信息泄露，不是"宽容"。
        """
        kinds = [k for k in (kinds or ObjectKind.ALL) if k in KIND_FILTERS]
        if not kinds:
            return []
        search = "SUBTREE" if str(scope).upper() == "SUBTREE" else "LEVEL"

        pattern = ""
        if keyword and keyword.strip():
            from ldap3.utils.conv import escape_filter_chars
            key = escape_filter_chars(keyword.strip())
            pattern = (f"(|(sAMAccountName=*{key}*)(cn=*{key}*)"
                       f"(displayName=*{key}*)(description=*{key}*)"
                       f"(mail=*{key}*)(dNSHostName=*{key}*))")

        out: list[DirObject] = []
        remaining = limit
        for kind in kinds:
            if remaining is not None and remaining <= 0:
                break
            raw = self._paged_search(
                base_dn, f"(&{KIND_FILTERS[kind]}{pattern})", search,
                OBJECT_ATTRIBUTES.get(kind, ["cn", "distinguishedName"]),
                limit=remaining)
            for entry in raw:
                out.append(self._to_dir_object(entry, kind))
            if remaining is not None:
                remaining -= len(raw)

        # 按名称排序 —— ADUC 默认也是按名称排的。
        # 用 casefold 而不是 lower：德文 ß、土耳其语 İ 这类字符 lower() 排不对。
        out.sort(key=lambda o: ((o.cn or o.sam or o.dn or "").casefold(), o.kind))
        return out

    def search_raw_filter(self, base_dn: str, ldap_filter: str,
                          limit: int = 500) -> list[DirObject]:
        """按使用者自写的 LDAP 过滤器搜索（F12 高级查找）。

        ⚠️ 过滤器是**使用者写的原文**，不做任何转义或改写 —— 这是高级
        功能的语义（ADUC 的「自定义搜索」同理）。本地只做括号配平这类
        能确定的校验，值语法的错误交给域控报、再翻译成中文。
        属性表拉的是四类对象的并集，类型判定交给 ``objectClass``。
        """
        self._ensure()
        from utils import validate_ldap_filter
        reason = validate_ldap_filter(ldap_filter)
        if reason:
            raise AdToolError(reason)
        base_dn = (base_dn or self.base_dn).strip()
        if not base_dn:
            raise AdToolError("未确定搜索起点（BaseDN）。")

        raw = self._paged_search(base_dn, ldap_filter.strip(), "SUBTREE",
                                 self.MEMBER_FETCH_ATTRIBUTES,
                                 limit=max(1, int(limit or 500)))
        out: list[DirObject] = []
        for entry in raw:
            kind = self._kind_of_attrs(entry.get("attributes") or {})
            if kind in (ObjectKind.OU, ObjectKind.OTHER):
                # 高级查找面向四类业务对象；OU/容器混进来会让人误以为
                # 可以在这里管理它们（树才是 OU 的家）。
                continue
            out.append(self._to_dir_object(entry, kind))
        out.sort(key=lambda o: ((o.cn or o.sam or o.dn or "").casefold(), o.kind))
        return out

    def list_upn_suffixes(self) -> list[str]:
        """UPN 后缀清单：域默认 + 「AD 域和信任关系」里自定义的后缀。

        读 ``CN=Partitions,CN=Configuration,<BaseDN>`` 的 ``uPNSuffixes``
        属性。**刻意容错**：读不到（权限不足 / 属性为空 / 容器被清）
        不抛错 —— 至少返回默认 ``@域名``，别让建号界面的 UPN 空着。
        """
        self._ensure()
        from ldap3 import BASE
        suffixes: list[str] = []
        if self.domain:
            suffixes.append(f"@{self.domain}")
        partitions_dn = f"CN=Partitions,CN=Configuration,{self.base_dn}"
        try:
            ok = self._conn.search(search_base=partitions_dn,
                                   search_filter="(objectClass=*)",
                                   search_scope=BASE,
                                   attributes=["uPNSuffixes"])
            if ok and self._conn.response:
                values = (self._conn.response[0].get("attributes") or {}).get(
                    "uPNSuffixes") or []
                if isinstance(values, (str, bytes)):
                    values = [values]
                for value in values:
                    text = (value.decode("utf-8", "ignore")
                            if isinstance(value, bytes) else str(value))
                    text = text.strip()
                    if not text:
                        continue
                    if not text.startswith("@"):
                        text = f"@{text}"
                    if text not in suffixes:
                        suffixes.append(text)
        except Exception as exc:                 # noqa: BLE001 —— 刻意吞掉
            _log.debug("读取 uPNSuffixes 失败（不影响建号）：%s", exc)
        return suffixes

    def get_object(self, dn: str, kind: str = "") -> DirObject:
        """读单个对象（BASE 搜索），返回通用行结构。

        `kind` 留空时按 `objectClass` 自动判断 —— 界面上右键一个对象时
        经常不知道它是用户还是计算机，判断交给后端更省事。
        """
        # ⚠️ 不能只拉 "*"：msDS-UserPasswordExpiryTimeComputed /
        #    msDS-User-Account-Control-Computed 是**构造属性**，AD 对 "*"
        #    一律不返回（列表查询显式列了它们才有的）。回读少这两样，
        #    刷新出来的行会把「23 天后」错画成「永不过期」。
        attrs = self.read_attributes(dn, ["*", *USER_ATTRIBUTES])
        if not attrs:
            raise AdToolError("对象不存在或已被删除，请刷新后重试。")
        return self._to_dir_object({"dn": dn, "attributes": attrs}, kind)

    def read_attributes(self, dn: str, names: Iterable[str] | None = None,
                        ) -> dict[str, list[str]]:
        """读对象属性，返回 ``{属性名: [值, ...]}``（**保留多值**）。

        **保留每个值**（而不是拼成一个字符串）是刻意的：属性编辑器要拿它做
        **逐值比对** —— 改前 / 改后各是哪些值，拼过的字符串比对不出「改了哪一个」。

        ⚠️ 这段原先写的是「与 `get_user_attributes()` 的区别：那个返回分号拼起来的
        字符串，只够展示」—— 那个方法 **2026-09-18 已删**（拍板项 `G-06`：生产零调用点，
        且它是第三份自己写的转换）。**现役的读属性入口只有这一条**：
        UI 的「读取属性」/「读取模板属性」都走它（`ui_browser.py`）。
        """
        self._ensure()
        from ldap3 import BASE
        ok = self._conn.search(
            search_base=dn, search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=list(names) if names else ["*"])
        self._report_search(ok, "读取对象属性")
        if not self._conn.response:
            raise AdToolError("对象不存在或已被删除，请刷新后重试。")
        # ⚠️ **必须取 `raw_attributes`**（ldap3 无条件保留的原始 bytes），
        #    不能取 `attributes`：后者已被 ldap3 解过一遍，且**结果一律是 `str`**
        #    （快解码器 + latin-1 兜底，见 `utils.py` §6.1）
        #    ⇒ `objectSid` / `objectGUID` / `userAccountControl` 这些
        #    **全部**会变成含控制字符或 latin-1 乱码的 `str`
        #    （⚠️ 不存在"含高字节所以侥幸保持 bytes"的属性）
        #    ⇒ `format_attr_value` 的 bytes 判据静默失效
        #    ⇒ 属性面板乱码、`int()` 抛 ValueError（账号属性页整体打不开）。
        #    反证 C113：把这一行改回 `attributes`，SID 那批判据会精确变红。
        # ⚠️ 转换只有一份实现（`_attrs_to_text`）—— `search_attributes` 也用它。
        #    在这里再抄一遍 dict 推导，两条路就会分叉，而分叉的表现是
        #    "某一个入口上 SID 变乱码"，另一个入口一切正常。
        return _attrs_to_text(self._conn.response[0].get("raw_attributes"))

    def search_attributes(self, base_dn: str, ldap_filter: str,
                          attributes: Iterable[str] = (),
                          scope: str = "SUBTREE",
                          limit: int | None = None,
                          what: str = "查询") -> list[dict[str, list[str]]]:
        """按过滤器**一次查一批**对象，返回原始属性 ``{属性名: [值, ...]}``。

        与 `read_attributes` 是同一个转换（`_attrs_to_text`），区别只有两点：
        这里一次查一批、且要哪些属性由调用方列。**不是**它的替代品 ——
        单对象回读仍然走 `read_attributes`。

        它存在的理由：有些 AD 容器里的对象**不属于**四类业务对象
        （用户 / 组 / 计算机 / 联系人），而 `list_objects` 与
        `search_raw_filter` 都按那种"业务视图"过滤 —— `groupPolicyContainer`
        会当场被判成 OTHER 丢掉。那些容器只能走这里。

        ``what`` 只进错误文案（`_report_search` 的 context），让报错说得出
        "是在查什么的时候挂的"。

        ⚠️ **不做类型判定、不过滤、不排序** —— 这里是**协议层**：要什么过滤器
        就给什么，返回的东西原样交给调用方。语义（哪些算 GPO、怎么排序）
        属调用方。`attributes` 里没写 ``distinguishedName`` 也会带上：
        DN 是这些对象的**唯一标识**，少了它调用方还得再查一次。
        """
        self._ensure()
        base_dn = (base_dn or self.base_dn or "").strip()
        if not base_dn:
            raise AdToolError("未确定搜索起点（BaseDN）。")

        names = [str(name) for name in (attributes or ())]
        if "distinguishedName" not in names:
            names.append("distinguishedName")

        raw = self._paged_search(
            base_dn, (ldap_filter or "").strip() or "(objectClass=*)",
            "SUBTREE" if str(scope).upper() == "SUBTREE" else "LEVEL",
            names, limit=limit)

        out: list[dict[str, list[str]]] = []
        for entry in raw:
            attrs = _attrs_to_text(entry.get("raw_attributes"))
            # 条目的 `dn` 是权威值（ldap3 一定给），属性表里那份是我们要来的。
            # 只补不覆盖：真取到了属性就用属性表里那份。
            dn = (entry.get("dn") or "").strip()
            if dn:
                attrs.setdefault("distinguishedName", [dn])
            out.append(attrs)
        return out

    def read_object_sid(self, dn: str) -> str:
        """读对象的 SID 文本（``'S-1-5-21-…'``）—— **严格版**。

        ⚠️ **不要拿 `read_attributes(dn, ["objectSid"])` 替代它** ——
        那条走的是**展示**路径（`utils.format_attr_value`），SID 畸形时会**降级**
        成 ``<原始字节：01 05 00 …>`` 这种文本（属性面板不该被一条畸形值打挂，
        那个降级是**故意的**）。而授权路径**绝不能**吃降级文本：把它喂给解析
        SID 的那条路要么炸，要么更糟 —— 变成一条**形式合法、
        指向未知主体**的权限项。

        所以这里**不走** `_as_list` 的文本转换，直接拿原始 bytes 交给
        `utils.sid_bytes_to_string`（它逐段校验长度、非法就抛错）。
        这也是本方法存在的唯一理由：**把"展示"与"授权"两条路径分开**。

        ⚠️ 2026-09-16 注：本方法**生产侧零调用点** —— 原先唯一的调用者是
        「共享盘权限」那批 worker（`_domain_sid_of` / `grant_share_layer`），
        它们已随「操作共享盘」功能整体删除。**保留它是有意为之**，且它
        **不适用**「零调用点 = 死代码」那条红线 —— 它有调用点，只是没有
        **生产**调用点：`tests/test_ad_client.py::TestReadObjectSid`（6 例）、
        `tests/test_binary_attr_read.py`（1 例）、反证 C114 / C121，以及
        `tests/test_client_contract.py` 拿它对账两个客户端的**能力面**（4 例）。
        删掉省不到什么，却会让"授权读 / 展示读"这条安全边界从代码里**消失**
        ⇒ 将来谁要按 SID 授权，会自然而然地写 `read_attributes(dn, ["objectSid"])`，
        而那正是**真域返回乱码**的那条路（见下）。
        `mock_client.read_object_sid` 侧有同样的说明，两侧一致。

        ⚠️ **更正一条曾经写在本文档里的假设**（2026-09-15 真域缺陷）：
        这里以前写「直接读 `attributes` 拿到的**就是**原始 bytes」——
        在真域上**不成立**。`attributes` 的值已被 ldap3 解过一遍，且
        **结果一律是 `str`**（快解码器 + latin-1 兜底，见 `utils.py` §6.1），
        SID 也不例外（全 < 0x80 得到控制字符、含 ≥ 0x80 得到 latin-1 乱码）
        ⇒ 下面那条 `isinstance(raw, (bytes, bytearray))` 守卫会命中并抛
        「读到的 SID 不是二进制形式」—— **安全，但授权功能整体不可用**。
        所以改成用 `_raw_first`（优先 `raw_attributes`，那是真·原始 bytes）。
        反证 C114：把这里改回读 `attributes`，授权那条判据会精确变红。
        """
        self._ensure()
        from ldap3 import BASE
        ok = self._conn.search(search_base=dn, search_filter="(objectClass=*)",
                               search_scope=BASE, attributes=["objectSid"])
        self._report_search(ok, "读取对象 SID")
        if not self._conn.response:
            raise AdToolError("对象不存在或已被删除，请刷新后重试。")
        raw = _raw_first(self._conn.response[0], "objectSid")
        if raw is None:
            # ⚠️ 只说"没有 SID"，**不列举**哪些对象类型没有 —— 联系人确定没有，
            #    但组织单位（OU）在 AD 里**是有 `objectSid` 的**，写进举例就是错的。
            raise AdToolError(
                "该对象没有 SID 属性 —— 它不是安全主体，无法用于授权。")
        if not isinstance(raw, (bytes, bytearray)):
            # ldap3 正常会回 bytes；回字符串说明连接/解码层被改过，不能装作没事。
            raise AdToolError("读到的 SID 不是二进制形式，无法用于授权，已中止。")
        return sid_bytes_to_string(bytes(raw))

    # ------------------------------------------------------------------
    # 转换
    # ------------------------------------------------------------------

    @classmethod
    def _to_dir_object(cls, entry: dict[str, Any], kind: str = "") -> DirObject:
        """原始搜索条目 → `DirObject`（四类对象通用的行结构）。"""
        attrs = entry.get("attributes") or {}
        dn = (entry.get("dn") or "").strip() or normalize_attr(
            attrs.get("distinguishedName"))
        kind = kind or cls._kind_of_attrs(attrs)

        when_created = ad_generalized_time_to_dt(first_value(attrs, "whenCreated"))
        when_changed = ad_generalized_time_to_dt(first_value(attrs, "whenChanged"))

        if kind == ObjectKind.USER:
            # 复用 _to_user_row：UAC 位、锁定判定、pwdLastSet=0 那套边界逻辑
            # 已经在后端 118 例测试里磨过，**不要在这里重写一遍**（必然分叉）。
            row = cls._to_user_row(entry)
            obj = DirObject.from_user(row)
            obj.cn = (normalize_attr(attrs.get("cn")) or row.display_name
                      or row.sam)
            obj.description = normalize_attr(attrs.get("description"))
            obj.mail = normalize_attr(attrs.get("mail"))
            obj.when_created = when_created
            obj.when_changed = when_changed
            return obj

        if kind == ObjectKind.OU:
            return DirObject(
                kind=kind,
                cn=(normalize_attr(attrs.get("ou"))
                    or normalize_attr(attrs.get("cn"))),
                description=normalize_attr(attrs.get("description")),
                dn=dn, parent_dn=parent_of_dn(dn),
                when_created=when_created, when_changed=when_changed)

        common: dict[str, Any] = {
            "kind": kind,
            "cn": normalize_attr(attrs.get("cn")),
            "sam": normalize_attr(attrs.get("sAMAccountName")),
            "display_name": normalize_attr(attrs.get("displayName")),
            "description": normalize_attr(attrs.get("description")),
            "dn": dn,
            "parent_dn": parent_of_dn(dn),
            "when_created": when_created,
            "when_changed": when_changed,
        }

        if kind == ObjectKind.GROUP:
            # groupType 是**有符号**返回时的 0x80000000 会变成负数，
            # 所以先 & 0xFFFFFFFF 再判位，否则安全组会被认成通讯组。
            #
            # ⚠️ 走 `_attr_text`（优先 `raw_attributes`）：groupType 的字节常全
            #    < 0x80（如 `02 00 00 00`）⇒ `attributes` 里是控制字符串
            #    ⇒ `_safe_int` 给 `None`。
            #
            # 🔴 读不到就是**读不到**，不许 `or 0`（2026-09-17 改）。
            #    `or 0` 之后 gtype=0，而 0 里 `GROUP_SECURITY_ENABLED` 是关的
            #    ⇒ 一个**安全组**被显示成"通讯组"（旧注释自己都点出了这条路）。
            #    现在两个维度都留空串 = 未知，由 `models` 显示成"组类型未知"。
            raw_gtype = _safe_int(_attr_text(entry, "groupType"))
            gtype = None if raw_gtype is None else raw_gtype & 0xFFFFFFFF
            return DirObject(
                **common,
                has_account=False,
                group_scope="" if gtype is None else _group_scope_of(gtype),
                group_category=("" if gtype is None
                                else ("security" if gtype & GROUP_SECURITY_ENABLED
                                      else "distribution")),
            )

        if kind == ObjectKind.COMPUTER:
            # ⚠️ 同 `groupType`：电脑的 UAC 也常全 < 0x80。
            #
            # 🔴 读不到 ⇒ 三个字段全 `None`：**"不知道这台机器是不是域控"这件事
            #    必须一路传到界面**（2026-09-17 改）。旧写法 `or 0` 之后
            #    uac=0 ⇒ `enabled` 变 True、`is_dc` 变 False ⇒ 一台域控在界面上
            #    就是"已启用的普通电脑"，右键菜单照给「禁用 / 重置计算机账户 /
            #    删除」，而这三件事对域控本应被拦掉。
            uac = _safe_int(_attr_text(entry, "userAccountControl"))
            return DirObject(
                **common,
                has_account=True,
                enabled=(None if uac is None
                         else not has_uac_flag(uac, UF_ACCOUNTDISABLE)),
                # 域控就是一台计算机；它比普通计算机多一堆禁区（不能禁用/删除）
                is_dc=(None if uac is None
                       else has_uac_flag(uac, UF_SERVER_TRUST_ACCOUNT)),
                uac=uac,
                dns_host_name=normalize_attr(attrs.get("dNSHostName")),
                os=normalize_attr(attrs.get("operatingSystem")),
                os_version=normalize_attr(attrs.get("operatingSystemVersion")),
                location=normalize_attr(attrs.get("location")),
                last_logon=ad_filetime_to_dt(
                    _attr_text(entry, "lastLogonTimestamp")),
            )

        if kind == ObjectKind.CONTACT:
            return DirObject(
                **common,
                has_account=False,
                mail=normalize_attr(attrs.get("mail")),
                given_name=normalize_attr(attrs.get("givenName")),
                surname=normalize_attr(attrs.get("sn")),
            )

        # 容器、打印机队列、MSA 之类：能列出来、能删，但不假装懂它
        return DirObject(**common, has_account=False)

    @staticmethod
    def _kind_of_attrs(attrs: Any) -> str:
        """按 `objectClass` 判断对象类型。

        ⚠️ **判断顺序有硬性要求**：计算机账号的 `objectClass` 是
        ``[top, person, organizationalPerson, user, computer]`` —— **含 user**。
        先判 `user` 的话，每台计算机会被认成用户，然后界面上会多出一批
        "登录名带 $" 的奇怪用户。必须**先判具体类型，user 放最后**。
        """
        classes = {c.lower() for c in _as_list((attrs or {}).get("objectClass"))}
        if not classes:
            return ""
        if "organizationalunit" in classes:
            return ObjectKind.OU
        if "group" in classes:
            return ObjectKind.GROUP
        if "computer" in classes:
            return ObjectKind.COMPUTER
        if "contact" in classes:
            return ObjectKind.CONTACT
        if "user" in classes:
            return ObjectKind.USER
        return ObjectKind.OTHER

    # ==================================================================
    # 删除
    # ==================================================================

    def plan_delete(self, dn: str, kind: str = "", label: str = "") -> DeletePlan:
        """算出"删这个会删掉什么"。**不执行任何写操作。**

        先算再确认 —— 删一个 OU 时，使用者必须**在点确认之前**就看到
        「下面还有 37 个对象会一起没」，而不是点完才收到一个
        `NOT_ALLOWED_ON_NON_LEAF` 错误码。
        """
        self._ensure()
        dn = (dn or "").strip()
        if not dn:
            raise AdToolError("未指定要删除的对象。")

        attrs = self.read_attributes(
            dn, ["objectClass", "cn", "ou", "sAMAccountName", "displayName",
                 "userAccountControl", "groupType"])
        real_kind = self._kind_of_attrs(attrs) or kind
        label = label or (normalize_attr(attrs.get("cn"))
                          or normalize_attr(attrs.get("ou")) or dn)

        blocked = self._delete_block_reason(dn, real_kind, attrs)
        if blocked:
            return DeletePlan(root_dn=dn, root_label=label,
                              blocked_reason=blocked)

        # 只有容器类对象可能有后代。用户/组/计算机/联系人在 AD 里都是叶子，
        # 对它们做子树搜索纯属浪费一次往返。
        if real_kind not in (ObjectKind.OU, ObjectKind.OTHER):
            return DeletePlan(root_dn=dn, root_label=label)

        raw = self._paged_search(dn, "(objectClass=*)", "SUBTREE",
                                 DELETE_SCAN_ATTRIBUTES)
        target = dn.casefold()
        descendants: list[DirObject] = []
        for entry in raw:
            entry_dn = (entry.get("dn") or "").strip()
            if entry_dn.casefold() == target:
                continue      # 子树搜索包含 base 自身，要排掉
            descendants.append(self._to_dir_object(entry))

        # 深 → 浅排序：子对象的 DN 一定比父对象多一段，
        # 按深度降序删就天然保证"先删完孩子再删爹"。
        descendants.sort(key=lambda o: dn_depth(o.dn), reverse=True)
        return DeletePlan(root_dn=dn, root_label=label, descendants=descendants)

    def _delete_block_reason(self, dn: str, kind: str, attrs: Any) -> str:
        """本地拦截不该删的对象。返回空串 = 允许删。"""
        base = (self.base_dn or "").strip()
        if base and dn.strip().casefold() == base.casefold():
            return "这是域根目录，本工具不允许删除整个域。"
        if not parent_of_dn(dn):
            return "这是域根目录，不能删除。"

        rdn = rdn_of(dn).casefold()
        if rdn in PROTECTED_CONTAINERS:
            return PROTECTED_CONTAINERS[rdn]

        if kind == ObjectKind.COMPUTER:
            raw_uac = _safe_int(first_value(attrs, "userAccountControl"))
            if raw_uac is None:
                # 🔴 fail-closed（2026-09-17 改）。这是一道**安全闸**，它要回答的
                #    问题就是"它是不是域控"。读不到 ⇒ 排除不掉 ⇒ 拒。
                #    旧写法 `or 0` 会让这道闸**静默失效**：删域控只剩域控侧兜底，
                #    而本机这一层看起来是"放行"的。
                #    方向的取舍与 `_uac_of_now` 一致：删除不可逆（AD 回收站默认
                #    关闭），而"这一次删不了"是看得见、可重试的。
                return ("读不到这台计算机的 userAccountControl，无法确认它不是"
                        "域控制器，因此拒绝删除（删除域控会破坏整个域的复制与"
                        "认证）。请刷新后重试；若持续如此，请检查读取该属性的权限。")
            if has_uac_flag(raw_uac, UF_SERVER_TRUST_ACCOUNT):
                return ("该对象是「域控制器」（DC）。删除域控会破坏整个域的"
                        "复制与认证，本工具不允许。")
        return ""

    def delete_object(self, dn: str, kind: str = "", label: str = "",
                      sam: str = "", expected_total: int | None = None,
                      confirmed_dns: list[str] | None = None) -> int:
        """删除对象（容器则递归删除子对象）。返回实际删除的对象总数。

        `expected_total` 是「确认框里显示的那个总数」。传了就做一次
        **删除范围复核**：重新算计划，个数对不上就中止。
        理由：删除不可逆，而确认框和真正执行之间可能隔了几十秒 ——
        正好有人往这个 OU 里放了个新账号的话，他会连带删掉一个
        自己从没看过的对象。

        `confirmed_dns`（推荐，UI 单条删除流程传的是确认时刻的**后代
        DN 快照**）：比数量复核更精确 —— 数量抓不住「同数量的替换」
        （移走一个、又移进另一个，数量不变但删的是没确认过的对象）。
        传了它就以 DN 集合 diff 为准，数量检查自动被覆盖。

        ⚠️ 删完是**真的没了**：AD 回收站默认关闭（Windows Server 2008 R2 起
        可选启用，但默认不开）。删错了只能从备份恢复。
        """
        self._ensure()
        plan = self.plan_delete(dn, kind, label)

        if not plan.allowed:
            err = AdToolError(plan.blocked_reason)
            self._audit_failure(OP_DELETE, sam, dn, err)
            raise err

        if confirmed_dns is not None:
            diff = plan.diff_against(confirmed_dns)
            if diff:
                err = AdToolError(
                    f"「{plan.root_label}」的内容在确认之后发生了变化：{diff}\n"
                    "为避免删掉你没看过的对象，本次删除已中止，请重新确认。")
                self._audit_failure(OP_DELETE, sam, dn, err)
                raise err
        elif expected_total is not None and plan.total != expected_total:
            err = AdToolError(
                f"「{plan.root_label}」的内容在确认之后发生了变化"
                f"（确认时 {expected_total} 个对象，现在 {plan.total} 个）。\n"
                "为避免删掉你没看过的对象，本次删除已中止，请重新确认。")
            self._audit_failure(OP_DELETE, sam, dn, err)
            raise err

        descendants = plan.descendants
        deleted = 0
        for obj in descendants:
            if self._delete_raw(obj.dn):
                deleted += 1
                continue
            err = _result_error(self._conn, f"删除「{obj.title or obj.dn}」")
            detail = (f"部分删除：已删 {deleted} / {len(descendants)} 个子对象，"
                      f"在 {obj.dn} 处中断。{err.message}")
            self._audit_failure(OP_DELETE, sam, dn, err, detail=detail)
            raise AdToolError(
                f"删除中断：已删 {deleted} / {len(descendants)} 个子对象，"
                f"删除「{obj.title or obj.dn}」时失败 —— {err.message}\n"
                "该容器「未被删除」，但里面的部分对象已经删掉了。"
                "请刷新列表确认现状后决定是否继续。")

        if not self._delete_raw(dn):
            err = _result_error(self._conn, f"删除「{plan.root_label}」")
            detail = (f"子对象已全部删除（{deleted} 个），"
                      f"但根对象删除失败：{err.message}")
            self._audit_failure(OP_DELETE, sam, dn, err, detail=detail)
            raise AdToolError(
                f"{detail}\n常见原因：该容器设置了「防止对象被意外删除」保护，"
                "或你没有删除该容器的权限。")

        self._children_cache.pop(parent_of_dn(dn), None)
        self._children_cache.pop(dn, None)
        self._audit_success(
            OP_DELETE, sam, dn,
            detail=f"{plan.summary()}；共删除 {plan.total} 个对象",
            before={"distinguishedName": dn,
                    "descendant_count": len(descendants)},
            after=None)
        _log.info("已删除 %s（含子对象 %d 个）", dn, len(descendants))
        return plan.total

    def _delete_raw(self, dn: str) -> bool:
        """真正发一次 delete。**结果必须是 True** 才算成功。

        `raise_exceptions=False` 的连接下，失败会返回 ``False`` 或一个
        带 ``result`` 的 dict —— 用 ``if result:`` 判断会把
        ``{'result': 50, ...}``（权限不足）当成成功。
        """
        try:
            result = self._conn.delete(dn)
        except Exception as exc:                 # noqa: BLE001
            _log.warning("删除 %s 抛出异常：%s", dn, exc)
            return False
        if result is True:
            return True
        if isinstance(result, dict):
            try:
                return int(result.get("result")) == 0
            except (TypeError, ValueError):
                return False
        return False

    # ==================================================================
    # 移动 / 重命名
    # ==================================================================

    def move_object(self, dn: str, new_parent_dn: str, sam: str = "",
                    label: str = "") -> str:
        """把对象移动到另一个容器。返回新的 DN。

        **AD 用同一个操作实现「移动」与「重命名」**：都是 ModifyDN。
        只给 ``new_superior`` 就是移动；只改 RDN 就是重命名；
        两个都给就是「移动并改名」。所以这两个方法长得像不是巧合。

        移动是**安全**的：组成员关系、manager/directReports 这些指向它的
        链接由 AD 自动跟着更新 DN，不会断。
        """
        self._ensure()
        dn = (dn or "").strip()
        new_parent_dn = (new_parent_dn or "").strip()
        if not dn:
            raise AdToolError("未指定要移动的对象。")
        if not new_parent_dn:
            raise AdToolError("请选择要移动到的目标容器。")

        old_parent = parent_of_dn(dn)
        if old_parent.casefold() == new_parent_dn.casefold():
            raise AdToolError(f"对象已经在这个容器里了（{old_parent}）。")
        if (new_parent_dn.casefold() == dn.casefold()
                or is_descendant_dn(new_parent_dn, dn)):
            raise AdToolError(
                "不能把对象移动到它自己或它的下级容器里 —— 那会形成一个"
                "无法解析的环，AD 也拒绝执行。")

        rdn = rdn_of(dn)
        if not rdn:
            raise AdToolError("无法解析对象的名称，请刷新列表后重试。")
        new_dn = f"{rdn},{new_parent_dn}"

        if not self._modify_dn(dn, rdn, new_superior=new_parent_dn):
            err = _result_error(self._conn, f"移动「{label or dn}」")
            self._audit_failure(OP_MOVE, sam, dn, err,
                                detail=f"目标容器：{new_parent_dn}")
            raise err

        self._children_cache.pop(old_parent, None)
        self._children_cache.pop(new_parent_dn, None)
        self._audit_success(OP_MOVE, sam, dn,
                            detail=f"{old_parent} → {new_parent_dn}",
                            before={"distinguishedName": dn},
                            after={"distinguishedName": new_dn})
        _log.info("已移动 %s → %s", dn, new_dn)
        return new_dn

    def rename_object(self, dn: str, new_name: str, kind: str = "",
                      sam: str = "", sync_account_name: bool = True) -> str:
        """重命名对象（只改 RDN）。返回新的 DN。

        ⚠️ **重命名不会改 `sAMAccountName`。**
        把「张三」改成「张四」，登录名还是 `zhangsan` —— ADUC 的简单重命名
        也是这个行为（要改登录名得单独去「账户」页）。这一点必须让使用者
        知道，否则他会以为改完名字登录名也跟着变了。

        例外是**计算机**：`cn` 与 `sAMAccountName`/`dNSHostName` 是绑在一起的，
        只改 cn 会让这台机器在域里名字对不上。所以计算机默认同步登录名
        （``sync_account_name=True``），与 ADUC 行为一致。
        """
        self._ensure()
        dn = (dn or "").strip()
        new_name = (new_name or "").strip()
        if not dn:
            raise AdToolError("未指定要重命名的对象。")
        if not new_name:
            raise AdToolError("请填写新的名称。")
        if any(ch in new_name for ch in '\\/[]:;|=,+*?<>"'):
            raise AdToolError(f"名称「{new_name}」含有 AD 不允许的字符。")

        old_rdn = rdn_of(dn)
        prefix = old_rdn.split("=", 1)[0] if "=" in old_rdn else "CN"
        new_rdn = f"{prefix}={_escape_rdn(new_name)}"
        if new_rdn.casefold() == old_rdn.strip().casefold():
            raise AdToolError("新名称与当前名称相同，无需修改。")

        attrs = self.read_attributes(
            dn, ["cn", "ou", "sAMAccountName", "dNSHostName",
                 "userAccountControl"])
        kind = kind or self._kind_of_attrs(attrs)
        before = {
            "distinguishedName": dn,
            "cn": normalize_attr(attrs.get("cn")),
            "sAMAccountName": normalize_attr(attrs.get("sAMAccountName")),
        }

        if not self._modify_dn(dn, new_rdn):
            err = _result_error(self._conn, f"重命名「{before['cn'] or dn}」")
            self._audit_failure(OP_RENAME, sam, dn, err,
                                detail=f"目标名称：{new_name}", before=before)
            raise err

        parent = parent_of_dn(dn)
        new_dn = f"{new_rdn},{parent}" if parent else new_rdn
        after = {"distinguishedName": new_dn, "cn": new_name}

        # 计算机：cn 改了但登录名没改 → 这台机器在域里会对不上号
        if kind == ObjectKind.COMPUTER and sync_account_name:
            updates: dict[str, Any] = {"sAMAccountName": [f"{new_name}$"]}
            old_dns = normalize_attr(attrs.get("dNSHostName"))
            suffix = (old_dns.split(".", 1)[1] if "." in old_dns
                      else self.domain)
            if suffix:
                updates["dNSHostName"] = [f"{new_name}.{suffix}"]

            ok = self._conn.modify(new_dn, {
                key: [(_modify_replace(), value)]
                for key, value in updates.items()})
            if not ok:
                reason = _result_error(self._conn, "同步计算机登录名").message
                self._audit_success(
                    OP_RENAME, sam, dn,
                    detail=(f"{old_rdn} → {new_rdn}；"
                            f"但同步 sAMAccountName/dNSHostName 失败：{reason}"),
                    before=before, after=after)
                raise AdToolError(
                    f"已重命名为「{new_name}」，但同步计算机登录名失败：{reason}\n"
                    f"这台机器的 cn 与 sAMAccountName 现在不一致，"
                    f"请在「属性编辑器」里手工把 sAMAccountName 改成 {new_name}$。")
            after.update({k: v[0] for k, v in updates.items()})

        self._children_cache.pop(parent, None)
        self._audit_success(
            OP_RENAME, sam, dn,
            detail=f"{old_rdn} → {new_rdn}"
                   + ("（已同步计算机登录名）" if kind == ObjectKind.COMPUTER
                      and sync_account_name else "（登录名未改）"),
            before=before, after=after)
        _log.info("已重命名 %s → %s", dn, new_dn)
        return new_dn

    def _modify_dn(self, dn: str, new_rdn: str,
                   new_superior: str | None = None) -> bool:
        r"""发一次 ModifyDN。返回是否成功。

        ⚠️ 连接是 ``check_names=False``，此时 ldap3 **不做** `safe_rdn` 净化，
        传进来的 RDN 必须已经转义过（本文件里的调用点都走 `_escape_rdn`）。
        重命名时 RDN 来自既有 DN（已经是转义态），原样回传即可，
        **不能再转义一次** —— 会把 `\,` 变成 `\\,`。
        """
        try:
            result = self._conn.modify_dn(
                dn, new_rdn, delete_old_dn=True, new_superior=new_superior)
        except Exception as exc:                 # noqa: BLE001
            _log.warning("ModifyDN %s → %s 抛出异常：%s", dn, new_rdn, exc)
            return False
        if result is True:
            return True
        if isinstance(result, dict):
            try:
                return int(result.get("result")) == 0
            except (TypeError, ValueError):
                return False
        return False

    # ==================================================================
    # 修改属性
    # ==================================================================

    def modify_object(self, dn: str, changes: Iterable[AttributeChange],
                      sam: str = "") -> ModifyResult:
        """批量写属性（属性编辑器与各属性页共用）。

        ``AttributeChange.values`` 为空列表 = **删除该属性**，走
        `MODIFY_DELETE`；否则走 `MODIFY_REPLACE`。

        ⚠️ 空列表与「空字符串」是两回事：把 `mail` 写成 `""` 会在 AD 里留下
        一个"存在但为空"的 mail（很多工具会当成有值），真正的清空必须
        `MODIFY_DELETE`。这个区分是属性编辑器最容易做错的地方。

        写完**立刻回读比对**，不信任 `modify()` 的返回值 ——
        ACL 静默忽略、值类型不对被丢弃，都会返回 True。
        """
        self._ensure()
        items = [c for c in (changes or []) if c and (c.attribute or "").strip()]
        if not items:
            raise AdToolError("没有需要修改的属性。")

        operations: dict[str, Any] = {}
        refused: list[str] = []
        warnings: list[str] = []
        for change in items:
            attr = change.attribute.strip()
            allowed, reason = is_attribute_writable(attr)
            if not allowed:
                refused.append(f"{attr}（{reason}）")
                continue
            if reason:
                warnings.append(f"{attr}：{reason}")
            if change.is_delete:
                operations[attr] = [(_modify_delete(), [])]
            else:
                operations[attr] = [(_modify_replace(), list(change.values))]

        if refused:
            err = AdToolError("以下属性不允许在这里修改：\n· "
                              + "\n· ".join(refused))
            self._audit_failure(OP_UPDATE, sam, dn, err,
                                detail="；".join(str(c) for c in items))
            raise err
        if not operations:
            raise AdToolError("没有可写入的属性。")

        names = sorted(operations)
        before = self.read_attributes(dn, names)

        if not self._conn.modify(dn, operations):
            err = _result_error(self._conn, "修改属性")
            self._audit_failure(OP_UPDATE, sam, dn, err,
                                detail="；".join(str(c) for c in items),
                                before=before)
            raise err

        after = self.read_attributes(dn, names)
        written, unchanged = verify_changes(items, after)

        self._audit_success(
            OP_UPDATE, sam, dn,
            detail="；".join(str(c) for c in items)
                   + (f"；未生效：{'、'.join(unchanged)}" if unchanged else ""),
            before=before, after=after)
        return ModifyResult(written=written, unchanged=unchanged,
                            warnings=warnings)

    # ==================================================================
    # 审计辅助
    # ==================================================================

    def _audit_success(self, op: str, sam: str, dn: str, detail: str = "",
                       before: Any = None, after: Any = None,
                       secrets: tuple = ()) -> None:
        if self.audit is None:
            return
        warn = self.audit.write_or_warn(
            op=op, target_sam=sam, target_dn=dn, result="success",
            detail=detail, before=before, after=after, secrets=secrets)
        if warn:
            # 操作成功但日志没落盘 —— 必须让使用者知道
            _log.error("审计写入失败 op=%s sam=%s", op, sam)

    def _audit_failure(self, op: str, sam: str, dn: str, error: AdToolError,
                       detail: str = "", before: Any = None,
                       secrets: tuple = ()) -> None:
        if self.audit is None:
            return
        self.audit.write(op=op, target_sam=sam, target_dn=dn, result="failed",
                         detail=detail or error.message, before=before,
                         after=None, secrets=secrets)


# ============================================================================
# 小工具
# ============================================================================

def _modify_replace():
    from ldap3 import MODIFY_REPLACE
    return MODIFY_REPLACE


def _modify_delete():
    """`MODIFY_DELETE` —— 真正把属性删掉。

    ⚠️ 与「写空字符串」不是一回事，见 `AttributeChange` 的说明。
    """
    from ldap3 import MODIFY_DELETE
    return MODIFY_DELETE


def _raw_first(entry: Any, name: str) -> Any:
    """从 ldap3 的原始条目里取**单值属性**，**优先 `raw_attributes`**。

    ⚠️ 为什么必须优先（2026-09-15 真域缺陷的修法，`utils.format_attr_value`
    的 docstring 有完整根因链）：`attributes` 里的值**已经被解过一遍，而且解出来
    的是 `str` —— 不是"有时是 str"**。本项目连接的既有配置决定了它走**快解码器**：

      * `Connection(fast_decoder=True)` 是**默认值**（`ldap3/core/connection.py:207`，
        项目没覆盖）+ 本模块的 `check_names=False`
        ⇒ `ldap3/operation/search.py:573` 选 `attributes_to_dict_fast`；
      * 它经 `decode_vals_fast`（`:388`）→ `to_unicode(..., from_server=True)`
        （`ldap3/utils/conv.py:35`）；后者在 UTF-8 失败后**依次尝试
        `['latin-1','koi8-r']`**（`conv.py:53`）⇒ **latin-1 必然成功**。

    ⇒ **每个值都是 `str`**（全 < 0x80 的是一串控制字符，含 ≥ 0x80 的是 latin-1
    乱码），于是 `format_attr_value` 的 `isinstance(value, bytes)` 判据**恒假**：

      * SID/GUID 乱码上屏；`userAccountControl` 的 `'\x00\x02\x00\x00'`
        让 `int()` 直接 `ValueError`（账号属性页打不开）；
      * `_safe_int` 把它当文本读 ⇒ `None` ⇒ 调用方 `or 0`
        ⇒ `set_enabled` 把当前 UAC 当成 0，写回时**冲掉 NORMAL_ACCOUNT
        及其它所有标志位**（`512` → `2`）。

    `raw_attributes` 不过任何解码器（`ldap3/operation/search.py:569` 无条件构造），
    是唯一可信的字节来源。

    ⚠️ **这里曾经写过一条被真域证伪的判断**：「字节里一旦出现 ≥ 0x80 就解码失败、
    留下 `bytes`，看起来就好了」。那是**慢解码器**（`format_unicode`）的行为，
    本项目**不走那条**。真域上 `objectGUID` 一样是乱码 `str`，只是走 latin-1 分支。
    ⇒ 别用"这个对象显示正常"推断"这条路径没问题"。
    """
    raw = first_value(entry.get("raw_attributes"), name)
    if raw is not None:
        return raw
    # 回落分支：只为兼容不带 `raw_attributes` 的替身 / 手工拼的条目。
    return first_value(entry.get("attributes"), name)


def _attr_text(entry: Any, name: str) -> str | None:
    """取属性 → **文本视图**；属性缺失/为空 ⇒ ``None``。

    ⚠️ 属性缺失**必须回 `None`**，不能回 `format_attr_value(name, None)` ——
    后者对已知整数属性会给出 ``<已解码文本，非原始字节：None>``，把
    「没读到」伪装成一个值。`_is_zero` 那类判据最怕这个
    （它专门区分「属性值是 0」和「属性没读到」）。
    """
    raw = _raw_first(entry, name)
    if raw is None:
        return None
    return format_attr_value(name, raw)


def _attrs_to_text(raw: Any) -> dict[str, list[str]]:
    """ldap3 的 ``raw_attributes`` → ``{属性名: [值, ...]}``（**按属性名**转换）。

    ⚠️ 必须**带属性名**转换：`objectSid` / `objectGUID` 是二进制，按 UTF-8
    解码会得到一串控制字符（属性面板上就是乱码）。

    🔴 这份转换**只有这一处**：`read_attributes`（单对象）与
    `search_attributes`（一批对象）共用它。抄第二份必然分叉，而分叉的表现是
    "某一个入口上 SID 是乱码、另一个入口正常" —— 那种缺陷只会被
    **恰好走到那个入口**的用例抓到。
    """
    if raw is None:
        return {}
    return {key: _as_list(value, key) for key, value in raw.items()}


def _as_list(value: Any, name: str = "") -> list[str]:
    """把 ldap3 的属性值统一成**字符串列表**（保留多值）。

    :param name: 属性名。**只有知道属性名才能认出二进制属性**（`objectSid` /
        `objectGUID` —— 它们的 bytes 不能按 UTF-8 解码，见
        `utils.format_attr_value`）。不传 = 按纯文本处理。

    ⚠️ 位图类属性（`logonHours`）**刻意不走这里**：它必须保持 bytes 才能逐字节
    比对，`get_logon_hours` 因此自己开了一条裸读通道。别把本函数当"万能入口"。
    """
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [format_attr_value(name, item) for item in value if item is not None]
    return [format_attr_value(name, value)]


def _group_scope_of(group_type: int) -> str:
    """从 `groupType` 位组合里解出作用域。

    位值：全局 2 / 域本地 4 / 通用 8。老域里可能还有 BUILTIN_LOCAL_GROUP(1)，
    那不是作用域，忽略。
    """
    value = int(group_type) & 0xFFFFFFFF
    for name in ("universal", "domainlocal", "global"):
        if value & GROUP_SCOPE[name]:
            return name
    return ""


def _logon_hours_brief(raw: bytes | bytearray | None) -> str:
    """位图的审计摘要。``None`` = 未限制；否则 21 字节十六进制（42 字符）。"""
    if raw is None:
        return "（未限制）"
    return bytes(raw).hex()


def _result_error(conn: Any, context: str) -> AdToolError:
    """从 ``conn.result`` 造一个中文 ``AdToolError``。

    ⚠️ 这里**必须**做 None 防御：``LDAPSocketSendError`` 等场景下
    ``conn.result`` 里根本没有 ``result`` 键，直接丢给 ``translate_ldap_code``
    会变成 ``TypeError: int() argument must be...`` —— 一个本该是
    "网络断了" 的提示会变成看不懂的类型错误。
    """
    result = (getattr(conn, "result", None) or {})
    code = result.get("result")
    if code is not None:
        try:
            return AdToolError(translate_ldap_code(int(code)), code=str(code))
        except (TypeError, ValueError):
            pass
    message = result.get("message") or result.get("description") or "域控未返回具体原因"
    return AdToolError(f"{context}失败：{message}")


def _safe_int(value: Any) -> int | None:
    """把可能是 str / bytes / list / None 的值安全转 int。

    ⚠️ 两条分支**不能混**（混了就是 2026-09-15 那个真域缺陷）：
      * ``bytes``（整数属性在 `raw_attributes` 里的形态）⇒ **一律转交**
        `utils.int_bytes_to_int`（全项目唯一的「字节 → 整数」换算；
        **形态由它判，这里不许自己再猜一次**）。
        ⚠️ 原注释写作「（真域上…的形态）⇒ `utils.int_bytes_to_int`（**小端**无符号）」，
        **把两种形态标反了** —— 2026-09-16 按真域实测更正（= T-3）：
        **真域 AD 发的是 ASCII 十进制文本**（`b'512'`，证据在
        `utils.int_bytes_to_int` docstring 的表格与 `tools/repro_int_attr_decode.py`），
        **小端无符号二进制才是替身 `tests/fake_ldap`** 的建模。
        真域那侧若按小端读，512 会被解成 `0x323135`（=「密码永不过期」报 80 的成因）。
        ❌ 绝不能 `decode()` 当文本读 —— 那正是把 `userAccountControl`
        读成 `None` 的原因（`'\\x00\\x02\\x00\\x00'` 的 `int()` 直接 ValueError）。
      * ``str`` ⇒ 十进制文本（审计 / 界面 / 演示域 / 替身给的形态）⇒ `int(value)`。
        ❌ 绝不能对 `str` 用 `from_bytes` —— 那会算出一个巨大的假值。

    ⚠️ 返回 ``None`` = 「没读到 / 读不懂」。调用方**不要**无条件 `or 0` 了事：
    对 `userAccountControl` 这种「读当前值 → 翻一位 → 写回」的语义，
    把读不懂当成 0 **等于把账号其余所有标志位（含 NORMAL_ACCOUNT）清空**。
    读不到时应当**中止**（见 `set_enabled` / `set_uac_single_flag`）。
    """
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
        if value is None:
            return None
    if isinstance(value, (bytes, bytearray)):
        return int_bytes_to_int(value)
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _uac_of_now(raw_text: Any, context: str) -> int:
    """把「改动前的 `userAccountControl`」读成一个整数；**读不到就中止**。

    ⚠️ 为什么不能 `or 0` 兜底（2026-09-15 真域缺陷的连带部分）：
    启用/禁用与「翻转一个 UAC 位」都是**读当前值 → 翻一位 → 写回**的语义。
    一旦读不到（真域上 `attributes` 给的是含控制字符的 `str`，`_safe_int`
    返回 `None`）而调用方 `or 0`，`set_uac_flag(0, 0x0002, True)` 就是 `2`
    ⇒ **写回时把 `NORMAL_ACCOUNT`(0x200) 及其它所有位冲掉**，
    而这两个方法的 docstring 都承诺"其余位原样保留"。

    ⇒ 「读不到」必须**中止**。宁可这一次操作失败，也不能悄悄把别人账号的
    标志位清空 —— 前者看得见、可重试，后者看不出来、要事后翻审计才发现。
    """
    value = _safe_int(raw_text)
    if value is None:
        raise AdToolError(
            "读不到当前的账号控制标志（userAccountControl），无法安全地只翻转目标位。"
            "若按 0 继续写入，会把账号其余标志位（含「普通账号」）一并清空，"
            "因此已中止本次「%s」。请刷新后重试；若持续如此，请检查读取该属性的权限。"
            % context)
    return value


def _is_zero(raw: Any) -> bool:
    """属性**存在**且数值为 0。

    ⚠️ 必须把「属性缺失（``None``）」和「属性值是 0」分开 ——
    两者含义天差地别：

    ==========================  ======================================
    ``pwdLastSet``              ``msDS-UserPasswordExpiryTimeComputed``
    ==========================  ======================================
    ``0`` = 下次登录必须改密码      ``0`` = 密码已过期（须立即修改）
    缺失  = 没读到，不代表任何事    缺失  = 没读到，不代表任何事
    ==========================  ======================================

    ⚠️ 之所以单独写一个函数：``ad_filetime_to_dt(0)`` 返回 ``None``，
    而 ``None`` 在界面上显示为「永不过期」—— 若不区分，一个
    **被要求改密码的账号会被显示成「永不过期」**，正好相反。
    本工具自己建的号（``UserSpec.must_change=True``）就是 ``pwdLastSet=0``，
    所以这个坑是必然会踩到的。
    """
    if raw is None:
        return False
    try:
        return int(raw) == 0
    except (TypeError, ValueError):
        return False
