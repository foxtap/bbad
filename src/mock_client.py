# -*- coding: utf-8 -*-
"""
mock_client.py —— 「演示域」客户端（T01b / Mock 先行策略）

用途：**没有域控权限、域控端口不通、或本机未加域时，也能把整套界面跑起来**。

它与 `AdClient` **接口完全一致**，可以直接换进 UI：

.. code-block:: python

    from mock_client import make_mock_client
    client = make_mock_client(audit)      # 想要真实域控就换回 AdClient()
    client.connect(ConnConfig(dc_ip="demo"))   # 任意 IP 都能"连上"

设计上刻意做了三件「假戏真做」的事：

  1. **真的走审计**（AuditLog），所以「操作日志」窗口有真数据可看
  2. **真的做位运算**（set_uac_flag），所以「密码永不过期」之类的位不会假
  3. **真的会失败**（可注入），所以错误提示路径能被看见 ——
     只做"永远成功"的 Mock，等于把最需要验证的错误分支藏起来了

⚠️ 严禁把它当真实域使用：``IS_MOCK = True``，且域名固定为 ``demo.local``，
   界面上必须显示醒目的「演示模式」标记。
"""

from __future__ import annotations

import hashlib
import os
import random
import re
import time
from datetime import datetime as _datetime
from datetime import timedelta as _timedelta
from datetime import timezone as _timezone
from typing import Any

from audit import AuditLog
from ad_client import PROTECTED_CONTAINERS, verify_changes
from config import app_dir
from password_backend import ntlm_bind_identity
from preg_backend import REG_DWORD, REG_SZ, PregEntry, build_preg
from models import (
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
)
from utils import (
    GROUP_SECURITY_ENABLED,
    LOGON_HOURS_BYTES,
    UF_ACCOUNTDISABLE,
    UF_DONT_EXPIRE_PASSWORD,
    UF_LOCKOUT,
    UF_NORMAL_ACCOUNT,
    UF_PASSWD_NOTREQD,
    UF_SERVER_TRUST_ACCOUNT,
    AdToolError,
    ad_filetime_to_dt,
    ad_generalized_time_to_dt,
    datetime_to_ad_filetime,
    dn_depth,
    escape_dn_value,
    format_attr_value,
    get_logger,
    group_type_value,
    has_uac_flag,
    is_descendant_dn,
    parent_of_dn,
    rdn_of,
    set_uac_flag,
    sid_bytes_to_string,
    validate_ldap_filter,
)

__all__ = ["MockAdClient", "make_mock_client"]

_log = get_logger("mock")


# ---------------------------------------------------------------------------
# 演示对象的 objectSid / objectGUID
# ---------------------------------------------------------------------------
#
# ⚠️ 演示域**必须**给这两个属性，而且要用**真的二进制形态**（`bytes`）：
#   ① 真 AD 里每个对象都有它们（容器、OU 也有）⇒ 少了这两行，
#      「演示模式看到的面板」与「真域看到的面板」就不一样；
#   ② 真身 `read_attributes` 拿到的是 **bytes**，替身若直接存文本，
#      那条「二进制 → 文本」的转换在演示模式下**永远走不到** ⇒ 它坏了也看不见。
#
# 取值**按 DN/域名稳定派生**：同一个对象每次运行都得到同一个值（能用来验"没变"），
# 不同对象不同；同一个域里所有对象**共享域 SID 前缀**（这是真 AD 的语义，顺手保真）。
# 全部是**虚构**值：RID 由哈希导出，不对应任何真实账号。

#: 域 SID 的形态是 ``S-1-5-21-<域三元组>-<RID>`` —— 那个 **21** 是**固定值**
#: （`SECURITY_NT_NON_UNIQUE`），不是随机数，也不是域三元组的第一项。
#: ⚠️ 漏掉它得到的是 ``S-1-5-<三元组[0]>-…``（少一段）—— 形态看着还挺像，
#: 只有"前缀必须是 `S-1-5-21-`"这条判据能抓出来。
_NT_NON_UNIQUE = 21


def _demo_domain_sid_subs(domain: str) -> list[int]:
    """域 SID 的子权限**三元组**（`S-1-5-21-` 后面那 X-Y-Z）—— 同域共享。"""
    digest = hashlib.md5(("demo-domain-sid:" + domain).encode("utf-8")).digest()
    return [int.from_bytes(digest[0:4], "big"),
            int.from_bytes(digest[4:8], "big"),
            int.from_bytes(digest[8:12], "big")]


def _demo_sid_bytes(dn: str, domain: str) -> bytes:
    """按 MS-DTYP 的**规范布局**造一个稳定的演示 SID。"""
    digest = hashlib.md5(("demo-rid:" + dn).encode("utf-8")).digest()
    rid = 1000 + int.from_bytes(digest[0:4], "big") % 90_000
    subs = [_NT_NON_UNIQUE, *_demo_domain_sid_subs(domain), rid]
    raw = bytes([1, len(subs)]) + (5).to_bytes(6, "big")
    for sub in subs:
        raw += sub.to_bytes(4, "little")
    return raw


def _demo_guid_bytes(dn: str) -> bytes:
    """16 字节的稳定演示 GUID —— **原始形态**，即真身从域控拿回来的那种。"""
    return hashlib.md5(("demo-guid:" + dn).encode("utf-8")).digest()


#: 演示域把**这些属性按小端二进制整数**发出去（`Integer` 4 字节 /
#: `LargeInteger` 8 字节）—— 这就是 AD 的真实行为，也是真身
#: `read_attributes` 通过 `raw_attributes` 拿到的**唯一形态**。
#:
#: ⚠️ 为什么演示域也必须这么做（2026-09-15 真域缺陷）：
#: 真域上 ldap3 在无 schema 时会把整数**解成 `str`**（快解码器 +
#: latin-1 兜底，见 `utils.py` §6.1）—— `userAccountControl = 512`
#: 的 `00 02 00 00` 会变成**含控制字符的 `str`**。演示域若在这里存十进制文本，
#: 「整数属性读取」在演示模式走的就是**另一条分支**，
#: 真域上才暴露的缺陷在演示模式下**永远看不见**（1300+ 条用例全绿也照样漏）。
#:
#: ⚠️ 这张表是**演示域对"服务端"的建模**，与客户端侧的识别名单
#: （`utils._INTEGER_ATTRS`）刻意分开写：共用一份的话，
#: 「生产名单漏了一条」就永远不会变红。两边的一致性由
#: `tests/test_binary_attr_read.py::TestTheFakesModelTheServerIndependently` 盯着。
_AD_INT_WIDTH: dict[str, int] = {
    # ---- Integer（4 字节）----
    "useraccountcontrol": 4,
    "msds-user-account-control-computed": 4,
    "grouptype": 4,
    "primarygroupid": 4,
    "samaccounttype": 4,
    #: GPO 对象上的版本号（32 位：高 16 位计算机、低 16 位用户）。
    #: AD 语法就是 `Integer`（与 `utils._INTEGER_ATTRS` 里那条同源），
    #: 所以**必须**按小端二进制发出去 —— 演示域若直接发十进制文本，
    #: 「读回版本号」在演示模式走的就是另一条分支。
    "versionnumber": 4,
    # ---- LargeInteger（8 字节）----
    "pwdlastset": 8,
    "accountexpires": 8,
    "lockouttime": 8,
    "lastlogontimestamp": 8,
    "msds-userpasswordexpirytimecomputed": 8,
}


def _wire_attr_value(name: str, value: Any) -> Any:
    """演示域里一个属性值的**线上形态**。

    * 已经是 `bytes`（`objectSid` / `objectGUID` / `logonHours`）⇒ 原样；
    * 整数属性（见 `_AD_INT_WIDTH`）⇒ 小端二进制；
    * 其余（文本）⇒ 原样。

    ⚠️ 整数属性必须转：属性编辑器写下来的是 `"514"` 这种**文本**
    （LDAP modify 报文里传的就是文本），而 AD **读**回来给的是 4 字节二进制。
    演示域不做这一跳，"写进去读回来"两头都在，但走的是**两条不同分支** ——
    真域那条就成了整条链上唯一没被测过的部分。
    """
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    width = _AD_INT_WIDTH.get((name or "").casefold())
    if width is None:
        return value
    try:
        number = int(value)
    except (TypeError, ValueError):
        # 读不懂就原样交出去：演示域**不是**异常源，别让属性编辑器
        # 因为一个手写错的值整页打不开（那类问题该由真域/校验收口）。
        return value
    return (number & ((1 << (width * 8)) - 1)).to_bytes(width, "little")


IS_MOCK = True

MOCK_BASE_DN = "DC=demo,DC=local"
MOCK_DOMAIN = "demo.local"
MOCK_DC_IP = "192.0.2.10"          # RFC 5737 TEST-NET-1，永远不会是真地址

#: 演示域的「密码最长使用期限」，默认域策略通常是 42 天，这里取 90 天更宽容。
#: 真实环境这个值来自域策略，`AdClient` 直接读 AD 算好的
#: ``msDS-UserPasswordExpiryTimeComputed``；Mock 只能自己按这个常量推。
MAX_PWD_AGE_DAYS = 90


def _filetime_days_ago(days: float) -> int:
    """把「N 天前」换算成 FILETIME。

    ⚠️ 演示数据必须**相对当前时间**生成，不能写死常量 ——
    写死的话跑一段时间后所有人都会显示成「已过期 700 天」，
    演示界面会变得毫无参考价值。
    """
    return datetime_to_ad_filetime(
        _datetime.now(_timezone.utc) - _timedelta(days=days)) or 0


# ============================================================================
# 演示数据
# ============================================================================

def _default_tree() -> list[dict[str, Any]]:
    """默认的 OU 结构（三层，覆盖懒加载的展开场景）。"""
    return [
        {"name": "总部", "parent": MOCK_BASE_DN, "description": "公司总部"},
        {"name": "研发中心", "parent": f"OU=总部,{MOCK_BASE_DN}", "description": ""},
        {"name": "运维部", "parent": f"OU=研发中心,OU=总部,{MOCK_BASE_DN}", "description": "桌面运维 / 监控"},
        {"name": "开发部", "parent": f"OU=研发中心,OU=总部,{MOCK_BASE_DN}", "description": ""},
        {"name": "财务部", "parent": f"OU=总部,{MOCK_BASE_DN}", "description": ""},
        {"name": "南方工厂", "parent": MOCK_BASE_DN, "description": "示例制造基地"},
        {"name": "生产部", "parent": f"OU=南方工厂,{MOCK_BASE_DN}", "description": ""},
        {"name": "停用的旧部门", "parent": MOCK_BASE_DN, "description": "（用于验证空 OU 的显示）"},
        # AD 的默认容器。演示域里放一个，是为了让「域控不能删/不能禁用」
        # 这条拦截规则**在演示模式下也能被验证** —— 否则只能上真域才试得出来。
        {"name": "Domain Controllers", "parent": MOCK_BASE_DN,
         "description": "域控所在容器（不可删除）"},
        # ---- 内置 CN 容器（F10）：树里要和 ADUC 一样显示这三个 ----
        {"name": "Users", "parent": MOCK_BASE_DN, "container": True,
         "description": "默认用户容器（内置，不可删除）"},
        {"name": "Computers", "parent": MOCK_BASE_DN, "container": True,
         "description": "默认计算机容器（内置，不可删除）"},
        {"name": "Builtin", "parent": MOCK_BASE_DN, "container": True,
         "description": "内置组容器（不可删除）"},
    ]


_DEMO_PEOPLE = [
    # (sam, 姓名, OU, 密码已用天数, 附加属性)
    # 密码年龄刻意拉开，好让「密码」列出现
    # 已过期 / 即将过期 / 还剩一大截 / 永不过期 / 待改密码 五种形态。
    # 天数写 ``None`` 表示 ``pwdLastSet=0``（下次登录必须改密码）。
    # ⚠️ 全部为虚构姓名（张三/李四…），禁止放任何真实人名/账号。
    ("zhangsan", "张三", "运维部", 45, dict(title="IT 主管", department="运维部")),
    ("lisi", "李四", "运维部", 88, dict(title="桌面运维", department="运维部")),
    ("wangwu", "王五", "开发部", 95, dict(title="后端工程师", department="开发部")),
    ("zhaoliu", "赵六", "开发部", 12, dict(title="前端工程师", department="开发部")),
    ("sunqi", "孙七", "财务部", 91, dict(title="会计", department="财务部")),
    ("zhouba", "周八", "财务部", 30, dict(title="出纳", department="财务部")),
    ("qianjiu", "钱九", "生产部", 60, dict(title="产线主管", department="生产部")),
    ("wushi", "吴十", "生产部", 100, dict(title="技术员", department="生产部")),
    ("yushiyi", "于十一", "生产部", None, dict(title="技术员", department="生产部")),
    ("mashan", "马珊", "研发中心", 200, dict(title="", department="研发中心")),
]


class _MockUser:
    __slots__ = ("sam", "display_name", "given_name", "surname", "parent",
                 "uac", "locked", "pwd_last_set", "last_logon", "extra",
                 "when_created", "when_changed", "overrides",
                 "acct_expire_at")

    def __init__(self, sam: str, display_name: str, parent: str, **kw):
        self.sam = sam
        self.display_name = display_name
        self.given_name = kw.get("given_name", "")
        self.surname = kw.get("surname", "")
        self.parent = parent
        self.uac = kw.get("uac", UF_NORMAL_ACCOUNT)
        self.locked = kw.get("locked", False)
        self.pwd_last_set = kw.get("pwd_last_set", 133_000_000_000_000_000)
        #: 账户过期时间（``None`` = 永不过期）。
        #: ⚠️ 必须存成字段而不是只写进 ``overrides`` —— `get_object()` 与
        #:    列表行走的是这个字段。只写 overrides 会让「设置账户过期时间」
        #:    在演示模式里回读成「永不过期」，看着像功能没生效。
        self.acct_expire_at = kw.get("acct_expire_at", None)
        self.last_logon = kw.get("last_logon", None)
        self.extra = kw.get("extra", {})
        self.when_created = kw.get("when_created", "2024-03-12 09:31:07")
        self.when_changed = kw.get("when_changed", "2026-08-30 17:02:44")
        #: 属性编辑器写下来的"任意属性"。核心属性走 _apply_core 真正改字段，
        #: 其余落在这里 —— 这样 read_attributes 能读回刚写的内容，
        #: 「写完回读校验」那条路径在演示模式下也走得通。
        self.overrides: dict[str, list[str]] = kw.get("overrides", {})

    @property
    def dn(self) -> str:
        """⚠️ RDN 值必须走 **RFC 4514 转义**（与真域后端同一个 `escape_dn_value`）。

        名字里带逗号（`张三,备份`）时不转义，DN 会被解析成两段：
        「所属位置」列立刻错位，移动/删除按分段比较也会一起错。
        真域 `ad_client` 全程走 `ldap3.utils.dn.escape_rdn`，演示域漏掉
        就等于教用户一件错的事 —— 见 `tools/probe_mock_dn_escaping.py`。
        """
        return f"CN={escape_dn_value(self.display_name)},{self.parent}"

    @property
    def cn(self) -> str:
        """对象的 CN，也就是 RDN 里的名字。

        ⚠️ 必须和 `dn` **读同一份存储**（`display_name`）：否则
        `rename_object` 改了 `cn` 而 DN 没变（或反过来），演示域立刻自相矛盾 ——
        树里显示新名字、点进去却按旧 DN 找不到对象。

        这个属性曾经缺失，代价是「重命名用户」在演示模式下
        **100% 抛 AttributeError**，功能整个不可用（见 test_mock_client.py）。
        `_MockDirObject` 那三类天然有 `cn`，只有用户这类是从
        `display_name` 反推 DN 的，于是被漏掉了。
        """
        return self.display_name

    @cn.setter
    def cn(self, value: str) -> None:
        self.display_name = value or ""

    @property
    def pwd_expire_at(self) -> int | None:
        """AD 服务端算好的密码到期时间（FILETIME），近似 ``pwdLastSet + 域密码最长期限``。

        ⚠️ 三种情况要分开，别糊在一起：

        - **密码永不过期**：AD 返回 ``0x7FFFFFFF...`` 哨兵 → ``None``
        - **``pwdLastSet=0``**（下次登录必须改密码）：AD 的 computed 属性也返回
          ``0``。注意 ``0`` 不是"永不过期" —— 这个语义由
          `UserRow.pwd_must_change` 单独承载，`to_row()` 会同时把它置 True
        - **正常**：``pwdLastSet + 90 天``
        """
        if has_uac_flag(self.uac, UF_DONT_EXPIRE_PASSWORD):
            return None
        if not self.pwd_last_set:
            return 0                       # 与真实 AD 一致：computed 也是 0
        return self.pwd_last_set + MAX_PWD_AGE_DAYS * 86_400 * 10_000_000

    def to_row(self) -> UserRow:
        return UserRow(
            sam=self.sam,
            display_name=self.display_name or self.sam,
            enabled=not has_uac_flag(self.uac, UF_ACCOUNTDISABLE),
            locked=self.locked,
            pwd_expire_at=ad_filetime_to_dt(self.pwd_expire_at),
            pwd_must_change=not self.pwd_last_set,
            acct_expire_at=self.acct_expire_at,
            pwd_last_set=ad_filetime_to_dt(self.pwd_last_set),
            last_logon=ad_filetime_to_dt(self.last_logon) if self.last_logon else None,
            uac=self.uac,
            dn=self.dn,
        )


# ============================================================================
# 演示数据：组 / 计算机 / 联系人（批次 1 新增，让四类对象都能被看见）
# ============================================================================
#
# 为什么演示域要有这四类：ADUC 的一个 OU 里本来就是混合列的。
# 只演示用户的话，"混合列表 + 类型筛选 + 右键菜单按类型变" 这些界面
# 根本没法验证 —— 而它们恰好是最容易出 bug 的部分。

class _MockDirObject:
    """组 / 计算机 / 联系人的共同基类（用户另有 `_MockUser`，不动它）。

    只放四类共有的东西：名字、父容器、描述、时间戳、属性覆盖表。
    类型专属字段在子类里。
    """

    kind = ""
    __slots__ = ("cn", "sam", "parent", "description", "when_created",
                 "when_changed", "overrides")

    def __init__(self, cn: str, parent: str, sam: str = "",
                 description: str = "", **kw):
        self.cn = cn
        self.sam = sam or cn
        self.parent = parent
        self.description = description
        self.when_created = kw.get("when_created", "2024-03-12 09:31:07")
        self.when_changed = kw.get("when_changed", "2026-08-30 17:02:44")
        self.overrides: dict[str, list[str]] = kw.get("overrides", {})

    @property
    def dn(self) -> str:
        # 与 _MockUser.dn 同理：RDN 值一律转义（真域后端也是这么做的）
        return f"CN={escape_dn_value(self.cn)},{self.parent}"

    @property
    def title(self) -> str:
        return self.cn


class _MockGroup(_MockDirObject):
    kind = ObjectKind.GROUP
    __slots__ = ("scope", "category", "members")

    def __init__(self, cn: str, parent: str, **kw):
        super().__init__(cn, parent, **kw)
        self.scope = kw.get("scope", "global")
        self.category = kw.get("category", "security")
        self.members: list[str] = list(kw.get("members", []))


class _MockComputer(_MockDirObject):
    kind = ObjectKind.COMPUTER
    __slots__ = ("uac", "dns_host_name", "os", "os_version", "location",
                 "last_logon")

    def __init__(self, cn: str, parent: str, **kw):
        super().__init__(cn, parent, **kw)
        self.uac = kw.get("uac", 0x1000)          # WORKSTATION_TRUST_ACCOUNT
        self.dns_host_name = kw.get("dns_host_name", "")
        self.os = kw.get("os", "Windows 10 专业版")
        self.os_version = kw.get("os_version", "10.0 (19045)")
        self.location = kw.get("location", "")
        self.last_logon = kw.get("last_logon")


class _MockContact(_MockDirObject):
    kind = ObjectKind.CONTACT
    __slots__ = ("display_name", "given_name", "surname", "mail",
                 "telephone", "title_text", "department")

    def __init__(self, cn: str, parent: str, **kw):
        super().__init__(cn, parent, **kw)
        self.display_name = kw.get("display_name", cn)
        self.given_name = kw.get("given_name", "")
        self.surname = kw.get("surname", "")
        self.mail = kw.get("mail", "")
        self.telephone = kw.get("telephone", "")
        self.title_text = kw.get("title_text", "")
        self.department = kw.get("department", "")


class _MockOu:
    """演示域里的组织单位（包一层，好让它和别的对象有同样的 `.dn` 接口）。

    ``container=True`` 表示 CN 容器（Users / Computers / Builtin）——
    DN 前缀是 ``CN=`` 而不是 ``OU=``，两者在 AD 里是不同的 objectClass。
    """

    kind = ObjectKind.OU
    __slots__ = ("cn", "parent", "description", "container")

    def __init__(self, name: str, parent: str, description: str = "",
                 container: bool = False):
        self.cn = name
        self.parent = parent
        self.description = description
        self.container = container

    @property
    def dn(self) -> str:
        prefix = "CN" if self.container else "OU"
        return f"{prefix}={escape_dn_value(self.cn)},{self.parent}"

    @property
    def title(self) -> str:
        return self.cn


class _MockRoot:
    """域根目录本身（``DC=demo,DC=local``）。

    它既不是 OU 也不是普通对象，但它**必须能被选中并被保护** ——
    否则演示模式下对着域根点删除，会得到一个"对象不存在"，
    而不是"不允许删除整个域"。这两句提示教给人的东西完全不一样。
    """

    kind = ObjectKind.OTHER
    __slots__ = ("dn",)

    def __init__(self, dn: str):
        self.dn = dn

    @property
    def cn(self) -> str:
        return self.dn

    @property
    def parent(self) -> str:
        return ""

    @property
    def sam(self) -> str:
        return ""

    @property
    def title(self) -> str:
        return self.dn


def _set_override(obj: Any, attr: str, values: list[str]) -> None:
    """把属性写进演示对象的 overrides，先清掉大小写不同的同名旧键。

    不清的话 `mail` 与 `Mail` 会同时存在，读回来变成两个值 ——
    演示数据看着就像 AD 出了故障。
    """
    overrides = getattr(obj, "overrides", None)
    if overrides is None:
        return
    low = attr.casefold()
    for key in [k for k in overrides if k.casefold() == low]:
        del overrides[key]
    overrides[attr] = list(values)


def _override_first(obj: Any, name: str) -> str:
    """取 overrides 里某属性的第一个值（属性编辑器写过的话）。"""
    low = name.casefold()
    for key, values in (getattr(obj, "overrides", {}) or {}).items():
        if key.casefold() == low and values:
            return values[0]
    return ""


def _in_scope(dn: str, base: str, subtree: bool) -> bool:
    """对象是否落在容器内。

    子树模式用 DN **段比较**（`utils.is_descendant_dn`）而不是 `endswith` ——
    `endswith("DC=x")` 对 `DC=xx` 也是 True，会把隔壁域的对象带进来。
    """
    base = (base or "").strip()
    if subtree:
        return dn.casefold() == base.casefold() or is_descendant_dn(dn, base)
    return parent_of_dn(dn).casefold() == base.casefold()


# ============================================================================
# 迷你 LDAP 过滤器求值器（仅演示模式高级查找用）
#
# 支持：&(..)(..) / |(..)(..) / !(..) / 属性=值 / 属性=*片段* 通配 /
#       存在性判断（属性=*）。不支持的语法（>=、<=、~=、扩展匹配）
#       明确报错而不是静默给错结果。
# ============================================================================

_ESCAPED_HEX = re.compile(r"\\([0-9a-fA-F]{2})")


def _unescape_filter_value(value: str) -> str:
    """过滤器值里的 ``\\2a`` 这类十六进制转义 → 原字符。"""
    return _ESCAPED_HEX.sub(lambda m: chr(int(m.group(1), 16)), value)


def _find_unescaped(text: str, ch: str, start: int) -> int:
    """找未被反斜杠转义的字符位置。找不到返回 -1。"""
    i = start
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == ch:
            return i
        i += 1
    return -1


def _parse_filter_expr(text: str) -> tuple[tuple, int]:
    """解析一个 ``( … )`` 表达式，返回 ``((节点), 消耗字符数)``。

    节点形态：``("&", [子节点…])`` / ``("|", …)`` / ``("!", [子节点])`` /
    ``("=", (attr, matcher))`` —— matcher 是通配模式片段列表（"" 表示存在性）。
    """
    if not text.startswith("("):
        raise AdToolError("过滤器语法错误：表达式必须以 ( 开头。", code="87")
    if len(text) < 2:
        raise AdToolError("过滤器语法错误：括号内没有内容。", code="87")

    if text[1] in "&|!":
        op = text[1]
        i = 2
        children: list[tuple] = []
        if op == "!":
            if not text.startswith("(", i):
                raise AdToolError("过滤器语法错误：! 后面必须紧跟一个括号表达式。",
                                  code="87")
            child, used = _parse_filter_expr(text[i:])
            children.append(child)
            i += used
        else:
            if op == "&" and not text.startswith("(", i):
                raise AdToolError("过滤器语法错误：& 后面必须至少跟一个括号表达式。",
                                  code="87")
            if op == "|" and not text.startswith("(", i):
                raise AdToolError("过滤器语法错误：| 后面必须至少跟一个括号表达式。",
                                  code="87")
            while text.startswith("(", i):
                child, used = _parse_filter_expr(text[i:])
                children.append(child)
                i += used
        if i >= len(text) or text[i] != ")":
            raise AdToolError("过滤器语法错误：括号不配平。", code="87")
        return (op, children), i + 1

    end = _find_unescaped(text, ")", 1)
    if end < 0:
        raise AdToolError("过滤器语法错误：括号不配平。", code="87")
    cond = text[1:end]

    # 先找关系符（未转义的）：= 优先，>=、<=、~= 明确拒绝
    eq = _find_unescaped(cond, "=", 0)
    if eq <= 0:
        raise AdToolError(
            f"过滤器语法错误：「{cond}」缺少 = 关系符（或不支持的写法）。", code="87")
    if eq > 0 and cond[eq - 1] in "><~":
        raise AdToolError(
            f"演示模式暂不支持 {cond[eq - 1]}= 比较（真域上可用）—— "
            "请改用通配符匹配。", code="87")
    if eq > 1 and cond[eq - 1] == ":":
        raise AdToolError("演示模式暂不支持扩展匹配（:dn: / :oid:）。", code="87")

    attr = cond[:eq].strip()
    if not attr or not attr.replace("-", "").isalnum():
        raise AdToolError(f"过滤器语法错误：属性名「{attr}」不合法。", code="87")
    value = _unescape_filter_value(cond[eq + 1:])
    if "*" in value:
        matcher = [p.casefold() for p in value.split("*")]
    elif value == "":
        matcher = None                       # 纯等空 = 没有这个语法，按存在性处理
    else:
        matcher = value.casefold()
    return ("=", (attr, value, matcher)), end + 1


def _eval_filter_node(attrs: dict[str, list[str]], node: tuple) -> bool:
    """对 mock 属性表求值过滤器节点。属性名比对大小写不敏感。"""
    op, payload = node
    if op == "&":
        return all(_eval_filter_node(attrs, child) for child in payload)
    if op == "|":
        return any(_eval_filter_node(attrs, child) for child in payload)
    if op == "!":
        return not _eval_filter_node(attrs, payload[0])

    attr, value, matcher = payload
    low = attr.casefold()
    values: list[str] = []
    for key, vs in attrs.items():
        if key.casefold() == low:
            values = [str(v) for v in (vs or [])]
            break

    if matcher is None:
        # (attr=) 语义上是"等于空串"，AD 里等于要求属性存在且为空 —— 演示
        # 环境没有这种数据，统一按"属性存在"处理并给出可预期结果。
        return bool(values)
    if "*" in value:
        # 通配匹配：首尾片段锚定，中间片段按序出现
        parts = matcher
        if len(parts) == 1:
            return True                      # 单个 * = 存在性
        haystack = "￰".join(values).casefold() if values else ""
        if not haystack:
            return False
        if parts[0] and not haystack.startswith(parts[0]):
            return False
        if parts[-1] and not haystack.endswith(parts[-1]):
            return False
        cursor = len(parts[0])
        for middle in parts[1:-1]:
            if not middle:
                continue
            found = haystack.find(middle, cursor)
            if found < 0:
                return False
            cursor = found + len(middle)
        return True
    return any(v.casefold() == value.casefold() for v in values)


def _to_generalized(text: str) -> str:
    """演示数据里的可读时间 → AD 的 generalizedTime（``20240312093107.0Z``）。

    演示数据写成 ``2024-03-12 09:31:07`` 是为了好读好改；但
    `utils.ad_generalized_time_to_dt` 只认 generalizedTime。
    在**边界上转一次**，别让演示数据自成一派时间格式 ——
    否则界面上的「创建时间」列在演示模式下永远空着，
    真域上列错格式时也看不出问题。
    """
    text = (text or "").strip()
    if not text:
        return ""
    if text == "刚刚":
        return _datetime.now(_timezone.utc).strftime("%Y%m%d%H%M%S") + ".0Z"
    try:
        stamp = _datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return text
    return stamp.strftime("%Y%m%d%H%M%S") + ".0Z"


def _demo_groups() -> list[_MockGroup]:
    ou_yunwei = f"OU=运维部,OU=研发中心,OU=总部,{MOCK_BASE_DN}"
    ou_dev = f"OU=开发部,OU=研发中心,OU=总部,{MOCK_BASE_DN}"
    ou_center = f"OU=研发中心,OU=总部,{MOCK_BASE_DN}"
    ou_caiwu = f"OU=财务部,OU=总部,{MOCK_BASE_DN}"
    ou_hq = f"OU=总部,{MOCK_BASE_DN}"
    cn_users = f"CN=Users,{MOCK_BASE_DN}"
    return [
        # 内置容器里的「Domain Users」：每个用户的主要组（不可直接移除），
        # 演示「主要组成员不能从 member 里移除」这条真实约束。
        # 刻意不给 member —— 主要组关系存 primaryGroupID，不在 member 属性里。
        _MockGroup("Domain Users", cn_users, sam="Domain Users",
                   scope="domainlocal", category="security",
                   description="所有域用户的主要组（内置）"),
        _MockGroup("IT-Admins", ou_yunwei, sam="IT-Admins", scope="global",
                   category="security", description="域管理员（演示）",
                   members=[f"CN=张三,{ou_yunwei}", f"CN=李四,{ou_yunwei}"]),
        _MockGroup("运维-远程桌面", ou_yunwei, sam="运维-远程桌面",
                   scope="domainlocal", category="security",
                   description="可远程登录服务器",
                   members=[f"CN=李四,{ou_yunwei}",
                            f"CN=PC-ZHANGSAN,{ou_yunwei}"]),
        _MockGroup("研发中心-全员", ou_center, scope="global",
                   description="研发中心通讯与权限组",
                   members=[f"CN=张三,{ou_yunwei}", f"CN=李四,{ou_yunwei}",
                            f"CN=王五,{ou_dev}", f"CN=赵六,{ou_dev}",
                            f"CN=马珊,{ou_center}"]),
        _MockGroup("全公司通知", ou_hq, scope="universal",
                   category="distribution", description="邮件通讯组（非安全组）",
                   members=[f"CN=孙七,{ou_caiwu}", f"CN=王五,{ou_dev}"]),
        _MockGroup("财务-只读", ou_hq, scope="domainlocal",
                   description="仅可查看财务报表",
                   members=[f"CN=孙七,{ou_caiwu}", f"CN=周八,{ou_caiwu}"]),
    ]


def _demo_computers() -> list[_MockComputer]:
    ou_yunwei = f"OU=运维部,OU=研发中心,OU=总部,{MOCK_BASE_DN}"
    ou_dev = f"OU=开发部,OU=研发中心,OU=总部,{MOCK_BASE_DN}"
    ou_hq = f"OU=总部,{MOCK_BASE_DN}"
    cn_computers = f"CN=Computers,{MOCK_BASE_DN}"
    return [
        # 加域时没往 OU 里放、落在默认容器里的典型样本
        _MockComputer("PC-LEGACY-01", cn_computers, sam="PC-LEGACY-01$",
                      dns_host_name=f"PC-LEGACY-01.{MOCK_DOMAIN}",
                      os="Windows 7 旗舰版", os_version="6.1 (7601)",
                      description="未归位到 OU 的旧机器"),
        _MockComputer("PC-ZHANGSAN", ou_yunwei, sam="PC-ZHANGSAN$",
                      dns_host_name=f"PC-ZHANGSAN.{MOCK_DOMAIN}",
                      location="总部大楼 3 楼", description="张三的办公机"),
        _MockComputer("PC-DEV-01", ou_dev, sam="PC-DEV-01$",
                      dns_host_name=f"PC-DEV-01.{MOCK_DOMAIN}",
                      os="Windows 11 专业版", os_version="10.0 (22631)",
                      location="总部大楼 3 楼"),
        _MockComputer("SRV-FILE01", ou_hq, sam="SRV-FILE01$",
                      dns_host_name=f"SRV-FILE01.{MOCK_DOMAIN}",
                      os="Windows Server 2016", os_version="10.0 (14393)",
                      location="总部机房", description="文件服务器"),
        # ---- 域控样本：专门用来验证「域控不能删 / 不能禁用」的拦截 ----
        _MockComputer("DC01", f"OU=Domain Controllers,{MOCK_BASE_DN}",
                      sam="DC01$", dns_host_name=f"dc01.{MOCK_DOMAIN}",
                      # 532480 = 0x82000：SERVER_TRUST_ACCOUNT | TRUSTED_FOR_DELEGATION
                      # —— 真实域控的典型 UAC 值（注意**不含** ACCOUNTDISABLE）
                      uac=0x82000,
                      os="Windows Server 2016", os_version="10.0 (14393)",
                      location="总部机房", description="主域控（演示）"),
    ]


def _demo_contacts() -> list[_MockContact]:
    ou_hq = f"OU=总部,{MOCK_BASE_DN}"
    ou_yunwei = f"OU=运维部,OU=研发中心,OU=总部,{MOCK_BASE_DN}"
    return [
        _MockContact("供应商-示例快递", ou_hq, display_name="示例快递企业客服",
                     mail="service@express.example", telephone="400-000-0001",
                     title_text="快递服务", description="月度对账联系人"),
        _MockContact("厂商-示例电脑售后", ou_yunwei, display_name="示例电脑企业支持",
                     given_name="企业", surname="支持",
                     mail="support@computer.example", telephone="400-000-0002",
                     department="售后", description="服务器维保联系人"),
    ]


# ============================================================================
# 组策略（演示域）—— 影子 SYSVOL
# ============================================================================
#
# 🔴 **2026-09-18 改了一条相反的决定，两边的理由都记在这里。**
#
# 原来演示域**刻意不造 GPO 数据**（`search_attributes` 那段注释写着理由）：
# 「编两条假 GPO 出来会让『列表能读』看起来是通的，而真域上那条路
# （SYSVOL/GPMC 的字段对不对）**一点都没被验到**」。
#
# 2026-09-18 的指令要的是**能编辑**。而"能不能编辑"这件事，
# 拆开看只有一层是本机验不了的：
#
#   ======================================  ===================  ==================
#   要验的东西                                本机能验吗           靠什么验
#   ======================================  ===================  ==================
#   PReg 字节格式的读 / 写 / 往返               **能**              `preg_backend`
#   「哪些设置被改过」的 ADMX 对照               **能**              `admx_backend`
#   版本号双处同步的算法与时机                   **能**              `gpo_write`
#   快照 / 回滚 / 写开关 / 审计                  **能**              本地影子目录
#   **SMB / UNC 的权限与重定向**（445 端口）   **不能**            ⇒ 归真域验收
#   ======================================  ===================  ==================
#
# ⇒ 那就把能验的全验掉：影子 SYSVOL 里放**真 PReg 字节**（用生产同一份编码器
#   `preg_backend.build_preg` 写出来），路径也**逐层照抄**真域那棵树
#   （`<root>\<域名>\Policies\{GUID}\Machine\Registry.pol`）。
#   于是「拼路径 → 解 PReg → 写回 → 升版本」整条链在演示模式下走的是
#   **同一份实现**，唯一的差别只剩传输介质（本地文件 vs SMB）。
#
# ⚠️ 但**旧的担忧仍然成立**，不许被"演示模式全绿"盖掉：
#   **「演示模式能改」 ≠ 「真域能改」** —— 真域多出来的是 SMB 权限与重定向。
#   那句话必须一直挂在界面上（见 `GpoPanel` 的副标题）。

#: 影子 SYSVOL 的目录名（挂在 `config.app_dir()` 下）。
DEMO_SYSVOL_DIRNAME = "demo_sysvol"

#: 影子 SYSVOL 的**内容版本**。
#:
#: 🔴 **2026-09-18 更正：这个常量现在没有任何地方读它** —— 全库 `grep` 只有本行
#: 与 `_sync_demo_sysvol` 的一句注释两处。原来那句「下次连接会把这些已知文件按
#: 新内容重写一遍」是**写侧还在时**的描述：`gpo_write.py` 随「组策略只读」这条
#: 裁定移出仓库之后，演示域**没有**再实现「按版本重铺」这一步
#: （`_sync_demo_sysvol` 只在文件**不存在**时写，为的是保住使用者在演示模式里
#: 已经改出来的东西）。
#: ⇒ 保留它是为了**别让"种子改过"这件事弄丢**（写侧一旦回来，第一个要接的就是
#: 它），但它**现在不产生任何行为**。改种子时照样 +1，别让这个约定也烂掉。
#:
#: 影子 SYSVOL 里我们管的文件现在是**五类**：每作用域一份 `Registry.pol`
#: （Machine / User）＋ 一份 `GPT.INI` ＋ 一份安全策略
#: `MACHINE\microsoft\windows nt\SecEdit\GptTmpl.inf`。
DEMO_GPO_CONTENT_VERSION = 2

#: `Default Domain Policy` 的 GUID。**这是公开常量**（每个 AD 域里都是这一个），
#: 不是从哪台真实域抄来的东西 —— 用它是为了让演示域"长得像真的域"。
DEMO_DEFAULT_POLICY_GUID = "{31B2F340-016D-11D2-945F-00C04FB984F9}"

#: 安全 CSE（Security Client Side Extension）的 GUID。
#:
#: 🔴 **在演示域里它必须是自己的一份字面量，不许 `import` 生产那份。**
#: 理由是本项目 2026-09-18 刚吃过的那个形状 —— `gpo_ldap._version_split()` 与
#: 演示域的 `_MockGpo.version_number` **同时反向、互相抵消** ⇒ 演示域里
#: 「编码 → 解码」自洽、界面看着完全正确，而**真域是反的**，且两边判据都绿。
#: 一般化：**替身从被测物那里取常量，就永远验不出那个常量是错的。**
#: ⇒ 这一份的出处**独立于** `gpo_security_backend.SECURITY_CSE_GUID`
#: （那份引 KB885009）。本机实测（`winreg`，`reg.exe` 被本机安全策略拦了）：
#:
#:     HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\
#:         {827D319E-6EAC-11D2-A4EA-00C04F79F83A}\DllName  =  scecli.dll
#:
#: 「两个出处相等」这件事由 `tests/test_gpo_demo_security.py` 钉住 ——
#: 谁改错一个，那一条就红。
DEMO_SECURITY_CSE = "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}"

#: 注册表 CSE 的 GUID（本机 `GPExtensions` 里实测有这一键，**没有** `DllName`
#: —— 它是注册表扩展的容器键，不是可加载的客户端扩展）。
#: 演示域用它来拼一份**合法但缺安全扩展**的 `gPCMachineExtensionNames`，
#: 于是「这条 GPO 的安全策略**不会被应用**」在演示模式里也看得见。
DEMO_REGISTRY_CSE = "{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"


def demo_sysvol_root() -> str:
    """演示域的 SYSVOL 根目录（**本地目录**，不是共享）。

    真域那棵树在 ``\\\\<域名>\\SYSVOL`` 下；这里把"共享"换成一个普通目录，
    **共享名以下的部分逐层一致**。所以
    `gpo_settings.sysvol_gpo_dir(域名, GUID, root=<本函数>)` 拼出来的路径
    在演示模式下真的能读到文件、也真的能写回去。
    """
    return os.path.join(app_dir(), DEMO_SYSVOL_DIRNAME)


class _MockGpo(_MockDirObject):
    """演示域里的一个组策略对象（`groupPolicyContainer`）。

    ``cn`` 就是 GUID（**带花括号**）—— 真 AD 里也是这么存的，
    所以 `dn` 长成 ``CN={31B2F340-…},CN=Policies,CN=System,DC=demo,DC=local``。
    """

    kind = ObjectKind.OTHER
    __slots__ = ("guid", "display_name", "computer_version", "user_version",
                 "settings", "extension_names", "security_body")

    def __init__(self, guid: str, display_name: str, parent: str,
                 computer_version: int = 0, user_version: int = 0,
                 settings: Any = (), extension_names: str = "",
                 security: str = "", **kw):
        # ⚠️ `description` **不**拿 display_name 顶替：真 AD 里这是两个属性，
        #    绝大多数 GPO 的 `description` 是空的。用名字顶上去，会让
        #    「属性」页与 GPMC 并排看时对不上。
        super().__init__(cn=guid, parent=parent, sam=guid,
                         description=kw.pop("description", ""), **kw)
        self.guid = guid
        self.display_name = display_name
        self.computer_version = int(computer_version)
        self.user_version = int(user_version)
        #: ``(作用域, 键, 值名, 类型码, 数据)`` 的清单 —— 影子 SYSVOL 的种子。
        self.settings = tuple(settings)
        #: AD 属性 `gPCMachineExtensionNames` 的值。`""` = 该属性**没有值**
        #: （真 AD 里就不会把这个属性回给查询方，与"回了空串"在**取值上**等价、
        #: 在**语义上**是同一件事：对象上没登记机器侧扩展）。
        self.extension_names = extension_names
        #: `GptTmpl.inf` 的正文。`""` = 这条 GPO **没有**安全策略。
        self.security_body = security

    @property
    def version_number(self) -> int:
        """AD 属性 `versionNumber` 的值：**高 16 位用户、低 16 位计算机**。

        （与 `gpo_ldap._version_split()` 是同一个口径的两个方向。
        真值来源见那个函数的更正段 —— 它此前也写反了，
        于是**两处同时反向、互相抵消**，演示域看着完全正确而真域是反的。）
        """
        return ((self.user_version & 0xFFFF) << 16) | (self.computer_version & 0xFFFF)


def _sz(text: str) -> bytes:
    """`REG_SZ` 的数据形态：UTF-16LE ＋ 结尾一个 ``\\0\\0``（实测 6/6 真实样本）。"""
    return text.encode("utf-16-le") + b"\x00\x00"


def _dword(number: int) -> bytes:
    """`REG_DWORD` 的数据形态：4 字节小端。"""
    return (int(number) & 0xFFFFFFFF).to_bytes(4, "little")


#: 键的写法用真域里的原样（反斜杠），**不要**改成 `/`：
#: 它们是注册表键，而 ADMX 里的 `<key>` 也是这个写法（对照才逐字对得上）。
_K_EXPLORER = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"
_K_SYSTEM = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
_K_PERSONALIZATION = "Software\\Policies\\Microsoft\\Windows\\Personalization"
_K_WU = "Software\\Policies\\Microsoft\\Windows\\WindowsUpdate"
_K_WU_AU = "Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"


def _demo_gpo_seed() -> dict[str, tuple[tuple[str, str, str, int, bytes], ...]]:
    """演示 GPO 的种子设置：``GUID → ((作用域, 键, 值名, 类型码, 数据), ...)``。

    🔑 **每一条 `(键, 值名)` 都在本机 ADMX 里核对过**（`AdmxCatalog.
    elements_by_registry()`），所以演示模式里能看到真实的本地化策略名与
    分类路径 —— 不是编一个"看起来像策略"的假键名。

    ⚠️ 这里的**值**全部是虚构的（`wsus.demo.local` 是演示域名）。
    """
    return {
        DEMO_DEFAULT_POLICY_GUID: (
            ("Machine", _K_PERSONALIZATION, "NoLockScreen", REG_DWORD, _dword(1)),
            ("User", _K_EXPLORER, "NoRun", REG_DWORD, _dword(1)),
        ),
        "{8E2A6B44-1C3D-4E77-9A5B-1F0C7D23A901}": (
            ("Machine", _K_WU, "WUServer", REG_SZ,
             _sz("http://wsus.demo.local:8530")),
            ("Machine", _K_WU, "WUStatusServer", REG_SZ,
             _sz("http://wsus.demo.local:8530")),
            ("Machine", _K_WU_AU, "AUOptions", REG_DWORD, _dword(4)),
        ),
        "{A17C6E02-5B84-4F31-8D6E-0C39B7A24417}": (
            ("User", _K_EXPLORER, "NoControlPanel", REG_DWORD, _dword(1)),
            ("User", _K_SYSTEM, "DisableTaskMgr", REG_DWORD, _dword(1)),
        ),
        # 一条**什么都没配**的策略：演示「确实没配过」与「我们没读到」
        # 在界面上必须长得不一样（两个文件都是 0 字节）。
        "{C4F0D51B-7A26-4E90-B3D8-6E5A1F0C88E3}": (),
    }


def _demo_gpos() -> list[_MockGpo]:
    """演示域里的四个组策略对象。"""
    parent = "CN=Policies,CN=System,%s" % MOCK_BASE_DN
    seed = _demo_gpo_seed()
    secure = _demo_security_seed()
    specs = [
        (DEMO_DEFAULT_POLICY_GUID, "Default Domain Policy",
         3, 3, "2024-03-12 09:12:40", "2026-08-21 15:44:02"),
        ("{8E2A6B44-1C3D-4E77-9A5B-1F0C7D23A901}", "演示 - 内网更新源",
         5, 2, "2025-06-04 11:20:15", "2026-08-30 09:05:51"),
        ("{A17C6E02-5B84-4F31-8D6E-0C39B7A24417}", "演示 - 桌面与任务管理器限制",
         1, 7, "2025-11-19 14:02:33", "2026-07-16 16:38:20"),
        ("{C4F0D51B-7A26-4E90-B3D8-6E5A1F0C88E3}", "演示 - 空白策略（什么都没配）",
         0, 0, "2026-01-08 10:00:00", "2026-01-08 10:00:00"),
    ]
    return [_MockGpo(guid, name, parent, computer_version=cv, user_version=uv,
                     settings=seed.get(guid, ()),
                     extension_names=secure.get(guid, ("", ""))[0],
                     security=secure.get(guid, ("", ""))[1],
                     when_created=created, when_changed=changed)
            for guid, name, cv, uv, created, changed in specs]


# ============================================================================
# 演示域的安全策略（`GptTmpl.inf`）—— 段名 / 键名取自本机两份真实样本
# ============================================================================

#: 演示域的**安全策略**种子：``GUID → (gPCMachineExtensionNames, GptTmpl.inf 正文)``。
#:
#: * 正文 `""` ⇒ 这条 GPO **没有** `GptTmpl.inf`（真域里最常见、完全正常）；
#: * 扩展名 `""` ⇒ 对象上**没登记**机器侧扩展（真 AD 里就是该属性没有值）。
#:
#: 🔑 **段名与键名一个都不是编的**，逐条核过本机两份真实样本：
#:
#: | 来源 | 实测 |
#: |---|---|
#: | `secedit /export`（**实跑**，操作系统自己生成） | rc=0、17358 字节、BOM `fffe`、**恰好 6 段** |
#: | `C:\Windows\inf\defltbase.inf`（Windows 自带） | 29572 字节、13 段 |
#:
#: 分工是**实测出来的、不是猜的**：`[System Access]` / `[Privilege Rights]` 两段
#: 两份样本都有；`[Event Audit]` 那 9 个键**只在** `secedit` 样本里
#: （`defltbase` 是裸默认模板，不含审核设置）；`[Group Membership]` 那两行
#: **只在** `defltbase` 里，且**逐字**抄自它。
#:
#: ⚠️ 值全部是虚构的（演示域口径）—— 而**段名 / 键名是真的**，
#: 因为界面要显示的就是它们，编一个"看起来像策略"的键名等于教使用者认错东西。
_DEMO_INF_DEFAULT = r"""[Unicode]
Unicode=yes
[System Access]
;----------------------------------------------------------------
;Account Policies - Password Policy
;----------------------------------------------------------------
MinimumPasswordAge = 1
MaximumPasswordAge = 90
MinimumPasswordLength = 8
PasswordComplexity = 1
PasswordHistorySize = 24
LockoutBadCount = 5
ResetLockoutCount = 30
LockoutDuration = 30
[Event Audit]
AuditSystemEvents = 3
AuditLogonEvents = 3
AuditObjectAccess = 0
AuditPrivilegeUse = 0
AuditPolicyChange = 3
AuditAccountManage = 3
AuditProcessTracking = 0
AuditDSAccess = 0
AuditAccountLogon = 3
[Group Membership]
*S-1-5-32-545__Memberof =
*S-1-5-32-545__Members = *S-1-5-11,*S-1-5-4
[Registry Values]
; REG_SZ (1)  REG_DWORD (4)  REG_MULTI_SZ (7)
MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=4,1
[Privilege Rights]
SeNetworkLogonRight = *S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-555
SeInteractiveLogonRight = *S-1-5-32-544
SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555
SeDenyNetworkLogonRight = Guest
SeShutdownPrivilege = *S-1-5-32-544
[Version]
signature="$CHICAGO$"
Revision=1
"""

#: 第二条带安全策略的 GPO（「桌面与任务管理器限制」）—— 它是本演示**最值钱**的一条：
#: `GptTmpl.inf` **在**、内容合法、版本号也涨了，但它的
#: `gPCMachineExtensionNames` 里**只有注册表 CSE、没有安全 CSE** ⇒
#: 这份模板会被**完全忽略**（KB885009），而 GPMC 界面上**没有任何线索**。
#: 这正是本工具"看得见"能给出、别处拿不到的那一句。
#: （`[System Access]` 这一段与上一条**故意不同**：两条策略的密码要求不一样，
#: 一眼能看出"看的是哪一条"。）
_DEMO_INF_LOCKDOWN = r"""[Unicode]
Unicode=yes
[System Access]
MinimumPasswordLength = 12
PasswordComplexity = 1
LockoutBadCount = 3
ResetLockoutCount = 15
LockoutDuration = 15
[Event Audit]
AuditLogonEvents = 3
AuditAccountLogon = 3
[Privilege Rights]
SeDenyNetworkLogonRight = Guest,*S-1-5-32-546
[Version]
signature="$CHICAGO$"
Revision=1
"""


def _demo_security_seed() -> dict[str, tuple[str, str]]:
    """``GUID → (扩展名属性, GptTmpl.inf 正文)``（正文 / 扩展名取 `""` 的含义见上）。"""
    return {
        # 机器侧登记了**注册表 CSE ＋ 安全 CSE** ⇒ 这份模板**会被应用**。
        DEMO_DEFAULT_POLICY_GUID: (
            "[%s%s]" % (DEMO_REGISTRY_CSE, DEMO_SECURITY_CSE),
            _DEMO_INF_DEFAULT),
        # 「内网更新源」只有管理模板设置，**没有**安全策略 —— 最常见的正常形态。
        "{8E2A6B44-1C3D-4E77-9A5B-1F0C7D23A901}": ("[%s]" % DEMO_REGISTRY_CSE, ""),
        # 🔑 有模板、但扩展名里**缺安全 CSE** ⇒ **不会被应用**（KB885009）。
        "{A17C6E02-5B84-4F31-8D6E-0C39B7A24417}": (
            "[%s]" % DEMO_REGISTRY_CSE, _DEMO_INF_LOCKDOWN),
        # 空白策略：什么都没登记、也没有模板（真 AD 里该属性就是**没有值**）。
        "{C4F0D51B-7A26-4E90-B3D8-6E5A1F0C88E3}": ("", ""),
    }


def _demo_inf_bytes(body: str) -> bytes:
    """`GptTmpl.inf` 正文 → **真实字节**：UTF-16LE ＋ BOM ＋ CRLF。

    🔴 三件都不能省，而且**少一件都不是"格式不同"、是"读不出来"**：

    * **BOM**：`gpo_security_backend.parse_template()` **见到无 BOM 就抛** ——
      实测同一份内容去掉 BOM 之后，编码探测会落到 `cp1252`，段数解析成 **0**，
      而且**不抛任何异常**（界面会把"读不懂"显示成"什么都没配"）。
    * **UTF-16LE**：`[MS-GPSB]` 规定的形态，本机两份真实样本都是它。
    * **CRLF**：`parse_template` 按 `"\\r\\n"` 分行 —— 写成 LF 会把**整份文件**
      读成一行。

    ⚠️ 这里**不复用** `tests/test_gpo_security_backend.build_inf()`：那是夹具，
    替身依赖测试件会形成环（而且 `tests` 不该被生产模块 import）。
    两边是否一致由 `tests/test_gpo_demo_security.py` 拿**生产解析器**读回来钉。
    """
    return ("\ufeff" + body.replace("\n", "\r\n")).encode("utf-16-le")


# ============================================================================
# Mock 客户端
# ============================================================================

class MockAdClient:
    """与 `AdClient` 接口一致的演示实现。"""

    IS_MOCK = True

    def __init__(self, audit: AuditLog | None = None,
                 latency: float = 0.25, seed: int = 20260811):
        self.audit = audit
        self.latency = latency           # 人为延迟，让 UI 的忙碌态能真的被看到
        self._rand = random.Random(seed)

        self.cfg: ConnConfig | None = None
        self.info: DomainInfo | None = None

        self._ous: list[dict[str, Any]] = _default_tree()
        self._groups: list[_MockGroup] = _demo_groups()
        self._computers: list[_MockComputer] = _demo_computers()
        self._contacts: list[_MockContact] = _demo_contacts()
        self._gpos: list[_MockGpo] = _demo_gpos()
        self._users: list[_MockUser] = []
        self._build_people()

        #: 演示域的 **SYSVOL 影子根目录**（本地）。真域那棵树在
        #: ``\\<域名>\SYSVOL`` 上，这里就是一个普通目录 —— 见本文件
        #: 「组策略（演示域）」那一节的长说明。
        #:
        #: ⚠️ 与 `AdClient` 的同名属性**必须同合同**：真身给空串
        #: （表示"按 UNC 约定算"），演示域给本地目录。两边都由
        #: `tests/test_client_contract.py` 钉着，漏一边就是 AttributeError。
        self.sysvol_root: str = demo_sysvol_root()

        # ---- 故障注入（UI 用它演示错误分支）----
        self.fail_next: AdToolError | None = None
        self.failure_rate: float = 0.0
        self._failure_code: str = "0x80072030"
        self._failure_message: str = "模拟故障：该账号已被移动或删除。"

    # ---------------- 演示数据 ----------------

    def _build_people(self) -> None:
        self._users = []
        for index, (sam, name, ou_name, pwd_age, extra) in enumerate(_DEMO_PEOPLE):
            parent = self._ou_dn(ou_name)
            uac = UF_NORMAL_ACCOUNT
            if sam == "mashan":
                uac |= UF_DONT_EXPIRE_PASSWORD       # 「密码永不过期」样本
            if sam == "qianjiu":
                uac |= UF_ACCOUNTDISABLE             # 「已禁用」样本
            self._users.append(_MockUser(
                sam, name, parent, uac=uac,
                locked=(sam == "zhouba"),           # 「已锁定」样本
                # pwd_age=None → pwdLastSet=0 → 「待改密码」样本
                pwd_last_set=0 if pwd_age is None else _filetime_days_ago(pwd_age),
                last_logon=_filetime_days_ago(1 + index * 3),
                extra=extra,
            ))
        # 一个超长的名字，用来验证表格列宽/省略号处理
        self._users.append(_MockUser(
            "zhangshanshan", "张三丰（这是一个用来测试超长显示的名字）",
            self._ou_dn("开发部"), pwd_last_set=_filetime_days_ago(20),
            extra={"title": "架构师"}))

    def _ou_dn(self, name: str) -> str:
        for node in self._ous:
            if node["name"] == name:
                return f"OU={escape_dn_value(name)},{node['parent']}"
        return MOCK_BASE_DN

    def _find_user(self, dn: str = "", sam: str = "") -> _MockUser:
        for user in self._users:
            if (dn and user.dn == dn) or (sam and user.sam == sam):
                return user
        raise AdToolError("对象不存在或已被删除，请刷新后重试。", code="32")

    # ---------------- 假延迟与假故障 ----------------

    def _tick(self, work: float = 1.0) -> None:
        if self.latency:
            time.sleep(self.latency * work)
        if self.fail_next is not None:
            error, self.fail_next = self.fail_next, None
            raise error
        if self.failure_rate and self._rand.random() < self.failure_rate:
            raise AdToolError(self._failure_message, code=self._failure_code)

    def _audit(self, op: str, sam: str, dn: str, result: str = "success",
               detail: str = "", before=None, after=None,
               secrets: tuple = ()) -> None:
        """演示模式的审计与真实模式走**同一条** write() —— 脱敏规则也完全相同。

        ``secrets`` 照样要传：演示模式的文案今天不含口令，不代表以后不含，
        而「demo 不需要脱敏」是最容易把红线抄漏的一句想当然。
        """
        if self.audit is None:
            return
        self.audit.write(op=op, target_sam=sam, target_dn=dn, result=result,
                         detail=detail, before=before, after=after,
                         secrets=secrets)

    # ---------------- 连接 ----------------

    @staticmethod
    def probe(dc_ip: str, port: int | None = None,
              use_ssl: bool | None = None,
              timeout: int = 5) -> DomainInfo:
        # ⚠️ `use_ssl` 必须在这里存在，哪怕演示域不需要它：真实客户端
        #    (`ad_client.AdClient.probe`) 有它，而 `tests/test_client_contract.py`
        #    要求两者**签名形状全等** —— 2026-09-17 给真实路径补上 `use_ssl`
        #    时，这条判据当场把演示模式的漏跟报了出来（它是对的：调用方按
        #    真实合同传参时，演示模式会 `TypeError`）。
        time.sleep(0.1)
        return DomainInfo(dc_ip=dc_ip or MOCK_DC_IP, dns_domain=MOCK_DOMAIN,
                          base_dn=MOCK_BASE_DN,
                          dns_host_name=f"dc01.{MOCK_DOMAIN}",
                          config_dn=f"CN=Configuration,{MOCK_BASE_DN}",
                          schema_dn=f"CN=Schema,CN=Configuration,{MOCK_BASE_DN}",
                          root_domain_dn=MOCK_BASE_DN,
                          supported_sasl=["GSSAPI", "GSS-SPNEGO", "NTLM"],
                          functional_level="Windows Server 2016")

    def test_connection(self, cfg: ConnConfig) -> tuple[bool, str]:
        time.sleep(0.3)
        if cfg.bind_user.strip().lower().endswith("bad"):
            return False, "绑定失败：用户名或密码错误。"
        return True, (f"连接成功（演示模式）。域：{MOCK_DOMAIN}　"
                      f"BaseDN：{MOCK_BASE_DN}")

    def connect(self, cfg: ConnConfig) -> DomainInfo:
        self._tick(1.5)
        if not cfg.bind_user:
            raise AdToolError("请填写绑定账号。")
        if not cfg.password:
            raise AdToolError("请填写绑定账号密码。")
        self.cfg = cfg
        self.info = self.probe(cfg.dc_ip or MOCK_DC_IP)
        self.cfg.domain = self.cfg.domain or MOCK_DOMAIN
        self.cfg.base_dn = self.cfg.base_dn or MOCK_BASE_DN
        if self.audit is not None:
            self.audit.bind_context(dc_ip=cfg.dc_ip or MOCK_DC_IP,
                                    domain=MOCK_DOMAIN,
                                    operator=cfg.bind_user)
        _log.info("（演示模式）已连接 dc=%s", cfg.dc_ip)
        # 🔑 组策略的**内容**（Registry.pol / GPT.INI）落在影子 SYSVOL 上。
        #    在这里铺一次（而不是在 __init__）：① 建目录失败只该在"真的要用"
        #    的时候才报；② 使用者看到"连上了"时，策略内容已经就位。
        self._sync_demo_sysvol()
        return self.info

    def disconnect(self) -> None:
        self.info = None
        self.cfg = None

    @property
    def connected(self) -> bool:
        return self.info is not None

    @property
    def base_dn(self) -> str:
        return (self.cfg.base_dn if self.cfg and self.cfg.base_dn else MOCK_BASE_DN)

    @property
    def domain(self) -> str:
        return (self.cfg.domain if self.cfg and self.cfg.domain else MOCK_DOMAIN)

    @property
    def bind_identity(self) -> str:
        r"""与真客户端**逐字一致**的绑定身份（``域\用户``）。

        演示域也要守这条：真域那边 NTLM 硬要求带反斜杠，演示域若还回 UPN，
        界面/审计在两套环境里就显示成两种东西 —— 保真度一破，
        演示里过的东西到真域就未必过。
        """
        raw = (self.cfg.bind_user if self.cfg else "demo") or "demo"
        return ntlm_bind_identity(raw, self.domain)

    # ---------------- 浏览 ----------------

    def list_child_ous(self, parent_dn: str) -> list[OuNode]:
        self._tick(0.6)
        nodes: list[OuNode] = []
        for node in self._ous:
            if node["parent"] != parent_dn:
                continue
            prefix = "CN" if node.get("container") else "OU"
            dn = f"{prefix}={escape_dn_value(node['name'])},{parent_dn}"
            nodes.append(OuNode(
                name=node["name"], dn=dn,
                has_children=any(o["parent"] == dn for o in self._ous),
                description=node.get("description", ""),
            ))
        nodes.sort(key=lambda n: n.name.lower())
        return nodes

    def list_users(self, ou_dn: str, subtree: bool = False,
                   limit: int | None = None) -> list[UserRow]:
        self._tick(0.8)
        if subtree:
            # 真子树语义：DN 以该容器结尾的都算
            # （``OU=A,DC=x`` 与 ``CN=u,OU=A,DC=x`` 都落在 ``DC=x`` 子树里）
            suffix = "," + ou_dn if ou_dn else ""
            hits = [u for u in self._users
                    if u.parent == ou_dn or u.parent.endswith(suffix)]
        else:
            hits = [u for u in self._users if u.parent == ou_dn]
        return [u.to_row() for u in (hits[:limit] if limit else hits)]

    def search_users(self, keyword: str, base_dn: str | None = None,
                     limit: int = 500) -> list[UserRow]:
        self._tick(0.7)
        key = (keyword or "").strip().lower()
        if not key:
            return []
        hits = [u for u in self._users
                if key in u.sam.lower() or key in u.display_name.lower()]
        return [u.to_row() for u in hits[:limit]]

    # 🔴 `get_user_attributes()` **真身与替身一起**于 2026-09-18 删除（拍板项 `G-06`）。
    #    真身那边删的理由是「生产零调用点 ＋ 第三份自己写的转换」；
    #    替身这边**必须跟着删** —— 留着就成了「演示域有、真身没有」，
    #    那正是本项目的红线「**名字不许说谎**」：调用方在演示模式里试通了，
    #    拿到真域上直接 `AttributeError`。
    #    替身原本那段「整数属性不要手拼」的教训（含 `T-3` 更正）**一字未改**
    #    搬进了 `_text_attrs()` 的 docstring —— 那才是它该住的地方。

    # ---------------- 账号操作 ----------------

    def unlock(self, dn: str, sam: str = "") -> None:
        self._tick(0.8)
        user = self._find_user(dn, sam)
        before = user.locked
        user.locked = False
        self._audit("unlock", user.sam, user.dn,
                    detail="演示模式：已解锁",
                    before={"locked": before}, after={"locked": False})

    def set_enabled(self, dn: str, enabled: bool, sam: str = "") -> None:
        self._tick(0.8)
        user = self._find_user(dn, sam)
        old = user.uac
        user.uac = set_uac_flag(user.uac, UF_ACCOUNTDISABLE, not enabled)
        self._audit("enable" if enabled else "disable", user.sam, user.dn,
                    detail="演示模式",
                    before={"userAccountControl": f"0x{old:X}"},
                    after={"userAccountControl": f"0x{user.uac:X}"})

    def reset_password(self, dn: str, new_password: str, sam: str = "",
                       must_change: bool = False) -> str:
        self._tick(1.0)
        if not new_password:
            raise AdToolError("请填写新密码。")
        if len(new_password) < 8:
            raise AdToolError("新密码不符合域密码策略（长度、复杂度或密码历史限制）。",
                              code="0x800708C5")
        user = self._find_user(dn, sam)
        user.locked = False
        # 0 = 「下次登录必须修改」；否则给一个正常的"刚改过"时间戳
        user.pwd_last_set = 0 if must_change else _filetime_days_ago(0)
        self._audit("reset_password", user.sam, user.dn,
                    detail=f"演示模式；通道：rpc；下次登录必须修改：{'是' if must_change else '否'}",
                    before={"pwdLastSet": "（已记录）"},
                    after={"channel": "rpc"},
                    secrets=(new_password,))
        return "rpc"

    # ---------------- 新建 ----------------

    def sam_exists(self, sam: str) -> bool:
        return any(u.sam.lower() == (sam or "").lower() for u in self._users)

    def suggest_sam(self, base: str, limit: int = 20) -> str:
        root = (base or "").strip()[:18] or "user"
        if not self.sam_exists(root):
            return root
        for i in range(2, limit + 1):
            if not self.sam_exists(f"{root}{i}"):
                return f"{root}{i}"
        return f"{root}{self._rand.randint(100, 999)}"

    def create_user(self, parent_dn: str, spec: UserSpec) -> str:
        self._tick(1.4)
        spec.validate()
        if self.sam_exists(spec.sam):
            raise AdToolError(
                f"登录名「{spec.sam}」已存在，建议改用「{self.suggest_sam(spec.sam)}」。")

        uac = UF_NORMAL_ACCOUNT
        if spec.keep_disabled:
            uac |= UF_ACCOUNTDISABLE
        user = _MockUser(
            spec.sam.strip(),
            spec.display_name.strip() or f"{spec.given_name}{spec.surname}".strip() or spec.sam,
            parent_dn, uac=uac, given_name=spec.given_name, surname=spec.surname,
            pwd_last_set=0 if spec.must_change else _filetime_days_ago(0),
            extra=dict(spec.extra or {}))
        self._users.append(user)
        self._audit("create_user", user.sam, user.dn,
                    detail=("演示模式：已创建并启用" if not spec.keep_disabled
                            else "演示模式：已创建（保持禁用）"),
                    before=None,
                    after={"distinguishedName": user.dn,
                           "userAccountControl": str(uac)},
                    secrets=(spec.init_password,))
        return user.dn

    def create_ou(self, parent_dn: str, name: str, description: str = "") -> str:
        self._tick(0.9)
        name = (name or "").strip()
        if not name:
            raise AdToolError("请填写组织单位名称。")
        if any(o["name"] == name and o["parent"] == parent_dn for o in self._ous):
            raise AdToolError("同名对象已存在，请换一个名称。", code="68")
        self._ous.append({"name": name, "parent": parent_dn,
                          "description": description})
        dn = f"OU={escape_dn_value(name)},{parent_dn}"
        self._audit("create_ou", name, dn, detail="演示模式", before=None,
                    after={"distinguishedName": dn, "description": description})
        return dn

    def create_group(self, parent_dn: str, name: str, scope: str = "global",
                     category: str = "security", description: str = "") -> str:
        self._tick(0.9)
        name = (name or "").strip()
        if not name:
            raise AdToolError("请填写组名。")
        if any(g.cn == name and g.parent == parent_dn for g in self._groups):
            raise AdToolError("同名对象已存在，请换一个名称。", code="68")
        group = _MockGroup(name, parent_dn, sam=name, scope=scope,
                           category=category, description=description)
        self._groups.append(group)
        gtype = group_type_value(scope, category)
        self._audit("create_group", name, group.dn, detail="演示模式",
                    before=None,
                    after={"distinguishedName": group.dn, "groupType": gtype})
        return group.dn

    # ---------------- 组成员 / 计算机 / 联系人（F06 / F07 / F08） ----------------

    def _require_group(self, group_dn: str) -> _MockGroup:
        obj, kind = self._find_entry(group_dn)
        if kind != ObjectKind.GROUP:
            raise AdToolError("该对象不是组，没有成员可管理。")
        return obj

    def list_group_members(self, group_dn: str, limit: int = 500,
                           ) -> list[DirObject]:
        self._tick(0.5)
        group = self._require_group(group_dn)
        want = {d.casefold() for d in group.members[:limit]}
        out: list[DirObject] = []
        for obj, kind in self._all_entries():
            if obj.dn.casefold() in want:
                out.append(self._to_dir_object(obj, kind))
        out.sort(key=lambda o: ((o.cn or o.sam or "").casefold(), o.kind))
        return out

    def add_to_group(self, member_dns: Any, group_dn: str, sam: str = "") -> int:
        self._tick(0.6)
        group = self._require_group(group_dn)
        members = [d.strip() for d in (member_dns or []) if d and d.strip()]
        if not members:
            raise AdToolError("未选择要加入组的对象。")
        for dn in members:
            self._find_entry(dn)                 # 不存在会抛真实的 code=32
        existing = {m.casefold() for m in group.members}
        fresh = [d for d in members if d.casefold() not in existing]
        if not fresh:
            raise AdToolError("所选对象已经全部是该组的成员。")
        group.members.extend(fresh)
        self._audit("add_member", sam, group.dn,
                    detail=f"演示模式：加入 {len(fresh)} 个成员",
                    after={"member": fresh})
        return len(fresh)

    def remove_from_group(self, member_dns: Any, group_dn: str,
                          sam: str = "") -> int:
        self._tick(0.6)
        group = self._require_group(group_dn)
        members = [d.strip() for d in (member_dns or []) if d and d.strip()]
        if not members:
            raise AdToolError("未选择要移出的成员。")
        existing = {m.casefold() for m in group.members}
        absent = [d for d in members if d.casefold() not in existing]
        if absent:
            raise AdToolError(
                "以下对象不是该组的直接成员（很可能是它的「主要组」 —— "
                "主要组不能直接移除，必须先把用户的「主要组」换成别的组）：\n· "
                + "\n· ".join(absent))
        removed_case = {d.casefold() for d in members}
        group.members = [m for m in group.members if m.casefold() not in removed_case]
        self._audit("remove_member", sam, group.dn,
                    detail=f"演示模式：移出 {len(members)} 个成员",
                    before={"member": members})
        return len(members)

    def create_computer(self, parent_dn: str, name: str,
                        description: str = "") -> str:
        self._tick(0.9)
        name = (name or "").strip()
        if not name:
            raise AdToolError("请填写计算机名。")
        if any(ch in name for ch in '\\/[]:;|=,+*?<>"'):
            raise AdToolError(f"计算机名「{name}」含有 AD 不允许的字符。")
        if len(name) > 15:
            raise AdToolError(
                f"计算机名「{name}」超过 15 个字符 —— NetBIOS 名上限 15，"
                "加域会被拒。")
        if any(c.cn == name and c.parent == parent_dn for c in self._computers):
            raise AdToolError("同名对象已存在，请换一个名称。", code="68")
        computer = _MockComputer(name, parent_dn, sam=f"{name}$",
                                 description=description,
                                 dns_host_name="", os="", os_version="",
                                 uac=0x1000 | UF_PASSWD_NOTREQD)
        self._computers.append(computer)
        self._audit("create_computer", computer.sam, computer.dn,
                    detail="演示模式：预创建（待加域）", before=None,
                    after={"distinguishedName": computer.dn})
        return computer.dn

    def reset_computer_account(self, dn: str, sam: str = "") -> str:
        self._tick(0.8)
        obj, kind = self._find_entry(dn)
        if kind != ObjectKind.COMPUTER:
            raise AdToolError("只有计算机账号才能执行「重置计算机账户」。")
        if has_uac_flag(obj.uac, UF_SERVER_TRUST_ACCOUNT):
            raise AdToolError("域控制器不能在这里重置 —— 请走域控专门的降级/重装流程。")
        self._audit("reset_computer", obj.sam, obj.dn,
                    detail="演示模式：机器密码已随机化；该机器需重新加入域",
                    after={"channel": "rpc"})
        return "rpc"

    def create_contact(self, parent_dn: str, name: str, mail: str = "",
                       description: str = "") -> str:
        self._tick(0.8)
        name = (name or "").strip()
        if not name:
            raise AdToolError("请填写联系人名称。")
        if any(c.cn == name and c.parent == parent_dn for c in self._contacts):
            raise AdToolError("同名对象已存在，请换一个名称。", code="68")
        contact = _MockContact(name, parent_dn, mail=mail,
                               description=description)
        self._contacts.append(contact)
        self._audit("create_contact", name, contact.dn, detail="演示模式",
                    before=None, after={"distinguishedName": contact.dn,
                                        "mail": mail})
        return contact.dn

    # ---------------- 账户页专用操作 ----------------

    def set_uac_single_flag(self, dn: str, flag: int, enabled: bool,
                            sam: str = "") -> None:
        self._tick(0.5)
        obj, kind = self._find_entry(dn)
        old = getattr(obj, "uac", 0)
        obj.uac = set_uac_flag(old, flag, enabled)
        self._audit("update", sam or obj.sam, obj.dn,
                    detail=f"演示模式：UAC 位 0x{flag:X} {'置 1' if enabled else '清 0'}",
                    before={"userAccountControl": f"0x{old:X}"},
                    after={"userAccountControl": f"0x{obj.uac:X}"})

    def set_account_expiry(self, dn: str, when: _datetime | None,
                           sam: str = "") -> None:
        self._tick(0.5)
        obj, _kind = self._find_entry(dn)
        overrides = getattr(obj, "overrides", None)
        if overrides is not None:
            _set_override(obj, "accountExpires",
                          ["0"] if when is None
                          else [str(datetime_to_ad_filetime(when))])
        if isinstance(obj, _MockUser):
            # 同时落到字段上：`get_object()` / 列表行读的是它，只写
            # `overrides` 会让回读永远是「永不过期」（同 `to_row` 的注释）
            obj.acct_expire_at = when
        self._audit("update", sam or getattr(obj, "sam", ""), obj.dn,
                    detail="演示模式：账户过期 = 永不过期" if when is None
                    else f"演示模式：账户过期 = {when:%Y-%m-%d %H:%M}",
                    after={"accountExpires": "0" if when is None else "（FILETIME）"})

    def set_must_change_password(self, dn: str, must: bool = True,
                                 sam: str = "") -> None:
        self._tick(0.5)
        user = self._find_user(dn=dn)
        user.pwd_last_set = 0 if must else _filetime_days_ago(0)
        self._audit("reset_password", user.sam, user.dn,
                    detail=("演示模式：下次登录必须修改密码" if must
                            else "演示模式：已取消「下次登录必须修改密码」"),
                    after={"pwdLastSet": "0" if must else "（当前时间）"})

    # ---------------- 登录时间 / 工作站 / 拨入（F13 / F14 / F15） ----------------

    def _override_value(self, obj: Any, name: str) -> Any:
        """取 overrides 里某属性的**原始**值（大小写不敏感）。没有返回 None。"""
        low = name.casefold()
        for key, values in (getattr(obj, "overrides", {}) or {}).items():
            if key.casefold() == low and values:
                return values[0]
        return None

    def get_logon_hours(self, dn: str) -> bytes | None:
        self._tick(0.2)
        obj, _kind = self._find_entry(dn)
        raw = self._override_value(obj, "logonHours")
        return bytes(raw) if isinstance(raw, (bytes, bytearray)) else None

    def set_logon_hours(self, dn: str, hours: bytes | None,
                        sam: str = "") -> None:
        self._tick(0.5)
        obj, _kind = self._find_entry(dn)
        old = self.get_logon_hours(dn)
        if hours is None:
            _set_override(obj, "logonHours", [])
        else:
            data = bytes(hours)
            if len(data) != LOGON_HOURS_BYTES:
                raise AdToolError(
                    f"登录时间位图必须是 {LOGON_HOURS_BYTES} 字节（当前 {len(data)}）。")
            _set_override(obj, "logonHours", [data])
        self._audit("update", sam or getattr(obj, "sam", ""), obj.dn,
                    detail="演示模式：登录时间 = 清除限制" if hours is None
                    else f"演示模式：登录时间已更新（{bytes(hours).hex()}）",
                    before={"logonHours": old.hex() if old else "（未限制）"},
                    after={"logonHours": "（未限制）" if hours is None
                           else bytes(hours).hex()})

    def get_logon_workstations(self, dn: str) -> list[str]:
        self._tick(0.2)
        obj, _kind = self._find_entry(dn)
        raw = self._override_value(obj, "userWorkstations")
        if raw is None:
            return []
        return [p.strip() for p in str(raw).split(",") if p.strip()]

    def set_logon_workstations(self, dn: str, names: list[str] | None,
                               sam: str = "") -> None:
        self._tick(0.5)
        obj, _kind = self._find_entry(dn)
        clean: list[str] = []
        for name in (names or []):
            name = (name or "").strip()
            if name and name not in clean:
                clean.append(name)
        old = self.get_logon_workstations(dn)
        if clean:
            _set_override(obj, "userWorkstations", [",".join(clean)])
        else:
            _set_override(obj, "userWorkstations", [])
        self._audit("update", sam or getattr(obj, "sam", ""), obj.dn,
                    detail="演示模式：登录工作站 = 清除限制" if not clean
                    else f"演示模式：登录工作站 = {','.join(clean)}",
                    before={"userWorkstations": old or "（未限制）"},
                    after={"userWorkstations": clean or "（未限制）"})

    def get_dialin(self, dn: str) -> dict[str, Any]:
        self._tick(0.2)
        obj, _kind = self._find_entry(dn)
        raw_allow = self._override_value(obj, "msNPAllowDialin")
        allow: bool | None
        if raw_allow is None:
            allow = None
        elif isinstance(raw_allow, bool):
            allow = raw_allow
        else:
            allow = str(raw_allow).strip().upper() == "TRUE"
        callback = str(self._override_value(obj, "msRADIUSCallbackNumber") or "")
        return {"allow": allow, "callback": callback}

    def set_dialin(self, dn: str, allow: bool | None,
                   callback: str = "", sam: str = "") -> None:
        self._tick(0.5)
        obj, _kind = self._find_entry(dn)
        old = self.get_dialin(dn)
        if allow is None:
            _set_override(obj, "msNPAllowDialin", [])
        else:
            _set_override(obj, "msNPAllowDialin",
                          ["TRUE" if allow else "FALSE"])
        callback = (callback or "").strip()
        if callback:
            _set_override(obj, "msRADIUSCallbackNumber", [callback])
            _set_override(obj, "msRASSavedCallbackNumber", [callback])
        elif old["callback"]:
            _set_override(obj, "msRADIUSCallbackNumber", [])
            _set_override(obj, "msRASSavedCallbackNumber", [])
        label = "允许" if allow else "拒绝" if allow is False else "由 NPS 策略控制"
        self._audit("update", sam or getattr(obj, "sam", ""), obj.dn,
                    detail=f"演示模式：拨入 = {label}；回拨 = {callback or '不回拨'}",
                    before=old, after={"allow": allow, "callback": callback})

    def search_raw_filter(self, base_dn: str, ldap_filter: str,
                          limit: int = 500) -> list[DirObject]:
        """演示模式的高级查找：迷你过滤器求值器（够 ADUC 对齐演示用）。"""
        self._tick(0.8)
        reason = validate_ldap_filter(ldap_filter)
        if reason:
            raise AdToolError(reason)
        subtree = True
        out: list[DirObject] = []
        for obj, kind in self._all_entries() + [(gpo, ObjectKind.OTHER)
                                                for gpo in self._gpo_entries()]:
            if len(out) >= max(1, int(limit or 500)):
                break
            if not _in_scope(obj.dn, base_dn or self.base_dn, subtree):
                continue
            # ⚠️ 用 `_text_attrs` 而不是 `_attrs_of`：过滤器比较的是**文本**，
            #    直接喂 bytes 会让 `(objectSid=...)` 这类过滤在演示域与真域上
            #    得到不同结果（真域比较的是编码后的字节）。
            attrs = self._text_attrs(obj, kind)
            if not _eval_filter_node(attrs, _parse_filter_expr(
                    ldap_filter.strip())[0]):
                continue
            out.append(self._to_dir_object(obj, kind))
        out.sort(key=lambda o: ((o.cn or o.sam or "").casefold(), o.kind))
        return out

    def list_well_known_containers(self, base_dn: str) -> list[OuNode]:
        # ⚠️ base_dn 必填，与真实客户端同合同 —— 演示域是「造出来的真实域」，
        #    调用方漏传参数必须在演示模式就爆，而不是静默兜底掩盖漂移。
        self._tick(0.3)
        base = (base_dn or "").strip()
        if not base:
            raise AdToolError("未指定容器。")
        # 拼法必须与 `OuNode.dn`（`_list_child_ous` 里那条）**逐字一致**：
        # 那边是 `f"{prefix}={escape_dn_value(name)},{parent_dn}"`，这里少一层
        # 转义就会在容器名含特殊字符时静默对不上 —— 名字是常量（Users/…）
        # 时恰好恒等，所以以前没暴露。见 test_mock_client.TestEveryDnRdnIsEscaped。
        wanted = {f"CN={escape_dn_value(name)},{base}".casefold()
                  for name in ("Users", "Computers", "Builtin")}
        return [node for node in self.list_child_ous(base)
                if node.dn.casefold() in wanted]

    def invalidate_tree_cache(self) -> None:
        """与真实客户端同名的整体失效口（演示域没有探测缓存，no-op）。

        合同在 `tests/test_client_contract.py` 钉住：real 有它，mock 也必须有，
        否则演示模式下谁调用它就是 AttributeError。
        """

    # ---------------- 多类型对象（ADUC 对齐） ----------------

    def _all_entries(self) -> list[tuple[Any, str]]:
        """四类业务对象的 (对象, 类型) 列表。**不含 OU**（OU 单独走 `_ou_entries`）。"""
        entries: list[tuple[Any, str]] = [(u, ObjectKind.USER) for u in self._users]
        entries += [(g, ObjectKind.GROUP) for g in self._groups]
        entries += [(c, ObjectKind.COMPUTER) for c in self._computers]
        entries += [(c, ObjectKind.CONTACT) for c in self._contacts]
        return entries

    def _ou_entries(self) -> list[_MockOu]:
        return [_MockOu(n["name"], n["parent"], n.get("description", ""),
                        container=n.get("container", False))
                for n in self._ous]

    def _gpo_entries(self) -> list[_MockGpo]:
        """演示域里的组策略对象。

        ⚠️ **刻意不并进 `_all_entries()`** —— 那一份是"用户/组/计算机/联系人"
        四类业务对象，喂给列表页（`list_objects`）与删除计划。
        真 AD 里 GPO 在 ``CN=Policies,CN=System`` 下，而那个容器
        **不在控制台树里**，所以它也不该出现在列表页。
        只在"按过滤器搜属性"（`search_attributes` / `search_raw_filter`）
        与"按 DN 找对象"（`_find_entry`）两处认它 —— 那两处才是真域上
        真能查到 GPO 的地方。
        """
        return list(self._gpos)

    # ---------------- 影子 SYSVOL（演示域的策略内容） ----------------

    def _demo_gpo_dir(self, guid: str) -> str:
        """某个 GPO 在影子 SYSVOL 上的目录（**与真域的路径构成逐层一致**）。

        ⚠️ **私有，且名字带 `demo_`**：真域的 GPO 目录来自 AD 属性
        `gPCFileSysPath`（卷上真实存在的共享），**不是**自己按 GUID 拼出来的
        ⇒ 这个方法**不该**长在真身（`AdClient`）上。做成公开方法会被
        `test_client_contract` 记成「演示域独有接口」—— 那等于在说
        「这是个真能力」，**名字说谎**。

        ⚠️ 这里**不调** `gpo_settings.sysvol_gpo_dir()` —— 那个函数属于生产侧，
        它按"域名 × GUID"拼路径；演示域只是把同一棵树放在本地根下。
        两边一旦互相调用，就没法分别验证"路径算得对"与"文件写得了"。
        一致性由 `tests/test_gpo_demo_security.py` 拿生产那个函数**对照**着钉
        （它同时钉 `GPT.INI` 与 `GptTmpl.inf` 两条路径）。
        """
        return os.path.join(self.sysvol_root, MOCK_DOMAIN, "Policies", guid)

    def _demo_gpt_ini(self, guid: str) -> str:
        """影子 SYSVOL 上那份 `GPT.INI` 的完整路径（私有理由同上）。"""
        return os.path.join(self._demo_gpo_dir(guid), "GPT.INI")

    def _demo_security_inf(self, guid: str) -> str:
        """影子 SYSVOL 上那份 `GptTmpl.inf` 的完整路径（私有理由同上）。

        ⚠️ 这里**不调** `gpo_security.security_inf_path()`（生产那一个）——
        理由与 `_demo_gpo_dir()` 不调 `sysvol_gpo_dir()` 是同一条：
        两边一旦互相调用，就分不开"路径算得对"与"文件写得了"。
        一致性由 `tests/test_gpo_demo_security.py` 拿生产那个函数
        **对照**着钉（两份拼出来的路径必须逐字符相等）。

        子目录串**逐字**抄协议（连大小写一起）：
        `MACHINE\\microsoft\\windows nt\\SecEdit\\GptTmpl.inf` ——
        真域的文件系统大小写不敏感，但判据会在 Linux 上跑，那时就有所谓了。
        """
        return os.path.join(self._demo_gpo_dir(guid), "MACHINE", "microsoft",
                            "windows nt", "SecEdit", "GptTmpl.inf")

    def _sync_demo_sysvol(self) -> None:
        """把种子设置落到影子 SYSVOL 上（**只覆盖我们自己管的文件**）。

        🔴 两个判据：

        1. **内容是"真字节"**：`Registry.pol` 用生产同一份编码器
           （`preg_backend.build_preg`）写出来、`GptTmpl.inf` 按
           `_demo_inf_bytes()` 的 UTF-16LE ＋ BOM ＋ CRLF 写 —— 所以演示模式
           读到的都是真格式，不是"看起来像"的东西。
        2. **不删任何东西**：只写五类已知文件
           （每作用域一份 `Registry.pol` ＋ 一份 `GPT.INI`
           ＋ 一份 `GptTmpl.inf`），且**只在文件不存在时写**。
           不做"清空目录再铺"—— 那会把使用者自己改出来的东西一并抹掉
           （演示模式的意义正是**让改动看得见、留得住**）。

        ⚠️ `DEMO_GPO_CONTENT_VERSION` **现在不在这里被读**（见那个常量的更正段）。
        本方法在 `connect()` 成功之后调一次。
        """
        try:
            os.makedirs(os.path.join(self.sysvol_root, MOCK_DOMAIN,
                                     "Policies"), exist_ok=True)
        except OSError as exc:
            _log.warning("影子 SYSVOL 建不出来（演示模式的组策略内容将不可用）："
                              "%s：%s", self.sysvol_root, exc)
            return

        for gpo in self._gpos:
            directory = self._demo_gpo_dir(gpo.guid)
            by_scope: dict[str, list[PregEntry]] = {"Machine": [], "User": []}
            for scope, key, value_name, type_code, data in gpo.settings:
                by_scope.setdefault(scope, []).append(
                    PregEntry(key=key, value_name=value_name,
                              type_code=type_code, data=data))
            for scope, rows in by_scope.items():
                path = os.path.join(directory, scope, "Registry.pol")
                os.makedirs(os.path.dirname(path), exist_ok=True)
                if os.path.isfile(path):
                    continue                    # ⚠️ 已存在的**不覆盖**（保住改动）
                # 空策略写 **0 字节**（不是只有文件头的 8 字节）——
                # 真域里"这个作用域没有管理模板设置"就是 0 字节，
                # 而 `preg_backend.is_empty_preg()` 正是按这个判的。
                with open(path, "wb") as handle:
                    handle.write(build_preg(rows) if rows else b"")
            self._sync_gpt_ini(gpo)
            self._sync_security_inf(gpo)

    def _sync_security_inf(self, gpo: _MockGpo) -> None:
        """把安全策略正文落到影子 SYSVOL 的 `GptTmpl.inf`（**只在缺文件时写**）。

        ⚠️ 正文为空 ⇒ **一个字节都不写**，连目录都不建 —— 真域里"这条 GPO 没配
        安全策略"就是**文件不存在**。若在这里写个 0 字节文件，演示出来的
        「没配过」就变成了「文件坏了」，那正好是本项目最忌讳的那种
        "把两种截然不同的状态显示成同一句话"。

        🔒 这张文件**没有任何生产写入者**（写侧随「组策略只读」裁定移出仓库），
        所以它是"**服务端的初始状态**"：照它自己该有的样子铺数据，
        才验得出**客户端的读法**对不对。与 `_sync_gpt_ini()` 同一条理由。
        """
        if not gpo.security_body:
            return
        path = self._demo_security_inf(gpo.guid)
        if os.path.isfile(path):
            return                      # ⚠️ 已存在的不动 —— 与 Registry.pol 同一条纪律
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(_demo_inf_bytes(gpo.security_body))

    def _sync_gpt_ini(self, gpo: _MockGpo) -> None:
        """把种子里的版本号落到 ``GPT.INI``（**只在缺这一行时写**）。

        ⚠️ **2026-09-18 更正**：本方法原来写着「`GPT.INI` 的写入实现只有一份，
        在 `gpo_write.py`，由 `tests/test_gpo_demo_sysvol.py` 拿它的读法来钉」——
        **这两句现在都不成立**：`gpo_write.py` 随「组策略只读」裁定移出仓库，
        那个测试件**全库都不存在**（是幻影指针）。
        ⇒ 现在的实情是：**生产侧没有任何代码读这个文件**
        （`grep -rn "GPT.INI"` 只剩本文件与两处注释）。它是演示域里一份
        **"服务端事实"的忠实复制品**，用途是让将来重接版本对齐时有原始材料。
        版本号写得对不对，由 `tests/test_gpo_demo_security.py` 按 `[General]`
        行**自己解析**来钉（不假装有一个不存在的读取者）。
        """
        path = self._demo_gpt_ini(gpo.guid)
        if os.path.isfile(path):
            return                      # ⚠️ 已存在的不动 —— 保住使用者改过的版本
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\r\n") as handle:
            handle.write("[General]\nVersion=%d\n" % gpo.version_number)

    def _find_entry(self, dn: str) -> tuple[Any, str]:
        """按 DN 找对象。找不到就抛**真实 AD 的那种错误**（含 code=32）。"""
        target = (dn or "").strip().casefold()
        if not target:
            raise AdToolError("未指定对象。", code="32")
        if target == (self.base_dn or MOCK_BASE_DN).casefold():
            return _MockRoot(self.base_dn or MOCK_BASE_DN), ObjectKind.OTHER
        for obj, kind in self._all_entries():
            if obj.dn.casefold() == target:
                return obj, kind
        for gpo in self._gpo_entries():
            if gpo.dn.casefold() == target:
                return gpo, ObjectKind.OTHER
        for ou in self._ou_entries():
            if ou.dn.casefold() == target:
                return ou, ObjectKind.OU
        raise AdToolError("对象不存在或已被删除，请刷新后重试。", code="32")

    def _container_exists(self, dn: str) -> bool:
        """目标容器是否可放东西（域根 / OU / 容器算，用户不算）。"""
        if not dn:
            return False
        try:
            _, kind = self._find_entry(dn)
        except AdToolError:
            return False
        return kind in (ObjectKind.OU, ObjectKind.OTHER)

    def _text_attrs(self, obj: Any, kind: str) -> dict[str, list[str]]:
        """属性表 → **展示形态**（`bytes` 转成文本）。

        与真身**同一条路径**：真身的 `read_attributes` 也是在这里把 ldap3 给的
        `bytes` 交给 `utils.format_attr_value`。所以演示域必须走同一个函数，
        而不是自己存一份文本 —— 否则转换坏掉时演示模式照样"正常"。

        ⚠️ **整数属性不要「在这里把模型值手拼成文本」**（比如 `str(user.uac)`）：
        那是演示域自己算出一份文本，真域走的是「`raw_attributes` 的字节 →
        唯一换算口 `int_bytes_to_int`」。两条路眼下给出同一个数，但只要真域
        那一侧坏掉（2026-09-15 就是），演示模式**永远是绿的** ⇒ 必须复用同一条转换链。

        ⚠️ 此处曾经写作「真域走的是『小端二进制 → `format_attr_value`』」——**说反了**
        （2026-09-16 更正，= 拍板项 `T-3`）：真域发的是 **ASCII 十进制文本** `b'512'`；
        **小端二进制来自替身** `tests/fake_ldap`。
        （这段话原住在 `get_user_attributes()` 里，那个方法 2026-09-18 已删 —— 内容**一字未改**搬到这里。）
        """
        return {key: [format_attr_value(key, item) for item in values]
                for key, values in self._attrs_of(obj, kind).items()}

    def read_attributes(self, dn: str, names: Any = None) -> dict[str, list[str]]:
        """读对象属性，``{属性名: [值, ...]}``（保留多值）。"""
        self._tick(0.3)
        obj, kind = self._find_entry(dn)
        data = self._text_attrs(obj, kind)
        if names and "*" not in list(names):
            want = {str(n).casefold() for n in names}
            data = {k: v for k, v in data.items() if k.casefold() in want}
        return {k: list(v) for k, v in data.items()}

    def search_attributes(self, base_dn: str, ldap_filter: str,
                          attributes: Any = (), scope: str = "SUBTREE",
                          limit: Any = None, what: str = "查询") -> dict:
        """按过滤器一次查一批对象，返回 ``{属性名: [值, ...]}``。

        与 `AdClient.search_attributes` 同合同（参数名与默认值逐一对应，
        由 `tests/test_client_contract.py` 对账）。

        ⚠️ **组策略对象（`groupPolicyContainer`）在演示域里是有的**
        （2026-09-18 起，见本文件「组策略（演示域）」那节的长说明）：
        要在演示模式下验"**能不能编辑**"，而编辑这件事只有
        "SMB 权限与重定向"那一层是本机验不了的，其余（PReg 字节、ADMX 对照、
        版本号同步、快照回滚）都能在本地影子 SYSVOL 上验。
        ⇒ 编造与否**不是关键，诚实边界才是**：结论里必须写清
        **「演示模式能改」 ≠ 「真域能改」**，那句话挂在界面上。

        ⚠️ 与真身一样**只回请求的属性**（外加 ``distinguishedName``）：
        真身 `search_attributes` 传什么属性名给域控，域控就只回什么。
        演示域若"顺手全给"，调用方少写一个属性名在演示模式里照样有值、
        到真域才空 —— 这类漂移必须在演示模式就暴露。
        """
        self._tick(0.5)
        base = (base_dn or self.base_dn or "").strip()
        subtree = str(scope).upper() != "LEVEL"
        names = [str(name) for name in (attributes or ())]
        if "distinguishedName" not in names:
            names.append("distinguishedName")

        node = _parse_filter_expr(
            (ldap_filter or "(objectClass=*)").strip())[0]

        out: list[dict[str, list[str]]] = []
        for obj, kind in self._all_entries() + [(gpo, ObjectKind.OTHER)
                                                for gpo in self._gpo_entries()]:
            if limit is not None and len(out) >= int(limit):
                break
            if not _in_scope(obj.dn, base, subtree):
                continue
            # ⚠️ 用 `_text_attrs`（与 `search_raw_filter` 同一个理由）：
            #    过滤器比较的是**文本**，直接喂 bytes 会让同一个过滤器在
            #    演示域与真域上得到不同结果。
            attrs = self._text_attrs(obj, kind)
            if not _eval_filter_node(attrs, node):
                continue
            row: dict[str, list[str]] = {}
            for name in names:
                values = attrs.get(name)
                if values:
                    row[name] = list(values)
            row.setdefault("distinguishedName", [obj.dn])
            out.append(row)
        return out

    def read_object_sid(self, dn: str) -> str:
        """读对象的 SID 文本（``'S-1-5-…'``）—— 与 `AdClient.read_object_sid` 同语义。

        ⚠️ 演示域必须实现这一条：`AdClient.read_object_sid` 是**客户端契约**的
        一部分（`tests/test_client_contract.py` 对账两个客户端的能力面）。
        演示域缺了它，任何"拿 SID 去授权"的路径在演示模式里就会 AttributeError,
        而真域上却是好的（**这正是"演示域覆盖薄"那类缺陷**：两个域在
        主流程上的能力必须一致，否则演示模式会在意想不到的地方崩）。

        ⚠️ 2026-09-16 注：本方法**唯一的生产调用者**原先是「共享盘权限」那批
        worker（`_domain_sid_of` / `grant_share_layer`）—— 它们已随
        「操作共享盘」功能整体删除 ⇒ 现在**生产侧零调用点**，只剩契约与测试在用。
        保留它是**有意为之**（客户端契约不该因为一个功能下线就收窄），
        是否收窄另行决定；**不要**因为"没人调"就顺手删掉它。

        与真域一致：**联系人等非安全主体没有 SID**，这里同样抛 `AdToolError`
        （而不是回一个假 SID —— 那会让「拿 SID 去授权」在演示里看起来是通的）。
        """
        self._tick(0.3)
        obj, kind = self._find_entry(dn)
        raw = (self._attrs_of(obj, kind).get("objectSid") or [None])[0]
        if not isinstance(raw, (bytes, bytearray)):
            raise AdToolError(
                "该对象没有 SID —— 它可能不是安全主体（联系人等没有 SID）。")
        return sid_bytes_to_string(bytes(raw))

    def list_upn_suffixes(self) -> list[str]:
        """演示模式的 UPN 后缀：默认域 + 一个虚构的自定义后缀。"""
        self._tick(0.3)
        suffixes = [f"@{self.domain}"]
        extra = "@hq.demo.local"
        if extra not in suffixes:
            suffixes.append(extra)
        return suffixes

    def get_object(self, dn: str, kind: str = "") -> DirObject:
        self._tick(0.3)
        obj, kind = self._find_entry(dn)
        return self._to_dir_object(obj, kind)

    def list_objects(self, base_dn: str, kinds: Any = None,
                     scope: str = "LEVEL", keyword: str = "",
                     limit: int | None = None) -> list[DirObject]:
        self._tick(0.8)
        wanted = list(kinds or ObjectKind.ALL)
        subtree = str(scope).upper() == "SUBTREE"
        key = (keyword or "").strip().casefold()

        out: list[DirObject] = []
        # ⚠️ OU 不在 _all_entries() 里（那里刻意只放四类业务对象），
        #    按 kind 过滤查 OU（部门候选、高级查找）必须把 _ou_entries() 拼进来，
        #    否则 (ObjectKind.OU,) 的查询永远返回 0 行。
        entries: list[tuple[Any, str]] = self._all_entries() + [
            (ou, ObjectKind.OU) for ou in self._ou_entries()]
        for obj, kind in entries:
            if kind not in wanted:
                continue
            if not _in_scope(obj.dn, base_dn, subtree):
                continue
            if key and not self._matches(obj, kind, key):
                continue
            out.append(self._to_dir_object(obj, kind))
        out.sort(key=lambda o: ((o.cn or o.sam or "").casefold(), o.kind))
        return out[:limit] if limit else out

    @staticmethod
    def _matches(obj: Any, kind: str, key: str) -> bool:
        fields = [getattr(obj, "cn", ""), getattr(obj, "sam", ""),
                  getattr(obj, "display_name", ""),
                  getattr(obj, "description", "")]
        if kind == ObjectKind.USER:
            fields.append(getattr(obj, "display_name", ""))
        if kind == ObjectKind.CONTACT:
            fields += [getattr(obj, "display_name", ""), getattr(obj, "mail", "")]
        if kind == ObjectKind.COMPUTER:
            fields.append(getattr(obj, "dns_host_name", ""))
        return any(key in str(f or "").casefold() for f in fields)

    def _to_dir_object(self, obj: Any, kind: str) -> DirObject:
        """演示对象 → 通用行结构。字段语义必须与 `AdClient._to_dir_object` 一致。"""
        # ⚠️ `_MockUser` 没有 `cn` 字段（用户的 cn 就是 displayName），
        #    统一在这里取一次，别在下面每个分支各写一遍 getattr。
        cn = getattr(obj, "cn", "") or getattr(obj, "display_name", "") or \
            getattr(obj, "sam", "")
        common: dict[str, Any] = {
            "kind": kind,
            "cn": cn,
            "sam": getattr(obj, "sam", ""),
            "display_name": getattr(obj, "display_name", "") or cn,
            "description": getattr(obj, "description", ""),
            "dn": obj.dn,
            "parent_dn": parent_of_dn(obj.dn),
            "when_created": ad_generalized_time_to_dt(
                _to_generalized(getattr(obj, "when_created", ""))),
            "when_changed": ad_generalized_time_to_dt(
                _to_generalized(getattr(obj, "when_changed", ""))),
        }

        if kind == ObjectKind.USER:
            row = obj.to_row()
            out = DirObject.from_user(row)
            out.cn = obj.display_name or obj.sam
            out.description = getattr(obj, "description", "")
            out.mail = _override_first(obj, "mail") or str(
                (obj.extra or {}).get("mail", ""))
            out.when_created = common["when_created"]
            out.when_changed = common["when_changed"]
            return out

        if kind == ObjectKind.GROUP:
            # ⚠️ 2026-09-17：原来这里还传 `member_count=len(obj.members)`，
            #    而 `DirObject.member_count` 已作为零调用点死代码删除（界面从不显示它）
            #    ⇒ 演示域不许再给一个不存在的字段赋值（那样会 TypeError）。
            return DirObject(**common, has_account=False,
                             group_scope=obj.scope, group_category=obj.category)
        if kind == ObjectKind.COMPUTER:
            return DirObject(
                **common, has_account=True,
                enabled=not has_uac_flag(obj.uac, UF_ACCOUNTDISABLE),
                is_dc=has_uac_flag(obj.uac, UF_SERVER_TRUST_ACCOUNT),
                uac=obj.uac, dns_host_name=obj.dns_host_name, os=obj.os,
                os_version=obj.os_version, location=obj.location,
                last_logon=ad_filetime_to_dt(obj.last_logon) if obj.last_logon else None)
        if kind == ObjectKind.CONTACT:
            return DirObject(**common, has_account=False, mail=obj.mail,
                             given_name=obj.given_name, surname=obj.surname)
        return DirObject(**common, has_account=False)

    def _attrs_of(self, obj: Any, kind: str) -> dict[str, list[Any]]:
        """把演示对象摊成 LDAP 属性表（属性名用真实 AD 的写法）。

        刻意用真实属性名而不是自定义字段名：这样界面里"显示哪个属性"
        的代码在演示模式与真域上走的是同一条路径。
        """
        dn = obj.dn
        data: dict[str, list[Any]] = {
            "distinguishedName": [dn],
            # ⚠️ 类型是 **bytes**，不是文本 —— 与真域一致（真身拿到的就是 bytes，
            #    由 `read_attributes` 负责转成文本）。见文件上方那段说明。
            "objectGUID": [_demo_guid_bytes(dn)],
            "objectSid": [_demo_sid_bytes(dn, self.domain)],
        }
        if isinstance(obj, _MockGpo):
            # ⚠️ 用 `isinstance` 认，不靠 `kind == OTHER` —— OTHER 也会落到
            #    域根（`_MockRoot`）之类的对象上，那一类没有这些属性。
            data.update({
                "objectClass": ["top", "container", "groupPolicyContainer"],
                # `gpo_ldap.list_gpos()` 的过滤器是
                # `(objectCategory=groupPolicyContainer)`。真 AD 里这个属性存的
                # 是 **DN**，而 AD 的 `objectCategory` 支持"用 DN 的首个 RDN 值
                # 匹配"（有专用匹配规则、且该属性有索引）—— 所以过滤器写成
                # 短名是能命中的。演示域直接存短名，与其它对象的写法一致
                # （`person` / `group` / `computer` / `contact` 也都是短名）。
                "objectCategory": ["groupPolicyContainer"],
                "cn": [obj.guid],
                "name": [obj.guid],
                "displayName": [obj.display_name],
                # 真 AD 里 `versionNumber` 是 **Integer** ⇒ 由 `_wire_attr_value`
                # 转成小端二进制发出去，客户端再用 `utils.format_attr_value`
                # 读回十进制（两边都不许"按 Python 类型猜"）。
                "versionNumber": [str(obj.version_number)],
                "gPCFileSysPath": [self._demo_gpo_dir(obj.guid)],
                "whenCreated": [_to_generalized(obj.when_created)],
                "whenChanged": [_to_generalized(obj.when_changed)],
            })
            # ⚠️ `gPCMachineExtensionNames` **只在有值时才进字典** ——
            #    真 AD 不回「没有值」的属性，而 `org`/`ou` 那些对象的属性
            #    也是同一个规矩（`search_attributes` 只回请求过的、**且有值的**）。
            #    塞一个 `[""]` 进去，演示域就会多出一档真域没有的形态，
            #    于是 `gpo_ldap._machine_extension_names()` 里那条
            #    「键不在 = 域控说没有值」的推理在演示模式下**永远验不到**。
            if obj.extension_names:
                data["gPCMachineExtensionNames"] = [obj.extension_names]
        elif kind == ObjectKind.USER:
            computed = obj.uac | (UF_LOCKOUT if obj.locked else 0)
            data.update({
                "objectClass": ["top", "person", "organizationalPerson", "user"],
                "objectCategory": ["person"],
                "cn": [obj.display_name or obj.sam],
                "name": [obj.display_name or obj.sam],
                "sAMAccountName": [obj.sam],
                "userPrincipalName": [f"{obj.sam}@{self.domain}"],
                "displayName": [obj.display_name],
                "givenName": [obj.given_name],
                "sn": [obj.surname],
                "userAccountControl": [str(obj.uac)],
                "msDS-User-Account-Control-Computed": [str(computed)],
                "lockoutTime": ["133700000000000000"] if obj.locked else [],
                "pwdLastSet": [str(obj.pwd_last_set)],
                "msDS-UserPasswordExpiryTimeComputed": [str(obj.pwd_expire_at)],
                # 与真 AD 同一套哨兵语义：0 / 0x7FFFFFFFFFFFFFFF = 永不过期
                "accountExpires": [
                    "0" if obj.acct_expire_at is None
                    else str(datetime_to_ad_filetime(obj.acct_expire_at))],
                "lastLogonTimestamp": ([str(obj.last_logon)] if obj.last_logon else []),
                "whenCreated": [_to_generalized(obj.when_created)],
                "whenChanged": [_to_generalized(obj.when_changed)],
            })
            for key, value in (obj.extra or {}).items():
                if value:
                    data[key] = [str(value)]
            member_of = [g.dn for g in self._groups if dn in g.members]
            if member_of:
                data["memberOf"] = member_of
        elif kind == ObjectKind.GROUP:
            gtype = group_type_value(obj.scope, obj.category)
            data.update({
                "objectClass": ["top", "group"],
                "objectCategory": ["group"],
                "cn": [obj.cn],
                "name": [obj.cn],
                "sAMAccountName": [obj.sam],
                "groupType": [str(gtype)],
                "description": [obj.description],
                "member": list(obj.members),
                "whenCreated": [_to_generalized(obj.when_created)],
                "whenChanged": [_to_generalized(obj.when_changed)],
            })
        elif kind == ObjectKind.COMPUTER:
            data.update({
                "objectClass": ["top", "person", "organizationalPerson",
                                "user", "computer"],
                "objectCategory": ["computer"],
                "cn": [obj.cn],
                "name": [obj.cn],
                "sAMAccountName": [obj.sam],
                "dNSHostName": [obj.dns_host_name],
                "operatingSystem": [obj.os],
                "operatingSystemVersion": [obj.os_version],
                "location": [obj.location],
                "description": [obj.description],
                "userAccountControl": [str(obj.uac)],
                "whenCreated": [_to_generalized(obj.when_created)],
                "whenChanged": [_to_generalized(obj.when_changed)],
            })
        elif kind == ObjectKind.CONTACT:
            data.update({
                "objectClass": ["top", "person", "organizationalPerson",
                                "contact"],
                "objectCategory": ["contact"],
                "cn": [obj.cn],
                "name": [obj.cn],
                "displayName": [obj.display_name],
                "givenName": [obj.given_name],
                "sn": [obj.surname],
                "mail": [obj.mail],
                "telephoneNumber": [obj.telephone],
                "title": [obj.title_text],
                "department": [obj.department],
                "description": [obj.description],
                "whenCreated": [_to_generalized(obj.when_created)],
                "whenChanged": [_to_generalized(obj.when_changed)],
            })
        else:                                   # OU / 其它容器
            data.update({
                "objectClass": (["top", "organizationalUnit"]
                                if kind == ObjectKind.OU else ["top", "container"]),
                "cn": [obj.cn],
                "name": [obj.cn],
                "ou": [obj.cn] if kind == ObjectKind.OU else [],
                "description": [getattr(obj, "description", "")],
            })

        # 最后套上用户手工写过的属性（属性编辑器写下来的东西）
        for key, values in (getattr(obj, "overrides", {}) or {}).items():
            low = key.casefold()
            for existing in [k for k in data if k.casefold() == low]:
                del data[existing]
            if values:
                data[key] = list(values)
        # 出口统一成**线上形态**（整数 → 小端二进制）。
        # ⚠️ 放在最后一步，是为了让"属性编辑器写下来的文本"也一起归一化：
        #    真域上写完再读回来，域控给的是二进制，不是当初写进去的那串文本。
        return {k: [_wire_attr_value(k, v) for v in vals]
                for k, vals in data.items() if vals}

    # ---------------- 删除 ----------------

    def plan_delete(self, dn: str, kind: str = "", label: str = "") -> DeletePlan:
        self._tick(0.4)
        obj, real_kind = self._find_entry(dn)
        label = label or obj.cn
        blocked = self._delete_block_reason(obj, real_kind)
        if blocked:
            return DeletePlan(root_dn=obj.dn, root_label=label,
                              blocked_reason=blocked)

        descendants: list[DirObject] = []
        if real_kind == ObjectKind.OU:
            for child, child_kind in self._all_entries():
                if is_descendant_dn(child.dn, obj.dn):
                    descendants.append(self._to_dir_object(child, child_kind))
            for child_ou in self._ou_entries():
                if is_descendant_dn(child_ou.dn, obj.dn):
                    descendants.append(
                        self._to_dir_object(child_ou, ObjectKind.OU))
        descendants.sort(key=lambda o: dn_depth(o.dn), reverse=True)
        return DeletePlan(root_dn=obj.dn, root_label=label,
                          descendants=descendants)

    def _delete_block_reason(self, obj: Any, kind: str) -> str:
        dn = obj.dn
        if dn.casefold() == (self.base_dn or "").casefold():
            return "这是域根目录，本工具不允许删除整个域。"
        if not parent_of_dn(dn):
            return "这是域根目录，不能删除。"
        if rdn_of(dn).casefold() in PROTECTED_CONTAINERS:
            return PROTECTED_CONTAINERS[rdn_of(dn).casefold()]
        if kind == ObjectKind.COMPUTER and has_uac_flag(obj.uac,
                                                        UF_SERVER_TRUST_ACCOUNT):
            return ("该对象是「域控制器」（DC）。删除域控会破坏整个域的"
                    "复制与认证，本工具不允许。")
        return ""

    def delete_object(self, dn: str, kind: str = "", label: str = "",
                      sam: str = "", expected_total: int | None = None,
                      confirmed_dns: list[str] | None = None) -> int:
        self._tick(1.0)
        plan = self.plan_delete(dn, kind, label)
        if not plan.allowed:
            self._audit("delete", sam, dn, result="failed",
                        detail=plan.blocked_reason)
            raise AdToolError(plan.blocked_reason)
        # 与真实客户端同一份复核语义（DN diff 优先，数量检查兜底）
        if confirmed_dns is not None:
            diff = plan.diff_against(confirmed_dns)
            if diff:
                message = (f"「{plan.root_label}」的内容在确认之后发生了变化："
                           f"{diff}\n"
                           "为避免删掉你没看过的对象，本次删除已中止，"
                           "请重新确认。")
                self._audit("delete", sam, dn, result="failed", detail=message)
                raise AdToolError(message)
        elif expected_total is not None and plan.total != expected_total:
            message = (f"「{plan.root_label}」的内容在确认之后发生了变化"
                       f"（确认时 {expected_total} 个对象，现在 {plan.total} 个）。\n"
                       "为避免删掉你没看过的对象，本次删除已中止，请重新确认。")
            self._audit("delete", sam, dn, result="failed", detail=message)
            raise AdToolError(message)

        self._remove_by_dn([o.dn for o in plan.descendants] + [plan.root_dn])
        self._audit("delete", sam, dn,
                    detail=f"{plan.summary()}；共删除 {plan.total} 个对象",
                    before={"distinguishedName": dn,
                            "descendant_count": len(plan.descendants)})
        return plan.total

    def _remove_by_dn(self, dns: list[str]) -> int:
        targets = {d.casefold() for d in dns}
        removed = 0

        def _filter(seq: list[Any]) -> list[Any]:
            nonlocal removed
            keep = []
            for item in seq:
                if item.dn.casefold() in targets:
                    removed += 1
                else:
                    keep.append(item)
            return keep

        self._users = _filter(self._users)
        self._groups = _filter(self._groups)
        self._computers = _filter(self._computers)
        self._contacts = _filter(self._contacts)
        kept_ous = []
        for node in self._ous:
            ou = _MockOu(node["name"], node["parent"])
            if ou.dn.casefold() in targets:
                removed += 1
            else:
                kept_ous.append(node)
        self._ous = kept_ous
        # 组里的成员引用也要跟着清掉，否则会在组属性里看到幽灵成员
        for group in self._groups:
            group.members = [m for m in group.members
                             if m.casefold() not in targets]
        return removed

    # ---------------- 移动 / 重命名 ----------------

    def move_object(self, dn: str, new_parent_dn: str, sam: str = "",
                    label: str = "") -> str:
        self._tick(0.6)
        obj, kind = self._find_entry(dn)
        new_parent_dn = (new_parent_dn or "").strip()
        if not new_parent_dn:
            raise AdToolError("请选择要移动到的目标容器。")
        old_parent = parent_of_dn(obj.dn)
        if old_parent.casefold() == new_parent_dn.casefold():
            raise AdToolError(f"对象已经在这个容器里了（{old_parent}）。")
        if (new_parent_dn.casefold() == obj.dn.casefold()
                or is_descendant_dn(new_parent_dn, obj.dn)):
            raise AdToolError(
                "不能把对象移动到它自己或它的下级容器里 —— 那会形成一个"
                "无法解析的环，AD 也拒绝执行。")
        if not self._container_exists(new_parent_dn):
            raise AdToolError("目标容器不存在，请刷新左侧目录树后重试。",
                              code="32")

        old_dn = obj.dn
        if kind == ObjectKind.OU:
            for node in self._ous:
                if (node["name"] == obj.cn
                        and node["parent"] == old_parent):
                    node["parent"] = new_parent_dn
        else:
            obj.parent = new_parent_dn
        new_dn = f"{rdn_of(old_dn)},{new_parent_dn}"

        self._audit("move", sam, old_dn,
                    detail=f"{old_parent} → {new_parent_dn}",
                    before={"distinguishedName": old_dn},
                    after={"distinguishedName": new_dn})
        return new_dn

    def rename_object(self, dn: str, new_name: str, kind: str = "",
                      sam: str = "", sync_account_name: bool = True) -> str:
        self._tick(0.6)
        new_name = (new_name or "").strip()
        if not new_name:
            raise AdToolError("请填写新的名称。")
        obj, kind = self._find_entry(dn)
        old_dn = obj.dn
        old_rdn = rdn_of(old_dn)
        if new_name.casefold() == obj.cn.casefold():
            raise AdToolError("新名称与当前名称相同，无需修改。")

        before = {"distinguishedName": old_dn, "cn": obj.cn,
                  "sAMAccountName": getattr(obj, "sam", "")}
        if kind == ObjectKind.OU:
            for node in self._ous:
                if node["name"] == obj.cn and node["parent"] == obj.parent:
                    node["name"] = new_name
            new_dn = f"OU={escape_dn_value(new_name)},{obj.parent}"
        else:
            obj.cn = new_name
            new_dn = obj.dn

        # 真实 AD 会自动重写子树里所有对象的 DN。演示域照做，
        # 否则改完 OU 名字子对象就"找不到爹"，树会直接空掉。
        children = self._rewrite_subtree(old_dn, new_dn)

        after = {"distinguishedName": new_dn, "cn": new_name}
        if kind == ObjectKind.COMPUTER and sync_account_name:
            obj.sam = f"{new_name}$"
            suffix = (obj.dns_host_name.split(".", 1)[1]
                      if "." in obj.dns_host_name else self.domain)
            obj.dns_host_name = f"{new_name}.{suffix}" if suffix else ""
            after.update({"sAMAccountName": obj.sam,
                          "dNSHostName": obj.dns_host_name})

        self._audit("rename", sam, old_dn,
                    detail=(f"{old_rdn} → {new_dn}"
                            + (f"（连带重写 {children} 个子对象）" if children else "")
                            + ("（已同步计算机登录名）"
                               if kind == ObjectKind.COMPUTER and sync_account_name
                               else "（登录名未改）")),
                    before=before, after=after)
        return new_dn

    def _rewrite_subtree(self, old_dn: str, new_dn: str) -> int:
        """把子树里所有对象的父 DN 换成新的。返回被改写的对象数。

        ⚠️ **DN 是「叶子在前、祖先在后」**：``CN=王五,OU=运维部,OU=研发中心,OU=总部,DC=…``
        被改名的 OU 永远在**后缀**位置。所以重写是

            前缀（对象自己的 RDN 链） + 新祖先 DN

        写成 ``new_dn + 前缀`` 就把祖先拼到了叶子前面 —— DN 直接变成
        ``OU=总部X,DC=demo,DC=localOU=研发中心,`` 这种乱码，
        于是**孙级以下整片子树从树上蒸发**（实测：把演示域的「总部」改个名，
        「运维部」连同它下面 6 个对象全部消失，看起来像"数据丢了"）。
        真域由域控自己重写、不会走到这里，所以这个缺陷只在演示模式暴露 ——
        而这恰好是新机器上唯一能看到的那条路径。
        """
        old_low = old_dn.casefold()

        def _fix(parent: str) -> str:
            if parent.casefold() == old_low:
                return new_dn
            if len(parent) <= len(old_dn):
                return parent
            tail = parent[len(parent) - len(old_dn):]
            if tail.casefold() != old_low:
                return parent
            # 前缀必须以逗号收尾（它原本是 ",old_dn" 的那一段）
            head = parent[:len(parent) - len(old_dn)]
            return f"{head}{new_dn}"

        fixed = 0
        for entry, _kind in self._all_entries():
            new_parent = _fix(entry.parent)
            if new_parent != entry.parent:
                entry.parent = new_parent
                fixed += 1
        for node in self._ous:
            new_parent = _fix(node["parent"])
            if new_parent != node["parent"]:
                node["parent"] = new_parent
                fixed += 1
        return fixed

    # ---------------- 修改属性 ----------------

    def modify_object(self, dn: str, changes: Any,
                      sam: str = "") -> ModifyResult:
        self._tick(0.8)
        items = [c for c in (changes or []) if c and (c.attribute or "").strip()]
        if not items:
            raise AdToolError("没有需要修改的属性。")

        refused, warnings = [], []
        for change in items:
            allowed, reason = is_attribute_writable(change.attribute)
            if not allowed:
                refused.append(f"{change.attribute}（{reason}）")
            elif reason:
                warnings.append(f"{change.attribute}：{reason}")
        if refused:
            raise AdToolError("以下属性不允许在这里修改：\n· "
                              + "\n· ".join(refused))

        obj, kind = self._find_entry(dn)
        names = [c.attribute.strip() for c in items]
        before = self.read_attributes(dn, names)
        for change in items:
            attr = change.attribute.strip()
            if not self._apply_core(obj, kind, attr, change.values):
                _set_override(obj, attr, change.values)
        obj.when_changed = "刚刚"

        after = self.read_attributes(dn, names)
        written, unchanged = verify_changes(items, after)
        self._audit("update", sam or getattr(obj, "sam", ""), dn,
                    detail="；".join(str(c) for c in items),
                    before=before, after=after)
        return ModifyResult(written=written, unchanged=unchanged,
                            warnings=warnings)

    @staticmethod
    def _apply_core(obj: Any, kind: str, attr: str,
                    values: list[str]) -> bool:
        """把**会影响界面其它地方**的属性真正改到对象字段上。

        为什么不能全塞进 overrides：改完 `userAccountControl` 之后，
        列表里的「已启用 / 已禁用」必须跟着变 —— 只写进属性覆盖表的话，
        属性页显示改了、列表还是老样子，演示立刻露馅。

        返回 False 表示"这不是核心字段，交给 overrides 存"。
        """
        low = attr.casefold()
        first = values[0] if values else ""

        if kind == ObjectKind.USER:
            if low == "useraccountcontrol":
                obj.uac = int(first or 0)
                return True
            if low == "pwdlastset":
                obj.pwd_last_set = int(first or 0)
                return True
            if low in ("displayname", "cn", "name"):
                obj.display_name = first
                return True
            if low == "givenname":
                obj.given_name = first
                return True
            if low == "sn":
                obj.surname = first
                return True
            # title / department 之类存在 extra 里，跟着一起更新，
            # 否则「详情面板」与「属性编辑器」会给出两套说法
            for key in list((obj.extra or {}).keys()):
                if key.casefold() == low:
                    if values:
                        obj.extra[key] = "；".join(values)
                    else:
                        obj.extra.pop(key, None)
                    return True
            return False

        if kind == ObjectKind.COMPUTER:
            if low == "useraccountcontrol":
                obj.uac = int(first or 0)
                return True
            if low == "samaccountname":
                obj.sam = first or obj.sam
                return True
            if low == "dnshostname":
                obj.dns_host_name = first
                return True
            if low == "operatingsystem":
                obj.os = first
                return True
            if low == "description":
                obj.description = first
                return True
            if low == "location":
                obj.location = first
                return True
            if low in ("cn", "name"):
                obj.cn = first or obj.cn
                return True
            return False

        if kind == ObjectKind.GROUP:
            if low == "description":
                obj.description = first
                return True
            if low == "samaccountname":
                obj.sam = first or obj.sam
                return True
            if low in ("cn", "name"):
                obj.cn = first or obj.cn
                return True
            if low == "member":
                obj.members = list(values)
                return True
            return False

        if kind == ObjectKind.CONTACT:
            if low == "description":
                obj.description = first
                return True
            if low == "displayname":
                obj.display_name = first
                return True
            if low == "mail":
                obj.mail = first
                return True
            if low == "givenname":
                obj.given_name = first
                return True
            if low == "sn":
                obj.surname = first
                return True
            if low in ("cn", "name"):
                obj.cn = first or obj.cn
                return True
            return False

        if kind == ObjectKind.OU and low == "description":
            for node in self._ous:
                if node["name"] == obj.cn and node["parent"] == obj.parent:
                    node["description"] = first
            return True
        return False

    # ---------------- 演示辅助 ----------------

    def inject_failure(self, message: str = "模拟故障：权限不足。",
                       code: str = "0x80072032") -> None:
        """让**下一次**操作失败 —— UI 用它演示错误分支。"""
        self.fail_next = AdToolError(message, code=code)

    def set_random_failure(self, rate: float, *,
                           code: str = "0x80072030",
                           message: str = "模拟故障：该账号已被移动或删除。") -> None:
        """设置随机失败率（0.0 ~ 1.0），用于演示批量的**部分失败**。

        ⚠️ 默认给的是**条目级**错误码（``0x80072030`` 对象不存在），
        不是连接级（``52`` / ``81``）。原因：随机失败的演示价值在于
        让使用者看见「50 个人里挂了 1 个，另外 49 个照常成功」。
        如果默认吐连接级错误，批量会立刻整批中止，结果面板只剩一条
        中止记录 —— 恰好演示不出最该看的那个场景。

        想演示「域控挂了 → 整批停」，显式传 ``code="52"``。
        """
        self.failure_rate = max(0.0, min(1.0, rate))
        self._failure_code = code
        self._failure_message = message


def make_mock_client(audit: AuditLog | None = None,
                     latency: float = 0.25) -> MockAdClient:
    """造一个演示客户端。``latency=0`` 可关掉人为延迟。"""
    return MockAdClient(audit=audit, latency=latency)
