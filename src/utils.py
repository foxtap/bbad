# -*- coding: utf-8 -*-
"""
utils.py —— 通用工具层（T02）

约束：
  * **纯标准库，零第三方依赖**。任何模块都可以安全 import 本模块。
  * 不包含任何 UI 代码，不包含任何网络调用。
  * 所有对外异常统一为 AdToolError，message 必须已是中文。

包含：
  - AD FILETIME 时间戳 ⇄ datetime（含哨兵值处理）
  - userAccountControl 位运算
  - DN 值转义
  - 二进制属性（objectSid / objectGUID）→ 文本
  - 底层异常 → 中文提示翻译
  - 日志脱敏与日志器
  - CSV 导出的**公式注入**防护
"""

from __future__ import annotations

import logging
import logging.handlers
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

__all__ = [
    "AdToolError",
    "AD_EPOCH",
    "NEVER_FILETIME",
    "ad_filetime_to_dt",
    "datetime_to_ad_filetime",
    "UF_SCRIPT", "UF_ACCOUNTDISABLE", "UF_HOMEDIR_REQUIRED", "UF_LOCKOUT",
    "UF_PASSWD_NOTREQD", "UF_PASSWD_CANT_CHANGE", "UF_NORMAL_ACCOUNT",
    "UF_DONT_EXPIRE_PASSWORD", "UF_SMARTCARD_REQUIRED", "UF_TRUSTED_FOR_DELEGATION",
    "UF_NOT_DELEGATED", "UF_DONT_REQUIRE_PREAUTH", "UF_PASSWORD_EXPIRED",
    "USER_UAC_DISABLED", "USER_UAC_ENABLED",
    "GROUP_SCOPE", "GROUP_SECURITY_ENABLED", "group_type_value",
    "set_uac_flag", "has_uac_flag",
    "escape_dn_value",
    "ad_generalized_time_to_dt",
    "split_dn", "rdn_of", "parent_of_dn", "dn_depth", "is_descendant_dn",
    "normalize_attr", "format_attr_value", "has_text_write_back_form",
    "sid_bytes_to_string", "guid_bytes_to_string", "BINARY_ATTRS",
    "first_value",
    "translate_error", "translate_hresult", "translate_ldap_code",
    "hresult_from_ldap_code", "LDAP_AUTH_CODES",
    "SAM_WRITE_DENIED_CODES", "sam_write_denied_hint",
    "now_iso", "redact", "redact_obj", "setup_logging", "get_logger", "breadcrumb",
    "generate_password", "check_password_guessability",
    "LOGON_HOURS_BYTES", "LOGON_HOURS_CELLS", "SECRET_ATTRS",
    "logon_hours_from_bytes",
    "logon_hours_to_bytes", "logon_hours_shift",
    "validate_workstation_names", "validate_ldap_filter",
    "CSV_FORMULA_PREFIXES", "defuse_csv_cell",
]


# ============================================================================
# 1. 统一异常
# ============================================================================

class AdToolError(Exception):
    """业务层唯一对外异常。message 必须已经是中文，可直接展示给使用者。"""

    def __init__(self, message: str, code: str | None = None):
        super().__init__(message)
        self.message = message
        self.code = code

    def __str__(self) -> str:  # pragma: no cover - 平凡实现
        return self.message


# ============================================================================
# 2. AD 时间戳 ⇄ datetime
# ============================================================================

#: AD 的 FILETIME 纪元：1601-01-01 00:00:00 UTC
AD_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

#: "永不过期"哨兵值（accountExpires / msDS-UserPasswordExpiryTimeComputed）
NEVER_FILETIME = 0x7FFFFFFFFFFFFFFF


def ad_filetime_to_dt(value: Any, tz: timezone | None = None) -> datetime | None:
    """AD FILETIME（自 1601-01-01 UTC 起的 100 纳秒数）→ 带时区的 datetime。

    返回 ``None`` 表示 **永不过期 / 无效 / 未设置**：

    ============================  ==========================================
    输入                            含义（注意各属性语义不同）
    ============================  ==========================================
    ``None`` / 不可转 int           无值
    ``<= 0``                        ``accountExpires``=0 → 永不过期
    ``0x7FFFFFFFFFFFFFFF``         永不过期
    ``> 0x7FFFFFFFFFFFFFFF``       溢出值，视为无效
    ============================  ==========================================

    注意：``pwdLastSet == 0`` 的语义是「用户下次登录必须改密码」，
    **不是**「未设置」。该语义由调用方判断，本函数只做数值转换。
    """
    if value is None:
        return None
    try:
        raw = int(value)
    except (TypeError, ValueError):
        return None

    if raw <= 0 or raw >= NEVER_FILETIME:
        return None

    dt = AD_EPOCH + timedelta(microseconds=raw // 10)
    # 默认返回 **UTC**（AD_EPOCH 本身就是 UTC-aware）。
    # 为什么不转本地：解析器应保持"UTC 语义"单一职责，显示层的本地化
    # 由界面格式化函数统一做 —— 两层各管一件事，才不会出现
    # "解析器转一次、显示层再转一次"的 8 小时双重偏移。
    return dt if tz is not None else dt


def datetime_to_ad_filetime(dt: datetime | None) -> int | None:
    """datetime → AD FILETIME 整数。导航时间（naive）按本地时区解释。

    全程整数运算，不用 ``total_seconds() * 1e7``（会引入浮点误差）。
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.astimezone()          # naive → 视为本地时间
    delta = dt.astimezone(timezone.utc) - AD_EPOCH
    return (delta.days * 86400 + delta.seconds) * 10_000_000 + delta.microseconds * 10


# ============================================================================
# 3. userAccountControl 位运算
# ============================================================================

UF_SCRIPT                          = 0x00000001
UF_ACCOUNTDISABLE                  = 0x00000002
UF_HOMEDIR_REQUIRED                = 0x00000008
UF_LOCKOUT                         = 0x00000010   # 只读计算位，写它无效
UF_PASSWD_NOTREQD                  = 0x00000020
UF_PASSWD_CANT_CHANGE              = 0x00000040
UF_ENCRYPTED_TEXT_PWD_ALLOWED      = 0x00000080
UF_TEMP_DUPLICATE_ACCOUNT          = 0x00000100
UF_NORMAL_ACCOUNT                  = 0x00000200
UF_INTERDOMAIN_TRUST_ACCOUNT       = 0x00000800
UF_WORKSTATION_TRUST_ACCOUNT       = 0x00001000
UF_SERVER_TRUST_ACCOUNT            = 0x00002000
UF_DONT_EXPIRE_PASSWORD            = 0x00010000   # 最容易被整值覆盖冲掉的位
UF_MNS_LOGON_ACCOUNT               = 0x00020000
UF_SMARTCARD_REQUIRED              = 0x00040000
UF_TRUSTED_FOR_DELEGATION          = 0x00080000
UF_NOT_DELEGATED                   = 0x00100000
UF_USE_DES_KEY_ONLY                = 0x00200000
UF_DONT_REQUIRE_PREAUTH            = 0x00400000
UF_PASSWORD_EXPIRED                = 0x00800000   # 只读计算位
UF_TRUSTED_TO_AUTH_FOR_DELEGATION  = 0x01000000

# ⚠️ 2026-09-17 删掉了 `UAC_BITS`（位 → 中文说明的字典）与 `describe_uac()`：
#    两者**零生产调用点**，而且这个注释当时写的是"用于详情面板展示" ——
#    **详情面板从来没调过它**（属性页显示的是 `format_attr_value` 那条路，
#    状态列走 `models.account_state_label`）⇒ 属于"注释承诺了一个不存在的事"。
#    按铁律「零调用点 = 死代码要删」处理；原先唯一调用它的是 `tests/test_utils.py`
#    里那条 `test_describe_uac`，已一并删除（判据与被判对象同生共死）。

#: 新建用户时使用：禁用态 = 普通账号 | 已禁用
USER_UAC_DISABLED = UF_NORMAL_ACCOUNT | UF_ACCOUNTDISABLE   # 514
#: 启用态 = 普通账号
USER_UAC_ENABLED = UF_NORMAL_ACCOUNT                        # 512

#: 组作用域位
GROUP_SCOPE: dict[str, int] = {
    "global": 0x00000002,
    "domainlocal": 0x00000004,
    "universal": 0x00000008,
}
#: 安全组标记位（写成无符号十进制；ADSI/VBS 里是负数，别抄错）
GROUP_SECURITY_ENABLED = 0x80000000


def group_type_value(scope: str, category: str = "security") -> int:
    """按作用域与类别算出 ``groupType`` 的无符号整数值。"""
    key = (scope or "").strip().lower().replace("-", "").replace("_", "")
    if key not in GROUP_SCOPE:
        raise AdToolError(f"不支持的组作用域「{scope}」，可选：全局 / 域本地 / 通用")
    value = GROUP_SCOPE[key]
    if (category or "").strip().lower() in ("security", "安全", "安全组"):
        value |= GROUP_SECURITY_ENABLED
    return value


def set_uac_flag(uac: int, flag: int, on: bool) -> int:
    """**位运算**修改 UAC 的某一位，其余位原样保留。

    这是本项目的红线函数：禁止用整值覆盖代替它。
    """
    value = int(uac) & 0xFFFFFFFF
    flag = int(flag) & 0xFFFFFFFF
    return (value | flag) if on else (value & ~flag)


def has_uac_flag(uac: int, flag: int) -> bool:
    """判断 UAC 是否含某一位。"""
    return bool((int(uac) & 0xFFFFFFFF) & (int(flag) & 0xFFFFFFFF))


def text_to_int(raw: Any) -> int | None:
    """把**已经是文本**的属性值读成整数；**空串 / 读不懂都给 `None`**。

    🔴 `None` 的含义是「**不知道**」，不是 0。调用方**不许** `or 0` 兜底 ——
    本项目已经吃过这一句的亏：`userAccountControl` 读不到时 `or 0` 让
    `UF_ACCOUNTDISABLE`(0x2) 判定为"关"，于是**每个人都被显示成"已启用"**，
    一条报错都没有（见 `models.account_state_label` 的说明）。
    另一个方向同样危险：按 0 写回会把账号其余标志位一起冲掉
    （见 `ad_client._uac_of_now`）。

    ⚠️ 为什么不去掉 `ad_client._safe_int` 只留这一份：那个函数还要处理
    `bytes` / `list`（`raw_attributes` 的形态）并把字节分支**转交**
    `int_bytes_to_int`（全项目唯一的「字节 → 整数」换算，有专门反证守着）。
    这里只管"文本"这一种形态 —— 两者是**形态不同**，不是逻辑重复；
    但"读不懂 ⇒ `None`"这条**语义是共用的**，所以两边都返回 `None`。
    """
    if raw is None or isinstance(raw, bool):
        return None
    if isinstance(raw, (bytes, bytearray)):
        # 形态判断由 `int_bytes_to_int` 独家负责，这里不许自己再猜一次。
        return None
    try:
        return int(str(raw).strip())
    except (TypeError, ValueError):
        return None


# ============================================================================
# 4. DN 转义
# ============================================================================

#: RFC 4514 需要转义的特殊字符
_DN_SPECIAL = set(',+"\\<>;=')


def escape_dn_value(value: Any) -> str:
    """转义 DN 中某个属性的**值**（如 ``CN=<这里>``）。

    ⚠️ 这不是过滤器转义。``ldap3.utils.conv.escape_filter_chars`` 是给
    search_filter 用的，两者不能互换，混用会报 ``LDAP_INVALID_DN_SYNTAX``。

    > **不造轮子说明**：ldap3 自带 ``ldap3.utils.dn.escape_rdn()``，
    > `ad_client.py` 里**直接用它**。本函数是无 ldap3 环境（离线/单测/Mock）下的
    > 兜底实现，算法与之等价，由 `tests/test_utils.py` 的对照用例保证一致。

    > **RDN 拼接惯例**：拼一个 RDN 一律**就地手写**
    > ``f"CN={escape_dn_value(name)},{parent_dn}"``（真域后端一样，只是把
    > `escape_dn_value` 换成 ldap3 的 `_escape_rdn`）。**本模块故意不提供**
    > ``escape_dn_rdn("CN", name)`` 这类糖函数：它拦不住"忘了转义"这件事
    > （该手写的照样手写），却会让 grep 的人以为"有守卫"。真正的守卫是
    > `TestRdnEscapingMatchesRealDomain` 与 `TestEveryDnRdnIsEscaped`。
    """
    s = "" if value is None else str(value)
    last = len(s) - 1
    out: list[str] = []
    for i, ch in enumerate(s):
        if ch in _DN_SPECIAL:
            out.append("\\" + ch)
        elif ch == "#" and i == 0:
            out.append("\\#")
        elif ch == " " and (i == 0 or i == last):
            out.append("\\ ")
        else:
            out.append(ch)
    return "".join(out)


def ad_generalized_time_to_dt(value: Any, tz: timezone | None = None) -> datetime | None:
    """AD 的 **generalizedTime** 字符串 → 带时区的 datetime。

    用于 ``whenCreated`` / ``whenChanged`` / ``dSCorePropagationData`` 这类属性。

    ⚠️ **这是与 ``ad_filetime_to_dt`` 完全不同的时间格式，不能混用**：

    ======================  ============================  ==================
    属性                     格式                            正确的解析函数
    ======================  ============================  ==================
    ``whenCreated``          ``20240101120000.0Z``（字符串） 本函数
    ``pwdLastSet``           ``133500000000000000``（整数）  ``ad_filetime_to_dt``
    ``accountExpires``       ``9223372036854775807``         ``ad_filetime_to_dt``
    ======================  ============================  ==================

    拿 ``ad_filetime_to_dt("20240101120000.0Z")`` 去解会得到 ``None``
    （``int()`` 抛 ValueError 被吞掉），历史时间就会**整列空白** ——
    看起来像"这个域没有该数据"，而不是像"解析器用错了"。

    **不造轮子**：优先用 ldap3 官方的
    ``ldap3.protocol.formatters.formatters.format_time``（支持时区偏移、
    小数秒，甚至闰秒），无 ldap3 时回落本实现。

    ⚠️ **那个路径是实证过的，不是凭印象写的**：这里曾经写的是
    ``ldap3.utils.conv.generalized_time_to_datetime`` —— 该函数**在 ldap3 里
    根本不存在**（2.9.1 全包搜索零命中，`conv.py` 只有 to_unicode /
    escape_filter_chars 等 12 个函数）。后果是"优先用官方实现"从来没生效过，
    每次调用都白付一次 ImportError 再落回本实现 —— 而且从结果上看不出来
    （兜底实现是对的）。现由
    `tests/test_utils.TestGeneralizedTimeUsesLdap3First` 钉住"官方确实被调用"。
    """
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    text = str(value).strip()
    if not text:
        return None
    # AD 偶尔返回带冒号的偏移（``+08:00``）——ldap3 的解析器只认 ``+0800``，
    # 先归一化，否则这条真实数据会解析成 None，whenCreated 整列空白。
    text = re.sub(r"([+-]\d{2}):(\d{2})$", r"\1\2", text)

    # 已经是 datetime 就直接归一化时区
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(tz) if tz is not None else value

    try:
        from ldap3.protocol.formatters.formatters import format_time
        parsed = format_time(text)
        # ⚠️ 官方实现**解析失败时返回原字符串**（不是 None）——所以这里的判断
        #    必须是 isinstance：写成 `if parsed is not None` 就会把字符串当成
        #    datetime 返回，调用方一个 `.year` 就 AttributeError。
        if isinstance(parsed, datetime):
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            # 与 ad_filetime_to_dt 同一套约定：默认返回 UTC，不转本地
            return parsed.astimezone(tz) if tz is not None else parsed
    except ImportError:                          # 无 ldap3（离线/单测环境）
        pass
    except Exception:                            # noqa: BLE001 - ldap3 版本差异
        pass

    # ---- 兜底实现（与 ldap3 等价）----
    # 去掉不参与计算的 ".0" 小数秒；偏移带不带冒号都要能吃
    m = re.match(r"^(\d{14})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$", text)
    if not m:
        return None
    try:
        base = datetime.strptime(m.group(1), "%Y%m%d%H%M%S")
    except ValueError:
        return None
    offset = m.group(3)
    if offset == "Z" or offset is None:
        parsed = base.replace(tzinfo=timezone.utc)
    else:
        digits = offset[1:].replace(":", "")
        sign = 1 if offset[0] == "+" else -1
        delta = timedelta(hours=int(digits[:2]), minutes=int(digits[2:4]))
        parsed = (base - sign * delta).replace(tzinfo=timezone.utc)
    return parsed.astimezone(tz) if tz is not None else parsed


# ============================================================================
# 5. DN 拆分（不依赖 ldap3，任何模块都能用）
# ============================================================================

def split_dn(dn: str) -> list[str]:
    """把 DN 拆成 RDN 列表，**按未转义的逗号**切。

    示例里用 ``O=`` 作根段 —— 生产模块有一条红线测试禁止出现**真实环境**字面量
    （见 ``tests/test_no_real_env_live.py::TestNoRealEnvInTheRealProductionModules``），
    而 RDN 拆分逻辑与属性类型无关，换成何种根段都不影响说明::

        CN=张三\\,李四,OU=研发部,O=示例  →  ['CN=张三\\,李四', 'OU=研发部', 'O=示例']
    """
    if not dn:
        return []
    parts: list[str] = []
    buf: list[str] = []
    i = 0
    while i < len(dn):
        ch = dn[i]
        if ch == "\\":
            # 反斜杠转义的是**下一个字符**，整体原样保留（含反斜杠）
            buf.append(dn[i:i + 2])
            i += 2
            continue
        if ch == ",":
            parts.append("".join(buf).strip())
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return [p for p in parts if p]


def rdn_of(dn: str) -> str:
    """取 DN 的第一段 RDN：``CN=zhangsan,OU=x,O=y`` → ``CN=zhangsan``。"""
    parts = split_dn(dn)
    return parts[0] if parts else ""


def parent_of_dn(dn: str) -> str:
    """``CN=zhangsan,OU=研发,O=示例`` → ``OU=研发,O=示例``。已经是根则返回空串。"""
    parts = split_dn(dn)
    return ",".join(parts[1:]) if len(parts) > 1 else ""


def dn_depth(dn: str) -> int:
    """DN 的层级深度（RDN 段数）。用于「深→浅」排序删除。"""
    return len(split_dn(dn))


def is_descendant_dn(child: str, ancestor: str) -> bool:
    """``child`` 是否是 ``ancestor`` 的**下级**（不含自身）。

    用 **DN 段比较**而不是字符串 ``endswith``：AD 返回的 DN 在逗号后可能带
    空格（``CN=a, OU=y``），大小写也不保证一致 —— 字符串后缀匹配要么漏判
    要么误判，而且面对带转义逗号的 RDN（``CN=a\\,b,OU=y``）会切错。
    段比较统一 strip + 小写，并且按未转义逗号切，三种情况都对。
    """
    if not child or not ancestor:
        return False
    child_parts = [p.lower() for p in split_dn(child)]
    anc_parts = [p.lower() for p in split_dn(ancestor)]
    if len(child_parts) <= len(anc_parts):
        return False
    return child_parts[-len(anc_parts):] == anc_parts


# ============================================================================
# 6. LDAP 返回值归一化
# ============================================================================

# ---------------------------------------------------------------------------
# 6.1 二进制属性 → 文本
# ---------------------------------------------------------------------------
#
# `objectSid` / `objectGUID` 在 AD 里存的是**结构化二进制**，本项目的连接是
# `Server(..., get_info=None)`（不加载 schema），而 ldap3 标准 formatter 表的键是
# **属性 OID** ⇒ 按属性名查永不命中 ⇒ **转换必须做在我们这一侧**。
#（实测见 `tools/probe_binary_attr_format.py` D 项，离线可判。）
#
# ⚠️ **更正一条以前写在这里的错误结论**（2026-09-15 真域缺陷之后）：
# 以前这里写「查不到 formatter ⇒ 拿回来就是原始 bytes」。**这条整体是错的。**
#
# 真域上 ldap3 走的是**快解码器**（`Connection(fast_decoder=True)` 是默认值，
# `ldap3/core/connection.py:207`），加上本项目 `ad_client.py:540` 的
# `check_names=False` ⇒ 响应由 `attributes_to_dict_fast` 构造
# （`ldap3/operation/search.py:573`）⇒ 值经 `to_unicode(..., from_server=True)`
# （`ldap3/utils/conv.py:35`），它在 UTF-8 失败后**依次尝试 `['latin-1','koi8-r']`**
# ⇒ **latin-1 必然成功**。所以 `attributes` 里**每一个值都是 `str`**：
#
#   * 字节全 < 0x80 ⇒ UTF-8 成功 ⇒ 一串控制字符（`'\x00\x02\x00\x00'`）；
#   * 含 ≥ 0x80    ⇒ UTF-8 失败 ⇒ latin-1 乱码（`'ª»ÌÝîÿ'`）。
#
# ⇒ 本模块 `isinstance(value, bytes)` 的判据在真域上**恒假**，不是"有时假"。
# （"UTF-8 失败就保持 bytes"那个推断来自**慢解码器**路径
#   `checked_attributes_to_dict` ⇒ `format_unicode`，本项目连接**不走那条**。）
# 正解不是在这里"猜回字节"，而是**从 ldap3 的 `raw_attributes` 取值**
# （那是无条件保留的原始 bytes）；本模块只负责"拿到 bytes 之后怎么转"。
#
# ⚠️ 两条最容易犯的错都不是"报错"，而是**静默给出一个别的值**：
#    * 字节序写反 → 得到属于**别人**的 SID/GUID；
#    * 长度不校验 → 得到**缺了几段**的 SID（形式合法）。
# 所以下面两个函数都**先校验长度**。

def sid_bytes_to_string(raw: bytes) -> str:
    """AD 的 ``objectSid``（二进制）→ ``'S-1-5-21-...'``。

    为什么要自己拼：pywin32 的 ``ConvertSidToStringSid`` 只吃 ``PySID`` 对象，
    而 ldap3 从域控拿回来的是 ``bytes`` —— **中间这一跳 Windows 没给现成入口**。
    好在 SID 的二进制结构极简、是公开格式（MS-DTYP §2.4.2.2）：
    1 字节修订号 + 1 字节子权限段数 + 6 字节**大端**标识符权限 + N × 4 字节**小端**子权限。

    ⚠️ **两个字节序不一样**（标识符权限大端、子权限小端），这是最容易写错的地方 ——
    而且写反**不会报错**，只会得到**另一个合法 SID**。

    ⚠️ 也**刻意不复用** ldap3 自带的 `format_sid`
    （`ldap3/protocol/formatters/formatters.py:369`）：它对长度**不做校验**，
    实测（`tools/probe_binary_attr_format.py` C 项）喂一段"声明 4 段、实际只有 1 段"
    的截断数据，它**不报错**，静默产出 ``'S-1-5-21-2222-0-0'`` ——
    **形式完全合法、值却是错的**。拿这种 SID 去授权 = 把权限给了一个不知道是谁的主体，
    而且整条链路上没有任何一环会报错。所以这里逐段先比长度、不合法就抛错。

    ⚠️ 反过来，也别拿它跟 `str(pysid)` 比（那个带 ``PySID:`` 前缀）——
    这正是本项目**不用** `str(pysid)` 那条路的原因。
    """
    if not raw:
        raise AdToolError("账号的安全标识符（SID）为空，无法授权。")
    if len(raw) < 8:
        raise AdToolError("安全标识符（SID）长度不合法（只有 %d 字节）。" % len(raw))

    revision = raw[0]
    count = raw[1]
    authority = int.from_bytes(raw[2:8], "big")
    if len(raw) < 8 + count * 4:
        raise AdToolError(
            "安全标识符（SID）内容不完整：声明 %d 段子权限，实际只有 %d 字节。"
            % (count, len(raw)))

    parts = ["S", str(revision), str(authority)]
    for index in range(count):
        start = 8 + index * 4
        parts.append(str(int.from_bytes(raw[start:start + 4], "little")))
    return "-".join(parts)


def guid_bytes_to_string(raw: bytes) -> str:
    """AD 的 ``objectGUID``（16 字节二进制）→ 标准 GUID 文本。

    ⚠️ **不是逐字节转 hex**：GUID 在内存里是**混合字节序** ——
    前 4 字节（Data1）、接下来 2 字节（Data2）、再 2 字节（Data3）都要**反转**，
    最后 8 字节（Data4）保持**原序**。实测（`tools/probe_binary_attr_format.py` A 项，
    用 `pythoncom.CreateGuid()` 造真值对照 6 次）：混合解释 **6/6** 命中、
    "全原序"解释 **0/6**。写错同样**不报错**，只是得到一个属于**别人**的 GUID ——
    而 GUID 正是用来在复制/脚本里唯一定位对象的，认错对象比报错危险得多。

    输出**不带花括号**（``xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx``），与 PowerShell 的
    ``ObjectGUID`` 一致、可直接粘贴进脚本；ldap3 的 `format_uuid_le` 会加一层 ``{}``，
    那是它自己的选择（而且它同样依赖 schema 才生效）。
    """
    if not raw:
        raise AdToolError("对象的全局唯一标识符（GUID）为空。")
    if len(raw) != 16:
        raise AdToolError(
            "全局唯一标识符（GUID）长度不合法（应为 16 字节，实际 %d 字节）。" % len(raw))
    return str(uuid.UUID(bytes_le=raw))


#: **只有这些**属性是「二进制存储、但展示时应该变成文本」的。判据是：
#: AD 里存的是结构化二进制，而人/其它工具认的是它的文本形式。
#:
#: ⚠️ 别顺手往里加 `logonHours`：那是**位图**，必须**保持字节**才能逐字节比对
#: （`ad_client.get_logon_hours` 走独立裸读通道，见那里的说明）；
#: 转成文本只会有害。
_BINARY_ATTR_FORMATTERS = {
    "objectsid": sid_bytes_to_string,
    "objectguid": guid_bytes_to_string,
}


def int_bytes_to_int(raw: Any) -> int:
    """AD 的 ``Integer`` / ``LargeInteger`` 二进制 → Python ``int``。

    **整数属性的「字节 → 整数」换算，全项目只有这一处**：展示层
    （`_int_bytes_to_text` ⇒ `format_attr_value`）与读写路径
    （`ad_client._safe_int`，UAC / lockoutTime / pwdLastSet 的"改动前读数"）
    都走它 —— 两处必须给出**同一个数**，否则会出现「界面显示 512、写回却按 0 算」
    这种自相矛盾（正是 2026-09-15 那次把 ``userAccountControl`` 从 512 写成 2 的成因）。

    ⚠️ "只有这一处"**限定在整数属性**：同目录的 `sid_bytes_to_string`（大端 SID）
    与 `logon_hours_from_bytes`（位图）也做字节→整数，但那是**另外三种语义**，
    各有各的唯一入口，**不许互借**（借了就是名字说谎）。

    🟥 **两种线上形态都要认**（2026-09-15 真域实测）：

    ============================  ==========================  ============================
    形态                          样本                        谁发的
    ============================  ==========================  ============================
    **ASCII 十进制文本**           ``b'512'`` / ``b'0'``       **真域 AD**（整数语法属性）
    小端无符号二进制              ``b'\\x00\\x02\\x00\\x00'``   替身 `tests/fake_ldap` 的建模
    ============================  ==========================  ============================

    **真域证据（两条互相独立，都来自审计日志，见
    ``tools/repro_int_attr_decode.py``）**：

    * 勾「密码永不过期」失败那条写着 ``before.userAccountControl = 0x323135``
      —— 而 ``int.from_bytes(b'512', 'little')`` **正好** = ``0x323135``，
      ``int.from_bytes(b'\\x00\\x02\\x00\\x00', 'little')`` 却是 ``0x200``；
    * 另一条 ``before.accountExpires = 48`` —— 而 ``int.from_bytes(b'0', 'little')``
      **正好** = ``48``（``0x30``），真值是 ``0``（永不过期哨兵）。

    ⇒ 真域的 ``raw_attributes`` 给的是 **ASCII**（``b'512'``），
    不是小端二进制。**两条独立读数同时命中 ASCII 假设、小端假设 0 命中。**

    ⚠️ 本函数**历史上只做 `from_bytes`** ⇒ 把 ASCII 的 ``b'512'`` 解成
    ``3289397``（``0x323135``）。后果不是"显示错"而是**写坏账号**：
    ``set_uac_single_flag`` 是「读→翻一位→写回」，读出来已经含
    ``UF_LOCKOUT(0x10)`` / 无定义位 ``0x4`` / 两个互斥的账户类型位，
    写回时 DC 校验这些位 ⇒ **``LDAP_UNWILLING_TO_PERFORM``（结果码 80）**。
    ⚠️ 现场「只有『永不过期』报错、右键『启用/禁用』看不出问题」—— **别把这两条当同一回事**：
    它们走**不同代码路径**（属性保存 job 走 `set_uac_single_flag`；右键走 `batch_set_enabled`），
    而本次日志里**没有** `batch_set_enabled` 的记录 ⇒ 它是否同样受影响 **未验证**。**别猜，去测。**

    ⚠️ `80` 是**整条 modify 被拒** ⇒ 按 LDAP 语义**不应留下部分写入**；
    但这一条**未在真域复核**（不碰生产域）⇒ 要下结论请自己查一次那个账号的 UAC。

    ⚠️ 判据顺序**必须先 ASCII 后 from_bytes**：ASCII 数字串一旦整体落进
    ``\\x30-\\x39`` 区间，两种解释都能成立（``b'01'`` = 文本 1 / 小端 12592）。
    真域发的是文本 ⇒ 文本优先。**两条分支都保留**，所以对端发哪一种都不会解错。

    ⚠️ 只接受字节类；拿到 `str`/`int` 由调用方自己决定怎么办 —— 本函数**不猜**。
    **非字节一律抛 `TypeError`**（不看空不空），让"来源不对"在**调用点**暴露，
    而不是在这里悄悄给一个 0（悄悄给 0 就会把账号标志位写坏）。

    ⚠️ **畸形文本一律回落到 ②，不抛异常**（`b'--5'` / `b'1_0'` 这类）：
    本函数没有"抛错"这条出口 —— 调用点（`_safe_int` 的 bytes 分支）**不兜异常**，
    抛出去就是界面层一个未预期崩溃。判据与 `int()` **等价**，见下方 ① 的注释。

    ⚠️ **空字节 `b''` 返回 `0`**（Python `from_bytes(b'')` 的语义，不是"读到了 0"）。
    要区分「属性缺失」必须靠**调用方拦 `None` / 空列表**（`_safe_int` 就是这么做的，
    它返回 `None` 而不是 0）；直接拿空字节喂进来就会得到 0，**别把它当有效读数**。
    """
    if not isinstance(raw, (bytes, bytearray, memoryview)):
        raise TypeError("整数属性应为字节形式，实际是 %s" % type(raw).__name__)
    data = bytes(raw)

    # ① 优先按 **ASCII 十进制文本**解（真域形态，见 docstring）。
    try:
        text = data.decode("ascii").strip()
    except UnicodeDecodeError:
        text = ""
    # ⚠️ 这里的判据必须与 `int()` **等价**，不许比它松（2026-09-16 T-2 复核抓到的洞）：
    #    原写法是 `text.lstrip("-").isdigit()` —— 它把 `b'--5'` 判成"是数字"，
    #    于是走到 `int("--5")` **抛 ValueError**，而这个函数**没有兜底**
    #    （`ad_client._safe_int` 的 `str` 分支有 try/except，`bytes` 分支直接
    #     `return int_bytes_to_int(value)`，**不兜**）⇒ 畸形输入会一路抛到调用点。
    #    去一个前导 `-` 正是 `int()` 的规则（认 `pwdLastSet = -1` 那个"恢复正常"哨兵），
    #    所以只剥**一个**；剥完不是全数字就**老实回落到 ②**，与本函数的
    #    「两条分支都保留，对端发哪一种都不会解错」一致。
    #    注：`data.decode("ascii")` 已保证全是 ASCII ⇒ `isdigit()` 只可能是 `0-9`
    #    （不会出现 `"²".isdigit() == True` 那种 Unicode 干扰）。
    body = text[1:] if text.startswith("-") else text
    if body.isdigit():
        return int(text)

    # ② 回落：小端无符号二进制（替身建模的形态，保留以覆盖另一条分支）。
    return int.from_bytes(data, "little", signed=False)


def _int_bytes_to_text(raw: bytes) -> str:
    """AD 的 ``Integer`` / ``LargeInteger`` 二进制 → **十进制文本**。

    AD 在 LDAP 上把整数按**小端**二进制发出来（Integer = 4 字节、
    LargeInteger = 8 字节），而 ldap3 在无 schema 时**认不出**它们
    （见 `_INTEGER_ATTRS` 的说明），`attributes` 里交回的是**解过的 `str`**
    （含控制字符或 latin-1 乱码，见本文件 §6.1 那段），于是
    `'\\x00\\x02\\x00\\x00'` 这种「控制字符串」被当成正常值一路传下去。

    换算本身复用 `int_bytes_to_int`（**只有一份实现**）；
    这里只负责把它变成屏上该看的十进制文本。

    ⚠️ **不要写成 `int(raw.decode(...))`**：那是把二进制当文本读，
    和 `_safe_int` 以前那个错同源。整数必须 `from_bytes`。
    """
    return str(int_bytes_to_int(raw))


#: AD 里以**小端二进制整数**传输的属性（`Integer` / `LargeInteger` 语法）。
#:
#: 为什么必须列出来：ldap3 的 `standard_formatter` 表把 AD 属性**按 OID 注册**
#: （`1.2.840.113556.1.4.96` 之类），而本项目的连接是 `get_info=None`（不加载
#: schema）⇒ 按**属性名**查必然落空。**但"查不到 formatter"并不意味着 bytes** ——
#: 值还会过一遍 `to_unicode(..., from_server=True)`（快解码器，
#: 见本文件 §6.1 的完整链路），它在 UTF-8 失败后**回落 latin-1**：
#:   * 字节**全是** < 0x80 的值（如 `userAccountControl = 512` → `00 02 00 00`）
#:     ⇒ 解成**合法字符串** `'\x00\x02\x00\x00'` ⇒ 屏上乱码、`int()` 炸；
#:   * 含 ≥ 0x80 的值 ⇒ UTF-8 失败但 **latin-1 成功** ⇒ 同样是乱码 `str`。
#: ⚠️ 这里曾经写「含 ≥ 0x80 ⇒ 保持 bytes ⇒ 侥幸正常」——**真域实测证伪**
#:    （那是慢解码器的行为，本项目不走）。\u21d2 不存在"侥幸正常"的属性。
#:
#: ⇒ 与 SID/GUID 同一条纪律：**认属性名，不按值的 Python 类型猜**。
#: 名单只收「AD 语法确实是整数」的属性；收错一个会让那个属性显示成大数字，
#: 所以**新增前请先确认 AD 语法**，别凭印象加。
_INTEGER_ATTRS = frozenset({
    # ---- Integer（4 字节）----
    "useraccountcontrol",
    "grouptype",
    "primarygroupid",
    "samaccounttype",
    "instancetype",
    "systemflags",
    "countrycode",
    "codepage",
    "logoncount",
    "badpwdcount",
    "admincount",
    "revision",
    "versionnumber",                    # GPO 的 versionNumber（GPC 对象上）
    "gpcfunctionalityversion",
    "msds-user-account-control-computed",
    # ---- LargeInteger（8 字节）----
    "accountexpires",
    "pwdlastset",
    "lockouttime",
    "lastlogon",
    "lastlogoff",
    "lastlogontimestamp",
    "badpasswordtime",
    "msds-userpasswordexpirytimecomputed",
    "usncreated",
    "usnchanged",
    "creationtime",
    "builtincreationtime",
    "maxpwdage",
    "minpwdage",
    "lockoutduration",
    "lockoutobservationwindow",
})

#: 二进制属性的**名字**（小写）—— 界面要拿它决定「语法」列写什么
#: （ADUC 对这种属性写「八位字节串」）。**别按值的 Python 类型猜**：
#: 值到这里已经被转成文本了，"是 `bytes` 就报八位字节串"那种分支永远不成立。
BINARY_ATTRS = frozenset(_BINARY_ATTR_FORMATTERS)


def format_attr_value(name: str, value: Any) -> str:
    """**按属性名**把 ldap3 的单个原始值转成可展示的文本。

    这是「全量读属性时二进制怎么显示」的**唯一入口**（`ad_client.read_attributes`
    走它）；`normalize_attr` 是它的回落分支 —— 后者拿不到属性名，**认不出**二进制属性。

    ⚠️ `logonHours`（登录时间**位图**）在这里**单开一条分支**，返回**可读摘要**
    （"每周 X 小时，共 N 段"）—— 详见 `_logon_hours_summary`。它**不在**
    `_BINARY_ATTR_FORMATTERS` 里：那个名单的语义是「有**权威文本形式**」
    （`objectSid` / `objectGUID`），而位图没有 —— 摘要只给**人看**，
    字节本身仍由 `ad_client.get_logon_hours` 的裸读通道负责。

    ⚠️ 认不出 / 转不出来时**不抛错、也不静默**：
      * 不是已知二进制属性 → 回落 `normalize_attr`（正常路径）；
      * 是二进制属性但值畸形 → 返回 ``<原始字节：01 05 00 ...>`` 这种**看得出是降级**
        的文本。理由：属性编辑器要能打开**任意**对象（含系统对象），
        不该因为某一个畸形值把整个面板打挂；但静默给一串裸 hex 又会被当成正常值。
        降级文本自带标记 ⇒ 两种要求都满足。
      * **是二进制/整数属性、值却是 `str`** → 返回 ``<已解码文本，非原始字节：…>``。
        这条是 2026-09-15 真域缺陷之后补的：那时读取层读的是 ldap3 的
        `attributes`（已被 ldap3 解过，且**结果一律是 `str`** —— 快解码器 +
        latin-1 兜底，见本文件 §6.1），于是 `isinstance(value, bytes)`
        **恒假**，`'\x00\x02\x00\x00'` 被原样当成正常值上屏 —— 调用方
        `int()` 直接 `ValueError`（账号属性页整体打不开）；`set_enabled`
        更糟：`_safe_int(...) or 0` 把当前 UAC 当成 0，写回时**把其它所有标志位
        冲掉**。⇒ 「静默给一个别的值」必须变成「看得出来的降级」，哪怕代价是炸。
    """
    key = (name or "").casefold()
    if key == "logonhours":
        # ⚠️ 位图**单开一条分支**，不丢给下面的通用分支：`normalize_attr` 对
        #    bytes 一律 `decode("utf-8", "replace")` ⇒ 21 字节位图变成一串
        #    **乱码**（含 ≥0x80 的是 `U+FFFD`，全 <0x80 的是控制字符）；
        #    更糟的是下游 `logon_hours_from_bytes` 拿到含 `U+FFFD` 的那串 str
        #    会编码失败、返回 `None` ⇒ 界面把「只允许 1 小时」
        #    显示成「未限制」——**方向说反了**。判据只认**属性名**。
        return _logon_hours_summary(value)
    formatter = _BINARY_ATTR_FORMATTERS.get(key)
    if formatter is None:
        if key in _INTEGER_ATTRS:
            formatter = _int_bytes_to_text
        else:
            return normalize_attr(value)
    if isinstance(value, (list, tuple)):
        # 多值：必须**逐个**走本函数再拼，不能交给 `normalize_attr` 的 list 分支 ——
        # 那一支会递归回 `normalize_attr`，多值里的二进制又被 UTF-8 解码了。
        return "; ".join(format_attr_value(name, item)
                         for item in value if item is not None)
    if not isinstance(value, (bytes, bytearray)):
        # ⚠️ 到这一步说明**来源不对**（读取层该给 bytes 却给了 str）。
        #    以前这里 `return normalize_attr(value)` —— 静默把乱码当正常值。
        return "<已解码文本，非原始字节：%s>" % _visible(value)
    data = bytes(value)
    try:
        return formatter(data)
    except AdToolError:
        # 注意：把 `AdToolError` 也降级，**不要**往上抛 —— 这条路径是"展示"，
        # 不是"授权"。真正要写权限的那条路会自己调用严格版本，让错误在
        # **写之前**就炸出来（那条路 —— 共享盘 ACL —— 已于 2026-09-16 随功能
        # 整体删除；但"展示降级 / 授权严格"这条分界本身仍然是本文件的设计）。
        return "<原始字节：%s>" % data.hex(" ")


#: 展示文本**不是**该属性的值的那些属性名（小写）。
#:
#: 🔴 这份名单与上面 `format_attr_value` 里那条**摘要分支**（`key == "logonhours"`）
#: 说的是同一件事的两种说法：那边把 21 字节位图换成**给人看的摘要**，摘要就
#: **不是**这个属性的值了。⚠️ 谁在那边加了新的摘要型分支，就得往这里加一条；
#: `tests/test_logon_hours_display.py` 有一条判据会**枚举全部可写属性**当场把
#: 不一致报出来 —— 不必靠人记得。
_NO_TEXT_WRITE_BACK = frozenset({"logonhours"})


def has_text_write_back_form(attribute: str) -> bool:
    """这个属性在**通用文本编辑器**里，有没有「能原样写回去的文本形态」。

    **有**：值列显示的文本就是该属性的值（普通文本属性），或是一个 AD 认得的
    文本形态 —— `_INTEGER_ATTRS` 的十进制、`_BINARY_ATTR_FORMATTERS` 的权威文本
    形式（`S-1-5-…` / GUID 串）。这类属性在属性编辑器里可以照着文本改。

    **没有**：值列显示的是**给人看的摘要**（`logonHours` 的"每周 X 小时，共 N 段"）
    —— 它既不是那 21 字节位图本身，也不在任何「文本 → 值」的表里。

    ⚠️ 「没有」**不等于**「不该让人改」，而是**这个属性只有一个写入口**：
        `logonHours` 的写入形态是 **21 字节位图，不是文本**；通用文本编辑器
        **没有能写回去的文本形态**，所以它在属性编辑器里不提供文本编辑，
        提示指向「登录时间」网格（`models.ATTRIBUTE_MANAGED` 里那句就是它的去处）。

    🔴 **不许**为它发明一种文本格式（十六进制串之类）来"让格子变得能写" ——
        那是自造一个 AD 与 ADUC 都不认的中间语言，比"不让改"危险得多。
    """
    return (attribute or "").strip().casefold() not in _NO_TEXT_WRITE_BACK


def _visible(value: Any) -> str:
    """把控制字符转义成看得见的形式（给降级文案用）。

    ⚠️ 不能直接 `str(value)`：`'\\x00\\x02'` 打在终端/日志里**看不见**，
    使用者会以为那里是空的 —— 而降级文案的全部意义就是"看得出来"。
    """
    return repr(value) if isinstance(value, str) else str(value)


def normalize_attr(value: Any) -> str:
    """把 ldap3 返回的属性值拍平成字符串。

    处理三种常见情况：``list``（多值）、``bytes``（二进制）、``None``。

    ⚠️ 它对 ``bytes`` 一律按 UTF-8 解码（不可解码字节变成 U+FFFD）——
    这对 `objectSid` / `objectGUID` 这类**结构化二进制**是**错的**，会得到一串
    控制字符。**知道属性名时请用 `format_attr_value(name, value)`**，
    这个函数只处理纯文本属性。
    """
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return "; ".join(normalize_attr(v) for v in value if v is not None)
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def first_value(entry: Any, attr: str, default: Any = None) -> Any:
    """从 ldap3 Entry / dict 里取单值属性。"""
    if entry is None:
        return default
    try:
        value = entry[attr] if attr in entry else default
    except TypeError:
        value = default
    if isinstance(value, (list, tuple)):
        return value[0] if value else default
    return value if value is not None else default


# ============================================================================
# 7. 异常 → 中文提示
# ============================================================================

_LDAP_HRESULT_BASE = 0x80072000

#: Win32 / SAM 类错误码 → 中文
_WIN32_MESSAGES: dict[int, str] = {
    0x80070005: "权限不足：当前绑定账号缺少对目标对象的操作权限。",
    0x8007052E: "用户名或密码错误，请检查绑定账号与密码。",
    0x8007052F: "账号受限（可能是登录时间或工作站限制）。",
    0x80070533: "该账号已被禁用，无法完成操作。",
    0x80070569: "未授予该账号在本机的登录权限。请改用 LOGON32_LOGON_NEW_CREDENTIALS(9) 模拟类型。",
    0x80070775: "该账号当前处于锁定状态，请先解锁。",
    0x800708C5: "新密码不符合域密码策略（长度、复杂度或密码历史限制）。",
    0x800708C6: "账号受限，无法设置密码。",
    0x800708C7: "当前时间不允许该账号登录。",
    0x800708C8: "该账号不允许从本机登录。",
    0x800708C9: "该账号密码已过期。",
    0x800708CA: "该账号已被禁用。",
    0x800708CB: "该账号已过期。",
}

#: LDAP 结果码 → 中文（HRESULT = 0x80072000 | 结果码）
_LDAP_CODE_MESSAGES: dict[int, str] = {
    7:  "服务器要求加密连接。请确认使用 NTLM 认证，或改用 LDAPS(636)。",
    16: "目标对象不存在该属性。",
    19: "属性值违反约束（可能是密码不合策略、名称超长或 groupType 位非法）。",
    32: "对象不存在：DN 可能已被移动或删除，请刷新 OU 树后重试。",
    34: "对象名称含非法字符。请检查姓名里的 , + \" \\ < > ; = 等符号。",
    49: "用户名或密码错误（也可能是账号被锁定）。",
    50: "权限不足：请让管理员为该账号授予对应委派权限。",
    52: "域控服务不可用，请检查网络或稍后重试。",
    53: "服务器拒绝执行。若为改密码，多半是走了明文 LDAP 写密码（必须走 RPC 或 LDAPS）。",
    64: "该名称不允许作为对象名（可能已存在同名 OU 或组）。",
    65: "对象类型不合法（例如在不允许的位置创建该类型对象）。",
    68: "同名对象已存在，请换一个名称。",
    87: "过滤器语法错误：请检查括号是否配平、运算符是否为 & | ! = 开头。",
}

#: LDAP 结果码里「**换通道也是同样的错**」的那些 —— 改密降级链禁止为它们降级。
#:
#: 进这个集合的判据**不是"错误严重"**，而是下面两条之一：
#:   ① 降级会**造成额外伤害** —— 认证失败会被 AD 累计绑定失败次数，
#:      多试一个通道就是把服务账号往锁定阈值上再推一格；
#:   ② 降级会**掩盖真实原因** —— 用户最后看到的是"所有改密通道均失败"，
#:      而不是"新密码不符合域密码策略"这种一眼能改的提示。
#:
#: 它是**唯一的一份实现**：`PasswordBackendChain._NO_FALLBACK_CODES` 直接由它
#: 换算派生（`hresult_from_ldap_code`），不是手抄一份 —— 手抄就一定会漏，
#: 而这次漏掉的正是 19（见下）。
LDAP_AUTH_CODES = frozenset({
    # 属性值违反约束 —— 改密场景就是「密码不合策略」。
    # RPC 侧同一语义的错误码是 0x800708C5，它**早已**在不降级名单里；
    # LDAPS 侧这条却一直漏着，于是同一个错在两条通道上被区别对待：
    # 走 RPC 时正确停下并提示"密码不符策略"，走 LDAPS 时却白跑一遍另一个通道，
    # 最后糊成一句"所有改密通道均失败"。
    19,
    49,   # 凭据无效（判据 ①：会累计失败绑定次数）
    50,   # 权限不足（判据 ②：换通道也一样没权限）
})

#: **工具自身的编程错误** —— 这类异常的 message 就是诊断信息，见 `translate_error` 的 3.6。
#: 都取基类，把子类一并收进来（`UnboundLocalError` 是 `NameError` 的子类等）。
_PROGRAMMING_ERRORS: tuple[type[BaseException], ...] = (
    TypeError, AttributeError, NameError, UnboundLocalError,
    KeyError, IndexError, NotImplementedError,
)

#: ldap3 异常类名 → 中文
_LDAP3_EXC_MESSAGES: dict[str, str] = {
    "LDAPSocketOpenError": "无法连接到域控，请确认 IP 与端口可达、且目标确实是域控。",
    "LDAPSocketReceiveError": "与域控的通信中断，可能是网络不稳定或连接已超时。",
    "LDAPSocketSendError": "向域控发送请求失败，请检查网络。",
    "LDAPBindError": "绑定失败：用户名或密码错误。",
    "LDAPInvalidCredentialsResult": "凭据无效。请检查账号格式（域\\用户 或 用户@域）。",
    "LDAPInsufficientAccessRightsResult": "权限不足：绑定账号没有执行该操作的委派权限。",
    "LDAPStrongerAuthRequiredResult": "服务器要求加密连接，请改用 LDAPS(636)。",
    "LDAPUnwillingToPerformResult": "服务器拒绝执行该操作。",
    "LDAPSessionTerminatedByServerError": "会话被域控终止，请重新连接。",
    "LDAPStartTLSError": "StartTLS 协商失败，当前网络可能被中间设备阻断。",
    "LDAPCertificateError": "域控证书校验失败，请确认证书有效或改用 389 端口。",
    "LDAPResponseTimeoutError": "域控响应超时。",
    "LDAPOperationResult": "LDAP 操作失败。",
}


def _extract_hresult(exc: BaseException) -> int | None:
    """从异常里提取 HRESULT。

    只有 ``pywintypes.com_error`` 或值本身带高位标志的才算 HRESULT；
    普通 ``OSError`` 的 errno（如 10061）不会被误判。
    """
    args = getattr(exc, "args", None) or ()
    if not args:
        return None
    first = args[0]
    if not isinstance(first, int):
        return None
    name = type(exc).__name__
    if "com_error" in name or (first & 0x80000000):
        return first & 0xFFFFFFFF
    return None


def translate_hresult(hr: int) -> str:
    """HRESULT → 中文提示。查不到时保留错误码供排障，但不暴露堆栈。"""
    hr &= 0xFFFFFFFF
    if hr in _WIN32_MESSAGES:
        return _WIN32_MESSAGES[hr]
    if _LDAP_HRESULT_BASE <= hr <= _LDAP_HRESULT_BASE + 0xFF:
        code = hr - _LDAP_HRESULT_BASE
        if code in _LDAP_CODE_MESSAGES:
            return _LDAP_CODE_MESSAGES[code]
    return f"操作失败（错误码 0x{hr:08X}）。请把此码提供给管理员以便定位。"


def translate_ldap_code(code: int) -> str:
    """LDAP 结果码 → 中文提示。"""
    return _LDAP_CODE_MESSAGES.get(
        int(code), f"LDAP 操作失败（结果码 {code}）。请把此码提供给管理员以便定位。"
    )


#: **改登录名（``sAMAccountName``）被拒**的判据码 —— 用于 `sam_write_denied_hint`。
#:
#: * ``50`` —— LDAP 结果码 `insufficientAccessRights`。改登录名最常撞上的就是它：
#:   `ad_client._result_error` 把 ``conn.result["result"]`` 交给 `translate_ldap_code`，
#:   拿到的就是这个**裸码**（`AdToolError.code == "50"`）。
#: * ``0x80072032`` —— 上一条的 HRESULT 形态（= `hresult_from_ldap_code(50)`）。
#:   走 LDAPS / PyWin32 的通道就是这个形状。
#: * ``0x80070005`` —— Win32 `E_ACCESSDENIED`（`_WIN32_MESSAGES` 里已有它）。
#:
#: ⚠️ 为什么不直接把 `_LDAP_CODE_MESSAGES[50]` 改掉：那句话（"请让管理员为该账号
#: 授予对应委派权限"）服务于**所有**写入被拒的场景，它说不出"该找谁"；而改登录名
#: 是**唯一**有确定答案的一处（账户操作员 / 域管理员）。所以另立一条专用文案，
#: 由调用方在"这次改动里含 sAMAccountName"时才用它。
SAM_WRITE_DENIED_CODES = frozenset({50, 0x80072032, 0x80070005})


def sam_write_denied_hint(code: Any) -> str:
    """改 ``sAMAccountName`` 被权限拒绝时的**专用**文案；不是权限码则返回空串。

    ``code`` 收的是 ``AdToolError.code`` 的形态：裸 LDAP 结果码（``"50"``）、
    HRESULT 串（``"0x80072032"``），也可能是 int —— 三种都认。

    为什么要单独一条：`_LDAP_CODE_MESSAGES[50]` 的通用文案只说到"授予委派权限"，
    使用者拿着它还是不知道该申请什么角色；`insufficientAccessRights` 在改登录名
    这个场景上有确定的答案。
    """
    value: Any = code
    if isinstance(value, str):
        try:
            value = int(value.strip(), 0)      # 同时认 "50" 与 "0x80072032"
        except ValueError:
            return ""
    if not isinstance(value, int) or value not in SAM_WRITE_DENIED_CODES:
        return ""
    return ("改登录名（sAMAccountName）需要「账户操作员」或「域管理员」权限，"
            "或由管理员在它所在的组织单位上委派「写 sAMAccountName」")


def hresult_from_ldap_code(code: int) -> str:
    """LDAP 结果码 → 与 pywin32 **同口径**的 HRESULT 字符串（49 → ``0x80072031``）。

    为什么需要它：`PasswordBackendChain` 用 ``AdToolError.code`` 判断
    「认证/策略类错误不降级」——而 RPC 通道走 `translate_error`，码已经是
    ``0x%08X``；LDAPS 通道拿到的是裸 LDAP 结果码。后者不换算就直接抛，
    那条纪律对 LDAPS 就**形同虚设**：密码错、账号被锁会被当成通道故障，
    白跑一遍另一个通道（AD 会累计失败绑定次数，多试几次把服务账号自己锁掉）。
    """
    return f"0x{(_LDAP_HRESULT_BASE + int(code)) & 0xFFFFFFFF:08X}"


def translate_error(exc: BaseException, context: str = "") -> AdToolError:
    """**唯一**的底层异常出口。任何 ldap3 / pywin32 异常都必须经过这里。

    :param exc:     原始异常
    :param context: 可选的动作说明，如「重置密码」，会拼进提示里
    :return: 中文 ``AdToolError``
    """
    if isinstance(exc, AdToolError):
        return exc

    prefix = f"{context}失败：" if context else ""
    name = type(exc).__name__

    # 1) ldap3 异常（按类名逐级向上查）
    for klass in type(exc).__mro__:
        msg = _LDAP3_EXC_MESSAGES.get(klass.__name__)
        if msg:
            return AdToolError(prefix + msg, code=klass.__name__)

    # 2) HRESULT
    hr = _extract_hresult(exc)
    if hr is not None:
        return AdToolError(prefix + translate_hresult(hr), code=f"0x{hr:08X}")

    # 3) 网络类标准异常
    if isinstance(exc, TimeoutError):
        return AdToolError(prefix + "连接超时，域控可能不可达或响应缓慢。", code="timeout")
    if isinstance(exc, ConnectionError):
        return AdToolError(prefix + "网络连接失败，请检查 IP、端口与防火墙。", code="network")
    if isinstance(exc, PermissionError):
        return AdToolError(prefix + "权限不足，无法访问该资源。", code="permission")
    if isinstance(exc, UnicodeDecodeError):
        return AdToolError(prefix + "返回内容编码异常，可能是域控语言环境不匹配。", code="encoding")

    # 3.5) NTLM 算不出 MD4 —— 环境缺 pycryptodome
    #
    # ldap3 算 NTLMv2 响应必须有 MD4，它先找 `Crypto.Hash.MD4`（pycryptodome），
    # 找不到就回落 `hashlib.new('MD4')`；而 **Python 3.13 / OpenSSL 3 已把 MD4
    # 移出内置库**（legacy provider），于是回落那步抛
    # `ValueError: unsupported hash type MD4`。
    #
    # 它发生在**绑定过程中**，会被下面的兜底分支糊成「发生未预期的错误（ValueError）」——
    # 使用者完全无从下手。而这个缺陷**所有测试都抓不到**（测试用的是 fake ldap3，
    # 从不真算 NTLM）。真域实测（2026-09-12）：装上 pycryptodome 后同一段代码
    # 立刻走到正确的「用户名或密码错误」，说明 NTLM 通路本来就是通的。
    # 判据取 exc 的**消息**：ValueError 太通用，不能按类型拦。
    if isinstance(exc, ValueError) and "MD4" in str(exc):
        return AdToolError(
            prefix + "NTLM 认证需要 MD4 算法，但当前 Python 环境没有可用实现"
            "（Python 3.13 / OpenSSL 3 已把它移出内置库）。\n"
            "请执行：pip install pycryptodome，然后重启本工具。",
            code="ntlm-no-md4")

    # 3.6) 工具**自己的编程错误** —— 把异常原文带上
    #
    # 这一段是 2026-09-12 真域联调现场补的。当时 `ui_main._connect` 漏传 `cfg`，
    # 使用者看到的全部信息只有：
    #     「连接域控#1失败：发生未预期的错误（TypeError）。请查看日志获取详情。」
    # 而真正有用的那句 `missing 1 required positional argument: 'cfg'` 只躺在
    # 日志里 —— 于是排查绕了一大圈。
    #
    # 判据：这几个异常的 **message 本身就是诊断信息**，而且
    #   * 不含任何敏感内容（类型错误的文案里只有参数名 / 类型名）；
    #   * 不是"域控返回了什么"，而是"我们代码写错了" —— 藏起来没有任何收益，
    #     只会让使用者多跳一次日志（甚至以为是自己填错了）。
    # 其余异常（OSError / 第三方库的怪消息）仍旧走下面的兜底，只给指针。
    if isinstance(exc, _PROGRAMMING_ERRORS):
        detail = " ".join(str(exc).split())
        if len(detail) > 200:
            detail = detail[:200] + "…"
        hint = "这是工具自身的缺陷，请把这句话连同日志一起反馈。"
        return AdToolError(
            prefix + f"发生编程错误（{name}）：{detail}\n{hint}",
            code=name)

    # 4) 兜底：保留异常类型名，方便排障，但不给使用者看堆栈
    return AdToolError(prefix + f"发生未预期的错误（{name}）。请查看日志获取详情。", code=name)


# ============================================================================
# 8. 时间与脱敏
# ============================================================================

def now_iso() -> str:
    """当前时间，ISO8601 **带时区偏移**（审计日志用）。"""
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


_MASK = "******"
#: 形态匹配：``password='xxx'`` / ``密码：xxx`` / ``初始密码 Abc123`` 这类夹在
#: 长文本里的口令。两个分支的宽严不同，原因很具体：
#:
#: * **英文关键词**必须跟分隔符（``=`` / ``:``）。放开的话
#:   ``password must be at least 8 characters`` 会把 ``must`` 打成掩码，
#:   原本可读的日志变成一句废话。
#: * **中文关键词**可以省分隔符（中文文案常写成「初始密码 Abc123 不满足策略」），
#:   但口令 token 里必须**至少含一个 ASCII 字母或数字** —— 否则
#:   「密码已重置」「口令已清除」这种正常文案会被整段吃掉。
_PWD_PATTERN = re.compile(
    r"(password|pwd|passwd)\s*[=:：]\s*('[^']*'|\"[^\"]*\"|\S+)"
    r"|(密码|口令)\s*[=:：]?\s*"
    r"((?=[^\s，。；、）】]*[0-9A-Za-z])[^\s，。；、）】]{3,})",
    re.IGNORECASE,
)

#: 属性名命中即**整值打码**，不管值长什么样。
#:
#: 这类属性的值天然就是口令 / 密钥材料，按名字判比按内容猜可靠得多 ——
#: ``unicodePwd`` 的值是 UTF-16 编码的二进制密文，正则永远认不出来它是什么。
SECRET_ATTRS = frozenset({
    "unicodepwd", "userpassword", "unixuserpassword", "dbcspwd",
    "supplementalcredentials", "nthash", "lmhash", "ms-mcs-admpwd",
    "msds-managedpassword",          # gMSA 的托管口令
})


def redact(text: Any, *secrets: str | None) -> str:
    """日志脱敏（**字符串版**）：抹掉已知口令字面量，以及 ``[密码|password]=xxx`` 形态。

    只适合 ``detail`` 这类纯文本。属性字典请用 :func:`redact_obj`。
    """
    return _mask_text("" if text is None else str(text), secrets)


def redact_obj(value: Any, *secrets: str | None) -> Any:
    """结构化脱敏：递归处理 dict / list / tuple / str（审计的 before / after 用）。

    为什么必须单独有一个：``before`` / ``after`` 是**属性字典**，口令可能以
    「某个属性的值」的形式出现（属性编辑器写了 ``unicodePwd``、有人在
    ``description`` 里粘了密码）。只对 ``detail`` 脱敏等于把口令原样落盘。

    三层防护，从强到弱：

    1. **按属性名** —— 键命中 :data:`SECRET_ATTRS` 时整值打码，值长什么样都不看；
    2. **按已知口令** —— 调用方传进来的 ``secrets`` 字面量全量替换；
    3. **按形态** —— 夹在长文本里的 ``密码=xxx``。

    字典的**键不参与脱敏**：键是 AD 属性名（schema 固定），不夹带用户数据，
    改键反而会破坏审计记录的可读性与可检索性。
    """
    return _redact_obj(value, tuple(s for s in secrets if s))


def _mask_text(s: str, secrets: Iterable[str | None]) -> str:
    for secret in secrets:
        if secret and isinstance(secret, str):
            s = s.replace(secret, _MASK)
    return _PWD_PATTERN.sub(_mask_match, s)


def _mask_match(match: re.Match) -> str:
    """正则替换体：中文分支的关键词在第 3 组，英文分支在第 1 组。"""
    keyword = match.group(1) or match.group(3) or ""
    return f"{keyword}={_MASK}"


def _mask_all(value: Any) -> Any:
    """整个值打成掩码，但保留容器的**形状**（审计记录照样看得懂结构）。"""
    if isinstance(value, dict):
        return {k: _MASK for k in value}
    if isinstance(value, (list, tuple)):
        return [_MASK for _ in value]
    return _MASK


def _redact_obj(value: Any, secrets: tuple[str, ...]) -> Any:
    if isinstance(value, str):
        return _mask_text(value, secrets)
    if isinstance(value, dict):
        result: dict[Any, Any] = {}
        for key, item in value.items():
            if isinstance(key, str) and key.strip().casefold() in SECRET_ATTRS:
                result[key] = _mask_all(item)
            else:
                result[key] = _redact_obj(item, secrets)
        return result
    if isinstance(value, (list, tuple)):
        return [_redact_obj(item, secrets) for item in value]
    return value          # 数字 / 布尔 / None 原样：它们不可能是口令


# ============================================================================
# 9. 日志
# ============================================================================

_LOG_FORMAT = "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"
_configured = False


class _RedactFilter(logging.Filter):
    """给**落盘的日志**兜一层脱敏。

    ``app.log`` 与审计日志一样是磁盘文件、一样会被拿去排障、一样可能被别人
    看到。而 ``_log.warning("改密通道自动降级：%s", reason)`` 这类写法会把上游
    异常文案（「密码 Abc123 不满足策略」）原样写进去 —— 审计脱敏了、日志没脱敏，
    等于把门锁上却开着窗。

    只做形态匹配（拿不到本次操作的口令明文），所以是**兜底**不是保证：
    真正的保证仍然靠调用方把 ``secrets`` 传给 ``audit.write()``。
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            return True                 # 参数不匹配等异常交给 logging 自己报
        cleaned = redact(message)
        if cleaned != message:
            record.msg = cleaned
            record.args = ()
        return True


_redact_filter = _RedactFilter()


def setup_logging(log_dir: str, level: int = logging.INFO, filename: str = "app.log") -> str:
    """配置滚动文件日志（5MB × 5）。返回日志文件路径。

    打包成 ``--windowed`` 的 exe 后没有控制台，所有诊断信息**必须**走这里。
    写入前会过一遍脱敏过滤器（见 :class:`_RedactFilter`）。
    """
    global _configured
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, filename)

    root = logging.getLogger()
    root.setLevel(level)
    if not _configured:
        handler = logging.handlers.RotatingFileHandler(
            log_path, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        handler.setFormatter(logging.Formatter(_LOG_FORMAT))
        handler.addFilter(_redact_filter)
        root.addHandler(handler)
        _configured = True
    return log_path


def bootstrap_logging() -> str:
    """**进程入口的第一件事**：把日志落进 ``app.log``；失败也绝不抛（返回空串）。

    为什么需要它（而不是各处自己 ``setup_logging(logs_dir())``）：
    ``main.py``（GUI）与 ``tools/`` 下的排障脚本是**两条入口**，而它们必须写进
    **同一个** ``app.log``。曾经只有 ``main.py`` 初始化日志，排障脚本没有 ——
    后果不是"少了几行"，而是排障脚本自己产出的日志**一行都不落盘**（只剩
    WARNING 以上被 logging 的 lastResort 打到 stderr），而脚本回头读 ``app.log``
    时读到的是**上一次 GUI 运行留下的旧日志**：排障的人看到"这次什么都没记"，
    更糟的是 ``verify_connect_wiring_live.py`` 会拿**旧日志里的 TypeError**
    当成本次的判决依据（判据读到陈旧数据 —— 比没有判据更坏）。

    ⚠️ 函数体内才 import ``config`` 是必须的，不是风格：``config.py`` 顶部就
    ``from utils import ...``，在模块级 import 会成环。

    ⚠️ **必须在任何连接尝试之前调用**。放到"要读日志了"那一步才调用等于没调：
    那时连接日志早丢光了，而且会让人误以为读到的是本次运行的日志。
    `tests/test_tools_logging.py` 钉住了这个**时机**：它必须是 ``main()`` 的
    第一条可执行语句。

    ⚠️ **刻意不带 ``level`` 参数**：没有任何调用方需要非默认级别。多这一个参数反而
    有害 —— 测试替身若写成 ``lambda d: ...``（匹配 ``setup_logging(log_dir)`` 的
    真实签名），多传的 ``level=`` 会抛 ``TypeError``，再被下面的 ``except`` 吞成
    "返回空串"：**报出来的现象是"日志没起来"，真因却是参数装配错**（本项目踩过
    一模一样的坑）。签名越窄，替身越不可能说谎。
    """
    try:
        from config import logs_dir

        return setup_logging(logs_dir())
    except Exception:                                # noqa: BLE001
        # 日志起不来也必须能继续（否则双击没反应 = 更难排查）。
        return ""


def read_log_tail(log_path: str, *, lines: int = 30,
                  needle: str | None = None) -> list[str]:
    """读某个日志文件的尾部若干行（排障用）。**只负责读**，不初始化日志。

    参数是**完整文件路径**（也就是 :func:`setup_logging` 的返回值）而不是目录：
    「日志文件名是 ``app.log``」这件事只该由 ``setup_logging`` 的默认参数决定，
    别处再 join 一次就多了一份会漂的实现（踩过：手写路径漏了 ``logs\\`` 子目录，
    于是永远打印"文件不存在"，而文件就在旁边）。

    读法的唯一实现：先按 ``needle`` 过滤（``None`` 表示不过滤），再取**最后**
    ``lines`` 行。两种用法因此共用一份 —— 取末尾若干行，或捞含某个错字的行。

    ⚠️ **"过滤后取尾"而不是"取尾后过滤"**：后者会让目标行落在尾部窗口之外时
    整个漏掉（真发生过的形状：错误在第 10 行、窗口是最后 6 行 ⇒ 判据说没找到）。

    ⚠️ 调用者必须在进程**入口**先调 :func:`bootstrap_logging`，否则读到的可能是
    上一次运行留下的旧日志（见 bootstrap_logging 的说明）。
    """
    if not log_path or not os.path.exists(log_path):
        return []
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
            all_lines = fh.readlines()
    except OSError:
        return []
    if needle is not None:
        all_lines = [ln for ln in all_lines if needle in ln]
    return [ln.rstrip() for ln in all_lines[-lines:]]


def get_logger(name: str = "ad_tool") -> logging.Logger:
    """取日志器。未调用 ``setup_logging`` 时也能安全使用（无 handler 时不报错）。"""
    return logging.getLogger(name)


def breadcrumb(action: str) -> None:
    """记一条**界面动作面包屑**（排障用）。

    为什么需要它：解释器级崩溃（`faulthandler` 写进 ``crash.log``）只留各线程堆栈，
    而崩溃瞬间的堆栈**常常全是正常代码** —— 实测过一次 ``0x8001010d``，
    主线程停在 ``app.exec()``、工作线程停在 ``queue.get``，看不出用户当时在干什么，
    最后只能靠翻审计日志猜。

    面包屑补的就是这一环：``app.log`` 里**最后一条 ``[UI]`` 行**就是现场。
    只记会碰 Windows 原生 COM/OLE 的动作（原生文件对话框、剪贴板），
    不记普通点击 —— 记多了等于没记。
    """
    get_logger("ui").info("[UI] %s", action)


# ============================================================================
# 10. 绑定账号（"现在是谁在操作"）
# ============================================================================

def bind_account_name(bind_user: str) -> str:
    """从三种账号写法里取出**账号名**部分，取不出来就返回空串（**不抛异常**）。

    ====================  ==================
    ``DEMO\\zhangsan``     ``zhangsan``
    ``zhangsan@corp``      ``zhangsan``
    ``zhangsan``           ``zhangsan``
    ====================  ==================

    与 `password_backend.parse_bind_user` 的区别就一条：**那个会抛**，
    因为它要拿解析结果去认证，解析不出来就不能继续。这里只用于界面提示
    （例如「你选中的对象里有你自己」），提示不出来**绝不该把操作挡掉** ——
    所以容错、返回空串。

    ⚠️ 但「容错」不等于「瞎猜」：`zhangsan@` / `域\\` 这种**半截写法**
    两侧缺一，就不知道该按哪一段认账号 —— 返回空串，宁可不提示，
    也不要拿一个猜出来的名字去说「你在禁用你自己」。
    """
    value = (bind_user or "").strip()
    if not value:
        return ""
    if "\\" in value:
        dom, _, user = value.partition("\\")
        return user.strip() if dom.strip() and user.strip() else ""
    if "@" in value:
        user, _, dom = value.partition("@")
        return user.strip() if user.strip() and dom.strip() else ""
    return value


# ============================================================================
# 11. 登录时间位图与工作站限制（F13 / F14）
# ============================================================================

#: ``logonHours`` 恒为 21 字节 = 168 位，从**周日 00:00（UTC）**起每小时一位。
#: 位序是 **LSB 在前**：第 0 字节的 bit0 = 周日 00:00~00:59。
LOGON_HOURS_BYTES = 21
LOGON_HOURS_CELLS = 168

#: 工作站名里 AD 不允许出现的字符（与计算机名同一套非法字符）
_WORKSTATION_ILLEGAL = set('\\/[]:;|=,+*?<>" ')


def logon_hours_from_bytes(raw: Any) -> list[bool] | None:
    """AD 原始值 → 168 格布尔表（**UTC 序**，索引 0 = 周日 00:00 UTC）。

    返回 ``None`` 表示属性不存在 = 未做限制（等价全允许）。
    长度不对的值按 ``None`` 处理 —— 老域/迁移域可能出现截断数据，
    此时**网格**宁可显示"未限制"也不画一张**错位**的时间表。

    ⚠️ 但那个 ``None`` **只对「网格」那条链有效**（`ui_panels.fill_logon_hours`，
    它拿的是 `ad_client.get_logon_hours` 的裸读字节）。**展示层不许照抄**：
    `_logon_hours_summary` 对"长度不对"必须**显式降级** —— 把「读不懂」
    说成「未限制」在那边是**说反了**（「一小时都不允许」会显示成「全时允许」）。
    两条链要的东西不同，别为了"口径统一"把其中一条改坏。
    """
    if raw is None:
        return None
    if isinstance(raw, str):
        try:
            raw = raw.encode("latin-1")
        except UnicodeEncodeError:
            return None
    if not isinstance(raw, (bytes, bytearray)):
        return None
    data = bytes(raw)
    if len(data) != LOGON_HOURS_BYTES:
        return None
    cells: list[bool] = []
    for byte in data:
        for bit in range(8):
            cells.append(bool(byte & (1 << bit)))
    return cells


def _logon_hours_segments(cells: list[bool]) -> int:
    """168 格布尔表 → **连续段数**（跨周界的那一段算**一段**）。

    ⚠️ 必须**环形**数：一周是个环，周六 23:00 与周日 00:00 在 ADUC 的
    网格上就是相邻的两格。按线性数会把「周六晚到周日早」这一段
    拆成两段 —— 而"共 N 段"这种数字只有对得上网格才有意义。
    """
    total = sum(cells)
    if total == 0:
        return 0
    if total == len(cells):
        return 1
    # `cells[index - 1]`：index == 0 时取到 cells[-1]（周六末），正好是周界前驱。
    return sum(1 for index, on in enumerate(cells) if on and not cells[index - 1])


def _logon_hours_summary(value: Any) -> str:
    """``logonHours`` 位图 → **人看得懂的摘要**（**只给展示层**用）。

    🟥 为什么位图不能走 `format_attr_value` 的通用分支（2026-09-16 缺陷 D-20）：

    * 通用分支把它交给 `normalize_attr`，后者对 ``bytes`` 一律
      ``decode("utf-8", "replace")`` ⇒ 属性编辑器里那一行是**乱码**，
      而且两种位图烂得**不一样**（两种都骗得过眼睛）：
        · 含 ≥0x80 的字节（如"只开了一格"的那张）⇒ 一串 **`U+FFFD`**；
        · 字节全 <0x80（如全 `0x00`）⇒ 解码"成功"，是一串**控制字符**，
          在表格里看着像"这一行没有值"。
    * 更糟的是**其中一种还会让下游撒谎**：`logon_hours_from_bytes` 拿到
      含 `U+FFFD` 的那串 ``str``（U+FFFD 不在 latin-1 里）会编码失败、
      返回 ``None``，而 ``None`` 的含义是**「未限制」** ⇒
      「只允许 1 小时」被显示成「未限制」（= 全时允许）——
      这个错误**方向相反**，比乱码危险得多。
      ⚠️ 全 `0x00` 那张**不走**这条：它编得回 latin-1、会被解成
      "一小时都不允许"，方向是对的。**这两种乱码不是一回事，别混。**
      （三种形态都实测过：`tools/counterproof_logon_hours.py` 的 C178 反证
      就是"拿掉这条分支"，届时整套判据精确变红。）

    ⚠️ 判据只有一条：**按属性名**（`format_attr_value` 的
    ``key == "logonhours"`` 分支）。**不按值的 Python 类型猜** ——
    读取层给的是 bytes 还是 str 恰恰取决于**上游有没有做对**
    （真域上 ldap3 会把同一个属性交给 `attributes` 变成 str、
    交给 `raw_attributes` 才是 bytes，见 `ad_client.read_attributes`），
    按类型猜等于把上游的错当成自己的输入。

    ⚠️ **这不是**「有权威文本形式的二进制属性」那种转换（那类才进
    `_BINARY_ATTR_FORMATTERS`）：摘要只给人看，字节本身仍由
    `ad_client.get_logon_hours` 的**裸读通道**负责（逐字节比对靠它）。
    """
    if value is None:
        # AD 里「属性不存在」就是「未限制」（等价全时允许）——
        # 这一条**不是降级**，是属性的真实含义。
        return "未限制"
    if isinstance(value, (list, tuple)):
        return "; ".join(_logon_hours_summary(item) for item in value
                         if item is not None)
    if isinstance(value, str):
        # 来源不对（该给 bytes 却给了 str）。**绝不能**当位图解析：
        # 能 latin-1 编码的会被解出一张**错位**的时间表，
        # 不能编码的（含 U+FFFD）会回落 `None` = 「未限制」—— 两种都是撒谎。
        return "<已解码文本，非原始字节：%s>" % _visible(value)
    if isinstance(value, (bytes, bytearray)):
        data = bytes(value)
        cells = logon_hours_from_bytes(data)
        if cells is None:
            # 长度不对（老域 / 迁移域可能截断）。**不许**回落「未限制」——
            # 那等于把「读不懂」说成「没有限制」。
            return ("<登录时间位图不合法（%d 字节，应为 %d）：%s>"
                    % (len(data), LOGON_HOURS_BYTES, data.hex(" ")))
        hours = sum(cells)
        if hours == 0:
            return "不允许任何时间登录（每周 0 小时）"
        if hours == LOGON_HOURS_CELLS:
            return "全周允许（每周 168 小时）"
        return "每周 %d 小时，共 %d 段" % (hours, _logon_hours_segments(cells))
    return "<无法识别的登录时间值：%s>" % _visible(value)


def logon_hours_to_bytes(cells: list[bool]) -> bytes:
    """168 格布尔表 → 21 字节位图。输入长度不对直接抛错（别悄悄截断）。"""
    if len(cells) != LOGON_HOURS_CELLS:
        raise AdToolError(
            f"登录时间表必须是 {LOGON_HOURS_CELLS} 格（当前 {len(cells)} 格）。")
    out = bytearray(LOGON_HOURS_BYTES)
    for index, on in enumerate(cells):
        if on:
            out[index // 8] |= 1 << (index % 8)
    return bytes(out)


def logon_hours_shift(cells: list[bool], offset_minutes: int) -> list[bool]:
    """把 UTC 序的 168 格表平移时区偏移（本地 ⇄ UTC 的唯一换算点）。

    ``offset_minutes`` 是**本地相对 UTC 的偏移**（东八区 = +480）。
    平移量按小时取整 —— 位图本身就是小时粒度，半小时时区（如 +5:30）
    只能近似，ADUC 同样如此。

    往返一致：``shift(shift(x, +m), -m) == x``，由单测锁定。
    """
    if len(cells) != LOGON_HOURS_CELLS:
        raise AdToolError(
            f"登录时间表必须是 {LOGON_HOURS_CELLS} 格（当前 {len(cells)} 格）。")
    hours = int(round(offset_minutes / 60))
    if hours == 0:
        return list(cells)
    # ⚠️ 直接用 Python 的负数取模（结果非负）—— 环形缓冲长度是 168，
    # 把 -8h 归一化成 +16h（% 24）是错的：24 整除 168 但偏移量语义不同。
    return [cells[(i + hours) % LOGON_HOURS_CELLS]
            for i in range(LOGON_HOURS_CELLS)]


def validate_workstation_names(text: str) -> tuple[list[str], str]:
    """「登录到」工作站名单本地校验。返回 ``(去重后的名单, 中文错误原因)``。

    ``text`` 是逗号 / 换行分隔的计算机名。空名单 = 不限制（允许所有工作站）。
    校验三条：非法字符、单个名字超长（NetBIOS 15）、条数超上限（AD 63）。
    """
    raw = (text or "").replace("\n", ",").replace("；", ",")
    names: list[str] = []
    for piece in raw.split(","):
        name = piece.strip()
        if not name:
            continue
        bad = _WORKSTATION_ILLEGAL & set(name)
        if bad:
            return [], (f"计算机名「{name}」含非法字符 "
                        f"{'、'.join(sorted(bad))}（逗号用于分隔多个名字）。")
        if len(name) > 15:
            return [], (f"计算机名「{name}」超过 15 个字符 —— "
                        "「登录到」用 NetBIOS 名，上限 15。")
        if name.lower() not in [n.lower() for n in names]:
            names.append(name)
    if len(names) > 63:
        return [], f"工作站名单最多 63 台（当前 {len(names)} 台）—— 这是 AD 的硬限制。"
    return names, ""


def validate_ldap_filter(text: str) -> str:
    """本地校验自定义 LDAP 过滤器（F12）。返回中文错误原因，空串 = 通过。

    只做**本地能确定**的三件事：非空、首尾是括号、括号配平。
    值语法是否合法只有域控知道 —— 交给它报，报错会翻译成中文。
    """
    f = (text or "").strip()
    if not f:
        return "请输入 LDAP 过滤器。"
    if not f.startswith("("):
        return "过滤器必须以 ( 开头，如 (objectClass=user)。"
    if not f.endswith(")"):
        return "括号不配平：缺少结尾的右括号。"
    depth = 0
    for ch in f:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                return "括号不配平：出现了多余的右括号。"
    if depth != 0:
        return f"括号不配平：还差 {depth} 个右括号。"
    inner = f[1:-1].strip()
    if inner.startswith("("):
        # "((a=b))" 这类裸嵌套：LDAP 语法里括号后必须跟 & | ! 或属性名
        return "过滤器语法错误：括号后必须跟 & / | / ! 或属性名，不能是又一个裸括号。"
    return ""


# ============================================================================
# 12. 密码生成与本地合规预检
# ============================================================================

#: 生成密码用的字符集。**故意去掉易混字符** `0/O/o` 与 `1/l/I` ——
#: 这些在**几乎所有无衬线字体**里都分不清（本工具界面用的就是无衬线）。
#: 这东西是要念给同事听、或抄在纸上的，`1980O0l1` 这种组合纯属害人。
#:
#: ⚠️ `5/S`、`2/Z` **刻意保留**：它们只在手写体/某些字体里像，
#: 再加两个类别只会白白损失熵。以前这里的注释把它们也写成"已去掉"，
#: 与代码不符（实现只去了 `0Oo`/`1lI`）—— 已按实现改正，并由
#: `tests/test_utils.py::TestGeneratePassword` 钉住。
_PWD_LOWER = "abcdefghijkmnpqrstuvwxyz"
_PWD_UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"
_PWD_DIGIT = "23456789"
_PWD_SYMBOL = "!@#$%^&*+-="


def generate_password(length: int = 14) -> str:
    """生成一个大概率能通过域密码策略的随机密码。

    保证包含大写 / 小写 / 数字 / 符号各至少一个 —— AD 默认要求
    「4 类里满足 3 类」，四类齐全就稳了，不用使用者试三次。
    """
    import secrets

    length = max(8, int(length))
    pools = [_PWD_LOWER, _PWD_UPPER, _PWD_DIGIT, _PWD_SYMBOL]

    # 先各取一个保证类别齐全，再补齐长度，最后打乱
    chars = [secrets.choice(pool) for pool in pools]
    everything = "".join(pools)
    chars.extend(secrets.choice(everything) for _ in range(length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def check_password_guessability(password: str, *related: str) -> str:
    """本地预检「这密码是不是一看就会被域拒」，返回中文原因（空串=看起来没问题）。

    ⚠️ 这**不是**密码策略校验器。真正的策略（长度、历史、复杂度、
    细粒度 PSO）只有域控知道 —— 写一个客户端版策略引擎既做不到又误导人。
    这里只拦最容易命中的三条：太短、类别太少、包含账号名。

    目的是**减少无谓往返**：批量重置 50 个人，如果密码一看就不合规，
    应该在本地就报出来，而不是让域控拒 50 次。
    """
    value = password or ""
    if len(value) < 8:
        return "密码长度不足 8 位（AD 默认策略要求至少 7~8 位）。"

    classes = sum([
        any(c.islower() for c in value),
        any(c.isupper() for c in value),
        any(c.isdigit() for c in value),
        any(not c.isalnum() for c in value),
    ])
    if classes < 3:
        return "密码包含的字符类别太少（AD 默认要求大写/小写/数字/符号里至少 3 类）。"

    lowered = value.lower()
    for item in related:
        item = (item or "").strip().lower()
        # 短片段（如 2 个字的姓名）拿来比会误伤，只在 4 字符以上才判定
        if len(item) >= 4 and item in lowered:
            return f"密码里包含账号或姓名「{item}」，AD 默认策略不允许。"

    return ""


# ============================================================================
# CSV 导出的公式注入防护
# ============================================================================
#
# 为什么单独一节：这是本项目**唯一**一处「我们写出去的文件会被别人的程序执行」
# 的地方。审计日志与对象列表都要导出成 CSV 给运维用 Excel 打开，而 Excel 会把
# 以 `=` `+` `-` `@` 开头的单元格**当公式跑**。
#
# 触发场景完全真实：AD 里 `displayName` / `description` / DN 都属于可控输入
# （被建号的人自己也未必知道），有人写成 `=cmd|'/c calc'!A0`，
# 运维导出后双击打开就中招。分类上就是 CWE-1236 / OWASP A03（注入）。
#
# 两条独立口径取并集，都是"别人已经踩过"的现成经验，不自造判定规则：

#: 会让表格软件把单元格**当公式求值**的开头字符。
#:
#: * **OWASP《CSV Injection》**：核心四字符 `=` `+` `-` `@`；
#:   外加 `\t`(0x09) `\r`(0x0D) `\n`(0x0A) —— 控制字符也能把恶意内容
#:   顶到**新单元格的开头**（攻击者先在值里塞一个分隔符再塞公式）。
#: * **`defusedcsv`**（PyPI 上专治这条的 drop-in 库，3.0.0）：
#:   `@ + - = | %`。其中 `|` 是 DDE 载荷 `=cmd|'/c calc'!A0` 里的分隔符，
#:   `%` 见于部分语言环境。与 OWASP 并集后只多这两类。
#: * 全角 `＝ ＋ － ＠`：OWASP 列出的、**依赖 locale** 的项（原文举了日文环境）。
#:   那一条我无法在本机复现，但这里**采取保守立场一并处理** —— 代价只是
#:   一个 Excel 里**不显示**的 `'`（见 :func:`defuse_csv_cell`），
#:   而漏判的代价是执行别人写的命令。两侧不对称，选保守那一侧。
CSV_FORMULA_PREFIXES: tuple[str, ...] = (
    "=", "+", "-", "@",                        # OWASP 核心
    "\t", "\r", "\n",                          # OWASP 控制字符
    "|", "%",                                  # defusedcsv 补充
    "\uff1d", "\uff0b", "\uff0d", "\uff20",    # ＝ ＋ － ＠（全角）
)


def defuse_csv_cell(value: Any) -> str:
    """把一个值处理成**不会被表格软件当公式执行**的 CSV 单元格文本。

    ## 它防什么

    ``csv.writer`` 只保证 CSV 的**语法**正确（逗号、引号、换行怎么转义），
    它**完全不管** Excel/WPS 拿到这个值会怎么解释。所以要在这里单独防。

    ## 怎么防

    给危险值**前置一个单引号 ``'``**。这是 OWASP 列的缓解措施，也是
    ``defusedcsv`` 的实际做法：Excel 把开头的 ``'`` 当成"这格是文本"的标记，
    **界面上不显示它**（人不觉得别扭），但公式不会被执行。

    ## 边界（写清楚，免得被当成万能的）

    * **不负责 CSV 语法** —— 引号 / 逗号 / 换行的转义仍然交给 ``csv.writer``。
    * ``'`` 会**留在落盘的字节**里：用 ``pandas.read_csv`` 之类的程序化消费者
      会读到多出来的那个 ``'``。这是 OWASP 明确列出的取舍 —— 它推荐的
      "tab 前缀"更抗 Excel，但 **tab 会污染数据**；我们选"人不别扭"这一侧。
      另一个理由：导出里含 **DN**，tab 会把它弄坏。
    * OWASP 还提醒：Excel **另存为 CSV 再打开**时可能把转义字符吃掉、公式复活。
      那一步不在本函数能管的范围内（本函数防的是"拿到文件直接打开"这个
      真实场景），但它说明**这不是一条一劳永逸的防线**，别以为加完就天下太平。
    * 以 ``-`` 开头的**负数字符串**（如 ``-5``）也会被加前缀 ⇒ 在 Excel 里变成
      文本而不是数字。``-5`` 本身不危险，但 ``-1+1`` 是**会求值**的公式，
      客户端无法只靠字符串分辨二者 ⇒ 一律保守处理。本项目的导出列全是文本
      字段（名称 / 描述 / 登录名 / 状态 / DN / 时间…），所以这个误伤是**纯理论的**；
      **一旦以后加了数值列，必须回到这里重新评估**（`tests/test_utils.py`
      有一条用例把这个取舍钉住，它会提醒你）。
    * 前缀集里不含 ``'`` 本身 ⇒ 对同一份数据重复调用**不会叠加**引号（幂等）。

    返回的永远是 ``str``。
    """
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    if text and text[0] in CSV_FORMULA_PREFIXES:
        return "'" + text
    return text

