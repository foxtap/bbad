# -*- coding: utf-8 -*-
r"""gpo_security_backend.py —— 安全策略模板（`GptTmpl.inf`）的**读**（纯只读）

> 🔴 **2026-09-18 范围变更**：已定「**这个工具不做组策略编辑，只做能看见就可以，
> 不需要编辑和新加这种**」⇒ 本模块的**写侧整体移出仓库归档**（不是删掉）。
> 移走的清单与理由**未进本仓库**；回滚件（整份文件快照 ＋ 每文件 md5）留在本地。
> ⇒ 本模块**只剩读**，且**不再有任何写入口**（连"改一个字节"的函数都没有）。
> 那份安全策略编辑的设计稿（**同样不在本仓库里**）描述的写路径**已不适用**。

## 它解决的是哪一类问题

组策略的「策略内容」有两种截然不同的载体，本模块管**第二种**：

| 载体 | 文件 | 管什么 | 谁在管 |
|---|---|---|---|
| 管理模板 | `Registry.pol`（PReg 二进制） | 禁用U盘 / 壁纸 / 控制面板 / 自动更新 | `preg_backend` ＋ `admx_backend` ＋ `gpo_settings` |
| **安全策略** | **`GptTmpl.inf`（纯文本 INF）** | **密码策略 / 锁定策略 / 审核策略 / 安全选项 / 用户权限分配** | **本模块（读）** |

**为什么单做这一个**：需求文档 `docs/需求-组策略-2026-09-15.md` §2.3 的原话 ——
「工厂 IT 最常改的（密码长度 / 复杂度 / 锁定阈值 / 账户锁定时间 / 审核策略）
**全在第一层，是纯文本**」。⇒ 它也是**最该看得见**的一档：这几项现在都在
`GPMC` 或 `secedit` 里才看得到，没装 RSAT 的机器两眼一抹黑。

## 实测（本机两个真实样本，不是抄文档）

| 样本 | 字节 | 段数 | 编码 / 行尾 |
|---|---|---|---|
| `secedit /export`（**操作系统自己生成**） | 17 358 | 6 | `utf-16-le` ＋ BOM `FF FE` ＋ CRLF |
| `C:\Windows\inf\defltbase.inf`（Windows 自带） | 29 572 | 13 | 同上 |

**三件本机实测、与想当然不一样的事**：

1. **BOM 是承重的**。同一内容去掉 BOM ⇒ 编码探测落到 `cp1252` ⇒ 段数解析成 **0**，
   而且**不抛任何异常**。这正是本项目最忌讳的静默失效 ⇒ 本模块**见到无 BOM 就抛**。
   （另一面：`utf-16-le` 解码会把 BOM **当成一个字符留在文本里**，而 `\ufeff` 不属于 `\s`
   ⇒ 分行前必须剥掉它，否则**第一段整段消失**。这是本轮冒烟抓到的真缺陷，见 `parse_template`。）
2. **`[Privilege Rights]` 的值有四种形态**（`*SID` / `&相对SID` / `裸账号` / `域\账号`），
   而且**同一行可以混**（实测：`SeServiceLogonRight = *S-1-5-80-0,受限服务\所有受限服务`）。
   只认 `*SID` 的解析器会**静默漏掉 4/71 个主体** —— 而这一段是**全量替换语义**，
   所以"漏认"与"看漏了几个人有权限"是同一件事。（写侧已归档，但**读侧漏认**照样是
   "看得见却看错了"，仍必须四种形态齐全。）
3. **`[Registry Values]` 有表外类型码**：`8` ＋ `Remove:` 前缀真实存在
   （`MACHINE\...\NullSessionPipes=8,Remove:,lsarpc,samr,netlogon`），
   而它**不在微软自己写在该段注释里的类型表**（1/2/3/4/7）里。

## 边界（哪些事本模块**不**做）

* **不连域、不碰 SYSVOL、不落盘、不导入 PyQt**。本模块是**纯字节函数层** ——
  设计稿 §7 的话：「把最难验的东西变成最容易验的东西」。读文件与接域是
  `workers` / `gpo_settings` 那一层的事；
* **不写**（2026-09-18 起）。没有 `patch` / `apply` / `bump` / `diff` 之类；
* **不猜**。段名/键名一律 `re.IGNORECASE`（实测两种拼写都存在），但**找不到就抛**，
  绝无「没找到就跳过」；认不出的行**原样保留并标记**（`known=False`），绝不静默丢弃。

## 判据（`tests/test_gpo_security_backend.py`）与反证（`tools/counterproof_gpo_security.py`）

三层，全部**离线**（喂真实样本字节，不需要域）：

1. **解析的可信度** —— 段数/条目数/未识别数**如实报**；认不出的行**原样保留并标记**
   （`known=False`），既不丢弃也不误标成正常行；
2. **格式真相** —— 四种主体形态各一条、同一行可混、类型码表内表外、
   只按**第一个**逗号切值、段名大小写不敏感；
3. **一件只有"看"才做得到的诊断** —— 安全 CSE 的 GUID 在不在
   （不在 ⇒ 这份安全策略**根本不会生效**，而界面别无线索）。

⚠️ **版本号的按位拆分不在这里**：「只有一份实现」是红线，而它归
`gpo_ldap._version_split()`（那份更正过方向，见它的 docstring）。
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from utils import AdToolError

# --------------------------------------------------------------------------
# §1 常量：段名、主体形态、GUID、类型码
# --------------------------------------------------------------------------

SECTION_SYSTEM_ACCESS = "System Access"
SECTION_EVENT_AUDIT = "Event Audit"
SECTION_REGISTRY_VALUES = "Registry Values"
SECTION_PRIVILEGE_RIGHTS = "Privilege Rights"

#: 安全 CSE 的 GUID（微软 KB885009）。
#:
#: `GptTmpl.inf` 写进 SYSVOL 之后，若 GPC 对象的属性 `gPCMachineExtensionNames`
#: 里**没有**这个 GUID，**这份文件会被完全忽略** —— 文件在、编码对、版本号也涨了、
#: GPMC 里甚至看得到，但**策略就是不生效**，而界面上**没有任何线索**指向
#: 「属性少了一个 GUID」。这是最阴的一种失败。
#:
#: 🔴 **它是"看"不是"改"**：`has_security_cse()` 让界面能说出一句别处看不到的话 ——
#: 「这条 GPO 的安全策略**不会被应用**」。2026-09-18 收敛写侧时**刻意保留**它。
SECURITY_CSE_GUID = "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}"

#: 微软**自己写在** `[Registry Values]` 段开头的类型码表（原样抄自 `defltbase.inf`
#: 的注释）。⚠️ 实测存在**表外**的码 `8` ＋ `Remove:` 前缀。
DOCUMENTED_REG_TYPES: dict[int, str] = {
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    7: "REG_MULTI_SZ",
}

#: `[Privilege Rights]` 里主体（principal）的形态。**实测四种全部真实存在**，
#: 且**同一行可以混**（见模块头第 2 条）。
PRINCIPAL_STAR_SID = "星号SID"
PRINCIPAL_AMP_SID = "与号相对SID"
PRINCIPAL_DOMAIN_ACCOUNT = "域\\账号"
PRINCIPAL_BARE_SID = "裸SID"
PRINCIPAL_BARE_ACCOUNT = "裸账号"
PRINCIPAL_UNKNOWN = "认不出"

#: 六种形态的目录 —— 界面按它列「这份策略里的主体分几类」。
PRINCIPAL_KINDS: tuple[str, ...] = (
    PRINCIPAL_STAR_SID, PRINCIPAL_AMP_SID, PRINCIPAL_DOMAIN_ACCOUNT,
    PRINCIPAL_BARE_SID, PRINCIPAL_BARE_ACCOUNT, PRINCIPAL_UNKNOWN,
)

_HEADER_BOM_UTF16 = b"\xff\xfe"
_HEADER_BOM_UTF8 = b"\xef\xbb\xbf"

_SECTION_RE = re.compile(r"^\s*\[(?P<name>[^\]]+)\]\s*$")
_ENTRY_RE = re.compile(r"^(?P<left>\s*(?P<key>[^=;\[\]]+?)\s*=\s*)(?P<value>.*)$")
_COMMENT_RE = re.compile(r"^\s*;")


# --------------------------------------------------------------------------
# §2 数据模型
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class InfLine:
    """一行原始文本 ＋ 它的解析结果。

    🔴 **原文必须留着**（`raw`）—— 界面要显示「认不出的那一行**长什么样**」，
    只报一句"有 9 行没识别"是不够的（使用者得看见它们，才知道要不要手工去看）。

    ⚠️ 与设计稿 §7 的两处差异（都是实测逼出来的，不是随手的改动）：

    * `principal_kind: str` → **`principal_kinds: tuple[str, ...]`**：
      实测同一行可以混形态（`SeServiceLogonRight = *S-1-5-80-0,受限服务\所有受限服务`），
      单个字符串**表达不了**；
    * 新增 `reg_type: int`：`[Registry Values]` 的类型码是**格式层的事实**，
      不给它一个字段的后果是**每个调用方各解析一遍**（违反「只有一份实现」）。
    """

    index: int
    raw: str
    kind: str                                   # "section" | "entry" | "comment" | "blank" | "unknown"
    section: str = ""
    key: str = ""
    value: str = ""
    principal_kinds: tuple[str, ...] = ()
    reg_type: int = -1                          # -1 = 不适用 / 未能解析出类型码
    known: bool = True                          # False = 我们认不出它 ⇒ 界面标「未识别」


@dataclass(frozen=True)
class SecurityTemplate:
    """一份 `GptTmpl.inf` 的完整读视图。"""

    path: str
    codec: str
    has_bom: bool
    line_ending: str                            # "crlf" / "lf" / "mixed" / "none"
    lines: tuple[InfLine, ...]
    md5: str
    raw: bytes = field(repr=False)              # 原字节（界面要"看原样"时用）

    def sections(self) -> tuple[str, ...]:
        """段名按**出现顺序**去重（原样拼写，不归一大小写）。"""
        seen: list[str] = []
        for line in self.lines:
            if line.kind == "section" and line.section not in seen:
                seen.append(line.section)
        return tuple(seen)

    def entries(self, section: str = "") -> tuple[InfLine, ...]:
        """取 `entry` 行；给了 `section` 就只取那一段（**大小写不敏感**）。"""
        want = section.lower()
        return tuple(l for l in self.lines
                     if l.kind == "entry" and (not want or l.section.lower() == want))

    def value_of(self, section: str, key: str) -> str | None:
        """读一个键的值。**找不到返回 None**（调用方必须区分「没有」与「空值」）。"""
        for line in self.entries(section):
            if line.key.lower() == key.lower():
                return line.value
        return None

    def unknown_lines(self) -> tuple[InfLine, ...]:
        """我们认不出的行 —— 界面要如实显示「未识别（原样保留，不会被修改）」。"""
        return tuple(l for l in self.lines if not l.known)


# --------------------------------------------------------------------------
# §3 编码 / 行尾 / 主体形态 / 类型码（纯函数）
# --------------------------------------------------------------------------

def detect_codec(raw: bytes) -> tuple[str, bool]:
    """返回 ``(codec, has_bom)``。

    ⚠️ 为什么不能写死 `utf-16`：`GptTmpl.inf` 按 [MS-GPSB] 是 UTF-16LE ＋ BOM，
    但**同目录的 `GPT.INI` 是 ANSI/ASCII**，与 `gpt.ini` 那一路会走同一条代码路径
    ⇒ 必须探测。

    ⚠️ 用 `utf-16-le` 而**不是** `utf-16`：后者会让 codec 自己吃／吐 BOM，
    端序也可能被改 ⇒ 字节不保真。这里把 BOM 当**普通字符**留着，
    由 `parse_template` 自己剥（理由见那里）。
    """
    if raw.startswith(_HEADER_BOM_UTF16):
        return "utf-16-le", True
    if raw.startswith(_HEADER_BOM_UTF8):
        return "utf-8-sig", True
    return "cp1252", False


def line_ending(text: str) -> str:
    """判定行尾。返回 ``'crlf'`` / ``'lf'`` / ``'mixed'`` / ``'none'``。"""
    crlf = text.count("\r\n")
    lf_only = text.count("\n") - crlf
    if crlf and lf_only:
        return "mixed"
    if crlf:
        return "crlf"
    if lf_only:
        return "lf"
    return "none"


def classify_principal(token: str) -> str:
    """给 `[Privilege Rights]` 里的一个主体归类。**四种形态的判定顺序是有意的**：

    `*` / `&` 前缀**最先**判 —— 因为它们才是「明确的机制」，而后面两种是
    「没有前缀时按**长相**猜」，务必放在最后，免得把 `*-501` 之类误判成别的东西。
    """
    text = (token or "").strip()
    if not text:
        return PRINCIPAL_UNKNOWN
    if text.startswith("*"):
        return PRINCIPAL_STAR_SID
    if text.startswith("&"):
        return PRINCIPAL_AMP_SID
    if "\\" in text:
        return PRINCIPAL_DOMAIN_ACCOUNT
    if text.upper().startswith("S-1-"):
        return PRINCIPAL_BARE_SID
    return PRINCIPAL_BARE_ACCOUNT


def split_principals(value: str) -> tuple[str, ...]:
    """把 `[Privilege Rights]` 的一行值切成主体列表。

    ⚠️ **空值不等于没主体**：`SeCreatePermanentPrivilege =` 的意思是
    **「没有人有这个权限」**（实测 `defltbase.inf` 里有 8 个这样的键），
    而**删掉这一行**的意思是「这个设置不由本策略管」。两者语义**完全不同** ⇒
    本函数对空值返回**空元组**，调用方必须自己区分「空元组但键在」与「键不在」。
    """
    text = (value or "").strip()
    if not text:
        return ()
    return tuple(part.strip() for part in text.split(",") if part.strip())


def reg_type_name(code: int) -> str:
    """类型码 → 名字。表外的码如实说「未收录」，**不许当成某个默认值**。"""
    return DOCUMENTED_REG_TYPES.get(code, "未收录（表外类型码 %d）" % code)


def split_registry_value(value: str) -> tuple[int, str]:
    """把 `[Registry Values]` 的值切成 ``(类型码, 值文本)``。

    ⚠️ **只切第一个逗号**：值可以自带逗号 —— 实测
    `MACHINE\\...\\NullSessionPipes=8,Remove:,lsarpc,samr,netlogon`（多值）
    与 `MACHINE\\...\\AllowedPaths\\Machine=7,System\\...,Software\\...`（多路径）。
    拿 `split(",")` 全切会把值的结构毁掉 —— **看起来"解析成功了"，实际读错**。

    切不出类型码时返回 ``(-1, 原文本)`` —— **不猜**，让调用方看见「未收录」。
    """
    text = value or ""
    head, sep, rest = text.partition(",")
    if not sep:
        return -1, text
    try:
        return int(head.strip()), rest
    except ValueError:
        return -1, text


# --------------------------------------------------------------------------
# §4 解析（本模块的全部功能）
# --------------------------------------------------------------------------

def _classify(line: str) -> str:
    if not line.strip():
        return "blank"
    if _COMMENT_RE.match(line):
        return "comment"
    if _SECTION_RE.match(line):
        return "section"
    if _ENTRY_RE.match(line):
        return "entry"
    return "unknown"


def parse_template(raw: bytes, path: str = "") -> SecurityTemplate:
    """解析一份 `GptTmpl.inf` 的字节。

    🔴 **见到无 BOM 就抛**，不许"给个空结果"。理由是实测的：

        同一内容去掉 BOM ⇒ 编码探测落到 cp1252 ⇒ 段数解析成 **0**，且**不抛异常**。

    那就是本项目最忌讳的静默失效 —— 界面会把「读不懂这份文件」显示成
    「这份策略里什么都没配」。**宁可吵，不可哑。**

    ⚠️ 段名/键名一律 `re.IGNORECASE`（实测 `[Version]` / `[version]` 都存在），
    但 `InfLine` 里**保留原样拼写**（界面要按原文显示）。
    """
    codec, has_bom = detect_codec(raw)
    if not has_bom:
        raise AdToolError(
            "这份安全策略文件没有 BOM，本工具「不猜」它的编码：%s\n"
            "（%s 按规范是 UTF-16LE ＋ BOM。实测：同一份内容去掉 BOM 之后，"
            "整份文件会被当成 cp1252 读，段数解析成 0，而且不报任何错 ——"
            "界面就会把「读不懂」显示成「什么都没配」。）"
            % (path or "（未给路径）", "GptTmpl.inf"))

    text = raw.decode(codec)
    # 🔴 **分行之前必须剥掉 BOM 字符**。本模块用 `utf-16-le` 解码（为了字节保真），
    # 于是文件开头的 BOM 会**留在文本里** —— 而 `\ufeff` 不属于 `\s`，
    # 所以 `^\s*\[…\]` 匹配不到 `\ufeff[Unicode]`。实测后果是**第一段整段消失**：
    # `secedit /export` 样本的段数从 6 变成 5，`[Unicode]` 段头被降级成
    # 「认不出的行」，而它下面的 `Unicode=yes` 被挂到了**空段名**上。
    # 这是「静默少读」的典型形态（少了东西，一声不响）。
    if text.startswith("\ufeff"):
        text = text[1:]
    ending = line_ending(text)
    lines: list[InfLine] = []
    section = ""
    for index, text_line in enumerate(text.split("\r\n")):
        kind = _classify(text_line)
        if kind == "section":
            section = _SECTION_RE.match(text_line).group("name").strip()
            lines.append(InfLine(index=index, raw=text_line, kind="section",
                                 section=section))
            continue
        if kind == "entry":
            match = _ENTRY_RE.match(text_line)
            key = match.group("key").strip()
            value = match.group("value").strip()
            principal_kinds: tuple[str, ...] = ()
            reg_type = -1
            if section.lower() == SECTION_PRIVILEGE_RIGHTS.lower():
                principal_kinds = tuple(classify_principal(t)
                                        for t in split_principals(value))
            elif section.lower() == SECTION_REGISTRY_VALUES.lower():
                reg_type = split_registry_value(value)[0]
            lines.append(InfLine(index=index, raw=text_line, kind="entry",
                                 section=section, key=key, value=value,
                                 principal_kinds=principal_kinds,
                                 reg_type=reg_type))
            continue
        lines.append(InfLine(index=index, raw=text_line, kind=kind,
                             section=section, known=(kind != "unknown")))

    return SecurityTemplate(
        path=path,
        codec=codec,
        has_bom=has_bom,
        line_ending=ending,
        lines=tuple(lines),
        md5=hashlib.md5(raw).hexdigest(),
        raw=raw,
    )


# --------------------------------------------------------------------------
# §5 唯一一处"别处看不到"的诊断
# --------------------------------------------------------------------------

# ⚠️ **版本号的按位拆分不在这里**（2026-09-18 更正时删掉了本模块那份）。
# 原因：`gpo_ldap._version_split()` 已经在做同一件事，而「**只有一份实现**」
# 是本项目红线 —— 两份实现必然分叉，而这一对**真的分叉过**：
# 09-15 这份探针说「高 16 = 用户」，09-17 走 LDAP 那份说「高 16 = 计算机」，
# 两边都自称有依据，谁也没报错。裁定见 `gpo_ldap._version_split` 的更正段
# （**高 16 位 = 用户、低 16 位 = 计算机**，四个独立权威来源）。
# ⇒ 要看 GPO 版本，用 `GpoInfo.user_version` / `computer_version`（已拆好）。


def has_security_cse(extension_names: str) -> bool:
    """`gPCMachineExtensionNames` 里有没有安全 CSE 的 GUID（**大小写不敏感**）。

    该属性的形态是几对花括号拼起来的串，例如
    ``[{827D319E-...}{803E14A0-...}]``。**没有安全 CSE 的 GUID ⇒ SYSVOL 里那份
    `GptTmpl.inf` 被完全忽略**（KB885009），而界面上没有任何线索指向它。

    ⇒ 这是本模块**唯一一处"别处看不到"的判断**：界面拿它说一句
    「这条 GPO 的安全策略**不会被应用**」。没装 RSAT 的机器上，
    这句话在别的地方**根本得不到**。
    """
    return SECURITY_CSE_GUID.lower() in (extension_names or "").lower()
