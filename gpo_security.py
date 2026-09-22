# -*- coding: utf-8 -*-
"""gpo_security.py —— 「这个 GPO 的安全策略」（`GptTmpl.inf` 的**只读**视图）

## 它回答什么

| 段 | 里面是什么 | 界面上的用词 |
|---|---|---|
| `[System Access]` | 密码 / 锁定 / 账户时长 | 账户策略（密码 · 锁定） |
| `[Event Audit]` | 审核策略 | 审核策略 |
| `[Privilege Rights]` | 用户权限分配（谁有「关机」「备份」…） | 用户权限分配 |
| `[Registry Values]` | 安全选项（注册表值） | 安全选项（注册表值） |
| 其它段（`[Group Membership]` / `[File Security]` / `[Registry Keys]` …） | **原样列出** | 段名原样 |

## 三件它**不做**（都写明理由，免得下一个人以为是漏了）

1. **不解析字节** —— 那是 `gpo_security_backend.py`（**唯一实现**）。本模块只回答
   「文件在哪儿 / 读得到吗 / 文件里有什么」，再把结论包成界面要的形状。
2. **不把键名翻成中文**。本机确实有权威词表（`%SystemRoot%\\inf\\sceregvl.inf`，
   SCE 自己的注册表值清单，`[Register Registry Values]` ＋ `[strings]` 两级映射），
   但它是**另一条解析线**，本轮不做 ⇒ 界面显示文件里写的键名本身
   （`MinimumPasswordLength`）。那是**文件真实内容**，不是"没做完的占位"；
   要做时的原料与语法已写在 §5，**不许手搓词表**。
3. **不连域、不碰 COM、不导入 PyQt、不写任何东西**。

## 位置：只有一条，而且**没有用户侧**

```
\\\\<DNS域名>\\SYSVOL\\<DNS域名>\\Policies\\{<GUID>}\\MACHINE\\
        microsoft\\windows nt\\SecEdit\\GptTmpl.inf
```

⚠️ **没有 `User` 侧** —— 与 `Registry.pol` 不同：安全策略由 **Security CSE** 处理，
它是**计算机侧扩展**（AD 里那个属性就叫 `gPCMachineExtensionNames`）。
所以本模块**没有 `pol_paths()` 那种两作用域循环**，路径写死一条 ——
这一点本身是判据：写成循环会让人以为"我们少读了一份用户侧的文件"。

⚠️ **未在真域验证**（本机未加域、碰不到 SYSVOL）—— 与 `gpo_settings.py` 同一条已知边界。
判决装置 `tools/probe_gpo_security.py` 会把「按本条约定拼出来的路径」与 AD 属性
`gPCFileSysPath` **并排打印**，第一次真域运行就能看出两者是否一致 —— 那是一次判决，不是装饰。

## 「这条安全策略会不会生效」—— 本线**唯一别处看不到**的东西

`GptTmpl.inf` 写进 SYSVOL 之后，若 GPC 的属性 `gPCMachineExtensionNames` 里**没有**
安全 CSE 的 GUID，**这份文件会被完全忽略**：文件在、编码对、版本号也涨了、GPMC 里
甚至看得到，但**策略就是不生效**，而界面上没有任何线索（KB885009）。

⇒ 本模块给出**三态**（不是一个布尔）：

| 取值 | 什么时候 | 界面说什么 |
|---|---|---|
| `present` | 属性里有那个 GUID | 「**会被应用**」 |
| `absent` | 属性**有值但不含**那个 GUID | 「**不会被应用**」（＋为什么） |
| `unknown` | 调用方**没提供**这个属性（`None`） | 「**说不清**」—— **不许**说"不会生效" |

🔴 `unknown` 这一档是**必须的**：把「我们没读到那个属性」当成「这条策略不生效」，
就是本项目反复记的 `or 0` 家族 —— 把**取数失败**当成**证据成立**。
（GPMC 那条对照尺就拿不到这个属性 ⇒ 它永远走 `unknown` 分支，是**正确**行为。）

## 边界

* **只读**：没有 `write` / `open(...,"w")` / 任何写入口。
* 不 import `gpo_backend`（那是 COM 层）；也不重复实现 SYSVOL 路径构成 ——
  `sysvol_gpo_dir()` **复用** `gpo_settings.py` 那一份。
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from gpo_security_backend import (
    SECTION_EVENT_AUDIT,
    SECTION_PRIVILEGE_RIGHTS,
    SECTION_REGISTRY_VALUES,
    SECTION_SYSTEM_ACCESS,
    InfLine,
    SecurityTemplate,
    has_security_cse,
    parse_template,
    reg_type_name,
)
from gpo_settings import sysvol_gpo_dir                       # noqa: F401（公开面转出）
from utils import AdToolError, get_logger

_log = get_logger("gpo_security")

__all__ = [
    "INF_FILENAME",
    "SECEDIT_DIR",
    "CSE_PRESENT",
    "CSE_ABSENT",
    "CSE_UNKNOWN",
    "SECTION_WORDS",
    "SecurityEntry",
    "SecuritySection",
    "GpoSecurity",
    "security_inf_path",
    "cse_verdict",
    "collect_security",
    "read_gpo_security",
]

#: 策略文件名。**写死是对的** —— 它不是可选配置，是协议的一部分
#: （Security CSE 只会去读这个名字）。
INF_FILENAME = "GptTmpl.inf"

#: GPO 目录下那一串子目录，**逐字来自协议**（大小写也照写）。
#: 真域与演示域两边都用它拼（大小写不敏感的文件系统上无所谓，
#: 但 Linux 上跑判据时就有所谓了 ⇒ 别"顺手"改小写）。
SECEDIT_DIR = ("MACHINE", "microsoft", "windows nt", "SecEdit")

CSE_PRESENT = "present"
CSE_ABSENT = "absent"
CSE_UNKNOWN = "unknown"

#: 三态 → 界面用词。**单一映射源**（面板不重复一份）。
#: ⚠️ 强调用「」不写 `**` —— 交付模块的字面量里不许出现 Markdown 标记
#: （`tests/test_source_hygiene.py` 第三个守卫；本项目没有渲染器会解释它）。
_CSE_WORDS = {
    CSE_PRESENT: "会被应用",
    CSE_ABSENT: "不会被应用",
    CSE_UNKNOWN: "说不清",
}

#: 三态 → **为什么**（面板在标签下面再印一行）。与 `_CSE_WORDS` 同一个源，
#: 不许面板自己再编一套理由 —— 两处措辞必然分叉。
_CSE_REASONS = {
    CSE_PRESENT: "GPC 的 gPCMachineExtensionNames 里登记了安全扩展，"
                 "这份模板会被 Security CSE 读取。",
    CSE_ABSENT: "GPC 的 gPCMachineExtensionNames 里没有安全扩展的 GUID —— "
                "文件在、版本号也涨了，但这份模板会被完全忽略（KB885009）。",
    CSE_UNKNOWN: "这条读取路径拿不到 gPCMachineExtensionNames，"
                 "所以判断不了它会不会生效。",
}

#: 段名 → 界面用词。**只在这里映射一次**（面板再映射一遍就是两份真相，
#: 改一处忘另一处，界面上会出现两种叫法）。
#: 不在这张表里的段（第三方模板、`[File Security]` 那种）**原样返回段名** ——
#: 猜一个中文名比不翻更糟。
SECTION_WORDS = {
    SECTION_SYSTEM_ACCESS: "账户策略（密码 · 锁定）",
    SECTION_EVENT_AUDIT: "审核策略",
    SECTION_PRIVILEGE_RIGHTS: "用户权限分配",
    SECTION_REGISTRY_VALUES: "安全选项（注册表值）",
}

#: 有界面用词的段（= 我们「认识」的段）。其余段原样显示，但**照样列出**。
_KNOWN_SECTIONS = frozenset(SECTION_WORDS)


# ============================================================================
# 1. 路径
# ============================================================================

def security_inf_path(gpo_dir: str) -> str:
    """GPO 目录 → `GptTmpl.inf` 的完整路径。**只有一条**（没有用户侧，见模块头）。

    ⚠️ 这里**不判断文件在不在** —— 存在性由 `read_gpo_security()` 分类记录。
    把「路径算不出来」与「文件不存在」混在一起，会让人分不清是拼错了还是域里没有
    （与 `gpo_settings.pol_paths()` 同一条纪律）。

    ⚠️ `gpo_dir` 先 `strip()` 再判空：只 `rstrip("\\\\/")` 的话，
    **全是空白**的目录串（`"   "`）会溜过去，拼出一条
    ``"   \\MACHINE\\…\\GptTmpl.inf"`` 的垃圾路径，然后被报成"文件不存在"——
    那是把「我们拿到了一个空目录」冒充成「这条 GPO 没有安全策略」。
    （判据 `test_no_directory_at_all_raises` 抓的就是这个。）
    """
    base = (gpo_dir or "").strip().rstrip("\\/")
    if not base:
        raise AdToolError("没有 GPO 目录，算不出安全策略文件的位置。")
    return os.path.join(base, *SECEDIT_DIR, INF_FILENAME)


# ============================================================================
# 2. 「会不会生效」—— 三态，不是一个布尔
# ============================================================================

def cse_verdict(extension_names: str | None) -> str:
    """`gPCMachineExtensionNames` → `present` / `absent` / `unknown`。

    🔴 **`None` 与空串是两件事**（这条是本节存在的全部理由）：

    * `None` = **这条路没提供这个属性**（例：GPMC 那条对照尺拿不到它）
      ⇒ `unknown` ⇒ 界面必须说「说不清」，**不许**说"不会生效"；
    * `""` = 提供了、但这个对象上**没有值** —— 一个 GPO 连机器侧扩展都没登记
      ⇒ 安全 CSE 必然没注册 ⇒ `absent`，说"不会被应用"是**对**的。

    把这两者合并，就会在**没读到属性**的时候给出一句听起来很确定的错结论 ——
    而这句话（"你的安全策略是废的"）恰恰是使用者最会当真的一句。
    """
    if extension_names is None:
        return CSE_UNKNOWN
    return CSE_PRESENT if has_security_cse(extension_names) else CSE_ABSENT


# ============================================================================
# 3. 数据模型
# ============================================================================

@dataclass(frozen=True)
class SecurityEntry:
    """文件里的一条 `键 = 值`。**认不出的行也是这一档**（`known=False`）。

    🔴 `known == False` 的条目**照样产出、照样显示**。它们在盘上是真实存在的行，
    「界面里看不到它」正是本项目最忌讳的那种**静默少读**。
    """

    section: str
    key: str
    value: str
    #: 这一条认不认得（段内但形态陌生 ⇒ False）。**不是**"有没有用"。
    known: bool = True
    #: `[Registry Values]` 的主体形态；其它段为空元组。
    principal_kinds: tuple[str, ...] = ()
    #: `[Registry Values]` 的类型码与它的名字；-1 = 不适用 / 解不出。
    reg_type: int = -1
    reg_type_name: str = ""


@dataclass(frozen=True)
class SecuritySection:
    """一个段 ＋ 它的条目。**段名不认识也照样建**（`known=False`）。"""

    name: str
    entries: tuple[SecurityEntry, ...]

    @property
    def known(self) -> bool:
        """是不是我们给得出界面用词的那四个段之一。"""
        return self.name in _KNOWN_SECTIONS

    @property
    def label(self) -> str:
        """界面用词。**不认识就原样返回段名**（不猜、也不吞）。"""
        return SECTION_WORDS.get(self.name, self.name)


@dataclass
class GpoSecurity:
    """一个 GPO 的安全策略 ＋ **读的过程记录**。

    ⚠️ `files` / `missing_files` / `failed` **不是**诊断装饰：它们回答的是
    「**我们有没有看漏**」。⚠️ **这里没有 `empty_files`**，与 `GpoSettings` 不同 ——
    见 `read_gpo_security()` 里那句「0 字节归 failed」的理由。

    | 字段 | 含义 |
    |---|---|
    | `files` | 读到了、解析成功的（**一个 GPO 最多一份**）|
    | `missing_files` | 位置**不存在** ⇒ 这条 GPO 没配安全策略（**最常见、正常**）|
    | `failed` | 存在但**读不了 / 是 0 字节 / 解析失败** ⇒ 我们少看了（**必须显示**）|
    """

    gpo_dir: str = ""
    display_name: str = ""
    template: SecurityTemplate | None = None
    sections: tuple[SecuritySection, ...] = ()
    #: 认不出的行（段头之外的、既不是注释也不是条目的行）。**要显示，不许丢。**
    unknown_lines: tuple[SecurityEntry, ...] = ()
    files: tuple[str, ...] = ()
    missing_files: tuple[str, ...] = ()
    failed: tuple[str, ...] = ()
    #: `present` / `absent` / `unknown` —— 见 `cse_verdict()`。
    cse: str = CSE_UNKNOWN

    @property
    def is_conclusive(self) -> bool:
        """这次读取**能不能下结论**。

        判据：读到过文件（`files` 非空）**或**确认过位置不存在（`missing_files` 非空）
        ⇒ 能说"这条 GPO 的安全策略就这些 / 就没有"。
        只有 `failed` 时**不能说** —— 那时是"我们什么都没看到"。
        """
        return bool(self.files or self.missing_files)

    @property
    def cse_label(self) -> str:
        """「会不会生效」的界面用词。取不到就回落成"说不清"（**不猜**）。"""
        return _CSE_WORDS.get(self.cse, _CSE_WORDS[CSE_UNKNOWN])

    @property
    def cse_reason(self) -> str:
        """「为什么是这个结论」—— 与 `cse_label` 同源同回落。"""
        return _CSE_REASONS.get(self.cse, _CSE_REASONS[CSE_UNKNOWN])

    @property
    def cse_is_relevant(self) -> bool:
        """「会不会生效」这条结论**有没有对象**。

        🔴 **只有读到过模板（`files` 非空）时它才有意义。** 一个连
        `GptTmpl.inf` 都没有的 GPO，谈"这份模板会不会被应用"是**无意义**的 ——
        而界面上一旦印出「不会被应用」，使用者会去找一份**根本不存在的策略**，
        找不到就当成缺陷报上来（演示域冒烟时实测过这个读数：
        「内网更新源」与「空白策略」都会被印成"不会被应用"）。

        ⇒ 界面必须拿这个属性决定**渲不渲染那一行**，而不是自己判断
        `files` 空不空 —— 那是把同一条语义在两处各写一遍。
        """
        return bool(self.files)

    @property
    def section_names(self) -> tuple[str, ...]:
        """段名（按文件里的出现顺序）。面板要显示"有哪几段"时用它。"""
        return tuple(section.name for section in self.sections)

    @property
    def entry_count(self) -> int:
        """条目总数（**不含**段头 / 注释 / 空行）。"""
        return sum(len(section.entries) for section in self.sections)


# ============================================================================
# 4. 分类：解析结果 → 界面要的形状（**纯数据、可单测**）
# ============================================================================

def _entry_of(line: InfLine) -> SecurityEntry:
    """一条 `InfLine` → `SecurityEntry`（认不出的行也走这里）。"""
    return SecurityEntry(
        section=line.section, key=line.key, value=line.value, known=line.known,
        principal_kinds=line.principal_kinds,
        reg_type=line.reg_type,
        reg_type_name=reg_type_name(line.reg_type) if line.reg_type >= 0 else "",
    )


def collect_security(template: SecurityTemplate) -> tuple[SecuritySection, ...]:
    """把解析结果按**段**归拢。**纯数据、可单测。**

    🔒 两条纪律：

    1. **顺序照文件**：段按首次出现顺序、条目按行序 —— 界面读起来与文件一致，
       排过序就再也看不出"文件里第几行写的"。
    2. **一条不丢**：`known=False` 的条目、认不出段名的段，**都进结果**。
       过滤掉它们会让一份"有 3 条我们认不出"的模板显示成"干净读完"。
    """
    order: list[str] = []
    bucket: dict[str, list[SecurityEntry]] = {}
    for line in template.lines:
        if line.kind != "entry":
            continue
        name = line.section
        if name not in bucket:
            bucket[name] = []
            order.append(name)
        bucket[name].append(_entry_of(line))
    return tuple(SecuritySection(name=name, entries=tuple(bucket[name]))
                 for name in order)


def _unknown_entries(template: SecurityTemplate) -> tuple[SecurityEntry, ...]:
    """文件里**既不是段头、也不是注释/空行、也不是条目**的行（原样收着）。"""
    return tuple(SecurityEntry(section=line.section, key=line.raw.strip(),
                               value="", known=False)
                 for line in template.unknown_lines())


# ============================================================================
# 5. 读一个 GPO 的目录（**0 字节归 failed，不归 empty**）
# ============================================================================

def read_gpo_security(gpo_dir: str, display_name: str = "",
                      extension_names: str | None = None) -> GpoSecurity:
    """读某个 GPO 目录下的 `GptTmpl.inf`，产出**只读**视图。

    ``extension_names`` 是 AD 属性 `gPCMachineExtensionNames` 的原文；
    **传 `None` 表示"这条路拿不到这个属性"**（⇒ 结论是"说不清"，见 `cse_verdict`）。

    🔴 **0 字节的文件归 `failed`，不归"空文件"** —— 这条与 `gpo_settings` 的做法
    **不同**，理由是真域事实：`GptTmpl.inf` 只要合法，**第一段必然是 `[Unicode]`
    且必然有内容**（安全模板没有"空模板"这种正常形态）。
    所以 0 字节只可能是**截断 / 写坏**，把它当成"这条 GPO 没有安全策略"显示，
    等于用一句平静的结论盖住一份坏文件 —— 那比报错危险得多。
    """
    result = GpoSecurity(gpo_dir=gpo_dir, display_name=display_name,
                         cse=cse_verdict(extension_names))
    path = security_inf_path(gpo_dir)

    if not os.path.isfile(path):
        result.missing_files += (path,)
        _log.info("这条 GPO 没有安全策略文件（正常）：%s", path)
        return result

    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        result.failed += ("%s：%s" % (path, exc),)
        _log.warning("安全策略文件读失败（已记进 failed，不静默跳过）：%s：%s",
                     path, exc)
        return result

    if not raw:
        result.failed += (
            "%s：文件是 0 字节（安全模板不存在「空模板」这种正常形态，"
            "只可能是截断或写坏）" % path,)
        _log.warning(
            "安全策略文件是 0 字节（归 failed，不当成「没有安全策略」）：%s",
            path)
        return result

    try:
        template = parse_template(raw, path)
    except AdToolError as exc:
        result.failed += ("%s：%s" % (path, exc.message),)
        _log.warning("安全策略文件解析失败（已记进 failed）：%s：%s",
                     path, exc.message)
        return result

    result.files += (path,)
    result.template = template
    result.sections = collect_security(template)
    result.unknown_lines = _unknown_entries(template)
    _log.info("安全策略已读：%d 段 / %d 条 / 认不出的行 %d / 会不会生效=%s",
              len(result.sections), result.entry_count,
              len(result.unknown_lines), result.cse)
    return result
