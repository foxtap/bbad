# -*- coding: utf-8 -*-
"""admx_backend.py —— ADMX/ADML 的**只读**解析器（组策略「管理模板」目录）

## 为什么自己解析，而不是拿现成库

2026-09-17 的判决实验（`tools/probe_admx_feasibility.py`）量清了代价，
同时做了一次库检索，结论有两条：

| 候选 | 许可 | 判定 |
|---|---|---|
| `nohuto/admx-parser` | **AGPL-3.0** | 🔴 **有传染性，不嵌** |
| `innovato dev/WindowsAdmxParser` · `stknohg/AdmxPolicy` | — | PowerShell 实现，要运行时 |
| `dooblpls/json-gpo` | — | JS，要 Node |

⇒ 没有**许可干净且不自带运行时**的现成件。而 ADMX 的 schema 是**公开的**，
实测解析代价也量得出来（见下），所以照规范自己写 —— 这不是"造轮子"，
是"没有可用的轮子"（判据见 `SKILL: library-first-check` 第 ③ 条）。

## 为什么要这个模块（它解决的是哪一类问题）

组策略的「管理模板」在磁盘上只有**注册表值**（`registry.pol`），
**值本身不带任何说明** —— 想知道 `SOFTWARE\\Policies\\Microsoft\\WindowsUpdate`
下那个 `NoAutoUpdate=1` 到底叫什么、还有哪些可能取值，**只能靠 ADMX**。
⇒ ADMX 是「策略 ⇄ 注册表值」之间**唯一的映射表**。
本模块把它读成结构化目录，供上层的「策略树」与「哪些设置被改过」使用。

## 实测代价（`tools/probe_admx_feasibility.py`，本机 Windows）

| 项 | 实测 |
|---|---|
| 文件数 | **224** 个 `.admx` + `zh-CN` **224** 个 `.adml`，合计 **6.8 MB** |
| 解析 | **224 / 224 成功** |
| policy 总数 | **3552**（machine 1718 / both 1081 / user 753） |
| elements 形态 | **6 种**（enum 1075 · decimal 404 · boolean 364 · text 362 · list 125 · multiText 106） |
| 两态（无 elements） | **1923** |
| `zh-CN` 文案 | **7809** 条 string |
| 第三方依赖 | **零**（`xml.etree` 是标准库） |

## 🔴 三个「不处理就静默少读」的坑（都实测踩过）

1. **XML 声明写的是 `encoding="unicode"`** ⇒ Python `ElementTree` 抛
   `LookupError: unknown encoding: unicode`。**不处理则 224 个文件全部读不出来。**
2. **编码不统一**：`utf-8+bom` **153** / `utf-8` **69** / `utf-16-le+bom` **2**
   （`Search.admx` 等，声明还是**单引号**）。
   「按 UTF-8 读全部」会漏 2 个；「读不出来就跳过」更糟 ——
   那是**静默少读整片策略**，而这个模块的产物是"策略目录"，
   少读了一片就等于**界面上那些策略凭空消失**，使用者根本不会知道。
3. 正确读法**只有一种**：**按 BOM 判编码 → 解码成 `str` → 整段删掉 XML 声明
   → `fromstring`**（`str` 输入不允许带 encoding 声明）。

## 不许静默少读：读不了的文件必须**报到**

`AdmxCatalog.failed` 逐条列出「哪个文件、什么错」。上层要么显示它、
要么据此拒绝工作 —— 但**不许**把 `failed` 忽略掉当没发生。
守这条的是 `tests/test_admx_backend.py::TestNothingIsSilentlySkipped`。

## 边界

* 本模块**只读文件**：不连域、不碰 SYSVOL、不写任何东西、不导入 PyQt；
* 不做「策略 → 界面控件」的映射（那是 UI 层的事），只给结构化数据；
* 不解析 `presentation`（下拉框布局等在 ADML 里），P0 用不到。
"""

from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Iterable

from utils import AdToolError, get_logger

_log = get_logger("admx_backend")

#: ADMX 的 XML 声明 —— 必须整段删掉（它写的是 `encoding="unicode"`，Python 不认）
_XML_DECL = re.compile(r"<\?xml[^>]*\?>", re.IGNORECASE)

BOM_UTF16LE = b"\xff\xfe"
BOM_UTF16BE = b"\xfe\xff"
BOM_UTF8 = b"\xef\xbb\xbf"

#: Windows 自带的 ADMX 目录。**不是所有 Windows 都有**（家庭版存疑，未验证）
#: ⇒ 调用方必须能接受"这个目录不存在"，而不是崩掉。
DEFAULT_ADMX_DIR = os.path.join(
    os.environ.get("SystemRoot", r"C:\Windows"), "PolicyDefinitions")

#: 界面语言的候选顺序。第一个是本项目的默认（简体中文）。
FALLBACK_LANGUAGES = ("zh-CN", "en-US")

#: `elements` 的全部 6 种形态（实测穷举过，没有第 7 种）
ELEMENT_KINDS = ("enum", "decimal", "boolean", "text", "list", "multiText")


# ============================================================================
# 1. 编码安全的读取（唯一入口）
# ============================================================================

def detect_encoding(raw: bytes) -> str:
    """按 **BOM** 判断编码（ADMX 的 XML 声明不可信 —— 它写 `unicode`）。"""
    if raw.startswith(BOM_UTF16LE):
        return "utf-16-le+bom"
    if raw.startswith(BOM_UTF16BE):
        return "utf-16-be+bom"
    if raw.startswith(BOM_UTF8):
        return "utf-8+bom"
    return "utf-8"


def _strip_namespaces(root: ET.Element) -> ET.Element:
    """把 `{http://…}policy` 这类标签**就地还原成 `policy`**。

    🔴 **不做这一步，224 个文件里有 217 个会被判成"不是 ADMX"**（实测）：
    ADMX 声明了命名空间，`root.tag` 实际是
    `{http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions}policyDefinitions`，
    而 `findall("./policies/policy")` **不认带命名空间的标签** ⇒ 一条策略都取不到。
    更坏的是它**不报错** —— 你会拿到一个"ADMX 里一条策略都没有"的目录，
    而界面表现就是「设置树是空的」，看不出是读法少了一层。

    ⚠️ 命名空间**不止一种**（实测至少三种写法）：
      * `http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions`
      * `https://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions`
      * `http://www.microsoft.com/GroupPolicy/PolicyDefinitions`
    ⇒ 所以**不许**按某个具体 URI 去匹配，一律"去掉花括号前缀取 local name"。
    """
    for node in root.iter():
        if isinstance(node.tag, str) and "}" in node.tag:
            node.tag = node.tag.rsplit("}", 1)[-1]
    return root


def read_xml(path: str) -> ET.Element:
    """读一个 ADMX/ADML XML 文件。**这是本模块唯一的读入口**。

    顺序不能变：**BOM 定编码 → 解码成 str → 删掉 XML 声明 → `fromstring`
    → 去掉命名空间**。

    * 不能先 `ET.parse`：它自己解析声明，遇到 `encoding="unicode"` 直接抛
      `LookupError`（实测：224 个文件**全部**读不出来）。
    * 不能"读不出来就跳过"：那是静默少读（见模块头第 2 条）。
    * `fromstring` 传 **`str`** 时**不允许**带 encoding 声明 ⇒ 必须先删掉。
    * **必须去命名空间**（见 `_strip_namespaces`）：否则 217/224 个文件
      一条策略都取不到，而且不报错。

    读不了就抛 `AdToolError`（中文、能直接显示）——由调用方决定是中止还是记进
    `AdmxCatalog.failed`；本函数**不**吞异常。
    """
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        raise AdToolError(f"读不了 ADMX 文件：{path}（{type(exc).__name__}: {exc}）") from exc

    encoding = detect_encoding(raw)
    codec = {"utf-16-le+bom": "utf-16", "utf-16-be+bom": "utf-16",
             "utf-8+bom": "utf-8-sig"}.get(encoding, "utf-8")
    try:
        text = raw.decode(codec)
    except UnicodeDecodeError as exc:
        raise AdToolError(
            f"ADMX 文件解码失败：{path}（按 {encoding} 解不开：{exc}）"
            "—— 这个文件既不是 UTF-8 也不是 UTF-16LE/BE，需要人工看一眼。") from exc

    try:
        return _strip_namespaces(ET.fromstring(_XML_DECL.sub("", text, count=1)))
    except ET.ParseError as exc:
        raise AdToolError(f"ADMX 文件 XML 不合法：{path}（{exc}）") from exc


# ============================================================================
# 2. 数据模型
# ============================================================================

@dataclass(frozen=True)
class AdmxItem:
    """`enum` / `list` 里的一个选项。"""

    label: str                      # 已经过 ADML 本地化的显示名
    value: int | None               # `<value><decimal value="N"/></value>`
    raw_value: str = ""             # `<value><string>..</string></value>` 的原文


@dataclass(frozen=True)
class AdmxElement:
    """`<elements>` 里的一个设置项（实测只有 `ELEMENT_KINDS` 这 6 种）。"""

    kind: str                       # ∈ ELEMENT_KINDS
    id: str                         # 同一 policy 内唯一
    value_name: str                 # 真正的注册表值名（**可能是空串**）
    required: bool = False
    default_item: int | None = None
    min_value: int | None = None    # 只对 decimal
    max_value: int | None = None
    items: tuple[AdmxItem, ...] = ()  # 只对 enum / list
    #: 只对 `boolean`：勾选 / 不勾选**各自要写的值**。
    #: ⚠️ **本机实测：364 个 boolean 元素里 307 个声明了 `<trueValue>`**，
    #:    而且有声明成 0/1 反过来的 ⇒ "勾选就写 1"是**错的**。
    #:    没声明时才是 1 / 0（ADMX 的惯例）。
    true_value: int | None = None
    false_value: int | None = None


@dataclass(frozen=True)
class ValueDecl:
    """`<enabledValue>` / `<disabledValue>` **声明了什么**（原始形态）。

    `kind` 取值与含义（`ADMX_DECL_KINDS`）：

    ==========  ==========================================================
    ``number``  `<decimal value="N"/>` ⇒ 写 N（REG_DWORD）
    ``true``    `<trueValue/>`        ⇒ 写 1（boolean 形态）
    ``false``   `<falseValue/>`       ⇒ 写 0
    ``delete``  `<delete/>`           ⇒ **删掉这个值**
    ``text``    `<string>x</string>`   ⇒ 写字符串（REG_SZ）
    ``items``   `<item><value>…` 若干  ⇒ 写多个值（列表形态）
    ``unknown`` 有声明，但子元素不在上面这些里 ⇒ **我们读不懂**
    ==========  ==========================================================

    ⚠️ `unknown` 与 `None`（整个元素不存在）**是两件不同的事**：
    前者"ADMX 说了、我们没读懂"，后者"ADMX 没说"。
    写路径对这两者的处置相反 —— 前者**拒绝写**，后者按惯例取值并**标注**。
    """

    kind: str
    number: int | None = None
    text: str = ""
    items: tuple[int, ...] = ()

    @property
    def understood(self) -> bool:
        """这条声明我们读得懂吗（`unknown` ⇒ 读不懂）。"""
        return self.kind != "unknown"

    @property
    def is_delete(self) -> bool:
        return self.kind == "delete"


#: `ValueDecl.kind` 的全部取值（写在数据模型旁边，别让别的模块自己再列一遍）。
ADMX_DECL_KINDS = ("number", "true", "false", "delete", "text", "items", "unknown")


@dataclass(frozen=True)
class AdmxPolicy:
    """一条策略 = ADMX 里一个 `<policy>`。"""

    policy_id: str                  # `name` 属性（ADML 用它取显示名）
    name: str                       # 本地化后的显示名（取不到时回落成 policy_id）
    explain: str                    # 本地化后的说明
    klass: str                      # machine / user / both（ADMX 里就是小写）
    key: str                        # 注册表键
    value_name: str                 # 两态策略的值名（有 elements 时可能是空串）
    category_ref: str               # `<parentCategory ref=…>`
    admx_file: str                  # 来源文件名（排错用）
    elements: tuple[AdmxElement, ...] = ()
    enabled_value: int | None = None    # `<enabledValue><decimal value=…>`
    disabled_value: int | None = None
    enabled_list: tuple[int, ...] = ()
    disabled_list: tuple[int, ...] = ()
    true_value: int | None = None       # `<enabledValue><trueValue/>`（boolean 形态）
    false_value: int | None = None
    #: **原始**声明（`None` = ADMX 根本没写这个元素）。上面那六个字段**分不出**
    #: 「没声明」与「声明了 delete/string/读不懂」—— 而**读**这一侧正要靠这个区分
    #: 去决定「能不能按惯例 1/0 判」（见 `_falls_back_to_defaults`）。
    #: ⚠️ 2026-09-18：原来这里写的是「**写路径**靠它决定写什么」—— 写路径已移出仓库，
    #: 那句话**不再成立**，留着就是说过头。
    enabled_decl: ValueDecl | None = None
    disabled_decl: ValueDecl | None = None

    @property
    def is_two_state(self) -> bool:
        """只有启用/禁用两态、**没有** `elements` 的策略。

        实测有 **1923** 条属于这种（占 3552 的 54%）—— 界面上就是一个三态复选框。
        """
        return not self.elements


@dataclass(frozen=True)
class AdmxCategory:
    """策略树的一个节点。`name` 同时是 ADML 取显示名用的 id。"""

    name: str
    display_name: str
    parent_ref: str
    admx_file: str


@dataclass
class AdmxCatalog:
    """一个 ADMX 目录读出来的全部内容。

    `failed` **不是**可有可无的诊断信息：它是"我们少读了多少"的唯一记录
    （见模块头「不许静默少读」）。空列表 = 一个都没少读。
    """

    policies: tuple[AdmxPolicy, ...] = ()
    categories: tuple[AdmxCategory, ...] = ()
    directory: str = ""
    language: str = ""
    admx_files: tuple[str, ...] = ()
    failed: tuple[str, ...] = ()            # ["文件名：原因", ...]
    encoding_counts: dict[str, int] = field(default_factory=dict)

    _by_registry: dict[tuple[str, str], AdmxPolicy] = field(
        default_factory=dict, repr=False, compare=False)

    # ---- 查询 --------------------------------------------------------------

    def policy_by_registry(self, key: str, value_name: str) -> AdmxPolicy | None:
        """按 `(注册表键, 值名)` 反查策略 —— **「哪些设置被改过」就靠它**。

        大小写不敏感（注册表键不区分大小写，ADMX 里的写法也不统一）。
        一对 `(key, value_name)` 可能被多条策略共用，这里**返回第一条**并
        在 `policy_by_registry_all()` 里给出全部。
        """
        return self._by_registry.get((key.lower(), (value_name or "").lower()))

    def policy_by_registry_all(self, key: str, value_name: str) -> tuple[AdmxPolicy, ...]:
        """同一对 `(键, 值名)` 上的**全部**策略（不含只按 elements 值名的匹配）。"""
        pair = (key.lower(), (value_name or "").lower())
        return tuple(p for p in self.policies
                     if (p.key.lower(), p.value_name.lower()) == pair)

    def elements_by_registry(self, key: str, value_name: str) -> tuple[AdmxPolicy, tuple[AdmxElement, ...]]:
        """能解释 `(键, 值名)` 这个值的候选：两态策略 **或** 带该 elements 值名的策略。

        P0 的「对照」要的是这个：`registry.pol` 里的一条记录，往往对应
        **某条策略的某个 element**（值名在 element 上，而不是策略上）。
        """
        want_key, want_value = key.lower(), (value_name or "").lower()
        two_state: list[AdmxPolicy] = []
        with_element: list[AdmxElement] = []
        owner: list[AdmxPolicy] = []
        for policy in self.policies:
            if policy.key.lower() != want_key:
                continue
            if policy.value_name.lower() == want_value:
                two_state.append(policy)
            for element in policy.elements:
                if element.value_name and element.value_name.lower() == want_value:
                    owner.append(policy)
                    with_element.append(element)
        if two_state:
            return two_state[0], ()
        if owner:
            return owner[0], tuple(with_element)
        return None, ()

    def categories_of(self, policy: AdmxPolicy) -> tuple[str, ...]:
        """从 `category_ref` 一路往上走到根，返回显示名（**从根到叶**）。

        用来在界面上给策略分组；`category_ref` 指向的分类可能不在本目录里
        （第三方 ADMX 常见），那样就**止步**并保留已有的层级，不报错也不丢。
        """
        by_name = {c.name: c for c in self.categories}
        chain: list[str] = []
        current = policy.category_ref
        guard = 0
        while current and current in by_name and guard < 32:
            category = by_name[current]
            chain.append(category.display_name or category.name)
            current = category.parent_ref
            guard += 1
        chain.reverse()
        return tuple(chain)


# ============================================================================
# 3. 解析：ADMX（结构）＋ ADML（文案）
# ============================================================================

def _text_of(node: ET.Element | None) -> str:
    """取元素的文本（None / 空白都当空串）。"""
    return (node.text or "").strip() if node is not None else ""


def _int_attr(node: ET.Element, name: str) -> int | None:
    raw = node.get(name)
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


class _StringTable:
    """ADML 里的 `$(string.xxx)` 解析器。

    `id` 有**两种**写法，ADMX 里两种都在用：
      * 新写法（Win7+）：`<string id="xyz">…</string>`，引用写成 `$(string.xyz)`
      * 老写法：`<string id="$(string.xyz)">…</string>`
    ⇒ 建表时把两种都归一化成 `xyz`，取值时再归一化一次
      （只处理一种的话，**另一种的文案会全部取不到**，而表现只是"显示成 id"，
      很难发现）。
    """

    def __init__(self, root: ET.Element | None):
        self._map: dict[str, str] = {}
        if root is None:
            return
        for node in root.iter("string"):
            key = (node.get("id") or "").strip()
            if not key:
                continue
            self._map[_normalize_string_id(key)] = _text_of(node)

    def resolve(self, text: str) -> str:
        """把 `$(string.xyz)` 换成文案。

        **取不到就返回空串**（不是原样返回引用）—— 这一点是判据，不是风格：
        调用方普遍写成 `resolve(...) or 回落值`。若这里返回的是
        `"$(string.NoAutoUpdate)"`（非空），那么"没有 ADML 的第三方模板"
        就会把显示名变成**一串 `$(string.…)` 字面量糊在界面上**，
        而回落逻辑**永远不会触发**（本项目已栽过一次
        `or 0` 那类兜底被"真值"挡住的事故）。

        注意**只对 `$(string.x)` 这种引用形态**做这个处理：ADMX 里
        `displayName` 也可以是**字面文案**（不带 `$(`），那种原样返回。
        """
        if not text or "$(" not in text:
            return text
        match = re.fullmatch(r"\$\(string\.([^)]+)\)", text.strip())
        if not match:
            return text
        return self._map.get(_normalize_string_id(match.group(1)), "")

    def __len__(self) -> int:
        return len(self._map)


def _normalize_string_id(raw: str) -> str:
    cleaned = raw.strip()
    if cleaned.startswith("$(") and cleaned.endswith(")"):
        cleaned = cleaned[2:-1]
    if cleaned.startswith("string."):
        cleaned = cleaned[len("string."):]
    return cleaned


def _load_string_table(directory: str, admx_path: str,
                       language: str) -> _StringTable:
    """找 `<目录>\\<语言>\\<同名>.adml` 并读它的 stringTable。

    **找不到 ADML 不是错误**（第三方 ADMX 常常没带本地化）⇒ 返回空表，
    文案回落成 id。但这一步**会记日志**，不静默。
    """
    stem = os.path.splitext(os.path.basename(admx_path))[0]
    for lang in ([language] if language else []) + list(FALLBACK_LANGUAGES):
        candidate = os.path.join(directory, lang, stem + ".adml")
        if os.path.isfile(candidate):
            root = read_xml(candidate)
            found = root.find(".//stringTable")
            return _StringTable(found if found is not None else root)
    _log.debug("ADMX %s 没有配套 ADML（语言 %s），文案回落成 id",
               os.path.basename(admx_path), language)
    return _StringTable(None)


def _parse_items(node: ET.Element, strings: _StringTable) -> tuple[AdmxItem, ...]:
    """把 `<item>` 抽成 `AdmxItem`。

    ⚠️ 必须用 `iter("item")` 而**不是** `findall("item")`：`<item>` 的位置
    **两种都真实存在**：

      * `<enum id=…><item displayName=…>…</item></enum>`  ← 直接子节点
      * `<enabledValue><list><item>…</item></list></enabledValue>` ← 嵌在 `<list>` 里

    只写 `findall` 会**把 `list` 形态的取值全部读成空** —— 而表现只是
    "这条策略的选项列表是空的"，看不出是读法漏了一层。
    """
    items: list[AdmxItem] = []
    for item in node.iter("item"):
        value_node = item.find("value")
        number: int | None = None
        raw = ""
        if value_node is not None:
            decimal = value_node.find("decimal")
            if decimal is not None:
                try:
                    number = int(decimal.get("value", ""))
                except ValueError:
                    number = None
            else:
                raw = _text_of(value_node.find("string"))
        items.append(AdmxItem(
            label=strings.resolve(item.get("displayName") or ""),
            value=number, raw_value=raw))
    return tuple(items)


def _parse_elements(policy_node: ET.Element, strings: _StringTable) -> tuple[AdmxElement, ...]:
    """`<elements>` 下的 6 种形态。**认不出的形态要记日志**（不静默丢弃）。"""
    container = policy_node.find("elements")
    if container is None:
        return ()
    out: list[AdmxElement] = []
    for node in container:
        kind = node.tag if isinstance(node.tag, str) else ""
        if kind not in ELEMENT_KINDS:
            _log.warning("ADMX 里出现了没见过的 elements 形态：%r（策略 %s）——"
                         "已跳过它，但这意味着「这个设置项界面上看不到」",
                         kind, policy_node.get("name"))
            continue
        out.append(AdmxElement(
            kind=kind,
            id=node.get("id") or "",
            value_name=node.get("valueName") or "",
            required=(node.get("required") or "").lower() == "true",
            default_item=_int_attr(node, "defaultItem"),
            min_value=_int_attr(node, "minValue"),
            max_value=_int_attr(node, "maxValue"),
            items=_parse_items(node, strings) if kind in ("enum", "list") else (),
            # `boolean` 的勾选/不勾选取值：**有 `<trueValue>` 就按它**，
            # 没有才回落成 1 / 0（ADMX 惯例）。本机 307/364 有声明，
            # 所以"回落"是小概率路径，但绝不能反过来（先回落再看声明）。
            true_value=_bool_side_value(node, "trueValue"),
            false_value=_bool_side_value(node, "falseValue"),
        ))
    return tuple(out)


def _bool_side_value(node: ET.Element, tag: str) -> int | None:
    """`boolean` 元素里 `<trueValue>` / `<falseValue>` 的取值（没有就 `None`）。

    写法与策略级那两个同源（`<decimal value=…>` / `<string>` / `<delete/>`），
    所以**复用同一个解析器** —— 两边各写一遍必然分叉。
    只取得到数字的情形（本项目只写数字型；字符串型由调用方拒绝）。
    """
    decl, number, listed, sentinel = _parse_two_state_value(node, tag)
    if decl is None:
        return None
    if decl.kind in ("number", "true", "false"):
        return number if number is not None else sentinel
    if decl.kind == "items" and listed:
        return listed[0]
    return None


def _parse_two_state_value(policy_node: ET.Element, tag: str
                           ) -> tuple[ValueDecl | None, int | None,
                                      tuple[int, ...], int | None]:
    """`<enabledValue>` / `<disabledValue>` 的**全部**写法。

    返回 `(声明, 单个 decimal 值, list 里的全部值, trueValue/falseValue 的哨兵)`。

    🔴 **第一个返回值是 2026-09-18 加的，它修的是一个"看不见"的缺口。**

    原来只返回后三项，于是下面三种情形**返回值完全一样**（都是
    `(None, (), None)`），调用方**分不出来**：

    ============================  =====================================
    ADMX 里写的                   含义
    ============================  =====================================
    整个 `<enabledValue>` 没有     ADMX **没说**启用该写什么
    `<enabledValue><delete/>`     ADMX 说：启用 = **删掉这个值**
    `<enabledValue><string>x</>`  ADMX 说：启用 = 写字符串 "x"
    ============================  =====================================

    读的时候分不出来只影响"状态说不清"（保守，可接受）；**写的时候分不出来
    就会写错** —— 把"删掉"当成"没声明"→ 按惯例写 1，那是在域里**真改错东西**。
    ⇒ 所以 `ValueDecl` 必须把"声明了什么"如实带出来。
    （旧的三项仍然返回，是为了不动已经在用的 `evaluate_policy`。）

    `trueValue` / `falseValue` 是**无文本元素**（boolean 形态），
    语义是"写 1 / 写 0"，用一个哨兵把方向带出来。
    """
    node = policy_node.find(tag)
    if node is None:
        return None, None, (), None
    decimal = node.find("decimal")
    if decimal is not None:
        try:
            number = int(decimal.get("value", ""))
        except ValueError:
            return ValueDecl(kind="number", number=None), None, (), None
        return ValueDecl(kind="number", number=number), number, (), None
    if node.find("trueValue") is not None:
        return ValueDecl(kind="true", number=1), None, (), 1
    if node.find("falseValue") is not None:
        return ValueDecl(kind="false", number=0), None, (), 0
    if node.find("delete") is not None:
        return ValueDecl(kind="delete"), None, (), None
    text = node.find("string")
    if text is not None:
        return (ValueDecl(kind="text", text=(text.text or "")), None, (), None)
    listed = tuple(item.value for item in _parse_items(node, _StringTable(None))
                   if item.value is not None)
    if listed:
        return ValueDecl(kind="items", items=listed), None, listed, None
    # 有 `<enabledValue>` 但子元素一个都不是我们认识的那几种。
    # ⚠️ **不许**当成"没声明"（那会让写路径按惯例写 1）—— 如实记成"不认识的形态"。
    return ValueDecl(kind="unknown"), None, (), None


def _explain_of(policy_node: ET.Element, strings: _StringTable) -> str:
    """策略的说明文字。**属性名是 `explainText`，不是 `explain`。**

    🔴 2026-09-17 实测：本机 224 个 ADMX 里 `explain*` 类属性共出现 **3589 次，
    全部是 `explainText`，`explain` 零次**。而公开 schema 的记载里有 `explain`
    ⇒ 两个都读（`explainText` 优先）。

    ⚠️ 这个坑的形态值得记：读错属性名**不报错**、`get()` 返回 `None`、
    回落成空串 —— 界面上表现为"说明那一栏是空的"，看起来像**系统模板本来就没写说明**。
    本项目的判据（`test_policy_fields_are_parsed`）正是拿真实属性名当夹具才抓到的。
    """
    return strings.resolve(policy_node.get("explainText")
                           or policy_node.get("explain") or "")


def parse_admx_file(path: str, directory: str, language: str) -> tuple[
        list[AdmxPolicy], list[AdmxCategory]]:
    """读一个 `.admx`（＋配套 `.adml`）→ 策略与分类。

    抛 `AdToolError` 表示**这个文件读不了**；由 `load_catalog` 决定记进 `failed`。
    """
    strings = _load_string_table(directory, path, language)
    root = read_xml(path)
    if root.tag != "policyDefinitions":
        raise AdToolError(
            f"{os.path.basename(path)} 的根节点是 <{root.tag}>，"
            "不是 <policyDefinitions> —— 这不像一个 ADMX 文件。")

    categories: list[AdmxCategory] = []
    for node in root.findall("./categories/category"):
        parent = node.find("parentCategory")
        categories.append(AdmxCategory(
            name=node.get("name") or "",
            display_name=strings.resolve(node.get("displayName") or ""),
            parent_ref=(parent.get("ref") or "") if parent is not None else "",
            admx_file=os.path.basename(path)))

    name = os.path.basename(path)
    policies: list[AdmxPolicy] = []
    for node in root.findall("./policies/policy"):
        enabled_decl, enabled, enabled_list, true_value = _parse_two_state_value(
            node, "enabledValue")
        disabled_decl, disabled, disabled_list, false_value = _parse_two_state_value(
            node, "disabledValue")
        parent = node.find("parentCategory")
        policy_id = node.get("name") or ""
        policies.append(AdmxPolicy(
            policy_id=policy_id,
            name=strings.resolve(node.get("displayName") or "") or policy_id,
            explain=_explain_of(node, strings),
            klass=(node.get("class") or "machine").strip().lower(),
            key=node.get("key") or "",
            value_name=node.get("valueName") or "",
            category_ref=(parent.get("ref") or "") if parent is not None else "",
            admx_file=name,
            elements=_parse_elements(node, strings),
            enabled_value=enabled,
            disabled_value=disabled,
            enabled_list=enabled_list,
            disabled_list=disabled_list,
            true_value=true_value,
            false_value=false_value,
            enabled_decl=enabled_decl,
            disabled_decl=disabled_decl,
        ))
    return policies, categories


def load_catalog(directory: str | None = None, language: str = "zh-CN") -> AdmxCatalog:
    """读整个 ADMX 目录。

    * `directory` 默认 `DEFAULT_ADMX_DIR`；
    * **目录不存在 ⇒ 抛 `AdToolError`**（不是一个空目录 —— 空目录会让界面
      显示"一条策略都没有"，而真相是"我们没找到原料"，两者必须能分清）；
    * 单个文件坏掉 ⇒ 记进 `AdmxCatalog.failed` 并继续读其余文件，
      **不中止、也不隐瞒**。
    """
    target = directory or DEFAULT_ADMX_DIR
    if not os.path.isdir(target):
        raise AdToolError(
            f"找不到 ADMX 目录：{target}\n\n"
            "组策略的「管理模板」需要 ADMX/ADML 文件才能显示设置名称。\n"
            "· 正常 Windows 自带一份（本机路径就是上面那个）；\n"
            "· 若确实没有（某些精简/家庭版本），可从微软官网下载"
            "「Administrative Templates (.admx)」模板包，解压后把目录指过来。")

    admx_files = sorted(f for f in os.listdir(target) if f.lower().endswith(".admx"))
    policies: list[AdmxPolicy] = []
    categories: list[AdmxCategory] = []
    failed: list[str] = []
    encodings: dict[str, int] = {}

    for name in admx_files:
        path = os.path.join(target, name)
        try:
            found_policies, found_categories = parse_admx_file(path, target, language)
        except AdToolError as exc:
            failed.append(f"{name}：{exc.message}")
            _log.warning("ADMX 读失败，已记进 failed（不静默跳过）：%s：%s", name, exc.message)
            continue
        policies.extend(found_policies)
        categories.extend(found_categories)

    #: 编码分布 —— 让"这个目录里有三种编码"在界面上看得见。
    #: ⚠️ 不数一遍的后果：`utf-16` 那两个文件哪天读法退化，**没有任何信号**
    #: （实测分布：utf-8+bom 153 / utf-8 69 / utf-16-le+bom 2）。
    encodings: dict[str, int] = {}
    for name in admx_files:
        try:
            with open(os.path.join(target, name), "rb") as handle:
                key = detect_encoding(handle.read(4))
            encodings[key] = encodings.get(key, 0) + 1
        except OSError:
            pass

    catalog = AdmxCatalog(
        policies=tuple(policies),
        categories=tuple(categories),
        directory=target,
        language=language,
        admx_files=tuple(admx_files),
        failed=tuple(failed),
        encoding_counts=encodings,
    )
    index: dict[tuple[str, str], AdmxPolicy] = {}
    for policy in catalog.policies:
        index.setdefault((policy.key.lower(), policy.value_name.lower()), policy)
    catalog._by_registry = index
    _log.info("ADMX 目录已读：%d 个文件 / %d 条策略 / %d 个分类 / 失败 %d（语言 %s）",
              len(admx_files), len(catalog.policies), len(catalog.categories),
              len(catalog.failed), language)
    return catalog


# ============================================================================
# 4. 「这条注册表值对应哪条策略、是什么状态」
# ============================================================================

#: `evaluate_policy` 的三种结果 + 一种「说不清」
STATE_UNSET = "unset"       # 落盘数据里根本没有这条 ⇒ 未配置
STATE_ENABLED = "enabled"
STATE_DISABLED = "disabled"
STATE_UNKNOWN = "unknown"   # 有值但和 ADMX 说的对不上（第三方写进去的 / ADMX 版本不同）


def evaluate_policy(policy: AdmxPolicy,
                    entries: Iterable[tuple[str, str, int, bytes]]) -> str:
    """给定落盘记录，判断这条策略是「未配置 / 已启用 / 已禁用 / 说不清」。

    `entries` 是 `(注册表键, 值名, 类型码, 数据)` 的可迭代对象 —— 形状与
    `registry.pol` 里的一条记录一一对应。**本函数不认识 PReg 格式**
    （解格式是另一个模块的事），这样它可以被纯数据单测。

    判定顺序（**顺序本身是判据**）：

    1. 先在两态策略的 `valueName` 上找；
    2. 再在 `elements` 的值名上找；
    3. 找得到但要和 `enabledValue` / `disabledValue` 比 —— 对不上返回
       `STATE_UNKNOWN`，**不许**猜成"已启用"（`or 0` 那类兜底是本项目的红线）；
    4. 有 `elements` 的策略：只要**任何一个 element 的值名**有落盘记录，
       就算这条策略"已配置"（ADMX 的语义就是如此），状态取 `STATE_ENABLED`。
    """
    key = policy.key.lower()
    matched = [(value_name, type_code, data) for (k, value_name, type_code, data) in entries
               if k.lower() == key]

    def _as_int(data: bytes) -> int | None:
        return int.from_bytes(data[:4], "little") if len(data) >= 4 else None

    if policy.value_name:
        for value_name, _type_code, data in matched:
            if value_name.lower() != policy.value_name.lower():
                continue
            number = _as_int(data)
            if policy.true_value is not None or policy.false_value is not None:
                # boolean 形态：ADMX 说「写 1 = 启用」
                if number == (policy.true_value if policy.true_value is not None else 1):
                    return STATE_ENABLED
                if number == (policy.false_value if policy.false_value is not None else 0):
                    return STATE_DISABLED
                return STATE_UNKNOWN
            if policy.enabled_value is not None and number == policy.enabled_value:
                return STATE_ENABLED
            if policy.disabled_value is not None and number == policy.disabled_value:
                return STATE_DISABLED
            if _falls_back_to_defaults(policy):
                # ADMX 既没声明启用值、也没声明禁用值（本机真实样本里有，
                # 例如「删除任务管理器」「禁止访问控制面板」）⇒ 按**惯例**判。
                # 长注释与证据在 `DEFAULT_ENABLED_NUMBER` 那里。
                # ⚠️ 2026-09-18：原来这句后面还写着「与写路径共用同一对常量，
                # 读回来的结论和写下去的东西**必然一致**」—— **写路径已移出仓库**
                # ⇒ 那个对称性**不再存在**。留着它就是**说过头**
                # （红线：名字/说明不许说谎）。
                if number == DEFAULT_ENABLED_NUMBER:
                    return STATE_ENABLED
                if number == DEFAULT_DISABLED_NUMBER:
                    return STATE_DISABLED
            return STATE_UNKNOWN

    if policy.elements:
        element_names = {e.value_name.lower() for e in policy.elements if e.value_name}
        for value_name, _type_code, _data in matched:
            if value_name.lower() in element_names:
                return STATE_ENABLED
    return STATE_UNSET


# ============================================================================
# 4. **ADMX 未声明取值时的惯例兜底**（只服务「读」这一侧）
# ============================================================================
#
# 🔴 2026-09-18：已定「**这个工具不做组策略编辑**」⇒ 本节原来的主体
#    （**写回计划**：`PolicyValue` / `PolicyPatch` / `plan_policy_state` /
#    `_decl_writes` / `_element_writes` / `_truthy`，以及展示映射 `state_word`）
#    **已移出仓库归档**（回滚件未进本仓库）。
#    ⇒ ⚠️ **上面那几个名字现在在本仓库里再也查不到**，那不是笔误。
#    本节只剩下面这条**读路径真的会走**的分支所需的两个常量与一个判据函数。

#: ADMX **没有声明** `<enabledValue>` / `<disabledValue>` 时，本工具按惯例取的值。
#:
#: 🔴 这不是"兜底"，是**格式自身的默认**，而且证据是查来的（2026-09-18）：
#:
#:   1. ADM 时代的规范（微软出版的技术资料原文）：
#:      「Unless you set the keywords VALUEON and VALUEOFF, the policy editor
#:        creates the policy as a REG_DWORD value: **Enabled. Sets the value to
#:        0x01**」—— 启用写 1 是明文写着的。
#:   2. 「Disabled ... **This setting is saved in the registry**」（MS Learn
#:      《Working with Group Policies》对三个状态的说明）⇒ 禁用**必须有落盘值**，
#:      否则"禁用"与"未配置"在字节层无法区分（而规范明说"未配置"是删除）。
#:   3. 本机 3552 条真实策略里，绝大多数两态策略都显式声明了取值；
#:      只有少数只写 `valueName` 的（如「删除任务管理器」）落到这条惯例上。
#:
#: ⚠️ **代价与边界（必须让使用者看见）**：
#:    * 惯例只是惯例 —— 界面**必须标注**「ADMX 未声明取值，按默认 1/0」。
#:      ✅ 这条**仍然有效**：本工具的「看改过哪些设置」正是靠它把这类策略的
#:      状态说清楚，而不是把"我们按惯例判的"混进"盘上写的就是这个"。
#:    * ~~编辑对话框必须把要写的字节级内容显示出来~~ · ~~真域验收：拿一条这种
#:      策略真改一次~~ —— **两条随写侧一起作废**（2026-09-18：本工具不做编辑）。
DEFAULT_ENABLED_NUMBER = 1
DEFAULT_DISABLED_NUMBER = 0


def _falls_back_to_defaults(policy: AdmxPolicy) -> bool:
    """这条策略的"启用/禁用取值"ADMX **完全没声明**，只能按惯例。

    判据（四个条件缺一不可）：

    * 两个 `ValueDecl` 都**不存在**（注意：``ValueDecl(kind="unknown")``
      是"声明了我们读不懂"，**不算**没声明）；
    * `trueValue` / `falseValue` 都没有；
    * 策略有 `valueName`（没有值名就无处可写，那是另一档）；
    * 策略**没有** `elements`（有 elements 的策略，落盘的是各个 element
      的值，"启用/禁用"由元素表达，套用 1/0 会写出一条多余的记录）。
    """
    return (policy.enabled_decl is None and policy.disabled_decl is None
            and policy.true_value is None and policy.false_value is None
            and bool(policy.value_name) and not policy.elements)
