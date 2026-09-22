# -*- coding: utf-8 -*-
"""gpo_settings.py —— 「这个 GPO 改过哪些设置」（`registry.pol` × ADMX 的对照）

## 它把哪三样东西接起来

| 来源 | 提供什么 | 在哪个模块 |
|---|---|---|
| ADMX / ADML | 策略 ⇄ 注册表值的**映射表**，以及「启用 / 禁用」的判据 | `admx_backend` |
| `Registry.pol` | 盘上**实际写了**哪些注册表值（二进制 PReg） | `preg_backend` |
| SYSVOL | 上面那两个文件在**哪**（UNC 路径） | 本模块 |

回答的问题：**这个 GPO 改过哪些设置、每条现在是什么状态**。

## 为什么 SYSVOL 路径在这一层算，而不是塞进 `gpo_backend`

`gpo_backend` 是 **GPMC 的 COM 封装**，它的边界写得很明确：「不碰 SYSVOL 的文件」。
本模块干的是**文件**的事（拼 UNC 路径 + 读字节），与 COM 无关 ⇒ 分开。

两者的接缝只有**两个值**：`(DNS 域名, GPO 的 GUID)` —— 都由 `gpo_backend` 提供
（`session.domain_name`、`GpoInfo.guid`），所以本模块**不需要** import 它。
（避免互相 import 的环，也让本模块能被纯数据单测。）

## SYSVOL 路径的构成（**这是约定，不是猜的**）

```
\\\\<DNS域名>\\SYSVOL\\<DNS域名>\\Policies\\{<GUID>}\\Machine\\Registry.pol
                                             \\User\\Registry.pol
```

⚠️ **未在真域验证**（本机未加域，碰不到 SYSVOL）。所以：

* 本模块**只用**这一条构成法；**不**拿 `GpoInfo.path` 去凑
  —— GPMC 的 `IGPMGPO.Path` 到底是什么（LDAP 路径还是 UNC）我**没验过**，
  用没验过的东西拼路径，错了的表现是「文件找不到」，而那种报错会被读成「权限问题」；
* `tools/probe_gpo_settings.py` 会**把两者并排打印**，好让第一次真域运行就能看出
  它们是否一致 —— 那是一次**判决**，不是装饰。

GUID 的形状会被**校验**（8-4-4-4-12 十六进制），不符合就抛：
一个畸形 GUID 拼出来的路径**不会报错**，只会"找不到文件" —— 又是一次静默。

## 「哪些设置被改过」的判据方向：**从记录出发，不是从策略出发**

`registry.pol` 里有什么，就报什么（**以盘上为准**），逐条到 ADMX 里找归属：

* 找得到 ⇒ 给出本地化名称、分类路径、以及状态（启用 / 禁用 / 说不清）；
* **找不到 ⇒ 也报**（`SettingItem.explained == False`），**一条都不许丢**。
  第三方策略、域控上的 ADMX 比本机旧、纯手工写进去的注册表值都会落到这一类。
  「界面上看不到它」正是本项目最忌讳的那种**静默少读**。

反过来（把 3552 条策略全列出来、再标哪些没配）是**另一个功能**，不做：
那会让人以为"这里能看到所有设置"，而实际能看到的是"盘上写了的那些"。

## 边界

* **只读**：不连域、不碰 COM、不导入 PyQt、**不写任何东西**；
* 不解析 `GptTmpl.inf`（安全策略是另一条线，P1 再说）；
* 状态判定的**唯一实现**在 `admx_backend.evaluate_policy()` —— 本模块**不重写**它，
  只负责把同一作用域的记录凑齐了喂给它。
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Iterable

from admx_backend import (
    STATE_DISABLED,
    STATE_ENABLED,
    STATE_UNKNOWN,
    STATE_UNSET,
    AdmxCatalog,
    AdmxPolicy,
    evaluate_policy,
)
from preg_backend import PregEntry, display_value, is_empty_preg, parse_preg
from utils import AdToolError, get_logger

_log = get_logger("gpo_settings")

__all__ = [
    "SCOPE_MACHINE",
    "SCOPE_USER",
    "SCOPES",
    "POL_FILENAME",
    "SettingItem",
    "GpoSettings",
    "sysvol_gpo_dir",
    "pol_paths",
    "collect_settings",
    "read_gpo_settings",
]

SCOPE_MACHINE = "Machine"
SCOPE_USER = "User"

#: 两个作用域。**顺序固定**：界面上机器策略在前（它管的是"这台机器"，
#: 与人是谁无关，排查时先看它）。
SCOPES: tuple[str, ...] = (SCOPE_MACHINE, SCOPE_USER)

#: 策略文件名。**写死是对的** —— 它不是可选配置，是协议的一部分。
POL_FILENAME = "Registry.pol"

#: SYSVOL 共享名与策略目录名（同样是协议的一部分）。
SYSVOL_SHARE = "SYSVOL"
POLICIES_DIR = "Policies"

#: GUID 的形状（**不带**花括号的那一部分）。**必须校验**：
#: 畸形 GUID 拼出来的路径不报错，只"找不到文件"。
_GUID_RE = re.compile(r"^([0-9a-fA-F]{8})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-"
                      r"([0-9a-fA-F]{4})-([0-9a-fA-F]{12})$")

#: 每个作用域在 GPO 目录下的子目录名（与 `SCOPES` 同源，不另起一份）。
_SCOPE_DIRS = {SCOPE_MACHINE: SCOPE_MACHINE, SCOPE_USER: SCOPE_USER}

#: 注册表根：机器策略落在 `HKEY_LOCAL_MACHINE`，用户策略落在 `HKEY_CURRENT_USER`。
#: ⚠️ 这不是"猜" —— `registry.pol` 的分作用域存放**就是**这个语义
#:   （策略引擎把 Machine 那份写进 HKLM、User 那份写进 HKCU）。
_SCOPE_HIVES = {SCOPE_MACHINE: "HKEY_LOCAL_MACHINE", SCOPE_USER: "HKEY_CURRENT_USER"}

#: 作用域 → 界面用词。**只在这里映射一次** —— 面板再映射一遍就是两份真相，
#: 改了一处忘另一处，界面上就会出现「Machine」和「计算机」混着显示。
_SCOPE_WORDS = {SCOPE_MACHINE: "计算机", SCOPE_USER: "用户"}


# ============================================================================
# 1. SYSVOL 路径
# ============================================================================

def normalize_guid(raw: str) -> str:
    """把 GPO 的 GUID 规范化成 SYSVOL 里那种带花括号的大写形式。

    ⚠️ **不接受"看起来差不多"的输入**：不是 GUID 就抛。
    不校验的后果是拼出一条**格式正确但指向不存在位置**的路径，
    而那种失败在界面上长得像「没有权限」。
    """
    text = (raw or "").strip()
    if text.startswith("{") or text.endswith("}"):
        # 🔴 花括号**必须成对**。只有一边，通常说明这个串是从别处**截断**来的
        #    （复制粘贴常事）—— 替它补上那一边等于**替调用方猜**它想指哪个 GPO，
        #    而猜错了只会表现为"找不到文件"。所以不成对就拒绝。
        if not (text.startswith("{") and text.endswith("}")):
            raise AdToolError(
                "GPO 的 GUID 花括号不成对：%r\n"
                "（要么两边都没有、要么两边都有。）这不像是完整的 GUID，"
                "更像是从别处截断粘过来的 —— 本实现不替调用方补全。" % (raw,))
        text = text[1:-1]
    match = _GUID_RE.match(text)
    if not match:
        raise AdToolError(
            "这不是一个 GPO 的 GUID：%r\n"
            "（期望 8-4-4-4-12 的十六进制，可带成对的花括号。）"
            "—— 拿它拼 SYSVOL 路径只会拼出一个「指向不存在位置」的路径，"
            "所以这里直接拒绝，不猜。" % (raw,))
    joined = "".join(match.groups()).upper()
    return "{%s-%s-%s-%s-%s}" % (joined[0:8], joined[8:12], joined[12:16],
                                 joined[16:20], joined[20:32])


def sysvol_gpo_dir(domain_dns: str, guid: str, root: str = "") -> str:
    """GPO 在 SYSVOL 上的目录（UNC）。

    ``domain_dns`` 必须是 **DNS 域名**（如 ``corp.example.com``）——
    它同时出现在 UNC 的**主机名**与**路径**两处，这是 SYSVOL 的约定
    （``\\\\corp.example.com\\SYSVOL\\corp.example.com\\Policies\\{…}``）。
    ⚠️ **不要**传 NetBIOS 名：那会把 UNC 变成另一个位置。

    ``root`` —— 共享名以上那一段的替代品，**只有演示域与离线装置会传**：

    ==================  =========================================================
    ``root``            拼出来的路径
    ==================  =========================================================
    空（默认，真域）     ``\\\\<域名>\\SYSVOL\\<域名>\\Policies\\{GUID}``
    非空（演示域）       ``<root>\\<域名>\\Policies\\{GUID}``
    ==================  =========================================================

    ⚠️ **``root`` 以下的部分两边逐字相同** —— 这正是它存在的意义：
    "共享名以下"的路径构成是协议的一部分，演示域不许自己再写一套；
    能变的只有"那个共享挂在哪儿"。于是「拼路径 → 解 PReg → 写回」
    整条链在演示模式下走的是同一份实现，唯一差别是传输介质。
    """
    domain = (domain_dns or "").strip()
    if not domain:
        raise AdToolError("没有域名，算不出这个 GPO 在 SYSVOL 上的位置。")
    normalized = normalize_guid(guid)
    base = (root or "").strip()
    if base:
        # 演示域：把"共享"换成一个本地目录。⚠️ 这里**不**做 `abspath()`
        # 之类的"规范化"——那是调用方给进来的根，替它改造等于换位置。
        return os.path.join(base, domain, POLICIES_DIR, normalized)
    return "\\\\%s\\%s\\%s\\%s\\%s" % (domain, SYSVOL_SHARE, domain,
                                      POLICIES_DIR, normalized)


def pol_paths(gpo_dir: str) -> tuple[tuple[str, str], ...]:
    """``(作用域, Registry.pol 的完整路径)`` 两张，顺序同 `SCOPES`。

    ⚠️ 这里**不判断文件在不在** —— 存在性由 `read_gpo_settings()` 分别记录。
    把"路径算不出来"与"文件不存在"混在一起，会让人分不清是拼错了还是域里没有。
    """
    base = (gpo_dir or "").rstrip("\\/")
    if not base:
        raise AdToolError("没有 GPO 目录，算不出策略文件的位置。")
    return tuple((scope, os.path.join(base, _SCOPE_DIRS[scope], POL_FILENAME))
                 for scope in SCOPES)


# ============================================================================
# 2. 数据模型
# ============================================================================

#: 状态码 → 界面用词。**单一映射源**（面板不重复一份）。
#: 四个码同源于 `admx_backend`；认不出来就**原样显示**，不猜。
_STATE_WORDS = {
    STATE_ENABLED: "已启用",
    STATE_DISABLED: "已禁用",
    STATE_UNSET: "未配置",
    STATE_UNKNOWN: "状态对不上",
}


@dataclass(frozen=True)
class SettingItem:
    """`registry.pol` 里的一条记录 ＋ 它在 ADMX 里的归属。

    🔴 **`explained == False` 的条目也要报**（`policy_id` 为空）：
    「盘上有这条、但本地 ADMX 解释不了它」。这一类的正确处置是**显示出来**
    并注一句「ADMX 里没有收录」，**不是**过滤掉 —— 过滤掉就是静默少读。
    """

    scope: str
    key: str
    value_name: str
    type_code: int
    type_name: str
    value_display: str
    #: ADMX 里找到的归属。空串 = **没找到**（见 `explained`）。
    policy_id: str = ""
    name: str = ""
    category_path: tuple[str, ...] = ()
    admx_file: str = ""
    #: 状态；**只有找到归属时才有意义**（`explained` 为假时是空串）。
    state: str = ""
    #: 值解不开的原因（空 = 没问题）。解不开时 `value_display` 是**原始字节的十六进制**，
    #: 不丢数据、也不假装读懂了。
    value_problem: str = ""

    @property
    def explained(self) -> bool:
        """这条记录在 ADMX 里找不找得到归属。"""
        return bool(self.policy_id)

    @property
    def registry_path(self) -> str:
        """完整的注册表路径（作用域决定根键）。**仅供展示与排错。**"""
        hive = _SCOPE_HIVES.get(self.scope, self.scope or "?")
        if self.value_name:
            return "%s\\%s\\%s" % (hive, self.key, self.value_name)
        return "%s\\%s" % (hive, self.key)

    @property
    def label(self) -> str:
        """界面上显示的名字：**有归属就用策略名，没有就回落成值名**。

        ⚠️ 回落成值名（而不是空串或"—"）是判据：值名是**盘上真实写着的东西**，
        空串会让人以为"这条记录没有名字"，而它只是"ADMX 里没收录"。
        """
        return self.name or self.policy_id or self.value_name or "（无名值）"

    @property
    def scope_label(self) -> str:
        """作用域的界面用词。认不出来**原样返回**（不猜、也不吞）。"""
        return _SCOPE_WORDS.get(self.scope, self.scope or "（未知作用域）")

    @property
    def state_label(self) -> str:
        """状态的界面用词。

        ⚠️ **没找到归属时返回空串，不回落成"未配置"** —— 「ADMX 里没有这条」
        与「这条没配」是两件事，说成后者就是**替使用者下了一个相反的结论**。
        """
        if not self.state:
            return ""
        return _STATE_WORDS.get(self.state, self.state)


@dataclass
class GpoSettings:
    """一个 GPO 的「改过的设置」清单 ＋ **读的过程记录**。

    ⚠️ `files` / `empty_files` / `missing_files` / `failed` **不是**诊断装饰：
    它们回答的是「**我们有没有看漏**」。四者必须分清：

    | 字段 | 含义 |
    |---|---|
    | `files` | 读到了、解析成功的 |
    | `empty_files` | 存在但是 **0 字节** ⇒ 这个作用域没有管理模板设置（**正常**）|
    | `missing_files` | 位置**不存在** ⇒ 可能这个 GPO 没这一侧，也可能路径算错了（**要人看**）|
    | `failed` | 存在但**读不了 / 解析失败** ⇒ 我们少看了（**必须显示**）|
    """

    gpo_dir: str = ""
    display_name: str = ""
    items: tuple[SettingItem, ...] = ()
    files: tuple[str, ...] = ()
    empty_files: tuple[str, ...] = ()
    missing_files: tuple[str, ...] = ()
    failed: tuple[str, ...] = field(default_factory=tuple)

    @property
    def changed(self) -> tuple[SettingItem, ...]:
        """在 ADMX 里**有归属**的那些（= 界面上"改过的设置"主列表）。"""
        return tuple(item for item in self.items if item.explained)

    @property
    def unexplained(self) -> tuple[SettingItem, ...]:
        """盘上有、但本地 ADMX 解释不了的（**要显示出来，不是丢掉**）。"""
        return tuple(item for item in self.items if not item.explained)

    @property
    def is_conclusive(self) -> bool:
        """这次读取**是否能下结论**。

        判据：一个文件都没读成功、也没有"空文件"这种正常情形 ⇒ 说明我们
        **什么都没看到**，此时"这个 GPO 没改过设置"是**不能说的**。
        （"0 条"与"没读到"必须分开 —— 本项目已栽过 `or 0` 那类兜底。）
        """
        return bool(self.files or self.empty_files)


# ============================================================================
# 3. 对照：记录 → 归属
# ============================================================================

def _item_of(scope: str, entry: PregEntry, policy: AdmxPolicy | None,
             catalog: AdmxCatalog | None, state: str) -> SettingItem:
    """把一条记录 ＋ 它的归属拼成 `SettingItem`（**值解不开也照样产出**）。"""
    try:
        shown = display_value(entry)
        problem = ""
    except AdToolError as exc:
        # ⚠️ 这不是"吞掉异常"：原始字节**原样保留**在 value_display 里，
        #    原因**写在字段上**，界面能显示。丢数据才是静默。
        shown = entry.data.hex(" ")
        problem = exc.message
        _log.warning("策略 %s 的值 %s\\%s 解释不了（已回落成十六进制原文）：%s",
                     scope, entry.key, entry.value_name, exc.message)

    if policy is None:
        return SettingItem(scope=scope, key=entry.key, value_name=entry.value_name,
                           type_code=entry.type_code, type_name=entry.type_name,
                           value_display=shown, value_problem=problem)

    return SettingItem(
        scope=scope, key=entry.key, value_name=entry.value_name,
        type_code=entry.type_code, type_name=entry.type_name,
        value_display=shown, value_problem=problem,
        policy_id=policy.policy_id,
        name=policy.name or policy.policy_id,
        category_path=catalog.categories_of(policy) if catalog is not None else (),
        admx_file=policy.admx_file,
        state=state,
    )


def collect_settings(catalog: AdmxCatalog,
                     scoped_entries: Iterable[tuple[str, PregEntry]]
                     ) -> tuple[SettingItem, ...]:
    """把 ``(作用域, 记录)`` 逐条对照成 `SettingItem`。**纯数据、可单测。**

    ⚠️ 状态判定按**作用域分组**：机器策略与用户策略可能落在**同一个注册表键**上
    （两侧的 `Registry.pol` 是两份文件），把两个作用域的记录混在一起喂给
    `evaluate_policy()` 会让 A 侧的值参与 B 侧的判定。
    ⇒ 分组，每组各自判定。

    ⚠️ **每条记录都产出一个 item**，一条不丢（找不到归属的 `explained` 为假）。
    """
    rows = list(scoped_entries)
    by_scope: dict[str, list[PregEntry]] = {}
    for scope, entry in rows:
        by_scope.setdefault(scope, []).append(entry)

    tuples_by_scope = {scope: [e.as_tuple for e in group]
                       for scope, group in by_scope.items()}

    out: list[SettingItem] = []
    for scope, entry in rows:
        policy, _elements = catalog.elements_by_registry(entry.key, entry.value_name)
        state = ""
        if policy is not None:
            state = evaluate_policy(policy, tuples_by_scope[scope])
            if state == STATE_UNSET:              # pragma: no cover —— 见下
                # 🔴 理论上到不了这里：能命中 `elements_by_registry()` 就说明
                #    这条记录本身就在那个键上，`evaluate_policy()` 一定看得见它。
                #    真出现说明两个函数的判据口径**已经分叉**了 ——
                #    这时候**不许**当成"未配置"混过去（那会让一条真实存在的
                #    记录在界面上显示成"没配"），要如实标成"说不清"。
                state = STATE_UNKNOWN
        out.append(_item_of(scope, entry, policy, catalog, state))
    return tuple(out)


# ============================================================================
# 4. 读一个 GPO 的目录
# ============================================================================

def _read_one_scope(scope: str, path: str
                    ) -> tuple[list[tuple[str, PregEntry]], str]:
    """读一个作用域的策略文件。返回 ``(记录, 分类)``，分类 ∈ ``ok/empty/missing/failed``。

    ⚠️ **分类必须由这里给出**，不许让调用方"看 items 空不空"去猜：
    0 条与读失败在界面上长得一样，而处置完全不同（一个是正常、一个要人查）。
    """
    if not os.path.isfile(path):
        return [], "missing"
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        return [], "failed:%s" % exc

    if is_empty_preg(raw):
        return [], "empty"
    try:
        entries = parse_preg(raw, source=path)
    except AdToolError as exc:
        return [], "failed:%s" % exc.message
    return [(scope, entry) for entry in entries], "ok"


def read_gpo_settings(catalog: AdmxCatalog, gpo_dir: str,
                      display_name: str = "") -> GpoSettings:
    """读某个 GPO 目录下的两个 `Registry.pol`，对照 ADMX，产出「改过的设置」。"""
    result = GpoSettings(gpo_dir=gpo_dir, display_name=display_name)
    rows: list[tuple[str, PregEntry]] = []

    for scope, path in pol_paths(gpo_dir):
        entries, verdict = _read_one_scope(scope, path)
        if verdict == "ok":
            result.files += (path,)
            rows.extend(entries)
        elif verdict == "empty":
            result.empty_files += (path,)
        elif verdict == "missing":
            result.missing_files += (path,)
        else:
            reason = verdict.split(":", 1)[1]
            result.failed += ("%s：%s" % (path, reason),)
            _log.warning("策略文件读失败（已记进 failed，不静默跳过）：%s：%s",
                         path, reason)

    result.items = collect_settings(catalog, rows)
    _log.info("GPO 设置已读：%d 条（其中有 ADMX 归属 %d 条）/ 读成功 %d 个文件 / "
              "失败 %d 个",
              len(result.items), len(result.changed),
              len(result.files), len(result.failed))
    return result
