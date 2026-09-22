# -*- coding: utf-8 -*-
"""preg_backend.py —— `registry.pol`（PReg 二进制）的**只读**解析器

## 它解决的是哪一类问题

组策略的「管理模板」设置，在磁盘上**只以注册表值的形式**存在
（`<GPO 目录>\\Machine\\Registry.pol` 与 `\\User\\Registry.pol`）。
`admx_backend.py` 给出「策略 ⇄ 注册表值」的**映射表**；本模块把盘上那份
**记录**读出来。两者一对照，就能回答「**这个 GPO 改过哪些设置**」。

## 🔴 为什么自己写，而不是用现成的 `registrypol`

（判据见 `SKILL: library-first-check` —— 「复用 > 自造」要**留证据**，这次留的是**反向证据**。）

`registrypol`（PyPI，Apache-2.0、零依赖）**已做过往返保真实验**，结论是**不能复用**：

* **正例**：本机三个**微软产真实样本**做 `load → to_bytes()` ⇒ **往返逐字节一致** ✅；
* 🔴 **反例（自己按格式构造）**：它 `policy.py` 里用
  `re.findall(rb'(\\x5b\\x00.*?\\x5d\\x00)', …)` 切条目，**没加 `re.S`** ⇒
  值的**数据里一旦出现 `0x0A`，整条被丢**（单条 → 解析出 0 条、往返只剩 8 字节头；
  后面还有条目 → **前一条无声消失**）。而 `REG_BINARY` 的数据是**任意字节**，
  442 字节的规则块命中 `0x0A` 的概率约 **82%**。
* 而这个格式的产物**将来要写回 SYSVOL**（P1）⇒ 缺陷表现是「**策略条目无声消失**」。
  ⇒ **判决：自写**（格式已被那次实验**字节级摸清**，8 个用例直接变成实现的判据）。

> 顺带记一条方法论：本机 6 个真实样本里 `0x0A` 出现 **0 次** ——
> 所以「真实样本往返一致」**证明不了保真**。真实样本往往**不覆盖边界字节**，
> 负例必须自己造（见 `tests/test_preg_backend.py` 的 `TestDataMayContainAnyByte`）。

## 格式（公开规范 `[MS-GPREG]`；**本机 6 个真实样本实测**）

```
文件 = 头 + 条目*
头   = "PReg" + 01 00 00 00                     （8 字节，版本 1）
条目 = 5B 00 | 键(UTF-16LE, 结尾 \\0\\0) | 3B 00 | 值名(UTF-16LE, 结尾 \\0\\0) | 3B 00
              | 类型(4 字节 LE) | 3B 00 | 长度(4 字节 LE) | 3B 00
              | 数据(长度字节) | 5D 00
```

* **文件尾没有独立终止符**：真实样本以最后一个 `5D 00` 结束
  （6/6 实测 —— 读完最后一条时位置**恰好**等于文件长度）；
* 数据长度**只认长度字段**，**绝不用正则 / 扫描**去猜边界 ——
  这是上面那个缺陷的根因，也是本模块存在的理由。数据里出现 `[`、`]`、`;`、`0x0A`
  **全都合法**。

## 实测（本机 6 个微软产真实样本：2 个 StarterGPO + 4 个 WinSxS 组件级）

| 项 | 实测 |
|---|---|
| 文件 | **6** 个，全部**精确收尾**（无残留字节）|
| 条目 | **27** 条 |
| 类型码 | 只有 **1（REG_SZ）21 条** 与 **4（REG_DWORD）6 条** |
| 字符串数据 | **UTF-16LE + 尾部一个 `\\0\\0`**（21 条的末尾 4 字节全是 `7c000000`）|
| 数据里出现 `0x0A` | **0 条** ⇒ 真实样本**不覆盖**那个失败模式 |

复现：`tools/probe_preg_corpus.py`（本机）—— 它是这张表的执行装置。

## 边界

* **不连域、不碰 SYSVOL、不导入 PyQt、不碰文件系统** —— 本模块**只收字节、只回字节**，
  连 `open()` 都没有。文件读取归调用方（`gpo_settings._read_one_scope`），
  理由见下面那条。
* 🔴 **`read_preg_file` 已删除**（2026-09-18，已定）：它原是「读文件 ＋ `parse_preg`」
  的包装器，docstring 自称「**本模块唯一的文件入口**」，可**生产一次都没调用过它** ——
  生产侧自己读字节再走 `is_empty_preg()` ＋ `parse_preg(raw, source=…)`，
  为的是把「**这个作用域没有管理模板设置**」（正常）与「**我们读不了**」（要人查）分开。
  那个包装器把「空」直接交给 `parse_preg` 去抛 ⇒ **它做不到这个区分，所以没人用它**；
  「本模块唯一的文件入口」那句话**本身就在说谎**（真入口在 `gpo_settings`）。
  **回滚件**留在本地（整目录覆盖即可回滚，未进本仓库）。
  ⚠️ 这个名字**现在在本仓库里再也查不到**，那不是笔误。
* **编码（`build_preg`）也在这个模块** —— 理由只有一个：`parse_preg` 与 `build_preg`
  必须是**同一份格式知识的两个方向**。分成两个模块，改了一边忘另一边，
  表现就是「读得出来、写回去变了样」，而那正是要根治的病。
* 🔴 **2026-09-18：本模块的「编辑」那一半已移出仓库**（已定「**这个工具不做
  组策略编辑**」）⇒ 写入口、原地替换、删条目、按 `(键, 值名)` 查找这四项**均已删除**；
  **回滚件**留在本地。
  ⚠️ 那四个名字**现在在本仓库里再也查不到**，那不是笔误。
  **`build_preg` 留下 ≠ 编辑功能**：它唯一的真调用点是 `mock_client.py`，
  用来造**演示域**的影子 SYSVOL（4 条 GPO × (GPT.INI ＋ Machine/User `Registry.pol`)）。
* **未知类型码不许当成某个默认值**：`type_name()` 会如实说「未收录」，
  `display_value()` 对它给十六进制（**原始字节**，不是猜出来的解释）。
  编码同理：`build_preg` **原样搬运** `type_code` 与 `data`，不解释、不归一。

## 判据（`tests/test_preg_backend.py`）

往返是**唯一**能同时钉住两个方向的判据，所以它有三层：

1. `build_preg(parse_preg(raw)) == raw`，`raw` = 本机 **6 个微软产真实样本**；
2. 构造用例覆盖**真实样本不含**的边界字节（`0x0A` / `[` / `]` / `;` /
   空串 / 旧式字符串尾部两个 NUL / 奇数长度的 `REG_BINARY`）；
3. `parse(build(x)) == x`（结构与值都不许变）—— **编码方向**的判据。
   ⚠️ 第 3 条原来还有一半是「**写坏了要能发现**」（写文件后把新字节读回来核对），
   那一半**随写侧一起移出仓库**（回滚件见上面「边界」段）。
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterable

from utils import AdToolError

#: 文件头：`PReg` + 版本 1（4 字节 LE）。实测 6/6 完全一致。
PREG_HEADER = b"PReg\x01\x00\x00\x00"

#: 条目的四个定界标记（都是 UTF-16LE 的两字节）。
_ENTRY_OPEN = b"[\x00"          # 0x5B 0x00
_FIELD_SEP = b";\x00"           # 0x3B 0x00
_ENTRY_CLOSE = b"]\x00"         # 0x5D 0x00
_NUL2 = b"\x00\x00"

#: 注册表类型码。**数值必须与 `winreg` 一致** ——
#: 有单测拿 `winreg.REG_*` 逐个断言（`tests/test_preg_backend.py::TestTypeCodes`），
#: 所以这里不是"照文档抄的常量"，而是**被机械核对过**的一份。
REG_NONE = 0
REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_DWORD_BIG_ENDIAN = 5
REG_LINK = 6
REG_MULTI_SZ = 7
REG_RESOURCE_LIST = 8
REG_FULL_RESOURCE_DESCRIPTOR = 9
REG_RESOURCE_REQUIREMENTS_LIST = 10
REG_QWORD = 11

REG_TYPE_NAMES = {
    REG_NONE: "REG_NONE",
    REG_SZ: "REG_SZ",
    REG_EXPAND_SZ: "REG_EXPAND_SZ",
    REG_BINARY: "REG_BINARY",
    REG_DWORD: "REG_DWORD",
    REG_DWORD_BIG_ENDIAN: "REG_DWORD_BIG_ENDIAN",
    REG_LINK: "REG_LINK",
    REG_MULTI_SZ: "REG_MULTI_SZ",
    REG_RESOURCE_LIST: "REG_RESOURCE_LIST",
    REG_FULL_RESOURCE_DESCRIPTOR: "REG_FULL_RESOURCE_DESCRIPTOR",
    REG_RESOURCE_REQUIREMENTS_LIST: "REG_RESOURCE_REQUIREMENTS_LIST",
    REG_QWORD: "REG_QWORD",
}

#: 名字里带 NUL 结尾的两种字符串类型（读到之后要**去掉一个**尾部 `\\0`）。
_STRINGY = (REG_SZ, REG_EXPAND_SZ)

#: 定长整数类型 → (结构体格式, 字节数)。**只列真实定长的**：
#: `REG_DWORD` 实测就是 4 字节（27 条里 6 条），长度对不上要**当场抛**，
#: 不许"按前 4 个字节读"——那正是本项目红线禁掉的那类兜底。
_FIXED_INTS = {
    REG_DWORD: ("<I", 4),
    REG_DWORD_BIG_ENDIAN: (">I", 4),
    REG_QWORD: ("<Q", 8),
}


# ============================================================================
# 1. 数据模型
# ============================================================================

@dataclass(frozen=True)
class PregEntry:
    """`registry.pol` 里的一条记录。

    `data` 是**原始字节**，长度由文件里的长度字段决定 ——
    本类**不做任何解释**（解释是 `display_value()` 的事），
    因为同一个字节串在不同类型码下含义完全不同。
    """

    key: str
    value_name: str
    type_code: int
    data: bytes

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def type_name(self) -> str:
        """类型名；**未收录的类型码如实说出来**（不回落成某个默认名）。"""
        return type_name(self.type_code)

    @property
    def as_tuple(self) -> tuple[str, str, int, bytes]:
        """喂给 `admx_backend.evaluate_policy()` 的形状。

        `evaluate_policy` **刻意不认识 PReg 格式**（它收的就是这个四元组），
        这样"解格式"与"判状态"各自能被单独测。
        """
        return (self.key, self.value_name, self.type_code, self.data)


def type_name(code: int) -> str:
    """类型码 → 名字。未收录时返回 ``类型码 N（未收录）``。

    ⚠️ **不许**把未收录的码回落成 `REG_BINARY` 之类 —— 那会让一条读不懂的记录
    在界面上长得像"一个正常的二进制值"，而不是"我们没读懂它"。
    """
    return REG_TYPE_NAMES.get(code, "类型码 %d（未收录）" % code)


# ============================================================================
# 2. 解析（唯一入口）
# ============================================================================

def _read_wstring(raw: bytes, pos: int, source: str, what: str) -> tuple[str, int]:
    """从 ``pos`` 读一条 UTF-16LE、以 `\\0\\0` 结尾的串。返回 ``(文本, 新位置)``。

    🔴 找结尾时**必须按偶数对齐**：`\\0\\0` 可以出现在**奇数**偏移上
    （比如某个字符的低字节恰好是 `0x00`，而下一个字符的高字节也是 `0x00`
    —— 形如 `U+0100` 接 `U+4100` 就会造出这种巧合）。朴素的
    `find(b"\\x00\\x00")` 会**提前截断**键名，而后果是"键名看起来是坏的"
    而不是报错。
    """
    end = raw.find(_NUL2, pos)
    while end != -1 and (end - pos) % 2:
        end = raw.find(_NUL2, end + 1)
    if end == -1:
        raise AdToolError(
            "%s 的%s在偏移 %d 处没有找到结束标记（UTF-16LE 的 \\0\\0）"
            "—— 文件在中间被截断了，或者这不是一份 PReg。" % (source, what, pos))
    try:
        text = raw[pos:end].decode("utf-16-le")
    except UnicodeDecodeError as exc:
        raise AdToolError(
            "%s 的%s（偏移 %d）解码失败：%s —— 它不是 UTF-16LE。"
            % (source, what, pos, exc)) from exc
    return text, end + len(_NUL2)


def _expect(raw: bytes, pos: int, marker: bytes, source: str, what: str,
            entry_no: int) -> int:
    """断言 ``pos`` 处是某个定界标记，返回标记之后的位置。

    ⚠️ 这里**不许**"找不到就往前找找看" —— 一旦允许容错，后面所有条目的
    边界都会跟着错位，而错位的表现是"读出来的值是别的设置的"，
    **不会有任何报错**。所以一律**当场抛**并带上偏移与标记名。
    """
    if raw[pos:pos + len(marker)] != marker:
        raise AdToolError(
            "%s 第 %d 条记录：在偏移 %d 处期望标记 %s，实际是 %s"
            "—— 文件格式与本实现不符（「拒绝继续」：容错会让后面每条都错位）。"
            % (source, entry_no, pos, marker.hex(" "),
               raw[pos:pos + len(marker)].hex(" ") or "（文件到此结束）"))
    return pos + len(marker)


def parse_preg(raw: bytes, source: str = "<内存>") -> tuple[PregEntry, ...]:
    """把一份 `registry.pol` 的字节解析成记录表。**这是本模块唯一的解析入口。**

    严格（fail-closed）：
      * 头不对 ⇒ 抛；
      * 少任何一个定界标记 ⇒ 抛；
      * **长度字段超出剩余字节** ⇒ 抛；
      * **读完最后一条还有剩余字节** ⇒ 抛（真实样本是**恰好**收尾的，
        有残留说明我们的读法漏了一层 —— 那种情况下"少读几条"正是最坏结果）。

    ⚠️ **0 字节也抛**，而不是返回空表：真实 SYSVOL 里 `Registry.pol` 可以是空的
    （= 这个作用域没有任何管理模板设置），但"空文件"与"格式不对"是**两件事**，
    必须由调用方分别表达。判断空文件请用 `is_empty_preg()`，
    **不要**拿"解析出 0 条"来代替 —— 那会把"读失败"混进"没有设置"里。
    """
    if not raw:
        raise AdToolError(
            "%s 是 0 字节。空文件既可能是「这条 GPO 在该作用域下没有管理模板设置」，"
            "也可能是文件被截断 —— 本模块「不替调用方猜」："
            "请先用 is_empty_preg() 判断，再决定是「没有设置」还是「读不了」。"
            % source)
    if len(raw) < len(PREG_HEADER):
        raise AdToolError(
            "%s 只有 %d 字节，连 %d 字节的文件头都不够 —— 这不是一份 PReg。"
            % (source, len(raw), len(PREG_HEADER)))
    if not raw.startswith(PREG_HEADER):
        raise AdToolError(
            "%s 的文件头是 %s，而 PReg 的头必须是 %s（PReg + 版本 1）"
            "—— 这不是 `registry.pol`（`.pol` 扩展名在 Windows 上另有其他格式）。"
            % (source, raw[:len(PREG_HEADER)].hex(" "), PREG_HEADER.hex(" ")))

    entries: list[PregEntry] = []
    pos = len(PREG_HEADER)
    while pos < len(raw):
        entry_no = len(entries) + 1
        pos = _expect(raw, pos, _ENTRY_OPEN, source, "条目起始", entry_no)
        key, pos = _read_wstring(raw, pos, source, "键名")
        pos = _expect(raw, pos, _FIELD_SEP, source, "键名之后的字段分隔符", entry_no)
        value_name, pos = _read_wstring(raw, pos, source, "值名")
        pos = _expect(raw, pos, _FIELD_SEP, source, "值名之后的字段分隔符", entry_no)

        if pos + 4 > len(raw):
            raise AdToolError(
                "%s 第 %d 条记录：偏移 %d 处的类型字段不完整（只剩 %d 字节）。"
                % (source, entry_no, pos, len(raw) - pos))
        type_code, = struct.unpack_from("<I", raw, pos)
        pos += 4
        pos = _expect(raw, pos, _FIELD_SEP, source, "类型之后的字段分隔符", entry_no)

        if pos + 4 > len(raw):
            raise AdToolError(
                "%s 第 %d 条记录：偏移 %d 处的长度字段不完整（只剩 %d 字节）。"
                % (source, entry_no, pos, len(raw) - pos))
        size, = struct.unpack_from("<I", raw, pos)
        pos += 4
        pos = _expect(raw, pos, _FIELD_SEP, source, "长度之后的字段分隔符", entry_no)

        # 🔴 长度**只认这个字段**。不许拿 `]` 去扫、不许拿正则去切 ——
        #    数据是任意字节，`]` 0x5D 0x00 完全可能出现在数据里。
        if pos + size > len(raw):
            raise AdToolError(
                "%s 第 %d 条记录（键 %s）：长度字段说要 %d 字节数据，"
                "而偏移 %d 之后只剩 %d 字节 —— 文件被截断了。"
                % (source, entry_no, key or "（空）", size, pos, len(raw) - pos))
        data = raw[pos:pos + size]
        pos += size

        pos = _expect(raw, pos, _ENTRY_CLOSE, source, "条目结束标记", entry_no)
        entries.append(PregEntry(key=key, value_name=value_name,
                                 type_code=type_code, data=data))

    if pos != len(raw):                              # pragma: no cover —— 由上两处保证
        raise AdToolError(
            "%s 读完 %d 条之后位置是 %d，而文件长度是 %d —— 解析器与文件不一致。"
            % (source, len(entries), pos, len(raw)))
    return tuple(entries)


def is_empty_preg(raw: bytes) -> bool:
    """这份字节是不是「空的 `registry.pol`」。

    ⚠️ 它存在的意义是**把两件事分开**：`parse_preg` 对 0 字节会抛，
    而调用方需要能区分「这个作用域没有管理模板设置」（正常）与
    「读不了」（要报出来）。拿"解析出 0 条"当"没有设置"是**静默少读**的一种。
    """
    return len(raw) == 0


# ============================================================================
# 3. 值的呈现（**不猜**）
# ============================================================================

def display_value(entry: PregEntry) -> str:
    """把一条记录的**数据**翻成给界面看的字符串。

    🔴 三条判据：

    1. **长度不合约就抛**，绝不"读前 4 个字节算了"。
       `REG_DWORD` 实测就是 4 字节，长度不对说明这条记录不是我们以为的那种，
       硬读会给出一个**看起来正常的数字**——那比报错危险得多。
    2. **定长类型按类型码解释，不定长类型给十六进制**，不猜。
    3. **未收录的类型码 ⇒ 十六进制原文**（`type_name()` 那边已经会说明"未收录"）
       —— 给原始字节是**如实**，不是猜。
    """
    code = entry.type_code

    if code in _FIXED_INTS:
        fmt, expected = _FIXED_INTS[code]
        if len(entry.data) != expected:
            raise AdToolError(
                "记录 %s\\%s 的类型是 %s（应当是 %d 字节），实际有 %d 字节"
                "—— 这条记录与类型不符，本模块「不按前几个字节硬读」。"
                % (entry.key, entry.value_name, entry.type_name,
                   expected, len(entry.data)))
        return str(struct.unpack(fmt, entry.data)[0])

    if code in _STRINGY:
        text = _decode_string(entry)
        # 去掉**一个**尾部 NUL（那是格式要求的结束符，不是文本的一部分）。
        # ⚠️ 用"去掉一个"而不是 `rstrip("\x00")`：后者会把文本里**真有**的
        #    尾部空字符一起吃掉，那是**改数据**。
        return text[:-1] if text.endswith("\x00") else text

    if code == REG_MULTI_SZ:
        parts = [p for p in _decode_string(entry).split("\x00") if p]
        #: 多字符串用 ` | ` 连接（纯文本通道里不能再出现 NUL）。
        return " | ".join(parts)

    # `REG_NONE` / `REG_BINARY` / 未收录 —— 给原始字节。
    return entry.data.hex(" ")


def _decode_string(entry: PregEntry) -> str:
    """按 UTF-16LE 解字符串型数据。**奇数长度 ⇒ 抛**（不补、不截、不忽略）。"""
    if len(entry.data) % 2:
        raise AdToolError(
            "记录 %s\\%s 是字符串类型，但数据有 %d 字节（奇数）"
            "—— UTF-16LE 不可能解出奇数个字节，这条记录坏了。"
            % (entry.key, entry.value_name, len(entry.data)))
    try:
        return entry.data.decode("utf-16-le")
    except UnicodeDecodeError as exc:
        raise AdToolError(
            "记录 %s\\%s 的字符串数据解不开：%s" % (entry.key, entry.value_name, exc)
        ) from exc


# ============================================================================
# 4. 编码（**同一份格式知识的另一个方向**）—— **只为演示域造数据**
# ============================================================================
#
# 🔒 本模块是 `registry.pol` 的**唯一**实现（读 ＋ 编码），**只用标准库** ——
#    没有任何第三方件，也没有 GPMC / RSAT。
#
# 🔴 2026-09-18：**写回（磁盘写入 / 原地替换 / 删条目）已移出仓库**（已定
#    「这个工具不做组策略编辑」）⇒ 本节只剩 `build_preg` 一个函数，而它的用途是
#    **造演示域影子 SYSVOL 的数据**（真调用点：`mock_client.py`），**不是编辑功能**。
#    回滚用的原件：见模块 docstring「边界」段。

def _encode_wstring(text: str, what: str) -> bytes:
    """一条 UTF-16LE 串 ＋ 结尾的 ``\\0\\0``。

    🔴 **文本里不许含 NUL**：`\\0\\0` 在这个格式里**就是定界符**，
    把含 NUL 的文本编出来，读回去必然**提前截断** —— 写出来的文件
    「看起来写成功了」，而策略键名从中间断开，客户端**根本不会应用**。
    这种"写坏的产物不报错"正是本模块存在的理由，所以这里**当场抛**。
    """
    if "\x00" in text:
        raise AdToolError(
            "要写进去的%s里含空字符（NUL）：%r\n"
            "（NUL 在本格式里是定界符，编进去读回来会被截断。）"
            % (what, text))
    return text.encode("utf-16-le") + _NUL2


def build_preg(entries: Iterable[PregEntry]) -> bytes:
    """把记录表编成 `registry.pol` 的字节。**本模块唯一的编码入口。**

    🔴 **它是 `parse_preg` 的严格逆运算**：`type_code` 与 `data` **原样搬运**，
    不做类型归一、不做值解释、不重排顺序 ——
    判据是 `build_preg(parse_preg(raw)) == raw`（本机 6 个真实样本逐字节一致）。

    长度字段由 `len(data)` **算出来**（不是调用方传的）⇒ 不存在"长度与数据不符"
    这种自己制造的坏文件；反过来，读进来的文件长度不符会被 `parse_preg` 拦住。

    ⚠️ **0 条 ⇒ 只回 8 字节文件头**（一个合法的、不含任何条目的 PReg），
    **不是** 0 字节。"空文件"与"有文件头但没有条目"是两件事，
    见 `is_empty_preg()` 与 `parse_preg()` 的说明。
    """
    out = bytearray(PREG_HEADER)
    for entry in entries:
        out += _ENTRY_OPEN
        out += _encode_wstring(entry.key, "注册表键名")
        out += _FIELD_SEP
        out += _encode_wstring(entry.value_name, "值名")
        out += _FIELD_SEP
        out += struct.pack("<I", entry.type_code)
        out += _FIELD_SEP
        out += struct.pack("<I", len(entry.data))
        out += _FIELD_SEP
        out += entry.data                      # 数据原样，**不做任何转义**
        out += _ENTRY_CLOSE
    return bytes(out)
