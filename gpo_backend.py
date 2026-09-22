# -*- coding: utf-8 -*-
"""gpo_backend.py —— 组策略（GPMC COM）的**只读**封装

## 为什么是 GPMC 的 COM，而不是自己读文件

组策略的"内容"存在两种载体里，散在 SYSVOL 与 AD 中：

* `GptTmpl.inf`（安全策略，纯文本）—— 好办；
* `registry.pol`（管理模板，**二进制 PReg**）—— 有公开规范 `[MS-GPREG]`，
  但"哪条策略对应哪个注册表值"要去读 ADMX/ADML，那就等于重写 gpedit。

Windows 自带 **GPMC 引擎**（`GPMgmt.GPM`，`gpmgmt.dll`）：RSAT 的「组策略管理」
界面走它，PowerShell 的 `GroupPolicy` 模块（`New-GPO` / `Get-GPOReport`…）也走它。
⇒ **本项目一行 `registry.pol` 都不解析**，全部交给它。

> 🔴 **2026-09-17 更正**：上面这条**只在本模块内成立**（`gpo_backend` 至今
> 仍是只读、仍不碰 `registry.pol`）。但主理人同日要求「**组策略要和 ADUC 一样
> 可以编辑**」＋「**内部嵌入的东西要下载到本地，不许本地没组件就用不了**」，
> 而 GPMC/cmdlet 两条路**都要 RSAT** ⇒ 编辑能力改走**自包含**路线，
> `registry.pol` 由本项目自己读写。**进度**：
> * ✅ ADMX/ADML 解析 ⇒ `admx_backend.py`（只读）；
> * ✅ `registry.pol` **读** ＋ 「改过哪些设置」的对照 ⇒ `preg_backend.py`
>   ＋ `gpo_settings.py`（只读；判决装置 `tools/probe_gpo_settings.py`）；
> * ⏳ **写**回（P1）**尚未开工** —— 它只在本项目的开关后面存在，
>   且**真机写操作只能主理人跑**。
> 方案与代价/许可对账 ⇒ `.workbuddy/artifacts/方案-组策略可编辑-自包含-2026-09-17.md`。

> 🔴 **2026-09-17（同日，第二处）**：「**列 GPO**」这条**生产路径已搬走** ——
> 现在是 `gpo_ldap.py`（走 LDAP，**不需要 RSAT**）。理由同上一段：
> 列 GPO 原来只有 GPMC 一条路 ⇒ **没装 RSAT 的机器连列表都拿不到**，
> 面板根本打不开，于是"读设置不需要 RSAT"在它本该服务的那些机器上
> 照样够不到。
> ⇒ 本模块的 `list_gpos` / `search_gpos` **降级为"对照尺"**（真域上跟 LDAP
> 的结果并排比），**不再是界面调的那条路** —— 别把两条路都接回生产
> （那会变成两份读实现，裁定见 `gpo_ldap.py`）。
> 本模块仍在生产里的是：**看链接位置**（`links_of_som` / `soms_linking_gpo`）
> 与**看设置摘要**（`generate_report`）—— 这两件 LDAP 目前不做，所以它们
> 依旧要求装 RSAT。

判决实验：`tools/probe_gpo_backend.py`（引擎在不在）、
`tools/probe_gpo_typelib.py`（**常量到底叫什么**）。

## ⚠️ 常量名：文档、类型库、COM 对象是三回事

这是本模块最容易踩的坑。同一个"GPO 显示名"的搜索属性，三种写法里**只有一种能用**：

| 来源 | 写法 | 实测 |
|---|---|---|
| 老 MSDN 方法页 | `gpoDisplayName` | ❌ `AttributeError` |
| 类型库里的枚举成员 | `GPODisplayName` | ❌ `AttributeError` |
| **COM 常量对象** | **`SearchPropertyGPODisplayName`** | ✅ `= 2` |

`tools/probe_gpo_typelib.py` 第一次跑就抓出 **10 个 MISSING**。
照文档抄进代码 = 10 处 `AttributeError`；给它们加 `try/except` 兜底 = 10 处**静默失效**
（后者最难查）。所以本模块：

* 常量名一律抄 `tools/probe_gpo_typelib.py` 的实测输出；
* `_require_constants()` 在开会话时**一次性全查**，缺哪个就**当场抛**并列出缺失名单
  —— 这是 fail-fast 的**前置校验**，不是兜底：它不提供"缺了就跳过"的路径。

## 身份通道：组策略走的**不是** SMB 那条路

| | 组策略（本模块） | 对照：共享盘 ACL —— 🔴 **2026-09-16 已整体删除** |
|---|---|---|
| 传输 | DCOM/RPC（135 + 动态端口）+ LDAP（389） | SMB（445） |
| 换凭据 | `password_backend.impersonate()`（挂线程令牌） | `net use`（给网络位置带凭据，进程令牌不变） |
| 为什么 | COM/RPC 用**线程令牌**，必须真挂令牌 | 实测 `NEW_CREDENTIALS` 不换本机身份，但给网络位置带凭据有效 |

⚠️ 右列那条路连同它的后端 `share_backend.py` 已按主理人拍板
（「把操作共享盘这个功能全部删除掉」）一起销掉 —— **留在这里只是对照，
不要照它去实现**。

**两者不能互换。** 所以 `open_session()` **自己不管身份** —— 身份由调用方
（`workers`）在外面用 `impersonate()` 包住。这样也避开了另一个坑：
`impersonate(user, domain, ...)` 要的是 **NetBIOS 域**，而 GPMC 的 `GetDomain()`
要的是 **DNS 域名**，两个 `domain` 语义不同，混在一个参数里必然错。

⚠️ **未验证**：`impersonate` 用的 `LOGON32_LOGON_NEW_CREDENTIALS(9)` 语义是
"本机身份不变、出站网络访问用这份凭据"，对 GPMC 的出站调用**方向上应该有效，
但没有实测**（域不通）。`tools/acceptance_gpo.py` 里配了**假口令反证**：
错误口令若照样成功，说明凭据根本没起作用。

## 边界

* **只读**：对外函数里没有 `CreateGPO` / `CreateGPOLink` / `Delete` / `Backup` /
  `Import` / `CopyTo` / `Set*`。有 AST 静态判据钉着。
* 非 Windows / 没装 pywin32 / 没装 RSAT-GPMC ⇒ `engine_status()` 给明确中文说明，
  并说清这是**部署前置条件**（不是"连接失败"）。
* 不碰 AD 的 LDAP、不碰 SYSVOL 的文件。
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Iterator

from utils import AdToolError, get_logger

__all__ = [
    "PROGID",
    "REPORT_XML",
    "REPORT_HTML",
    "SOM_KIND_NAMES",
    "SOM_KIND_LABELS",
    "GpoInfo",
    "SomInfo",
    "GpoLink",
    "GpmSession",
    "engine_status",
    "open_session",
    "list_gpos",
    "search_gpos",
    "list_soms",
    "links_of_som",
    "soms_linking_gpo",
    "generate_report",
]

_log = get_logger("gpo")

PROGID = "GPMgmt.GPM"

REPORT_XML = "xml"
REPORT_HTML = "html"

#: 引擎缺失时给使用者看的话。**必须**区别于"连不上域" —— 前者是"没装东西"，
#: 后者是"网络/权限"。混在一起会把人引到错误的方向去排查。
ENGINE_MISSING_HINT = (
    "本机未安装 RSAT「组策略管理工具」，组策略功能不可用。\n"
    "这是「部署前置条件」（不是网络或权限问题）：\n"
    "  服务器：服务器管理器 → 添加角色和功能 → 功能 → 远程服务器管理工具 → "
    "组策略管理工具\n"
    "  客户端：Windows 可选功能 → RSAT → 组策略管理工具"
)

#: 实现里**必须**能从 `GetConstants()` 取到的常量。
#: 名字来源：`tools/probe_gpo_typelib.py` 的实测输出（**不是**文档页）。
#: 改这里之前先跑那个探针 —— 它是这条红线的执行装置。
NEEDED_CONSTANTS: tuple[str, ...] = (
    # SOM 类型（GetSOM / SearchSOMs 用）
    "somSite", "somDomain", "somOU",
    # 搜索属性
    "SearchPropertyGPODisplayName", "SearchPropertyGPOID",
    "SearchPropertySOMLinks", "SearchPropertyGPODomain",
    # 搜索操作
    "SearchOpEquals", "SearchOpContains", "SearchOpNotContains",
    # 报告类型
    "ReportXML", "ReportHTML",
    # GetDomain 的 flags
    "UseAnyDC",
)


#: 三种 SOM 类型在 `GetConstants()` 上的**属性名**。
#: 调用 `GetSOM(path, kind)` 时用它们去取名 —— **不要把 0/1/2 硬编码进逻辑**：
#: 硬编码等于把"真实值恰好是这几个数"当成前提，而这个前提没有任何东西守着它。
SOM_KIND_NAMES: tuple[str, ...] = ("somSite", "somDomain", "somOU")

#: 把 COM 返回的 `Type`（一个裸数字）翻成中文，**仅供展示**。
#: 值来自类型库实测（`__MIDL_IGPMSOM_0001`：somSite=0 / somDomain=1 / somOU=2），
#: 由 `tools/probe_gpo_typelib.py` 可复现。
SOM_KIND_LABELS = {0: "站点", 1: "域", 2: "组织单位"}


# ============================================================================
# 1. 数据
# ============================================================================

@dataclass
class GpoInfo:
    """一个 GPO 的**元信息**（不含设置内容 —— 那要走 `generate_report`）。"""

    guid: str = ""
    display_name: str = ""
    domain: str = ""
    path: str = ""
    created: str = ""
    modified: str = ""
    #: 版本号：AD 侧与 SYSVOL 侧不一致 = 复制没同步完（GPMC 界面上会标红）。
    user_version: int = 0
    computer_version: int = 0
    #: AD 属性 `gPCMachineExtensionNames` 的**原文** —— 用来回答「这条 GPO 的
    #: 安全策略到底会不会生效」（`gpo_security.cse_verdict()` 的输入）。
    #:
    #: 🔴 **三态，`None` 与 `""` 是两件事**（默认值取 `None` 是**有意的**）：
    #:
    #: | 取值 | 谁会给 | 含义 |
    #: |---|---|---|
    #: | `None` | **本模块**（GPMC 那条路）与一切构造 `GpoInfo` 的旧代码 | 这条路**没提供**这个属性 ⇒ 结论是"说不清" |
    #: | `""` | `gpo_ldap._to_gpo()` —— 它**明确请求过**这个属性，域控回"没有值" | 对象上确实没登记 ⇒ 安全 CSE 没注册 ⇒ **不会被应用** |
    #:
    #: 合并两者就会在**没读到属性**时给出一句听起来很确定的错结论
    #: （"你的安全策略是废的"）—— 那正是使用者最会当真的一句。
    #: GPMC 的 `IGPMGPO` **不暴露**扩展名列表，所以本模块这条对照尺
    #: 永远停在 `None`（走"说不清"分支）是**正确行为**，不是没做完。
    machine_extension_names: str | None = None

    @property
    def label(self) -> str:
        return self.display_name or self.guid or "（未命名）"


@dataclass
class SomInfo:
    """一个"管理范围"（SOM = Site / Domain / OU）。

    ⚠️ `path` 的**格式未验证**（DN 还是 ADsPath）—— 见设计文档第 7 节第 2 条。
    `links_of_som()` 直接把它传给 `GetSOM()`，验收脚本会打出真实值来对照。
    """

    path: str = ""
    name: str = ""
    kind: int = -1
    inheritance_blocked: bool = False

    @property
    def kind_label(self) -> str:
        return SOM_KIND_LABELS.get(self.kind, "未知")


@dataclass
class GpoLink:
    """一条 GPO 链接（GPO ↔ SOM）。

    ⚠️ 链接**只长在 SOM 那一侧** —— `IGPMGPO` 上**没有** `GetGPOLinks`
    （类型库实测，36 项里没有它）。所以要么 `GetSOM().GetGPOLinks()`，
    要么 `SearchSOMs(SearchPropertySOMLinks, …)` 反查。
    """

    gpo_id: str = ""
    enabled: bool = True
    enforced: bool = False
    order: int = 0
    som_path: str = ""
    #: 从 SOM 侧查时，GPO 的显示名要另外 `GetGPO` 才有 —— 这里留空，
    #: 界面上用 `gpo_id` 去已加载的列表里对照，避免 N+1 次往返。
    display_name: str = ""


@dataclass
class GpmSession:
    """一个已打开的 GPMC 会话。

    **刻意是个普通数据类而不是隐藏全局** —— 查询函数都显式收它，
    这样测试能塞假对象进来（依赖注入），不必依赖本机装没装 GPMC。
    """

    gpm: Any = None
    domain: Any = None
    constants: Any = None
    domain_name: str = ""
    dc: str = ""
    values: dict = field(default_factory=dict)

    def value(self, name: str) -> int:
        """取常量值（`_require_constants` 已经保证它存在）。"""
        return self.values[name]


# ============================================================================
# 2. 前置检测
# ============================================================================

def engine_status() -> tuple[bool, str]:
    """本机能不能驱动 GPMC。返回 ``(可用, 说明)``。

    ⚠️ 不可用时**必须**说成"没装 RSAT"（部署前置条件），
    **不许**包装成"连接域失败" —— 那会让人去查网络，而问题在没装东西。
    """
    try:
        import win32com.client  # noqa: PLC0415
    except ImportError:
        return False, ("缺少 pywin32，本机无法驱动 GPMC。\n"
                       "（非 Windows 环境或未安装 pywin32 时，组策略功能不可用。）")

    from com_env import ensure_apartment  # noqa: PLC0415

    ensure_apartment()
    try:
        win32com.client.Dispatch(PROGID)
    except Exception as exc:                    # noqa: BLE001
        return False, "%s\n\n（原始错误：%s: %s）" % (
            ENGINE_MISSING_HINT, type(exc).__name__, exc)
    return True, "GPMC 引擎可用。"


def _require_constants(constants) -> dict:
    """把需要的常量**一次性全取出来**；缺任何一个就抛。

    这是**前置校验（fail-fast）**，不是兜底：它**没有**"缺了就跳过"的分支。
    一处的 `try/except` 只是用来**收集**缺失名单，好让报错一次列全
    （而不是让人改一个跑一次、改一个跑一次）。

    为什么值得单独写：`SearchPropertyGPODisplayName` 这类名字，
    照文档写会写成 `gpoDisplayName` ⇒ `AttributeError`；
    若被通用兜底吃掉，就变成"GPO 列表永远是空的"这种**静默失效**。
    """
    values: dict = {}
    missing: list[str] = []
    for name in NEEDED_CONSTANTS:
        try:
            values[name] = int(getattr(constants, name))
        except AttributeError:
            missing.append(name)
    if missing:
        raise AdToolError(
            "GPMC 常量取不到：%s\n"
            "这说明实现里的常量名与这台机器的 GPMC 类型库不符 —— "
            "请跑 `tools/probe_gpo_typelib.py` 核对真实名字（它是这件事的权威来源）。"
            % "、".join(missing))
    return values


# ============================================================================
# 3. 会话
# ============================================================================

@contextmanager
def open_session(domain: str, dc: str = "") -> Iterator[GpmSession]:
    """打开一个 GPMC 会话（`GPMDomain`）。

    * ``domain``：**DNS 域名**（如 ``corp.example.com``），来自
      `ad_client.domain`（RootDSE 反查）—— **禁硬编码**；
    * ``dc``：域控的机器名/IP。给了就指定它，留空则用 ``UseAnyDC``
      （让 GPMC 自己挑一个）。**未加域的机器**通常必须给（DNS 可能解析不到域）。

    ⚠️ **本函数不管身份。** 要"用工具里填的域账号"，请在**外面**再包一层
    `password_backend.impersonate()` —— 原因见模块说明（两个 domain 语义不同）。

    退出时放手 COM 对象引用。注意顺序：**先丢 GPMDomain 再退出 COM 公寓**
    （公寓由 `com_env` 长效持有，这里不动它）。
    """
    if not domain:
        raise AdToolError("没有域名，无法打开组策略会话。请先连接域控（域名由 RootDSE 反查）。")

    from com_env import ensure_apartment  # noqa: PLC0415

    ensure_apartment()
    try:
        import win32com.client  # noqa: PLC0415
    except ImportError as exc:
        raise AdToolError(ENGINE_MISSING_HINT) from exc

    try:
        gpm = win32com.client.Dispatch(PROGID)
    except Exception as exc:                    # noqa: BLE001
        raise AdToolError("%s\n\n（原始错误：%s: %s）"
                          % (ENGINE_MISSING_HINT, type(exc).__name__, exc)) from exc

    try:
        constants = gpm.GetConstants()
    except AttributeError:
        # 装置故障：COM 对象不是我们以为的那个 —— 原样冒泡，别包装成"连接失败"。
        raise
    except Exception as exc:                    # noqa: BLE001
        raise AdToolError("取 GPMC 常量失败：%s: %s" % (type(exc).__name__, exc)) from exc

    values = _require_constants(constants)

    try:
        if dc:
            domain_obj = gpm.GetDomain(domain, dc, 0)
        else:
            domain_obj = gpm.GetDomain(domain, "", values["UseAnyDC"])
    except AttributeError:
        raise
    except Exception as exc:                    # noqa: BLE001
        raise AdToolError(_explain(exc, domain, dc)) from exc

    session = GpmSession(gpm=gpm, domain=domain_obj, constants=constants,
                         domain_name=domain, dc=dc, values=values)
    _log.info("GPMC 会话已打开 domain=%s dc=%s", domain, dc or "（UseAnyDC）")
    try:
        yield session
    finally:
        # 先放掉域对象，再放掉根对象 —— 让引用计数在这里就归零，
        # 而不是留到 GC 时（`com_env` 讲过的悬空对象问题）。
        session.domain = None
        session.gpm = None


# ============================================================================
# 4. 错误翻译
# ============================================================================

#: COM 错误码 → 人话。**这张表永远写不全**，所以命不中时一律回落到
#: Windows 自己的消息（见 `_explain`）—— 不要自己再转一遍。
_COM_ERRORS = {
    0x80070005: "访问被拒绝 —— 当前身份没有读取组策略的权限。",
    0x800706BA: "RPC 服务器不可用 —— 到域控的 135 端口不通（检查 VPN / 防火墙）。",
    0x800706BE: "RPC 调用失败 —— 到域控的连接中断了。",
    0x80070035: "找不到网络路径 —— 域控的 SYSVOL（445）不可达。",
    0x8007203A: "域控已关闭或不可达。",
    0x80072020: "目录服务操作出错（通常是权限或复制问题）。",
    0x80072030: "对象不存在。",
}


def _explain(exc: Exception, domain: str, dc: str) -> str:
    """把 COM 异常翻成人能行动的话。

    ⚠️ 判据：**这条错误是"我们能做什么"，不是"发生了什么"**。
    所以每条都带上下一步动作（开 VPN / 换账号 / 指定域控）。
    """
    hr = getattr(exc, "hresult", None)
    if hr is None and exc.args and isinstance(exc.args[0], int):
        hr = exc.args[0]

    lines = ["打开组策略失败：域 %s，域控 %s。" % (domain, dc or "（自动选择）")]
    if isinstance(hr, int):
        key = hr & 0xFFFFFFFF
        lines.append("    %s" % _COM_ERRORS.get(key, "未收录的错误码 0x%08X" % key))
    else:
        lines.append("    %s: %s" % (type(exc).__name__, exc))

    # Windows 自己的消息兜底 —— 码表命不中时它往往更准。
    for item in (exc.args or ()):
        if isinstance(item, str) and item.strip() and item not in lines[1]:
            lines.append("    系统消息：%s" % item.strip())
            break

    lines.append("    可尝试：① 确认 VPN / 到域控的 135、389、445 通；"
                 "② 用有权限的域账号；③ 在连接里显式指定域控。")
    return "\n".join(lines)


def _each(collection) -> Iterator[Any]:
    """遍历 COM 集合。

    走 `_NewEnum`（IEnumVARIANT）而**不是** `Item(1..Count)`：后者要赌集合是
    **1-based 还是 0-based**，赌错就是"少一项或多一项"——而"少一项"在界面上
    长得像"这条 GPO 没链接"，**不会报错**。
    """
    if collection is None:
        return
    for item in collection:
        yield item


def _text(value) -> str:
    """COM 的 BSTR 有时是 None ⇒ 统一成空串（界面不用到处判 None）。"""
    return "" if value is None else str(value)


# ============================================================================
# 5. 只读查询
# ============================================================================

def _to_gpo(obj) -> GpoInfo:
    """一条 GPMC 的 GPO 对象 → `GpoInfo`（**与 LDAP 那条路同一个数据形状**）。

    ⚠️ `machine_extension_names` **显式传 `None`**，这是**有意的**，不是漏填：

    它在本项目里是**三态**的 —— `present`（属性里有安全扩展的 GUID）/
    `absent`（属性有值、但没有那个 GUID）/ `unknown`（**这条路没提供这个属性**）。
    `IGPMGPO` 不暴露扩展名列表 ⇒ 本模块这条路**永远**给不出这个属性的原文，
    于是它每一行都必须是 `unknown`，界面说「说不清」。

    🔴 **不许**在这里塞 `""`：`""` 的语义是"问了、对象上确实没有值" ⇒
    结论会变成「这份安全策略**不会被应用**」—— 一句听起来很确定、而**我们根本
    没查过**的错结论。那正是本项目 `or 0` 家族的同一种错（把取数失败当证据成立）。

    ⚠️ 为什么不干脆**不填**这个字段（靠 dataclass 默认值）：
    `tests/test_gpo_ldap.py::test_the_keyword_sets_are_identical` 会**从 AST 里**
    比两条路填了哪些字段 —— 那是为了防止"对照真域时把『我们没读』误报成
    『域里没有』"。所以两条路都**明确表态**：LDAP 说 `""`（问了，没有值），
    GPMC 说 `None`（没这条路）。两边集合一致、取值不同，差异是**写下来的**。
    """
    return GpoInfo(
        guid=_text(getattr(obj, "ID", "")),
        display_name=_text(getattr(obj, "DisplayName", "")),
        domain=_text(getattr(obj, "DomainName", "")),
        path=_text(getattr(obj, "Path", "")),
        created=_text(getattr(obj, "CreationTime", "")),
        modified=_text(getattr(obj, "ModificationTime", "")),
        user_version=int(getattr(obj, "UserDSVersionNumber", 0) or 0),
        computer_version=int(getattr(obj, "ComputerDSVersionNumber", 0) or 0),
        # 这条路拿不到它（`IGPMGPO` 不暴露扩展名列表）⇒ `None` = "说不清"。
        machine_extension_names=None,
    )


def _criteria(session: GpmSession):
    """一个**空**的搜索条件对象。

    空 criteria = 不给条件 = "全部"。不要拿"遍历所有 OU 去凑 GPO 列表"来代替 ——
    那是第二份实现，而且会漏掉没链接的 GPO。
    """
    try:
        return session.gpm.CreateSearchCriteria()
    except AttributeError:
        raise
    except Exception as exc:                    # noqa: BLE001
        raise AdToolError("创建搜索条件失败：%s: %s" % (type(exc).__name__, exc)) from exc


def _search_gpos_with(session: GpmSession, criteria) -> list[GpoInfo]:
    try:
        result = session.domain.SearchGPOs(criteria)
    except AttributeError:
        raise
    except Exception as exc:                    # noqa: BLE001
        raise AdToolError(_explain(exc, session.domain_name, session.dc)) from exc
    return [_to_gpo(obj) for obj in _each(result)]


def list_gpos(session: GpmSession) -> list[GpoInfo]:
    """列出域内**全部** GPO（含没有被链接的）。

    🔴 **2026-09-17：这不是生产路径了，是"对照尺"。**

    生产上的「列 GPO」已改走 **LDAP**（`gpo_ldap.py` ⇒ 不需要 RSAT）。
    本函数留在 GPMC 这一侧的角色是**独立的第二把尺** —— 真域上拿它跟
    LDAP 的结果并排比，证明 LDAP 那份没读少、没读错。
    调用它的是判决装置（`tools/probe_gpo_settings.py --from-gpm` 等），
    **不是界面**。⚠️ 别把它当"备选路径"接回 `workers`：
    那会变成两份读实现，而且有 RSAT 和没 RSAT 的机器会拿到不同结果
    （裁定见 `gpo_ldap.py` 模块说明与
    `.workbuddy/artifacts/方案-组策略可编辑-自包含-2026-09-17.md` N1）。

    ⇒ 只返回 0 项是**合法结果**（域里可能真没有 GPO），**不是失败**。
    界面必须把"空"和"错"显示成两回事。
    """
    return _search_gpos_with(session, _criteria(session))


def search_gpos(session: GpmSession, text: str) -> list[GpoInfo]:
    """按**显示名**模糊搜索 GPO。（**对照尺**：见 `list_gpos` 的说明。）

    空 `text` ⇒ 等同于 `list_gpos`（不是"搜不到"）。
    """
    text = (text or "").strip()
    if not text:
        return list_gpos(session)

    criteria = _criteria(session)
    try:
        criteria.Add(session.value("SearchPropertyGPODisplayName"),
                     session.value("SearchOpContains"), text)
    except AttributeError:
        raise
    except Exception as exc:                    # noqa: BLE001
        raise AdToolError("构造 GPO 搜索条件失败：%s: %s"
                          % (type(exc).__name__, exc)) from exc
    return _search_gpos_with(session, criteria)


def list_soms(session: GpmSession) -> list[SomInfo]:
    """列出全部 SOM（站点 + 域 + 所有 OU）。

    ⇒ 这是**"看某 GPO 链在哪些 OU"的原料**：链接只长在 SOM 一侧，
    见 `GpoLink` 的说明。
    """
    try:
        result = session.domain.SearchSOMs(_criteria(session))
    except AttributeError:
        raise
    except Exception as exc:                    # noqa: BLE001
        raise AdToolError(_explain(exc, session.domain_name, session.dc)) from exc

    out: list[SomInfo] = []
    for obj in _each(result):
        out.append(SomInfo(
            path=_text(getattr(obj, "Path", "")),
            name=_text(getattr(obj, "Name", "")),
            kind=int(getattr(obj, "Type", -1) or -1),
            inheritance_blocked=bool(getattr(obj, "GPOInheritanceBlocked", False)),
        ))
    return out


def _som_kind_value(session: GpmSession, kind_name: str) -> int:
    """把 SOM 类型名翻成 `GetSOM` 要的数字。

    **走名字不走数字**：`0/1/2` 是类型库里的值，不是我们该写死的东西。
    名字写错时在这里就报出来（而不是拿一个错误的数字去查一个不存在的对象）。
    """
    name = (kind_name or "").strip()
    if name not in SOM_KIND_NAMES:
        raise AdToolError("不认识的 SOM 类型：%r（可用：%s）"
                          % (kind_name, "、".join(SOM_KIND_NAMES)))
    return session.value(name)


def links_of_som(session: GpmSession, som_path: str, kind_name: str = "somOU",
                 inherited: bool = False) -> list[GpoLink]:
    """某个 SOM（域 / OU / 站点）上链了哪些 GPO，按**链接顺序**。

    ``kind_name``：``"somOU"``（默认）/ ``"somDomain"`` / ``"somSite"``。

    ``inherited=True`` 时用 `GetInheritedGPOLinks()`，含从上层继承来的
    （界面上要回答"这台机器为什么会应用这条策略"就得用后者）。

    ⚠️ `som_path` 的**格式未验证** —— 直接来自 `list_soms()` 的 `SomInfo.path`
    最保险（那是 GPMC 自己给的）。验收脚本会打印真实值。
    """
    som_kind = _som_kind_value(session, kind_name)
    try:
        som = session.domain.GetSOM(som_path, som_kind)
        coll = som.GetInheritedGPOLinks() if inherited else som.GetGPOLinks()
    except AttributeError:
        raise
    except Exception as exc:                    # noqa: BLE001
        raise AdToolError(_explain(exc, session.domain_name, session.dc)) from exc

    out: list[GpoLink] = []
    for link in _each(coll):
        out.append(GpoLink(
            gpo_id=_text(getattr(link, "GPOID", "")),
            enabled=bool(getattr(link, "Enabled", True)),
            enforced=bool(getattr(link, "Enforced", False)),
            order=int(getattr(link, "SOMLinkOrder", 0) or 0),
            som_path=som_path,
        ))
    return out


def soms_linking_gpo(session: GpmSession, gpo_guid: str) -> list[SomInfo]:
    """某个 GPO **链在哪些** SOM 上（OU / 域 / 站点）。

    这是需求文档 §2.2 写错的那一格：`IGPMGPO` 上**没有** `GetGPOLinks`，
    所以只能反过来 —— 拿 GPO 对象去 `SearchSOMs`，搜索属性用
    `SearchPropertySOMLinks` + `SearchOpContains`。

    `gpo_guid` 用 `GpoInfo.guid`（`SearchGPOs` 给的那个）。
    """
    gpo_guid = (gpo_guid or "").strip()
    if not gpo_guid:
        raise AdToolError("没有 GPO 的 GUID，无法反查它链在哪些位置。")

    try:
        gpo = session.domain.GetGPO(gpo_guid)
    except AttributeError:
        raise
    except Exception as exc:                    # noqa: BLE001
        raise AdToolError("找不到 GPO %s：%s" % (gpo_guid, _explain(
            exc, session.domain_name, session.dc))) from exc

    criteria = _criteria(session)
    try:
        criteria.Add(session.value("SearchPropertySOMLinks"),
                     session.value("SearchOpContains"), gpo)
        result = session.domain.SearchSOMs(criteria)
    except AttributeError:
        raise
    except Exception as exc:                    # noqa: BLE001
        raise AdToolError(_explain(exc, session.domain_name, session.dc)) from exc

    out: list[SomInfo] = []
    for obj in _each(result):
        out.append(SomInfo(
            path=_text(getattr(obj, "Path", "")),
            name=_text(getattr(obj, "Name", "")),
            kind=int(getattr(obj, "Type", -1) or -1),
            inheritance_blocked=bool(getattr(obj, "GPOInheritanceBlocked", False)),
        ))
    return out


def generate_report(session: GpmSession, gpo_guid: str,
                    fmt: str = REPORT_HTML) -> str:
    """取 GPO 的**设置摘要**。

    这里**零自造** —— GPMC 自己解析 `registry.pol` / `GptTmpl.inf` /
    `gpt.ini`，产出报告。我们只是把字符串拿回来。

    ⚠️ 报告内容是**域控 SYSVOL 上读来的**，所以这一步要求 **445 可达**
    （列 GPO / 看链接只要 135+389）。

    ⚠️ **未验证**：`GenerateReport` 的返回值是否**直接是字符串**。
    这里不猜 —— 拿到非字符串就抛，把"设计假设不成立"当场暴露出来，
    而不是让它在界面上显示成 `<COMObject ...>`。
    """
    gpo_guid = (gpo_guid or "").strip()
    if not gpo_guid:
        raise AdToolError("没有 GPO 的 GUID，无法生成设置摘要。")

    report_type = session.value(
        "ReportXML" if (fmt or "").lower() == REPORT_XML else "ReportHTML")

    try:
        gpo = session.domain.GetGPO(gpo_guid)
        raw = gpo.GenerateReport(report_type, None, None)
    except AttributeError:
        raise
    except Exception as exc:                    # noqa: BLE001
        raise AdToolError(_explain(exc, session.domain_name, session.dc)) from exc

    if not isinstance(raw, str):
        raise AdToolError(
            "GPMC 的 GenerateReport 返回了 %s，而本实现假设它直接返回字符串。\n"
            "这是实现假设不成立（不是域的问题）—— 见设计文档「未验证项」第 4 条，"
            "需要改成走 IGPMResult.Result。" % type(raw).__name__)
    return raw
