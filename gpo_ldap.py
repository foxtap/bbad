# -*- coding: utf-8 -*-
"""gpo_ldap.py —— 从 **LDAP** 读组策略对象的元信息（**只读**，不需要 RSAT）

## 为什么另开一个模块，而不是塞进 `gpo_backend`

`gpo_backend.py` 的模块边界里明写着「不碰 AD 的 LDAP」—— 它走的是 **GPMC 的
COM**，而 GPMC 要求本机装 RSAT。要求是「**内部嵌入的东西要下载到
本地，不许本地没组件就用不了**」，所以「列 GPO」原本只有 GPMC 一条路，
等于**没装 RSAT 的机器连列表都拿不到**：面板打不开、一条都选不中，
于是「读设置不需要 RSAT」（`gpo_settings.py` 那条自包含路）在它**本该服务
的那些机器上照样够不到**。这是最初就定下的边界。

⇒ 列 GPO 的**生产路径改走 LDAP**：`CN=Policies,CN=System,<域 DN>` 下每个
`groupPolicyContainer` 就是一个 GPO。默认安全描述符给「经过身份验证的用户」
读权限（`Get-GPO` 能对普通域账号工作就是靠它），所以这条路**不额外要权限**、
也**不用再挂一次凭据** —— LDAP 连接本身就绑在工具连域控用的那个身份上。

## 与 GPMC 那条路的分工（明确不做"双路"）

| | 谁在用 | 为什么 |
|---|---|---|
| **本模块（LDAP）** | **生产**：`workers.list_gpos` / `workers.search_gpos` | 不需要 RSAT |
| `gpo_backend.list_gpos` / `search_gpos`（GPMC） | **对照尺**：`tools/probe_gpo_settings.py --from-gpm` 等判决装置 | 真域上拿它跟 LDAP 的结果并排比 |

⚠️ **明确不做「有 RSAT 就走 COM、没有就走 LDAP」的双路** —— 那会变成两份
读实现、结果必然漂移（同一条裁定：对写实现
只保留一份）。生产只认 LDAP 一条；GPMC 那份的角色是**独立的
第二把尺**，用来证明 LDAP 那份没读少、没读错。

## 两把尺子的**已知差异**（真域对照时必须知道）

⚠️ 下面这些差异**不是缺陷**，但不知道就会把「格式不同」误报成「数据不同」：

| 字段 | GPMC（对照尺） | 本模块 |
|---|---|---|
| `path` | ADsPath | 同样拼成 ``LDAP://<DN>`` |
| `created` / `modified` | GPMC 自己的本地化时间文本 | ``%Y-%m-%d %H:%M:%S``（**本地时区**） |
| `user_version` / `computer_version` | 两个独立属性 | 同一个 `versionNumber` 拆高低 16 位 |
| `guid` | COM 给的形态 | `gpo_settings.normalize_guid()` 归一成 ``{大写}`` |
| 排序 | GPMC 自己的顺序 | 按显示名 `casefold`（与 `list_objects` 一致） |

## 边界

* **只读**：本模块只有读，没有任何写回（`CreateGPOLink` / `Set*` 一个都不碰）。
* **零 COM**：不 import `win32com`，也不 import `gpo_backend` 的引擎件 ——
  「不依赖 RSAT」正是它存在的理由，有 AST 判据钉着。
* **不碰文件**：SYSVOL 上的内容由 `gpo_settings.py` 读，不是这里的事。
"""

from __future__ import annotations

from gpo_backend import GpoInfo
from gpo_settings import normalize_guid
from utils import AdToolError, ad_generalized_time_to_dt

__all__ = [
    "POLICIES_RDN",
    "GPO_CLASS",
    "GPO_ATTRIBUTES",
    "policies_dn",
    "list_gpos",
    "search_gpos",
]

#: 组策略容器在 AD 里的位置（相对于域 DN）。
POLICIES_RDN = "CN=Policies,CN=System"

#: 一个 GPO 在 AD 里的对象类。过滤器一律挂它 —— 它是**有索引**的，
#: 而按 `objectClass` 过滤（子类关系）在 AD 上不是索引属性。
GPO_CLASS = "groupPolicyContainer"

#: 要拉的属性。列全需要的、别顺手写 `*`：
#: `*` 会把每个对象上几十个用不上的属性都拖回来（域里 GPO 一多就是白白几倍流量）。
GPO_ATTRIBUTES = (
    "cn",                 # 就是 GUID（形如 `{31B2F340-…}`）
    "displayName",        # 界面上那个名字
    "versionNumber",      # 高 16 位 = 用户版本，低 16 位 = 计算机版本（2026-09-18 更正）
    "whenCreated",        # → `created`
    "whenChanged",        # → `modified`
    "gPCFileSysPath",     # SYSVOL 上的目录（AD 侧与 SYSVOL 侧的复制状态也靠它对账）
    # 机器侧**已注册的 CSE 清单** —— 只为一件事：回答「这条 GPO 的安全策略
    # （`GptTmpl.inf`）会不会被应用」。里面没有安全 CSE 的 GUID ⇒ SYSVOL 里那份
    # 模板**被完全忽略**，而文件在、编码对、版本号也涨了、GPMC 里还看得到
    # （KB885009）。没装 RSAT 的机器上，这句话在别处**根本得不到**。
    # ⚠️ 本属性**只跟机器侧有关**（安全策略是计算机侧扩展）⇒ 没有"用户侧的那一份"。
    # ⚠️ **必须列进这张表**：`search_attributes` 只回请求过的属性，
    #    漏了它 ⇒ `_to_gpo` 拿到的永远是"域控说没有" ⇒ 界面会把
    #    「我们没问」显示成「这条策略不会被应用」—— 判据
    #    `tests/test_gpo_security.py::test_the_attribute_is_actually_requested`
    #    钉住这一点（它也断言 `_to_gpo` 给的是 `""` 而不是 `None`，
    #    以及 GPMC 那条路给的是 `None` —— 三态见 `gpo_security.cse_verdict`）。
    "gPCMachineExtensionNames",
    "distinguishedName",  # 对象的唯一标识（`path` 由它拼）
)


def policies_dn(base_dn: str) -> str:
    """域 DN → 组策略容器的 DN（``CN=Policies,CN=System,<域 DN>``）。

    ⚠️ 拼不出来就**当场抛**，不回落成"域根" —— 拿域根去搜
    `groupPolicyContainer` 也能搜到（子树搜索），但随后
    「读不到」与「真没有」就分不开了：容器不存在该报错，
    而域根永远存在、只会安安静静返回 0 条。
    """
    base = (base_dn or "").strip()
    if not base:
        raise AdToolError(
            "不知道域的 DN（由 RootDSE 反查），定位不到组策略容器。请先连接域控。")
    return "%s,%s" % (POLICIES_RDN, base)


def _first(attrs: dict[str, list[str]], name: str) -> str:
    """取单值属性的第一个非空值（取不到给空串 —— 界面不用到处判 None）。

    找不到就算找到空串：`displayName` 缺了是**合法**的（GPO 可以没名字），
    由 `GpoInfo.label` 回落成 GUID 显示。这里不替它编一个名字。
    """
    for value in attrs.get(name) or []:
        text = str(value).strip()
        if text:
            return text
    return ""


def _version_split(raw: str) -> tuple[int, int]:
    """``versionNumber`` → ``(用户版本, 计算机版本)``。

    🔴 **2026-09-18 更正：方向原来说反了。** 正确是
    **高 16 位 = 用户版本、低 16 位 = 计算机版本**（本函数此前写成"高 = 计算机"）。

    四个**互相独立**的权威来源一致（逐条核对过原文，不是转述）：

    | 来源 | 原文关键句 |
    |---|---|
    | MS Learn《How Core Group Policy Works》 | 「the **upper** two bytes … contain the GPO **user** settings version and the **lower** two bytes contain the **computer** settings version」——同页举例 `10003` hex ⇒ user **1** / computer **3** |
    | MS Learn 博客《Group Policy Basics Part 3》 | `versionNumber = {User Node: upper 16 bits}{Machine Node: lower 16 bits}`；`65540` = `00010004` ⇒ User 1 / Machine 4 |
    | **[MS-GPOL]** 规范（`versionNumber` 属性定义） | 「a 32-bit integer which consists of 16 bits of **user** GPO version and 16 bits of **machine** GPO version」 |
    | MSDN 术语表（cc268399） | 「The **upper 16 bits** of the integer are the **user** GPO version and the **bottom 16 bits** … the **machine** GPO version.」 |

    ⚠️ **它为什么能一直错着而没人发现**（一个值得记住的形状）：
    `mock_client._MockGpo.version_number` 按**同一个反向**去编码 ⇒ 演示域里
    「编码 → 解码」**自洽**，界面上看着完全正确；而**真域**那条路没有反向编码者，
    于是**显示是反的**（`ui_panels.py` 那一列「用户 %s / 计算机 %s」）。
    ⇒ **两个实现同时错、且互相抵消**时，单看任何一边的判据都是绿的。
    本项目的"对照尺"本来抓得到它：`gpo_backend._to_gpo` 走 GPMC，拿的是
    `UserDSVersionNumber` / `ComputerDSVersionNumber` **两个独立属性**，
    不经过高低位拆分 —— 真域上并排一比就露。

    ⚠️ 读不到 / 解不出 ⇒ ``(0, 0)``，**不抛**。这与「读不到
    `userAccountControl` 必须中止、禁 `or 0`」那条**不冲突**，因为管的东西不同：

      * `userAccountControl` 是**授权判据** —— 错一位就把"已禁用"说成"在用"；
      * 版本号只进「版本」那一列，**不参与任何判断**。为一条坏数据抛掉，
        代价是整张列表都用不了。

    而且 GPMC 那条路（`gpo_backend._to_gpo` 的 ``or 0``）本来就是同样宽 ——
    两条路必须一样宽，否则对照时会把「宽容度不同」误报成「数据不同」。
    """
    text = (raw or "").strip()
    if not text:
        return 0, 0
    try:
        value = int(text)
    except (TypeError, ValueError):
        return 0, 0
    value &= 0xFFFFFFFF
    return (value >> 16) & 0xFFFF, value & 0xFFFF


def _display_time(raw: str) -> str:
    """`whenCreated` / `whenChanged`（generalizedTime）→ 本地时间文本。

    ⚠️ 这一列**不用**属性面板那套 UTC：属性面板上的时间都带「（UTC）」标签，
    而这里的列头是「修改时间」，使用者会拿它跟 GPMC 并排看 —— GPMC 给的是
    **本地时间**。直接显示 UTC 会整整差一个时区，然后被当成缺陷去查。
    """
    moment = ad_generalized_time_to_dt(raw)
    if moment is None:
        return ""
    return moment.astimezone().strftime("%Y-%m-%d %H:%M:%S")


def _machine_extension_names(attrs: dict[str, list[str]]) -> str:
    """`gPCMachineExtensionNames` 的原文。**返回 `""` 而不是 `None` —— 这是有意的。**

    本模块的 `attrs` 来自 `_fetch`，而它走的是 `GPO_ATTRIBUTES` ——
    那张表里**明确请求过**这个属性，且 `search_attributes` 与真身同一条约定：
    **只回请求过的属性**。⇒ 「这个键不在返回里」的含义是
    「**域控查过了、对象上确实没有值**」，于是结论是 `absent`
    （安全 CSE 没注册 ⇒ 这份 `GptTmpl.inf` 不会被应用），**不是** `unknown`。

    ⇒ `None`（= 说不清）**只可能来自别的构造者** —— 即 GPMC 那条对照尺
    `gpo_backend._to_gpo`（`IGPMGPO` 不暴露扩展名列表）。
    「我们没问」与「问了、是空」在这里**必须分开**：合并它们会在
    **根本没问**的时候说出一句"你的安全策略是废的"。
    """
    return _first(attrs, "gPCMachineExtensionNames")


def _to_gpo(attrs: dict[str, list[str]], domain: str) -> GpoInfo:
    """一条 LDAP 记录 → `GpoInfo`（**与 GPMC 那条路同一个数据形状**）。

    ⚠️ `cn` 一律过 `normalize_guid()`，**不自己拼字符串**：GUID 的形态
    （带不带花括号、大小写）在下游是有后果的 ——
    `sysvol_gpo_dir()` 拿它拼 UNC、GPMC 的 `GetGPO()` 要 ``{…}`` 形式。
    归一化只有那一处实现，这里再用第二种写法必然分叉。

    ⚠️ `cn` 不是 GUID 时**当场抛**（`normalize_guid` 自己抛），**不跳过这一条**：
    悄悄少列一条，使用者会以为"域里就这些 GPO" ——
    那是把「我们没读懂」冒充成「域里没有」。
    """
    dn = _first(attrs, "distinguishedName")
    user_version, computer_version = _version_split(_first(attrs, "versionNumber"))
    return GpoInfo(
        guid=normalize_guid(_first(attrs, "cn")),
        display_name=_first(attrs, "displayName"),
        domain=domain,
        # GPMC 那边 `Path` 给的是 ADsPath，这里保持同一个含义；
        # ⚠️ **不要**把 `gPCFileSysPath`（SYSVOL 的 UNC）塞进这个字段 ——
        #    那是另一个位置，混进来会让人以为 `path` 指 SYSVOL。
        path=("LDAP://%s" % dn) if dn else "",
        created=_display_time(_first(attrs, "whenCreated")),
        modified=_display_time(_first(attrs, "whenChanged")),
        user_version=user_version,
        computer_version=computer_version,
        machine_extension_names=_machine_extension_names(attrs),
    )


def _fetch(client, ldap_filter: str) -> list[GpoInfo]:
    """按过滤器取一批 GPO，映射成 `GpoInfo` 并按显示名排序。

    ``client`` 是**已连上**的客户端（`AdClient` 或演示域的 `MockAdClient`）——
    两者同合同，由 `tests/test_client_contract.py` 钉着。
    """
    domain = getattr(client, "domain", "") or ""
    base_dn = getattr(client, "base_dn", "") or ""
    rows = client.search_attributes(policies_dn(base_dn), ldap_filter,
                                    GPO_ATTRIBUTES, scope="SUBTREE",
                                    what="查询组策略")
    out = [_to_gpo(row, domain) for row in rows]
    # 按显示名排序 —— ADUC/GPMC 的习惯，也让两把尺子能逐行对。
    out.sort(key=lambda gpo: (gpo.display_name or gpo.guid).casefold())
    return out


def list_gpos(client) -> list[GpoInfo]:
    """列出域内**全部** GPO（含没有被链接的）。**只读。**

    ⇒ 返回空列表是**合法结果**（域里可能真没有 GPO），**不是失败**；
    「容器读不到」（权限不足 / 容器不存在）会**抛**出来。界面必须把
    「空」和「读不到」显示成两回事 —— 这与 `gpo_backend.list_gpos` 的约定一致。
    """
    return _fetch(client, "(objectCategory=%s)" % GPO_CLASS)


def search_gpos(client, text: str) -> list[GpoInfo]:
    """按**显示名**模糊搜 GPO。**只读。**

    空 ``text`` ⇒ 等同于 `list_gpos`（不是"搜不到"）。

    ⚠️ 过滤值必须 `escape_filter_chars`：`(name=*a*b*)` 里的 `a` 是使用者
    输入，里面一个 `(` 就能把过滤器改成别的意思（LDAP 注入）。这里的用法与
    `ad_client.list_objects` 的关键词过滤是同一套。
    """
    key = (text or "").strip()
    if not key:
        return list_gpos(client)
    from ldap3.utils.conv import escape_filter_chars
    pattern = escape_filter_chars(key)
    return _fetch(client,
                  "(&(objectCategory=%s)(displayName=*%s*))" % (GPO_CLASS, pattern))
