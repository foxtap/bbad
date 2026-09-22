# -*- coding: utf-8 -*-
"""replication.py —— AD 全域复制强制同步（`repadmin /syncall`）

为什么需要这个模块
------------------
新建一个用户，**当前操作的域控**上立刻就能查到；但已加域的文件服务器在
「文件夹 → 安全 → 选择用户或组」里搜不到他，要等约一小时。删除同理：删完
短时间内还能搜到。原因不在 AD 本身，在**复制**：

  * 那个对话框默认查的是**全局编录（GC，端口 3268）**，不是单台域控的
    LDAP（389）—— 而我们写的是当前这台域控；
  * 跨站点复制的默认周期是 **180 分钟**（同站点内约 15 秒），所以"约一小时"
    这个量级指向跨站点；
  * 删除是**软删除**：对象进 `Deleted Objects` 容器、打上 `isDeleted=TRUE`，
    在复制到位之前 GC 上那个对象**还在** ⇒ "删了还能搜到"。

`repadmin /syncall <域控> /AdeP` 就是「别等，现在推」。

🔴 「新建完用户之后，在加了域的 server 上**能不能立马搜到**」——这一节是
**环境事实**，不是本模块的行为（2026-09-16 补，全仓此前**没有一处**写过）
--------------------------------------------------------------------------------
主理人的头号诉求原话就是这一句。它能不能达成，**完全不取决于本模块写得好不好**，
取决于**拓扑**。下面三条是判它的全部依据（本机只有一个站点，属"域内查"范畴）：

  1. **`/syncall` 是"一次、一跳"的推送。** 它只叫**目标域控**立刻向**它的直接
     复制伙伴**推一轮；伙伴拿到之后再推给自己的伙伴 —— **第二跳要下一次触发**。
     ⇒ 所以"多跳"的可见时间 ≈ 每一跳各自的复制延迟之和，**不是**一次 `/syncall`
     能覆盖的。
  2. **`userAccountControl` / `member` 这一类属性【不在】AD 的紧急复制（urgent
     replication）清单里。** 紧急复制只覆盖 `lockoutTime`、LSA secret、
     以及 **PDC 上**的 `unicodePwd` 那几类**等不了**的东西。
     ⇒ 新建用户改的正是 `userAccountControl`、加权限组改的正是 `member`
     ⇒ **它们一律走普通复制**，一次都不会被"紧急"那一档加速。
  3. **普通复制的周期**：同一站点内约 **15 秒**（由 KCC 生成的复制间隔决定）；
     跨站点**默认 180 分钟**，在**站点链接（site link）**上最短可配到 **15 分钟**。
     ⚠️ 这个值是**林的拓扑配置**，不是本工具设的，也不是本工具能改的。

  🔴 **2026-09-17 更正 —— 上面"本机只有一个站点"这句【前提是错的】，按铁律保留原措辞、
  在此写明它错在哪**（不要就地改写，原文留着才能看出当初是怎么想歪的）：

  真实部署**不是**单站点：域里有**多台域控、分属不同站点**（现场实测 2 台，
  一台在站点 A、另一台在站点 B）。「只有一个站点」这个错误前提，正是让人把
  "跨站点"当成**理论情形**的原因 —— 结果它**真的发生了**：工具的写入点落在
  站点 A 那台，而需要"马上看得见"的那台服务器读的是站点 B 的那台 ⇒ 实测
  "约一小时"的量级完全吻合。**教训：不许拿"本机看不到 X"去推"X 不存在"**
  （本机未加域，本来就看不到任何站点）。

  ✅ **这条拓扑下最省事的那条出路（原文档漏写，而它比"推"更根本）**：
  不要"写一台、再推过去"，而是**直接把写入点设在读点那一台** ⇒ 无跳可推，
  复制延迟**归零**。所以上面那三条排序在它之下 —— **"写在读点上"这件事本身就是解**，
  `/syncall` 只是够不着时才用的补救。
  怎么问出读点：**在需要看见对象的那台机器上**跑 `nltest /dsgetdc:<域名>`
  （⚠️ **不带 `/PDC`** —— 角色叫 PDC 的那台不是目标）。字段与用法见
  `models.ConnConfig.dc_ip` 的注释。

🔴 **判定分界线（这一句是写给主理人和后人看的）：**

> 目标机器用的那台域控，如果是**当前域控的同站点直连伙伴** ⇒ 秒级，
> 「立马」**可达**；如果是**跨站点 / 多跳** ⇒ **即使 `repadmin` 报 rc=0，
> 也可能最长 180 分钟才可见**，而**界面一个字都不会说**。
> **这时该怪拓扑，不是代码** —— 代码能保证的只有「这一跳已经推了」。

⚠️ **「是不是同站点直连伙伴」怎么核**：在**域内**跑（本仓库**不代跑**外部命令）：

  * 站点归属 —— `nltest /dsgetdc:<域名>` 的输出里同时有 `DC Site Name:` 与
    `Our Site Name:`，**两个名字一样**就是同站点；
  * 是不是**直连**（一跳）—— `repadmin /showrepl <域控名>` 逐段列出的就是那台
    域控的**入站邻居**（`CN=NTDS Settings,CN=<伙伴>,...`），伙伴出现在里面就是直连；
    伙伴**不在**里面 ⇒ 那是多跳。

  ⚠️ 这两条命令的**出处是微软文档**，但本仓库**没在真实多站点林里实测过它们的
  输出格式**（本机未加域、只有一个站点）⇒ 当**待核**用，**不许**当成已实测的事实。

  ⚠️ 判据在哪：**本节是环境事实，没有机械判据**（跨站拓扑在本机复现不了）。
  本节唯一有判据的**派生结论**是"同站点 ⇒ 强制同步失败基本无害（约 15 秒）"，
  它钉在 `tests/test_replication.py::TestNoticeTextAndLevels.test_the_failure_branch_says_a_same_site_failure_is_mostly_harmless`。

⚠️ 它**不遵守复制协议，也不理会 `DISABLE_INBOUND_REPL` / `DISABLE_OUTBOUND_REPL`**
   （微软官方对 `/force` 类操作的原话是"可能损坏复制系统"）。在几百个站点的
   大林里它可能造成复制风暴。本工具的用法是「一次人工操作之后推一次」，不是
   轮询、不是定时，规模上够安全 —— 但这条必须留在文档里。

四个实测出来的坑（踩过，写在这里省下一个人两小时）
-------------------------------------------------
1. **开关大小写敏感，`/AdeP` 必须逐字保真。** 工具自己的帮助就写着：

       /a: 如果没有可用的服务器，则终止
       /A: 为 <Dest DSA> 的所有 NC 执行 /SyncAll

   大小写不同是**两件事**。任何"顺手规范化成小写"的写法都是 bug
   （`SYNC_SWITCHES` 由判据钉住大小写）。

2. 🔴 **`repadmin` 不接受 IP 形式的域控名。** 本机实测
   （`tools/probe_repadmin_console.py` 可复跑）：

       repadmin /syncall 192.0.2.1 /AdeP    → rc=87   「参数错误」
       repadmin /syncall 127.0.0.1 /AdeP    → rc=87   「参数错误」
       repadmin /syncall abc /AdeP          → rc=1722 「RPC 服务器不可用」
       repadmin /syncall no-such-host.invalid → rc=1722

   后两条说明 **87 不是"网络不通"，是"参数形态不对"** —— 名字形式被接受了，
   只是连不上所以报 1722。而本工具的主用例恰恰是**未加域机器**填
   「**IP** + 账号 + 密码」（通用零配置），直接拿 `cfg.dc_ip` 去跑
   ⇒ **永远 87 失败** ⇒ 功能**一次都没生效过**，还会把使用者往"我是不是
   没有域管理员权限"的方向带死。
   ⇒ 所以必须先把 IP 换成**那台域控自己报的名字**（`RootDSE` 的
   `dnsHostName`，连接时已经反查到了，见 `ad_client.connect` 里 `self.info = info`）。

3. 🔴 **退出码 0 不等于成功。** 实测：

       repadmin /syncall /nosuchflag   → rc=0，但打印的是帮助界面
       repadmin （无参数）              → rc=0，同样打印帮助
       repadmin /?                     → rc=1

   ⇒ 判据必须是「**rc==0 且输出里没有失败字样**」。单看 rc 会把语法错误当成功。

   🔴 2026-09-16 追加（同一条的另一半）：**「没有失败字样」也不等于「成功」**。
   `repadmin` 在本机实测里**从没有过"rc=0 且一个字节都不输出"**的样本 ——
   真有第三次的话，那更可能是**我们根本没拿到输出**（管道/重定向/包装器把它吃了），
   而不是"它做了事但懒得说话"。这两种在旧实现里**一模一样**：都判 `ok=True`、
   都判 `silent=True` ⇒ 界面一个字都不说，报告里干干净净，而主理人那边
   看到的是「搜不到」。**"没证据"不能走"成功"那条路** ——
   所以这种情况有**自己的原因码**（`REASON_NO_EVIDENCE`）和**自己的话**，
   它属于"要动手核一下"，不属于"静默"。判据见
   `tests/test_replication.py::TestFailureDetection.test_empty_output_is_not_a_success`。

4. **输出是 OEM 代码页（中文 Windows = cp936），不是 UTF-8**，行尾是 `\r\r\n`：

       repadmin /?  首 4 字节 = b'\\xd3\\xc3\\xb7\\xa8' == cp936 的「用法」

   ⚠️ **不要用 `locale.getpreferredencoding(False)` 当兜底**：本进程实测
   `sys.flags.utf8_mode == 1` 而它返回 `'utf-8'` —— **它在这件事上会说谎**。
   唯一正确的来源是 `kernel32.GetOEMCP()`。
   （好在主判据是退出码，编码只影响可读性 ⇒ 解码失败**不许**影响判决。）

🔴 2026-09-16 追加：`1722` 这一个数字里混着两件完全不同的事
-----------------------------------------------------------
现场弹的原话是「删除对象已成功，但强制复制同步**没成功**：返回码 1722」——
**只给数字、不给下一步**。而 1722 底下其实压着两件事，**下一步动作完全不同**：

  * **本机 DNS 解析不了那个域控名**（`socket.getaddrinfo` 正查失败）；
  * **RPC 这一路连不上**（本机未加域 / 135+动态端口被挡 / 目标域控 RPC 异常）。

第二件的证据（主理人机器实测）：`USERDOMAIN=<本机名>`、
`LOGONSERVER=\\<本机名>`、`USERDNSDOMAIN=None` ⇒ **本机未加域**；
而第一件是**更容易被忽略的那一半**：那台机器用的是**公网 DNS**
（该域的公网 DNS 名解析到的是**公网 IP**，不是内网域控），
那台域控的 FQDN 与短名 **都解析不了**。

⚠️ 为什么「LDAP 通、RPC 不通」一点都不矛盾：LDAP 那条路用的是
**IP + 显式凭据**（不需要 DNS），而 `repadmin` **只吃域名**。
**两条路对 DNS 的依赖不同** —— 别看到"LDAP 都通了"就断定"网络没问题"。

⇒ 因此本模块新增两道**在发命令之前**就能下结论的闸：

  * `name_resolves()`：本地 DNS **正查**（零副作用、不连域控、不绑凭据）。
    它拦的是「注定失败」的那一次调用 —— 和 `resolve_dc_name` 对 **IP 字面量**
    （实测 rc=87）执行的那条原则**是同一个**，只是原来漏了"名字解析不了"这一类；
  * `join_status()`：本机是**域**还是**工作组**（`NetGetJoinInformation`，
    只用 `ctypes`，不引 pywin32），用来把 1722 的原因说成**最可能**的那一条。

⚠️ 措辞铁律：加域状态只是**概率最高**的那条线索，**不是结论** ——
文案里一律写「最可能」，不许把推测当事实。

边界（哪些事本模块**不做**）
-----------------------------
* **不抛异常**。建号/删号已经成功了，同步失败绝不能让那次操作看起来失败。
* **不代跑有中断的命令**。`net stop netlogon` 会中断本机认证 ——
  只把命令行给使用者，工具不许替他按下去（见 `DIAGNOSTIC_COMMANDS`）。
* **不认识 `AdClient`**。本模块只认字符串（域控名、路径、字节），
  「从 client 上取哪几个字段」是任务层的活（`workers.sync_replication`），
  这样这里的每一条都能用替身单独验。
"""

from __future__ import annotations

import ctypes
import ipaddress
import locale
import os
import shutil
import socket
import subprocess
from dataclasses import dataclass
from typing import Callable

from utils import get_logger

__all__ = [
    "SYNC_SWITCHES",
    "SYNC_TIMEOUT",
    "DIAGNOSTIC_COMMANDS",
    "RC_MEANINGS",
    "SyncOutcome",
    "console_encoding",
    "decode_console",
    "find_repadmin",
    "join_status",
    "looks_failed",
    "manual_command",
    "diagnostics_text",
    "name_resolves",
    "resolve_dc_name",
    "sync_all",
]

_log = get_logger("replication")


# ============================================================================
# 常量
# ============================================================================

#: `repadmin /syncall` 的开关。**逐字保真，不许改大小写**（见模块头第 1 条）。
#:
#:   /A  同步<b>所有</b>命名上下文（schema / configuration / 域 / DNS 分区），
#:       只推默认域分区的话，GC 的**部分属性集**不一定跟着走；
#:   d   输出里用 DN 标识服务器（而不是 GUID）—— 只为可读，出错时人能看懂；
#:   e   **跨站点**：不含它就只同步本站点内的伙伴（默认站点 = 只主站点），
#:       而"约一小时"这个症状本身就指向跨站点；
#:   P   **往外推**（默认是往里拉）。这一位最关键：我们要的是"把这台域控上
#:       刚写的改动推出去"，不是"让它去别人那里拉"。
SYNC_SWITCHES = "/AdeP"

#: 可执行文件名。本机实测：装过 RSAT/AD DS 工具的工作站上就有它。
REPADMIN = "repadmin"

#: 命令超时（秒）。跨站点推给所有伙伴，几十秒是常态。
#: ⚠️ **超时不算"确定没同步"** —— 命令可能已经发出去了，只是我们没等到它回来。
#: 所以超时单独一个字段（`SyncOutcome.timed_out`），不并进"失败"里糊成一团。
SYNC_TIMEOUT = 120.0

#: 存进结果对象/日志的输出长度上限（**判废用的是全文，不是这份截断**）。
MAX_OUTPUT = 2000

#: 输出里出现这些字样 ⇒ **即便退出码是 0 也要当失败**。
#:
#: ⚠️ 只用明确表示失败的词，**不放宽泛的 `error`**：`repadmin` 的帮助界面里
#: 也可能出现这类词，误报会把"成功"报成"失败"（这个项目已经吃过"判据说谎"
#: 的亏）。中文 Windows 上输出是中文，所以中英都要覆盖。
#:
#: 依据是**真实失败样本**（本机实测）：`到 192.0.2.1 的 DsBindWithCred 失败，
#: 状态: 87 (0x57): 参数错误。` ——「失败」与「错误」都在里面。
_FAILURE_MARKERS = ("失败", "错误", "terminated with errors", "failed")

#: 官方文档里成功时的收尾句（英文）。**只当诊断参照，不当判据** ——
#: 中文系统上这句话大概率是本地化过的，而我们**没取到过真域成功样本**
#: （见模块头"没做的部分"），不能拿一句没见过的话去判生死。
SUCCESS_MARKER = "terminated with no errors"

#: 结果**原因码**。给机器判"该不该弹提示"用，**不是给人看的文案** ——
#: 靠文案里有没有某个词来决定要不要提示，是最脆的那类判据。
REASON_RAN = "ran"                        # 真的执行了（成败另看 `ok`）
REASON_DEMO = "demo"                      # 演示模式：预期不执行
REASON_NOT_CONNECTED = "not-connected"    # 没有已建立的连接
REASON_NO_TOOL = "no-tool"                # 本机没装 repadmin
REASON_NO_NAME = "no-name"                # 拿不到 repadmin 认的域控名
REASON_IP_NAME = "ip-name"                # 只拿得到 IP（不许用）
REASON_UNRESOLVED = "unresolved"          # 名字拿到了，但**本机解析不了**
REASON_ERROR = "error"                    # 调用过程中出了意外
#: 命令真的跑了、rc 也是 0，但**一个字节的输出都没拿到** ⇒ 无从判断成败。
#: ⚠️ 有它自己的原因码，正是为了让它**不落进 `silent`**（见 `_SILENT_REASONS`）。
REASON_NO_EVIDENCE = "no-evidence"

#: 这些原因属于「**没有下一步动作**」⇒ 不该弹提示。
#:
#: ⚠️ 演示模式必须在这里。踩过：加这条提示的**第一版在演示模式下也弹**，
#:    结果把上一条**更重要的**提示挤掉了 —— 当时被挤的是"账号已建好，但 N 个
#:    权限组没挂上"，而**那条用例与功能已随「共享盘权限」功能线一起删除**
#:    （墓碑：`tests/test_ui_smoke.py:17-24`，列了被删的
#:    `TestCreateUserGrantsPermissionGroups` 等三类），
#:    ⚠️ **不要再引用那条不存在的用例名**
#:    （`test_a_failing_group_does_not_hide_the_created_account` ——
#:    2026-09-16 全仓 grep 确认它已经不在任何 `def` 里了）。今天这条不变式的证据是活的：
#:    `tests/test_replication.py::TestWhenToSpeak` 里的
#:    `test_the_demo_skip_is_silent` / `test_a_disconnected_skip_is_silent`；
#:    现在最容易被它挤掉的兄弟提示是建号成功那条 `已创建：<DN>`
#:    （`ui_browser._on_created_user` 里 `notify` 之后紧接着就
#:    `_sync_after_change("新建用户")`）。
#:    提示条是一次性的：后一条弹出来，前一条就永远看不到了。
#:
#: 🔴 `REASON_UNRESOLVED` **必须不在**这张表里：它要的正是使用者**动手**
#:    （改 hosts / 换 DNS / 去域控上跑）—— 静默就等于没做。
#: 🔴 `REASON_NO_EVIDENCE` 同理**必须不在**：它是"跑了但拿不到证据"，
#:    使用者的下一步是去核（`repadmin /replsummary`），静默就等于把
#:    "不知道"说成了"没问题"。
_SILENT_REASONS = frozenset({REASON_DEMO, REASON_NOT_CONNECTED})

#: 退出码 → 中文含义。**只放有实测依据的**（见模块头第 2 条与追加那节）。
#:
#: ⚠️ 这张表**不是**"把能想到的都列上"。编一个没实测过的含义**比只给数字更坏**
#:    —— 它会把使用者引去查一个不存在的问题（本项目红线：确定的错答案比
#:    "不知道"糟）。表里没有的 rc 就照旧显示 `返回码 <数字>`，一个字都不许编。
RC_MEANINGS: dict[int, str] = {
    87: "参数形态错误（`/syncall` 不接受 IP 形式的域控名）",
    1722: "RPC 服务器不可用",
}

#: `NetGetJoinInformation` 的返回状态（Windows SDK：`NETSETUP_JOIN_STATUS`）。
_JOIN_UNKNOWN = 0        # NetSetupUnknownStatus
_JOIN_UNJOINED = 1       # NetSetupUnjoined
_JOIN_WORKGROUP = 2      # NetSetupWorkgroupName
_JOIN_DOMAIN = 3         # NetSetupDomainName

#: 状态 → 本模块的两种口径。
#:
#: ⚠️ `NetSetupUnjoined`（没加入任何域、也没有工作组）也归到 `workgroup`：
#:    对本次判断而言它与"在工作组里"是**同一种处境** —— 登录会话里没有域凭据，
#:    `repadmin` 只能拿本机身份去绑 RPC。名字缓冲区此时通常是空的。
_JOIN_KINDS: dict[int, str] = {
    _JOIN_UNJOINED: "workgroup",
    _JOIN_WORKGROUP: "workgroup",
    _JOIN_DOMAIN: "domain",
}

#: 配套诊断命令。**只作为文本提供，工具不代跑。**
#:
#: ⚠️ 为什么不做成"一键执行"：最后一条 `net stop netlogon` 会**中断本机认证**
#: （域登录/访问共享盘会短暂失败）。有中断的动作让工具替使用者按下去，属于
#: 越界 —— 把那行字给他，让他自己决定什么时候按。
DIAGNOSTIC_COMMANDS: tuple[tuple[str, str], ...] = (
    ("看这台域控与每个伙伴的复制状态（哪条链接红了）", "repadmin /showrepl"),
    ("看复制健康度汇总（最快定位断掉的链路，建议先看这条）", "repadmin /replsummary"),
    ("全量域控体检（DNS / 服务 / 复制 / 权限，要几分钟）", "dcdiag"),
    ("重启 Netlogon 服务（⚠️ 会短暂中断本机认证，慎用）",
     "net stop netlogon && net start netlogon"),
)


# ============================================================================
# 控制台编码
# ============================================================================

def console_encoding() -> str:
    """控制台程序输出用的编码名（Windows 上 = OEM 代码页，如 `cp936`）。

    ⚠️ **不要用 `locale.getpreferredencoding(False)` 代替。** 本机实测：

        GetOEMCP()                          = 936
        locale.getpreferredencoding(False)  = 'utf-8'     ← 说谎
        sys.flags.utf8_mode                 = 1

    Python 在 UTF-8 模式下，`locale` 报的是 **Python 自己要用的编码**，
    而不是**控制台实际吐出来的编码**。拿它去解 `repadmin` 的输出必然乱码。
    """
    try:
        codepage = int(ctypes.windll.kernel32.GetOEMCP())      # type: ignore[attr-defined]
        if codepage > 0:
            return f"cp{codepage}"
    except Exception:                       # noqa: BLE001 - 非 Windows / 取不到
        pass
    return locale.getpreferredencoding(False) or "utf-8"


def _tidy(text: str) -> str:
    """规范化行尾。

    `repadmin` 用的是 **`\\r\\r\\n`**（本机实测）—— 不归一化的话，按 `\\n` 拆行
    会在每行尾巴留一个 `\\r`，日志里看起来像乱码。
    """
    return (text.replace("\r\r\n", "\n")
                .replace("\r\n", "\n")
                .replace("\r", "\n")
                .strip())


def decode_console(raw: bytes) -> str:
    """把外部命令输出的**原始字节**解成文本。**永不抛异常。**

    顺序是先 `console_encoding()`（字节就是从那儿来的，这是定义）再 `utf-8`
    （万一某个工具就是吐 UTF-8）。两条都不行才上 `errors="replace"`。

    🔒 解码失败**不许影响判决**：成功/失败的判据是退出码 + 关键字，
    都是 ASCII 层面的事，乱码只会让人看不懂细节，不会让结论翻面。
    """
    if not raw:
        return ""
    first = console_encoding()
    for encoding in (first, "utf-8"):
        try:
            return _tidy(raw.decode(encoding))
        except (UnicodeDecodeError, LookupError):
            continue
    return _tidy(raw.decode(first, errors="replace"))


def looks_failed(text: str) -> bool:
    """输出里有没有**明确表示失败**的字样。纯函数，便于单独验。"""
    lowered = (text or "").lower()
    return any(marker in lowered for marker in _FAILURE_MARKERS)


# ============================================================================
# 本机状态：加域 / 名字能不能解析（两道**发命令之前**就能下结论**的闸）
# ============================================================================

def _netapi32():
    """`netapi32` 的两个入口 ⇒ `(NetGetJoinInformation, NetApiBufferFree)`。

    **本模块唯一的 ctypes 接触点**，单独抽出来只有一个理由：判据要能在这里
    打桩。真调一次是安全的（纯本机调用、不发网络包），但它**答什么随机器状态变**
    —— 加域的机器与不加域的机器给的是两句不同的话，拿它当判据的输入就成了
    "看运气"。打桩之后「状态 → 文案」这条映射才**可单独验**。
    """
    api = ctypes.windll.netapi32                  # type: ignore[attr-defined]
    get = api.NetGetJoinInformation
    free = api.NetApiBufferFree
    # ⚠️ 必须显式声明原型。不声明的话 64 位下指针会被当成 32 位 int ——
    #    那是"在某些机器上才对"的那类 bug，最难查。
    get.argtypes = [ctypes.c_wchar_p,               # LPCWSTR lpServer（None=本机）
                    ctypes.POINTER(ctypes.c_wchar_p),   # LPWSTR *lpNameBuffer
                    ctypes.POINTER(ctypes.c_int)]       # PNETSETUP_JOIN_STATUS
    get.restype = ctypes.c_ulong
    free.argtypes = [ctypes.c_void_p]
    free.restype = ctypes.c_ulong
    return get, free


def join_status() -> tuple[str, str]:
    """本机加域状态 ⇒ ``('domain' | 'workgroup' | 'unknown', 名字)``。

    `1722`（RPC 服务器不可用）时用来给出**最可能**的原因：
    未加域的机器上 `repadmin` 只能拿**本机身份**去绑 RPC，会被域控拒掉。

    ⚠️ 这是**判据**不是结论（文案里一律写"最可能"）。**永不抛异常** ——
    它跑在"建号/删号已经成功"之后的收尾路径上，任何意外都不该把那条成功
    变成报错；答不上来就老实答 `('unknown', '')`。

    🔴 名字缓冲区是 `NetGetJoinInformation` 用 `NetApiBufferAllocate` **分配**的
       （不是我们传进去的），拿到名字后**必须** `NetApiBufferFree` —— 不还就是
       每次调用泄漏一块内存。

    实测（本机 2026-09-16）：返回 `('workgroup', 'WORKGROUP')` —— 注意缓冲区里
    是**工作组名**（这台机器的工作组就叫默认名 WORKGROUP），**不是计算机名**
    （计算机名在 `USERDOMAIN` 里、是那台机器自己的名字）。别把这两个搞混。
    """
    try:
        get, free = _netapi32()
    except Exception:                             # noqa: BLE001 - 非 Windows / 取不到
        return "unknown", ""
    buf = ctypes.c_wchar_p()
    status = ctypes.c_int(_JOIN_UNKNOWN)
    try:
        code = int(get(None, ctypes.byref(buf), ctypes.byref(status)))
        kind = _JOIN_KINDS.get(int(status.value), "unknown")
        name = (buf.value or "").strip()
    except Exception:                             # noqa: BLE001 - 任何异常都不许抛
        return "unknown", ""
    finally:
        try:
            pointer = ctypes.cast(buf, ctypes.c_void_p).value
            if pointer:                           # 没分配（如未加入任何组）就别还
                free(pointer)
        except Exception:                          # noqa: BLE001 - 还不了也不许抛
            pass
    if code != 0 or kind == "unknown":
        return "unknown", ""                  # 判不出来就别带一个来路不明的名字
    return kind, name


def name_resolves(name: str) -> bool:
    """这个名字在**本机**能不能解析出来（`socket.getaddrinfo` **正查**）。永不抛。

    ⚠️ 和 `resolve_dc_name` 里那个 `socket.gethostbyaddr` **不是一个方向**：
    那个是**反查**（IP → 名字），这个是**正查**（名字 → IP）。`repadmin` 要的是
    "**我这台机器**能不能解析这个名字"，只有正查能回答 —— 拿反查的结果冒充
    "已经校验过了"是**假证据**。

    为什么零副作用也要单独判一道：

      * 本机实测 `repadmin /syncall <解析不了的名字>` ⇒ **rc=1722**，
        和"RPC 被拒"**报的是同一个数字** —— 光看 1722 分不出是哪一件事；
      * 而"解析不了"**在发命令之前**就能判出来（零副作用、不连域控、不绑凭据）。

    ⇒ 本项目最忌"发一条注定失败的命令"：`rc=87`（IP 形式）已经拦住了一次，
    这一类（名字解析不了）是同一条原则，原来漏了。
    """
    text = (name or "").strip().rstrip(".")
    if not text:
        return False
    try:
        return bool(socket.getaddrinfo(text, None))
    except Exception:                             # noqa: BLE001 - gaierror 是常态
        return False


# ============================================================================
# 定位可执行文件 / 解析域控名
# ============================================================================

def find_repadmin() -> str:
    """定位 `repadmin.exe`；找不到返回**空串**。

    先查 `PATH`，再查 `%SystemRoot%\\System32\\repadmin.exe`。
    为什么还要手查第二个：**打包成 exe 之后 PATH 可能被收窄**
    （PyInstaller 起的环境不保证继承完整 PATH），而 System32 是 RSAT 与
    域控上的标准落点。
    """
    found = shutil.which(REPADMIN)
    if found:
        return found
    system_root = os.environ.get("SystemRoot") or r"C:\Windows"
    candidate = os.path.join(system_root, "System32", REPADMIN + ".exe")
    return candidate if os.path.isfile(candidate) else ""


def _is_ip_literal(text: str) -> bool:
    """是不是一个 IP 字面量（v4 或 v6）。"""
    try:
        ipaddress.ip_address((text or "").strip())
        return True
    except ValueError:
        return False


def _is_loopback(ip: str) -> bool:
    """是不是回环地址（`127.0.0.0/8`、`::1`）。非 IP / 空串 ⇒ False。**永不抛**。"""
    try:
        return bool(ipaddress.ip_address((ip or "").strip()).is_loopback)
    except ValueError:
        return False


def _same_address(left: str, right: str) -> bool:
    """两个地址是不是同一个（**规范化后**比：`::1` == `0:0:0:0:0:0:0:1`）。

    ⚠️ 直接比字符串会把"同一个地址的不同写法"判成两台机器 —— 那正是
    FCrDNS 最不能出的假红。
    """
    try:
        return (ipaddress.ip_address((left or "").strip())
                == ipaddress.ip_address((right or "").strip()))
    except ValueError:
        return False


def _first_label(text: str) -> str:
    """名字的**第一段**（第一个 `.` 之前），小写。NetBIOS 短名靠它与 FQDN 对齐。"""
    return (text or "").split(".", 1)[0].strip().lower()


def _is_this_machine(name: str) -> bool:
    """这个名字是不是**本机自己**（`socket.gethostname`）。**永不抛**。

    🔴 为什么必须有这道闸 —— 2026-09-16 本机实跑复现：

        socket.gethostbyaddr("127.0.0.1")  ⇒  ('<本机名>', [], ['127.0.0.1'])

    Windows 上它返回的是**本机主机名**，而那个名字**不是** IP 字面量 ⇒ 原来
    第②级那道 `name_resolves(pointer)` 直接放行 ⇒ `resolve_dc_name` 把**本机**
    当成域控名返回。两个真实后果：

      * 验收报告打出「repadmin 认的域控名：<本机名>」—— **报告在撒谎**；
      * `workers.sync_replication` 在 `dnsHostName` 缺失时会走这条路 ⇒ 真的执行
        `repadmin /syncall <本机名> /AdeP`，**对错误的机器发命令**。

    ⚠️ **只取 `gethostname()`，不取 `socket.getfqdn()`** —— 这是有依据的取舍，
    不是漏了（实现在 `socket.getfqdn` 源码里，本机实测）：

        def getfqdn(name=''):
            ...
            hostname, aliases, ipaddrs = gethostbyaddr(name)   ← 同一条路！

    `getfqdn()` **内部就是** `gethostbyaddr` —— 而那正是本闸正在验证的那条反查。
    拿它当"本机身份"的独立 oracle 是**循环**的：实测在
    `patch("socket.gethostbyaddr", return_value=("dc01.corp.example.com", ...))`
    之下 `getfqdn()` 就返回 `'dc01.corp.example.com'` ⇒ 任何桩住反查的用例都会
    被自己的桩毒到（`tests/test_replication.py` 里 `TestDcNameResolution` 那两条
    既有用例正是这个形状），而这个 oracle 的**覆盖量是零**：
    "NetBIOS 短名 vs FQDN" 由下面的「取 `.` 前第一段再比一次」覆盖
    （`<本机名>` 与 `<本机名>.corp.local` 的第一段都是它）。
    另外 `getfqdn()` 每次调用都要发一次**反查**，而本闸要的是零副作用的判断。

    ⚠️ 代价（**明知故犯**的那一半）：本机短名与域控 FQDN 第一段**恰好同名**时
    也会被拒（例如本机就叫 `dc01`）。两边的代价不对称 —— 拒的代价只是退回
    第③级那个**更权威**的 RootDSE 名字；放行的代价是**对错误的机器发命令**。
    """
    text = (name or "").strip().rstrip(".")
    if not text:
        return False
    try:
        local = (socket.gethostname() or "").strip().rstrip(".")
    except Exception:                       # noqa: BLE001 - 取不到就当没有这台机器
        return False
    if not local:
        return False
    suspects = {local.lower(), _first_label(local)}
    return text.lower() in suspects or _first_label(text) in suspects


def _forward_confirms(name: str, ip: str) -> bool:
    """FCrDNS：`name` **正查**回不回到我们问的那个 `ip`。**永不抛**。

    ⚠️ "查不动"时返回 `True` —— **无从否认就不拦**。这一关要拒的是**已知的错**
    （"这个名字指向另一台机器"），不是"我们查不到"：可解析性已经由
    `name_resolves` 那一关确认过，而"本机解析不了"在本模块**从来不构成丢名字的
    理由**（第③④级是同一条原则 —— 手工命令要在**域控上**跑）。
    生产路径上这两次正查走的是同一个 `socket.getaddrinfo`，
    所以"第一关过了、这一关却查不动"实际上不可达 ⇒ 等价于严格 FCrDNS。
    """
    text = (name or "").strip().rstrip(".")
    if not text:
        return False
    try:
        infos = socket.getaddrinfo(text, None)
    except Exception:                       # noqa: BLE001 - 查不动 ⇒ 不构成拒绝的理由
        return True
    addresses: list[str] = []
    for info in infos or ():
        try:
            addresses.append(info[4][0])
        except (IndexError, TypeError):      # 形状不对的条目跳过，不许影响判决
            continue
    if not addresses:
        return True
    return any(_same_address(address, ip) for address in addresses)


def resolve_dc_name(dns_host_name: str = "", dc_ip: str = "") -> tuple[str, str]:
    """给出一个 `repadmin` **认**的域控名。返回 `(名字, 拿不到的原因)`。

    顺序（**能解析的名字优先**，其次才是兜底）：

      1. **RootDSE 的 `dnsHostName`** —— 那台域控**自己报**的名字，最权威；
         连接域控时已经反查到了（`ad_client.connect` → `DomainInfo.dns_host_name`），
         直接拿来用，不额外发网络请求。**且它在本机能解析** ⇒ 就用它。
      2. 拿不到（或解析不了）⇒ `dc_ip` 的 **PTR 反查**（`socket.gethostbyaddr`），
         反查到的名字**能解析** ⇒ 用它。⚠️ 但这个名字还要过**两道闸**
         （见下），过不了就**当它不存在**（连第④级的兜底都不许用）。
      3. RootDSE 的名字**形式合法、但本机解析不了** ⇒ **仍然返回它**。
         理由：它是那台域控**自己报**的名字，在**域控上**手工执行那条命令时
         是通的 —— "本机解析不了"这件事由 `sync_all` 里那道闸去解释
         （`REASON_UNRESOLVED`），不在这里把它丢掉（丢掉了连手工命令都没得抄）。
      4. 同理，PTR 名字解析不了也照样兜底返回。
      5. 都没有 ⇒ 返回 **空名 + 原因**，**绝不把 IP 当名字往下传**。

    🔴 第②级的两道新闸（2026-09-16，本机实跑复现的缺陷）：

      ① **回环短路**：`ip` 是回环（`127.0.0.0/8` / `::1`）时**直接不反查** ——
         回环的 PTR 只可能是本机，反查毫无意义；
      ② **本机名排除**（`_is_this_machine`）+ **FCrDNS**（`_forward_confirms`）：
         PTR 拿到的名字必须**不是本机自己**、且**正查能回到我们问的那个 IP**。

    为什么必须有：Windows 上 `socket.gethostbyaddr("127.0.0.1")` 返回
    **本机主机名**，而那个名字不是 IP 字面量 ⇒ 原来那道"能解析"就放行 ⇒
    `resolve_dc_name("dc01.demo.local", "127.0.0.1")` 返回 `('<本机名>', '')`
    —— 报告会打出"repadmin 认的域控名：<本机名>"（**在撒谎**），
    而 `workers.sync_replication` 会真的执行 `repadmin /syncall <本机名> /AdeP`
    （**对错误的机器发命令**）。
    ⚠️ 被这两道闸拒掉的名字**只叫"第②级不能用"**：流程**照旧往下走**（第③④⑤级
    一个字都没动），所以缺 `dnsHostName` 时返回的是第③级那个**诚实**的答案
    ——"那台域控自己报的名字，本机解析不了"。真域里 `dc_ip` 是真实域控 IP 时
    FCrDNS 通过 ⇒ 第②级行为与加闸之前**一模一样**。

    ⚠️ 第 5 条是本函数存在的**全部理由**：`repadmin /syncall <IP>` 一律
    `rc=87「参数错误」`（本机实测），拿 IP 去跑只会让使用者以为是权限问题。
    宁可明确报「没执行」，也不要执行一次注定失败的命令 —— 那正是本项目
    最忌讳的「确定的错答案」。

    ⚠️ 返回值**不携带**"能不能解析"这个信息（契约固定是 `(名字, 原因)`）：
    解析与否是**本机**的属性，由 `sync_all` 那道闸判（`REASON_UNRESOLVED`）——
    在这里偷偷丢掉一个解析不了的名字，会让上层连"该抄哪条命令"都说不出来。
    """
    rootdse = (dns_host_name or "").strip().rstrip(".")
    if _is_ip_literal(rootdse):
        rootdse = ""                        # IP 字面量不是"名字"

    if rootdse and name_resolves(rootdse):
        return rootdse, ""

    ip = (dc_ip or "").strip()
    pointer = ""                            # PTR 反查出来的名字（可能解析不了）
    pointer_ip = ""                         # PTR 只反查回另一个 IP 时记在这里
    refused = ""                            # 🔴 反查到的名字**已知是错的** ⇒ 连兜底都不许用
    loopback = _is_loopback(ip)             # 回环的反查只会得到本机名（见 docstring）
    if ip and not loopback:
        try:
            pointer = (socket.gethostbyaddr(ip)[0] or "").strip().rstrip(".")
        except Exception:                   # noqa: BLE001 - 无 PTR 记录是常态
            pointer = ""
        if pointer and _is_ip_literal(pointer):
            pointer_ip, pointer = pointer, ""
        # 🔴 第②级的两道新闸：本机名 / FCrDNS（见 docstring）
        if pointer and (_is_this_machine(pointer)
                        or (name_resolves(pointer)
                            and not _forward_confirms(pointer, ip))):
            refused, pointer = pointer, ""

    if pointer and name_resolves(pointer):
        return pointer, ""

    # 兜底：形式上是个名字就返回它 —— 手工命令里要展示这个名字
    if rootdse:
        return rootdse, ""
    if pointer:
        return pointer, ""

    if not ip:
        return "", ("拿不到这台域控的 DNS 名（RootDSE 没反查到 dnsHostName，"
                    "也没给 IP 可反查）")
    if refused:
        return "", (f"{ip} 的 PTR 反查拿到的是「{refused}」，而它不是我们要问的"
                    "那台域控（那名字是本机自己 / 正查回的是另一台机器）"
                    "⇒ 不敢拿它去跑")
    if loopback:
        return "", (f"{ip} 是回环地址（它的 PTR 只会反查回本机）⇒ 不作域控名；"
                    "RootDSE 也没反查到 dnsHostName")
    if pointer_ip:
        return "", (f"{ip} 的 PTR 反查只得到另一个 IP（{pointer_ip}），"
                    "而 repadmin 「不接受 IP 形式的域控名」 ⇒ 不敢拿它去跑")
    return "", (f"拿不到这台域控的 DNS 名：RootDSE 没反查到 dnsHostName，"
                f"{ip} 也没有 PTR 记录（而 repadmin 不接受 IP 形式的域控名）")


# ============================================================================
# 退出码 → 人话
# ============================================================================

def _rpc_bind_hint(join_kind: str, join_name: str) -> str:
    """`1722`（RPC 服务器不可用）**最可能**的原因与下一步。**纯函数**。

    ⚠️ 通篇写「**最可能**」：加域与否是**概率最高**的那条线索，**不是结论**
    （本项目红线：把使用者引去查一个不存在的问题，比只给他一个数字更坏）。

    分三个分支的唯一理由：**下一步动作完全不同** ——
    未加域要换一个身份去跑（或换台机器跑），已加域要去查 RPC 那一路的
    通路/服务；判不出来时两条都要列，但**不许替使用者挑一条**。
    """
    if join_kind == "workgroup":
        state = (f"本机在「工作组」「{join_name}」里（未加域，"
                 "当前登录会话里没有域凭据）" if join_name
                 else "本机未加域（当前登录会话里没有域凭据）")
        return (f"最可能的原因：{state} ⇒ `repadmin` 会拿「本机身份」去做 RPC "
                "绑定，被域控拒掉。两条路：\n"
                "  ① 在「域控上」执行上面那条命令（最简单，本机不用加域）；\n"
                "  ② 在本机起一个「带域凭据」的会话：\n"
                "     runas /netonly /user:<域>\\<账号> cmd /k \"<上面那条命令>\"\n"
                "     ⚠️ `/netonly` 只把凭据用于「网络访问」 ⇒ 本机不加域也能用；"
                "它会弹一个密码框，做不到无人值守。")
    if join_kind == "domain":
        state = f"本机「已加域」（域：{join_name}）" if join_name else "本机「已加域」"
        return (f"最可能的原因：{state} ⇒ 加域本身不是问题，更可能是「这一路 RPC "
                "被挡」（135 端口 + 动态端口没放通）或那台域控的 RPC 服务异常。\n"
                "先在域控上执行 `repadmin /replsummary` 看链路，"
                "再查防火墙的 RPC 规则。")
    return ("最可能的原因判不出来（`NetGetJoinInformation` 没答上来），"
            "所以下面两条都只是「最可能」，不敢写死：\n"
            "  ① 本机「未加域」（登录会话里没有域凭据）⇒ `repadmin` 拿本机身份"
            "做 RPC 绑定会被拒；要么在域控上执行，要么用 `runas /netonly` "
            "起一个带域凭据的会话；\n"
            "  ② 本机「已加域」，但「这一路 RPC 被挡」（135 + 动态端口）"
            "或目标域控的 RPC 服务异常 ⇒ 先看 `repadmin /replsummary` 与防火墙。")


def _rc_note(returncode: int | None, *, timed_out: bool = False,
             seconds: float | None = None, join_kind: str = "",
             join_name: str = "") -> str:
    """退出码 → 给人看的一句话。**纯函数**（无 I/O、无 subprocess）⇒ 便于判据。

      * `timed_out` ⇒ 超时。**不能说"确定没同步"** —— 命令可能已经发出去了；
      * `returncode is None` ⇒ **根本没拿到**（进程没正常返回）⇒ 老实说"没拿到"，
        🔴 **不许吐「返回码 None」**：`None` 不是返回码，写出来就是**名字在说谎**
        （使用者会拿着"返回码 None"去查一个不存在的东西），
        而且它还容易被误读成"0 的一种"；
      * 表里有的 rc ⇒ 中文含义（`1722` 再补一句**最可能**的原因与下一步）；
      * 🔴 表里没有的 rc ⇒ **照旧只给数字**，一个字都不编（见 `RC_MEANINGS`）。

    `seconds` 只是让"超时多少秒"说实话：调用方可能传了**非默认**的超时，
    这时候拿 `SYNC_TIMEOUT` 去写文案就是错的。省略则用 `SYNC_TIMEOUT`。
    """
    if timed_out:
        waited = SYNC_TIMEOUT if seconds is None else seconds
        return (f"命令超时（{waited:.0f}s 内没返回）。"
                "⚠️ 命令「可能已经发出去了」，不能断定没同步 —— "
                "建议用 `repadmin /replsummary` 看结果。")
    if returncode is None:
        return ("没拿到命令的退出码（它没有正常返回）⇒ 「无法」判断这次同步"
                "到底做没做，请人工看一眼输出。")
    meaning = RC_MEANINGS.get(returncode)
    if meaning is None:
        return f"返回码 {returncode}。"
    note = f"返回码 {returncode}：{meaning}。"
    if returncode == 1722:
        note += "\n" + _rpc_bind_hint(join_kind, join_name)
    return note


# ============================================================================
# 执行
# ============================================================================

@dataclass(frozen=True)
class SyncOutcome:
    """一次强制同步的结果。

    **三态**（不许把"没做"和"做失败了"混成一个 —— 下一步动作完全不同）：

      * ``ran=False``                     ⇒ **没执行**（演示模式 / 没装 repadmin /
        拿不到域控名 / 起不来进程）
      * ``ran=True, ok=True``             ⇒ 命令报告同步无错误
      * ``ran=True, ok=False``            ⇒ 执行了但失败（含超时）

    ``ran`` 的含义是「**我们确实调用了外部命令**」—— 命令启动失败（如文件存在
    但没有执行权限）也算 `ran=True`，因为那是一次真实的调用尝试，
    跟"我们压根没打算跑"是两回事。
    """

    ran: bool = False
    ok: bool = False
    returncode: int | None = None
    timed_out: bool = False
    #: 原因码（`REASON_*`）。**结构化**，别靠解析 `detail` 的文案来判断。
    reason: str = ""
    #: 中文说明，可直接给使用者看。
    detail: str = ""
    #: 命令输出（已解码、已按 `MAX_OUTPUT` 截断）。**判决用的是全文**，
    #: 这份只是给人看的副本。
    output: str = ""
    #: 实际用的域控名（排障用：能看出到底推的是哪一台）。
    dc_name: str = ""

    @property
    def skipped(self) -> bool:
        return not self.ran

    @property
    def silent(self) -> bool:
        """这次结果**值不值得弹一条提示**。

        提示条是一次性的（`toast`）—— 后一条弹出来，前一条就**永远看不到了**。
        所以判断标准不是"有没有结果"，而是「**使用者有没有下一步动作要做**」：

          * 演示模式的"没执行"、没有连接 ⇒ **预期状态**，弹了只会挤掉更重要的提示；
          * 成功 ⇒ **不弹**。需求要的是"失败告警"，一条"已推送复制"属于噪声，
            而它每次建号/删号都会出现（最高频的路径上挂一串噪声）。
            成功的记录进日志就够（`workers.sync_replication` 里有 INFO）。
          * 失败 / 没装工具 / 拿不到域控名 ⇒ **要弹**，因为这些下一步得动手。

        ⚠️ 这条判断**没法靠"有没有 detail"来做** —— 上面每一种都有 detail。
        """
        if self.reason in _SILENT_REASONS:
            return True
        return self.ran and self.ok

    @property
    def notice_key(self) -> tuple:
        """这条结果"**要说的那件事**"的结构化指纹 —— 界面层用它判"说过了没有"。

        为什么指纹里**不含 `what`（动作名）**：同一台机器上
        "新建用户推不动"和"删除对象推不动"是**同一件事**（同一台域控、同一个原因码），
        而它恰恰是重复弹得最凶的形态 —— 把动作名算进指纹等于去重完全失效。

        为什么**要含** `returncode` / `timed_out` / `dc_name`：它们**变了就是换了一件事**
        —— `1722`（RPC 不可用）变成 `87`（参数形态）是另一种故障；
        `dc_name` 变了说明目标换了一台域控（`REASON_UNRESOLVED` 时那句
        "本机解析不了域控名「X」"里的 X 就来自它）。这三样都是**新信息**，
        必须重新说一遍，不许被上一句压掉。

        ⚠️ 这是"**给谁看**"的指纹，不是判决用的（判决一律看 `reason`）。
        """
        return (self.reason, self.returncode, self.timed_out, self.dc_name)

    def notice(self, what: str) -> tuple[str, str]:
        """给界面用的 `(文案, 级别)`。级别取值与 `notify()` 一致。

        调用方应当**先看 `silent`**（`ui_browser._on_synced` 就是这么做的）；
        本方法只管把该说的话说对。

        级别只分两档，理由：**建号/删号已经成功了**，同步的任何结果都不该
        用 danger —— 那会让人以为操作本身失败。所以成功给 `ok`，
        其余一律 `warn`（意思是"要动手补一下"）。

        🔴 三个分支的**第一句**都必须先钉死「对象操作已经生效、无需重做」：
        旧文案的失败分支写的是「…已成功，但强制复制同步**没成功**」——
        「没成功」这三个字紧跟在"新建/删除"后面，读起来像**要重做建号/删号**
        （现场真会有人去重删一次）。对象已经写进 AD 了，这句话必须说在
        同步那半句**之前**。

        🔴 失败分支末尾补一条**降噪事实**：同站点复制的默认间隔约 15 秒 ⇒
        强制同步这一步失败**基本无害**（只有 `repadmin /replsummary` 真报出
        故障才需要处理）。不说这句，使用者会把它当成一次故障去追。
        """
        # 🔴 下面这一分支必须**也**给出可复制命令 —— 而且它才是最需要的那一条。
        #    未加域的机器上跑这个工具时，"没执行"是**常态**（`REASON_NO_TOOL`
        #    / `REASON_NO_NAME` / `REASON_IP_NAME` / `REASON_UNRESOLVED` /
        #    `REASON_ERROR` 全是 `ran=False`）。也就是说：使用者**最需要**
        #    那条命令的场景，恰恰是这一条分支。不给 ⇒ 提示等于半句空话。
        if not self.ran:
            return (f"{what}已成功（「已经生效、不需要重做」）；"
                    f"只是「没有」执行强制复制同步 —— {self.detail}\n"
                    f"可在域控上手工执行：{manual_command(self.dc_name or '<域控的DNS名>')}\n"
                    f"先看链路：repadmin /replsummary"), "warn"
        if self.ok:
            return (f"{what}已成功（「已经生效、不需要重做」），"
                    f"并已强制推送 AD 复制（{SYNC_SWITCHES} → {self.dc_name}）。"), "ok"
        if self.reason == REASON_NO_EVIDENCE:
            # 这一步**必须自己一条分支**，不许并进下面那条"没推成功"：
            # 那句话是**判决**，而这里我们手上**没有判决**（rc=0，但一个字节都没拿到）。
            # 把它说成"没成功"是另一种武断；说成"成功"则是撒谎。只能说"不知道"。
            return (f"{what}已成功（「已经生效、不需要重做」）：对象已经写进 AD，"
                    f"「不要」再建/删一次。\n"
                    f"强制复制同步「跑了、但拿不到证据」 —— {self.detail}\n"
                    f"可在域控上手工执行：{manual_command(self.dc_name or '<域控的DNS名>')}\n"
                    f"先看链路：repadmin /replsummary"), "warn"
        reason = self.detail or f"返回码 {self.returncode}"
        return (f"{what}已成功（「已经生效、不需要重做」）：对象已经写进 AD，"
                f"「不要」再建/删一次。\n"
                f"只是强制复制同步这一步没推成功：{reason}\n"
                f"可在域控上手工执行：{manual_command(self.dc_name or '<域控的DNS名>')}\n"
                f"先看链路：repadmin /replsummary\n"
                f"（补充：同站点复制的默认间隔约 「15 秒」 ⇒ 强制同步失败"
                f"「基本无害」；只有 `repadmin /replsummary` 真报出故障才需要处理。）"), "warn"


def manual_command(dc_name: str = "<域控的DNS名>") -> str:
    """给使用者抄的命令行。

    ⚠️ 占位符是 `<域控的DNS名>` 而不是 IP —— 拿 IP 去跑必然报参数错误，
    提示里给 IP 等于教人踩坑。
    """
    return f"repadmin /syncall {dc_name} {SYNC_SWITCHES}"


def diagnostics_text(dc_name: str = "") -> str:
    """把诊断命令列成一段可复制的文本（**只给文本，不执行**）。"""
    head = f"目标域控：{dc_name}" if dc_name else "（先在域控上执行，或加 /s:<域控名>）"
    lines = [head, ""]
    lines += [f"  {command}\n      # {reason}" for reason, command in DIAGNOSTIC_COMMANDS]
    return "\n".join(lines)


def sync_all(dc_name: str, *, exe: str = "", timeout: float = SYNC_TIMEOUT,
             runner: Callable | None = None) -> SyncOutcome:
    """对 `dc_name` 执行一次 `repadmin /syncall <dc_name> /AdeP`。**永不抛异常。**

    `runner` 是给判据用的注入点（默认 `subprocess.run`）—— **测试绝不允许
    真的跑 `repadmin`**：它会真的去推全域复制。判据必须对**实参**下断言
    （捕获到的 argv 是哪个 list、`/AdeP` 的大小写对不对），
    不能只验"被调用过"—— 只验调用次数的话，把参数换成 IP 也照样全绿。

    成功判据 = **`rc == 0` 且输出里没有失败字样**（见 `looks_failed`）。

    发命令之前有两道闸（**都只报"没执行"，绝不发一条注定失败的命令**）：

      * `REASON_IP_NAME`  —— 名字是个 IP（实测一律 `rc=87`）；
      * `REASON_UNRESOLVED` —— 名字**在本机解析不了**（实测同样报 1722，
        与"RPC 被拒"是同一个数字 ⇒ 光看数字分不出是哪一件事）。
    """
    exe = exe or find_repadmin()
    if not exe:
        return SyncOutcome(reason=REASON_NO_TOOL, detail=(
            f"本机没有找到 `{REPADMIN}.exe`（属于「AD DS 管理工具 / RSAT」）。"
            f"可按下面的命令在域控上手工执行：{manual_command(dc_name or None or '<域控的DNS名>')}"))

    name = (dc_name or "").strip()
    if not name:
        return SyncOutcome(reason=REASON_NO_NAME, detail=(
            "没拿到 repadmin 认的域控名，不敢拿 IP 去跑（会报「参数错误」）。"
            "请在能解析域控名的主机上手工执行。"))
    if _is_ip_literal(name):
        # 兜底闸：调用方理应已经用 resolve_dc_name 过滤过，这里再拦一道 ——
        # 这条路径如果被走到，说明上游漏了；宁可报"没执行"也不发一次注定 87 的命令。
        return SyncOutcome(reason=REASON_IP_NAME, dc_name=name, detail=(
            f"域控名是一个 IP（{name}），而 `repadmin` 「不接受 IP 形式的域控名」"
            f"（实测报「参数错误」）⇒ 本次没有执行。"))
    if not name_resolves(name):
        # 兜底闸之二（与上面那道**同一类**，2026-09-16 补）：
        # 名字形式是对的，但**本机解析不了** ⇒ 实测同样报 1722（与"RPC 被拒"
        # 报的是同一个数字，光看那个数字分不出是哪一件事）。而这件事**在发
        # 命令之前**就能判出来 ⇒ 不发一条注定失败的命令。
        return SyncOutcome(reason=REASON_UNRESOLVED, dc_name=name, detail=(
            f"本机解析不了域控名「{name}」（本地 DNS 正查失败）⇒ 「本次没有执行」。\n"
            f"`repadmin` 只吃域名、「不接受 IP」，所以这事必须先在「本机」解决：\n"
            f"① 在 `C:\\Windows\\System32\\drivers\\etc\\hosts` 加一行 "
            f"`<域控IP>  {name}`；\n"
            f"② 或把本机 DNS 指向内网域控；\n"
            f"③ 或直接在域控上手工执行：{manual_command(name)}"))

    argv = [exe, "/syncall", name, SYNC_SWITCHES]
    run = runner or subprocess.run
    try:
        proc = run(argv, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        _log.warning("强制 AD 复制同步超时（%.0fs）dc=%s", timeout, name)
        return SyncOutcome(
            ran=True, ok=False, timed_out=True, dc_name=name, reason=REASON_RAN,
            detail=_rc_note(None, timed_out=True, seconds=timeout))
    except Exception as exc:                 # noqa: BLE001 - 起不来也不许抛
        _log.warning("强制 AD 复制同步：无法启动 %s：%s", exe, exc)
        return SyncOutcome(ran=True, ok=False, dc_name=name, reason=REASON_RAN,
                           detail=f"无法启动 repadmin：{type(exc).__name__}: {exc}")

    raw = (getattr(proc, "stdout", b"") or b"") + (getattr(proc, "stderr", b"") or b"")
    full = decode_console(raw)
    code = getattr(proc, "returncode", None)

    # ⚠️ 判决用**全文**，展示用截断 —— 先判后截，别让截断吃掉那行错误。
    failed = looks_failed(full)
    #: 🔴 「一个字节的输出都没有」是**独立的一档**，既不归"成功"也不归"失败"。
    #:   实测里 `repadmin` 从没有过这种样本 ⇒ 更可能是**输出没被我们拿到**
    #:   （管道被吃/被包装器吞了），而不是"它做了事但没说话"。
    #:   旧实现在这里判 `ok=True` ⇒ 界面全静默 ⇒ 「搜不到」现场一个字都看不到。
    no_evidence = not full.strip()
    ok = (code == 0) and not failed and not no_evidence

    if ok:
        detail = "同步完成（返回码 0，输出里没有失败字样）。"
    elif code == 0 and no_evidence:
        detail = ("命令执行了、返回码是 0，但「没有拿到任何输出」 "
                  "⇒ 拿不到「这次复制真的发生了」的证据（不是「失败」，是「不知道」）。")
    elif code == 0:
        detail = "返回码是 0，但输出里出现了失败字样 —— 请人工看一眼原文。"
    else:
        # 只有 1722 需要"本机加域状态"这条线索；别在常用路径上白调一次 API。
        join_kind, join_name = ("", "")
        if code == 1722:
            join_kind, join_name = join_status()
        detail = _rc_note(code, join_kind=join_kind, join_name=join_name)

    reason = REASON_NO_EVIDENCE if (code == 0 and no_evidence) else REASON_RAN
    return SyncOutcome(ran=True, ok=ok, returncode=code, dc_name=name,
                       reason=reason, detail=detail,
                       output=full[:MAX_OUTPUT])
