# -*- coding: utf-8 -*-
"""
models.py —— 数据结构定义（业务层与 UI 层之间的契约）

放在独立文件的原因：`config.py` 与 `ad_client.py` 都要用这些类型，
若定义在 `ad_client.py` 里会形成循环导入。

🔒 红线：本文件中所有域相关字段的**默认值必须为空**。
   任何具体域的 IP / 域名 / BaseDN 都不得出现在这里。
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

__all__ = [
    "ConnConfig",
    "DomainInfo",
    "OuNode",
    "UserRow",
    "UserSpec",
    "AppConfig",
    "BatchItemResult",
    "BatchResult",
    # ---- ADUC 对齐（批次 1）：多对象类型 ----
    "ObjectKind",
    "DirObject",
    "AttributeChange",
    "ATTRIBUTE_BLACKLIST",
    "ATTRIBUTE_MANAGED",
    "is_attribute_writable",
    "lookup_attr",
    "verify_changes",
    "PROTECTED_CONTAINERS",
    "ModifyResult",
    "DeletePlan",
    "ObjectSpec",
]


# ============================================================================
# 连接配置
# ============================================================================

@dataclass
class ConnConfig:
    """一条域控连接配置。

    使用者**最少只需填 dc_ip / bind_user / password 三项**；
    ``base_dn`` 与 ``domain`` 留空时由 RootDSE 自动反查（见 discovery.py）。

    password 字段仅在内存中存在，**永不写入磁盘**（除非启用 DPAPI 记住密码）。

    ``id`` 是这条配置的**身份**（权威键）：``ConfigStore`` 负责分配并保证唯一，
    调用方**不要自己造**。为什么要单开一个身份字段、而不是继续用列表下标指认
    一条配置：下标是"位置"，位置在插入 / 删除 / 重排之后会**指到别人身上**，
    而且一声不响 —— 密码密文与连接记录过去正是按下标配对的，错位的后果是
    「拿甲域的域管密码去连乙域」。身份跟着记录走，不跟着位置走。
    """

    id: str = ""                # 身份（权威键）。空串 = store 还没分配
    name: str = ""              # 配置名，使用者自己起
    #: 域控地址。填 IP 或 DNS 名都行，但**建议填"文件服务器实际用的那台域控"**：
    #: 在那台已加域的机器上跑 `nltest /dsgetdc:<域名>`（⚠️ **不带 `/PDC`** ——
    #: 角色叫 PDC 的那台**不是**我们要找的目标），把 `DC:` 那行对应的 **IP** 填这里。
    #: 未加域的机器**优先填 IP**：内网域名（如 `dc01.corp.example.com`）在这种
    #: 机器上**一律解析不了**（`gaierror 11001`），填域名只会连不上。
    #:
    #: 为什么要盯"文件服务器实际读的那台"，而不是"PDC"：真正决定"新用户什么时候
    #: 能被搜到"的是**读点用的那台域控** —— DCLocator 会刻意把一台客户机的**所有**
    #: 调用方**粘在同一台 DC** 上（MS Learn 原话：*"…to encourage all callers to
    #: use that same DC."*）。写入点与读点不是同一台，就要等复制过来，而
    #: **跨站点复制的默认间隔是 180 分钟**（同站点只有约 15 秒）。
    dc_ip: str = ""
    bind_user: str = ""         # 域\用户 / 用户@域 / 纯用户名
    base_dn: str = ""           # 留空 → 自动反查
    domain: str = ""            # 留空 → 自动反查
    port: int = 389
    use_ssl: bool = False

    #: 一次**使用者可见的变更**（建号 / 删号 / 重置密码 ……）成功之后，
    #: 是否由**本工具**主动执行一次 ``repadmin /syncall <域控FQDN> /AdeP``。
    #:
    #: * ``False``（**默认**）= 本工具**不代跑** —— 本机没加域、或没装 RSAT 时
    #:   这条命令**注定失败**，只会每次操作后刷一条没用的告警 —— 改为在提示里
    #:   直接给出**可复制命令**，由使用者拿到已加域的机器上执行。
    #:   要主动推一次请走菜单「工具 → 强制复制同步」（`BrowserPage.sync_replication_now`）。
    #: * ``True`` = 保持旧行为：本工具每次变更后都尝试代跑。
    #:
    #: 🔴 **这是一次显式的行为变更，不是"顺手改个默认值"（2026-09-17）**：
    #:    改之前默认是 ``True``，而当时那条"出厂默认"判据写着「默认必须是 True：
    #:    把它改成 False 等于把既有行为**悄悄**关掉」—— 那条理由防的是
    #:    「**藏在"新加一个字段"里**的行为变更」。这次相反：是主理人看过三个方案
    #:    （删掉 / 只改文案 / 保能力+降噪+加按钮）之后的**当面裁决**，选的是第三条
    #:    ⇒ 那条判据**连着理由一起改写**（不是删掉）。
    #:    现场依据（2026-09-17 实测；⚠️ 真实环境标识只许留在 `tools/` 与 `tests/`
    #:    的实测出处里，本模块是**可复用**的、不许写实值）：跑工具的那台机器
    #:    **未加域**、用的是公网 DNS ⇒ 本机解析不了那台域控的 DNS 名 ⇒ 自动代跑
    #:    在**每一次**建/删之后都必然失败、并弹一条"本机解析不了域控名"的长提示；
    #:    而使用者的**写入点与读取点本来就是同一台域控**（连接备注里他自己写的
    #:    那句"文件服务器读的那台"）⇒ 无跳可推，这个自动同步对他**一次都没成功
    #:    过**、也**根本不需要**。
    #:
    #: ⚠️ **两条路都会给出可复制命令**（`replication.SyncOutcome.notice()`）——
    #:    这个开关只决定"工具要不要**也**试一次"，不决定"给不给命令"。
    #: ⚠️ 本机实测：``repadmin /syncall`` **只吃域名不吃 IP**（喂 IP ⇒ ``rc=87``），
    #:    而未加域的机器又解析不了域名 ⇒ **本机代跑必失败**，不是配置问题。
    sync_after_change: bool = False

    password: str = field(default="", repr=False)   # repr 里不出现，防止误打印到日志

    # ---------- 序列化 ----------
    def to_dict(self, *, include_password: bool = False) -> dict[str, Any]:
        data = asdict(self)
        if not include_password:
            data.pop("password", None)
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ConnConfig":
        allowed = {f for f in cls.__dataclass_fields__}   # noqa: SLF001
        return cls(**{k: v for k, v in (data or {}).items() if k in allowed})

    def display_name(self) -> str:
        """给 UI 的显示名；没起名就用 IP 兜底。"""
        return self.name.strip() or self.dc_ip.strip() or "（未命名连接）"


# ============================================================================
# 域探测结果
# ============================================================================

@dataclass
class DomainInfo:
    """匿名 RootDSE 反查结果 —— 「只输 IP 就能用」的技术基础。"""

    dc_ip: str = ""
    dns_domain: str | None = None       # corp.example.com
    base_dn: str | None = None          # DC=corp,DC=example,DC=com
    dns_host_name: str | None = None    # dc01.corp.example.com
    config_dn: str | None = None
    schema_dn: str | None = None
    root_domain_dn: str | None = None
    supported_sasl: list[str] = field(default_factory=list)
    functional_level: str | None = None
    use_ssl: bool = False               # 该结果是否来自 636 探测

    @property
    def ok(self) -> bool:
        """是否至少拿到了 BaseDN —— 拿到就能干活。"""
        return bool(self.base_dn)

    def summary(self) -> str:
        """给连接对话框显示的一行摘要。"""
        if not self.ok:
            return "未能从该地址反查到域信息，请手动填写域名与 BaseDN"
        return f"已识别域：{self.dns_domain or '（未知域名）'}　BaseDN：{self.base_dn}"


# ============================================================================
# 目录对象
# ============================================================================

@dataclass
class OuNode:
    """OU 树节点。"""

    name: str = ""
    dn: str = ""
    has_children: bool = False
    description: str = ""


# ============================================================================
# 「读不到」怎么表达 —— 显示层与写入口共用同一条口径
# ============================================================================
#
# 🔴 为什么 `enabled` 必须是**三态**（`bool | None`）而不是 `bool`：
#
# `userAccountControl` 读不到时（属性缺失 / 值畸形 / 无读权限），
# `enabled` 无论取 `True` 还是 `False` 都是在**编一个答案**。而这两个假答案
# 会导致**方向相反**的动作：显示成"已禁用"的人可能会去点"启用"，
# 显示成"已启用"的可能会去点"禁用" —— 而真实状态没人知道。
#
# 写入侧早就守住了这一条（`ad_client._uac_of_now`：读不到就**中止**，
# 因为它承诺"只翻转目标位、其余位原样保留"，按 0 继续会把 `NORMAL_ACCOUNT`
# 一起冲掉）。**显示侧以前没有** —— 它用 `or 0` 兜底，于是同一个"读不到"
# 在写入侧是"中止"，在显示侧却是"一个看起来很确定的值"。
# 同一个事实、两个安全等级，这是本项目明确不许的。
#
# ⇒ 现在的口径：**读不到就显示「未知」**，并且写入口一律 fail-closed
#    （读不到 ⇒ 不许发起这次写入），与写入侧的中止保持一致。

#: 「读不到」在界面上显示成什么。刻意不用 `—`（那在别处表示"不适用"）。
UNKNOWN_STATE = "未知"


def account_state_label(enabled: bool | None) -> str:
    """账号状态的中文标签。``None`` = 读不到（不是"禁用"，也不是"启用"）。"""
    if enabled is None:
        return UNKNOWN_STATE
    return "已启用" if enabled else "已禁用"


def account_rank(enabled: bool | None) -> int:
    """账号状态列的排序权重：已禁用 0 / 已启用 1 / **未知 2（永远排最后）**。

    未知排最后是刻意的：它既不是"启用"也不是"禁用"，不许插进任何一边
    去冒充一个确定的次序。（旧写法 `(row.enabled, ...)` 直接把 `None`
    当排序键，Python 3 里 `None < True` 会抛 `TypeError` —— 整列排序
    当场炸掉。这正好说明"三态"不是一个显示层的小修饰，它会传染到
    所有按状态排序/比较的地方。）
    """
    return 2 if enabled is None else int(bool(enabled))


def account_rank_enabled_first(enabled: bool | None) -> int:
    """同上，但"已启用"在前（混合列表的状态列历史上是这个方向）。

    ⚠️ 与 `account_rank` **只差已知值的方向**，"未知 ⇒ 排最后"是同一条：
    两张表可以有不同的已知值次序（那是各自的历史），但**"未知"不许插进
    任何一边**这条没有第二种解释。
    """
    return 2 if enabled is None else (0 if enabled else 1)


#: `groupType` 的两个维度 → 中文标签。**只有一份**，胶囊与状态列共用。
#: ⚠️ 空串表示"读不到 groupType"，**不在**这张表里 —— 调用方必须自己
#: 三态处理，不许默认成"安全组"（旧行为：`or 0` 之后 gtype=0 不是安全组，
#: 于是"安全组"这个词被按在了一个通讯组头上）。
GROUP_SCOPE_LABELS = {
    "global": "全局组",
    "domainlocal": "域本地组",
    "universal": "通用组",
}
GROUP_CATEGORY_LABELS = {
    "security": "安全组",
    "distribution": "通讯组",
}


@dataclass
class UserRow:
    """用户列表的一行。UI 只认这个结构，不碰原始 LDAP 属性。"""

    sam: str = ""
    display_name: str = ""
    #: ``None`` = 读不到 `userAccountControl`（**不是**默认启用）。见文首那一段。
    enabled: bool | None = None
    locked: bool = False
    pwd_expire_at: datetime | None = None    # None = 永不过期 / 未知
    pwd_must_change: bool = False            # 下次登录必须改密码（pwdLastSet=0）
    acct_expire_at: datetime | None = None   # None = 永不过期
    pwd_last_set: datetime | None = None
    last_logon: datetime | None = None
    #: ``None`` = 读不到。**不要**在别处 `or 0` 兜底 —— 见文首那一段。
    uac: int | None = None
    dn: str = ""

    def status_labels(self) -> list[str]:
        """给表格状态列用的中文标签。"""
        labels = [account_state_label(self.enabled)]
        if self.locked:
            labels.append("已锁定")
        return labels


# ============================================================================
# 多对象类型（ADUC 对齐）
# ============================================================================
#
# 为什么用「一个 superset 行类型」而不是四个各自独立的类：
#   ADUC 的一个 OU 里是**混合**列出用户/组/计算机/联系人的，列表模型只有一种
#   `set_rows(list)`。四个类会让表格模型里到处是 isinstance 分支。
#   这里用 `kind` 打标 + 超集字段，列按 `kind` 选 —— 表格模型只认一种类型。
#
# `UserRow` **保持不变**：它是 `list_users()` 的返回值，后端 118 例测试都依赖它。
# 需要进混合列表时用 `DirObject.from_user()` 转一次。

class ObjectKind:
    """目录对象类型。用字符串常量而非 Enum。

    理由：这些值会直接进审计日志与配置文件，字符串更好读也更好排查
    （Enum 序列化要额外处理，出错时看到的是 `<ObjectKind.USER: 'user'>`）。
    """

    USER = "user"
    GROUP = "group"
    COMPUTER = "computer"
    CONTACT = "contact"

    #: 组织单位 / 其它容器对象。
    #: 这两类**不在** ``ALL`` 里（列表默认只查四类业务对象），
    #: 但删除计划必须能标注它们 —— 删一个 OU 时下面可能还挂着子 OU 与
    #: 打印机队列、MSA 之类的东西，只说"对象 3 个"等于没说。
    OU = "ou"
    OTHER = "other"

    #: 四类业务对象（列表页默认查这批）
    ALL = (USER, GROUP, COMPUTER, CONTACT)

    #: 全部已知类型（含容器的）
    KNOWN = ALL + (OU, OTHER)

    #: 中文标签
    LABELS = {
        USER: "用户",
        GROUP: "组",
        COMPUTER: "计算机",
        CONTACT: "联系人",
        OU: "组织单位",
        OTHER: "其它对象",
    }

    @classmethod
    def label(cls, kind: str) -> str:
        return cls.LABELS.get(kind, kind or "对象")

    @classmethod
    def normalize(cls, kind: str) -> str:
        k = (kind or "").strip().lower()
        return k if k in cls.KNOWN else cls.USER


#: 对象类型 → LDAP objectClass 过滤器片段
KIND_FILTERS = {
    ObjectKind.USER: "(objectCategory=person)(objectClass=user)",
    ObjectKind.GROUP: "(objectCategory=group)",
    ObjectKind.COMPUTER: "(objectCategory=computer)",
    ObjectKind.CONTACT: "(objectCategory=person)(objectClass=contact)",
    ObjectKind.OU: "(objectClass=organizationalUnit)",
}


@dataclass
class DirObject:
    """混合列表里的一行：用户 / 组 / 计算机 / 联系人 四类通用。

    字段是**超集**：类型无关的字段（cn/sam/description/dn）所有类型都有，
    类型专属字段（如 `group_scope`、`os`）其他类型保持默认值。

    ⚠️ 与 `UserRow` 同名同义的那批字段（`sam` / `display_name` / `enabled` /
    `locked` / `pwd_*` / `uac` / `dn` / `status_labels()`）**必须与它语义一致** ——
    表格模型、排序键、状态胶囊的代码是共用的。
    """

    kind: str = ObjectKind.USER
    cn: str = ""                       # RDN 里的名字（重命名改的就是它）
    sam: str = ""                      # sAMAccountName（组/用户/计算机都有）
    display_name: str = ""
    description: str = ""
    dn: str = ""
    parent_dn: str = ""                # 所在容器，供「移动到」显示当前位置

    # ---- 账号状态（仅 user / computer 有意义）----
    has_account: bool = False          # False 时状态列显示「—」而不是「已启用」
    #: ``None`` = 读不到 `userAccountControl`。见文首那一段。
    enabled: bool | None = None
    locked: bool = False
    pwd_expire_at: datetime | None = None
    pwd_must_change: bool = False
    pwd_last_set: datetime | None = None
    acct_expire_at: datetime | None = None
    last_logon: datetime | None = None
    #: ``None`` = 读不到。**不要**在别处 `or 0` 兜底（见文首那一段）。
    uac: int | None = None

    # ---- 组专属 ----
    group_scope: str = ""              # global / domainlocal / universal
    group_category: str = ""           # security / distribution
    # ⚠️ 2026-09-17 删掉了字段 `member_count`：**只在演示域被赋值，界面从不显示它**
    #    （列表页刻意不查成员数 —— 太贵）。零调用点 = 死代码。

    # ---- 计算机专属 ----
    dns_host_name: str = ""
    os: str = ""
    os_version: str = ""
    location: str = ""
    #: 域控：禁止禁用/删除。
    #: ⚠️ 默认是 `False`，**不是** `None` —— 用户/组/联系人根本没有"是不是域控"
    #:    这个概念（`has_account` 才是判据）。把它们置成"未知"会让
    #:    `not obj.is_dc` 这类过滤把它们一起排掉 ⇒ **所有用户突然都从批量
    #:    账号操作里消失了**。只有**计算机**在 `userAccountControl` 读不到时
    #:    才置 `None`，意思是"不知道这台机器是不是域控"。
    #:    ⚠️ 于是判据要写成 `is True` / `is False`，**不许**写成真假值判断：
    #:    `not None` 是 `True`，会把"不知道"当成"不是域控"放行。
    is_dc: bool | None = False

    # ---- 联系人专属 ----
    mail: str = ""
    given_name: str = ""
    surname: str = ""

    # ---- 通用元数据 ----
    when_created: datetime | None = None
    when_changed: datetime | None = None

    # ---------- 展示辅助 ----------

    @property
    def title(self) -> str:
        """列表「名称」列显示什么。"""
        if self.kind == ObjectKind.GROUP:
            return self.cn or self.sam
        return self.display_name or self.cn or self.sam

    @property
    def subtitle(self) -> str:
        """名称列的次要行（ADUC 的「描述」列位置）。"""
        return self.description

    def status_labels(self) -> list[str]:
        """给表格状态列用的中文标签。

        ⚠️ 组和联系人是**没有账号状态**的 —— 返回空列表让状态列显示「—」，
        而不是硬凑一个「已启用」。ADUC 里组也没有启用/禁用。
        """
        if not self.has_account:
            if self.kind == ObjectKind.GROUP:
                labels = []
                category = GROUP_CATEGORY_LABELS.get(self.group_category)
                if category == "通讯组":
                    # ⚠️ **只有通讯组进状态列** —— 安全组是常态，标出来是噪音。
                    #    这是既有裁定（见 `tests/test_models.py::
                    #    test_groups_have_no_account_status`：通讯组"不能被授权，
                    #    与安全组不是一回事"）。
                    labels.append(category)
                elif not self.group_category:
                    # 读不到 `groupType`。这时**不选边**：既不说安全组也不说
                    # 通讯组，明说不知道。（旧行为是 `or 0` ⇒ 0 落进
                    # `if == "distribution"` 的 else ⇒ 什么都不显示，
                    # 而胶囊那边默认显示"安全组" —— 同一份数据两个答案。）
                    labels.append("组类型未知")
                return labels
            return []
        labels = [account_state_label(self.enabled)]
        if self.locked:
            labels.append("已锁定")
        if self.is_dc is True:
            labels = ["域控"] + labels
        return labels

    def scope_label(self) -> str:
        return GROUP_SCOPE_LABELS.get(self.group_scope, self.group_scope)

    def category_label(self) -> str:
        return GROUP_CATEGORY_LABELS.get(self.group_category, self.group_category)

    def kind_label(self) -> str:
        return ObjectKind.label(self.kind)

    # ---------- 转换 ----------

    @classmethod
    def from_user(cls, row: UserRow) -> "DirObject":
        """`UserRow`（`list_users` 的返回）→ 混合列表行。"""
        return cls(
            kind=ObjectKind.USER,
            cn=row.display_name or row.sam,
            sam=row.sam,
            display_name=row.display_name,
            dn=row.dn,
            parent_dn=_parent_dn(row.dn),
            has_account=True,
            enabled=row.enabled,
            locked=row.locked,
            pwd_expire_at=row.pwd_expire_at,
            pwd_must_change=row.pwd_must_change,
            pwd_last_set=row.pwd_last_set,
            acct_expire_at=row.acct_expire_at,
            last_logon=row.last_logon,
            uac=row.uac,
        )

    def to_user_row(self) -> UserRow:
        """混合列表行 → `UserRow`（批量用户操作要用的形态）。"""
        return UserRow(
            sam=self.sam,
            display_name=self.display_name or self.cn,
            enabled=self.enabled,
            locked=self.locked,
            pwd_expire_at=self.pwd_expire_at,
            pwd_must_change=self.pwd_must_change,
            acct_expire_at=self.acct_expire_at,
            pwd_last_set=self.pwd_last_set,
            last_logon=self.last_logon,
            uac=self.uac,
            dn=self.dn,
        )


def _parent_dn(dn: str) -> str:
    """``CN=x,OU=a,DC=b`` → ``OU=a,DC=b``（按第一个未转义的逗号切）。

    实现委托给 ``utils.parent_of_dn`` —— 同一份 DN 拆分逻辑在
    ``ad_client``（移动/重命名/删除计划）也要用，两份实现迟早会分叉。
    """
    from utils import parent_of_dn
    return parent_of_dn(dn)


# ============================================================================
# 属性写入
# ============================================================================

@dataclass
class AttributeChange:
    """一个属性的写入意图。

    ``values`` 为空列表 = **删除该属性**（不是"设成空字符串"）。

    ⚠️ 这个区分很关键：把 `mail` 写成空字符串，ADUC 里会看到一个空但存在的
    `mail`，很多工具还会把空串当成"有值"；真正的"清空"必须 `MODIFY_DELETE`。
    """

    attribute: str = ""
    values: list[str] = field(default_factory=list)

    @property
    def is_delete(self) -> bool:
        return not self.values

    def __str__(self) -> str:
        if self.is_delete:
            return f"{self.attribute} = (删除)"
        joined = "、".join(self.values)
        if len(joined) > 60:
            joined = joined[:57] + "…"
        return f"{self.attribute} = {joined}"


#: 属性编辑器**硬禁**名单：属性名（小写）→ 中文原因。
#:
#: 依据来自 Obsidian《10-ADUC功能对齐规格》§6.7。分两类：
#:   * 结构性属性 —— 改了对象会坏（objectClass / distinguishedName / name）
#:   * 域控计算或系统维护 —— 写了也不生效，还会让人误以为改成功了
#:   * 安全敏感 —— 密码必须走加密通道，安全描述符要专门的 ACL 编辑器
#:
#: ⚠️ 这份名单**同时**给后端（拒绝写入）和界面（灰显 + 悬浮原因）用，
#: 必须只有一份 —— 两边各写一遍，早晚会出现"界面能点、后端报错"的错配。
ATTRIBUTE_BLACKLIST: dict[str, str] = {
    # ---- 结构性：改了对象就坏 ----
    "objectclass": "对象类型，改动会破坏对象结构",
    "objectcategory": "对象分类，只在创建时确定",
    "name": "RDN 名称 —— 请用「重命名」",
    "cn": "RDN 名称 —— 请用「重命名」",
    "distinguishedname": "对象路径 —— 请用「重命名」或「移动到」",
    "canonicalname": "由对象路径推导，只读",
    # ---- 域控维护 / 实时计算：写了不生效 ----
    "objectguid": "AD 内部唯一标识，只读",
    "objectsid": "安全标识符 SID，只读且不可重新生成",
    "whencreated": "创建时间由域控写入，只读",
    "whenchanged": "修改时间由域控写入，只读",
    "usncreated": "更新序列号，只读",
    "usnchanged": "更新序列号，只读",
    "instancetype": "实例类型，只读",
    "systemflags": "系统标记，只读",
    "replpropertymetadata": "复制元数据，只读",
    "dscorepropagationdata": "复制元数据，只读",
    "subschemasubentry": "架构信息，只读",
    "msds-user-account-control-computed": "域控实时计算值（锁定状态等），只读",
    "samaccounttype": "账号类型由域控按 objectClass + UAC 计算，只读",
    "tokengroups": "域控实时计算值，只读",
    "badpwdcount": "由域控维护，只读",
    "badpasswordtime": "由域控维护，只读",
    "logoncount": "由域控维护，只读",
    "lastlogon": "由域控维护，只读",
    "lastlogontimestamp": "由域控维护，只读",
    # ---- 关系型：由 AD 自动维护反向链接 ----
    "memberof": "组成员关系由 AD 自动维护 —— 请在组的「成员」页增删",
    "directreports": "下属关系由 AD 自动维护 —— 请改 manager",
    "primarygroupid": "主要组不能用 member 增删 —— 请用「设置为主要组」",
    # ---- 安全敏感 ----
    "unicodepwd": "密码必须走加密通道（需 128 位 SSL），不能用属性写入",
    "userpassword": "密码必须走加密通道，不能用属性写入",
    "ntsecuritydescriptor": "安全描述符需要专门的 ACL 编辑器",
}

#: 有**专用界面**的属性（小写）→ 提示语。允许改，但界面上会挂一个 ⚠️ 提示。
#:
#: 为什么不直接禁掉：ADUC 的「属性编辑器」是能改这些的，禁了就对不齐了；
#: 但它们都有更安全的专用入口，直接从原始值下手很容易把状态搞成自相矛盾
#: （例如 logonHours 按 UTC 位图写错 8 小时）。
ATTRIBUTE_MANAGED: dict[str, str] = {
    "useraccountcontrol": "UAC 是「位组合」——请用「账户」页的勾选项，直接写整值会冲掉其它位",
    "pwdlastset": "写 0 = 下次登录必须改密；正常改密请用「重置密码」",
    "accountexpires": "请用「账户」页的「账户过期」",
    "logonhours": "登录时间按 「UTC」 位图存 21 字节，请用「登录时间」网格",
    "userworkstations": "请用「账户」页的「登录到」工作站限制",
    "member": "请在组的「成员」页增删 —— 这里写会绕过主要组检查",
    "grouptype": "组作用域/类别请用组属性页 —— 改错会出现无法解析的组",
    "samaccountname": "改登录名请用「常规」页或「账户」页的「登录名」输入框（两处同一个属性）；在这里手改不会同步 UPN",
    "userprincipalname": "UPN 请用「账户」页的「登录名(UPN)」—— 它和「登录名」(sAMAccountName) 是两个属性，改登录名不会动它",
}


def is_attribute_writable(attribute: str) -> tuple[bool, str]:
    """属性能否在属性编辑器里写。返回 ``(是否允许, 中文原因)``。

    允许写时原因是空串；有专用界面时原因是提示语（允许但会提示）。
    """
    key = (attribute or "").strip().lower()
    if not key:
        return False, "属性名为空"
    if key in ATTRIBUTE_BLACKLIST:
        return False, ATTRIBUTE_BLACKLIST[key]
    return True, ATTRIBUTE_MANAGED.get(key, "")


def lookup_attr(mapping: dict[str, list[str]], name: str) -> list[str]:
    """大小写不敏感地取属性值。

    AD 按 schema 里定义的写法返回属性名（`sAMAccountName` / `dNSHostName`），
    但不同版本、不同语言包偶尔有出入，比对时不能依赖大小写。
    """
    if name in mapping:
        return mapping[name]
    low = name.casefold()
    for key, value in mapping.items():
        if key.casefold() == low:
            return value
    return []


def verify_changes(changes: Any, actual: dict[str, list[str]],
                   ) -> tuple[list[str], list[str]]:
    """回读校验：返回 ``(确认生效的属性, 写了但没变化的属性)``。

    为什么必须回读：`modify()` 返回 True 只代表域控**接受了请求**，
    不代表值真的变成了你要的样子 —— ACL 静默忽略、值类型不对被丢弃，
    这两种都会规规矩矩返回成功。本项目的铁律是「假成功必须被抓出来」。

    只校验**存在性与子集**，不做逐字节相等：
      * 要求删除 → 属性必须真的不在了
      * 要求写入 → 写进去的值必须都能在回读结果里找到

    为什么不做逐字节相等：AD 会规范化部分属性的写法（大小写、多值顺序、
    DN 的显示形式），逐字节比会造出一堆假的"未生效"，最后没人再信这个提示。
    """
    written: list[str] = []
    unchanged: list[str] = []
    for change in (changes or []):
        attr = (change.attribute or "").strip()
        values = lookup_attr(actual, attr)
        if change.is_delete:
            ok = not values
        else:
            current = {v.casefold() for v in values}
            ok = bool(current) and all(
                v.casefold() in current for v in change.values)
        if ok:
            written.append(attr)
        else:
            unchanged.append(attr)
    return written, unchanged


#: 受保护的容器：RDN（小写）→ 拒绝删除的原因。
#:
#: 本地先拦，不让域控去报 ACL / `NOT_ALLOWED_ON_NON_LEAF` 那种含糊错误；
#: 更重要的是**别让使用者在确认框里点到「删除」** —— 那一下点下去，
#: 后悔都来不及。
#:
#: 放在 models 里而不是 ad_client 里：`ad_client` 与 `mock_client` 都要用，
#: 各写一份迟早会分叉 —— 而"演示域里什么不能删"必须与真实域完全一致，
#: 否则演示时看着能删、上真域一删就炸。
PROTECTED_CONTAINERS: dict[str, str] = {
    "ou=domain controllers": "「Domain Controllers」是域控所在容器，不能删除。",
    "cn=builtin": "内置容器「Builtin」由系统维护，不能删除。",
    "cn=users": "默认容器「Users」被 AD 保护，不能删除。",
    "cn=computers": "默认容器「Computers」被 AD 保护，不能删除。",
    "cn=system": "系统容器「System」不能删除。",
    "cn=foreignsecurityprincipals": "外部安全主体容器由系统维护，不能删除。",
    "cn=managed service accounts": "托管服务账号容器由系统维护，不能删除。",
    "cn=program data": "系统数据容器不能删除。",
    "cn=microsoft exchange security groups": "Exchange 安全组容器由 Exchange 维护，不能删除。",
}


@dataclass
class ModifyResult:
    """一次属性写入的结果，**含回读校验**。

    为什么要回读：`conn.modify()` 返回 True 只代表域控接受了这个请求，
    不代表值真的变成了你要的样子（ACL 静默忽略、类型不对被丢弃都会
    返回成功）。本工具的铁律是「假成功必须被抓出来」，所以写完立刻
    再读一次比对。

    校验只看**存在性与子集**，不做逐字节相等：
    AD 会规范化一部分属性的写法（大小写、多值顺序），逐字节比会造出
    一堆假的"未生效"告警，反而让人不再相信这个提示。
    """

    written: list[str] = field(default_factory=list)     # 确认已生效的属性
    unchanged: list[str] = field(default_factory=list)   # 写了但读回来没变
    warnings: list[str] = field(default_factory=list)    # 有专用界面的提示

    @property
    def ok(self) -> bool:
        return not self.unchanged

    def summary(self) -> str:
        if self.unchanged:
            return (f"已写入 {len(self.written)} 项，"
                    f"但 {len(self.unchanged)} 项读回后未见变化（可能被域控忽略）")
        return f"已写入 {len(self.written)} 项，均已回读确认"


@dataclass
class DeletePlan:
    """删除前算出来的"要删什么"。

    先算出计划再让使用者确认 —— 删 OU 时这一步能明确告诉他
    「这个 OU 下面还有 N 个对象，全都会被删掉」，而不是等他点了确认
    才丢一个 LDAP 错误码。
    """

    root_dn: str = ""
    root_label: str = ""
    descendants: list[DirObject] = field(default_factory=list)
    blocked_reason: str = ""          # 非空 = 不允许删（如域控、受保护容器）

    @property
    def total(self) -> int:
        return len(self.descendants) + 1

    @property
    def allowed(self) -> bool:
        return not self.blocked_reason

    def summary(self) -> str:
        if self.blocked_reason:
            return self.blocked_reason
        if not self.descendants:
            return f"将删除「{self.root_label}」"
        by_kind: dict[str, int] = {}
        for obj in self.descendants:
            by_kind[obj.kind] = by_kind.get(obj.kind, 0) + 1
        detail = "、".join(f"{ObjectKind.label(k)} {v} 个"
                           for k, v in sorted(by_kind.items()))
        return (f"将删除「{self.root_label}」及其下全部 {len(self.descendants)} 个对象"
                f"（{detail}）")

    def diff_against(self, confirmed_dns: list[str] | None) -> str:
        """与确认时刻的后代 DN 快照对比。一致返回空串，否则中文变化描述。

        ⚠️ 数量复核（expected_total）抓得住「多了 / 少了」，抓不住
        **同数量的替换** —— 确认之后有人把一个用户移走、又移进另一个，
        数量纹丝不动，但实际删掉的是使用者从没见过的那一个。
        DN 集合对比才是精确判据（外部安全审计建议的收紧项）。
        """
        if confirmed_dns is None:
            return ""
        now = {o.dn.casefold() for o in self.descendants}
        snap = {(d or "").strip().casefold()
                for d in confirmed_dns if (d or "").strip()}
        added = sorted(now - snap)
        removed = sorted(snap - now)
        if not added and not removed:
            return ""

        def _label(dn: str) -> str:
            return dn.split(",")[0].split("=", 1)[-1]

        parts = []
        if added:
            parts.append(f"新增了 {len(added)} 个对象"
                         f"（如「{_label(added[0])}」）")
        if removed:
            parts.append(f"减少了 {len(removed)} 个对象")
        return f"{'；'.join(parts)}。"


# ============================================================================
# 新建通用对象（组 / 计算机 / 联系人）
# ============================================================================

@dataclass
class ObjectSpec:
    """新建**非用户**对象（组 / 计算机 / 联系人）的输入。

    用户仍走 `UserSpec`（它有密码三步流程，与这三类差别太大，不合并）。
    """

    kind: str = ObjectKind.GROUP
    name: str = ""                     # cn（OU 里显示的名字）
    sam: str = ""                      # 组/计算机的 sAMAccountName；联系人留空
    description: str = ""
    parent_dn: str = ""

    # 组
    scope: str = "global"              # global / domainlocal / universal
    category: str = "security"         # security / distribution

    # 计算机
    dns_host_name: str = ""
    location: str = ""
    managed_by: str = ""               # DN

    # 联系人
    display_name: str = ""
    given_name: str = ""
    surname: str = ""
    mail: str = ""

    def validate(self) -> None:
        """本地前置校验，尽早给中文提示。"""
        from utils import AdToolError

        name = (self.name or "").strip()
        if not name:
            raise AdToolError("请填写名称。")
        if not self.parent_dn:
            raise AdToolError("请先在左侧选择一个部门。")

        if self.kind == ObjectKind.GROUP:
            if len(name) > 64:
                raise AdToolError(f"组名「{name}」超过 64 个字符。")
            sam = (self.sam or name).strip()
            if len(sam) > 20:
                raise AdToolError(
                    f"组名（2000 前）「{sam}」超过 20 个字符 —— "
                    "老客户端也要用这个字段，AD 限制不能超。")
            for ch in '\\/@[]:;|=,+*?<>"':
                if ch in sam:
                    raise AdToolError(f"组名「{sam}」含有 AD 不允许的字符「{ch}」。")

        elif self.kind == ObjectKind.COMPUTER:
            sam = (self.sam or name).strip().rstrip("$")
            if len(sam) > 15:
                raise AdToolError(
                    f"计算机名「{sam}」超过 15 个字符 —— "
                    "NetBIOS 名上限 15，超了机器会加不上域。")
            if not sam:
                raise AdToolError("请填写计算机名。")

        elif self.kind == ObjectKind.CONTACT:
            if not (name or self.display_name):
                raise AdToolError("请填写联系人姓名。")
        else:
            raise AdToolError(f"不支持的对象类型「{self.kind}」。")

    def labeled(self) -> str:
        return f"{ObjectKind.label(self.kind)}「{self.name}」"


# ============================================================================
# 新建用户
# ============================================================================

@dataclass
class UserSpec:
    """新建用户的输入。字段最小集 + 可选扩展属性。"""

    sam: str = ""                # sAMAccountName（≤20 字符）
    init_password: str = field(default="", repr=False)
    display_name: str = ""
    given_name: str = ""
    surname: str = ""
    must_change: bool = True     # 下次登录必须修改密码
    keep_disabled: bool = False  # 只创建不启用
    extra: dict[str, str] = field(default_factory=dict)   # department / title / mail ...

    def validate(self) -> None:
        """本地前置校验，尽早给中文提示，减少无谓的 LDAP/RPC 往返。"""
        from utils import AdToolError

        sam = (self.sam or "").strip()
        if not sam:
            raise AdToolError("请填写登录名（sAMAccountName）。")
        if len(sam) > 20:
            raise AdToolError(f"登录名「{sam}」超过 20 个字符，AD 不接受。")
        if any(ch in sam for ch in '\\/@[]:;|=,+*?<>"'):
            raise AdToolError(f"登录名「{sam}」含有 AD 不允许的字符。")
        if not self.init_password:
            raise AdToolError("请填写初始密码。")


# ============================================================================
# 批量操作结果
# ============================================================================

@dataclass
class BatchItemResult:
    """批量操作里单个对象的处理结果。

    批量**不因为一个人失败就中止整批** —— 但每一条失败都必须能追到人，
    所以这里带 sam 与中文原因，UI 直接渲染成表格给使用者抄。
    """

    sam: str = ""
    dn: str = ""
    #: 成功后的新 DN（目前只有批量移动回传）：树上「删旧插新」的精确
    #: 局部刷新靠它 —— 没有它界面只能对两端父节点整层重拉。
    new_dn: str = ""
    ok: bool = True
    message: str = ""


@dataclass
class BatchResult:
    """一次批量操作的总账。"""

    op_label: str = ""
    items: list[BatchItemResult] = field(default_factory=list)
    cancelled: bool = False              # 使用者中途点了「停止」
    aborted_reason: str = ""             # 连接断了等致命原因（整批中断）

    @property
    def total(self) -> int:
        return len(self.items)

    @property
    def succeeded(self) -> list[BatchItemResult]:
        return [i for i in self.items if i.ok]

    @property
    def failed(self) -> list[BatchItemResult]:
        return [i for i in self.items if not i.ok]

    def summary(self) -> str:
        """一句话总账，给状态栏/提示框用。"""
        head = f"{self.op_label}完成：成功 {len(self.succeeded)} 项，失败 {len(self.failed)} 项"
        if self.cancelled:
            head += f"，已按你的操作中止（共处理 {self.total} 项）"
        if self.aborted_reason:
            head += f"；整批中断：{self.aborted_reason}"
        return head

    def failure_text(self, limit: int = 20) -> str:
        """失败明细的纯文本（可直接复制给管理员）。"""
        rows = [f"· {i.sam or i.dn}：{i.message}" for i in self.failed[:limit]]
        if len(self.failed) > limit:
            rows.append(f"… 另有 {len(self.failed) - limit} 项未列出")
        return "\n".join(rows)


# ============================================================================
# 应用配置
# ============================================================================

@dataclass
class AppConfig:
    """整个配置文件的结构。出厂模板里所有域相关字段都是空串。"""

    version: int = 1
    connections: list[ConnConfig] = field(default_factory=list)
    last_used: str = ""
    page_size: int = 500
    audit_keep_days: int = 180
    log_level: str = "INFO"
    theme: str = "light"          # light / dark，用户上次选的
    #: 新建用户时「默认密码」按钮填入的那个口令，存 DPAPI 密文（明文不落盘）
    default_password_blob: str = ""
    # ⚠️ 2026-09-16：「权限组清单」与「按 OU 记住上次勾选」两个字段随
    #    「共享盘权限」一起销掉（主理人拍板 Q-1=删）。**旧配置文件里残留的
    #    `permission_groups` / `permission_picks_by_ou` 键会被静默忽略** ——
    #    `from_dict` 是按名取键的，不会因为多出来的键报错；下次存盘时它们
    #    自然消失。不要去写"迁移/清理"代码：配置读得进来就够了。

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "connections": [c.to_dict() for c in self.connections],
            "last_used": self.last_used,
            "ui": {
                "page_size": self.page_size,
                "default_scope": "LEVEL",
                "theme": self.theme,
            },
            "logging": {"audit_keep_days": self.audit_keep_days, "level": self.log_level},
            "creation": {
                "default_password_blob": self.default_password_blob,
            },
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AppConfig":
        data = data or {}
        ui = data.get("ui") or {}
        logging_cfg = data.get("logging") or {}
        creation = data.get("creation") or {}
        return cls(
            version=int(data.get("version") or 1),
            connections=[ConnConfig.from_dict(c) for c in (data.get("connections") or [])],
            last_used=data.get("last_used") or "",
            page_size=int(ui.get("page_size") or 500),
            audit_keep_days=int(logging_cfg.get("audit_keep_days") or 180),
            log_level=logging_cfg.get("level") or "INFO",
            theme=ui.get("theme") or "light",
            default_password_blob=creation.get("default_password_blob") or "",
        )
