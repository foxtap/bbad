# -*- coding: utf-8 -*-
"""
ui_models.py —— 表格数据模型

把 `UserRow` / `OuNode` 这类业务对象翻译成表格能显示的东西。
**翻译逻辑集中在这里**，UI 代码里不再散落 `if dt is None` 这种判断。
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from PyQt6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QSortFilterProxyModel,
    Qt,
)

from models import (DirObject, GROUP_CATEGORY_LABELS, ObjectKind, UNKNOWN_STATE,
                    UserRow, account_rank, account_rank_enabled_first,
                    account_state_label)

__all__ = [
    "ObjectTableModel",
    "ObjectSortProxy",
    "fmt_datetime",
    "fmt_relative",
    "fmt_password_expiry",
]


# ============================================================================
# 时间格式化
# ============================================================================

def _local(value: datetime) -> datetime:
    """把解析器给的 UTC 时间转成**本地时区**再显示。

    为什么在这里转而不是在解析器里转：解析器保持 UTC 单一语义（好测试、
    好换算），显示层负责本地化 —— 两层各管一件事。不带时区的值原样返回。
    """
    if value.tzinfo is None:
        return value
    return value.astimezone()


def fmt_datetime(value: datetime | None, empty: str = "—") -> str:
    """绝对时间：``2026-09-11 08:41``（本地时区）。"""
    if value is None:
        return empty
    return _local(value).strftime("%Y-%m-%d %H:%M")


def fmt_relative(value: datetime | None, empty: str = "—") -> str:
    """相对时间：``3 小时前`` / ``昨天 18:02``。

    为什么"最后登录"用相对时间：管理员关心的是"这人最近还在用吗"，
    而不是一个需要自己减法的绝对时间戳。
    """
    if value is None:
        return empty

    value = _local(value)
    now = datetime.now().astimezone()
    try:
        delta = now - value
    except TypeError:                            # naive vs aware 兜底
        delta = now - value.replace(tzinfo=now.tzinfo)

    seconds = delta.total_seconds()
    if seconds < 0:
        # 时钟偏差或时区差异，不要显示"未来 3 小时前"这种荒唐话
        return value.strftime("%m-%d %H:%M")
    if seconds < 90:
        return "刚刚"
    if seconds < 3600:
        return f"{int(seconds // 60)} 分钟前"
    if seconds < 86400:
        return f"{int(seconds // 3600)} 小时前"
    if seconds < 86400 * 2:
        return "昨天 " + value.strftime("%H:%M")
    if seconds < 86400 * 30:
        return f"{int(seconds // 86400)} 天前"
    return value.strftime("%Y-%m-%d")


def fmt_password_expiry(value: datetime | None,
                        must_change: bool = False) -> str:
    """密码有效期：``待改密码`` / ``23 天后`` / ``已过期 3 天`` / ``永不过期``。

    ⚠️ ``must_change`` 必须**先判** —— ``pwdLastSet=0`` 的账号，
    AD 返回的 ``msDS-UserPasswordExpiryTimeComputed`` 也是 0，经
    `utils.ad_filetime_to_dt` 转换后同样是 ``None``。如果只按 ``None``
    判断，一个「下次登录必须改密码」的账号会被显示成「永不过期」，
    语义正好反了。本工具自己新建的账号默认就是 ``must_change=True``。

    ⚠️ ``None`` 的语义是「永不过期」——`utils.ad_filetime_to_dt` 已经把
    ``accountExpires`` 的 ``0`` / ``0x7FFFFFFFFFFFFFFF`` 哨兵值过滤成 None。
    这里如果写成"未知"，使用者就会以为工具没读出来，反复刷新。
    """
    if must_change:
        return "待改密码"
    if value is None:
        return "永不过期"

    now = datetime.now().astimezone()
    try:
        days = (value - now).total_seconds() / 86400
    except TypeError:
        days = (value.replace(tzinfo=now.tzinfo) - now).total_seconds() / 86400

    if days < 0:
        return f"已过期 {int(-days)} 天"
    if days < 1:
        return "今天到期"
    if days > 3650:
        return "永不过期"
    return f"{int(days)} 天后"


# ============================================================================
# 共用小工具
# ============================================================================

# ⚠️ 2026-09-17 删掉了 `UserTableModel`（124 行）与 `UserSortProxy`（39 行）：
#    两者**零实例化** —— 浏览页在 2026-09-15 换成"混合对象表"之后用的是
#    `ObjectTableModel` / `ObjectSortProxy` ⇒ 这对"用户专用"的模型/代理
#    再没有任何调用点。按铁律「零调用点 = 死代码要删」处理。
#    ⚠️ 别按"ADUC 的用户列表"的印象把它们加回来：那个列表现在由
#    `ObjectTableModel` 承担（列定义在它自己的 `COLUMNS` 里，含"所属位置"一列，
#    用的正是下面这个 `_parent_label`）。


def _parent_label(dn: str) -> str:
    """从 DN 里提取「在哪个 OU」——比显示完整 DN 短得多，又够定位。"""
    if not dn:
        return "—"
    parts = [p for p in dn.split(",") if p.strip() ][1:]     # 去掉自己的 RDN
    ous = [p.split("=", 1)[1] for p in parts if p.upper().startswith("OU=")]
    return " / ".join(reversed(ous)) if ous else "（域根）"



# ============================================================================
# 混合对象表模型（ADUC 对齐 · F01）
# ============================================================================

def _status_pills(obj: DirObject) -> list[tuple[str, str]]:
    """DirObject → 状态胶囊 ``[(文字, 级别), ...]``。

    组 / 联系人**没有账号状态**（ADUC 里组也没有启用/禁用），
    返回空列表让状态列显示「—」，而不是硬凑一个「已启用」。
    """
    if not obj.has_account:
        pills: list[tuple[str, str]] = []
        if obj.kind == ObjectKind.GROUP:
            # 🔴 三态。旧写法 `if == "distribution": 通讯组 else: 安全组`
            #    会把"读不到 groupType"显示成**安全组** —— 一个编出来的答案。
            category = GROUP_CATEGORY_LABELS.get(obj.group_category)
            pills.append((category or "组类型未知",
                          "info" if category == "通讯组" else "muted"))
            scope = obj.scope_label()
            if scope:
                pills.append((scope, "muted"))
        return pills
    if obj.enabled is None:
        pills = [(UNKNOWN_STATE, "muted")]
    else:
        pills = [("已启用", "ok") if obj.enabled else ("已禁用", "warn")]
    if obj.locked:
        pills.append(("已锁定", "danger"))
    if obj.is_dc is True:
        pills.insert(0, ("域控", "info"))
    elif obj.is_dc is None and obj.kind == ObjectKind.COMPUTER:
        # "不知道是不是域控"必须说出来：它决定了这台机器能不能被禁用/删除。
        # 旧行为在这种情况下给的是"域控"的反面（当成普通电脑放行）。
        pills.insert(0, ("域控状态未知", "warn"))
    return pills


class ObjectTableModel(QAbstractTableModel):
    """混合对象列表模型：用户 / 组 / 计算机 / 联系人一行一个。

    ADUC 打开一个 OU，右窗格就是这四类**混在一起**列的（外加「类型」列），
    这个模型就是对齐它 —— 数据全部来自后端的 ``DirObject``（超集行结构）。

    排序键与显示值分离（本模块的铁律：'23 天后' / '永不过期' 这些**显示值是**
    字符串，拿它们排序会把 '2 天后' 排在 '10 天后' 后面），状态列同样
    交给 ``StatusPillDelegate`` 画胶囊。
    """

    #: (标题, 取值函数, 排序键, 是否画胶囊)
    COLUMNS = [
        ("名称", lambda o: o.title or o.sam or o.dn,
         lambda o: (o.title or o.sam or o.dn or "").casefold(), False),
        ("类型", lambda o: o.kind_label(),
         lambda o: o.kind, False),
        ("描述", lambda o: o.description or "—",
         lambda o: (o.description or "").casefold(), False),
        ("登录名", lambda o: o.sam or "—",
         lambda o: (o.sam or "").casefold(), False),
        ("状态", lambda o: "、".join(t for t, _ in _status_pills(o)),
         # ⚠️ 排序键必须把"未知"单独排（`not None` 是 `True`，直接参与比较会把
         #    "未知"混进"已禁用"那一档）；方向沿用本表历史：启用在前、未知最后。
         lambda o: (not o.has_account,
                    account_rank_enabled_first(o.enabled), o.locked), True),
        ("密码", lambda o: fmt_password_expiry(o.pwd_expire_at, o.pwd_must_change)
         if o.has_account else "—",
         # 无账号对象（组/联系人）排最后（1e13 > 永不过期哨兵 9e12）；
         # 待改密码 -1 最前；其余按到期时间戳
         lambda o: (-1.0 if o.pwd_must_change
                    else o.pwd_expire_at.timestamp() if o.pwd_expire_at
                    else 9e12) if o.has_account else 1e13, False),
        ("最后登录", lambda o: fmt_relative(o.last_logon) if o.last_logon else "—",
         lambda o: o.last_logon.timestamp() if o.last_logon else -1, False),
        ("所属位置", lambda o: _parent_label(o.dn),
         lambda o: _parent_label(o.dn), False),
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._rows: list[DirObject] = []

    # ---------- 数据装载 ----------

    def set_rows(self, rows: list[DirObject]) -> None:
        self.beginResetModel()
        self._rows = list(rows)
        self.endResetModel()

    def rows(self) -> list[DirObject]:
        return list(self._rows)

    def row_at(self, index: QModelIndex) -> DirObject | None:
        if not index.isValid() or not (0 <= index.row() < len(self._rows)):
            return None
        return self._rows[index.row()]

    # ⚠️ 2026-09-17 删掉了 `rows_at(indexes)`：**零调用**。
    #    页面从选中索引取对象的路径是 `ObjectSortProxy.selected_rows()`
    #    （先 proxy→source 映射再逐行 `row_at`）—— 那才是唯一那份实现。

    def index_of_dn(self, dn: str) -> QModelIndex:
        """按 DN 找行（右键定位 / 刷新后恢复选中用）。"""
        needle = (dn or "").casefold()
        for row, obj in enumerate(self._rows):
            if obj.dn.casefold() == needle:
                return self.index(row, 0)
        return QModelIndex()

    def by_dn(self, dn: str) -> DirObject | None:
        """按 DN 取**当前行里的那个对象**（大小写不敏感）；没有该行返回 ``None``。

        用途：属性面板保存后重新装载时，要拿模型里**最新的那一行**，而不是
        面板自己很久以前存下的快照 —— `update_rows` 是**替换**行对象，
        `ObjectPropertyPanel._obj` 从头到尾没人更新过，取它就会一直显示
        落库前的旧值（登录名 / 名称 / 启用状态全都过期）。

        ⚠️ 必须允许返回 ``None``：首屏也可能是从**OU 树**点开的属性，那时列表里
        根本没有这一行；调用方要有兜底，不许在这里抛。
        """
        needle = (dn or "").casefold()
        if not needle:
            return None
        for obj in self._rows:
            if (obj.dn or "").casefold() == needle:
                return obj
        return None

    def update_rows(self, objs: list[DirObject]) -> None:
        """按 DN **就地替换**行对象，只对受影响的行 emit dataChanged。

        写操作（启停/解锁/改密/属性保存）落库后的局部刷新入口。
        严禁改用 `set_rows`：begin/endResetModel 会清掉选中与排序状态，
        还整表重画 —— 改一个号闪一遍全表，就是它的味道。
        """
        by_dn = {(o.dn or "").casefold(): o for o in objs if o.dn}
        if not by_dn:
            return
        touched: list[int] = []
        for row, obj in enumerate(self._rows):
            fresh = by_dn.get(obj.dn.casefold())
            if fresh is not None:
                self._rows[row] = fresh
                touched.append(row)
        for row in touched:
            self.dataChanged.emit(self.index(row, 0),
                                  self.index(row, len(self.COLUMNS) - 1))

    def remove_rows(self, dns: list[str]) -> None:
        """按 DN **就地删行**（删除操作后的局部刷新，不 resetModel）。"""
        dead = {(dn or "").casefold() for dn in dns if dn}
        if not dead:
            return
        for row in sorted(
                (i for i, o in enumerate(self._rows)
                 if o.dn.casefold() in dead), reverse=True):
            self.beginRemoveRows(QModelIndex(), row, row)
            del self._rows[row]
            self.endRemoveRows()

    # ---------- QAbstractTableModel 接口 ----------

    def rowCount(self, parent=QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self.COLUMNS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):  # noqa: N802
        if orientation != Qt.Orientation.Horizontal:
            return None
        if role == Qt.ItemDataRole.DisplayRole and 0 <= section < len(self.COLUMNS):
            return self.COLUMNS[section][0]
        if role == Qt.ItemDataRole.TextAlignmentRole:
            return int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        return None

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        row = self.row_at(index)
        if row is None:
            return None
        _title, getter, _key, is_pills = self.COLUMNS[index.column()]

        if role == Qt.ItemDataRole.DisplayRole:
            value = getter(row)
            return "" if is_pills else str(value)

        if role == Qt.ItemDataRole.UserRole and is_pills:
            return _status_pills(row)

        if role == Qt.ItemDataRole.ToolTipRole:
            return self._tooltip(row)

        if role == Qt.ItemDataRole.TextAlignmentRole:
            return int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)

        return None

    def sort_key(self, obj: DirObject, column: int):
        if 0 <= column < len(self.COLUMNS):
            return self.COLUMNS[column][2](obj)
        return ""

    @staticmethod
    def _tooltip(obj: DirObject) -> str:
        lines = [
            f"类型：{obj.kind_label()}",
            f"名称：{obj.title or '—'}",
            f"登录名：{obj.sam or '—'}",
        ]
        if obj.description:
            lines.append(f"描述：{obj.description}")
        if obj.kind == ObjectKind.GROUP:
            lines.append(f"作用域：{obj.scope_label() or '—'}"
                         f"　类型：{obj.category_label() or '—'}")
        if obj.kind == ObjectKind.COMPUTER:
            if obj.dns_host_name:
                lines.append(f"DNS 名：{obj.dns_host_name}")
            if obj.os:
                lines.append(f"系统：{obj.os} {obj.os_version}")
        if obj.has_account:
            lines.append(
                f"状态：{'、'.join(t for t, _ in _status_pills(obj))}")
            lines.append(f"密码：{fmt_password_expiry(obj.pwd_expire_at, obj.pwd_must_change)}")
        if obj.mail:
            lines.append(f"邮箱：{obj.mail}")
        lines.append(f"DN：{obj.dn}")
        return "\n".join(lines)


class ObjectSortProxy(QSortFilterProxyModel):
    """混合对象表的排序代理 —— 排序键与显示值分离：列定义第 3 个元素才是
    排序用的值，**不许拿第 2 个（给人看的那个）去排**。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setDynamicSortFilter(True)
        self.setSortCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)

    def lessThan(self, left: QModelIndex, right: QModelIndex) -> bool:  # noqa: N802
        model = self.sourceModel()
        if not isinstance(model, ObjectTableModel):
            return super().lessThan(left, right)
        left_row = model.row_at(left)
        right_row = model.row_at(right)
        if left_row is None or right_row is None:
            return False
        try:
            return model.sort_key(left_row, left.column()) < \
                   model.sort_key(right_row, right.column())
        except TypeError:
            # 混合类型兜底（None 与 str 混排），绝不因为排序把界面搞崩
            return str(model.sort_key(left_row, left.column())) < \
                   str(model.sort_key(right_row, right.column()))

    def selected_rows(self, indexes) -> list[DirObject]:
        source = self.sourceModel()
        if not isinstance(source, ObjectTableModel):
            return []
        rows = sorted({self.mapToSource(i).row() for i in indexes if i.isValid()})
        return [source.row_at(source.index(r, 0)) for r in rows
                if source.row_at(source.index(r, 0)) is not None]
