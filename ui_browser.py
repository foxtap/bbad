# -*- coding: utf-8 -*-
"""
ui_browser.py —— 主浏览页（T05 / T08 / T09 / T10 / T10b~e + ADUC 对齐批次 1~3）

布局（严格按定版线框）::

    ┌──────────────────────────────────────────────────────────┐
    │ 顶部：域摘要 + 断开 + 日志 + 主题                          │  ← 常驻
    ├──────────┬───────────────────────────────────────────────┤
    │ 目录树    │ 搜索框  类型筛选 [新建用户][新建组][计算机][联系人]│
    │ 1/5      │ ─────────────────────────────────────────────  │
    │          │ 内联确认条（按需浮现）                          │
    │          │ 批量操作条（选中后浮现）                        │
    │          │ 对象表                        │ 内联面板        │
    │          │ 共 N 个对象                   │ （按需浮现）     │
    └──────────┴───────────────────────────────────────────────┘

三条交互铁律：
  1. **选中才浮现**：没选中任何行时，批量操作条完全不占地方。
  2. **内联不弹窗**：新建 / 确认 / 属性 / 结果全部在页面内完成，
     操作时左侧目录树始终可见 —— 填错目标能立刻发现。
  3. **单条与批量同一套代码**：选 1 个和选 50 个走同一条路径，
     不会出现"批量能改单人不能改"这种分裂行为。

ADUC 对齐（批次 1~3）：
  * F01 混合对象列表（用户/组/计算机/联系人）+ 类型筛选
  * F02 右键上下文菜单（表格 + 目录树）
  * F03 删除（先算删除范围 → 内联确认 → 范围复核）
  * F04 移动到（目标 = 左树当前选中）/ 重命名（计算机同步登录名）
  * F05 属性页（常规/地址/账户/配置文件/电话/组织/隶属于，可写回）
  * F06 组成员管理（成员页 + 右键「添加到组」）
  * F07 计算机账号（列出/预创建/启停/重置账户）
  * F08 联系人（列出/创建/删除）
  * F09 查找增强（全类型 + 全目录）
  * F10 树里显示内置容器（Users / Computers / Builtin）
"""

from __future__ import annotations

from PyQt6.QtCore import QItemSelectionModel, Qt, pyqtSignal
from PyQt6.QtGui import QShortcut
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMenu,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from audit import AuditLog  # noqa: F401  (类型标注用)
from models import BatchResult, DirObject, ObjectKind, UserRow, lookup_attr
from replication import manual_command
from types import SimpleNamespace
from ui_models import ObjectSortProxy, ObjectTableModel, _status_pills, fmt_datetime  # noqa: F401
from ui_panels import (
    AddToGroupPanel,
    BatchResultPanel,
    CreateGroupPanel,
    CreateOuPanel,
    CreateUserPanel,
    GpoPanel,
    MovePanel,
    NewComputerPanel,
    NewContactPanel,
    NOT_SET,
    ObjectPropertyPanel,
    RenamePanel,
)
from ui_tasks import TaskBridge
from ui_tree import OuTree
from ui_widgets import (
    Colors,
    ConfirmBar,
    DefaultPasswordDialog,
    FilterBuilderBar,
    SearchLineEdit,
    StatusPillDelegate,
    Toast,
    hint_label,
    log_notify,
    make_button,
    section_label,
)
from utils import (AdToolError, UF_DONT_EXPIRE_PASSWORD, bind_account_name,
                   breadcrumb, defuse_csv_cell, generate_password, get_logger,
                   is_descendant_dn, parent_of_dn, sam_write_denied_hint)
from workers import (GpoListResult, batch_delete, batch_move,
                     batch_reset_password, batch_set_enabled, batch_unlock,
                     gpo_engine_available, gpo_linked_soms, gpo_report,
                     gpo_security, gpo_settings,
                     list_gpos,
                     search_gpos, som_linked_gpos, sync_replication)

__all__ = ["BrowserPage"]

_log = get_logger("ui_browser")

#: 子树列表（点域根 / 整个域）的条数硬上限。
#: 一个几万人的域全量拉回来既慢又没必要 —— 到顶了就在计数栏明确告知被截断，
#: 让使用者改用搜索或点进具体部门，而不是默默少给一部分数据。
SUBTREE_USER_LIMIT = 2000

#: 就地回读刷新的 DN 数上限。回读 = 每个对象一次 LDAP BASE 往返，
#: 超过这个数，N 次往返比一次重拉当前视图（分页单查）还贵 ——
#: 降级为重拉（搜索态重搜 / 浏览态重读容器）。小批量仍走就地刷新，
#: 不整表重画、不清选中（见 `_refresh_rows`）。
REFRESH_INPLACE_LIMIT = 50

#: 类型筛选下拉的选项：``(显示文本, kinds 元组或 None=全部)``
KIND_FILTER_CHOICES = [
    ("全部对象", None),
    ("用户", (ObjectKind.USER,)),
    ("组", (ObjectKind.GROUP,)),
    ("计算机", (ObjectKind.COMPUTER,)),
    ("联系人", (ObjectKind.CONTACT,)),
]

#: 高级查找里类型筛选下拉对应的 LDAP 子句 —— 作为前置条件 AND 进
#: 构建器生成的过滤器（与 ad_client.USER_FILTER 的写法保持一致：
#: person 用 objectCategory=person + objectClass=user 双保险）。
KIND_LDAP_CLAUSES = {
    ObjectKind.USER: "(objectCategory=person)(objectClass=user)",
    ObjectKind.GROUP: "(objectClass=group)",
    ObjectKind.COMPUTER: "(objectClass=computer)",
    ObjectKind.CONTACT: "(objectClass=contact)",
}

#: 状态列（胶囊）的列号 —— 与 ``ObjectTableModel.COLUMNS`` 对齐
COL_STATUS = 4
COL_NAME = 0


class BrowserPage(QWidget):
    """连上域控之后的浏览与操作页面。"""

    disconnect_requested = pyqtSignal()
    audit_requested = pyqtSignal()
    theme_requested = pyqtSignal()
    status_message = pyqtSignal(str)

    def __init__(self, client, tasks: TaskBridge, settings=None,
                 parent: QWidget | None = None):
        super().__init__(parent)
        self.client = client              # AdClient 或 MockAdClient（鸭子类型）
        self.tasks = tasks
        self.settings = settings          # ConfigStore（可为 None：只读场景）

        self._current_dn = ""
        self._current_title = ""
        self._subtree = False
        self._search_active = False
        #: 列表（右窗格）的**请求序号** —— 后发的结果才允许写表格。
        #: 连着点两个部门时，先点的那个若后返回就会盖掉后点的
        #: （标题按"当前"拼、数据是"上一次"的），随后对表里的行做批量
        #: 操作，动的其实是另一个部门的人。
        self._list_token = 0
        self._pending_action: tuple[str, dict] | None = None
        self._current_rows: list[DirObject] = []
        self._filter_kinds: tuple | None = None
        self._upn_suffixes_loaded = False
        self._department_options_loaded = False
        self._template_dn = ""            # 建号表单是以谁为模板打开的

        #: 「这条同步结果**已经弹过**了」的指纹集合（元素是
        #: `SyncOutcome.notice_key`，**结构化**，不是文案）。
        #:
        #: 为什么需要它：一台机器上的"推不动"是**结构性**的 ——
        #: 建号、删号、建 OU 每次得到的是**同一句话**（本机解析不了域控名 /
        #: 没装 repadmin），而提示条是**一次性**的：重复弹它，代价是每次
        #: 挤掉别人（建号成功那条 `已创建：<DN>`），收益是零。
        #:
        #: ⚠️ 状态挂在**页面实例**上 ⇒ 换一条连接（`_enter_browser` 重建页面）
        #:    就是新一轮 —— 换域控之后"推不动"的原因可能完全不同，必须重新说。
        self._sync_seen: set[tuple] = set()

        self._build()
        self.toast = Toast(self, bottom_gap=76)

    # ==================================================================
    # 构建
    # ==================================================================

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_top_bar())

        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.splitter.setChildrenCollapsible(False)
        self.splitter.setHandleWidth(4)
        self.splitter.addWidget(self._build_tree_side())
        self.splitter.addWidget(self._build_list_side())
        self.splitter.setStretchFactor(0, 1)          # 左 1/5
        self.splitter.setStretchFactor(1, 4)          # 右 4/5
        self.splitter.setSizes([230, 920])
        root.addWidget(self.splitter, 1)

    # ---------- 顶部 ----------

    def _build_top_bar(self) -> QWidget:
        bar = QFrame()
        bar.setFrameShape(QFrame.Shape.StyledPanel)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(10)

        self.conn_label = QLabel("未连接")
        self.conn_label.setStyleSheet("font-weight: 600;")
        layout.addWidget(self.conn_label)

        self.domain_label = QLabel("")
        self.domain_label.setStyleSheet(f"color: {Colors.MUTED};")
        layout.addWidget(self.domain_label)

        self.mock_badge = QLabel("演示模式")
        self.mock_badge.setStyleSheet(
            f"color: #FFFFFF; background: {Colors.WARN};"
            " border-radius: 4px; padding: 1px 7px;")
        self.mock_badge.setVisible(False)
        layout.addWidget(self.mock_badge)

        layout.addStretch(1)

        for text, slot, tip in (
            ("刷新", self.refresh, "重新读取当前容器（F5）"),
            ("操作日志", self.audit_requested.emit, "查看本机记录的所有操作"),
            ("切换主题", self.theme_requested.emit, "浅色 / 深色"),
            ("断开", self._on_disconnect, "断开当前连接并回到连接页"),
        ):
            button = QPushButton(text)
            button.setToolTip(tip)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.clicked.connect(slot)
            layout.addWidget(button)

        return bar

    # ---------- 左侧树 ----------

    def _build_tree_side(self) -> QWidget:
        side = QWidget()
        layout = QVBoxLayout(side)
        layout.setContentsMargins(6, 6, 3, 6)
        layout.setSpacing(6)

        head = QHBoxLayout()
        head.addWidget(section_label("目录结构"))
        head.addStretch(1)
        add_ou = QPushButton("+ 新建 OU")
        add_ou.setFlat(True)
        add_ou.setCursor(Qt.CursorShape.PointingHandCursor)
        add_ou.setStyleSheet(f"color: {Colors.INFO}; padding: 1px 6px;")
        add_ou.clicked.connect(self._open_create_ou)
        head.addWidget(add_ou)
        layout.addLayout(head)

        self.tree = OuTree()
        self.tree.selection_changed.connect(self._on_tree_selected)
        self.tree.need_children.connect(self._load_ou_children)
        self.tree.context_menu_requested.connect(self._on_tree_context_menu)
        self.tree.tree.itemClicked.connect(self._on_tree_clicked)
        layout.addWidget(self.tree, 1)
        return side

    # ---------- 右侧列表 ----------

    def _build_list_side(self) -> QWidget:
        side = QWidget()
        layout = QVBoxLayout(side)
        layout.setContentsMargins(3, 6, 6, 6)
        layout.setSpacing(6)

        # 工具栏
        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)
        self.search = SearchLineEdit("搜索名称 / 登录名 / 描述（全目录、全类型）")
        self.search.submitted.connect(self._on_search)
        self.search.setMinimumWidth(200)
        toolbar.addWidget(self.search, 1)

        # F12：高级查找开关 —— 打开后浮现条件构建器（选字段 → 选条件 → 填值）
        self.adv_search_btn = QPushButton("高级")
        self.adv_search_btn.setCheckable(True)
        self.adv_search_btn.setFixedWidth(52)
        self.adv_search_btn.setToolTip(
            "高级查找：按条件组合搜索（ADUC「查找」对话框同款）\n"
            "例如：部门 包含「财务」 且 登录名 开头是「a」\n"
            "懂 LDAP 的也可以勾选「直接编辑 LDAP 源码」")
        self.adv_search_btn.toggled.connect(self._on_advanced_toggled)
        toolbar.addWidget(self.adv_search_btn)

        self.kind_filter = QComboBox()
        for text, _kinds in KIND_FILTER_CHOICES:
            self.kind_filter.addItem(text)
        self.kind_filter.setToolTip("按对象类型筛选列表（ADUC 的「查看 → 筛选器」）")
        self.kind_filter.currentIndexChanged.connect(self._on_kind_filter_changed)
        toolbar.addWidget(self.kind_filter)

        create_user = make_button("+ 新建用户", primary=True)
        create_user.clicked.connect(lambda: self._open_create_user())
        toolbar.addWidget(create_user)

        create_group = QPushButton("+ 新建组")
        create_group.clicked.connect(self._open_create_group)
        toolbar.addWidget(create_group)

        create_computer = QPushButton("+ 新建计算机")
        create_computer.setToolTip("预创建计算机账号（先建号、后加域）")
        create_computer.clicked.connect(self._open_create_computer)
        toolbar.addWidget(create_computer)

        create_contact = QPushButton("+ 新建联系人")
        create_contact.clicked.connect(self._open_create_contact)
        toolbar.addWidget(create_contact)

        export = QPushButton("导出 CSV")
        export.setToolTip("把当前列表导出，Excel 可直接打开")
        export.clicked.connect(self._export_csv)
        toolbar.addWidget(export)

        # 「强制复制同步」—— 2026-09-17 二次裁定后**补到页面里**。
        #
        # 背景（别再走回头路）：09-17 的原话是「能不能在软件**页面里**
        # 加一个同步按钮」。当时（方案 C）只落成了菜单「工具 → 强制复制同步」，
        # 把"页面里的按钮"当成**可选**没做。他复看界面时立刻发现
        # 「不是要做到页面里面一个按钮来同步吗？」⇒ **提问的用词就是需求**，
        # 落点被擅自改到菜单并不算交付。
        #
        # 它调用的是**同一个** `sync_replication_now()`（菜单那条也走它）
        # ⇒ 动作只有一份实现，两处入口只差"谁按的"。
        #
        # ⚠️ `clicked` 带一个 `checked=False` 的**位置参数**，而
        #    `sync_replication_now(what=<str>)` **正好收一个位置参数**
        #    ⇒ 直连 `clicked.connect(self.sync_replication_now)` 会把 `what`
        #    染成 `False`，提示当场变成「**False**已成功…」。
        #    用 lambda 把那个参数掐掉（菜单那条路是 0 参的 `_sync_replication`，
        #    所以它没这个问题）。判据见
        #    `tests/test_ui_smoke.py::TestTheSyncEntranceSitsWhereTheUserAsksForIt`。
        self.sync_now_btn = QPushButton("强制复制同步")
        self.sync_now_btn.setToolTip(
            "对当前连接推一次 AD 复制同步（repadmin /syncall … /AdeP）——\n"
            "把刚写完的改动立刻交给这台域控的复制伙伴，不必等复制周期。\n"
            "\n"
            "与菜单「工具 → 强制复制同步」是同一个动作。\n"
            "⚠️ 需要本机能解析域控名、且当前会话里有域凭据；否则它会如实告诉你\n"
            "是哪一件没满足（绝不会假装推成功）。")
        self.sync_now_btn.clicked.connect(lambda: self.sync_replication_now())
        toolbar.addWidget(self.sync_now_btn)

        layout.addLayout(toolbar)

        # F12：高级查找条件构建器（默认隐藏，点「高级」浮现 —— 内联不弹窗）
        self.filter_builder = FilterBuilderBar()
        self.filter_builder.setVisible(False)
        self.filter_builder.search_requested.connect(self._on_builder_search)
        layout.addWidget(self.filter_builder)

        # 内联确认条
        self.confirm = ConfirmBar()
        self.confirm.generate_fn = lambda: generate_password(14)
        self.confirm.confirmed.connect(self._on_confirm)
        self.confirm.cancelled.connect(lambda: self._set_pending(None))
        layout.addWidget(self.confirm)

        # 列表计数
        self.count_label = QLabel("")
        self.count_label.setStyleSheet(f"color: {Colors.MUTED};")
        layout.addWidget(self.count_label)

        # 表格 + 面板
        body = QSplitter(Qt.Orientation.Horizontal)
        body.setChildrenCollapsible(False)
        body.setHandleWidth(6)      # 拖拽手柄太细会让人以为面板不能拉（实测反馈）
        body.addWidget(self._build_table())
        body.addWidget(self._build_panel_stack())
        body.setStretchFactor(0, 1)
        body.setStretchFactor(1, 0)
        body.setSizes([620, 0])
        self.body_splitter = body
        layout.addWidget(body, 1)

        self.footer = hint_label("")
        layout.addWidget(self.footer)
        return side

    def _build_table(self) -> QWidget:
        self.model = ObjectTableModel(self)
        self.proxy = ObjectSortProxy(self)
        self.proxy.setSourceModel(self.model)

        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setWordWrap(False)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(26)
        self.table.setItemDelegateForColumn(COL_STATUS, StatusPillDelegate(self.table))
        self.table.setSortingEnabled(True)
        self.table.doubleClicked.connect(lambda _i: self._open_detail())
        self.table.selectionModel().selectionChanged.connect(self._on_selection_changed)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._on_table_context_menu)

        # 键盘快捷键（ADUC 习惯）：Delete 删除、F2 重命名、
        # Ctrl+F 定位搜索框、F5 刷新
        QShortcut("Delete", self.table, activated=self._on_delete_key)
        QShortcut("F2", self.table, activated=self._on_rename_key)
        QShortcut("Ctrl+F", self, activated=self._on_find_key)
        QShortcut("F5", self, activated=self._on_refresh_key)

        header = self.table.horizontalHeader()
        # 末列吃掉窗口宽度的全部变化（拉大缩小都由它吸收），
        # 其余列全部 Interactive —— 每一列都能自由拖拽。
        # 之前把 Stretch 给了第 1 列：窗口一变宽只有它动，其余列纹丝
        # 不动，右边留白/出横向滚动条，文字还被盖住（实测截图逮过）。
        header.setStretchLastSection(True)
        header.setMinimumSectionSize(64)
        for column in range(len(ObjectTableModel.COLUMNS)):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)
        self.table.setColumnWidth(0, 150)
        self.table.setColumnWidth(1, 90)
        self.table.setColumnWidth(2, 160)
        self.table.setColumnWidth(3, 110)
        self.table.setColumnWidth(COL_STATUS, 150)
        self.table.setColumnWidth(5, 110)
        self.table.setColumnWidth(6, 110)
        self.table.setColumnWidth(7, 150)
        return self.table

    def _build_panel_stack(self) -> QWidget:
        container = QFrame()
        container.setMinimumWidth(0)
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)

        self.panels = QStackedWidget()

        placeholder = QWidget()
        placeholder_layout = QVBoxLayout(placeholder)
        placeholder_layout.addStretch(1)
        empty = hint_label("选中左侧部门查看对象；\n双击某一行或右键 → 属性，可查看并编辑全部属性。")
        empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        placeholder_layout.addWidget(empty)
        placeholder_layout.addStretch(1)
        self.panels.addWidget(placeholder)                   # 0

        self.create_user_panel = CreateUserPanel()
        self.create_user_panel.accepted.connect(self._submit_create_user)
        self.create_user_panel.check_sam.connect(self._check_sam)
        self.create_user_panel.default_password_edit_requested.connect(
            self._edit_default_password)
        self.panels.addWidget(self.create_user_panel)        # 1

        self.create_ou_panel = CreateOuPanel()
        self.create_ou_panel.accepted.connect(self._submit_create_ou)
        self.panels.addWidget(self.create_ou_panel)          # 2

        self.create_group_panel = CreateGroupPanel()
        self.create_group_panel.accepted.connect(self._submit_create_group)
        self.panels.addWidget(self.create_group_panel)       # 3

        self.property_panel = ObjectPropertyPanel()
        #: 属性面板**当前正在显示**的 DN —— 异步回调的归属判据。
        #: 共享单例面板 + 异步读：请求在飞时用户换对象，旧结果必须丢。
        self._property_dn = ""
        self.property_panel.accepted.connect(self._submit_property_save)
        self.property_panel.check_sam.connect(self._check_property_sam)
        self.property_panel.load_members_requested.connect(self._load_group_members)
        self.property_panel.search_objects_requested.connect(self._on_member_search)
        self.property_panel.add_members_requested.connect(self._on_add_members)
        self.property_panel.remove_members_requested.connect(self._on_remove_members)
        self.property_panel.remove_membership_requested.connect(self._on_remove_membership)
        # 「隶属于」页的「添加到组…」—— 2026-09-17 前这个信号**没有接收方**
        # （发信号的是 `ui_panels.py:1105` 那个按钮，全仓零连接）⇒ 那个按钮
        # 点了什么都不发生。判据：tests/test_ui_smoke.py::TestMemberOfTabIsWired.test_the_add_button_really_opens_the_panel
        self.property_panel.add_to_group_requested.connect(
            self._on_add_to_group_from_properties)
        # 面板自己没有状态栏 ⇒ 它的"说一句"统一走浏览页的 notify。
        self.property_panel.notice.connect(self.notify)
        self.panels.addWidget(self.property_panel)           # 4

        self.result_panel = BatchResultPanel()
        self.panels.addWidget(self.result_panel)             # 5

        self.rename_panel = RenamePanel()
        self.rename_panel.accepted.connect(self._submit_rename)
        self.panels.addWidget(self.rename_panel)             # 6

        self.move_panel = MovePanel()
        self.move_panel.accepted.connect(self._submit_move)
        self.panels.addWidget(self.move_panel)               # 7

        self.add_to_group_panel = AddToGroupPanel()
        self.add_to_group_panel.accepted.connect(self._submit_add_to_group)
        self.add_to_group_panel.search_requested.connect(self._on_group_search)
        self.panels.addWidget(self.add_to_group_panel)       # 8

        self.create_computer_panel = NewComputerPanel()
        self.create_computer_panel.accepted.connect(self._submit_create_computer)
        self.panels.addWidget(self.create_computer_panel)    # 9

        self.create_contact_panel = NewContactPanel()
        self.create_contact_panel.accepted.connect(self._submit_create_contact)
        self.panels.addWidget(self.create_contact_panel)     # 10

        self.gpo_panel = GpoPanel()
        self.gpo_panel.refresh_requested.connect(self._submit_gpo_refresh)
        self.gpo_panel.search_requested.connect(self._submit_gpo_search)
        self.gpo_panel.links_requested.connect(self._submit_gpo_links)
        self.gpo_panel.settings_requested.connect(self._submit_gpo_settings)
        self.gpo_panel.security_requested.connect(self._submit_gpo_security)
        self.gpo_panel.report_requested.connect(self._submit_gpo_report)
        self.panels.addWidget(self.gpo_panel)                # 11
        #: 最近一次「看链接 / 看摘要」的 `(request_id, guid)`。
        #: ⚠️ 光有请求号**不够**：面板是共享单例，使用者可以在结果回来之前
        #: 换选中项而**不发起新请求** —— 那时请求号没变，结果却已经不属于
        #: 现在选中的那条了。所以还要比对 GUID。
        self._gpo_request: tuple[int, str] = (0, "")

        # ⚠️ 每个「关闭 / 取消」按钮都必须走到这里：面板自己的
        # hide 只把面板藏掉，QStackedWidget 会留一块空白、splitter
        # 宽度还占着（实测：属性面板关闭后空白遮列表）。此前
        # rejected 信号根本没人接 —— 这是移动/属性等所有面板的
        # 关闭残留的共同根因。
        for panel in (self.create_user_panel, self.create_ou_panel,
                      self.create_group_panel, self.property_panel,
                      self.result_panel, self.rename_panel,
                      self.move_panel, self.add_to_group_panel,
                      self.create_computer_panel, self.create_contact_panel,
                      self.gpo_panel):
            panel.rejected.connect(self._hide_panel)

        layout.addWidget(self.panels)
        container.setVisible(False)
        self.panel_container = container
        return container

    # ==================================================================
    # 对外
    # ==================================================================

    def start(self, info, is_mock: bool = False) -> None:
        """进入页面：设定树根并加载第一批数据。"""
        self.conn_label.setText(f"{self.client.cfg.dc_ip if self.client.cfg else ''}"
                                f"　{self.client.bind_identity}")
        self.domain_label.setText(
            f"域 {self.client.domain or '（未知）'}　BaseDN {self.client.base_dn}")
        self.mock_badge.setVisible(is_mock)
        self.tree.set_root(self.client.base_dn, self.client.domain or "域根")
        self._current_dn = self.client.base_dn
        self._current_title = f"{self.client.domain or '域根'}（整个域）"
        self._load_objects(self.client.base_dn, self._current_title, subtree=True)

    def refresh(self) -> None:
        self.tree.invalidate()
        if self._search_active:
            self.search.fire()
        else:
            self._load_objects(self._current_dn, self._current_title, self._subtree)

    def notify(self, text: str, level: str = "info") -> None:
        r"""一条提示：**既弹给使用者，也落进 ``app.log``**。
        ⚠️ 本 docstring **必须**留 `r` 前缀：下面 `grep` 写法里的 `\.` 在普通字符串里是**非法转义序列**（3.12+ 发 `SyntaxWarning`、`-W error` 下直接失败）；整段只此一处反斜杠，故整段 raw 安全。
        ⚠️ 为什么落盘写在**这里**，而不是 71 个调用点各写一行：
            本文件曾经是「``_log`` 定义在第 104 行，却**一次都没被调用**」。
            后果是：后端（`workers`）会记任务失败，但**使用者当场看到的那些失败**
            （读取对象失败 / 保存权限组失败 / 导出失败 / 本地预检不通过……）
            只弹一个 Toast，``app.log`` 里**一行都没有** ⇒
            真域实测报错后反馈，日志里**查不到对应现场**。

            本方法是这个类**唯一**的提示出口（现有 71 处调用全部经过它 ——
            2026-09-16 实测 `grep -c 'self\.notify(' ui_browser.py`；这个数字是
            **流动的**，加/删提示时同步改）⇒
            在这一处落盘，等于给所有现有**与将来**的提示都上了日志。
            反过来，靠"以后加提示时记得也写一行日志"是**必然要漂**的约定
            （同样的理由写在 `_sync_after_change` 的 docstring 里）。

        ⚠️ **连 `ok` / `info` 也记**，不做"只记错误"的过滤：排障时引用的
            原话常常是"我点了保存，它提示成功了" —— 只留失败行的话，恰恰少了
            能证明「他当时看到的是什么」的那一半。本项目是低频管理台，
            一次会话几十条而已，量不是问题。

        ⚠️ 文案里**不许出现口令**：这里落盘前会过 `utils._RedactFilter` 兜底，
            但兜底只做形态匹配、不是保证 —— 源头（调用点）就不该把口令拼进文案。
        """
        self.toast.show_message(text, level)
        # ⚠️ 级别 → 日志级别的映射在 `ui_widgets.NOTIFY_LOG_LEVELS`，
        #    落盘实现只有 `ui_widgets.log_notify` 一份。
        #    （2026-09-16 之前它还有个共用者 `ui_share`，那个模块已随「操作共享盘」
        #    功能整体删除；立这条不变式的理由不变 —— 两边各写一份的下场是
        #    "一边 danger 记成 INFO、另一边记成 ERROR"，按级别筛行就会漏。）
        log_notify(_log, text, level)

    # ==================================================================
    # 变更之后的「强制 AD 复制同步」（共用收尾，**只有这一处实现**）
    # ==================================================================

    def _sync_after_change(self, what: str) -> None:
        """一次使用者可见的变更**成功之后**，把这台域控的改动推给复制伙伴。

        为什么单独一个方法、而不是在三个入口各写一遍：**入口会漂**。
        三份拷贝意味着以后加第四个入口时必然漏掉同步，而漏掉**没有任何报错**
        —— 表现就是"有时候要等一小时、有时候不用"，最难查的那类问题。
        这里一处实现、三处调用。

        ⚠️ 粒度是「**一次操作**」而不是「一个对象」：批量删 20 个对象只推 **1** 次
           （理由见 `workers.sync_replication` 上方那段）。所以它不可能挂在
           `ad_client` 里 —— 那一层只知道单个对象。

        ⚠️ `self.client` 必须**显式传**：`sync_replication` 是模块级函数，
           不像 `self.client.xxx` 那样自带绑定。本项目踩过这个坑 ——
           漏传**不报"缺参数"**，后面的实参顶上来，直到别处才炸。

        ⚠️ **代跑还是只给命令，由连接的 `sync_after_change` 开关定**：
        本工具常常跑在一台**未加域**的机器上（实测那台机器解析不了域控名、
           `repadmin` 只吃域名不吃 IP）—— 在那里它**不可能**自己把复制推出去。
           与其让人对着"推失败"发呆，不如把**能直接抄走的那条命令**交出去。
           ⇒ 开关 **True**：照旧自动尝试（命令由 `SyncOutcome.notice` 在
              "没执行/推失败"时给出）；开关 **False**（**2026-09-17 起是默认值**）：
              不提交任务，直接给出命令。
        ⚠️ **"给命令"这件事不必每次都弹**：上面那个结论在一台机器上是**结构性**的
           —— 每次建/删都得到同一句话 ⇒ 交给 `_announce_sync` 去重（详见它）。
           要**主动**推一次请走 `sync_replication_now()`（菜单「工具 → 强制复制同步」）：
           它**不读这个开关**，因为按下去的意思就是"现在推"。

        ⚠️ 拿不到 `cfg`、或拿不到这个开关时，一律按**"照旧自动尝试"**处理
           （`getattr(..., True)`）。理由**不是**"兼容测试"：读不到只可能意味着
           "这条连接压根没带配置"（`cfg is None` = 已断开，或鸭子类型的替身），
           而那两种情况下的**既有行为**就是自动尝试 —— 这里不许凭空造出一个
           新的"静默不推"状态。（`cfg is None` 那条路照旧：提交出去，由
           `workers.sync_replication` 返回 `REASON_NOT_CONNECTED`，
           而它在 `_SILENT_REASONS` 里 ⇒ **静默跳过、不新增提示**。）
        """
        cfg = getattr(self.client, "cfg", None)
        if getattr(cfg, "sync_after_change", True):
            self._submit_sync(what, manual=False)
            return
        # 开关关掉 ⇒ **不代跑**，把命令交到使用者手上（他要拿去文件服务器上执行）。
        # 域控名取 RootDSE 反查到的 `dns_host_name`；拿不到就用占位形态，
        # **不许编造一个名字**（编出来的名字会被真的抄进命令行，比占位更坏）。
        info = getattr(self.client, "info", None)
        dc_name = (getattr(info, "dns_host_name", "") or "").strip() if info else ""
        command = manual_command(dc_name) if dc_name else manual_command()
        # 指纹里带上**这条命令**：换了一台域控就是换了一件事，必须重新说。
        self._announce_sync(
            ("skipped-by-switch", command),
            f"{what}已成功（「已经生效、不需要重做」）；"
            f"已按该连接的设置「跳过」自动强制复制同步。\n"
            f"可在域控上手工执行：{command}\n"
            f"（也可以随时用菜单「工具 → 强制复制同步」重推一次）", "warn")

    def _submit_sync(self, what: str, *, manual: bool) -> None:
        """提交一次强制复制同步的任务 —— **本文件唯一的提交口**。

        ⚠️ 为什么"唯一"要单独说：这条任务有**两个入口**（自动收尾 `_sync_after_change`、
        使用者按需 `sync_replication_now`），而两处各写一遍 `tasks.submit(...)` 的下场
        是"以后加第三个入口时漏掉一个参数"（同 `_sync_after_change` 上方那段理由）。
        两个入口的差别**只有两件事**：要不要看那个开关、以及说不说"成功"，
        ⇒ 差别放在**入参** `manual` 里，提交本身只有这一份。

        ⚠️ `manual` 必须**绑定在发起时**（`_m=manual` 默认参数），不许在回调里读
        `self` 的当前状态：回调到货时使用者可能已经点了别的操作，
        读"现在是谁"会把结果说成另一个动作的（本项目踩过这一类）。
        """
        self.tasks.submit(
            "强制 AD 复制同步", sync_replication,
            lambda outcome, _w=what, _m=manual: self._on_synced(outcome, _w, _m),
            lambda message, code, _w=what: self.notify(
                f"{_w}已成功，但强制复制同步出错：{message}", "warn"),
            self.client)

    def sync_replication_now(self, what: str = "强制复制同步") -> None:
        """**使用者按需**推一次（菜单「工具 → 强制复制同步」）。

        ⚠️ 与自动收尾的两点不同，都是**故意的**：

          * **不读**连接上的 `sync_after_change` —— 按下去的意思就是"现在推"，
            那个开关管的是"以后要不要自动推"；看它会让"关了自动"的人按不动按钮；
          * **不给去重、成功也要说话** —— 使用者亲手按的动作，"什么都没发生"
            是最坏的反馈。自动那条路成功时静默，是因为它**每次**变更后都会跑，
            说话就是噪声；这里一次点击换一句回话，不构成噪声。
        """
        self._submit_sync(what, manual=True)

    def _announce_sync(self, key: tuple, text: str, level: str, *,
                       always: bool = False) -> None:
        """说一条同步的结果 —— **同一件事只弹一次**，再出现只落盘。

        ⚠️ 为什么要去重：提示条是**一次性**的（后一条弹出来，前一条就永远看不到了），
        而"本机解析不了域控名""本机没装 repadmin"这类结论在一台机器上是
        **结构性**的 —— 建号得到它、删号得到它、建 OU 还是它。
        重复弹的收益是零，代价是每次都挤掉排在后面的真提示。

        ⚠️ **日志不去重**：排障依赖 `app.log` 里**每一次**都有那一行。
        "提示条是一次性的"与"日志是一次性的"是两件事 —— 这条区分是本方法存在的理由，
        所以这里走的是 `ui_widgets.log_notify`（与 `notify()` 内部**同一个落盘实现**），
        而不是自己写一行 `_log.info`。

        ⚠️ 指纹由调用方给（`SyncOutcome.notice_key` 或 `("skipped-by-switch", 命令)`），
        **不是文案比对**：文案里带动作名（"新建用户已成功…"与"删除对象已成功…"），
        拿它当指纹会在**重复弹得最凶的那种情形**上失效。

        ⚠️ 读不到 `_sync_seen`（鸭子类型替身 / 还没接线）⇒ 按"**没说过**"处理：
        宁多弹一次，也不许把该说的话吞掉（"静默降级"是本项目最怕的失败形态）。
        """
        seen = getattr(self, "_sync_seen", None)
        if not always and seen is not None and key in seen:
            log_notify(_log, text, level)
            return
        if seen is not None:
            seen.add(key)
        self.notify(text, level)

    def _on_synced(self, outcome, what: str, manual: bool = False) -> None:
        """把同步结果说出来 —— **但只在有话要说的时候**。

        ⚠️ `silent` 那一步不是优化，是**必需**：提示条是一次性的（`toast`），
           后一条弹出来前一条就永远看不到了。这条提示的第一版**在演示模式下
           也弹**，结果把上一条更重要的提示（"账号已建好，但 N 个权限组没挂上"）
           挤掉了 —— 当时把这件事归因给一条"抓到了它的界面冒烟用例"。
           ⚠️ **更正**（2026-09-16 全库悬空引用审计）：那个用例名
           `test_a_failing_group_does_not_hide_the_created_account`
           **从未作为 `def` 存在过**（当前仓库 + 两个库外快照，`def` 0 命中
           —— 它是一条**编出来的归因**，别按这个名字去找）；
           真守卫是 `tests/test_replication.py::TestWhenToSpeak` 里的
           `test_the_demo_skip_is_silent` / `test_a_disconnected_skip_is_silent`。
           判"该不该说"的依据在 `SyncOutcome.silent`（结构化原因码，不是文案匹配）。

        级别只有两档（成功 `ok` / 其余 `warn`），**故意没有 danger**：
        建号/删号本身已经成功了，用 danger 会让人以为整个操作失败。

        ⚠️ 2026-09-17 追加：多了一个 `manual`（菜单「工具 → 强制复制同步」进来的那条路）。

          * `manual=True` ⇒ **绕过** `silent`（使用者亲手按的，"什么都没发生"
            是最坏的反馈）**并且**绕过去重（理由见 `sync_replication_now`）；
          * `manual=False` ⇒ 照旧先看 `silent`，再交给 `_announce_sync` **去重**
            —— 同一件"事"只弹一次，但 `app.log` 里一次都不会少。
        """
        if not manual and outcome.silent:
            return
        text, level = outcome.notice(what)
        self._announce_sync(outcome.notice_key, text, level, always=manual)

    # ==================================================================
    # 数据加载
    # ==================================================================

    def _load_ou_children(self, dn: str) -> None:
        def job():
            nodes = list(self.client.list_child_ous(dn) or [])
            # F10：域根下补上内置容器（Users / Computers / Builtin）
            if dn == self.client.base_dn:
                known = {n.dn.casefold() for n in nodes}
                for container in self.client.list_well_known_containers(dn):
                    if container.dn.casefold() not in known:
                        nodes.append(container)
            nodes.sort(key=lambda n: n.name.lower())
            return nodes

        self.tasks.submit(
            "读取子部门", job,
            lambda nodes, _lbl=None, _dn=dn: self.tree.fill_children(_dn, nodes or []),
            lambda message, code, _dn=dn: self._on_children_failed(_dn, message))

    def _on_children_failed(self, dn: str, message: str) -> None:
        self.tree.mark_failed(dn)
        self.notify(f"读取子部门失败：{message}", "danger")

    def _load_objects(self, dn: str, title: str = "",
                      subtree: bool | None = None) -> None:
        """加载某容器下的**混合对象**（F01：ADUC 的右窗格行为）。

        ``subtree=None`` 表示「自动判断」：只有**域根**才递归整棵子树，
        其余容器一律只看直属对象。理由是从域根看直属对象必然是空的
        （对象都住在 OU / 内置容器里），点域根却看到空表会让人以为工具坏了。
        """
        if not dn:
            return
        if subtree is None:
            subtree = bool(self.client and dn == self.client.base_dn)
        self._search_active = False
        self._current_dn = dn
        self._current_title = title or dn
        self._subtree = subtree
        self.count_label.setText(f"正在读取　{self._current_title} …")
        token = self._next_list_token()
        self.tasks.submit(
            "读取对象", self.client.list_objects,
            lambda rows, tk=token, t=self._current_title, s=subtree:
                self._on_objects_loaded(tk, rows or [], t, s),
            lambda message, code, tk=token: self._on_load_failed(message, code, tk),
            dn, self._filter_kinds,
            "SUBTREE" if subtree else "LEVEL",
            None, SUBTREE_USER_LIMIT if subtree else None)

    def _next_list_token(self) -> int:
        """领一个列表请求号（见 ``_list_token``）。"""
        self._list_token += 1
        return self._list_token

    def _on_objects_loaded(self, token: int, rows: list[DirObject], title: str,
                           subtree: bool) -> None:
        if token != self._list_token:
            return                  # 已被更晚的一次加载取代 —— 别盖上去
        self._show_objects(rows, title, subtree)

    def _show_objects(self, rows: list[DirObject], title: str,
                      subtree: bool = False) -> None:
        self.model.set_rows(rows)
        self.table.clearSelection()
        self.table.sortByColumn(COL_NAME, Qt.SortOrder.AscendingOrder)
        scope = "（含下级部门）" if subtree else ""
        text = f"{title}{scope}　·　共 {len(rows)} 个对象"
        if subtree and len(rows) >= SUBTREE_USER_LIMIT:
            # 说清楚是被截断了，不然使用者会以为域里就这么点东西
            text += f"　·　已达上限 {SUBTREE_USER_LIMIT}，请缩小范围或用搜索"
        self.count_label.setText(text)

    def _on_load_failed(self, message: str, code: str, token: int = 0) -> None:
        if token and token != self._list_token:
            return                  # 旧的失败不该把已经加载好的新列表清空
        self.model.set_rows([])
        self.count_label.setText("")
        self.notify(f"读取对象失败：{message}", "danger")

    def _on_tree_selected(self, dn: str, title: str) -> None:
        self.search.clear()
        # 「移动到」面板开着时，点树就是**选目标** —— 这时候关面板
        # 等于把选目标的唯一入口关了，移动功能整个不可用（实测踩过）。
        moving = (self.panel_container.isVisible()
                  and self.panels.currentWidget() is self.move_panel)
        if not moving:
            self._hide_panel()
        if self.client and dn == self.client.base_dn:
            title = f"{title}（整个域）"
        self._load_objects(dn, title)
        if moving:
            self.move_panel.set_target(dn, title)

    def _on_tree_clicked(self, item, _column: int) -> None:
        """点左树**同一个**已选中节点（currentItemChanged 不会触发）。

        搜索态下这个动作必须能退出搜索 —— 否则使用者点着左树，
        界面却提示「请先点左侧部门」，点哪里都出不去（实测踩过）。
        """
        from ui_tree import ROLE_DN, ROLE_PLACEHOLDER
        if item is None or item.data(0, ROLE_PLACEHOLDER):
            return
        if self._search_active and item is self.tree.tree.currentItem():
            self._load_objects(item.data(0, ROLE_DN) or "", item.text(0))

    def _on_kind_filter_changed(self, index: int) -> None:
        self._filter_kinds = KIND_FILTER_CHOICES[max(0, index)][1]
        if self.filter_builder.isVisible():
            # 构建器开着：类型筛选作为前置条件 AND 进过滤器，条件变了要重查
            if self._search_active:
                self.filter_builder.emit_search()
            else:
                # ⚠️ 构建器开着但**还没搜过** ⇒ 改类型筛选眼下没有对象可作用。
                #    静默 return 会让人以为"筛选没生效"（浏览态同一操作是**会**
                #    立刻重载列表的，所以这个反差特别容易被误读）。
                self.notify("高级条件还没搜索过 —— 类型筛选会在点「搜索」时生效。")
            return
        if self._search_active:
            self.search.fire()
        else:
            self._load_objects(self._current_dn, self._current_title, self._subtree)

    # ==================================================================
    # 搜索（F09：全类型 + 全目录；F12：可视化条件构建器）
    # ==================================================================

    def _on_advanced_toggled(self, on: bool) -> None:
        """「高级」开关：浮现条件构建器、隐藏普通搜索框（二者互斥）。

        类型筛选下拉**保持可用** —— 在构建器模式下它作为前置条件
        AND 进生成的过滤器（ADUC 的查找窗也是先选对象类型再填条件）。
        """
        self.filter_builder.setVisible(on)
        self.search.setVisible(not on)
        if on:
            self.filter_builder.setFocus()
        else:
            self.search.setFocus()

    def _on_builder_search(self, flt: str, desc: str) -> None:
        """构建器发出「查找」：并入类型筛选子句 → 校验 → 后台搜索。"""
        clause = self._kind_ldap_clause()
        final = f"(&{clause}{flt})" if clause else flt
        from utils import validate_ldap_filter
        reason = validate_ldap_filter(final)
        if reason:
            self.notify(reason, "warn")
            return
        self._search_active = True
        self._hide_panel()
        scope = "（当前类型筛选）" if clause else ""
        self.count_label.setText(f"正在按条件搜索：{desc}{scope}…")
        token = self._next_list_token()
        self.tasks.submit(
            "高级查找", self.client.search_raw_filter,
            lambda rows, tk=token, d=f"{desc}{scope}":
                self._on_search_loaded(tk, rows or [], d),
            lambda message, code, tk=token: self._on_load_failed(message, code, tk),
            self.client.base_dn, final, 500)

    def _kind_ldap_clause(self) -> str:
        """当前类型筛选下拉 → LDAP 子句（空串 = 全部对象，不并）。"""
        index = max(0, self.kind_filter.currentIndex())
        kinds = KIND_FILTER_CHOICES[index][1]
        if not kinds:
            return ""
        return "".join(KIND_LDAP_CLAUSES[k] for k in kinds)

    def _on_search(self, keyword: str) -> None:
        if not keyword:
            self._load_objects(self._current_dn, self._current_title)
            return
        self._search_active = True
        self._hide_panel()
        self.count_label.setText(f"正在全目录搜索「{keyword}」…")
        token = self._next_list_token()
        self.tasks.submit(
            "搜索对象", self.client.list_objects,
            lambda rows, tk=token, kw=keyword:
                self._on_search_loaded(tk, rows or [], kw),
            lambda message, code, tk=token: self._on_load_failed(message, code, tk),
            self.client.base_dn, self._filter_kinds, "SUBTREE", keyword, 500)

    def _on_search_loaded(self, token: int, rows: list[DirObject],
                          keyword: str) -> None:
        if token != self._list_token:
            return                  # 用户已经点了别的部门／又搜了一次
        self._show_search(rows, keyword)

    def _show_search(self, rows: list[DirObject], keyword: str) -> None:
        self.model.set_rows(rows)
        self.table.clearSelection()
        scope = "（当前类型筛选）" if self._filter_kinds else ""
        self.count_label.setText(
            f"搜索「{keyword}」　·　命中 {len(rows)} 个对象{scope}　·　"
            "（跨整个目录；点左侧部门可退出搜索）")
        self.footer.setText("")

    # ==================================================================
    # 选中与批量
    # ==================================================================

    def selected_rows(self) -> list[DirObject]:
        return self.proxy.selected_rows(self.table.selectionModel().selectedIndexes())

    @staticmethod
    def account_rows(rows: list[DirObject]) -> list[UserRow]:
        """从混合选区里挑出**有账号**的对象（重置密码/启停/解锁只对它们有意义）。

        ⚠️ 判据必须写 `is False`，**不能**写 `not o.is_dc`：`is_dc` 对
        "读不到 UAC 的计算机"是 `None`，而 `not None` 是 `True` ⇒ 会把一台
        **没准就是域控**的机器放进批量账号操作里。挑少一台最多是这次批量
        少做了一个对象（看得见、可重试），挑错一台是往域控上写。
        """
        return [o.to_user_row() for o in rows
                if o.has_account and o.is_dc is False]

    def _on_selection_changed(self, *_args) -> None:
        rows = self.selected_rows()
        self._current_rows = rows

    def _set_pending(self, pending: tuple[str, dict] | None) -> None:
        self._pending_action = pending

    def _ask_reset_password(self) -> None:
        rows = self.account_rows(self.selected_rows())
        if not rows:
            self.notify("选中的对象里没有可重置密码的账号"
                        "（组 / 联系人 / 域控没有密码可重置）。", "warn")
            return
        self._set_pending(("reset_password", {"rows": rows}))
        self.confirm.ask(
            f"将对 {len(rows)} 个账号设置同一个新密码",
            need_password=True,
            extra_hint="（同一个密码发给多个人 —— 请确认确有需要）",
            ok_text="执行重置")

    def _ask_set_enabled(self, enabled: bool) -> None:
        rows = self.account_rows(self.selected_rows())
        if not rows:
            self.notify("选中的对象里没有可启停的账号"
                        "（组 / 联系人没有启用/禁用；域控不允许禁用）。", "warn")
            return
        verb = "启用" if enabled else "禁用"
        self._set_pending(("enable" if enabled else "disable", {"rows": rows}))
        self.confirm.ask(
            f"将对 {len(rows)} 个账号执行「{verb}」",
            extra_hint=self._disable_hints(rows) if not enabled else "",
            ok_text=f"执行{verb}")

    def _disable_hints(self, rows: list[UserRow]) -> str:
        """禁用前的提示行（可多行）。

        第二条「你自己」是运维视角加的：真域**允许**禁用当前登录的账号
        （现有会话不受影响，下次登录才生效），所以这不是"违规"，而是
        运维习惯上最容易把管理员关在门外的那一步 —— 批量勾选时手一滑
        很容易把绑定的那个账号一起带上，而确认条只写「将对 12 个账号执行
        「禁用」」，看不出里面有自己。取不到绑定账号就只留第一条提示。
        """
        hints = ["（禁用后这些人 / 这些机器将无法登录域）"]
        me = bind_account_name(self.client.cfg.bind_user if self.client
                               and self.client.cfg else "")
        if not me:
            return "\n".join(hints)
        mine = [r.sam for r in rows
                if (r.sam or "").casefold() == me.casefold()]
        if mine:
            hints.append(
                f"⚠️ 选中的对象里包含你当前登录的账号「{mine[0]}」—— "
                f"禁用后你「下次将无法登录域」，请先确认还有别的管理员账号可用。")
        return "\n".join(hints)

    def _ask_unlock(self) -> None:
        rows = self.account_rows(self.selected_rows())
        if not rows:
            self.notify("选中的对象里没有可解锁的账号。", "warn")
            return
        self._set_pending(("unlock", {"rows": rows}))
        self.confirm.ask(f"将解锁 {len(rows)} 个账号", ok_text="执行解锁")

    # ---------- 删除（F03：先算范围 → 内联确认 → 范围复核） ----------

    def _ask_delete(self, objs: list[DirObject] | None) -> None:
        rows = objs if objs is not None else self.selected_rows()
        if not rows:
            return
        if len(rows) == 1:
            obj = rows[0]
            self.count_label.setText(f"正在计算「{obj.title or obj.dn}」的删除范围…")
            self.tasks.submit(
                "计算删除范围", self.client.plan_delete,
                self._on_delete_plan, self._on_load_failed,
                obj.dn, obj.kind, obj.title or obj.sam or obj.dn)
            return

        names = "、".join((o.title or o.sam) for o in rows[:4])
        more = f" 等 {len(rows)} 个对象" if len(rows) > 4 else ""
        self._set_pending(("delete_multi", {"objs": list(rows)}))
        self.confirm.ask(
            f"将删除 {len(rows)} 个对象：{names}{more}",
            extra_hint="（删除后不可恢复 —— AD 回收站默认是关闭的）",
            ok_text="确认删除")

    def _on_delete_plan(self, plan) -> None:
        if not plan.allowed:
            self.notify(plan.blocked_reason, "danger")
            return
        target = DirObject(kind=ObjectKind.OTHER, cn=plan.root_label,
                           dn=plan.root_dn)
        self._set_pending(("delete_single",
                           {"obj": target, "total": plan.total,
                            # 确认时刻的后代 DN 快照：执行时做 diff 复核，
                            # 同数量的「替换」数量复核抓不住（审计建议项）
                            "dns": [o.dn for o in plan.descendants]}))
        extra = ""
        if plan.descendants:
            extra = f"（连同下级共 {plan.total} 个对象 —— 删除「不可恢复」）"
        else:
            extra = "（删除「不可恢复」 —— AD 回收站默认是关闭的）"
        self.confirm.ask(f"将删除「{plan.root_label}」{extra}", ok_text="确认删除")

    # ---------- 确认条执行 ----------

    def _on_confirm(self, password: str) -> None:
        if self._pending_action is None:
            return
        action, payload = self._pending_action

        if action == "reset_password":
            if not password:
                self.notify("请先填写新密码。", "warn")
                return
            rows = payload["rows"]
            if not rows:
                return
            from utils import check_password_guessability

            reason = check_password_guessability(password, rows[0].sam)
            if reason:
                self.notify("本地预检未通过：" + reason, "warn")
                return
            self._run_batch("批量重置密码", batch_reset_password,
                            "rows", rows, password, True)
            self.notify(f"已开始为 {len(rows)} 个账号重置密码。"
                        "所有人将使用同一个新密码。", "info")
        elif action in ("enable", "disable"):
            self._run_batch("批量启用账号" if action == "enable" else "批量禁用账号",
                            batch_set_enabled, "rows",
                            payload["rows"], action == "enable")
        elif action == "unlock":
            self._run_batch("批量解锁账号", batch_unlock,
                            "rows", payload["rows"])
        elif action == "delete_single":
            obj: DirObject = payload["obj"]
            self.tasks.submit(
                "删除对象", self.client.delete_object,
                lambda total, o=obj: self._on_deleted(
                    o.dn,
                    f"已删除「{o.cn or o.dn}」" +
                    (f"（含 {total - 1} 个下级对象）" if total > 1 else "")),
                self._on_delete_failed,
                obj.dn, obj.kind, obj.cn or obj.dn, obj.sam, payload["total"],
                payload.get("dns"))
        elif action == "delete_multi":
            self._run_batch("批量删除", batch_delete,
                            "delete", payload["objs"])
        elif action == "reset_computer":
            self._run_reset_computer(payload["obj"])

        self.confirm.hide_bar()
        self._set_pending(None)

    def _run_batch(self, label: str, fn, refresh, *args) -> None:
        """批量提交。``refresh`` 决定收尾方式（见 `_on_batch_done`）：

        * ``"rows"``              —— 属性类（启停/解锁/改密）：回读成功项、就地刷行；
        * ``"delete"``            —— 逐个摘树节点 + 重拉当前容器；
        * ``("move", target_dn)`` —— 只重载受影响父节点的子级 + 重拉当前容器。
        """
        self.tasks.submit(
            label, fn,
            lambda result, _r=refresh: self._on_batch_done(result, _r),
            self._on_batch_failed,
            self.client, *args, with_progress=True)

    def _on_batch_done(self, result, refresh="rows") -> None:
        if not isinstance(result, BatchResult):
            return
        self.result_panel.load(result)
        self._show_panel(self.result_panel)
        if result.failed:
            self.notify(result.summary(), "warn")
        else:
            self.notify(result.summary(), "ok")
        # 收尾分流：属性类修改**不许**整树重载/整表重拉 —— 只刷受影响的行；
        # 结构类（删/移）才动树，且按节点局部更新。
        mode = refresh[0] if isinstance(refresh, tuple) else refresh
        if mode == "rows":
            self._refresh_rows([i.dn for i in result.succeeded if i.dn])
        elif mode == "delete":
            for item in result.succeeded:
                if item.dn:
                    self.tree.remove_node(item.dn)
            self._reload_after_change()
            # 一次批量删除 = **一次**同步，不是每条一次（20 条会变成 20 次全域
            # 复制流量）。全失败就什么都没变，不需要推。
            if result.succeeded:
                self._sync_after_change(f"批量删除 {len(result.succeeded)} 个对象")
        elif mode == "move":
            target = refresh[1] if isinstance(refresh, tuple) else ""
            moved_precisely = False
            for item in result.succeeded:
                if item.dn and item.new_dn:
                    # 后端回传了新 DN → 树上删旧插新，精确且保留展开状态
                    self.tree.move_node(item.dn, item.new_dn, target)
                    moved_precisely = True
            if not moved_precisely:
                # 没有新 DN（旧合同/后端未回传）：降级为两端父节点整层重拉
                parents = {parent_of_dn(i.dn) for i in result.succeeded if i.dn}
                parents.discard("")
                if target:
                    parents.add(target)
                for parent in sorted(parents):
                    self.tree.reload_node(parent)
            self._reload_after_change()
        else:
            self._reload_after_change()

    def _on_batch_failed(self, message: str, code: str) -> None:
        self.notify(message, "danger")

    def _refresh_rows(self, dns: list[str]) -> None:
        """写操作落库后**就地**刷新受影响行（不重拉列表、不 resetModel）。

        逐个回读落库后的真实状态（userAccountControl / 锁定位 / 密码
        过期），按 DN 替换 model 内存行对象并精确 dataChanged。
        树只承载 OU 结构、不承载账号状态 —— 属性类修改**不碰树**。
        """
        dns = [dn for dn in dns if dn]
        if not dns:
            return
        if len(dns) > REFRESH_INPLACE_LIMIT:
            # 大批量（如域根 subtree 视图全选几百个禁用）：逐个回读 =
            # N 次 LDAP 往返，比一次重拉还贵 —— 降级为重拉当前视图。
            # 选中会被清掉，但这个量级下没人逐行盯着看。
            self.notify(f"已刷新列表（{len(dns)} 个对象，大批量走整体重载）。",
                        "info")
            if self._search_active:
                self.search.fire()
            else:
                self._load_objects(self._current_dn, self._current_title,
                                   self._subtree)
            return

        def job():
            objs, errors = [], []
            for dn in dns:
                try:
                    objs.append(self.client.get_object(dn))
                except Exception as exc:          # noqa: BLE001
                    # 条目级失败（对象刚好被人删了）别拖垮整批回读
                    errors.append(str(exc))
            return objs, errors

        def done(payload):
            objs, errors = payload
            if objs:
                self.model.update_rows(objs)
            if errors:
                if len(errors) * 2 >= len(dns):
                    # 过半失败：界面大概率整体过时，别让人以为已经刷过了
                    self.notify(
                        f"{len(errors)}/{len(dns)} 个对象的状态刷新失败 —— "
                        "列表可能已过时，请手动刷新当前视图确认。", "warn")
                else:
                    self.notify(
                        f"{len(errors)} 个对象的状态刷新失败：{errors[0]}",
                        "warn")

        self.tasks.submit("刷新行状态", job, done,
                          lambda message, code:
                          self.notify(f"刷新行状态失败：{message}", "warn"))

    # ==================================================================
    # 删除 / 移动 / 重命名 的收尾与失败
    # ==================================================================

    def _on_deleted(self, dn: str, message: str) -> None:
        self.notify(message, "ok")
        # 树上只有 OU / 容器：删 OU 才真有节点可摘，删用户/组是 no-op
        self.tree.remove_node(dn)
        self._reload_after_change()
        # 删除是**软删除**（对象进 Deleted Objects，`isDeleted=TRUE`）：复制到位
        # 之前 GC 上那个对象**还在**，所以"删了还能搜到"。推一次就立刻一致。
        self._sync_after_change("删除对象")

    def _on_delete_failed(self, message: str, code: str) -> None:
        self.notify(message, "danger")
        self._reload_after_change()

    def _reload_after_change(self) -> None:
        """结构变化（删/移/改名/建）后的收尾 —— **不再整树重载**。

        树的局部更新（摘节点/删旧插新/改文本）由各操作回调按需调用
        ``tree.remove_node / move_node / rename_node / insert_child /
        reload_node``；这里只负责：组织单位下拉缓存失效 + 当前列表重拉
        （one-level 很快）。属性类修改请走 `_refresh_rows`，别进这里。
        """
        # 组织单位下拉的候选是「每连接读一次」的缓存 —— 删除/移动/改名/建 OU
        # 都会改变目录结构，必须失效，否则新建的三级 OU 永远出现在下拉里。
        self._department_options_loaded = False
        if self._search_active:
            self.search.fire()
        else:
            self._load_objects(self._current_dn, self._current_title, self._subtree)

    # ==================================================================
    # 移动（F04）
    # ==================================================================

    def _open_move(self, objs: list[DirObject] | None) -> None:
        rows = objs if objs is not None else self.selected_rows()
        if not rows:
            self.notify("请先选中要移动的对象。", "warn")
            return
        base = (self.client.base_dn or "").casefold() if self.client else ""
        if any((o.dn or "").casefold() == base for o in rows):
            self.notify("域根不能移动。", "warn")
            return
        self.move_panel.load(rows)
        self.move_panel.set_target(self._current_dn, self._current_title or "当前容器")
        self._show_panel(self.move_panel)

    def _submit_move(self) -> None:
        dns, target = self.move_panel.values()
        if not target:
            self.notify("请先在左侧目录树中点选目标容器。", "warn")
            return
        if not dns:
            self.notify("没有要移动的对象，请重新选择。", "warn")
            return
        # ⚠️ 三种拒绝的原因**各不相同**，文案不能混用。
        #    原来只有一个分支，判据是「对象自己的 DN == 目标」，命中的其实是
        #    「把对象移进它自己」；而真正白跑一趟的「已经在这个容器里」根本没判到，
        #    于是提交给后端、再弹一句后端给的错误，文案还写着「有对象已经在目标
        #    容器里了」—— 用户以为目标选错了，其实是没换过目标。
        for dn in dns:
            if (parent_of_dn(dn) or "").casefold() == target.casefold():
                self.notify("对象已经在目标容器里了，无需移动。", "warn")
                return
            if dn.casefold() == target.casefold():
                self.notify("目标不能是对象自己。", "warn")
                return
            if is_descendant_dn(target, dn):
                self.notify("目标在选中对象的下级，移进去会形成环，AD 会拒绝。",
                            "warn")
                return
        if len(dns) == 1:
            # ⚠️ sam / 可读名称必须一路带到后端：审计靠 sam 记「对谁做的」，
            #    错误文案靠它说人话。漏传的话日志里只剩一条 DN。
            rows = self.move_panel.rows()
            obj = next((o for o in rows
                        if o.dn.casefold() == dns[0].casefold()), None)
            self.tasks.submit(
                "移动对象", self.client.move_object,
                lambda new_dn, _old=dns[0], _t=target:
                    self._on_moved(_old, new_dn or "", _t),
                self._on_move_failed, dns[0], target,
                (obj.sam if obj else ""),
                ((obj.title or obj.sam) if obj else ""))
        else:
            # ⚠️ 必须把**真实的**对象交给批量执行器。原来这里就地造
            #    `DirObject(kind=OTHER, dn=dn)`，账号名和名称全丢：
            #    结果列表只能退化显示整条 DN，审计的 target_sam 是空的，
            #    条目级失败记录也一样。别的批量操作（解锁/删除/重置计算机）
            #    都传的是真实行 —— 只有移动另写了一份，于是只有它漏。
            self._run_batch("批量移动", batch_move,
                            ("move", target), self.move_panel.rows(), target)
        self._hide_panel()

    def _on_moved(self, old_dn: str, new_dn: str, target: str) -> None:
        self.notify("已移动 1 个对象。", "ok")
        # 只有移动 **OU** 才需要动树（删旧插新）；用户/组在树上没有节点。
        if new_dn:
            self.tree.move_node(old_dn, new_dn, target)
        else:
            # 后端没回传新 DN：只作废两端父节点的子级，其余节点原样保留
            old_parent = parent_of_dn(old_dn)
            if old_parent:
                self.tree.reload_node(old_parent)
            self.tree.reload_node(target)
        self._reload_after_change()

    def _on_move_failed(self, message: str, code: str) -> None:
        self.notify(message, "danger")

    # ==================================================================
    # 重命名（F04）
    # ==================================================================

    def _on_rename_key(self) -> None:
        rows = self.selected_rows()
        if len(rows) == 1:
            self._open_rename(rows[0])
            return
        # ⚠️ 与 `_open_detail` 同一纪律：F2 是最容易被随手按的键，
        #    静默什么都不做会被读成"卡住了"（同文件里 `_open_detail`
        #    对同一个判据是会说话的 —— 落下的只有这一处）。
        self.notify("重命名需要且只能选中一个对象。", "warn")

    def _open_rename(self, obj: DirObject) -> None:
        if obj.kind == ObjectKind.OTHER and not obj.parent_dn:
            self.notify("域根不能重命名。", "warn")
            return
        self.rename_panel.load(obj)
        self._show_panel(self.rename_panel)

    def _submit_rename(self) -> None:
        dn, kind, sync_sam = self.rename_panel.values()
        name = self.rename_panel.name.text().strip()
        if not name:
            self.notify("请填写新的名称。", "warn")
            return
        self.tasks.submit(
            "重命名", self.client.rename_object,
            lambda new_dn, _old=dn: self._on_renamed(name, _old, new_dn or ""),
            self._on_move_failed, dn, name, kind,
            # 账号名要带回去写审计，否则日志里「对谁做的」是空的
            self.rename_panel.account_name(), sync_sam)
        self._hide_panel()

    def _on_renamed(self, name: str, old_dn: str, new_dn: str) -> None:
        self.notify(f"已重命名为「{name}」。", "ok")
        # 只改树上这一个节点（子树 DN 前缀一并换血），展开状态全保留
        if new_dn:
            self.tree.rename_node(old_dn, new_dn, name)
        else:
            self.tree.reload_node(parent_of_dn(old_dn))
        self._reload_after_change()

    # ==================================================================
    # 属性（F05 / F06）
    # ==================================================================

    def _open_detail(self) -> None:
        rows = self.selected_rows()
        if len(rows) != 1:
            self.notify("查看属性需要且只能选中一个对象。", "warn")
            return
        self._open_property(rows[0])

    def _open_property(self, obj: DirObject) -> None:
        self.property_panel.load(obj, {})
        self._show_panel(self.property_panel)
        self._ensure_department_options()
        self._request_property_attrs(obj.dn)

    def _request_property_attrs(self, dn: str) -> None:
        """发起属性读取。

        ⚠️ 回调**只带 dn**，不带面板引用 —— 面板是共享单例，回调里读
        ``property_panel._obj``（「现在显示的是谁」）而不是「这次读的是谁」，
        用户在请求飞行中换了对象时，A 的属性就会被贴上 B 的名字，
        而「保存」按钮就在旁边：点下去就是把 A 写进 B。
        """
        self._property_dn = dn
        self.tasks.submit(
            "读取属性", self.client.read_attributes,
            lambda attrs, d=dn: self._on_property_attrs(d, attrs),
            lambda message, code, d=dn: self._on_property_read_failed(d, message),
            # ⚠️ `memberOf` **显式点名**要，不吃 `*` 的默认集合：它是**反向链接**
            #    （backlink）属性，靠 `*` 是否包含它属于服务端实现细节。不点名的话
            #    "域控没返回"与"这个人不属于任何组"在界面上长得一模一样 ——
            #    正是本项目最忌讳的「把取数失败当成证据成立」。
            dn, ["*", "memberOf"])

    def _property_is_current(self, dn: str) -> bool:
        """这个 DN 还是属性面板正在显示的对象吗（且面板没被换掉/关掉）。"""
        if self.panels.currentWidget() is not self.property_panel:
            return False            # 面板被换掉或关掉了 —— 结果无处可落
        if not dn or not self._property_dn:
            return True             # 拿不到 DN 就退化为「面板还开着」这一层
        return dn.casefold() == self._property_dn.casefold()

    def _on_property_attrs(self, dn: str, attrs: dict) -> None:
        if not self._property_is_current(dn):
            return                       # 用户已经切走 —— 结果作废，别落错对象
        # ⚠️ 归属对象要取**模型里这一 DN 的最新行**，不是 `property_panel._obj`
        #    —— 后者是打开面板那一刻的行快照，而 `_refresh_rows` →
        #    `update_rows` 是**替换**行对象，面板里存的这个再没人更新过。
        #    取它 ⇒ 保存后回读时面板显示的还是旧值（登录名/名称/启用状态）。
        #    列表里未必有这一行（例如从 OU 树点开的属性）⇒ 必须有兜底。
        obj = self.model.by_dn(dn) or self.property_panel._obj
        if obj is None:
            return
        attrs = attrs or {}
        self.property_panel.load(obj, attrs)
        # 用户：位图是二进制属性，必须走专用裸读（F13）
        if obj.kind == ObjectKind.USER:
            self.tasks.submit(
                "读取登录时间", self.client.get_logon_hours,
                lambda raw, d=dn: self.property_panel.fill_logon_hours(raw, d),
                lambda message, code, d=dn: self._on_hours_read_failed(d, message),
                obj.dn)
        # 组：顺带拉成员列表
        if obj.kind == ObjectKind.GROUP:
            self._load_group_members(obj.dn)
        # 「隶属于」（除联系人外都有这一页）：数据**就在这一次的属性读数里**
        # ⇒ 不再单独发一次请求。这不只是省一次往返：属性与它**同源同批**，
        # 天然不存在"结果贴错对象"那一类问题（见 `_request_property_attrs`
        # 的 docstring）；单独发请求就得多写一层归属对账。
        if obj.kind != ObjectKind.CONTACT:
            self.property_panel.fill_memberof(self._memberof_of(attrs), dn)

    @staticmethod
    def _memberof_of(attrs: dict | None) -> list[str] | None:
        """从属性读数里取 ``memberOf`` 的值列表。

        返回 ``None`` = 读数里**根本没有这个属性**（没读到），与 ``[]``（读到了、
        但这个人不属于任何组）**必须分开** —— 面板按这两种情形给不同的提示。
        取值走 `models.lookup_attr`（大小写不敏感，全项目唯一一份实现）。
        """
        data = attrs or {}
        if not any(str(key).casefold() == "memberof" for key in data):
            return None
        return [str(value) for value in lookup_attr(data, "memberOf") if value]

    def _on_property_read_failed(self, dn: str, message: str) -> None:
        if not self._property_is_current(dn):
            return
        self.property_panel._summary.setText(f"读取失败：{message}")
        # 属性整体读失败 ⇒ 「隶属于」也**没读到**（不是"不属于任何组"）。
        # 不补这一句，那张表会停在空表 + 建页时的提示上，读起来像"这人没组"。
        self.property_panel.fill_memberof(None, dn)

    def _on_hours_read_failed(self, dn: str, message: str) -> None:
        if not self._property_is_current(dn):
            return
        self.property_panel._hours_hint.setText(f"读取登录时间失败：{message}")

    def _load_group_members(self, group_dn: str) -> None:
        self.tasks.submit(
            "读取组成员", self.client.list_group_members,
            lambda members, d=group_dn: self.property_panel.fill_members(
                members or [], d),
            lambda message, code, d=group_dn: self._on_members_read_failed(
                d, message),
            group_dn)

    def _on_members_read_failed(self, group_dn: str, message: str) -> None:
        if not self._property_is_current(group_dn):
            return
        self.notify(f"读取组成员失败：{message}", "danger")

    def _on_member_search(self, keyword: str) -> None:
        if not keyword:
            return
        # 搜索结果属于**发起搜索时面板装载的那个组**，不是「点回来时是谁」
        group_dn = self.property_panel.loaded_dn()
        if not group_dn:
            return
        self.tasks.submit(
            "搜索可加入对象", self.client.list_objects,
            lambda rows, d=group_dn: self.property_panel.fill_member_search(
                rows or [], d),
            lambda message, code, d=group_dn: self.notify(
                f"搜索失败：{message}", "danger"),
            self.client.base_dn, None, "SUBTREE", keyword, 50)

    def _on_add_members(self, member_dns: list[str]) -> None:
        group = self.property_panel._obj
        if group is None or not member_dns:
            return
        self.tasks.submit(
            "加入组", self.client.add_to_group,
            lambda count, g=group: self._on_members_changed(
                f"已把 {count} 个对象加入「{g.title or g.sam}」。", g.dn),
            self._on_member_op_failed, member_dns, group.dn)

    def _on_remove_members(self, member_dns: list[str]) -> None:
        group = self.property_panel._obj
        if group is None or not member_dns:
            return
        self.tasks.submit(
            "移出成员", self.client.remove_from_group,
            lambda count, g=group: self._on_members_changed(
                f"已从「{g.title or g.sam}」移出 {count} 个成员。", g.dn),
            self._on_member_op_failed, member_dns, group.dn)

    def _on_remove_membership(self, group_dn: str) -> None:
        obj = self.property_panel._obj
        if obj is None or not group_dn:
            return
        self.tasks.submit(
            "移出组", self.client.remove_from_group,
            lambda _count: self._on_members_changed("已移出该组。", obj.dn),
            self._on_member_op_failed, [obj.dn], group_dn)

    def _on_members_changed(self, message: str, group_dn: str) -> None:
        self.notify(message, "ok")
        self._audit_log_note(message)
        # 只有面板**还停在这个对象**上时才刷新，否则等于把别的对象的表盖掉。
        # ⚠️ 这里传的是"**被改动的那一方**的 DN"：从组的成员页移出成员时是组，
        #    从「隶属于」页移出组时是**那个用户**（`_on_remove_membership` 传的
        #    就是 `obj.dn`）⇒ 两种都要刷到。
        self._refresh_property_if_showing([group_dn])

    def _refresh_property_if_showing(self, dns: list[str]) -> None:
        """这几个 DN 里只要有一个正被属性面板显示着 ⇒ **重读它**。

        重读走的是 `_request_property_attrs` 这条既有通路，它顺带把该类型的
        附属数据一起刷（组 ⇒ 成员表；其它 ⇒ 「隶属于」）—— 于是这里**不需要**
        按类型分叉，也就不存在第二份"什么类型刷什么表"的知识。

        🟥 不刷新的后果是"**提示说成功、表格纹丝不动**"：从「隶属于」页把一个组
        移出后，那一行还挂在表上，用户会以为没生效而再点一次 —— 而第二次点
        「移出选中组」，`memberOf` 里已经没有它了（后端会报"不在该组里"，
        或者更糟：按旧 DN 去操作一个已经改过的对象）。
        """
        current = self.property_panel.loaded_dn()
        if not current:
            return
        low = current.casefold()
        if any((dn or "").casefold() == low for dn in dns):
            self._request_property_attrs(current)

    def _on_member_op_failed(self, message: str, code: str) -> None:
        self.notify(message, "danger")

    def _audit_log_note(self, _message: str) -> None:
        """预留：成员操作结果已在后端写审计，这里只做界面反馈。"""

    def _submit_property_save(self) -> None:
        obj = self.property_panel._obj
        if obj is None:
            return
        collected = self.property_panel.collect()
        # 本地校验失败（如工作站名单非法）→ 不发起任何写入
        errors = collected.get("errors") or []
        if errors:
            for message in errors:
                self.notify(message, "warn")
            return
        changes = collected["changes"]
        if (not changes and collected["expiry"] is NOT_SET
                and collected["pwd_never"] is NOT_SET
                and collected["must_change"] is NOT_SET
                and collected.get("workstations", NOT_SET) is NOT_SET
                and collected.get("logon_hours", NOT_SET) is NOT_SET
                and collected.get("dialin", NOT_SET) is NOT_SET):
            self.notify("没有需要保存的改动。", "info")
            return

        dn, sam = obj.dn, obj.sam
        # 这次改动里有没有登录名（sAMAccountName）—— 失败时要靠它区分文案：
        # 改登录名被拒有确定的"该找谁"（账户操作员 / 域管理员），
        # 其它属性被拒只有一句通用的"权限不足"。
        renames_sam = any(c.attribute.casefold() == "samaccountname"
                          for c in changes)

        def job():
            # 串行执行：属性 → 账户过期 → UAC 位 → 下次登录改密 → F13/F14/F15
            if changes:
                self.client.modify_object(dn, changes, sam=sam)
            if collected["expiry"] is not NOT_SET:
                self.client.set_account_expiry(dn, collected["expiry"], sam=sam)
            if collected["pwd_never"] is not NOT_SET:
                self.client.set_uac_single_flag(
                    dn, UF_DONT_EXPIRE_PASSWORD, collected["pwd_never"], sam=sam)
            if collected["must_change"] is not NOT_SET:
                self.client.set_must_change_password(
                    dn, collected["must_change"], sam=sam)
            if collected.get("workstations", NOT_SET) is not NOT_SET:
                self.client.set_logon_workstations(
                    dn, collected["workstations"], sam=sam)
            if collected.get("logon_hours", NOT_SET) is not NOT_SET:
                self.client.set_logon_hours(
                    dn, collected["logon_hours"], sam=sam)
            if collected.get("dialin", NOT_SET) is not NOT_SET:
                dialin = collected["dialin"]
                self.client.set_dialin(dn, dialin["allow"],
                                       dialin["callback"], sam=sam)
            return collected

        self.property_panel.ok_button.setEnabled(False)
        self.tasks.submit(
            "保存属性", job,
            lambda _c: self._on_property_saved(dn),
            lambda message, code: self._on_property_save_failed(
                message, code, renames_sam=renames_sam))

    def _on_property_saved(self, dn: str) -> None:
        self.property_panel.ok_button.setEnabled(True)
        self.notify("属性已保存。", "ok")
        # 属性类修改：只回读这一个对象、就地刷行 —— 不重拉列表、不碰树
        self._refresh_rows([dn])
        # 重新装载属性，让面板显示落库后的真实值
        # ⚠️ 走同一个入口：保存期间用户可能已经切到别的对象，刷新结果同样要判归属
        if self._property_is_current(dn):
            self._request_property_attrs(dn)

    def _on_property_save_failed(self, message: str, code: str, *,
                                 renames_sam: bool = False) -> None:
        """保存失败。改登录名被权限拒时，补上**该找谁**。

        `insufficientAccessRights`（LDAP 结果码 50）在改 `sAMAccountName` 这个
        场景上有确定答案（账户操作员 / 域管理员），而通用文案只说到"授予委派
        权限" —— 使用者拿着它不知道该申请什么角色。判据与文案都在
        `utils.sam_write_denied_hint`（**唯一**实现），这里只负责在
        "这次改动里含登录名"时把它接上。
        """
        if renames_sam:
            hint = sam_write_denied_hint(code)
            if hint:
                message = f"{message}　——　{hint}"
        self.property_panel.ok_button.setEnabled(True)
        self.notify(message, "danger")

    # ==================================================================
    # 添加到组（F06）
    # ==================================================================

    def _open_add_to_group(self, dns: list[str]) -> None:
        if not dns:
            return
        self.add_to_group_panel.load(dns)
        self.add_to_group_panel.fill_groups([])
        self._show_panel(self.add_to_group_panel)
        self._on_group_search("")

    def _on_add_to_group_from_properties(self) -> None:
        """「隶属于」页的「添加到组…」：把**属性面板当前显示的对象**加入某个组。

        ⚠️ 归属取 `loaded_dn()`（点击那一刻面板装着谁），**不读 `_obj`** ——
        与异步回调那条「绑定发起时归属」并不冲突：点击是**同步**动作，
        "面板现在显示谁"就是"用户正在看谁"，两者在这一点上是同一件事。
        复用 `_open_add_to_group`（右键「添加到组…」走的就是它）⇒ 只有一份实现。
        """
        dn = self.property_panel.loaded_dn()
        if not dn:
            self.notify("属性面板里没有对象，无法加入组。", "warn")
            return
        self._open_add_to_group([dn])

    def _on_group_search(self, keyword: str) -> None:
        """异步搜组，结果喂给「添加到组」面板。

        ⚠️ 2026-09-16：原先这里是三层（本方法 → `_search_groups_into` →
        `tasks.submit`），抽出中间层是为了让**两个**调用方共用一份口径
        （「添加到组…」与「配置权限组」）。权限组清单随「共享盘权限」一起
        销掉后只剩一个调用方 ⇒ 收回来。留着它就是"只有一个人用的复用层"，
        下一个人会以为还有第二个调用方而不敢动。
        """
        self.tasks.submit(
            "搜索组", self.client.list_objects,
            lambda rows: self.add_to_group_panel.fill_groups(rows or []),
            lambda message, code: self.notify(f"搜索组失败：{message}", "danger"),
            self.client.base_dn, (ObjectKind.GROUP,), "SUBTREE", keyword, 100)

    def _submit_add_to_group(self) -> None:
        group_dn = self.add_to_group_panel.selected_group_dn()
        if not group_dn:
            self.notify("请先在列表中选中一个目标组。", "warn")
            return
        members = self.add_to_group_panel.member_dns()
        if not members:
            self.notify("没有要加入组的对象。", "warn")
            return
        self.tasks.submit(
            "加入组", self.client.add_to_group,
            lambda count: self._on_added_to_group(count, group_dn),
            self._on_member_op_failed, members, group_dn)
        self._hide_panel()

    def _on_added_to_group(self, count: int, group_dn: str) -> None:
        label = group_dn.split(",")[0].split("=", 1)[-1]
        self.notify(f"已把 {count} 个对象加入「{label}」。", "ok")
        # 成员关系不在列表任何一列上展示 —— 不刷列表、不碰树
        # （组成员面板打开时的刷新由 _on_member_added 负责）
        #
        # ⚠️ 「隶属于」页**不用在这里刷**：`_submit_add_to_group` 提交时就把面板
        #    换回了列表（`_hide_panel` → `setCurrentIndex(0)`），属性面板已不是
        #    当前页 ⇒ `_property_is_current` 会把结果丢掉（那是**对的**：
        #    用户看不见那张表）。他下次打开属性时会重新读，不会看到旧值。
        #    ⇒ 不要为了"顺手刷一下"把这里改成无条件重读：那会在面板已关闭时
        #      白发一次请求，还会让归属守卫看起来像摆设。

    # ==================================================================
    # 新建（用户 / 组 / OU / 计算机 / 联系人）
    # ==================================================================

    def _require_browse_context(self) -> bool:
        if not self._current_dn:
            self.notify("请先在左侧选择一个部门。", "warn")
            return False
        if self._search_active:
            self.notify("搜索状态下不能新建 —— 请先点左侧部门回到浏览模式。", "warn")
            return False
        return True

    def _open_create_user(self, template: DirObject | None = None) -> None:
        # 对齐 ADUC：从树里新建 → 位置=选中项；从导航栏新建 → 允许先开面板，
        # 创建位置在「组织单位」下拉里选（提交时强校验）。搜索态仍然拦截 ——
        # 搜索结果和浏览树不是一回事，此刻建号放哪都不对。
        if self._search_active:
            self.notify("搜索状态下不能新建 —— 请先点左侧部门回到浏览模式。", "warn")
            return
        self.create_user_panel.reset()
        self.create_user_panel.set_target(self._current_dn, self._current_title)
        self.create_user_panel.set_default_password(self._stored_default_password())
        self._show_panel(self.create_user_panel)
        self.create_user_panel.display_name.setFocus()
        self._ensure_upn_suffixes()
        self._ensure_department_options()
        #: 这次表单是拿谁当模板的（空串=不是模板建号）—— 模板属性回来时对账用
        self._template_dn = template.dn if template else ""
        if template:
            # 复制用户（模板建号）：异步读模板属性，岗位类字段填进表单
            self.tasks.submit(
                "读取模板属性", self.client.read_attributes,
                lambda attrs, d=template.dn: self._on_template_attrs(d, attrs or {}),
                lambda *_: None,
                template.dn)

    # ---------- 新建用户的「默认密码」 ----------

    def _stored_default_password(self) -> str:
        """读已保存的默认密码（DPAPI 密文解出来的明文）；没设过=空串。"""
        if self.settings is None:
            return ""
        return self.settings.default_password()

    def _edit_default_password(self) -> None:
        """右键「默认密码」按钮 → 设置 / 修改 / 清除。

        口令走 DPAPI 加密后写进配置文件（明文不落盘），
        与「记住连接密码」是同一条通道。
        """
        if self.settings is None:
            self.status_message.emit("当前模式不支持保存默认密码。")
            return

        dialog = DefaultPasswordDialog(self._stored_default_password(), self)
        result = dialog.exec()
        if result == 2:                                  # 「清除」
            new_value = ""
        elif result == QDialog.DialogCode.Accepted:
            new_value = dialog.password_value()
        else:
            return                                       # 取消：什么都不动

        try:
            self.settings.set_default_password(new_value)
        except AdToolError as exc:
            self.status_message.emit(str(exc))
            return
        self.create_user_panel.set_default_password(new_value)
        self.status_message.emit(
            "默认密码已清除。" if not new_value else
            "默认密码已保存（本机加密存储，明文不落盘）。")

    # ------------------------------------------------------------ 组策略（只读）
    #
    # ⚠️ 这一档**只读**：面板上没有新建 / 链接 / 删除 / 改设置的入口。
    #    写 GPO 是需求文档第 5、6 项的事 —— 混进来会让"随手点一下"的代价
    #    从「查一下」变成「不可逆地改了域策略」。

    def _gpo_ready(self) -> bool:
        if not self.client or not self.client.connected:
            self.notify("尚未连接域控，无法读取组策略。", "warn")
            return False
        return True

    def _open_gpo_panel(self) -> None:
        """打开组策略面板并载入列表。

        🔴 **引擎（RSAT）缺失不再挡住整个面板**（2026-09-17 改）。

        原来这里在没装 RSAT 时 `return`：面板根本不出现。可「列 GPO」和
        「看改过哪些设置」现在都**不依赖 GPMC**（前者走 LDAP，后者自己解
        `Registry.pol`）—— 拦在门口等于把这条功能线**本该服务**的那些机器
        排除在外：拿不到列表就选中不了任何一条。
        现在改成：面板照开、列表照列，只有**真需要 GPMC 的那两个按钮**
        置灰（「看链接位置」/「看设置摘要」，见 `set_engine_available`）。
        """
        if not self._gpo_ready():
            return
        self._show_panel(self.gpo_panel)

        ok, note = gpo_engine_available()
        # ⚠️ 引擎缺失 = **部署前置条件**不满足，不是网络问题。
        #    说明必须指向"装 RSAT"，否则会把使用者引去查 VPN —— 方向完全相反。
        self.gpo_panel.set_engine_available(ok, note)
        if not ok:
            self.notify("这台机器没装 RSAT「组策略管理工具」：列表与「看改过哪些"
                        "设置」照常可用，「看链接位置 / 看设置摘要」不可用。",
                        "warn")
        self._submit_gpo_refresh()

    def _gpmc_ready(self) -> bool:
        """GPMC 那两个入口的前置检查（**与 `_gpo_ready` 分开**）。

        ⚠️ 别把它并进 `_gpo_ready`：那只查连接，是**所有** GPO 入口的公共
        前置；而引擎只有**其中两个**入口需要。并在一起会让不加区分的调用方
        （比如「看改过哪些设置」）也莫名其妙被 RSAT 挡住 ——
        而它恰恰是"不依赖 RSAT"那条路。
        """
        ok, note = gpo_engine_available()
        if not ok:
            self.gpo_panel.show_error(note)
            self.notify("这一步要 GPMC 引擎：这台机器没装 RSAT"
                        "「组策略管理工具」。", "warn")
            return False
        return True

    def _submit_gpo_refresh(self) -> None:
        if not self._gpo_ready():
            return
        rid = self.gpo_panel.begin()
        self.gpo_panel.set_busy(True, "正在读取组策略列表……")
        self.tasks.submit(
            "读取组策略列表", list_gpos,
            lambda result, _r=rid: self._on_gpo_list(result, _r),
            lambda message, code, _r=rid: self._on_gpo_failed(message, _r),
            # ⚠️ client 必须显式传 —— 它是模块级函数，漏传不会报"缺参数"。
            self.client)

    def _submit_gpo_search(self, text: str) -> None:
        if not self._gpo_ready():
            return
        rid = self.gpo_panel.begin()
        self.gpo_panel.set_busy(True, "正在搜索组策略……")
        self.tasks.submit(
            "搜索组策略", search_gpos,
            lambda result, _r=rid: self._on_gpo_list(result, _r),
            lambda message, code, _r=rid: self._on_gpo_failed(message, _r),
            self.client, text)

    def _submit_gpo_links(self, guid: str) -> None:
        if not self._gpo_ready() or not guid:
            return
        # ⚠️ 这一条**要 GPMC**（链接只长在 SOM 一侧，LDAP 那条路目前不查它）。
        if not self._gpmc_ready():
            return
        label = self.gpo_panel.selected_label()
        rid = self.gpo_panel.begin()
        # 记下"这次请求问的是谁" —— 回调时要拿它跟"现在选中的是谁"对账。
        self._gpo_request = (rid, guid)
        self.gpo_panel.set_busy(True, "正在查这条 GPO 链在哪些位置……")
        self.tasks.submit(
            "查询组策略链接位置", gpo_linked_soms,
            lambda soms, _r=rid, _g=guid, _l=label:
                self._on_gpo_links(soms, _r, _g, _l),
            lambda message, code, _r=rid: self._on_gpo_failed(message, _r),
            self.client, guid)

    def _submit_gpo_report(self, guid: str) -> None:
        if not self._gpo_ready() or not guid:
            return
        # ⚠️ 摘要**由 GPMC 生成**（它自己解 `registry.pol`）⇒ 这一条要引擎。
        #    我们那条自包含的读法不是它的替代品：它出的是**报告**，
        #    自包含那条出的是"改过哪些设置"的清单（另一个按钮）。
        if not self._gpmc_ready():
            return
        label = self.gpo_panel.selected_label()
        fmt = "html"
        rid = self.gpo_panel.begin()
        self._gpo_request = (rid, guid)
        self.gpo_panel.set_busy(
            True, "正在生成设置摘要……（GPMC 要读域控的 SYSVOL，比列列表慢）")
        self.tasks.submit(
            "生成组策略设置摘要", gpo_report,
            lambda text, _r=rid, _g=guid, _l=label, _f=fmt:
                self._on_gpo_report(text, _r, _g, _l, _f),
            lambda message, code, _r=rid: self._on_gpo_failed(message, _r),
            self.client, guid, fmt)

    def _submit_gpo_settings(self, guid: str) -> None:
        """读这个 GPO **改过哪些设置**（只读）。

        ⚠️ 「读设置」这一步本身**不需要 RSAT/GPMC** —— 走的是我们自己的
        `Registry.pol` 解析（`gpo_settings.py`），比 `gpo_report` 少一个 COM 依赖。

        ⚠️ 这一段**曾经**是这条路上最大的缺口（2026-09-17 两头都补上了，
        保留来历）：那时 `_open_gpo_panel()` 在没装 GPMC 引擎时会直接 return
        （面板都不出现），而"列出 GPO"这一步只能走 GPMC ⇒ 本入口虽然自己不需要
        RSAT，在**没装 RSAT 的机器上照样够不到** —— 拿不到列表就选中不了任何
        一条，于是它存在的理由在它本该服务的那些机器上**兑现不了**。
        现在：列 GPO 走 LDAP（`gpo_ldap.py`，搜 `CN=Policies,CN=System,…`）、
        面板也不再被引擎挡在门外（见 `_open_gpo_panel`）⇒ 本入口在没装 RSAT 的
        机器上**整段可用**。仍要求 RSAT 的只剩「看链接位置」与「看设置摘要」。
        """
        if not self._gpo_ready() or not guid:
            return
        label = self.gpo_panel.selected_label()
        rid = self.gpo_panel.begin()
        self._gpo_request = (rid, guid)
        self.gpo_panel.set_busy(
            True, "正在读这个 GPO 改过哪些设置……（要读域控的 SYSVOL，比列列表慢）")
        self.tasks.submit(
            "读取组策略已改设置", gpo_settings,
            lambda result, _r=rid, _g=guid, _l=label:
                self._on_gpo_settings(result, _r, _g, _l),
            lambda message, code, _r=rid: self._on_gpo_failed(message, _r),
            # ⚠️ client 必须显式传 —— 与其余 worker 调用点同规。
            self.client, guid, label)

    def _submit_gpo_security(self, guid: str, extension_names: object) -> None:
        """读这个 GPO 的**安全策略**（`GptTmpl.inf`：密码 / 锁定 / 审核 / 权限）。只读。

        ⚠️ 与「读设置」同一条自包含路线：**不需要 RSAT/GPMC** —— 自己按协议算
        SYSVOL 路径 ＋ 自己解 INF 字节（`gpo_security.py`）。

        🔴 ``extension_names`` 是那条 `gPCMachineExtensionNames` 属性的原文，
        由面板在**发起时**从选中行取快照（`selected_extension_names()`），
        这里原样往下传 —— **不许**在回调里再去问面板"现在选中的是谁"。
        它的取值有**三态**，`None`（没拿到属性）与 `""`（拿到了、对象上没登记）
        必须一路保持可区分，所以这里**不做任何 `or ""` 之类的兜底**：
        那种兜底会把"说不清"悄悄变成"不会被应用"，而那正是使用者最会当真的
        一句话（见 `gpo_security.cse_verdict`）。
        """
        if not self._gpo_ready() or not guid:
            return
        label = self.gpo_panel.selected_label()
        rid = self.gpo_panel.begin()
        self._gpo_request = (rid, guid)
        self.gpo_panel.set_busy(
            True, "正在读这个 GPO 的安全策略……（要读域控的 SYSVOL，比列列表慢）")
        self.tasks.submit(
            "读取组策略安全策略", gpo_security,
            lambda result, _r=rid, _g=guid, _l=label:
                self._on_gpo_security(result, _r, _g, _l),
            lambda message, code, _r=rid: self._on_gpo_failed(message, _r),
            # ⚠️ client 必须显式传 —— 与其余 worker 调用点同规。
            self.client, guid, label, extension_names)

    def _gpo_result_is_current(self, rid: int, guid: str) -> bool:
        """结果是不是还属于**现在选中的那条** GPO。

        ⚠️ 只看请求号不够。面板是共享单例，使用者可以在结果回来之前换选中项
        而**不发起新请求** —— 那时请求号没变，但结果已经不属于当前选中项了。
        这正是「A 的链接位置显示在 B 名下」的产生方式，所以在三个地方对账：
        请求号仍然是当前号（`is_current`）、记录的是这次请求（`stored_rid`）、
        记录的 GUID 就是这次的、且**现在选中的恰好还是它**。
        """
        stored_rid, stored_guid = self._gpo_request
        if not self.gpo_panel.is_current(rid) or stored_rid != rid:
            return False
        if stored_guid != guid:
            return False
        return self.gpo_panel.selected_guid() == guid

    def _on_gpo_list(self, result, rid: int) -> None:
        if not self.gpo_panel.is_current(rid):
            return
        self.gpo_panel.set_busy(False)
        self.gpo_panel.show_gpos(result)
        count = getattr(result, "count", 0)
        if count:
            self.notify("读到 %d 条组策略。" % count, "ok")
        else:
            self.notify("这个域里没有组策略对象。", "info")

    def _on_gpo_links(self, soms, rid: int, guid: str, label: str) -> None:
        if not self._gpo_result_is_current(rid, guid):
            return
        self.gpo_panel.set_busy(False)
        self.gpo_panel.show_links(soms, label)

    def _on_gpo_report(self, text, rid: int, guid: str, label: str,
                       fmt: str) -> None:
        if not self._gpo_result_is_current(rid, guid):
            return
        self.gpo_panel.set_busy(False)
        self.gpo_panel.show_report(text, label, fmt)

    def _on_gpo_settings(self, result, rid: int, guid: str, label: str) -> None:
        if not self._gpo_result_is_current(rid, guid):
            return
        self.gpo_panel.set_busy(False)
        self.gpo_panel.show_settings(result)
        count = getattr(result, "count", 0)
        if count:
            self.notify("「%s」改过 %d 项设置。" % (label or "这条组策略", count), "ok")
        else:
            # ⚠️ 0 条**不是**失败，但也**不能**直接说"没改过" ——
            #    那要 `is_conclusive` 成立（真读到了文件才算）。
            settings = getattr(result, "settings", None)
            if settings is not None and getattr(settings, "is_conclusive", False):
                self.notify("「%s」没有改过任何设置。" % (label or "这条组策略"), "info")
            else:
                self.notify("这次一个文件都没读到，说不了「没改过设置」。", "warn")

    def _on_gpo_security(self, result, rid: int, guid: str, label: str) -> None:
        if not self._gpo_result_is_current(rid, guid):
            return
        self.gpo_panel.set_busy(False)
        self.gpo_panel.show_security(result)
        name = label or "这条组策略"
        security = getattr(result, "security", None)
        if security is None:
            self.notify("没有拿到「%s」的安全策略。" % name, "warn")
            return
        count = getattr(result, "count", 0)
        if count:
            self.notify("「%s」的安全策略：%d 项。" % (name, count), "ok")
        elif getattr(security, "is_conclusive", False):
            # ⚠️ 0 项在这里**只可能**是"这条 GPO 没配安全策略"（文件不存在）——
            #    真有一份合法模板的话，第一段必然是 `[Unicode]` 且必然有内容。
            self.notify("「%s」没有配安全策略。" % name, "info")
        else:
            self.notify("这次没读到安全策略文件，说不了「没有配」。", "warn")
        # 🔑 这一句**别处拿不到**：文件在、版本号也涨了，但 GPC 没登记安全扩展
        #    ⇒ 策略被完全忽略，而 GPMC 界面上没有任何线索（KB885009）。
        #    ⚠️ 只在**读到过模板**时才说（`cse_is_relevant`）—— 没有模板却喊一句
        #    "不会被应用"，会让人去找一份根本不存在的策略。
        if (getattr(security, "cse_is_relevant", False)
                and getattr(security, "cse", "") == "absent"):
            self.notify(
                "⚠️「%s」的安全策略不会被应用：GPC 里没有登记安全扩展。" % name,
                "warn")

    def _on_gpo_failed(self, message: str, rid: int) -> None:
        if not self.gpo_panel.is_current(rid):
            return
        self.gpo_panel.set_busy(False)
        self.gpo_panel.show_error(message)
        self.notify("组策略：%s" % message, "danger")

    def _ensure_department_options(self) -> None:
        """部门下拉候选 = 目录里实际存在的 OU 名（每连接读一次）。

        部门是自由文本属性，但让人凭空手打必然和 OU 结构脱节 ——
        给候选，同时保留手输能力（有些部门没有对应 OU）。
        """
        if self._department_options_loaded:
            return
        self._department_options_loaded = True
        self.tasks.submit(
            "读取部门清单", self.client.list_objects,
            self._on_department_options, lambda *_: None,
            self.client.base_dn, (ObjectKind.OU,), "SUBTREE", "", 500)

    def _on_department_options(self, rows: list[DirObject]) -> None:
        rows = list(rows or [])
        # 域根也是合法的创建位置（ADUC 同款）—— 候选里没有它的话，
        # 树选「域根」新建时下拉会是空的，副标题只能退回旧格式。
        base = (self.client.base_dn or "").casefold() if self.client else ""
        if base and not any((r.dn or "").casefold() == base for r in rows):
            rows.insert(0, SimpleNamespace(dn=self.client.base_dn,
                                           cn="整个域（域根）"))
        # 新建面板：组织单位选择器（userData = DN，支持多级/同名 OU）
        self.create_user_panel.set_ou_options(rows)
        # 属性面板：department 是自由文本属性，候选给 OU 名就够
        names = sorted({r.cn for r in rows if r.cn})
        self.property_panel.set_department_options(names)

    def _ensure_upn_suffixes(self) -> None:
        """UPN 后缀清单读一次缓存 —— 后端已容错，失败就留着占位提示。"""
        if self._upn_suffixes_loaded:
            return
        self._upn_suffixes_loaded = True
        self.tasks.submit(
            "读取 UPN 后缀", self.client.list_upn_suffixes,
            self.create_user_panel.set_upn_suffixes,
            lambda *_: None)

    def _on_template_attrs(self, dn: str, attrs: dict) -> None:
        """模板属性能填，**只能**填在「还是这一次打开的表单」上。

        否则：右键 T1「复制用户」→ 还没读回来就从导航栏点「新建用户」
        （`reset()` 已经把表单清空）→ T1 的姓名/部门自己冒进空白表单，
        提交下去就是拿别人的资料建号。
        """
        if not dn or (self._template_dn or "").casefold() != dn.casefold():
            return                      # 表单已经换成别的模板／或不是模板建号
        self._fill_create_template(attrs)

    def _fill_create_template(self, attrs: dict) -> None:
        panel = self.create_user_panel
        if not panel.isVisible():
            return                      # 使用者已经关掉了面板，别硬填
        panel.apply_template(attrs)

    def _open_create_ou(self) -> None:
        parent = self._current_dn or (self.client.base_dn if self.client else "")
        if not parent:
            self.notify("请先选择上级部门。", "warn")
            return
        self.create_ou_panel.reset()
        self.create_ou_panel.set_target(parent, self._current_title or "域根")
        self._show_panel(self.create_ou_panel)
        self.create_ou_panel.name.setFocus()

    def _open_create_group(self) -> None:
        if not self._require_browse_context():
            return
        self.create_group_panel.reset()
        self.create_group_panel.set_target(self._current_dn, self._current_title)
        self._show_panel(self.create_group_panel)
        self.create_group_panel.name.setFocus()

    def _open_create_computer(self) -> None:
        if not self._require_browse_context():
            return
        self.create_computer_panel.reset()
        self.create_computer_panel.set_target(self._current_dn, self._current_title)
        self._show_panel(self.create_computer_panel)
        self.create_computer_panel.name.setFocus()

    def _open_create_contact(self) -> None:
        if not self._require_browse_context():
            return
        self.create_contact_panel.reset()
        self.create_contact_panel.set_target(self._current_dn, self._current_title)
        self._show_panel(self.create_contact_panel)
        self.create_contact_panel.name.setFocus()

    def _check_sam(self, sam: str) -> None:
        """登录名可用性检查。

        ⚠️ 结果要带 ``sam`` 回到面板对账 —— 边打边查时，前一个前缀的结论
        会追上来盖住当前名字的状态（看到「可用」就提交，撞名了还莫名其妙）。
        """
        self.tasks.submit(
            "检查登录名", self.client.sam_exists,
            lambda exists, name=sam: self.create_user_panel.set_sam_status_for(
                name, "已占用" if exists else "可用", "danger" if exists else "ok"),
            lambda message, code, name=sam:
                self.create_user_panel.set_sam_status_for(name, "检查失败", "warn"),
            sam)

    def _check_property_sam(self, sam: str) -> None:
        """属性面板里改登录名时的占用检查。

        与 `_check_sam`（新建用户）同一条纪律：**结果要带 ``sam`` 回到面板对账**
        —— 边打边查时，前一个名字的结论会追上来盖住当前名字的状态（看到
        「可用」就保存，撞名了也不知道为什么）。
        """
        self.tasks.submit(
            "检查登录名", self.client.sam_exists,
            lambda exists, name=sam: self.property_panel.set_sam_result_for(
                name, bool(exists)),
            lambda message, code, name=sam:
                self.property_panel.set_sam_check_failed_for(name),
            sam)

    def _submit_create_user(self) -> None:
        spec = self.create_user_panel.spec()
        try:
            spec.validate()
        except AdToolError as exc:
            self.notify(exc.message, "warn")
            return

        from utils import check_password_guessability

        reason = check_password_guessability(spec.init_password, spec.sam,
                                             spec.display_name)
        if reason:
            self.notify("本地预检未通过：" + reason, "warn")
            return

        parent = (self.create_user_panel.selected_ou_dn()
                  or self._current_dn)
        if not parent:
            self.notify("请选择组织单位 —— 用户将创建到该单位下。", "warn")
            return
        self.create_user_panel.ok_button.setEnabled(False)
        self.tasks.submit(
            "新建用户", self.client.create_user,
            self._on_created_user,
            self._on_create_failed, parent, spec)

    def _on_created_user(self, dn: str) -> None:
        self.create_user_panel.ok_button.setEnabled(True)
        self.create_user_panel.reset()
        self.notify(f"已创建：{dn}", "ok")
        # 新建用户不碰 OU 树（树上没有用户节点）—— 之前这里整树重载，
        # 纯属冤枉刷新，展开状态全丢。
        #
        # ⚠️ **2026-09-17 修正**：上一版在这里**手搓**了一次
        #    `self._load_objects(self._current_dn or parent_dn, self._current_title)`，
        #    与另外四条建号收尾（OU / 组 / 计算机 / 联系人，都走
        #    `_reload_after_change`）不一致。手搓那版丢了两件事：
        #      ① 漏传 `subtree` —— 走 `subtree=None` 自动判断。**今天恰好等价**
        #         （`_subtree` 只会被 `_load_objects` 自己写），但只要以后有地方让
        #         **非域根**容器 `subtree=True`，这一条就会把它静默丢掉；
        #      ② 🔴 **丢掉"搜索视图"那一支** —— `_load_objects` 一进门就把
        #         `self._search_active` 置回 `False`，而且**不会重新发起搜索**。
        #         于是下面这一帧会真实发生：建号请求还在飞 → 使用者在搜索框里敲了词、
        #         视图切到全目录搜索结果 → 建号回调到货 ⇒ **眼前的搜索结果被换成容器列表**。
        #    （参数 `parent_dn` 随之成了死参数，一并删掉；建号目标仍由
        #      `_submit_create_user` 交给 `create_user` 的第一个实参决定。）
        #    判据（**必须写成一块不可拆的**）：`tests/test_ui_smoke.py::TestCreateFlow.test_create_user_finish_keeps_the_search_view_alive`
        #    ⚠️ 2026-09-17 实测：这条引用**折成两行**时，悬空引用判据会把它拼成
        #       `TestCreateFlow.`（带尾点、方法名掉到下一行）⇒ 报「没有这个 def/class」，
        #       全量套件当场多出一个红。引用一个三层的名字就写成一整行。
        self._reload_after_change()
        # ⚠️ 2026-09-16：「建号 → 自动挂共享盘权限组」那后半段随「共享盘权限」
        #    一起销掉了，本回调现在是**纯建号**。要给人加组请用右键「添加到组…」。
        self._sync_after_change("新建用户")

    def _on_create_failed(self, message: str, code: str) -> None:
        for panel in (self.create_user_panel, self.create_ou_panel,
                      self.create_group_panel, self.create_computer_panel,
                      self.create_contact_panel):
            panel.ok_button.setEnabled(True)
        self.notify(message, "danger")

    def _submit_create_ou(self) -> None:
        name, description = self.create_ou_panel.values()
        if not name:
            self.notify("请填写组织单位名称。", "warn")
            return
        parent = self._current_dn or self.client.base_dn
        self.tasks.submit(
            "新建组织单位", self.client.create_ou,
            lambda dn, _p=parent: self._on_created_ou(dn, _p),
            self._on_create_failed, parent, name, description)

    def _on_created_ou(self, dn: str, parent_dn: str) -> None:
        self.create_ou_panel.reset()
        self._hide_panel()
        self.notify(f"已创建组织单位：{dn}", "ok")
        # 新 OU 必须出现在「组织单位」下拉里 —— 上一版缓存不失效，
        # 导致新建的三级组织单位选不到（截图/实测抓出来的）。
        self._department_options_loaded = False
        # 只往父节点下插这一个节点 —— 不再整树 invalidate 抹掉展开状态
        name = dn.split(",")[0].split("=", 1)[-1]
        self.tree.insert_child(parent_dn, name, dn)
        # ⚠️ 新 OU 也推一次。**不是为了文件服务器搜索**（OU **不进 GC**，
        #    部分属性集里没有它）—— 是为了「别的域控/别的站点现在就能看到这个 OU」：
        #    紧接着挂 GPO 链接、或者在别的 DC 上往这个 OU 里建对象，都要它先复制到位。
        self._sync_after_change("新建组织单位")

    def _submit_create_group(self) -> None:
        values = self.create_group_panel.values()
        if not values["name"]:
            self.notify("请填写组名。", "warn")
            return
        self.tasks.submit(
            "新建组", self.client.create_group,
            lambda dn: self._on_created_generic(
                f"已创建组：{values['name']}", dn, "新建组"),
            self._on_create_failed, self._current_dn,
            values["name"], values["scope"], values["category"],
            values["description"])

    def _submit_create_computer(self) -> None:
        name, description = self.create_computer_panel.values()
        if not name:
            self.notify("请填写计算机名。", "warn")
            return
        self.tasks.submit(
            "新建计算机账号", self.client.create_computer,
            lambda dn: self._on_created_generic(f"已预创建计算机「{name}」，"
                                                "机器加域时将使用该账号。", dn,
                                                "新建计算机"),
            self._on_create_failed, self._current_dn, name, description)

    def _submit_create_contact(self) -> None:
        name, mail, description = self.create_contact_panel.values()
        if not name:
            self.notify("请填写联系人名称。", "warn")
            return
        self.tasks.submit(
            "新建联系人", self.client.create_contact,
            lambda dn: self._on_created_generic(
                f"已创建联系人「{name}」。", dn, "新建联系人"),
            self._on_create_failed, self._current_dn, name, mail, description)

    def _on_created_generic(self, message: str, dn: str, label: str) -> None:
        """新建 组 / 计算机 / 联系人 的共用收尾。

        ⚠️ `label` 是给「强制复制同步」用的**动作名**（`"新建组"` / `"新建计算机"` /
           `"新建联系人"`），**不是**提示文案 —— 两者混用会拼出
           「已创建组：xxx已成功，但强制复制同步出错：…」这种拧在一起的句子
           （`_sync_after_change` 会写 `f"{what}已成功，但…"`）。
           **提示文案里带名字、动作名不带**，这是两件事，所以是两个参数。
        """
        self.notify(message, "ok")
        self._hide_panel()
        self._reload_after_change()
        # 与 `_on_created_user` 同样的理由：**放在最后** —— 上面 `_reload_after_change()`
        # 走的是同一台域控的 LDAP，**不受复制影响**，没必要让它排在几十秒的复制后面等。
        self._sync_after_change(label)

    # ==================================================================
    # 右键菜单（F02）
    # ==================================================================

    def _on_table_context_menu(self, pos) -> None:
        index = self.table.indexAt(pos)
        menu = QMenu(self)

        # 🔒 右键必须**先落到鼠标下的那一行**（ADUC 行为）：
        #   菜单里的动作全部基于 `selected_rows()`，而右键本身不改选中 ——
        #   不补这一步，用户右击 A 行、动作却打在先前选中的 B 行上：
        #   提示「成功」，目标行纹丝不动（2026-09-12 实测反馈：
        #   「解锁后已禁用标志消失 / 再禁用标志不回来」都是打在别的行上）。
        #   点已选中的行 → 保留整片多选（批量动作要靠它）。
        if index.isValid():
            selection = self.table.selectionModel()
            if selection is not None:
                if not selection.isRowSelected(index.row()):
                    selection.select(
                        index,
                        QItemSelectionModel.SelectionFlag.ClearAndSelect
                        | QItemSelectionModel.SelectionFlag.Rows)
                # 只移动「当前项」光标，**不碰选中** —— 用 setCurrentIndex()
                # 会按 ClearAndSelect 语义把整片多选缩成一个（实测）。
                selection.setCurrentIndex(
                    index, QItemSelectionModel.SelectionFlag.NoUpdate)
            else:
                self.table.setCurrentIndex(index)

        if not index.isValid() or not self.selected_rows():
            # 空白处：ADUC 的「新建」菜单
            menu.addAction("刷新", self.refresh)
            menu.addSeparator()
            menu.addAction("新建用户", lambda: self._open_create_user())
            menu.addAction("新建组", self._open_create_group)
            menu.addAction("新建计算机", self._open_create_computer)
            menu.addAction("新建联系人", self._open_create_contact)
            menu.addAction("新建组织单位", self._open_create_ou)
            menu.addSeparator()
            # 组策略是**域级**功能（链接挂在域 / 站点 / OU 上，不属于任何单个
            # 对象）⇒ 放在"空白处"这个菜单里，而不是某个对象的右键菜单里。
            menu.addAction("组策略…", self._open_gpo_panel)
            menu.exec(self.table.viewport().mapToGlobal(pos))
            return

        rows = self.selected_rows()
        single = rows[0] if len(rows) == 1 else None

        # ---- 多选：只出批量动作 ----
        if single is None:
            if any(o.has_account and o.is_dc is False for o in rows):
                menu.addAction("重置密码", self._ask_reset_password)
                menu.addAction("启用", lambda: self._ask_set_enabled(True))
                menu.addAction("禁用", lambda: self._ask_set_enabled(False))
                menu.addAction("解锁", self._ask_unlock)
                menu.addSeparator()
            menu.addAction("添加到组…", lambda: self._open_add_to_group(
                [o.dn for o in rows]))
            menu.addAction("移动到…", lambda: self._open_move(None))
            delete_action = menu.addAction("删除", lambda: self._ask_delete(None))
            delete_action.setProperty("danger", True)
            menu.exec(self.table.viewport().mapToGlobal(pos))
            return

        obj = single

        # ---- 单选：按类型出菜单（ADUC 心智模型） ----
        menu.addAction("属性", lambda: self._open_property(obj))
        menu.addSeparator()

        if obj.kind == ObjectKind.USER:
            menu.addAction("重置密码",
                           lambda: self._ask_reset_password_for([obj]))
            menu.addAction("复制用户…",
                           lambda: self._open_create_user(template=obj))
            if obj.locked:
                menu.addAction("解锁",
                               lambda: self._ask_unlock_for([obj]))
            # ⚠️ 第 2 个实参是**目标状态**（`_ask_set_enabled` 里
            #    `verb = "启用" if enabled else "禁用"`），**不是**当前状态。
            #    传 `obj.enabled` 会让菜单文字与动作**正好相反** ——
            #    已启用的账号写「禁用」、点下去执行的是「启用」（2026-09-15 修）。
            if obj.enabled is None:
                # 🔴 读不到当前状态 ⇒ **不提供**这两个动作。菜单文字该说"禁用"
                #    还是"启用"？说哪个都可能是反的，而点下去真的会写 AD。
                #    取舍与写入侧 `_uac_of_now` 一致（它读不到会**中止**）：
                #    少给一个入口是看得见的，写反是看不见的。
                menu.addAction("（读不到账号状态，无法启用 / 禁用）",
                               lambda: None).setEnabled(False)
            else:
                # ⚠️ 第 2 个实参是**目标状态**（`_ask_set_enabled` 里
                #    `verb = "启用" if enabled else "禁用"`），**不是**当前状态。
                #    传 `obj.enabled` 会让菜单文字与动作**正好相反** ——
                #    已启用的账号写「禁用」、点下去执行的是「启用」（2026-09-15 修）。
                menu.addAction("禁用" if obj.enabled else "启用",
                               lambda: self._ask_set_enabled_for(
                                   [obj], not obj.enabled))
            menu.addAction("添加到组…",
                           lambda: self._open_add_to_group([obj.dn]))
        elif obj.kind == ObjectKind.COMPUTER:
            if obj.is_dc is True:
                menu.addAction("（域控制器 —— 不允许在此禁用 / 重置 / 删除）",
                               lambda: None).setEnabled(False)
            elif obj.is_dc is None:
                # 读不到 UAC ⇒ **不知道它是不是域控**。旧行为会当成普通电脑，
                # 把「禁用 / 重置计算机账户 / 删除」全给出来 —— 而这三件事
                # 对域控本应被拦掉。宁可少给，不可给错。
                menu.addAction("（读不到账号控制属性，无法确认它是不是域控制器"
                               " —— 危险操作已停用）",
                               lambda: None).setEnabled(False)
            else:
                # 同用户那一处：传的必须是**目标状态**（`not obj.enabled`）。
                menu.addAction("禁用" if obj.enabled else "启用",
                               lambda: self._ask_set_enabled_for(
                                   [obj], not obj.enabled))
                menu.addAction("重置计算机账户…",
                               lambda: self._ask_reset_computer(obj))
                menu.addAction("添加到组…",
                               lambda: self._open_add_to_group([obj.dn]))
        elif obj.kind == ObjectKind.GROUP:
            menu.addAction("查看成员",
                           lambda: self._open_property(obj))
            menu.addAction("添加成员…",
                           lambda: self._open_property(obj))

        menu.addSeparator()
        menu.addAction("重命名", lambda: self._open_rename(obj))
        menu.addAction("移动到…", lambda: self._open_move([obj]))
        delete_action = menu.addAction("删除", lambda: self._ask_delete([obj]))
        delete_action.setProperty("danger", True)
        menu.addSeparator()
        menu.addAction("复制 DN", lambda: self._copy_dn(obj))
        menu.exec(self.table.viewport().mapToGlobal(pos))

    def _on_tree_context_menu(self, dn: str, title: str, global_pos) -> None:
        menu = QMenu(self)
        is_root = bool(self.client and dn == self.client.base_dn)

        menu.addAction("刷新", self.refresh)
        menu.addSeparator()
        menu.addAction("新建用户",
                       lambda: self._create_in(dn, title, self._open_create_user))
        menu.addAction("新建组",
                       lambda: self._create_in(dn, title, self._open_create_group))
        menu.addAction("新建计算机",
                       lambda: self._create_in(dn, title, self._open_create_computer))
        menu.addAction("新建联系人",
                       lambda: self._create_in(dn, title, self._open_create_contact))
        menu.addAction("新建组织单位",
                       lambda: self._create_in(dn, title, self._open_create_ou))

        if not is_root:
            menu.addSeparator()
            menu.addAction("重命名",
                           lambda: self._open_rename(DirObject(
                               kind=ObjectKind.OU, cn=title, dn=dn)))
            menu.addAction("移动到…",
                           lambda: self._open_move([DirObject(
                               kind=ObjectKind.OU, cn=title, dn=dn)]))
            delete_action = menu.addAction(
                "删除", lambda: self._ask_delete([DirObject(
                    kind=ObjectKind.OU, cn=title, dn=dn)]))
            delete_action.setProperty("danger", True)
        menu.exec(global_pos)

    def _create_in(self, dn: str, title: str, opener) -> None:
        """先切到目标容器再打开新建面板（树右键新建的入口）。"""
        self._load_objects(dn, title)
        opener()

    def _ask_reset_password_for(self, objs: list[DirObject]) -> None:
        self._select_only(objs)
        self._ask_reset_password()

    def _ask_unlock_for(self, objs: list[DirObject]) -> None:
        self._select_only(objs)
        self._ask_unlock()

    def _ask_set_enabled_for(self, objs: list[DirObject], enabled: bool) -> None:
        self._select_only(objs)
        self._ask_set_enabled(enabled)

    def _select_only(self, objs: list[DirObject]) -> None:
        """把表格选中集合成给定对象（右键动作复用批量路径的前提）。"""
        selection_model = self.table.selectionModel()
        from PyQt6.QtCore import QItemSelection

        selection = QItemSelection()
        for obj in objs:
            index = self.model.index_of_dn(obj.dn)
            if index.isValid():
                proxy_index = self.proxy.mapFromSource(index)
                if proxy_index.isValid():
                    selection.select(proxy_index, proxy_index)
        selection_model.clearSelection()
        selection_model.select(
            selection, selection_model.SelectionFlag.Select)
        # select() 会触发 selectionChanged → _on_selection_changed
        if not self.selected_rows():
            # 右键对象不在当前列表里（如从树菜单来的 OU）—— 塞进临时选区
            self._current_rows = list(objs)

    def _ask_reset_computer(self, obj: DirObject) -> None:
        """重置计算机账户：后果严重，必须明确确认（提示重新加域）。"""
        self._set_pending(("reset_computer", {"obj": obj}))
        self.confirm.ask(
            f"将重置计算机账户「{obj.cn or obj.sam}」的机器密码",
            extra_hint="（该机器下次连域会认证失败，需要重新加入域才能恢复。"
                       "仅用于机器失联 / 账号疑似冒用的场景）",
            ok_text="确认重置")

    def _copy_dn(self, obj: DirObject) -> None:
        from PyQt6.QtWidgets import QApplication

        # 剪贴板在 Windows 上是 OLE 对象，是会碰到 COM 公寓的少数几个动作之一 ——
        # 崩溃兜底靠这行面包屑定位（见 utils.breadcrumb）
        breadcrumb("复制 DN 到剪贴板")
        QApplication.clipboard().setText(obj.dn)
        self.notify("DN 已复制到剪贴板。", "info")

    # ==================================================================
    # 确认条：重置计算机账户
    # ==================================================================

    def _run_reset_computer(self, obj: DirObject) -> None:
        self.tasks.submit(
            "重置计算机账户", self.client.reset_computer_account,
            lambda _ret, o=obj: self._on_reset_computer(o),
            self._on_delete_failed, obj.dn, obj.sam or f"{obj.cn}$")

    def _on_reset_computer(self, obj: DirObject) -> None:
        """重置机器密码**成功之后**的收尾。

        ⚠️ 这个回调以前**借用了 `_on_deleted`**（`lambda _ch, o=obj:
           self._on_deleted("已重置…")`），一处改动同时踩了两个坑，而且
           **两个都静默**：

        ① **实参个数错**：`_on_deleted(self, dn, message)` 要 **2** 个必填，
           调用点只给了 **1** 个（那个字符串被当成 `dn` 顶了上去）⇒ 调用当场
           `TypeError`。而这个回调是交给 `TaskBridge.submit` 的 `on_ok` 位置的，
           `ui_tasks.TaskBridge._safe_call` 把它**吞掉**（只写一行日志，`except
           Exception`）⇒ 使用者**看不到**「已重置…」那条提示（提示的唯一出口
           断在回调里），而界面上**没有任何异常迹象**。守卫是
           `tests/test_callback_arity.py`（R1/R3 静态 AST，不看运行、不看界面）。

        ② **语义借错**：`reset_computer_account`（`ad_client.py:1417`）**不是
           删除** —— 对象、DN、树上的节点**全都不变**，它只把机器密码随机化。
           借来的 `_on_deleted` 干的是「弹提示 + `tree.remove_node(dn)` +
           借用**删除对象**的同步话术推复制」⇒ 就算把实参补齐，它也会去摘一个
           **根本没被删掉**的节点、并按错误的原因推同步。

        ⇒ 所以这里**不**调 `tree.remove_node`，也**不**借用"删除对象"的同步
           话术；`_sync_after_change` 的入参只是**文案标签**（`ui_browser.py:561`），
           按本次操作的**真实名字**传。
        """
        self.notify(
            f"已重置「{obj.cn or obj.sam}」的机器密码，该机器需重新加入域。", "ok")
        self._sync_after_change("重置计算机账户")

    # ==================================================================
    # 面板与导出
    # ==================================================================

    def _show_panel(self, panel: QWidget) -> None:
        self.panels.setCurrentWidget(panel)
        self.panel_container.setVisible(True)
        sizes = self.body_splitter.sizes()
        total = sum(sizes) if sizes else 0
        if len(sizes) < 2 or sizes[1] < 80:
            # 默认宽度跟**内容**走（属性编辑器/批量结果天然要更宽）；
            # 手动拖过的宽度记在面板自己身上 —— 不同面板各自记忆。
            # 之前是全局固定 400px：窗口再宽面板也纹丝不动，属性编辑器
            # 的长值被截断，拖拽手柄又太隐蔽（实测反馈：不能拉）。
            manual = getattr(panel, "_manual_width", 0)
            hint = max(panel.sizeHint().width(),
                       panel.minimumSizeHint().width(), 420)
            cap = max(total - 360, 380)
            if manual >= 320:
                panel_w = max(320, min(manual, cap))
            else:
                panel_w = max(380, min(hint, cap))
            self.body_splitter.setSizes([max(total - panel_w, 320), panel_w])
        self.body_splitter.update()

    def _hide_panel(self) -> None:
        sizes = self.body_splitter.sizes()
        total = sum(sizes)
        current = self.panels.currentWidget()
        if len(sizes) == 2 and sizes[1] >= 80 and current is not None:
            current._manual_width = sizes[1]     # 每种面板记住自己被拖过的宽度
        self.panels.setCurrentIndex(0)
        self.panel_container.setVisible(False)
        # ⚠️ 必须显式把空间还给表格：QSplitter 对「子项隐藏」的空间回收
        # 不总是即时生效，实测会残留一块空白遮着列表（界面截图逮过）。
        if total:
            self.body_splitter.setSizes([total, 0])
        self.body_splitter.update()
        self.update()

    def _export_csv(self) -> None:
        rows = self.model.rows()
        if not rows:
            self.notify("当前列表是空的，没有可导出的内容。", "warn")
            return
        from datetime import datetime

        default = f"{self._current_title or '对象列表'}_{datetime.now():%Y%m%d_%H%M}.csv"
        # 原生文件对话框是「输入同步」的 COM 调用 —— 崩溃排查最需要知道的
        # 就是「崩的时候是不是正开着这个框」，所以进出各记一条
        breadcrumb("打开导出对话框（对象列表）")
        path, _ = QFileDialog.getSaveFileName(self, "导出对象列表", default,
                                              "CSV 文件 (*.csv)")
        breadcrumb("导出对话框已关闭（对象列表）")
        if not path:
            return
        try:
            self._write_csv(path, rows)
        except OSError as exc:
            self.notify(f"导出失败：{exc}", "danger")
            return
        self.notify(f"已导出 {len(rows)} 条到 {path}", "ok")

    @staticmethod
    def _write_csv(path: str, rows: list[DirObject]) -> None:
        import csv

        from ui_models import _parent_label, fmt_password_expiry

        with open(path, "w", encoding="utf-8-sig", newline="") as fh:
            # utf-8-sig 带 BOM，Excel 双击打开中文才不乱码
            writer = csv.writer(fh)
            # 列必须覆盖**界面上看得见的每一列**：导出是拿去筛选/发工单的，
            # 表格里有的列在 CSV 里没有，使用者就得回头一行行看界面 ——
            # 「密码」列尤其（筛"30 天内到期"的账号发提醒），所以它在最前面
            # 那一组里。新增界面列时这里要同步（tools/adops_audit.py 的
            # O 组会拿 model.COLUMNS 与表头做差集比对）。
            writer.writerow(["名称", "类型", "描述", "登录名", "状态", "密码",
                             "最后登录", "所属位置", "DN"])
            for row in rows:
                status = "、".join(t for t, _ in _status_pills(row))
                cells = [
                    row.title or row.sam, row.kind_label(), row.description,
                    row.sam, status,
                    fmt_password_expiry(row.pwd_expire_at, row.pwd_must_change)
                    if row.has_account else "—",
                    fmt_datetime(row.last_logon),
                    _parent_label(row.dn), row.dn,
                ]
                # 🔒 每个单元格都过一遍公式注入防护 —— 这几列（名称/描述/登录名/
                #    DN）全是 AD 里的可控输入，导出后用 Excel 打开会被当公式执行。
                #    见 `utils.defuse_csv_cell`；静态判据在
                #    `tests/test_source_hygiene.py::TestNoUnsanitizedCsvExport`。
                writer.writerow([defuse_csv_cell(value) for value in cells])

    # ==================================================================
    # 键盘入口
    # ==================================================================

    def _on_delete_key(self) -> None:
        rows = self.selected_rows()
        if rows:
            self._ask_delete(rows)

    def _on_find_key(self) -> None:
        """Ctrl+F：构建器开着就聚焦构建器，否则聚焦普通搜索框。"""
        if self.filter_builder.isVisible():
            self.filter_builder.setFocus()
        else:
            self.search.setFocus()
            self.search.selectAll()

    def _on_refresh_key(self) -> None:
        """F5：搜索态重发同一条搜索，浏览态刷新当前 OU。"""
        if self.filter_builder.isVisible() and self._search_active:
            self.filter_builder.emit_search()
        elif self._search_active:
            self.search.fire()
        else:
            self.refresh()

    # ==================================================================
    # 其它
    # ==================================================================

    def _on_disconnect(self) -> None:
        if self.tasks.is_busy():
            self.notify("还有任务在执行，请等它结束再断开。", "warn")
            return
        self.disconnect_requested.emit()

    def set_busy(self, busy: bool, text: str = "") -> None:
        if text:
            self.footer.setText(text if busy else "")
        if not busy:
            self.footer.setText("")
