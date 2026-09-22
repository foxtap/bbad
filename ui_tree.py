# -*- coding: utf-8 -*-
"""
ui_tree.py —— OU 目录树（懒加载）

两条设计约束：

1. **懒加载**：一个几千人的域，整棵树一次拉下来要几十秒。
   只在展开时才拉一级子 OU。
2. **实测过 N+1 问题**：`AdClient.list_child_ous` 内部会为每个子 OU
   探测"有没有下级"（决定是否显示展开箭头），那是一次额外 LDAP 往返。
   `ad_client` 里已加缓存，这里也要避免重复请求（见 `_requested` 集合）。
"""

from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QLineEdit,
    QMenu,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from models import OuNode

__all__ = ["OuTree"]

#: 存在 item 上的自定义数据角色
ROLE_DN = int(Qt.ItemDataRole.UserRole) + 1
ROLE_LOADED = int(Qt.ItemDataRole.UserRole) + 2
ROLE_PLACEHOLDER = int(Qt.ItemDataRole.UserRole) + 3


class OuTree(QWidget):
    """左侧 1/5 的目录树。

    信号：
      * ``selection_changed(dn, title)`` —— 选中节点变化（右侧列表据此刷新）
      * ``need_children(dn)`` —— 需要拉某个节点的子 OU（由页面负责异步拉取）
      * ``context_menu_requested(dn, title, global_pos)`` —— 右键菜单
        （右键会**先选中**该节点 —— 与 ADUC 一致：右键谁就操作谁）

    ⚠️ 2026-09-17 删掉了这里的 ``create_ou_requested(parent_dn)``：
    它**既没有 emit 也没有 connect**（"在此新建 OU"实际走的是右键菜单那条路），
    是方案变更留下的空壳。按本项目铁律「零调用点 = 死代码要删」处理。
    """

    selection_changed = pyqtSignal(str, str)
    need_children = pyqtSignal(str)
    context_menu_requested = pyqtSignal(str, str, object)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.filter = QLineEdit()
        self.filter.setPlaceholderText("筛选部门名称")
        self.filter.setClearButtonEnabled(True)
        self.filter.textChanged.connect(self._apply_filter)
        layout.addWidget(self.filter)

        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setColumnCount(1)
        self.tree.setUniformRowHeights(True)          # 大树上显著的性能优化
        self.tree.setAnimated(True)
        self.tree.setExpandsOnDoubleClick(True)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.tree.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.tree.header().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.tree.itemExpanded.connect(self._on_expanded)
        self.tree.currentItemChanged.connect(self._on_current_changed)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._on_context_menu)
        layout.addWidget(self.tree, 1)

        #: 已发起过加载请求的 DN，避免折叠-展开反复打域控
        self._requested: set[str] = set()
        self._root_dn = ""

    # ==================================================================
    # 对外
    # ==================================================================

    def set_root(self, base_dn: str, title: str = "域根") -> None:
        """设定树根（一般是 BaseDN）。"""
        self._requested.clear()
        self.tree.clear()
        self._root_dn = base_dn

        root = QTreeWidgetItem([title])
        root.setData(0, ROLE_DN, base_dn)
        root.setData(0, ROLE_LOADED, False)
        root.setToolTip(0, base_dn)
        font = QFont()
        font.setWeight(QFont.Weight.DemiBold)
        root.setFont(0, font)
        self._add_placeholder(root)
        self.tree.addTopLevelItem(root)
        root.setExpanded(True)

    def fill_children(self, parent_dn: str, nodes: list[OuNode]) -> None:
        """把异步拉回来的子 OU 填进对应节点。"""
        parent = self._find(parent_dn)
        if parent is None:
            return

        parent.takeChildren()                        # 移除占位/旧内容
        for node in nodes:
            child = QTreeWidgetItem([node.name])
            child.setData(0, ROLE_DN, node.dn)
            child.setData(0, ROLE_LOADED, False)
            tip = node.description or node.dn
            child.setToolTip(0, tip)
            if node.has_children:
                self._add_placeholder(child)
            parent.addChild(child)

        parent.setData(0, ROLE_LOADED, True)
        self._apply_filter(self.filter.text())
        self._update_badges()

    def mark_failed(self, parent_dn: str) -> None:
        """加载失败：**留下一个可以重试的节点** —— 不许把子树永久判死。

        ⚠️ 这里**故意不写 `ROLE_LOADED = True`**，也**故意把它从 `_requested`
           里摘掉**。写过的人是这么想的："把占位去掉，避免一直转" —— 但那个写法
           等于把这个节点**永久标记成「已加载」**，而它其实一个子节点都没拿到：

             * `_on_expanded` 第一句就是 `if item.data(0, ROLE_LOADED): return`
               ⇒ 使用者再怎么点都不会再发请求；
             * `takeChildren()` 之后节点 0 个子节点 ⇒ **展开箭头也没了**。

           ⇒ **这个分支从此永远空着**，只有「重新连接」（走 `set_root`）
           或别处显式调 `reload_node` 才能救 —— 而界面上唯一的表现，
           是一个几秒后就消失的 Toast。

           域是跑在网上的：**一次瞬时失败（VPN 抖动、GC 忙、超时）就够触发。**
           实测（2026-09-16）：mark_failed 之后 `need_children` 不再发，
           使用者折叠再展开也发不出来。

        正确做法：把状态**退回"没加载过"**，并补回一个带说明的占位
        （占位 = 展开箭头还在）；同时**折叠**节点 —— 因为「展开」正是重试的动作，
           而一个已经展开的节点上"再展开一次"是不发信号的（同 `invalidate()` 那个坑）。
        """
        parent = self._find(parent_dn)
        if parent is None:
            return
        parent.takeChildren()
        parent.setData(0, ROLE_LOADED, False)
        self._requested.discard(parent_dn)
        self._add_placeholder(parent, "读取失败 —— 展开重试")
        self._update_badges()
        if parent.isExpanded():
            parent.setExpanded(False)

    def current_dn(self) -> str:
        item = self.tree.currentItem()
        return item.data(0, ROLE_DN) if item is not None else ""

    def current_title(self) -> str:
        item = self.tree.currentItem()
        return item.text(0) if item is not None else ""

    def invalidate(self) -> None:
        """整树作废（**只留给「切换连接」用** —— 那是另一棵树了）。

        ⚠️ 普通修改（删/移/改名/建/启停）**禁止**走这里：takeChildren 会
        抹掉全部已展开节点，下一次展开全部重新打域控 —— 表现就是
        「每改一下左边树就加载很久」。局部更新请用下面的
        remove_node / rename_node / insert_child / move_node / reload_node。
        """
        self._requested.clear()
        stack = [self.tree.topLevelItem(i)
                 for i in range(self.tree.topLevelItemCount())]
        while stack:
            item = stack.pop()
            if item is None:
                continue
            stack.extend(item.child(i) for i in range(item.childCount()))
            item.setData(0, ROLE_LOADED, False)

        root = self.tree.topLevelItem(0)
        if root is not None:
            root.takeChildren()
            self._add_placeholder(root)
            root.setExpanded(True)
            # ⚠️ 上面那句 `setExpanded(True)` **在根已经展开时是空操作、不发
            #    `itemExpanded`**（Qt 的 `QTreeView::setExpanded` 在状态没变时
            #    直接 return）⇒ **只靠它等于永远不请求根的子节点**：根下面只剩
            #    一个「正在读取…」占位符，一直卡到使用者手点一下展开箭头为止。
            #    这就是 2026-09-16 反馈的「刷新之后左边的树要很久才出来，
            #    用鼠标点一下就会更快出来」的根因（实测：`refresh()` →
            #    `invalidate()` 之后 `need_children` **一次都不发**；折叠再展开
            #    才发）。⇒ 这里**显式补一次**。
            #    `_on_expanded` 自带 `_requested` 去重，所以根原本是折叠态时
            #    （`setExpanded` 已经触发过一次）这次调用是幂等的，不会发两次。
            self._on_expanded(root)

    # ------------------------------------------------------------------
    # 局部更新原语（改完只动被改的那个节点，展开状态全保留）
    # ------------------------------------------------------------------

    def remove_node(self, dn: str) -> None:
        """删除对象后摘掉它的节点 —— 其余节点原样保留。

        树上只有 OU / 容器：删用户、删组时找不到节点是**正常**的，直接返回。
        """
        item = self._find(dn)
        if item is None:
            return
        parent = item.parent()
        if parent is None:
            self.tree.takeTopLevelItem(self.tree.indexOfTopLevelItem(item))
        else:
            parent.removeChild(item)
            self._update_badges()

    def rename_node(self, old_dn: str, new_dn: str, title: str) -> None:
        """重命名：改这一个节点的文本和 DN（子树 DN 前缀一并换血）。"""
        item = self._find(old_dn)
        if item is None:
            return
        item.setData(0, ROLE_DN, new_dn)
        self._retarget_subtree_dns(item, old_dn, new_dn)
        item.setText(0, title or new_dn.split(",")[0].split("=", 1)[-1])
        if old_dn.casefold() in {d.casefold() for d in self._requested}:
            self._requested.discard(old_dn)
            self._requested.add(new_dn)
        self._update_badges()

    def insert_child(self, parent_dn: str, name: str, dn: str) -> None:
        """新建 OU 后把节点插进父节点（父未加载则不插 —— 展开时自然拉到）。"""
        parent = self._find(parent_dn)
        if parent is None or not parent.data(0, ROLE_LOADED):
            return
        child = QTreeWidgetItem([name])
        child.setData(0, ROLE_DN, dn)
        child.setData(0, ROLE_LOADED, False)
        child.setToolTip(0, dn)
        # 新建 OU 是空的：不占位、不画展开箭头
        parent.addChild(child)
        self._apply_filter(self.filter.text())
        self._update_badges()

    def move_node(self, old_dn: str, new_dn: str, new_parent_dn: str) -> None:
        """移动节点：**删旧插新**（只有移动 OU 才走这条路）。

        新父未加载或不在树里时，摘下的节点就地作废 —— 展开新父时
        懒加载会重新拉到它，不会丢。
        """
        item = self._find(old_dn)
        if item is None:
            return
        name = item.text(0).split("  (")[0]
        # ⚠️ QTreeWidgetItem 被摘下来再挂回去，展开标志会丢 ——
        #    必须先把整棵子树的展开状态拍下来，挂回后原样恢复。
        #    ⚠️ 快照必须按**对象**记、不能按 DN 记：DN 在下面要换血，
        #    按 DN 记的键挂回后一个都对不上（实测踩过）。
        expanded_items: list[QTreeWidgetItem] = []
        snap = [item]
        while snap:
            it = snap.pop()
            if it.isExpanded():
                expanded_items.append(it)
            snap.extend(it.child(i) for i in range(it.childCount()))
        parent = item.parent()
        if parent is None:
            self.tree.takeTopLevelItem(self.tree.indexOfTopLevelItem(item))
        else:
            parent.removeChild(item)
            self._update_badges()
        item.setData(0, ROLE_DN, new_dn)
        self._retarget_subtree_dns(item, old_dn, new_dn)
        item.setText(0, name)
        if old_dn.casefold() in {d.casefold() for d in self._requested}:
            self._requested.discard(old_dn)
            self._requested.add(new_dn)
        new_parent = self._find(new_parent_dn)
        if new_parent is not None:
            # 目标父没加载过也挂上去：节点和它的已展开子树都是刚换过血
            # 的真实数据，丢了可惜；等目标父展开时 fill_children 会权威重拉
            new_parent.addChild(item)
            for it in expanded_items:
                it.setExpanded(True)
            self._apply_filter(self.filter.text())
            self._update_badges()

    def reload_node(self, dn: str) -> None:
        """只作废**一个**节点的子级并重新请求（批量移动后两端父节点用）。

        兄弟节点一概不动 —— 这是「整树重载」的局部替代品。
        """
        item = self._find(dn)
        if item is None:
            return
        self._requested.discard(dn)
        item.takeChildren()
        item.setData(0, ROLE_LOADED, False)
        self._add_placeholder(item)
        self._update_badges()
        if item.isExpanded():
            self._on_expanded(item)          # 已展开的立刻补拉

    def _retarget_subtree_dns(self, item: QTreeWidgetItem,
                              old_dn: str, new_dn: str) -> None:
        """子树里所有 DN 的父前缀从 old_dn 换成 new_dn（大小写不敏感）。"""
        old = old_dn.casefold()
        suffix = "," + old
        stack = [item.child(i) for i in range(item.childCount())]
        while stack:
            child = stack.pop()
            stack.extend(child.child(i) for i in range(child.childCount()))
            dn = child.data(0, ROLE_DN) or ""
            if dn and dn.casefold().endswith(suffix):
                child.setData(0, ROLE_DN, dn[: len(dn) - len(old_dn)] + new_dn)

    # ==================================================================
    # 内部
    # ==================================================================

    def _add_placeholder(self, item: QTreeWidgetItem,
                         text: str = "正在读取…") -> None:
        """先放一个假子节点，让 Qt 画出展开箭头；展开时再换成真的。

        ``text`` 只在失败后重试用（见 ``mark_failed``）—— 平时是「正在读取…」。
        """
        placeholder = QTreeWidgetItem([text])
        placeholder.setData(0, ROLE_PLACEHOLDER, True)
        placeholder.setDisabled(True)
        item.addChild(placeholder)

    def _find(self, dn: str) -> QTreeWidgetItem | None:
        if not dn:
            return None
        stack = [self.tree.topLevelItem(i) for i in range(self.tree.topLevelItemCount())]
        while stack:
            item = stack.pop()
            if item is None:
                continue
            if item.data(0, ROLE_DN) == dn:
                return item
            stack.extend(item.child(i) for i in range(item.childCount()))
        return None

    def _on_expanded(self, item: QTreeWidgetItem) -> None:
        dn = item.data(0, ROLE_DN)
        if not dn or item.data(0, ROLE_LOADED):
            return
        if dn in self._requested:
            return
        self._requested.add(dn)
        self.need_children.emit(dn)

    def _on_current_changed(self, current: QTreeWidgetItem, _previous) -> None:
        if current is None or current.data(0, ROLE_PLACEHOLDER):
            return
        dn = current.data(0, ROLE_DN) or ""
        self.selection_changed.emit(dn, current.text(0))

    def _on_context_menu(self, pos) -> None:
        item = self.tree.itemAt(pos)
        if item is None or item.data(0, ROLE_PLACEHOLDER):
            return
        # 右键谁就选中谁 —— 与 ADUC 一致，右侧列表同步切换
        self.tree.setCurrentItem(item)
        dn = item.data(0, ROLE_DN) or ""
        title = item.text(0).split("  (")[0]     # 去掉 _update_badges 的计数尾巴
        self.context_menu_requested.emit(dn, title,
                                         self.tree.viewport().mapToGlobal(pos))

    def _apply_filter(self, text: str) -> None:
        """本地筛选：只隐藏节点，不重新拉数据。

        Qt 的 ``QTreeWidgetItem.setHidden`` 对子孙生效，所以匹配的节点
        必须连同祖先一起显示 —— 否则筛到「运维部」却看不到它在哪棵子树下。
        """
        needle = (text or "").strip().lower()
        for i in range(self.tree.topLevelItemCount()):
            self._filter_item(self.tree.topLevelItem(i), needle)

    def _filter_item(self, item: QTreeWidgetItem, needle: str) -> bool:
        """返回 True 表示该节点或其子孙被保留。"""
        if not needle:
            item.setHidden(False)
            for i in range(item.childCount()):
                self._filter_item(item.child(i), needle)
            return True

        self_match = needle in item.text(0).lower()
        child_match = False
        for i in range(item.childCount()):
            if self._filter_item(item.child(i), needle):
                child_match = True

        visible = self_match or child_match
        item.setHidden(not visible)
        if child_match and not item.isExpanded() and not self_match:
            item.setExpanded(True)          # 有子节点命中就自动展开
        return visible

    def _update_badges(self) -> None:
        """在节点文字后追加子 OU 数量，如「总部 (3)」。"""
        stack = [self.tree.topLevelItem(i)
                 for i in range(self.tree.topLevelItemCount())]
        while stack:
            item = stack.pop()
            if item is None:
                continue
            stack.extend(item.child(i) for i in range(item.childCount()))

            clean = item.text(0).split("  (")[0]
            # 只在「已加载」时显示数量，否则会误导（未加载 ≠ 没有子节点）
            if not item.data(0, ROLE_LOADED):
                item.setText(0, clean)
                continue
            real_children = [item.child(i) for i in range(item.childCount())
                             if not item.child(i).data(0, ROLE_PLACEHOLDER)]
            item.setText(0, f"{clean}  ({len(real_children)})" if real_children
                        else clean)
