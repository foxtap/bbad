# -*- coding: utf-8 -*-
"""
ui_connect.py —— 连接页（T05 的连接部分）

这是启动后的第一个页面。**不弹连接对话框** —— 主窗口的中央区直接就是它，
连上之后整体换成浏览页。理由：连接不是"一个临时动作"，
而是这个工具的**唯一前置状态**，值得占满一屏。

三件事必须一眼看懂：
  1. 只需要填 IP / 账号 / 密码（域名和 BaseDN 会自动反查）
  2. 账号有哪三种写法都能用
  3. 没有域控也能用「演示数据」把界面走一遍
"""

from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from config import ConfigStore, dpapi_available
from models import ConnConfig, DomainInfo
from ui_widgets import Colors, hint_label, make_button, section_label
from utils import get_logger

__all__ = ["ConnectPage", "SavedConnectionList"]

_log = get_logger("ui_connect")

#: 「高级选项」折叠区的**唯一**标签字面量。
#: ⚠️ 展开与收起两处必须拼同一个常量 —— 以前两处各写一遍字面量，
#:    2026-09-17 往这个折叠区里**加装第二件事**（复制同步开关）之后，
#:    只改一处就会让"收起时的说法"和"里面的内容"对不上（名字说谎）。
_ADVANCED_LABEL = "高级选项（反查失败时手填域名 / BaseDN、复制同步开关）"


class SavedConnectionList(QListWidget):
    """「已保存的连接」列表 —— **不许 Qt 自己把"当前是哪一条"改掉**。

    ## 为什么不是裸 `QListWidget`

    Qt 把 `currentRow` 当作**键盘锚点**，不是"选中"：一个"当前行 = -1"的
    QListWidget 一旦**得到焦点**，Qt 会把当前行**补成第 0 行**，并同步发出
    `currentRowChanged(0)`（实测：`tools/probe_list_focus_refill.py` 第二段）。
    而本页把这条信号当成**使用者的选择** —— 它同时决定"表单回填哪一条"与
    "保存时是改还是新建" ⇒ 那一次补选等于**伪造**了一个使用者从没做过的选择。

    ## 现场（2026-09-18，`app.log`）

    ```
    14:01:14.550  [UI] 点击「测试连接」dc=〈他刚填的新目标〉
    14:01:14.888  [UI] 测试连接结果：成功
    14:01:17.931  [UI] 点击「连接域控」dc=〈上一条的旧目标〉   ← 表单自己变回去了
    ```

    （⚠️ 两个 IP 按红线遮掉了：生产模块里不许出现真实环境字样，判据见
    `tests/test_no_real_env_live.py`。**逐字原文**在 `tools/probe_list_focus_refill.py`，
    那里允许出现实测出处。）

    那 3 秒里使用者只做了两件事：看横幅、点「连接」。是**程序自己**改的表单。
    链条：点「测试连接」`_on_test()` 发出信号 → `MainWindow._test_connection()`
    立刻 `set_busy(True)` 把 `self.test_button` / `self.connect_button` /
    `self.demo_button` **一起 disable**，而焦点正停在刚点过的那个按钮上 ⇒ Qt 把焦点交给 tab 链里
    下一个可聚焦控件，即左边的本列表 ⇒ 而列表此刻的当前行**正好是 -1**
    （`_start_new()` 刚调过 `setCurrentRow(-1)`）⇒ Qt 补选第 0 行
    ⇒ 表单被**悄悄**回填成已有那条、`_is_new_connection` 被翻回 False
    ⇒ 再点「连接」，连上并存的都是**上一条**。使用者的原话：
    「**无法保存多个不同的连接，我新建之后，点击连接就会变成之前保存的**」。

    ## 做法：在**焦点进入这一个事件**里屏蔽信号 ＋ **撤销**被补选的状态

    * 屏蔽信号：Qt 的补选发生在 `super().focusInEvent()` 内部，是**同步**的，
      所以这一个事件里的 `currentRowChanged` 全部不是使用者的手势。
    * ⚠️ **必须撤销状态，不能只屏蔽信号**：Qt 补选之后 `currentRow()` 就是 0 了，
      而"点击**已经当前**的那一行"不会再发信号 ⇒ 使用者点第 0 行将**永远**
      回填不了（列表高亮着、表单里却是别人 —— 名字说谎）。撤销时同样屏蔽信号，
      免得又拨一次 `currentRowChanged(-1)`。
    * 撤销之后剩下的 `currentRowChanged` 才是他真的动了它：鼠标点某行 /
      方向键移动。两者都照旧生效（`test_clicking_a_row_still_refills_the_form`
      / `test_arrow_keys_still_pick_a_row` 钉着这两条反向守卫）。
    """

    def focusInEvent(self, event) -> None:                     # noqa: N802
        row_before = self.currentRow()
        signals_were_blocked = self.blockSignals(True)
        try:
            super().focusInEvent(event)
            if row_before < 0 and self.currentRow() >= 0:
                # Qt 拿它当键盘锚点补的 —— 本页的语义里"没有当前行"是一个
                # **真实状态**（= 正在填一条新连接），不能被它悄悄换掉。
                self.setCurrentRow(-1)
        finally:
            self.blockSignals(signals_were_blocked)


class ConnectPage(QWidget):
    """连接页。"""

    test_requested = pyqtSignal(object)       # ConnConfig
    connect_requested = pyqtSignal(object)    # ConnConfig
    demo_requested = pyqtSignal()

    def __init__(self, store: ConfigStore, parent: QWidget | None = None):
        super().__init__(parent)
        self.store = store
        #: 当前选中的那条配置的**身份**（`ConnConfig.id`），空串 = 没选中
        #: （在填新配置）。⚠️ 这里以前存的是**列表下标**：列表一刷新、中间
        #: 删掉一条，那个数字就指向别人了 —— 而"保存"会照着它写进去。
        #:
        #: 🔴 **2026-09-17：它不再决定"保存时是改还是新建"** —— 那件事现在
        #: 只看**连接目标**（见 `persist_current`）。留着它是因为另有三处要用：
        #: 选中态（`_selected_config` / 删除）、`saved_password`、以及
        #: `current_connection_key()`（给 `AppConfig.last_used`）。
        self._current_id = ""

        #: 使用者**明确点过「新建」**（且此后没在列表里点过任何一行）
        #: ⇒ 保存时**强制另存一条**，哪怕连接目标与已有记录**一模一样**。
        #:
        #: 🔴 为什么非要有它（2026-09-18 现场）：09-17 把"改还是新建"改成按
        #: **连接目标**（`dc_ip` + `bind_user`）分流之后，「同一个域控、同一个账号
        #: 再连一次」就**永远**被判成"编辑那条" ⇒ **点了「新建」也存不下第二条**
        #: （现场日志 `app.log`：`14:00:44` 与 `14:01:17` 两次连接目标逐字相同，
        #: 记录数始终 1 —— 使用者原话「无法保存多个不同的连接」）。
        #: 「新建」是使用者**明确说出来的意图**，规则必须尊重它。
        #:
        #: ⚠️ 它**只由使用者的动作**改（点「新建」置 True、点列表某行置 False），
        #: **绝不由 `persist_current()` 置 True** —— 那正是 09-17 那个缺陷的病根：
        #: 旧写法拿 `_current_id` 分流，而 `_current_id` 恰恰是保存函数**自己**
        #: 在末尾写进去的（= "上次连过的那条"）⇒ 连完 A 之后改 IP 去连 B，
        #: 就把 A 就地改写了。保存函数只允许把它**降为 False**（"这条已落地"）。
        #:
        #: ⚠️ "点列表某行"必须是**真的手势**：Qt 会在焦点进入时把"当前行为空"的
        #: 列表补选第 0 行，那一下会**伪造**出"使用者点了第 0 行"（2026-09-18
        #: 第二个现场缺陷：点「新建」+ 填新目标 + 点「测试连接」⇒ 焦点被
        #: `set_busy(True)` 交给列表 ⇒ 表单被悄悄回填、本字段被翻回 False
        #: ⇒ 再点「连接」存的是上一条）。挡它的是 `SavedConnectionList`。
        self._is_new_connection = True

        #: 这次连接**发出去的那一刻**定格的**三件套**：
        #: `(表单快照, 记住密码与否, 是不是"新建")`。
        #:
        #: 连接是**异步**的，等成功回调再去读，读到的可能已经是别的：
        #: 使用者中途点了列表 ⇒ 表单被回填成另一条记录、连"我在编辑哪条"
        #: 都变了。可**这次连接要存成什么**，在他点「连接」那一刻就已经定了。
        #: `_on_connect()` 定格，`persist_current()` 用它。
        self._pending_connect: tuple[ConnConfig, bool, bool] | None = None

        root = QHBoxLayout(self)
        root.setContentsMargins(18, 18, 18, 18)
        root.setSpacing(16)

        root.addWidget(self._build_saved_panel(), 0)
        root.addWidget(self._build_form_panel(), 1)

        self.reload()

    # ==================================================================
    # 左侧：已保存的连接
    # ==================================================================

    def _build_saved_panel(self) -> QWidget:
        panel = QFrame()
        panel.setFixedWidth(250)
        panel.setFrameShape(QFrame.Shape.StyledPanel)

        layout = QVBoxLayout(panel)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        layout.addWidget(section_label("已保存的连接"))

        self.saved_list = SavedConnectionList()
        self.saved_list.setMinimumHeight(220)
        self.saved_list.currentRowChanged.connect(self._on_saved_selected)
        layout.addWidget(self.saved_list, 1)

        row = QHBoxLayout()
        row.setSpacing(6)
        self.new_button = QPushButton("新建")
        self.new_button.clicked.connect(self._start_new)
        row.addWidget(self.new_button)

        self.delete_button = QPushButton("删除")
        self.delete_button.setToolTip("删除选中的连接配置")
        self.delete_button.clicked.connect(self._delete_selected)
        row.addWidget(self.delete_button)
        layout.addLayout(row)

        layout.addWidget(hint_label("连接配置里不存明文密码；"
                                    "只有勾选「记住密码」才会用 DPAPI 加密保存。"))
        return panel

    # ==================================================================
    # 右侧：表单
    # ==================================================================

    def _build_form_panel(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        inner = QWidget()
        scroll.setWidget(inner)
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(6, 2, 6, 2)
        layout.setSpacing(12)

        title = QLabel("连接域控")
        title.setStyleSheet("font-size: 16px; font-weight: 600;")
        layout.addWidget(title)
        layout.addWidget(hint_label(
            "只需要填「域控 IP / 账号 / 密码」三项。域名与 BaseDN 由工具匿名读取 "
            "RootDSE 自动反查 —— 所以本机不需要加入域，也不需要事先知道域名。"))

        # ---------- 输入 ----------
        form_box = QFrame()
        form_box.setFrameShape(QFrame.Shape.StyledPanel)
        form = QVBoxLayout(form_box)
        form.setContentsMargins(14, 14, 14, 14)
        form.setSpacing(10)

        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("给自己看的名字，如「示例主域」")
        form.addLayout(self._row("配置名", self.name_edit))

        self.ip_edit = QLineEdit()
        self.ip_edit.setPlaceholderText("如 192.0.2.10")
        self.ip_edit.textChanged.connect(self._on_ip_changed)
        form.addLayout(self._row("域控 IP", self.ip_edit, required=True))

        self.user_edit = QLineEdit()
        self.user_edit.setPlaceholderText("三种写法都行")
        form.addLayout(self._row("账号", self.user_edit, required=True))
        form.addWidget(hint_label(
            "推荐　域名\\用户名（CORP\\zhangsan，域用 NetBIOS 名）　·　"
            "用户名@域名（zhangsan@corp.example.com）　·　"
            "纯用户名（zhangsan，用反查到的域名自动补全）"))

        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_edit.setPlaceholderText("仅内存中使用，不写磁盘")
        form.addLayout(self._row("密码", self.password_edit, required=True))

        port_row = QHBoxLayout()
        port_row.setSpacing(10)
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(389)
        self.port_spin.setFixedWidth(110)
        port_row.addWidget(self.port_spin)
        self.ssl_check = QCheckBox("使用 SSL（636）")
        self.ssl_check.toggled.connect(self._on_ssl_toggled)
        port_row.addWidget(self.ssl_check)
        port_row.addStretch(1)
        form.addLayout(self._row("端口", port_row))

        self.remember_check = QCheckBox("记住密码（用 Windows DPAPI 加密保存）")
        if not dpapi_available():
            self.remember_check.setEnabled(False)
            self.remember_check.setText("记住密码（当前环境不支持 DPAPI）")
        form.addWidget(self.remember_check)

        # ⚠️ 2026-09-17 二次裁定：那个「变更后尝试强制 AD 复制同步」的勾**从这里
        #    （首页主表单）挪进下面的「高级选项」折叠区**。理由是原话：
        #    「不是要做到**页面里面一个按钮**来同步吗？为什么**首页**还有存在」——
        #    首页只该放"连接必须填的"，而这是个**每连接一份的配置项**（与端口/SSL/
        #    记住密码同类），且它默认就不勾 ⇒ 摆在首页只会让人以为漏了什么。
        #    要按需推请用**浏览页工具栏的「强制复制同步」按钮**（或菜单同一项）。
        #    ⇒ 控件挪了位置，`self.sync_check` 这个名字与读写路径**保持不变**。

        # ---------- 高级（反查失败时手填 + 复制同步开关）----------
        # ⚠️ 这个折叠区**从 2026-09-17 起装两件事**（域名/BaseDN 手填 + 复制同步开关）
        #    ⇒ 标签必须如实覆盖两件；标签字面量只此一份（`_ADVANCED_LABEL`），
        #    展开/收起两处各自拼字符串的写法已经删掉（那会让它们能各说各话）。
        self.advanced_toggle = QPushButton(f"{_ADVANCED_LABEL}　▸")
        self.advanced_toggle.setFlat(True)
        self.advanced_toggle.setCursor(Qt.CursorShape.PointingHandCursor)
        self.advanced_toggle.setStyleSheet("text-align: left; padding: 4px 0;")
        self.advanced_toggle.clicked.connect(self._toggle_advanced)
        form.addWidget(self.advanced_toggle)

        self.advanced_box = QWidget()
        adv = QVBoxLayout(self.advanced_box)
        adv.setContentsMargins(0, 0, 0, 0)
        adv.setSpacing(8)
        self.domain_edit = QLineEdit()
        self.domain_edit.setPlaceholderText("如 corp.example.com　（留空则自动反查）")
        adv.addLayout(self._row("域名", self.domain_edit))
        self.base_dn_edit = QLineEdit()
        self.base_dn_edit.setPlaceholderText("如 DC=corp,DC=example,DC=com　（留空则自动反查）")
        adv.addLayout(self._row("BaseDN", self.base_dn_edit))
        adv.addWidget(hint_label(
            "只有当域控禁用了匿名 RootDSE 读取时才需要手填 —— "
            "这种情况工具会明确提示你。"))

        self.sync_check = QCheckBox("变更后尝试强制 AD 复制同步")
        # ⚠️ 出厂**不勾**（2026-09-17 已定）：本工具常跑在未加域的机器上，
        #    那里 `repadmin` 必失败（只吃域名不吃 IP、且本机解析不了域控名）⇒
        #    "自动代跑"只会每次建/删之后刷一条提示。要推请用浏览页工具栏的
        #    「强制复制同步」按钮（或菜单「工具 → 强制复制同步」）。
        #    ⇒ 这行 tooltip 是"不勾"那一档的**唯一解释处**，别删。
        self.sync_check.setToolTip(
            "勾上 = 每次变更（建号 / 删号 / 新建 OU …）成功之后，自动尝试推一次\n"
            "AD 复制同步（repadmin /syncall … /AdeP）。\n"
            "⚠️ 需要本机能解析域控名、且当前会话里有域凭据；否则那一次只会失败。\n"
            "\n"
            "不勾（默认）= 不自动推。需要时点浏览页工具栏的「强制复制同步」\n"
            "按钮（或菜单「工具 → 强制复制同步」）按需推一次。")
        adv.addWidget(self.sync_check)

        self.advanced_box.setVisible(False)
        form.addWidget(self.advanced_box)

        layout.addWidget(form_box)

        # ---------- 探测结果 ----------
        self.result_banner = QFrame()
        self.result_banner.setVisible(False)
        banner_layout = QHBoxLayout(self.result_banner)
        banner_layout.setContentsMargins(12, 9, 12, 9)
        banner_layout.setSpacing(9)
        self.result_bar = QFrame()
        self.result_bar.setFixedWidth(3)
        banner_layout.addWidget(self.result_bar)
        self.result_label = QLabel("")
        self.result_label.setWordWrap(True)
        banner_layout.addWidget(self.result_label, 1)
        layout.addWidget(self.result_banner)

        # ---------- 按钮 ----------
        buttons = QHBoxLayout()
        buttons.setSpacing(9)
        self.test_button = make_button("测试连接")
        self.test_button.clicked.connect(self._on_test)
        buttons.addWidget(self.test_button)

        self.connect_button = make_button("连接", primary=True)
        self.connect_button.clicked.connect(self._on_connect)
        buttons.addWidget(self.connect_button)

        buttons.addStretch(1)

        self.demo_button = make_button("用演示数据体验（无需域控）")
        self.demo_button.setToolTip("加载一套假的域数据，先看看界面和功能")
        self.demo_button.clicked.connect(self.demo_requested.emit)
        buttons.addWidget(self.demo_button)
        layout.addLayout(buttons)

        layout.addStretch(1)
        return scroll

    @staticmethod
    def _row(label_text: str, widget, required: bool = False) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(10)
        label = QLabel(label_text + ("　*" if required else ""))
        label.setFixedWidth(72)
        label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        label.setStyleSheet(f"color: {Colors.MUTED};")
        row.addWidget(label)
        if isinstance(widget, QWidget):
            row.addWidget(widget, 1)
        else:
            row.addLayout(widget, 1)
        return row

    # ==================================================================
    # 交互
    # ==================================================================

    def _toggle_advanced(self) -> None:
        visible = not self.advanced_box.isVisible()
        self.advanced_box.setVisible(visible)
        arrow = "▾" if visible else "▸"
        self.advanced_toggle.setText(f"{_ADVANCED_LABEL}　{arrow}")

    def _on_ssl_toggled(self, checked: bool) -> None:
        # 端口跟着 SSL 走，但允许手动改（有人把 LDAPS 挪到别的端口）
        if checked and self.port_spin.value() == 389:
            self.port_spin.setValue(636)
        elif not checked and self.port_spin.value() == 636:
            self.port_spin.setValue(389)

    def _on_ip_changed(self, text: str) -> None:
        if not self.name_edit.text().strip():
            self.name_edit.setPlaceholderText(
                f"给自己看的名字，如「{text.strip() or '示例主域'}」")

    def _on_test(self) -> None:
        self.hide_result()
        self.test_requested.emit(self.current_config())

    def _on_connect(self) -> None:
        self.hide_result()
        # 🔴 定格"这次连接"的三件套：表单 / 记住密码 / 是不是「新建」。
        #    连接是**异步**的 —— 等成功回调再读，读到的可能已经是别的
        #    （使用者中途点了列表 ⇒ 表单被回填成另一条记录，连"我在编辑哪条"
        #    都变了）。可这次要存成什么，在他点「连接」这一刻就已经定了。
        self._pending_connect = (self.current_config(),
                                 self.remember_password(),
                                 self._is_new_connection)
        self.connect_requested.emit(self._pending_connect[0])

    def _on_saved_selected(self, index: int) -> None:
        """使用者在列表里**选中了**某一条（`saved_list.currentRowChanged` 的落点）。

        ⚠️ 这条信号**不是**"使用者选了什么"，它是"当前行变了" —— Qt 在焦点
        进入时会自己把"当前行为空"的列表补成第 0 行（见 `SavedConnectionList`）。
        所以本函数的**唯一合法上游**是那个控件类：它把焦点那一次挡掉了。
        换句话说，这里收到的每一次调用，都对应一个使用者的真实手势
        （鼠标点某行 / 方向键），**不是**程序自己的簿记动作。
        """
        conns = self.store.app.connections
        if not (0 <= index < len(conns)):
            self._current_id = ""
            # 一条都没选中 ⇒ 不是在编辑某一条 ⇒ 下次保存按「新建」算。
            self._is_new_connection = True
            return
        cfg = conns[index]
        # 选中这一格 → 记住的是它的**身份**，不是它现在排第几。
        self._current_id = cfg.id
        # 选中一条 = 使用者要**编辑那一条** ⇒ 保存时就地更新它，不另存。
        # （与 `_start_new` 相反：那是"我要一条新的"。这两处是「新建 / 编辑」
        #  这个意图**唯一**的两个来源 —— 保存函数不许自己改它。）
        self._is_new_connection = False
        self._load_into_form(cfg)
        # ⚠️ 判据是**实际拿到的明文**，不是配置里那个「记住密码」开关。
        #    开关开着但密文拿不到有两种情况：压根没存过、或 config.json
        #    来自别的机器/账号（DPAPI 解不开）。只认开关就会"打了勾、
        #    密码框却是空的"，而使用者不会想到是配置文件换过机器。
        saved = self.store.saved_password(self._current_id)
        if saved:
            self.password_edit.setText(saved)
        # 🔴 复选框反映的是**这条记录自己的意图**（`save_password`），
        #    不是"这一次解开了没有"。
        #
        #    用 `bool(saved)` 的后果是**不可逆**的：解不开 ⇒ 复选框被自动取消
        #    ⇒ 连接成功时 `persist_current()` 看到的是 `save_password=False`
        #    ⇒ `config.py` 把 `credential_blob` 置 None 并落盘
        #    ⇒ **盘上那份密文被静默删掉了**。
        #    而"解不开"往往恰恰说明这份配置是从**别的机器/别的 Windows 账号**
        #    拷过来的：本机这份副本一删，连"拿回原机器对照"这条路也没了。
        #    使用者当时看到的只是「请重新输入密码」—— **没人告诉他密文已经没了**。
        #
        #    意图与结果分开之后：勾还在（意图没变），上面那条横幅照旧说清
        #    "解不开、请重输"（结果如实上报），并且因为密码框是空的，
        #    `update_connection` 会**原样保留** blob（见那里两个分支都不命中）。
        self.remember_check.setChecked(
            bool(saved) or self.store.wants_password_saved(self._current_id))
        if saved:
            self.hide_result()
        elif self.store.wants_password_saved(self._current_id):
            # 两种原因要说准：没存过 vs 存了但换机器解不开
            reason = ("但本机解不开这份密文 —— 配置文件可能来自另一台电脑"
                      "或另一个 Windows 账号"
                      if self.store.has_password_blob(self._current_id)
                      else "但当时密码框是空的，没有可用的密文")
            self.set_result(False, f"「{cfg.display_name()}」标记了「记住密码」，"
                                   f"{reason}。请重新输入密码。")
        else:
            self.hide_result()

    def _selected_config(self) -> ConnConfig | None:
        """当前选中那条配置 —— 按**身份**找，不按"列表第几行"找。

        为什么不用 `saved_list.currentRow()`：列表刷新过（`reload()`）之后
        选中态会被清掉，而这个页面的"当前这条"在刷新前后**是同一条**。
        按行号找会在刷新后返回 None（删除按钮突然点不动），按位置找更糟 ——
        `reload()` 之后第 0 行可能是**另一条**配置。
        """
        if not self._current_id:
            return None
        for cfg in self.store.app.connections:
            if cfg.id == self._current_id:
                return cfg
        return None

    def _load_into_form(self, cfg: ConnConfig) -> None:
        self.name_edit.setText(cfg.name)
        self.ip_edit.setText(cfg.dc_ip)
        self.user_edit.setText(cfg.bind_user)
        self.port_spin.setValue(cfg.port)
        self.ssl_check.setChecked(cfg.use_ssl)
        self.domain_edit.setText(cfg.domain)
        self.base_dn_edit.setText(cfg.base_dn)
        self.sync_check.setChecked(cfg.sync_after_change)

    def _start_new(self) -> None:
        self._current_id = ""
        self.saved_list.setCurrentRow(-1)
        for widget in (self.name_edit, self.ip_edit, self.user_edit,
                       self.password_edit, self.domain_edit, self.base_dn_edit):
            widget.clear()
        self.port_spin.setValue(389)
        self.ssl_check.setChecked(False)
        self.remember_check.setChecked(False)
        # 与 `ConnConfig.sync_after_change` 的出厂默认值一致（True = 既有行为）。
        # ⚠️ 两处必须一致：这里漏一次，"新建一条配置"就会悄悄把同步关掉。
        self.sync_check.setChecked(ConnConfig().sync_after_change)
        self.hide_result()
        # ⚠️ 放在**最后**：上面那句 `setCurrentRow(-1)` 会触发 `_on_saved_selected`，
        #    而那条路会把它置 False（那是对"点列表选中某条 = 编辑它"的语义）。
        #    「新建」这个意图必须由**这一次点击**说了算，不能被信号盖掉。
        self._is_new_connection = True
        self.ip_edit.setFocus()

    def _delete_selected(self) -> None:
        cfg = self._selected_config()
        if cfg is None:
            # ⚠️ 没选中就**说一句**：删除按钮亮着、点了没反应，使用者会
            #    以为工具卡住了。本页其它失败路径都走 `set_result`，这里也走它。
            self.set_result(False, "请先在上面的列表里选中一条要删除的连接配置。")
            return
        name = cfg.display_name()
        try:
            self.store.remove_connection(cfg.id)
            self.store.save()
        except Exception as exc:                     # noqa: BLE001
            # ⚠️ 以前这里只把异常写进横幅、**不落盘**：使用者说"删不掉，红字一闪"
            #    时，日志里连"有没有报过异常"都查不到（异常对象本身也丢了，
            #    只有 str(exc) 那一句）。排障需要类型名 + 堆栈 ⇒ 记 exc_info。
            _log.error("删除连接配置失败 name=%s：%s", name, exc, exc_info=True)
            self.set_result(False, f"删除失败：{exc}")
            return
        self._start_new()
        self.reload()
        self.set_result(True, f"已删除连接配置「{name}」。")

    # ==================================================================
    # 对外
    # ==================================================================

    def reload(self) -> None:
        """重新加载已保存的连接列表。"""
        self.saved_list.blockSignals(True)
        self.saved_list.clear()
        for cfg in self.store.app.connections:
            item = QListWidgetItem(cfg.display_name())
            item.setToolTip(f"{cfg.dc_ip}:{cfg.port}\n{cfg.bind_user}")
            self.saved_list.addItem(item)
        self.saved_list.blockSignals(False)

    def current_config(self) -> ConnConfig:
        """把表单收成一个 ConnConfig。"""
        return ConnConfig(
            name=self.name_edit.text().strip(),
            dc_ip=self.ip_edit.text().strip(),
            bind_user=self.user_edit.text().strip(),
            password=self.password_edit.text(),
            port=self.port_spin.value(),
            use_ssl=self.ssl_check.isChecked(),
            domain=self.domain_edit.text().strip(),
            base_dn=self.base_dn_edit.text().strip(),
            sync_after_change=self.sync_check.isChecked(),
        )

    def set_result(self, ok: bool, text: str) -> None:
        color = Colors.OK if ok else Colors.DANGER
        self.result_bar.setStyleSheet(f"background: {color}; border-radius: 1px;")
        self.result_label.setText(text)
        self.result_label.setStyleSheet("")
        self.result_banner.setStyleSheet(
            "QFrame { background: palette(alternate-base); border-radius: 8px; }")
        self.result_banner.setVisible(True)

    def hide_result(self) -> None:
        self.result_banner.setVisible(False)

    def set_busy(self, busy: bool, text: str = "") -> None:
        for widget in (self.test_button, self.connect_button, self.demo_button):
            widget.setEnabled(not busy)
        if busy and text:
            self.set_result(True, text)

    def remember_password(self) -> bool:
        return self.remember_check.isChecked()

    def current_connection_key(self) -> str:
        """当前这条配置的**身份**（`ConnConfig.id`）；没有身份时回落「名字 / IP」。

        给 `AppConfig.last_used` 用。为什么记身份而不是名字/IP：那两个字段
        使用者随时能改，改完"上次用的是哪条"就落空了（于是下次启动静默
        退回第一条）。回落是为了老配置文件 —— 那里 `last_used` 存的正是
        名字/IP。
        """
        if self._current_id:
            return self._current_id
        cfg = self.current_config()
        return cfg.name or cfg.dc_ip

    def persist_current(self, cfg: ConnConfig | None = None,
                        remember: bool | None = None,
                        is_new: bool | None = None) -> None:
        """把**这次连接**存进配置（连接成功时调用）。

        ⚠️ 优先用 `_on_connect()` 定格的那份**快照**（表单 / 记住密码 /
        是不是「新建」），**不回头再读**：连接是**异步**的，这中间表单可能
        已经被改（点列表 ⇒ 回填成另一条）⇒ 存下来的会是**另一条**。
        只有没有快照时才回落到现读（测试直接调本函数时不经过 `_on_connect`）。

        🔴 **身份 = 连接目标**（`dc_ip` + `bind_user`），不是"当前选中哪一条"
        （2026-09-17 改。现场缺陷：**已保存的连接只能留一个，登录另一个就把
        第一个顶掉了**）。

        原来这里按 `self._current_id` 分流：非空就走 `update_connection`。
        而 `_current_id` 恰恰是**本函数自己**在末尾写进去的（= "上次连过的那条"）
        ⇒ 连完 A 之后它就指着 A，使用者接着在表单上改 IP / 账号去连 B，
        保存时就把 **A 就地改写**成 B 的内容 —— A **一声不响地没了**。
        （这一条有现场复现脚本与三种场景的实测输出作证据。）

        现在的规则有**两条**，各守一个方向（2026-09-18 补第二条）：

        * **第一问：使用者点过「新建」吗？**（`is_new`，只由他的动作决定：
          点「新建」置真、在列表里点某行置假。）点过 ⇒ 他要的就是**另一条**，
          直接 `add_connection` —— 哪怕连接目标跟已有记录**一模一样**。
          ⚠️ 少了这一问就会犯 09-18 现场那个缺陷：同一个域控、同一个账号
          再连一次被判成"编辑那条"⇒ **永远只有 1 条**。
        * **第二问：这个连接目标已经存过吗？**（`dc_ip` + `bind_user`）
          存过 ⇒ 这是在**编辑**已存的那条：改名 / 改端口 / 改域名 / 改 BaseDN /
          改「记住密码」都算 —— `update_connection`，不新增重复记录；
          没存过 ⇒ 这是**另一条连接**，另存一条，**绝不顶掉**任何已有记录。

        只有两条一起在，规则才既不丢数据也不越存越多：第一条防"点了「新建」
        却存不下第二条"，第二条防"连另一个域把上一条顶掉"（09-17 的缺陷）。

        ⚠️ 第二问的判据**只看这两个字段**是有意的：换个端口（389 → 636 开 SSL）
        仍然是同一个连接目标，该更新而不是新增。

        ⚠️ 两条路都可能被**存储层**拒：`config._assert_name_is_free` 是**共用**
        的那一份判据（新增与改名都过它）——「配置名不允许重名」是 2026-09-18
        既定的口径，理由是撞名之后使用者**分不清哪条是哪条**
        （连接页列表只显示名字）。本函数要保证的是**别骗人**：
        失败必须走 `set_result(False, ...)`。

        ⚠️ 代价（**有意付的**）：想把某条记录的**连接目标改掉**（把 A 改指向
        一个新 IP）现在会**多出一条**，需要手动删掉旧的那条。取舍是
        「多一步」换「不丢数据」—— 反过来的代价是**不可逆**的（现场就是这么
        丢的：使用者看到的是"只剩一条"，而旧的那条已经没有任何副本）。

        密码是否落盘由「记住密码」复选框决定；不勾就立刻清掉密文。
        """
        snap = self._pending_connect
        if cfg is None:
            cfg = snap[0] if snap else self.current_config()
        if remember is None:
            remember = snap[1] if snap else self.remember_password()
        # ⚠️ 「是不是新建」也要从快照取：连接发出之后使用者还可能去点列表
        #    （那会把实时的「我在编辑哪条」改掉）—— 可**这次连接存成什么**，
        #    在他点「连接」那一刻就已经定了。
        if is_new is None:
            is_new = snap[2] if snap else self._is_new_connection
        if not cfg.dc_ip:
            return
        if not cfg.name:
            cfg.name = cfg.dc_ip
        try:
            if is_new:
                # 使用者点过「新建」⇒ 他要的就是**另一条**，哪怕连接目标跟已有
                # 记录**一模一样**。2026-09-18 现场就是这里丢的：同一个域控、
                # 同一个账号再连一次，被当成"编辑那条"⇒ 永远只有 1 条。
                self.store.add_connection(cfg, remember, cfg.password)
            else:
                same = self._record_for_target(cfg.dc_ip, cfg.bind_user)
                if same is not None:
                    self.store.update_connection(same.id, cfg, remember, cfg.password)
                else:
                    self.store.add_connection(cfg, remember, cfg.password)
            # 身份由 store 决定（`add_connection` 给新记录补一个，
            # `update_connection` 把原来那个原样带回来）⇒ 存下来。
            self._current_id = cfg.id
            # ⚠️ 只**降**不**升**：这一条已经落地 ⇒ 之后按连接目标匹配
            #    （那是在编辑那条）。**绝不在这里置 True** —— 那正是 09-17
            #    那个缺陷的病根（"上次连过的那条"被当成"这次要编辑的那条"）。
            #    要再存一条新的，只有使用者**自己点「新建」**这一条路。
            self._is_new_connection = False
            self.store.save()
        except Exception as exc:                     # noqa: BLE001
            # 连接确实成功了，但**这条配置没存上** —— 必须出**失败色**：
            # 这是一件要使用者动手的事（最常见的就是名字跟已有配置撞了，
            # `add_connection` 会抛「已存在同名配置，请换一个名字」）。
            # ⚠️ 这里以前是 `set_result(True, ...)`（**成功色**）⇒ 使用者
            # 看到绿色的「已连接」就以为存上了，下一轮才发现"怎么老是只有
            # 一条"（2026-09-18 现场就是这么被绕进去的）。
            # ⚠️ 这句会**原样**显示在横幅上 —— 所以不许写 `**`（本项目没有
            #    Markdown 渲染器，落到界面上就是两个真的星号）；
            #    强调用「」：`test_source_hygiene` 有一条判据钉着这件事。
            self.set_result(False, f"已连接，但「这条连接没有保存」：{exc}")
            return
        finally:
            # 这次连接的快照只对**这一次**回调有效。连接失败时会从上面 `return`
            # 出去，所以清理必须放 `finally`，放函数末尾会漏。
            self._pending_connect = None
        self.reload()

    def _record_for_target(self, dc_ip: str, bind_user: str) -> ConnConfig | None:
        """这个**连接目标**已经存了哪一条（没有 ⇒ `None`）。

        ⚠️ 目标可能匹配到**多条** —— 使用者点过「新建」时，可以硬存下两条
        连接目标完全相同的记录（那是他明确要的）。这种情况下优先回**他当前
        选中的那一条**，否则取第一条：否则"点第 2 条去改密码"会改到第 1 条头上。
        """
        candidates = [c for c in self.store.app.connections
                      if c.dc_ip == dc_ip and c.bind_user == bind_user]
        if not candidates:
            return None
        for cfg in candidates:
            if cfg.id and cfg.id == self._current_id:
                return cfg
        return candidates[0]

    def show_domain_info(self, info: DomainInfo) -> None:
        """把反查结果渲染成"我读到了什么"。"""
        if not info.ok:
            self.set_result(False, info.summary())
            return
        parts = [f"已识别域：{info.dns_domain or '（未知）'}",
                 f"BaseDN：{info.base_dn}"]
        if info.dns_host_name:
            parts.append(f"域控主机：{info.dns_host_name}")
        if info.functional_level:
            parts.append(f"功能级别：{info.functional_level}")
        self.set_result(True, "　·　".join(parts))
