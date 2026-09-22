# -*- coding: utf-8 -*-
"""
ui_widgets.py —— 可复用控件

设计取向（用户偏好）：
  * **内联优先**：能嵌在页面里的操作绝不弹模态框。
    `InlinePanel` / `ConfirmBar` 就是为此存在 —— 面板出现时，
    左侧 OU 树与右侧列表**始终可见**，填错目标能立刻发现。
  * **不阻塞**：轻提示用 `Toast`（右下角自动消失），不用 QMessageBox
    打断操作流。只有「不可逆 + 需二次确认」才用模态。
  * **深浅色自适应**：所有颜色走 `theme.Colors`，不写死白底黑字。
"""

from __future__ import annotations

import logging
from typing import Callable

from PyQt6.QtCore import QEvent, QObject, QSize, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QPainter
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QStyledItemDelegate,
    QVBoxLayout,
    QWidget,
    # Qt 自己的「无上限」常量（``(1 << 24) - 1``，定义在 ``qwidget.h``）。
    # ⚠️ 用它的导出值而**不要手写 16777215** —— 手写的那个数一旦与 Qt 的
    #    定义脱节，`setMaximumHeight()` 就会把控件悄悄夹在一个更小的值上，
    #    而**不会有任何报错**。PyQt6 确实导出了它（已实测，非猜）。
    QWIDGETSIZE_MAX,
)

from ui_theme import SEMANTIC
from utils import check_password_guessability, generate_password

__all__ = [
    "Colors",
    "Toast",
    "InlinePanel",
    "ConfirmBar",
    "DefaultPasswordDialog",
    "StatusPillDelegate",
    "SearchLineEdit",
    "section_label",
    "hint_label",
    "make_button",
    "FILTER_FIELDS",
    "FILTER_CONDITIONS",
    "build_ldap_condition",
    "build_ldap_filter",
    "describe_condition",
    "FilterBuilderBar",
]


# ============================================================================
# 颜色（深浅色自适应）
# ============================================================================

class Colors:
    """状态标签用的颜色。

    取的是「在浅色和深色底上都能看清」的中等明度色，
    不跟随主题切换 —— 状态色一旦跟着主题变，"红色=异常"的直觉就没了。
    """

    OK = SEMANTIC["success"]         # 已启用
    DANGER = SEMANTIC["danger"]      # 已锁定 / 失败
    WARN = SEMANTIC["warning"]       # 已禁用 / 警告
    INFO = SEMANTIC["info"]          # 中性信息
    MUTED = "#8A8A8E"                # 次要 / 无数据

    @staticmethod
    def for_level(level: str) -> str:
        return {
            "ok": Colors.OK, "success": Colors.OK,
            "danger": Colors.DANGER, "error": Colors.DANGER,
            "warn": Colors.WARN, "warning": Colors.WARN,
            "info": Colors.INFO,
        }.get(level, Colors.MUTED)


# ============================================================================
# 「使用者可见的提示」的落盘（**全项目唯一的实现**）
# ============================================================================

#: 提示级别 → **日志**级别。
#:
#: 键 = 界面侧实际用的级别别名（与 `Colors.for_level` 认的是**同一套词汇**）。
#: ⚠️ **只有这一份映射**（唯一使用者是 `ui_browser.notify`）。
#:    2026-09-16 之前 `ui_share` 也走它，那个模块已随「操作共享盘」功能整体删除。
#:    立这条不变式的理由仍然成立：两个窗口各写一份的下场是
#:    「一边把 `danger` 记成 INFO、另一边记成 ERROR」，排障时按级别筛行就会漏
#:    —— 界面上的失败在日志里**按 ERROR 找不着**。
NOTIFY_LOG_LEVELS: dict[str, int] = {
    "danger": logging.ERROR,      # 使用者可见的失败 ⇒ 排障第一眼要找的行
    "error": logging.ERROR,
    "warn": logging.WARNING,
    "warning": logging.WARNING,
    "ok": logging.INFO,
    "success": logging.INFO,
    "info": logging.INFO,
}

#: 落盘行的统一前缀。诊断包按它把「使用者当时看到什么」单独抽成一节。
NOTIFY_LOG_PREFIX = "[提示]"


def log_notify(logger: logging.Logger, text: str, level: str = "info") -> None:
    """把一条**使用者可见的提示**记进日志。**全项目唯一的实现。**

    为什么需要它（本项目实测）：
        `ui_browser.py` 曾经是「`_log` 定义了却**一次都没被调用**」。
        后端（`workers`）会记任务失败，但**使用者当场看到的那些失败**
        （读取对象失败 / 保存权限组失败 / 导出失败 / 本地预检不通过……）
        只弹一个 Toast，`app.log` 里**一行都没有** ⇒
        主理人在真域实测报错后来问，日志里查不到对应现场。

    为什么不加「只记失败」的过滤：排障时主理人引用的原话常常是
        「我点了保存，它提示成功了」—— 只留失败行的话，恰恰少了能证明
        「他当时看到的是什么」的那一半。本项目是低频管理台，量不是问题。

    ⚠️ `level` 不认识时落到 **INFO**，而不是不记：`Colors.for_level` 对未知级别
        是"给个中性色"，日志这边必须保证**不丢** —— 丢了就等于这次操作在日志里
        根本不存在。**级别不准可以接受，丢才是排障时不可接受的。**
    """
    logger.log(NOTIFY_LOG_LEVELS.get(level, logging.INFO),
               "%s %s：%s", NOTIFY_LOG_PREFIX, level, text)


def section_label(text: str) -> QLabel:
    """小标题（用于面板分组）。"""
    label = QLabel(text)
    font = QFont()
    font.setPointSize(8)
    label.setFont(font)
    label.setStyleSheet(f"color: {Colors.MUTED};")
    return label


def hint_label(text: str = "") -> QLabel:
    """灰色提示文字。"""
    label = QLabel(text)
    label.setWordWrap(True)
    label.setStyleSheet(f"color: {Colors.MUTED};")
    return label


def make_button(text: str, primary: bool = False,
                danger: bool = False) -> QPushButton:
    """统一按钮工厂。主按钮加重，危险操作标红。"""
    button = QPushButton(text)
    button.setCursor(Qt.CursorShape.PointingHandCursor)
    if primary:
        button.setDefault(True)
        button.setStyleSheet(
            "QPushButton { background: #4F46E5; color: #FFFFFF;"
            " border: none; border-radius: 6px; padding: 5px 14px; }"
            "QPushButton:hover { background: #4338CA; }"
            "QPushButton:disabled { background: #A5A3C9; color: #EDEDF7; }")
    elif danger:
        button.setStyleSheet(
            f"QPushButton {{ color: {Colors.DANGER}; padding: 5px 12px; }}")
    return button


# ============================================================================
# Toast：右下角轻提示（非模态、自动消失）
# ============================================================================

class Toast(QFrame):
    """浮在父窗口右下角的提示条。

    为什么不用 QMessageBox：批量操作一次会报 N 条结果，
    用模态框会逼使用者点 N 次「确定」。这里只报一行总账，
    明细留在页面上的结果面板里。

    ⚠️ 它是**点击穿透**的（``WA_TransparentForMouseEvents``）。
    原先设成 False，结果发现它正好压在右侧内联面板的底部按钮上 ——
    提示条还在的那 4 秒里，「复制失败明细」「创建」这类按钮点了没反应，
    而且从界面上完全看不出是被一块提示条挡了。提示条自己没有任何
    可点元素，让点击落到底下的真按钮上才是对的。
    """

    _MARGIN = 18
    #: 常规宽度。文案长时按需放宽到 ``_MAX_WIDTH`` —— 固定宽度会把一段
    #: 4 行的错误挤成又高又窄的一条。
    _WIDTH = 360
    _MAX_WIDTH = 560
    #: label 之外的横向开销：左右边距 12+12、间距 9、左侧色条 3。
    #: 算换行高度时必须减掉它，否则宽度估大、行数估少、还是要裁。
    _CHROME_W = 12 + 12 + 9 + 3

    def __init__(self, parent: QWidget, bottom_gap: int = 28):
        """``bottom_gap``：距父容器底边的像素数。

        主窗口用默认值即可（避开状态栏）。浏览页要传大一些 ——
        右侧内联面板的按钮行就贴在底边，用默认值会让提示条正好
        盖在「创建」「复制失败明细」这些按钮上（虽然点击能穿透，
        但按钮看不见会让人以为操作入口没了）。
        """
        super().__init__(parent)
        self.setObjectName("toast")
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self.setFixedWidth(self._WIDTH)
        self._bottom_gap = bottom_gap

        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 9, 12, 9)
        layout.setSpacing(9)

        self._bar = QFrame()
        self._bar.setFixedWidth(3)
        layout.addWidget(self._bar)

        self._label = QLabel()
        self._label.setWordWrap(True)
        self._label.setSizePolicy(QSizePolicy.Policy.Expanding,
                                  QSizePolicy.Policy.Preferred)
        layout.addWidget(self._label, 1)

        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.hide)

        self.hide()
        parent.installEventFilter(self)

    # ---------- 对外 ----------

    def show_message(self, text: str, level: str = "info",
                     msec: int = 4000) -> None:
        color = Colors.for_level(level)
        self._bar.setStyleSheet(f"background: {color}; border-radius: 1px;")
        self._label.setText(text)
        self._label.setStyleSheet("color: palette(text);")
        self.setStyleSheet(
            "QFrame#toast { background: palette(window);"
            " border: 1px solid palette(mid); border-radius: 8px; }")

        # 🔒 必须**先定宽，再按这个宽度把 label 的高度算准**。
        #    QLabel 开了 wordWrap 之后 `sizeHint()` 返回的是「不换行要的宽度
        #    （实测 468）+ 一个偏小的高度」，而 `adjustSize()` 正好采信那个
        #    偏小的高度：
        #        4 行错误文案需要 138px，实际只给了 110px → 最后两行被裁掉；
        #        2 行文案需要 68px，只给了 54px → 第二行被切一半。
        #    使用者看到的就是「提示框太小、文字被挡住了」。
        #    正确做法是拿 `heightForWidth()` 问一次真实高度。
        #
        # 🔴 但 `setFixedHeight()` **同时钉住 min 与 max**，而 `heightForWidth()`
        #    的结果会被 clamp 进 `[min, max]` ⇒ 下面那句定高**只增不减**：
        #    上一轮那条长文案算出 96px 之后，短文案算出 12px 也会被顶回 96px
        #    ⇒ **「提示的窗口只有一句话，窗口显示很大」**（主理人 2026-09-16 实测）。
        #    `Toast` 在主窗口 / 浏览页都是**常驻实例** ⇒ 一旦被撑大就是**会话级**：
        #    连一次域控失败的长提示，之后所有短提示都被撑大，而且**永远回不去**。
        #    ⇒ 所以每次进来先把上一轮的约束清回无约束，再重新定高。
        #    ⚠️ **宽度不用管** —— `_fit_width()` 是直接按当前文案算的，不读控件现状
        #    （实测：长后短，宽度必定回到 360）。**只有高度**依赖控件当前状态。
        #    守卫：`tests/test_ui_toast.py::TestHeightMustShrinkBack`
        #    （反证 C143 / C144 是 🟥 审查跑通的**猴子补丁版**，不需要改本文件）。
        self._label.setMinimumHeight(0)
        self._label.setMaximumHeight(QWIDGETSIZE_MAX)

        width = self._fit_width(text)
        self.setFixedWidth(width)
        self._label.setFixedHeight(
            self._label.heightForWidth(max(40, width - self._CHROME_W)))
        self.adjustSize()
        # 布局跑完后再按 label 的**真实**宽度校一次：上一步估的是可用宽度，
        # Qt 还要扣掉自己的内边距 —— 估算 524 / 实际 522，差这 2px 就可能
        # 少算一行，而断言是按真实宽度量的，于是守卫会随机地红。
        self._label.setFixedHeight(self._label.heightForWidth(self._label.width()))
        self.adjustSize()
        self.reposition()
        self.show()
        self.raise_()
        self._timer.start(max(1500, msec))

    def _fit_width(self, text: str) -> int:
        """短文案用常规宽度；长文案（含换行）放宽，封顶 ``_MAX_WIDTH``。"""
        if "\n" in text or len(text) > 60:
            return self._MAX_WIDTH
        return self._WIDTH

    def ok(self, text: str) -> None:
        self.show_message(text, "ok")

    def error(self, text: str) -> None:
        self.show_message(text, "danger", msec=7000)

    def warn(self, text: str) -> None:
        self.show_message(text, "warn", msec=5500)

    # ---------- 跟随父窗口 ----------

    def reposition(self) -> None:
        parent = self.parentWidget()
        if parent is None:
            return
        x = max(0, parent.width() - self.width() - self._MARGIN)
        y = max(0, parent.height() - self.height() - self._MARGIN
                - self._bottom_gap)
        self.move(x, y)

    def eventFilter(self, obj: QObject, event: QEvent) -> bool:  # noqa: N802
        if obj is self.parentWidget() and event.type() in (
                QEvent.Type.Resize, QEvent.Type.Move):
            if self.isVisible():
                self.reposition()
        return super().eventFilter(obj, event)


# ============================================================================
# InlinePanel：内联面板（替代模态对话框）
# ============================================================================

class InlinePanel(QFrame):
    """带标题栏、内容区、底部按钮的内联面板。

    用法::

        panel = InlinePanel("新建用户")
        panel.body.addWidget(...)
        panel.accepted.connect(self._do_create)
        panel.show_panel()

    ``body`` 是可直接塞控件的 QVBoxLayout。
    """

    accepted = pyqtSignal()
    rejected = pyqtSignal()

    def __init__(self, title: str = "", parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("inlinePanel")
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setStyleSheet(
            "QFrame#inlinePanel { background: palette(window);"
            " border: 1px solid palette(mid); border-radius: 8px; }")

        outer = QVBoxLayout(self)
        outer.setContentsMargins(14, 11, 14, 11)
        outer.setSpacing(9)

        head = QHBoxLayout()
        head.setSpacing(8)
        self._title = QLabel(title)
        title_font = QFont()
        title_font.setPointSize(10)
        title_font.setWeight(QFont.Weight.DemiBold)
        self._title.setFont(title_font)
        head.addWidget(self._title)
        head.addStretch(1)

        self._close = QPushButton("关闭")
        self._close.setFlat(True)
        self._close.setCursor(Qt.CursorShape.PointingHandCursor)
        self._close.setStyleSheet(f"color: {Colors.MUTED}; padding: 2px 8px;")
        self._close.clicked.connect(self._on_reject)
        head.addWidget(self._close)
        outer.addLayout(head)

        self._subtitle = hint_label("")
        self._subtitle.hide()
        self._subtitle.setSizePolicy(QSizePolicy.Policy.Preferred,
                                     QSizePolicy.Policy.Fixed)
        outer.addWidget(self._subtitle)

        self.body = QVBoxLayout()
        self.body.setSpacing(8)
        # ⚠️ 必须给 stretch=1。否则面板被拉高时，多余的高度会落到
        #    **某一个** item 上（实测落到副标题：20px 的文案被撑成 300px，
        #    整个表单被推到面板下半部）。给 body 声明 stretch 后，
        #    多余空间由内容区统一吸收，副标题永远只是它该有的高度。
        outer.addLayout(self.body, 1)

        self._footer = QHBoxLayout()
        self._footer.setSpacing(8)
        self._footer.addStretch(1)

        self.cancel_button = QPushButton("取消")
        self.cancel_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.cancel_button.clicked.connect(self._on_reject)
        self._footer.addWidget(self.cancel_button)

        self.ok_button = make_button("确定", primary=True)
        self.ok_button.clicked.connect(self.accepted.emit)
        self._footer.addWidget(self.ok_button)

        outer.addLayout(self._footer)

    # ---------- 对外 ----------

    def set_title(self, text: str) -> None:
        self._title.setText(text)

    def set_subtitle(self, text: str) -> None:
        self._subtitle.setText(text)
        self._subtitle.setVisible(bool(text))

    def set_ok_text(self, text: str) -> None:
        self.ok_button.setText(text)

    def show_panel(self) -> None:
        self.setVisible(True)

    def hide_panel(self) -> None:
        self.setVisible(False)

    def _on_reject(self) -> None:
        self.hide_panel()
        self.rejected.emit()


# ============================================================================
# ConfirmBar：内联确认条（横向，嵌在列表上方）
# ============================================================================

class ConfirmBar(QFrame):
    """「即将对 N 个对象做 X」的确认条。

    比模态框好在：确认时**列表还看得见**，使用者能核对选中的是谁。
    """

    confirmed = pyqtSignal(str)          # 参数：输入框内容（可能为空）
    cancelled = pyqtSignal()

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("confirmBar")
        self.setStyleSheet(
            "QFrame#confirmBar { background: palette(alternate-base);"
            " border: 1px solid palette(mid); border-radius: 8px; }")

        # 两行结构：主行（说明 + 输入 + 按钮）之下再给提示文字**独占一行**。
        # 单行时提示被输入框/生成按钮挤到只剩百来像素，换行后高度又不重算，
        # 结果是文字被裁掉半截（2026-09-12 实测：「同一个密码发给多个人 ——
        # 请确认有需要」显示不全）。独占一行后它按条宽自适应，永不被挤。
        outer = QVBoxLayout(self)
        outer.setContentsMargins(12, 8, 12, 8)
        outer.setSpacing(4)

        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(9)
        outer.addLayout(layout)

        self._text = QLabel()
        self._text.setWordWrap(False)
        layout.addWidget(self._text)

        self.input = QLineEdit()
        self.input.setVisible(False)
        self.input.setMinimumWidth(200)
        self.input.returnPressed.connect(self._emit_confirm)
        layout.addWidget(self.input)

        self.gen_button = QPushButton("生成")
        self.gen_button.setVisible(False)
        self.gen_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.gen_button.clicked.connect(self._emit_generate)
        layout.addWidget(self.gen_button)

        layout.addStretch(1)

        self.ok_button = make_button("执行", primary=True)
        self.ok_button.clicked.connect(self._emit_confirm)
        layout.addWidget(self.ok_button)

        self.cancel_button = QPushButton("取消")
        self.cancel_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.cancel_button.clicked.connect(self._on_cancel)
        layout.addWidget(self.cancel_button)

        #: 独立的提示行（独占整条宽度）
        self._extra = hint_label("")
        self._extra.hide()
        outer.addWidget(self._extra)

        #: 外部可挂一个"生成随机密码"的函数
        self.generate_fn: Callable[[], str] | None = None

        self.hide()

    # ---------- 对外 ----------

    def ask(self, text: str, *, need_password: bool = False,
            extra_hint: str = "", ok_text: str = "执行") -> None:
        self._text.setText(text)
        self.input.setVisible(need_password)
        self.gen_button.setVisible(need_password and self.generate_fn is not None)
        self._extra.setText(extra_hint)
        self._extra.setVisible(bool(extra_hint))
        self.ok_button.setText(ok_text)
        if need_password:
            self.input.clear()
            self.input.setPlaceholderText("新的初始密码")
            self.input.setEchoMode(QLineEdit.EchoMode.Password)
        self.show()

    def hide_bar(self) -> None:
        self.input.clear()
        self.hide()

    def password(self) -> str:
        return self.input.text()

    # ---------- 内部 ----------

    def _emit_generate(self) -> None:
        if self.generate_fn is not None:
            self.input.setText(self.generate_fn())
            self.input.setEchoMode(QLineEdit.EchoMode.Normal)

    def _emit_confirm(self) -> None:
        self.confirmed.emit(self.input.text())

    def _on_cancel(self) -> None:
        self.hide_bar()
        self.cancelled.emit()


# ============================================================================
# 默认密码设置窗
# ============================================================================

class DefaultPasswordDialog(QDialog):
    """设置「新建用户 → 默认密码」按钮填入的那个口令。

    为什么这里破例用模态窗：这是个**跨会话的配置**（要写进配置文件），
    不是一次操作的参数 —— 必须让人明确「保存 / 取消」，
    而且要给「清除」留个明确入口。页面内的操作仍然一律内联。
    """

    def __init__(self, current: str = "", parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("设置默认密码")
        self.setMinimumWidth(430)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        layout.addWidget(section_label("默认密码"))

        row = QHBoxLayout()
        row.setSpacing(6)
        self.password = QLineEdit(current)
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText("新建用户时点「默认密码」就填这个")
        self.password.textChanged.connect(self._refresh_hint)
        row.addWidget(self.password, 1)

        self.show_plain = QCheckBox("显示")
        self.show_plain.toggled.connect(self._toggle_echo)
        row.addWidget(self.show_plain)

        gen = QPushButton("随机生成")
        gen.setCursor(Qt.CursorShape.PointingHandCursor)
        gen.setToolTip("按 AD 默认策略生成一个 14 位随机口令")
        gen.clicked.connect(self._generate)
        row.addWidget(gen)
        layout.addLayout(row)

        self.hint = hint_label("")
        layout.addWidget(self.hint)

        layout.addWidget(hint_label(
            "口令加密（DPAPI）后存在本机配置文件里，明文不落盘；"
            "换 Windows 账号或换机器后需要重设。"))

        buttons = QHBoxLayout()
        self.clear_button = make_button("清除", danger=True)
        self.clear_button.setToolTip("删除已保存的默认密码")
        self.clear_button.clicked.connect(self._on_clear)
        self.clear_button.setEnabled(bool(current))
        buttons.addWidget(self.clear_button)
        buttons.addStretch(1)
        cancel = QPushButton("取消")
        cancel.setCursor(Qt.CursorShape.PointingHandCursor)
        cancel.clicked.connect(self.reject)
        self.ok_button = make_button("保存", primary=True)
        self.ok_button.clicked.connect(self.accept)
        buttons.addWidget(cancel)
        buttons.addWidget(self.ok_button)
        layout.addLayout(buttons)

        self.password.setFocus()
        self._refresh_hint()

    # ---------- 对外 ----------

    def password_value(self) -> str:
        """确定要保存的口令（清除时返回空串）。"""
        return self.password.text()

    # ---------- 内部 ----------

    def _toggle_echo(self, show: bool) -> None:
        self.password.setEchoMode(QLineEdit.EchoMode.Normal if show
                                  else QLineEdit.EchoMode.Password)

    def _generate(self) -> None:
        self.password.setText(generate_password(14))
        self.show_plain.setChecked(True)    # 生成的口令要能看见才好抄

    def _on_clear(self) -> None:
        self.password.clear()
        self.done(2)                        # 2 = 清除（与 accept/reject 区分）

    def _refresh_hint(self) -> None:
        value = self.password.text()
        self.ok_button.setEnabled(bool(value))
        if not value:
            self.hint.setText("留空时不保存；要删掉已保存的口令请点「清除」。")
            self.hint.setStyleSheet(f"color: {Colors.MUTED};")
            return
        reason = check_password_guessability(value)
        self.hint.setText("本地预检：" + reason if reason
                          else "本地预检：看起来没问题（真实策略以域控为准）。")
        self.hint.setStyleSheet(
            f"color: {Colors.WARN if reason else Colors.OK};")


# ============================================================================
# 状态胶囊：把 QQ 风格的布尔列画成色块标签
# ============================================================================

class StatusPillDelegate(QStyledItemDelegate):
    """在单元格里画多个彩色胶囊标签。

    数据来源：``index.data(Qt.ItemDataRole.UserRole)`` 返回
    ``[(文字, 级别), ...]``，级别取 ok / warn / danger / info / muted。
    比显示 ``True / False`` 或 ``是 / 否`` 一眼能看明白。
    """

    PAD_X = 7
    PAD_Y = 2
    GAP = 5

    def paint(self, painter: QPainter, option, index) -> None:
        pills = index.data(Qt.ItemDataRole.UserRole)
        if not pills:
            super().paint(painter, option, index)
            return

        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        metrics = option.fontMetrics
        height = metrics.height() + self.PAD_Y * 2
        x = option.rect.left() + 4
        y = option.rect.top() + (option.rect.height() - height) // 2

        for text, level in pills:
            width = metrics.horizontalAdvance(text) + self.PAD_X * 2
            if x + width > option.rect.right() - 2:
                break                       # 放不下就截断，不画半个
            color = QColor(Colors.for_level(level))

            fill = QColor(color)
            fill.setAlpha(46)               # 底：同色 18% 透明
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(fill)
            painter.drawRoundedRect(x, y, width, height, 4, 4)

            painter.setPen(color)
            painter.drawText(x + self.PAD_X, y, width - self.PAD_X * 2, height,
                             int(Qt.AlignmentFlag.AlignCenter), text)
            x += width + self.GAP

        painter.restore()

    def sizeHint(self, option, index) -> QSize:  # noqa: N802
        hint = super().sizeHint(option, index)
        pills = index.data(Qt.ItemDataRole.UserRole) or []
        if pills:
            metrics = option.fontMetrics
            width = sum(metrics.horizontalAdvance(t) + self.PAD_X * 2 + self.GAP
                        for t, _ in pills)
            hint.setWidth(max(hint.width(), width + 10))
        return hint


# ============================================================================
# 搜索框：带防抖
# ============================================================================

class SearchLineEdit(QLineEdit):
    """带防抖的搜索框。

    每敲一个字符就发一次 LDAP 查询，在真实域上等于自杀 ——
    所以停 350ms 才真正触发。
    """

    submitted = pyqtSignal(str)

    def __init__(self, placeholder: str = "", delay_ms: int = 350,
                 parent: QWidget | None = None):
        super().__init__(parent)
        self.setPlaceholderText(placeholder)
        self.setClearButtonEnabled(True)
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(delay_ms)
        self._timer.timeout.connect(lambda: self.submitted.emit(self.text().strip()))
        self.textChanged.connect(lambda _t: self._timer.start())
        self.returnPressed.connect(self._fire_now)

    def _fire_now(self) -> None:
        self._timer.stop()
        self.submitted.emit(self.text().strip())

    def fire(self) -> None:
        self._fire_now()


# ============================================================================
# 高级查找条件构建器（F12 的"人类友好"入口）
# ============================================================================

#: 字段的**人类可读名 → LDAP 属性名**。顺序就是下拉里的顺序，
#: 常用的放前面。值是受信清单（不需要转义），用户输入只出现在值里。
FILTER_FIELDS: list[tuple[str, str]] = [
    ("名称 / 姓名", "cn"),
    ("登录名", "sAMAccountName"),
    ("显示名", "displayName"),
    ("描述", "description"),
    ("部门", "department"),
    ("职务", "title"),
    ("公司", "company"),
    ("电子邮件", "mail"),
    ("电话", "telephoneNumber"),
    ("UPN 登录名", "userPrincipalName"),
    ("操作系统", "operatingSystem"),
    ("位置", "location"),
    ("员工编号", "employeeID"),
]

#: 条件的人类可读名 → 运算符代号
FILTER_CONDITIONS: list[tuple[str, str]] = [
    ("包含", "contains"),
    ("等于", "equals"),
    ("开头是", "starts"),
    ("结尾是", "ends"),
    ("为空（没有这个属性）", "absent"),
    ("不为空（有这个属性）", "present"),
]

#: 构建 LDAP 子句需要先导入 ldap3 的转义器；离线测试环境可能没有，
#: 所以留一个与 ldap3 等价的兜底（只处理值里真正非法的四类字符）。
_FILTER_UNSAFE = str.maketrans({
    "\\": "\\5c", "*": "\\2a", "(": "\\28", ")": "\\29",
    "\0": "\\00",
})


def _escape_filter_value(value: str) -> str:
    try:
        from ldap3.utils.conv import escape_filter_chars
        return escape_filter_chars(value)
    except ImportError:                          # pragma: no cover - 离线环境
        return value.translate(_FILTER_UNSAFE)


def build_ldap_condition(attr: str, op: str, value: str) -> tuple[str, str]:
    """一条「属性 + 条件 + 值」→ LDAP 子句。返回 ``(子句, 中文错误)``。"""
    if not attr:
        return "", "请选择要查找的字段。"
    if op in ("absent", "present"):
        return (f"(!({attr}=*))" if op == "absent" else f"({attr}=*)"), ""
    text = (value or "").strip()
    if not text:
        return "", "这个条件需要填写比较值（「为空 / 不为空」除外）。"
    escaped = _escape_filter_value(text)
    clause = {
        "contains": f"({attr}=*{escaped}*)",
        "equals": f"({attr}={escaped})",
        "starts": f"({attr}={escaped}*)",
        "ends": f"({attr}=*{escaped})",
    }.get(op)
    if clause is None:
        return "", f"不支持的查找条件：{op}"
    return clause, ""


def build_ldap_filter(rows: list[tuple[str, str, str]],
                      logic: str = "and") -> tuple[str, str]:
    """多行条件 → 完整过滤器。返回 ``(过滤器, 中文错误)``。

    单行不包外层括号组（``(a=b)`` 而不是 ``(&(a=b))``）—— 源码可读性。
    """
    clauses: list[str] = []
    for attr, op, value in rows or []:
        clause, reason = build_ldap_condition(attr, op, value)
        if reason:
            return "", reason
        clauses.append(clause)
    if not clauses:
        return "", "请先添加至少一个查找条件。"
    if len(clauses) == 1:
        return clauses[0], ""
    joiner = "&" if (logic or "and").lower() == "and" else "|"
    return f"({joiner}{''.join(clauses)})", ""


def describe_condition(attr: str, op: str, value: str) -> str:
    """条件的中文摘要（搜索结果计数行用）。"""
    label = next((name for name, a in FILTER_FIELDS if a == attr), attr)
    op_label = next((name for name, o in FILTER_CONDITIONS if o == op), op)
    if op in ("absent", "present"):
        return f"{label} {op_label}"
    return f"{label} {op_label}「{value}」"


class FilterBuilderBar(QFrame):
    """内联的「高级查找」条件构建器 —— 替代手写 LDAP 过滤器。

    人类的使用逻辑（ADUC「查找」对话框同款）：
      选字段 → 选条件 → 填值，可加多行，行之间「且 / 或」组合。
    LDAP 源码自动生成在下方（默认只读，勾选后可直接改 —— 给懂行的人留门）。
    """

    #: (过滤器, 人类可读摘要)。摘要进搜索结果的计数行。
    search_requested = pyqtSignal(str, str)

    MAX_ROWS = 6

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("filterBuilder")
        self._rows: list[dict] = []

        outer = QVBoxLayout(self)
        outer.setContentsMargins(6, 6, 6, 6)
        outer.setSpacing(6)

        self.rows_box = QVBoxLayout()
        self.rows_box.setSpacing(4)
        outer.addLayout(self.rows_box)

        controls = QHBoxLayout()
        controls.setSpacing(8)
        self.logic_combo = QComboBox()
        self.logic_combo.addItem("满足全部条件（且）", "and")
        self.logic_combo.addItem("满足任一条件（或）", "or")
        controls.addWidget(self.logic_combo)
        add = make_button("+ 加一个条件")
        add.clicked.connect(self.add_row)
        controls.addWidget(add)
        clear = make_button("清空")
        clear.clicked.connect(self.reset)
        controls.addWidget(clear)
        self.source_toggle = QCheckBox("直接编辑 LDAP 源码")
        self.source_toggle.toggled.connect(self._on_source_toggled)
        controls.addWidget(self.source_toggle)
        controls.addStretch(1)
        find_btn = make_button("查找", primary=True)
        find_btn.clicked.connect(self.emit_search)
        controls.addWidget(find_btn)
        outer.addLayout(controls)

        self.source_edit = QLineEdit()
        self.source_edit.setReadOnly(True)
        self.source_edit.setPlaceholderText("生成的 LDAP 过滤器会显示在这里")
        self.source_edit.textEdited.connect(
            lambda _t: self.source_edit.setReadOnly(False))
        outer.addWidget(self.source_edit)

        self.hint = hint_label("")
        outer.addWidget(self.hint)

        self.add_row()

    # ---------- 行管理 ----------

    def add_row(self) -> None:
        if len(self._rows) >= self.MAX_ROWS:
            self.hint.setText(f"最多 {self.MAX_ROWS} 个条件 —— "
                              "再复杂的需求请直接编辑 LDAP 源码。")
            return
        row = QHBoxLayout()
        row.setSpacing(4)
        attr_combo = QComboBox()
        for label, attr in FILTER_FIELDS:
            attr_combo.addItem(label, attr)
        op_combo = QComboBox()
        for label, op in FILTER_CONDITIONS:
            op_combo.addItem(label, op)
        value_edit = QLineEdit()
        value_edit.setPlaceholderText("比较值")
        value_edit.returnPressed.connect(self.emit_search)
        op_combo.currentIndexChanged.connect(
            lambda _i, w=value_edit: w.setEnabled(
                self._op_needs_value(op_combo.currentData())))
        op_combo.currentIndexChanged.connect(lambda _i: self._sync_source())
        attr_combo.currentIndexChanged.connect(lambda _i: self._sync_source())
        value_edit.textChanged.connect(lambda _t: self._sync_source())
        remove = make_button("×", danger=True)
        row.addWidget(attr_combo, 2)
        row.addWidget(op_combo, 3)
        row.addWidget(value_edit, 3)
        row.addWidget(remove)

        container = QWidget()
        container.setLayout(row)
        self.rows_box.addWidget(container)

        record = {"widget": container, "attr": attr_combo, "op": op_combo,
                  "value": value_edit, "remove": remove}
        remove.clicked.connect(lambda: self._remove_row(record))
        self._rows.append(record)
        self._refresh_remove_buttons()
        self._sync_source()

    def _remove_row(self, record: dict) -> None:
        if len(self._rows) <= 1:
            return
        if record in self._rows:
            self._rows.remove(record)
        record["widget"].deleteLater()
        self._refresh_remove_buttons()
        self._sync_source()

    def _refresh_remove_buttons(self) -> None:
        for record in self._rows:
            record["remove"].setVisible(len(self._rows) > 1)

    def reset(self) -> None:
        for record in list(self._rows):
            self._remove_row(record)
        self.source_toggle.setChecked(False)
        self.hint.setText("")

    @staticmethod
    def _op_needs_value(op: str | None) -> bool:
        return op not in ("absent", "present")

    # ---------- 构建 ----------

    def _row_tuples(self) -> list[tuple[str, str, str]]:
        return [(r["attr"].currentData(), r["op"].currentData(),
                 r["value"].text()) for r in self._rows]

    def _sync_source(self) -> None:
        if self.source_toggle.isChecked():
            return                      # 源码模式下让使用者自由编辑
        flt, reason = build_ldap_filter(self._row_tuples(),
                                        self.logic_combo.currentData())
        if not reason:
            self.source_edit.setText(flt)

    def _on_source_toggled(self, on: bool) -> None:
        self.source_edit.setReadOnly(not on)
        if not on:
            self._sync_source()

    def emit_search(self) -> None:
        """点「查找」。源码模式用源码原文（本地配平校验交给页面）。"""
        if self.source_toggle.isChecked():
            text = self.source_edit.text().strip()
            if not text:
                self.hint.setText("源码是空的 —— 先写一个过滤器。")
                return
            self.search_requested.emit(text, f"LDAP：{text}")
            return
        flt, reason = build_ldap_filter(self._row_tuples(),
                                        self.logic_combo.currentData())
        if reason:
            self.hint.setText(reason)
            return
        self.hint.setText("")
        desc = " 且 ".join(
            describe_condition(a, o, v) for a, o, v in self._row_tuples()
            if o in ("absent", "present") or (v or "").strip())
        self.search_requested.emit(flt, desc)

    def summary(self) -> str:
        return " 且 ".join(
            describe_condition(a, o, v) for a, o, v in self._row_tuples()
            if o in ("absent", "present") or (v or "").strip())
