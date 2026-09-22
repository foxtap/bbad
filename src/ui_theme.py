# -*- coding: utf-8 -*-
"""
ui_theme.py —— 主题层（T05）

> **不造轮子**：浅/深色 QSS 全套交给 `pyqtdarktheme`，
> 本文件只做三件事：① 包一层容错 ② 注入主色 ③ 记住用户选择。

关于包名：PyPI 上的 `pyqtdarktheme` 是**另一个老项目**（0.1.x，只支持 Qt5，
API 是 `load_stylesheet`）。支持 Qt6 的是维护中的 fork
**`pyqtdarktheme-fork`**（import 名仍是 `qdarktheme`，2.3.x）。
requirements.txt 里写的就是 fork 版。
"""

from __future__ import annotations

from utils import get_logger

__all__ = ["THEME_LIGHT", "THEME_DARK", "THEME_AUTO", "BRAND_PRIMARY", "apply_theme"]

_log = get_logger("theme")

THEME_LIGHT = "light"
THEME_DARK = "dark"
THEME_AUTO = "auto"

#: 主色。与帮帮报修系统后台保持一致（靛蓝紫），
#: 这样两个工具放在一起看不出是两套东西。
#:
#: ⚠️ 必须**分主题给两个值**：同一个 #4F46E5 在深色底（#202124）上偏暗，
#: 按钮文字对比度不够；深色下要用提亮过的 #818CF8。
BRAND_PRIMARY_LIGHT = "#4F46E5"
BRAND_PRIMARY_DARK = "#818CF8"

#: 列表/树选中背景。与主色同系（靛蓝）的浅/深两档，
#: 用于修复 qdarktheme + windows11 样式叠加下、QTreeView 选中行的
#: 「branch 区被切成一截截蓝竖条」的渲染缺陷（见 tests 回归与截图验收）。
SELECTION_BG_LIGHT = "#E0E7FF"                  # indigo-100：浅底深字
SELECTION_BG_DARK = "#312E81"                   # indigo-900：深底浅字

#: 兼容旧引用
BRAND_PRIMARY = BRAND_PRIMARY_LIGHT

#: 自定义配色。pyqtdarktheme 的合法 color id 形如 ``background`` /
#: ``primary`` / ``primary>base``（``>`` 表示嵌套子键），
#: 没有 ``danger`` 这种语义键 —— 状态色由 ui_widgets.Colors 自己管。
CUSTOM_COLORS = {
    "[light]": {"primary": BRAND_PRIMARY_LIGHT},
    "[dark]": {"primary": BRAND_PRIMARY_DARK},
}

#: 语义色（浅/深色共用，保证「已锁定」这类状态在任何主题下都醒目）
SEMANTIC = {
    "danger": "#E24B4A",
    "warning": "#EF9F27",
    "success": "#639922",
    "info": "#378ADD",
}

#: 中文字体优先级。Windows 上「微软雅黑」最稳；退化到系统默认。
_FONT_CANDIDATES = ["Microsoft YaHei UI", "Microsoft YaHei", "Segoe UI"]

_cached_stylesheet: dict[str, str] = {}
_cached_palette: dict[str, object] = {}


def _stylesheet(theme: str) -> str:
    """取（并缓存）某个主题的 QSS。

    `setup_theme` 每次调用都会重新生成并解析一遍整份 QSS（约 1 万行），
    切换主题时会有肉眼可见的卡顿 —— 所以缓存下来，只调用一次。
    """
    if theme in _cached_stylesheet:
        return _cached_stylesheet[theme]

    try:
        import qdarktheme

        qss = qdarktheme.load_stylesheet(
            theme,
            corner_shape="rounded",
            custom_colors=CUSTOM_COLORS,
        )
        qss = qss + _tree_selection_fix(theme)
    except Exception as exc:                     # noqa: BLE001
        # 主题库挂了不能让整个应用起不来 —— 界面丑一点但能用
        _log.warning("加载主题 %s 失败，回退到默认配色：%s", theme, exc)
        qss = ""

    _cached_stylesheet[theme] = qss
    return qss


def _tree_selection_fix(theme: str) -> str:
    """修复 QTreeView/QTreeWidget 选中行的「蓝竖条」渲染缺陷。

    现象：选中树节点后，该行的缩进区（branch 格）被画成一根根蓝竖条，
    像界面坏了（截图验收抓出来的，真实 windows 平台 + qdarktheme 必现）。
    机理：qdarktheme 给 ``::branch:selected`` 单独设了背景色，再叠上
    Qt windows11 样式自带的选中指示条，两种绘制互相切片。

    修法（实验验证，见 tools 探针）：把整行（item + branch）统一刷成
    同一个选中背景色，覆盖库给的切片规则 —— ``!active`` 变体也要覆盖，
    否则窗口失焦时又回到库规则。
    """
    sel = SELECTION_BG_DARK if theme == THEME_DARK else SELECTION_BG_LIGHT
    return (
        f"QTreeView::item:selected, QTreeView::item:selected:!active,"
        f" QTreeView::branch:selected, QTreeView::branch:selected:!active"
        f" {{ background: {sel}; }}"
    )


def _palette(theme: str):
    """取（并缓存）某个主题的 QPalette。"""
    if theme in _cached_palette:
        return _cached_palette[theme]

    try:
        import qdarktheme

        pal = qdarktheme.load_palette(theme, custom_colors=CUSTOM_COLORS)
    except Exception as exc:                     # noqa: BLE001
        _log.warning("加载主题 %s 的调色板失败：%s", theme, exc)
        pal = None

    _cached_palette[theme] = pal
    return pal


def apply_theme(app, theme: str = THEME_LIGHT) -> str:
    """应用主题。返回实际生效的主题名（light / dark）。

    ``auto`` 交给系统深浅色判断。

    ⚠️ **必须同时设 palette 和 stylesheet**，两个都不能少：

    - 只设 QSS（本项目原先的写法）→ 界面会变成「一半深一半浅」：
      QSS 覆盖到的控件（菜单栏、状态栏、按钮）是深色，
      而靠 palette 取色的地方（``palette(window)``、自定义绘制的委托、
      QSS 没命中的控件）仍然是浅色。看上去像主题坏了。
    - ``qdarktheme.setup_theme()`` 内部做的就是这两件事，
      但它每次都重新生成整份 QSS，切主题会卡 —— 所以这里自己分开做并缓存。
    """
    if theme not in (THEME_LIGHT, THEME_DARK, THEME_AUTO):
        _log.warning("未知主题 %s，回退到浅色", theme)
        theme = THEME_LIGHT

    try:
        pal = _palette(theme)
        if pal is not None:
            app.setPalette(pal)
        app.setStyleSheet(_stylesheet(theme))
    except Exception as exc:                     # noqa: BLE001
        _log.warning("应用主题失败：%s", exc)

    _apply_font(app)
    return theme


def _apply_font(app) -> None:
    """设置中文字体与字号。

    不设这个，Qt 会用 9pt 的默认字体渲染中文，在高分屏上偏小且发虚。
    """
    from PyQt6.QtGui import QFont, QFontDatabase

    families = set(QFontDatabase.families())
    chosen = next((f for f in _FONT_CANDIDATES if f in families), "")
    font = QFont(chosen) if chosen else QFont()
    font.setPointSize(9)
    app.setFont(font)


def next_theme(current: str) -> str:
    """浅 ↔ 深 循环（给工具栏那个切换按钮用）。"""
    return THEME_DARK if current == THEME_LIGHT else THEME_LIGHT
