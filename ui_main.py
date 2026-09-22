# -*- coding: utf-8 -*-
"""
ui_main.py —— 主窗口

结构::

    MainWindow
    ├── QStackedWidget
    │   ├── ConnectPage      ← 未连接时（占满整个中央区，不是弹窗）
    │   └── BrowserPage      ← 已连接时
    ├── 菜单栏：文件 / 工具 / 帮助
    ├── 状态栏：状态文字 + 进度条
    └── Toast：右下角轻提示

**为什么连接页占满中央区而不是弹模态框**：
连接是这个工具唯一的前置状态，不是一个临时动作。做成模态框的话，
使用者第一次打开会看到一个空壳窗口 + 一个对话框，非常像半成品。
"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction, QKeySequence
from PyQt6.QtWidgets import (
    QDialog,
    QLabel,
    QMainWindow,
    QProgressBar,
    QStackedWidget,
    QWidget,
)

from ad_client import AdClient
from audit import AuditLog
from config import ConfigStore, logs_dir
from models import ConnConfig, DomainInfo
from ui_audit import AuditWindow
from ui_browser import BrowserPage
from ui_connect import ConnectPage
from ui_tasks import TaskBridge
from ui_theme import THEME_DARK, THEME_LIGHT, apply_theme, next_theme
from ui_widgets import Colors, Toast
from utils import AdToolError, get_logger, translate_error
from workers import TaskRunner

__all__ = ["MainWindow"]

_log = get_logger("ui_main")


class MainWindow(QMainWindow):
    """应用主窗口。"""

    def __init__(self, app, store: ConfigStore, audit: AuditLog,
                 runner: TaskRunner, parent: QWidget | None = None):
        super().__init__(parent)
        self.app = app
        self.store = store
        self.audit = audit
        self.runner = runner
        self.tasks = TaskBridge(runner)

        self.client = None
        self.theme = store.app.theme or THEME_LIGHT
        self._audit_window: AuditWindow | None = None
        #: 演示模式的人为延迟（让忙碌态看得见）。测试里会调成 0。
        self.demo_latency = 0.25

        # 对外显示名 = 「帮帮AD域管理工具」（2026-09-22 定名）。
        # 🔴 只改**显示名**。`config.APP_DIR_NAME` 那个 `AD域管理工具` 是**数据目录名**，
        #    改了它 ⇒ 程序换个目录启动 ⇒ 已缓存的连接信息一条都看不见。
        #    两个名字管两件事，别一起改。
        self.setWindowTitle("帮帮AD域管理工具")
        self.resize(1240, 780)
        self.setMinimumSize(980, 620)

        self._build_menu()
        self._build_central()
        self._build_status_bar()

        self.toast = Toast(self)
        self.tasks.on_started = self._on_task_started
        self.tasks.on_finished = self._on_task_finished
        self.runner.progress.connect(self._on_progress)

    # ==================================================================
    # 构建
    # ==================================================================

    def _build_menu(self) -> None:
        file_menu = self.menuBar().addMenu("文件(&F)")

        disconnect = QAction("断开当前连接(&D)", self)
        disconnect.setShortcut(QKeySequence("Ctrl+D"))
        disconnect.triggered.connect(self._disconnect)
        file_menu.addAction(disconnect)

        reconnect = QAction("刷新(&R)", self)
        reconnect.setShortcut(QKeySequence("F5"))
        reconnect.triggered.connect(self._refresh)
        file_menu.addAction(reconnect)

        file_menu.addSeparator()
        quit_action = QAction("退出(&Q)", self)
        quit_action.setShortcut(QKeySequence("Ctrl+Q"))
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)

        tools_menu = self.menuBar().addMenu("工具(&T)")

        # ⚠️ 2026-09-16：这里的「共享盘权限编辑器」入口**已整体删除**（已定
        #    「把操作共享盘这个功能全部删除掉」，共享盘权限改由使用者**自己远程
        #    登录文件服务器**处理）。连同 `ui_share.py` / `share_editor.py` /
        #    `share_backend.py` 三个模块与本项一起销掉 ⇒ 本菜单**不含任何共享盘入口**。
        audit_action = QAction("操作日志(&L)", self)
        audit_action.setShortcut(QKeySequence("Ctrl+L"))
        audit_action.triggered.connect(self._show_audit)
        tools_menu.addAction(audit_action)

        # 「强制复制同步」—— 2026-09-17 已定（方案 C）新增。
        #
        # 它服务的是那条**拓扑事实**：AD 是多主复制，写入点与读取点不是同一台时，
        # 新建/删除要等复制过去，才会在文件服务器的「选择用户或组」里搜得到
        # （同站点约 15 秒，跨站点默认 180 分钟）。
        #
        # ⚠️ 它是**按需**入口，不是"自动那条路"的开关：连接上那个
        # `sync_after_change` 管的是"每次变更后**自动**尝试推一次"，而本工具常
        # 跑在**未加域**的机器上（`repadmin` 只吃域名不吃 IP、本机也解析不了
        # 域控名）⇒ 自动那条路**必然失败**，只会每次操作后刷一条提示。
        # ⇒ 默认改成"不自动推"（见 `models.ConnConfig.sync_after_change`），
        #    要推的时候**按这里**。
        sync_action = QAction("强制复制同步(&S)", self)
        sync_action.setStatusTip(
            "对当前连接推一次 AD 复制同步（repadmin /syncall … /AdeP）——"
            "把刚写完的改动立刻交给这台域控的复制伙伴，不必等复制周期")
        sync_action.triggered.connect(self._sync_replication)
        tools_menu.addAction(sync_action)

        open_dir = QAction("打开配置与日志目录(&O)", self)
        open_dir.triggered.connect(self._open_app_dir)
        tools_menu.addAction(open_dir)

        # 一键诊断包 —— 2026-09-16 加。
        #
        # 它服务的是一个**具体的闭环**：使用者在真域里测、出了错，而排障的人
        # 拿不到他的屏幕，只能听他描述（"它说我没权限"），而日志里写着
        # `LDAP_UNWILLING_TO_PERFORM(80)` —— 两边说的不是一回事，于是来回猜。
        # 有了这一项，他**点一下**就能产出一个可发送的文件。
        #
        # ⚠️ 刻意**不**做成"自动上传/自动发邮件"：工具不该往外发任何东西。
        #    它只把文件放进自己的日志目录，发不发由人决定。
        diag_action = QAction("导出诊断包(&G)…", self)
        diag_action.setStatusTip(
            "把环境快照 / 提示记录 / app.log / crash.log / 审计日志打成一个文件，"
            "排障时把它发给维护的人")
        diag_action.triggered.connect(self._export_diagnostics)
        tools_menu.addAction(diag_action)

        tools_menu.addSeparator()
        self.theme_action = QAction("切换深浅色(&T)", self)
        self.theme_action.setShortcut(QKeySequence("Ctrl+T"))
        self.theme_action.triggered.connect(self._toggle_theme)
        tools_menu.addAction(self.theme_action)

        help_menu = self.menuBar().addMenu("帮助(&H)")
        about = QAction("关于(&A)", self)
        about.triggered.connect(self._show_about)
        help_menu.addAction(about)

    def _build_central(self) -> None:
        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)

        self.connect_page = ConnectPage(self.store)
        self.connect_page.test_requested.connect(self._test_connection)
        self.connect_page.connect_requested.connect(self._connect)
        self.connect_page.demo_requested.connect(self._start_demo)
        self.stack.addWidget(self.connect_page)          # 0

        self.browser_page: BrowserPage | None = None
        self.stack.setCurrentIndex(0)

    def _build_status_bar(self) -> None:
        bar = self.statusBar()

        self.status_label = QLabel("就绪")
        bar.addWidget(self.status_label, 1)

        self.progress = QProgressBar()
        self.progress.setMaximumWidth(220)
        self.progress.setMaximumHeight(14)
        self.progress.setTextVisible(False)
        self.progress.setVisible(False)
        bar.addPermanentWidget(self.progress)

        self.env_label = QLabel("")
        self.env_label.setStyleSheet(f"color: {Colors.MUTED};")
        bar.addPermanentWidget(self.env_label)

    # ==================================================================
    # 启动
    # ==================================================================

    def start(self) -> None:
        """应用启动后调一次：恢复上次的主题与配置。"""
        apply_theme(self.app, self.theme)
        self.connect_page.reload()

        count = len(self.store.app.connections)
        if count:
            # 自动选上次用过的，或者第一条 —— 少点一次鼠标
            index = self._startup_index()
            self.connect_page.saved_list.setCurrentRow(index)
            self._say(f"已载入 {count} 条连接配置，选中「"
                      f"{self.store.app.connections[index].display_name()}」。")
        else:
            self._say("请填写域控 IP、账号、密码后点「连接」；"
                      "没有域控可以点右下角「用演示数据体验」。")

        self.env_label.setText(f"日志：{logs_dir()}")

    def _startup_index(self) -> int:
        """「上次用的那条」在列表里的位置；认不出来就返回 0（第一条）。

        ⚠️ 两次匹配的**顺序**是判据的一部分：

        1. 先按**身份**（`ConnConfig.id`）—— 这是现在写进去的形态；
        2. 再按名字 / IP 字符串 —— 老配置文件里 `last_used` 存的就是它。

        为什么"再"：名字和 IP 都是使用者随手能改的，改一次 `last_used`
        就落空，于是"上次用的那条"静默退回第一条 —— 而这种回退不会报错，
        只会让人以为"工具记不住我选的"。身份不会因为改名而失效。
        字符串那一支**原样保留**（含空串会匹配到匿名配置这种旧行为），
        免得升级之后老配置的选中态跟以前不一样。
        """
        last = self.store.app.last_used
        conns = self.store.app.connections
        for i, cfg in enumerate(conns):
            if cfg.id and cfg.id == last:
                return i
        for i, cfg in enumerate(conns):
            if cfg.name == last or cfg.dc_ip == last:
                return i
        return 0

    # ==================================================================
    # 连接
    # ==================================================================

    def _test_connection(self, cfg: ConnConfig) -> None:
        problem = self._validate(cfg)
        if problem:
            self.connect_page.set_result(False, problem)
            return

        # 日志里要能看出"用户点了什么"（排障时先对齐现场，再看后端细节）
        _log.info("[UI] 点击「测试连接」dc=%s port=%s ssl=%s user=%s",
                  cfg.dc_ip, cfg.port, cfg.use_ssl, cfg.bind_user)
        self.connect_page.set_busy(True, "正在探测域信息并验证凭据…")
        self._say("正在测试连接…")

        def job():
            info = self._probe(cfg)
            client = AdClient(audit=None)
            ok, message = client.test_connection(cfg)
            return info, ok, message

        self.tasks.submit("测试连接", job,
                          self._on_test_done, self._on_test_failed)

    def _on_test_done(self, payload) -> None:
        info, ok, message = payload
        self.connect_page.set_busy(False)
        if ok:
            self.connect_page.show_domain_info(info)
            self.connect_page.set_result(True, f"{message}　·　凭据验证通过")
            self.toast.ok("连接测试通过。")
            self._say("连接测试通过。")
            _log.info("[UI] 测试连接结果：成功 %s", message)
        else:
            self.connect_page.set_result(False, message)
            self._say("连接测试失败。")
            self.toast.error(message)
            _log.warning("[UI] 测试连接结果：失败（用户看到的就是下面这句）%s", message)

    def _on_test_failed(self, message: str, code: str) -> None:
        self.connect_page.set_busy(False)
        self.connect_page.set_result(False, message)
        self._say("连接测试失败。")
        _log.error("[UI] 测试连接异常终止 code=%s message=%s", code, message)

    def _connect(self, cfg: ConnConfig) -> None:
        problem = self._validate(cfg)
        if problem:
            self.connect_page.set_result(False, problem)
            return

        _log.info("[UI] 点击「连接域控」dc=%s port=%s ssl=%s user=%s "
                  "手填 domain=%s base_dn=%s",
                  cfg.dc_ip, cfg.port, cfg.use_ssl, cfg.bind_user,
                  cfg.domain or "（空）", cfg.base_dn or "（空）")
        self.connect_page.set_busy(True, "正在连接…")
        self._say("正在连接域控…")
        client = AdClient(audit=self.audit)

        self.tasks.submit(
            "连接域控", client.connect,
            lambda info, c=client, cfg=cfg: self._on_connected(c, cfg, info),
            self._on_connect_failed, cfg)

    def _on_connected(self, client, cfg: ConnConfig, info: DomainInfo) -> None:
        self.client = client
        self.connect_page.set_busy(False)
        self.connect_page.show_domain_info(info)
        # 顺序要紧：先落配置（`persist_current` 顺带把这条记录的**身份**
        # 装进页面），再记「上次用的是哪条」—— 记的是身份，不是名字/IP。
        self.connect_page.persist_current()
        self.store.app.last_used = self.connect_page.current_connection_key()
        self._enter_browser(client, is_mock=False)
        if info and info.ok:
            self._say(f"已连接 {info.dns_domain or cfg.dc_ip}　"
                      f"BaseDN {info.base_dn}")
            self.toast.ok(f"已连接：{info.dns_domain or cfg.dc_ip}")
        else:
            self._say("已连接。")

    def _on_connect_failed(self, message: str, code: str) -> None:
        self.connect_page.set_busy(False)
        self.connect_page.set_result(False, message)
        self._say("连接失败。")
        self.toast.error(message)
        # 把「用户看到的那句话」也落进日志 —— 排障时先确认在说的是同一件事，
        # 再往下翻后端细节（code 是 translate_error 给的异常类型名/错误码）
        _log.error("[UI] 连接失败（弹给用户看的原文）：code=%s message=%s",
                   code, message)

    def _start_demo(self) -> None:
        """进入演示模式：用假数据把整套界面跑起来。"""
        from mock_client import MockAdClient

        self.connect_page.set_busy(True, "正在载入演示数据…")
        client = MockAdClient(audit=self.audit, latency=self.demo_latency)
        cfg = ConnConfig(dc_ip="192.0.2.10", bind_user="DEMO\\zhangsan",
                         password="demo", name="演示域")

        self.tasks.submit(
            "载入演示数据", client.connect,
            lambda info, c=client: self._on_demo_ready(c, info),
            self._on_connect_failed, cfg)

    def _on_demo_ready(self, client, info: DomainInfo) -> None:
        self.client = client
        self.connect_page.set_busy(False)
        self._enter_browser(client, is_mock=True)
        self._say("演示模式：数据全部是假的，任何操作都不会影响真实域。")
        self.toast.warn("演示模式已开启 —— 所有数据都是假的，随便点。")

    def _enter_browser(self, client, is_mock: bool) -> None:
        if self.browser_page is not None:
            self.stack.removeWidget(self.browser_page)
            self.browser_page.deleteLater()

        page = BrowserPage(client, self.tasks, settings=self.store)
        page.disconnect_requested.connect(self._disconnect)
        page.audit_requested.connect(self._show_audit)
        page.theme_requested.connect(self._toggle_theme)
        page.status_message.connect(self._say)
        self.stack.addWidget(page)
        self.browser_page = page
        self.stack.setCurrentWidget(page)
        page.start(client.info, is_mock=is_mock)

    def _disconnect(self) -> None:
        if self.browser_page is not None and self.tasks.is_busy():
            # 被**拒绝**的动作也要留一行：排障时"我点了断开，它没反应"这类
            # 反馈，靠的就是这一条（否则日志里只有"用户什么都没点"）。
            _log.info("[UI] 拒绝断开：仍有任务在执行")
            self.toast.warn("还有任务在执行，请等它结束再断开。")
            return
        # ⚠️ 先记住"断开之前到底连没连"：下面会把 client 置 None、把浏览页
        #    删掉，之后就没法判断了 —— 而末尾那句状态播报**依赖**它
        #    （无条件播报会在"本就没连"时谎报一次状态变更）。
        was_connected = self.client is not None or self.browser_page is not None
        if self.client is not None:
            try:
                self.client.disconnect()
            except Exception as exc:                 # noqa: BLE001
                _log.warning("断开连接时出错：%s", exc)
            self.client = None

        if self.browser_page is not None:
            self.stack.removeWidget(self.browser_page)
            self.browser_page.deleteLater()
            self.browser_page = None

        self.stack.setCurrentIndex(0)
        self.connect_page.set_busy(False)
        self.connect_page.hide_result()
        # ⚠️ 原来这里**无条件**说"已断开连接。" —— 而 Ctrl+D 在本就没连接时
        #    也能按，于是它会**谎报一次状态变更**（"我刚刚断开了"其实没有）。
        #    判据要在动状态**之前**取：下面已经把 client 置 None、把浏览页删了，
        #    之后就没法回答"刚才到底连没连"。
        self._say("已断开连接。" if was_connected else "当前没有连接，无需断开。")

    # ==================================================================
    # 工具
    # ==================================================================

    def _refresh(self) -> None:
        if self.browser_page is not None:
            self.browser_page.refresh()
            return
        # ⚠️ 没连接时**必须说一句**（与 `_sync_replication` 同一条纪律）：
        #    F5 是最容易被随手按的键，静默什么都不做会被读成"卡住了"，
        #    而日志里连"他按过"都查不到。
        _log.info("[UI] 拒绝刷新：当前没有连接")
        self.toast.warn("还没有连接域 —— 先连接，再刷新。")

    def _sync_replication(self) -> None:
        """菜单「工具 → 强制复制同步」：**按需**推一次（不看连接上那个自动开关）。

        ⚠️ 没连接时**必须说一句**，不许静默什么都不做 —— 本菜单项与「操作日志」
        「导出诊断包」一样**不做 enable 管理**（保持一致），静默会让使用者以为
        "点了没反应"，而日志里连"他点过"都查不到。
        """
        page = self.browser_page
        if page is None:
            _log.info("[UI] 拒绝强制复制同步：当前没有连接")
            self.toast.warn("还没有连接域控 —— 先连接，再推复制同步。")
            return
        _log.info("[UI] 点击「强制复制同步」")
        page.sync_replication_now()

    def _show_audit(self) -> None:
        # 非模态：日志要能"边看边操作"
        if self._audit_window is None:
            self._audit_window = AuditWindow(self.audit, self)
            self._audit_window.finished.connect(self._on_audit_closed)
        self._audit_window.reload()
        self._audit_window.show()
        self._audit_window.raise_()
        self._audit_window.activateWindow()

    def _on_audit_closed(self, _result: int) -> None:
        self._audit_window = None

    # ⚠️ 2026-09-16：`_show_share_editor()` / `_on_share_editor_closed()` 与
    #    `ui_share.ShareEditorWindow` 一起**整体删除**（已定：操作共享盘这个
    #    功能全部不要了）。上面菜单里也没有恢复它的入口 —— 不要照着旧版加回来。

    def _open_app_dir(self) -> None:
        import os
        import subprocess

        path = os.path.dirname(self.store.path)
        _log.info("[UI] 打开配置与日志目录：%s", path)
        try:
            os.startfile(path)                       # noqa: S606 - 打开资源管理器
        except AttributeError:
            subprocess.Popen(["explorer", path])     # noqa: S607
        except OSError as exc:
            # ⚠️ 这条以前只弹 Toast、**不落盘** —— 而它恰恰是"我打不开日志目录"
            #    这种求助里最该有的那一行（否则连日志在哪都无从查起）。
            _log.error("[UI] 打开配置与日志目录失败 path=%s：%s", path, exc)
            self.toast.error(f"打开目录失败：{exc}")

    def _export_diagnostics(self) -> None:
        """一键导出诊断包 —— 供「真域报错 → 把日志发给维护的人」这条闭环用。

        ⚠️ 日志路径从 `utils.bootstrap_logging()` 拿，**不自己 join "app.log"**：
            "日志文件叫什么名"只该由 `setup_logging` 的默认参数决定；
            别处再拼一次就多出一份会漂的实现（本项目踩过：手写路径漏了
            `logs\\` 子目录 ⇒ 永远"文件不存在"，而文件就在旁边）。
            `bootstrap_logging()` 是幂等的：已配置过就直接返回路径。

        ⚠️ 这个动作**不做成后台任务**：它只读几百行文本，几十毫秒的事。
            交给 TaskRunner 反而要处理"任务还在跑时断开"之类的边界，
            得不偿失。失败也**不弹模态框**（与全项目的内联优先一致）。
        """
        import diag
        import os                                   # noqa: PLC0415 - 本模块顶层不 import os
        from config import logs_dir
        from utils import bootstrap_logging

        dest = logs_dir()
        log_path = bootstrap_logging()
        try:
            path = diag.write_diagnostics(
                dest, log_path=log_path, audit_dir=dest)
        except Exception as exc:                     # noqa: BLE001
            # 导不出来是**真失败**（他正要拿它来求助）⇒ 必须落盘 + 让人看见
            _log.error("导出诊断包失败 dest=%s：%s", dest, exc, exc_info=True)
            self.toast.error(f"导出诊断包失败：{exc}")
            self._say("导出诊断包失败。")
            return

        size = os.path.getsize(path) if os.path.exists(path) else 0
        _log.info("已导出诊断包：%s（%d 字节）", path, size)
        self.toast.ok(f"诊断包已导出：{path}")
        self._say(f"诊断包已导出（{size} 字节）：{path}")

    def _toggle_theme(self) -> None:
        self.theme = next_theme(self.theme)
        apply_theme(self.app, self.theme)
        self.store.app.theme = self.theme
        try:
            self.store.save()
        except Exception as exc:                     # noqa: BLE001
            _log.warning("主题偏好保存失败：%s", exc)
        self._say("已切换到" + ("深色" if self.theme == THEME_DARK else "浅色") + "主题。")

    def _show_about(self) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle("关于")
        dialog.setModal(True)
        dialog.resize(520, 340)

        from PyQt6.QtWidgets import QTextBrowser, QVBoxLayout

        layout = QVBoxLayout(dialog)
        browser = QTextBrowser()
        # 🔴 必须是 True。关于框里现在有一个外链（项目地址），而 `QTextBrowser`
        #    默认会**在框内**跳转 —— 用户点一下，整个「关于」内容就被替换掉了
        #    （看着像界面坏了）。True = 交给系统默认浏览器打开。
        browser.setOpenExternalLinks(True)
        browser.setHtml(_ABOUT_HTML)
        layout.addWidget(browser)
        dialog.exec()

    # ==================================================================
    # 状态与进度
    # ==================================================================

    def _say(self, text: str) -> None:
        self.status_label.setText(text)

    def _on_task_started(self, label: str) -> None:
        self.env_label.setText(f"正在执行：{label}")
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)                 # 不确定进度 → 滚动

    def _on_task_finished(self, _label: str) -> None:
        self.progress.setVisible(False)
        self.progress.setRange(0, 100)
        self.env_label.setText(f"日志：{logs_dir()}")

    def _on_progress(self, done: int, total: int, label: str) -> None:
        if total <= 0:
            if not self.progress.isVisible():
                return
            self.progress.setRange(0, 0)
            return
        self.progress.setRange(0, total)
        self.progress.setValue(done)
        if label:
            self.env_label.setText(f"{done}/{total}　{label}")

    # ==================================================================
    # 校验与收尾
    # ==================================================================

    @staticmethod
    def _validate(cfg: ConnConfig) -> str:
        """本地前置校验。返回中文原因，空串表示通过。"""
        if not cfg.dc_ip:
            return "请填写域控 IP 地址。"
        if not cfg.bind_user:
            return "请填写绑定账号（推荐 域名\\用户名，也支持 用户名@域名 / 纯用户名）。"
        if not cfg.password:
            return "请填写绑定账号密码。"
        if not (1 <= cfg.port <= 65535):
            return "端口号不合法。"
        return ""

    @staticmethod
    def _probe(cfg: ConnConfig) -> DomainInfo:
        """匿名反查域信息；失败不致命（允许手填域名与 BaseDN）。"""
        try:
            return AdClient.probe(cfg.dc_ip,
                                  port=cfg.port if cfg.use_ssl else None,
                                  # 同 `AdClient.test_connection`：不勾 SSL 传 None
                                  # （走 389→636 自动回退），勾了传 True（只试 TLS）。
                                  use_ssl=True if cfg.use_ssl else None)
        except AdToolError as exc:
            _log.info("域探测失败（可手填 BaseDN 继续）：%s", exc.message)
            return DomainInfo(dc_ip=cfg.dc_ip)
        except Exception as exc:                     # noqa: BLE001
            _log.warning("域探测异常：%s", translate_error(exc).message)
            return DomainInfo(dc_ip=cfg.dc_ip)

    def closeEvent(self, event) -> None:             # noqa: N802
        """退出前必须把工作线程收干净。

        ⚠️ 不等线程结束就退进程 = `QThread: Destroyed while thread is still
        running` = 直接段错误。用户看到的是"关不掉/闪退"。
        """
        if self.tasks.is_busy():
            self.runner.cancel()
        self.runner.shutdown(wait_ms=4000)
        if self.client is not None:
            try:
                self.client.disconnect()
            except Exception:                        # noqa: BLE001
                pass
        super().closeEvent(event)


_ABOUT_HTML = """
<h3>帮帮AD域管理工具</h3>
<p>一个 Active Directory 轻量管理工具，用来替代 ADUC 的常用部分：
解锁、启用禁用、重置密码、新建用户 / OU / 组。</p>

<p><b>为什么需要它</b><br>
ADUC（dsa.msc）连接域控时会做 DNS 校验，在没有加入域的机器上
经常直接报「指定的域不存在，或无法联系」。本工具改用
<code>ldap3 + NTLM</code> 走 IP 直连，并先匿名读 RootDSE 反查域名与 BaseDN，
所以只要 IP 通、账号密码对，就能管。</p>

<p><b>安全与审计</b><br>
· 明文密码不落盘（勾选「记住密码」才会用 Windows DPAPI 加密保存）<br>
· 所有修改类操作都写本地审计日志，含操作前 / 操作后的值<br>
· 审计日志里不会出现任何密码明文</p>

<p><b>技术栈</b><br>
Python · PyQt6 · ldap3 · pywin32</p>

<p style="color:#888">配置与日志目录：%APPDATA%\\AD域管理工具<br>
项目地址：<a href="https://github.com/foxtap/bbad">github.com/foxtap/bbad</a><br>
许可：源码可见 · 禁止未授权商用（完整条款见仓库 <code>LICENSE</code>）</p>
"""
