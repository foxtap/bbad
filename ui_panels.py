# -*- coding: utf-8 -*-
"""
ui_panels.py —— 内联面板

全部继承 `InlinePanel`，嵌在页面里而不是弹窗。
面板本身**不含任何网络逻辑** —— 它只负责收集输入、发信号，
真正的操作由页面通过 `TaskRunner` 异步执行。这样面板可以在
没有域控的情况下单独测试。
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from PyQt6.QtCore import QRect, Qt, QDateTime, pyqtSignal
from PyQt6.QtGui import QColor, QPainter
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDateTimeEdit,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from models import (
    ATTRIBUTE_MANAGED,
    AttributeChange,
    BatchResult,
    DirObject,
    ObjectKind,
    UserSpec,
    account_state_label,
    is_attribute_writable,
    lookup_attr,
)
# ⚠️ 2026-09-17：上面原来还导入 `UserRow` —— 只被 `UserDetailPanel.load()`
#    的签名用到；那个类（零实例化）已删除 ⇒ 它随之成了未用导入，一并清掉。
# ⚠️ 2026-09-16：这里原来有一句 `from share_backend import LEVELS, LEVEL_LABELS`
#    —— 那是**导入后从未使用**的死导入（全文只有那一行出现这两个名字），
#    随「操作共享盘」功能 + `share_backend.py` 一起删除。**不要加回来**：
#    本模块**不含**网络/文件系统逻辑，档位常量在这里没有使用者。
from ui_widgets import Colors, InlinePanel, SearchLineEdit, hint_label, make_button
from utils import (
    BINARY_ATTRS,
    LOGON_HOURS_CELLS,
    ad_generalized_time_to_dt,
    has_text_write_back_form,
    logon_hours_from_bytes,
    logon_hours_shift,
    logon_hours_to_bytes,
    text_to_int,
    validate_workstation_names,
)

__all__ = [
    "CreateUserPanel",
    "CreateOuPanel",
    "CreateGroupPanel",
    "BatchResultPanel",
    "ObjectPropertyPanel",
    "RenamePanel",
    "MovePanel",
    "AddToGroupPanel",
    "GpoPanel",
    "NewComputerPanel",
    "NewContactPanel",
    "NOT_SET",
]


def _form() -> QFormLayout:
    form = QFormLayout()
    form.setContentsMargins(0, 0, 0, 0)
    form.setSpacing(8)
    form.setLabelAlignment(Qt.AlignmentFlag.AlignRight |
                           Qt.AlignmentFlag.AlignVCenter)
    form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
    return form


def _labeled(text: str) -> QLabel:
    label = QLabel(text)
    label.setStyleSheet(f"color: {Colors.MUTED};")
    return label


#: ``sAMAccountName`` 的**硬限制**：AD schema 里这个属性最长 20 字符。
#: 超长会被域控以 `invalidAttributeSyntax` 拒绝 —— 本地先拦住，
#: 不让使用者白等一次域控往返（对齐 ADUC 里那个 20 字符的输入框）。
SAM_MAX_LENGTH = 20


def validate_sam_chars(sam: str) -> str:
    """登录名（``sAMAccountName``）的**字符**判据。返回空串 = 合法，否则中文原因。

    AD 认的登录名字符集比这里宽（还允许 ``_ $`` 等），本工具取的是**更严的
    一档**：只放行 ASCII 字母数字与 ``.`` ``-``。这个口径不是新定的 ——
    「新建用户」面板一直就是这个判据（见 `CreateUserPanel._on_sam_changed`），
    这里只是把它**抽成唯一实现**：两处各写一遍必然漂移，而漂移的后果是
    「同一个名字在建号页合法、在属性页非法（或反过来）」，使用者只会觉得
    工具在乱说话。

    ⚠️ **唯一实现**：新建用户面板与属性面板的登录名输入框都经
    `apply_sam_precheck` 调它（测试用 ``assertIs`` 钉住是同一个函数对象）。
    """
    value = (sam or "").strip()
    if not value:
        return ""
    if not value.isascii() or not value.replace(".", "").replace("-", "").isalnum():
        return "登录名只能是英文字母、数字，以及 . 和 -（不能有空格、中文或其它符号）"
    return ""


def _set_sam_status(label: QLabel, text: str, level: str = "muted") -> None:
    """把登录名状态写到标签上（**唯一**的状态出口）。"""
    label.setText(text)
    label.setStyleSheet(f"color: {Colors.for_level(level)};")


def apply_sam_precheck(label: QLabel, sam: str) -> bool:
    """登录名输入框的**本地**预检（**唯一实现**）。

    :return: ``True`` = 字符合法，调用方应当再发起一次「占用检查」；
             ``False`` = 空值或字符非法 —— 本地就该拦住，别再跑一趟域控。
    """
    value = (sam or "").strip()
    if not value:
        label.setToolTip("")
        _set_sam_status(label, "")
        return False
    reason = validate_sam_chars(value)
    if reason:
        # 标签上只放四个字（列宽有限），完整原因进 tooltip
        label.setToolTip(reason)
        _set_sam_status(label, "字符非法", "danger")
        return False
    label.setToolTip("")
    _set_sam_status(label, "检查中…", "muted")
    return True


def sam_status_applies(current: str, sam: str) -> bool:
    """「这份登录名结论，还是当前输入框里那个名字的吗」——**唯一**的归属判据。

    登录名可用性是**异步**回来的：使用者边打边查时，前一个名字的「可用」
    会追上来盖住当前名字的状态（看到「可用」就提交，撞名了也不知道为什么）。
    两个面板共用这一条判据，别各写一遍（`create_user_panel` 与属性面板
    出这个缺陷的方式一模一样）。
    """
    return (current or "").strip().casefold() == (sam or "").strip().casefold()


def _ou_path_from_dn(dn: str) -> str:
    """DN → 组织单位路径（自上而下）。

    ``OU=财务一部,OU=财务部,OU=总部,DC=demo,DC=local`` → ``总部/财务部/财务一部``。
    多级 OU 在下拉里靠这个区分同名节点；没有 OU 前缀（如域根/CN 容器）返回空串。
    """
    parts: list[str] = []
    for comp in (dn or "").split(","):
        comp = comp.strip()
        if comp.upper().startswith("OU="):
            parts.append(comp[3:])
    return "/".join(reversed(parts))


#: 语法是「八位字节串」、但**故意不放进** `utils.BINARY_ATTRS` 的属性名。
#:
#: 为什么**单开一张表**、而不是把 `logonHours` 塞进 `BINARY_ATTRS`：
#: `BINARY_ATTRS` 是**读写路径**的判据（决定要不要保留 ``bytes``、要不要逐字节
#: 比对），而 `logonHours` 是位图、**必须**保持字节（`utils.py` 里那段
#: 「别顺手往里加 `logonHours`」的警告就是为它立的）。可它在 AD 里的**语法**
#: 明明白白就是八位字节串 ⇒ 于是它有**两个方向相反的答案**：
#: 读写路径要"**不算**二进制"，语法栏要"**是**二进制"。
#: ⇒ **两张表故意分开**（同 `A14`：扫描面可以比指纹面宽），谁也别去合并它们。
#:
#: ⚠️ 这张表**只给显示层用**。往这里加名字**不会**改变任何读写行为 ——
#: 真正的读写判据仍是 `utils.BINARY_ATTRS`。加名字之前先问一句：
#: 这个属性**有权威文本形式**吗？
#:   * 有 ⇒ 它该进 `_BINARY_ATTR_FORMATTERS`（那是要**转换**，不只是标注）；
#:   * 没有（只有给人看的摘要）⇒ 才来这张表。
OCTET_STRING_SYNTAX_ONLY = frozenset({"logonhours"})


def _attr_syntax(name: str, values: list) -> str:
    """属性的语法（ADUC「语法」列的友好版）。

    ⚠️ **必须按属性名判断**，不能靠值的 Python 类型猜 —— 本函数的输入来自
    `ad_client.read_attributes`，那里已经把**每个值**转成了文本（`objectSid`
    也是 `'S-1-5-21-…'`）。所以"是 `bytes` 就报八位字节串"那种分支
    **永远不成立**（是一段检测不到的假代码）；更要紧的是，按值猜出来的语法会写
    「Unicode 字符串」，而 ADUC 对 `objectSid` 写「八位字节串」——
    用户拿两边截图一对，就会以为我们这列是错的。

    🔴 **2026-09-17 补（D-20 的另一半）**：`logonHours` 是 21 字节位图，
    ADUC 对它的语法同样写「八位字节串」—— 可它**不在** `BINARY_ATTRS` 里
    （那张表保的是**读写路径**），于是本函数原先把一个位图标成
    「**Unicode 字符串**」，与 ADUC 截图一对就是**我们这列在说谎**。
    ⇒ 语法判据现在读**两张**表：读写用的 `BINARY_ATTRS`
    ＋ 只给显示用的 `OCTET_STRING_SYNTAX_ONLY`（见其上方注释，两张表**不许合并**）。
    """
    key = (name or "").casefold()
    if key in BINARY_ATTRS or key in OCTET_STRING_SYNTAX_ONLY:
        return "八位字节串 (Octet String)"
    if not values:
        return "（空）"
    if len(values) > 1:
        return "字符串（多值）"
    return "Unicode 字符串"


#: 常见属性中文说明（超出 ADUC 的增强列；缺失的显示「—」）。
#: 键全部小写 —— 属性名大小写不敏感。
_ATTR_DOCS = {
    "displayname": "显示名：对象列表里展示的名称（通常=姓名）",
    "samaccountname": "登录名（2000 前格式）：登录 Windows 用的账号名，≤20 字符",
    "userprincipalname": "UPN：形如 user@domain 的现代登录名",
    "givenname": "名（First Name）",
    "sn": "姓（Last Name）",
    "cn": "通用名称（Common Name），即 RDN",
    "mail": "电子邮件地址",
    "title": "职位/职务",
    "department": "部门（自由文本，不一定对应 OU 结构）",
    "company": "公司名称",
    "description": "描述",
    "telephonenumber": "办公电话",
    "mobile": "手机号",
    "ipphone": "IP 电话",
    "facsimiletelephonenumber": "传真号",
    "homephone": "家庭电话",
    "streetaddress": "街道地址",
    "l": "城市（Locality）",
    "st": "省/州（State）",
    "postalcode": "邮政编码",
    "c": "国家/地区（两字母代码）",
    "physicaldeliveryofficename": "办公室位置",
    "info": "备注（自由文本）",
    "useraccountcontrol": "账号控制标志位（启用/禁用、密码永不过期等，位运算）",
    "pwdlastset": "上次设置密码的时间；=0 表示下次登录必须改密码",
    "accountexpires": "账户过期时间；0 / 极大值 = 永不过期",
    "lockouttime": "最近一次被锁定的时间；=0 表示未锁定",
    "lastlogontimestamp": "最近一次登录时间（域控间异步复制，误差可达 14 天）",
    "lastlogon": "最近一次登录时间（仅本域控准确，不复制）",
    "badpwdcount": "连续登录失败次数（达到阈值触发锁定）",
    "badpasswordtime": "最近一次登录失败的时间",
    "logonhours": "登录时间限制位图（21 字节，168 格，UTC）",
    "userworkstations": "「登录到」限制：允许登录的工作站名单",
    "msnpallowdialin": "拨入权限：允许/拒绝/由 NPS 策略控制",
    "msradiuscallbacknumber": "拨入回拨号码",
    "msradiusservicetype": "拨入服务类型（回拨设置）",
    "scriptpath": "登录脚本路径",
    "homedirectory": "主目录（网络路径）",
    "homedrive": "主目录映射的盘符",
    "profilepath": "漫游配置文件路径",
    "primarygroupid": "主要组的 RID",
    "memberof": "隶属于（该对象直接加入的组，不含主要组嵌套）",
    "member": "成员（组内直接成员列表）",
    "managedby": "管理者（管理此对象的账号）",
    "grouptype": "组类型（安全/通讯 + 全局/通用/域本地，位标志）",
    "dnshostname": "计算机的 DNS 全名（加域时自动注册）",
    "operatingsystem": "计算机操作系统",
    "operatingsystemversion": "操作系统版本号",
    "serviceprincipalname": "SPN：Kerberos 服务主体名（多值）",
    "objectcategory": "对象类别（类别的 DN）",
    "objectclass": "对象类（继承链：top → user → …）",
    "whencreated": "对象创建时间（UTC）",
    "whenchanged": "对象最近修改时间（UTC）",
    "usncreated": "创建时的更新序列号（USN）",
    "usnchanged": "最近修改的更新序列号（USN）",
    "instancetype": "实例类型（副本标志，系统维护）",
    "objectguid": "对象 GUID（128 位，永不改变，系统维护）",
    "objectsid": "对象 SID（安全标识符，系统维护）",
    "msds-user-account-control-computed": "计算后的账号状态（锁定/密码过期，只读）",
    "msds-userpasswordexpirytimecomputed": "密码过期时间（计算值，只读）",
}


# ============================================================================
# 新建用户
# ============================================================================

class CreateUserPanel(InlinePanel):
    """新建用户内联面板。

    命名说明：这里的「姓名」= ``displayName``（显示名，可以是中文），
    「登录名」= ``sAMAccountName``（≤20 字符，只能是英文数字）。
    两者不自动互填 —— 中文姓名转拼音是不可靠的，猜错了反而要改。
    """

    check_sam = pyqtSignal(str)          # 请求检查登录名是否可用
    # ⚠️ 2026-09-17 删掉了 `generated = pyqtSignal()`：它**有 emit 零 connect**
    #    （注释写"页面可据此提示抄下来"，而那个提示**从未实现**）。
    #    按铁律「零调用点 = 死代码要删」处理 —— 页面拿不到这个信号，
    #    就等于"填了默认密码"这件事没有人需要被通知。
    #: 右键「默认密码」按钮 —— 请页面打开设置窗（口令存在配置文件里，
    #: 面板自己碰不到 ConfigStore，所以只能发出请求）
    default_password_edit_requested = pyqtSignal()

    def __init__(self, parent: QWidget | None = None):
        super().__init__("新建用户", parent)
        self.set_ok_text("创建")
        self._target_dn = ""                 # 待回填的创建位置（候选未到货时暂存）
        self._default_password = ""          # 已配置的默认密码（页面喂进来）

        self.display_name = QLineEdit()
        self.display_name.setPlaceholderText("张三")
        self.display_name.textChanged.connect(self._on_name_changed)

        sam_row = QWidget()
        sam_layout = QHBoxLayout(sam_row)
        sam_layout.setContentsMargins(0, 0, 0, 0)
        sam_layout.setSpacing(6)
        self.sam = QLineEdit()
        self.sam.setPlaceholderText("zhangsan")
        self.sam.setMaxLength(20)
        self.sam.textChanged.connect(self._on_sam_changed)
        sam_layout.addWidget(self.sam, 1)
        self.sam_status = QLabel("")
        self.sam_status.setMinimumWidth(52)
        sam_layout.addWidget(self.sam_status)

        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.textChanged.connect(self._on_password_changed)
        # 「默认密码」按钮：左键填入已配置的口令；右键弹出设置窗。
        # （不做成随机生成 —— 工厂/网吧这类场景要的是**统一初始口令**，
        #   随机值只是让管理员必须逐个抄；随机生成留在设置窗里当辅助。）
        self.generate_button = QPushButton("默认密码")
        self.generate_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.generate_button.clicked.connect(self._fill_default_password)
        self.generate_button.setContextMenuPolicy(
            Qt.ContextMenuPolicy.CustomContextMenu)
        self.generate_button.customContextMenuRequested.connect(
            lambda _pos: self.default_password_edit_requested.emit())

        pwd_row = QWidget()
        pwd_layout = QHBoxLayout(pwd_row)
        pwd_layout.setContentsMargins(0, 0, 0, 0)
        pwd_layout.setSpacing(6)
        pwd_layout.addWidget(self.password, 1)
        pwd_layout.addWidget(self.generate_button)

        # 组织单位（创建位置选择器，对齐 ADUC：新建向导没有「部门」字段，
        # 位置就是你要把人放进哪个 OU；department 属性建完后在属性面板里填）。
        # userData 存 DN —— 同名 OU（不同层级）也能区分开。
        self.ou_pick = QComboBox()
        self.ou_pick.addItem("")             # 首位留空 = 强制显式选择
        # 走一个中转只是为了让签名对得上（Qt 传一个 int 索引实参过来）
        # —— 原先它还要顺手告诉页面"位置变了"好回填权限组勾选，那条已随
        # 「共享盘权限」销掉（2026-09-16）。
        self.ou_pick.currentIndexChanged.connect(self._on_ou_changed)

        self.title = QLineEdit()
        self.title.setPlaceholderText("可选")
        self.mail = QLineEdit()
        self.mail.setPlaceholderText("可选")

        # UPN 后缀（F12）：后端从 CN=Partitions,CN=Configuration 读
        # uPNSuffixes，默认至少有 @域名。可编辑 —— 允许手输列表外的后缀。
        self.upn_suffix = QComboBox()
        self.upn_suffix.setEditable(True)
        self.upn_suffix.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.upn_suffix.lineEdit().setPlaceholderText("@域名（读取中…）")

        form = _form()
        form.addRow(_labeled("姓名"), self.display_name)
        form.addRow(_labeled("登录名"), sam_row)
        form.addRow(_labeled("UPN 后缀"), self.upn_suffix)
        form.addRow(_labeled("初始密码"), pwd_row)
        form.addRow(_labeled("组织单位"), self.ou_pick)
        form.addRow(_labeled("职位"), self.title)
        form.addRow(_labeled("邮箱"), self.mail)
        self.body.addLayout(form)

        self.policy_hint = hint_label("")
        self.policy_hint.hide()
        self.body.addWidget(self.policy_hint)

        self.must_change = QCheckBox("下次登录必须修改密码")
        self.must_change.setChecked(True)
        self.keep_disabled = QCheckBox("只创建，暂不启用")
        self.body.addWidget(self.must_change)
        self.body.addWidget(self.keep_disabled)

        # 表单从上往下排，剩下的空间留在最下面。
        # 不写这句的话，多出来的高度会被均匀分摊到各控件之间，表单看着散架。
        self.body.addStretch(1)

    # ---------- 对外 ----------

    def set_target(self, ou_dn: str, ou_title: str) -> None:
        """设定创建位置。树里有选中项就预选它；没有（导航栏新建）就留空让人选。"""
        self._target_dn = ou_dn or ""
        if self._target_dn:
            idx = self.ou_pick.findData(self._target_dn)
            if idx > 0:
                self.ou_pick.setCurrentIndex(idx)
            else:
                # 候选还没异步读到 —— 先记着，set_ou_options 到货后回填
                self.set_subtitle(f"将创建到　{ou_title}　（{ou_dn}）")
                return
        self._sync_subtitle()

    def _sync_subtitle(self) -> None:
        dn = self.selected_ou_dn()
        if dn:
            self.set_subtitle(f"将创建到　{self.ou_pick.currentText()}\n{dn}")
        else:
            self.set_subtitle("请选择组织单位 —— 用户将创建到该单位下")

    def _on_ou_changed(self, _index: int) -> None:
        """创建位置变了 → 同步副标题。

        ⚠️ 2026-09-16：原先这里还要 `emit(ou_changed)` 请页面回填「上次在这个
           部门勾的权限组」。权限组随「共享盘权限」一起销掉 ⇒ 本槽只剩副标题
           同步这一件事。名字保住了，是因为它接的信号就是 `currentIndexChanged`。
        """
        self._sync_subtitle()

    def set_sam_status_for(self, sam: str, text: str, level: str = "muted") -> None:
        """带归属的登录名状态：输入框已经改成别的名字时，旧结果作废。

        不改就不会露在脸上：使用者边打边查，前一个前缀的「可用」会追上来
        盖住当前名字的状态 —— 看到「可用」就提交，撞名了也不知道为什么。
        判据是共享的 `sam_status_applies`（属性面板用同一条）。
        """
        if not sam_status_applies(self.sam.text(), sam):
            return
        _set_sam_status(self.sam_status, text, level)

    def reset(self) -> None:
        for widget in (self.display_name, self.sam, self.password,
                       self.title, self.mail):
            widget.clear()
        # 填过默认密码后密码框是明文态，复位时必须收回 —— 否则下一次
        # 输入的初始密码会大喇喇显示在屏幕上
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self._target_dn = ""
        self.ou_pick.setCurrentIndex(0)      # 留空 = 必须显式选择
        if self.upn_suffix.count():
            self.upn_suffix.setCurrentIndex(0)   # 回到默认后缀
        else:
            self.upn_suffix.setEditText("")
        self.must_change.setChecked(True)
        self.keep_disabled.setChecked(False)
        self.sam_status.setText("")
        self.policy_hint.hide()

    def set_ou_options(self, rows: list) -> None:
        """组织单位下拉候选 = 目录里**全部** OU（含多级），页面异步喂进来。

        每项 userData 存 DN，显示文本带 DN 路径（总部/财务部/财务一部），
        三级单位也能一眼认出来。保留使用者已选中的那项。
        """
        selected = self.selected_ou_dn() or getattr(self, "_target_dn", "")
        self.ou_pick.blockSignals(True)
        self.ou_pick.clear()
        self.ou_pick.addItem("")
        for obj in rows or []:
            dn = getattr(obj, "dn", "")
            cn = getattr(obj, "cn", "")
            if not dn or not cn:
                continue
            path = _ou_path_from_dn(dn)
            self.ou_pick.addItem(f"{cn}（{path}）" if path else cn, dn)
        self.ou_pick.blockSignals(False)
        if selected:
            idx = self.ou_pick.findData(selected)
            if idx > 0:
                self.ou_pick.setCurrentIndex(idx)
        self._sync_subtitle()

    def selected_ou_dn(self) -> str:
        """当前选中的组织单位 DN（空串 = 未选择）。"""
        return str(self.ou_pick.currentData() or "")

    def set_upn_suffixes(self, suffixes: list[str]) -> None:
        """填充 UPN 后缀下拉（页面异步读到后调用）。保留使用者的手选。"""
        current = self.upn_suffix.currentText().strip()
        self.upn_suffix.clear()
        for text in suffixes or []:
            self.upn_suffix.addItem(text)
        if current:
            self.upn_suffix.setCurrentIndex(
                max(0, self.upn_suffix.findText(current)))

    def apply_template(self, attrs: dict[str, Any]) -> None:
        """复制用户（模板建号）：只抄「岗位描述类」字段。

        姓名 / 登录名 / 密码是每个身份唯一的，**必须留空让人填** ——
        这也是 ADUC「复制」对话框的语义。创建位置（组织单位）不跟模板走，
        以树选中项 / 手动选择为准。
        """
        for widget, attr in ((self.title, "title"),
                             (self.mail, "mail")):
            value = _first_attr(attrs, attr)
            if not value:
                continue
            is_combo = isinstance(widget, QComboBox)
            current = (widget.currentText() if is_combo
                       else widget.text())
            if current.strip():
                continue
            if is_combo:
                widget.setEditText(str(value))
            else:
                widget.setText(str(value))

    def spec(self) -> UserSpec:
        extra = {}
        if self.title.text().strip():
            extra["title"] = self.title.text().strip()
        if self.mail.text().strip():
            extra["mail"] = self.mail.text().strip()
        sam = self.sam.text().strip()
        suffix = self.upn_suffix.currentText().strip()
        if sam and suffix:
            if not suffix.startswith("@"):
                suffix = f"@{suffix}"
            extra["userPrincipalName"] = f"{sam}{suffix}"
        return UserSpec(
            sam=self.sam.text().strip(),
            init_password=self.password.text(),
            display_name=self.display_name.text().strip(),
            must_change=self.must_change.isChecked(),
            keep_disabled=self.keep_disabled.isChecked(),
            extra=extra,
        )

    # ---------- 内部 ----------

    def _on_name_changed(self, text: str) -> None:
        if not self.sam.text().strip():
            return
        self._check_policy()

    def _on_sam_changed(self, text: str) -> None:
        # 判据与状态出口都是共享实现（`apply_sam_precheck` → `validate_sam_chars`）：
        # 属性面板的登录名输入框用的是**同一个函数对象**，不是照抄一份。
        if not apply_sam_precheck(self.sam_status, text):
            return
        self.check_sam.emit(text.strip())
        self._check_policy()

    def _on_password_changed(self, _text: str) -> None:
        self._check_policy()

    def _check_policy(self) -> None:
        """本地预检，尽早提示 —— 减少 50 次无谓的域控往返。"""
        from utils import check_password_guessability

        password = self.password.text()
        if not password:
            self.policy_hint.hide()
            return
        reason = check_password_guessability(password, self.sam.text(),
                                             self.display_name.text())
        if reason:
            self.policy_hint.setText("本地预检：" + reason)
            self.policy_hint.setStyleSheet(f"color: {Colors.WARN};")
            self.policy_hint.show()
        else:
            self.policy_hint.hide()

    # ---------- 默认密码 ----------

    def set_default_password(self, password: str) -> None:
        """页面把「已配置的默认密码」喂进来（存在配置文件里，DPAPI 加密）。"""
        self._default_password = password or ""
        if self._default_password:
            tip = ("左键：填入已保存的默认密码\n"
                   "右键：修改 / 清除默认密码")
        else:
            tip = ("还没设置默认密码 —— 左键或右键都可以现在设置\n"
                   "（口令加密保存在本机配置文件里）")
        self.generate_button.setToolTip(tip)

    def _fill_default_password(self) -> None:
        """左键：填入默认密码；没设过就顺势打开设置窗，不留死路。"""
        if not self._default_password:
            self.default_password_edit_requested.emit()
            return
        self.password.setText(self._default_password)
        self.password.setEchoMode(QLineEdit.EchoMode.Normal)   # 显出来好抄
        # ⚠️ 2026-09-17：这里原来还有 `self.generated.emit()`，
        #    那个信号零 connect（页面从没接过），已随信号一起删除。


# ============================================================================
# 新建 OU / 组
# ============================================================================

class CreateOuPanel(InlinePanel):
    """新建组织单位。"""

    def __init__(self, parent: QWidget | None = None):
        super().__init__("新建组织单位（OU）", parent)
        self.set_ok_text("创建")

        self.name = QLineEdit()
        self.name.setPlaceholderText("如：运维部")
        self.description = QLineEdit()
        self.description.setPlaceholderText("可选")

        form = _form()
        form.addRow(_labeled("名称"), self.name)
        form.addRow(_labeled("描述"), self.description)
        self.body.addLayout(form)

        self.body.addWidget(hint_label(
            "名称里可以带空格和中文；逗号、加号、引号等符号会自动转义，不会被截断。"))
        self.body.addStretch(1)

    def set_target(self, parent_dn: str, parent_title: str) -> None:
        self.set_subtitle(f"将创建在　{parent_title}　之下")

    def reset(self) -> None:
        self.name.clear()
        self.description.clear()

    def values(self) -> tuple[str, str]:
        return self.name.text().strip(), self.description.text().strip()


class CreateGroupPanel(InlinePanel):
    """新建组。"""

    SCOPES = [("全局组（global）", "global"),
              ("域本地组（domainlocal）", "domainlocal"),
              ("通用组（universal）", "universal")]

    def __init__(self, parent: QWidget | None = None):
        super().__init__("新建组", parent)
        self.set_ok_text("创建")

        self.name = QLineEdit()
        self.name.setPlaceholderText("如：IT-Admins")

        self.scope = QComboBox()
        for label, value in self.SCOPES:
            self.scope.addItem(label, value)

        self.category = QComboBox()
        self.category.addItem("安全组（可授权）", "security")
        self.category.addItem("通讯组（仅邮件分发）", "distribution")

        self.description = QLineEdit()
        self.description.setPlaceholderText("可选")

        form = _form()
        form.addRow(_labeled("组名"), self.name)
        form.addRow(_labeled("作用域"), self.scope)
        form.addRow(_labeled("类型"), self.category)
        form.addRow(_labeled("描述"), self.description)
        self.body.addLayout(form)

        self.body.addWidget(hint_label(
            "作用域选「全局组」最通用；跨域授权才需要「通用组」。"
            "组名不要用中文全角符号，部分老域控会拒。"))
        self.body.addStretch(1)

    def set_target(self, parent_dn: str, parent_title: str) -> None:
        self.set_subtitle(f"将创建在　{parent_title}　之下")

    def reset(self) -> None:
        self.name.clear()
        self.description.clear()

    def values(self) -> dict:
        return {
            "name": self.name.text().strip(),
            "scope": self.scope.currentData(),
            "category": self.category.currentData(),
            "description": self.description.text().strip(),
        }


# ============================================================================
# ============================================================================
# 批量结果
# ============================================================================

class BatchResultPanel(InlinePanel):
    """批量操作结果。逐条列出，失败可一键复制给管理员。"""

    def __init__(self, parent: QWidget | None = None):
        super().__init__("批量操作结果", parent)
        self.cancel_button.hide()
        self.ok_button.hide()

        self.summary = QLabel("")
        self.summary.setWordWrap(True)
        self.body.addWidget(self.summary)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["账号", "结果", "原因 / 说明"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        _draggable_header(self.table)
        self.table.setColumnWidth(0, 150)      # 账号
        self.table.setColumnWidth(1, 60)       # 结果（成功/失败）
        self.table.setMinimumHeight(260)
        self.body.addWidget(self.table, 1)

        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setMaximumHeight(90)
        self.detail.setVisible(False)
        self.body.addWidget(self.detail)

        self.copy_button = QPushButton("复制失败明细")
        self.copy_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.copy_button.clicked.connect(self._copy_failures)
        self.body.addWidget(self.copy_button)

        self._result: BatchResult | None = None

    def load(self, result: BatchResult) -> None:
        self._result = result
        self.set_title(f"批量操作结果 · {result.op_label}")

        if result.failed or result.aborted_reason:
            self.summary.setStyleSheet(f"color: {Colors.WARN};")
        else:
            self.summary.setStyleSheet(f"color: {Colors.OK};")
        self.summary.setText(result.summary())

        self.table.setRowCount(len(result.items))
        for index, item in enumerate(result.items):
            sam_item = QTableWidgetItem(item.sam or item.dn)
            sam_item.setToolTip(item.dn or item.sam)
            mark_item = QTableWidgetItem("成功" if item.ok else "失败")
            mark_item.setForeground(QColor(Colors.OK if item.ok else Colors.DANGER))
            reason_item = QTableWidgetItem(item.message or "—")
            reason_item.setToolTip(reason_item.text())
            self.table.setItem(index, 0, sam_item)
            self.table.setItem(index, 1, mark_item)
            self.table.setItem(index, 2, reason_item)

        text = result.failure_text(limit=200)
        self.detail.setPlainText(text)
        self.detail.setVisible(bool(text))
        self.copy_button.setVisible(bool(result.failed))

    def _copy_failures(self) -> None:
        if self._result is None:
            return
        from PyQt6.QtWidgets import QApplication

        payload = f"{self._result.summary()}\n\n{self._result.failure_text(limit=500)}"
        QApplication.clipboard().setText(payload.strip())
        self.summary.setText(self._result.summary() + "　（失败明细已复制）")


# ============================================================================
# 属性面板（ADUC 对齐 · F05 / F06）
# ============================================================================

#: 「未改动」哨兵。``None`` 在账户过期里有真实语义（永不过期），
#: 不能再用它表达"用户没碰这个字段"。
NOT_SET = object()


def _first_attr(attrs: dict[str, list[str]], name: str) -> str:
    """从属性表里取第一个值（大小写不敏感，缺省空串）。"""
    low = name.casefold()
    for key, values in (attrs or {}).items():
        if key.casefold() == low and values:
            return str(values[0])
    return ""


def _filetime_to_datetime(raw: str) -> datetime | None:
    """accountExpires 的 FILETIME 字符串 → datetime（哨兵值 → None）。"""
    from utils import ad_filetime_to_dt
    try:
        return ad_filetime_to_dt(int(raw))
    except (TypeError, ValueError):
        return None


def _mark_checkbox_unknown(box: QCheckBox, reason: str) -> None:
    """把一个"读不到当前值"的复选框标成**未知且不可编辑**。

    🔴 为什么不能"就让它空着"：这一页的复选框全是**写入口**，而变更收集是
    **差分式**的（控件值 != 基线就发一条改动）。空着 = 一个明确的
    「不要这个策略」⇒ "未知"会被翻译成一条真的写进 AD 的改动，方向还可能
    正好相反。

    ⇒ 三态（`PartiallyChecked` 画成方块，既不是勾也不是空）+ 停用 + 说明。
      ⚠️ 这还不够。停用只挡得住人的手，挡不住"控件值与基线不同"这条代码路径，
      而且**三态的 `isChecked()` 返回 `True`**（Qt 只把 `Unchecked` 当未选中，
      `PartiallyChecked` 也算"选中"）—— 与"看起来是空的"直觉正好相反。
      基线记的是标成未知**之前**的值，所以 `_pwd_never` / `_must_change`
      那两处**一定会误发**一条编出来的改动。
      ⇒ `_collect_changes` 里那三处 `_*_unknown` 守卫是**第二道**，缺一不可。
    """
    box.setTristate(True)
    box.setCheckState(Qt.CheckState.PartiallyChecked)
    box.setEnabled(False)
    box.setToolTip(reason)


def _attr_field(label: str, attr: str, placeholder: str = "可选") -> tuple:
    """一个「标签 + 属性名 + 输入框」三元组（属性页表格行的定义单元）。"""
    return (label, attr, placeholder)


#: 各页签的字段布局：``{页签名: [(标签, 属性名, 占位), ...]}``。
#: 只用**允许写入**的属性 —— 黑名单属性（name / memberOf / whenCreated 等）
#: 一个都不进来，这是界面侧的第一道防线（后端 `modify_object` 还有第二道）。
_TAB_FIELDS: dict[str, list[tuple]] = {
    "常规": [
        _attr_field("显示名", "displayName", "张三"),
        _attr_field("名", "givenName"),
        _attr_field("姓", "sn"),
        _attr_field("描述", "description"),
        _attr_field("办公室", "physicalDeliveryOfficeName", "如：3 楼 302"),
        _attr_field("电子邮件", "mail", "name@example.com"),
        _attr_field("网页", "wWWHomePage", "https://"),
    ],
    "地址": [
        _attr_field("街道", "streetAddress"),
        _attr_field("信箱", "postOfficeBox"),
        _attr_field("城市", "l"),
        _attr_field("省/州", "st"),
        _attr_field("邮编", "postalCode"),
        _attr_field("国家/地区", "c", "两位字母代码，如 CN"),
    ],
    "电话": [
        _attr_field("电话", "telephoneNumber"),
        _attr_field("移动电话", "mobile"),
        _attr_field("寻呼机", "pager"),
        _attr_field("传真", "facsimileTelephoneNumber"),
        _attr_field("IP 电话", "ipPhone"),
        _attr_field("备注", "info"),
    ],
    "组织": [
        _attr_field("职务", "title"),
        _attr_field("部门", "department"),
        _attr_field("公司", "company"),
    ],
    "配置文件": [
        _attr_field("配置文件路径", "profilePath", r"\\服务器\profiles\%username%"),
        _attr_field("登录脚本", "scriptPath", "logon.bat"),
        _attr_field("主文件夹", "homeDirectory", r"\\服务器\homes\%username%"),
        _attr_field("主文件夹驱动器", "homeDrive", "Z:"),
    ],
}


#: 列宽下限 —— 只防「拖成 0 宽再也抓不回来」，不限制正常收窄
_MIN_COL_W = 48


def _draggable_header(table: QTableWidget) -> QHeaderView:
    """把表格的列设成**用户可拖动分隔线**，返回表头。

    Qt 铁律：只有 ``Interactive`` 的列能拖；``Stretch`` 与
    ``ResizeToContents`` 都是「宽度由 Qt 说了算」，鼠标移上去既不变
    成左右箭头光标、也拖不动（用户报的正是这个现象）。
    因此这里统一 Interactive，末列用 ``stretchLastSection`` 吃掉剩余宽度。
    """
    header = table.horizontalHeader()
    # 禁止拖动表头换列序：调用方按固定列号取值（如 UserRole 永远在第 0 列）
    header.setSectionsMovable(False)
    header.setMinimumSectionSize(_MIN_COL_W)
    for col in range(table.columnCount()):
        header.setSectionResizeMode(col, QHeaderView.ResizeMode.Interactive)
    header.setStretchLastSection(True)
    return header


class _MiniTable(QTableWidget):
    """属性页内部的小表格（属性编辑器 / 成员 / 隶属组 / 选组共用一个底子）。

    **列宽策略**：所有列可手动拖拽，初始宽度由构造方**显式指定**
    （``widths`` 只覆盖前面的列，最后一列交给 stretch 吃掉剩余宽度）。

    为什么不用「按内容自适应」量一次：面板只有几百像素宽，一个长属性名
    能占到 260px，把「值」列挤到只剩几十像素 —— 实测就是这个问题。
    显式宽度可预测，要变宽自己拖。
    """

    def __init__(self, headers: list[str], widths: list[int] | None = None,
                 parent=None, single: bool = False):
        super().__init__(0, len(headers), parent)
        self.setHorizontalHeaderLabels(headers)
        self.verticalHeader().setVisible(False)
        self.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        # 默认多选（成员 / 隶属于组这些页签要批量移出）；
        # 属性编辑器必须是**单选** —— 它的语义就是「选中一个属性、在下面编辑」，
        # 左键拖着划过多行既无意义又容易误以为「这些都会被改」。
        self.setSelectionMode(
            QTableWidget.SelectionMode.SingleSelection if single
            else QTableWidget.SelectionMode.ExtendedSelection)
        self.setAlternatingRowColors(True)
        _draggable_header(self)
        last = len(headers) - 1
        for col in range(len(headers)):
            if col == last:
                break                    # 末列由 stretch 接管，设了也被覆盖
            width = widths[col] if (widths and col < len(widths)) else 140
            self.setColumnWidth(col, max(_MIN_COL_W, int(width)))
        self.setMinimumHeight(140)


#: 组表格 DN 列上挂的第二个角色值：AD 里的**真 CN**。
#: 为什么要单独存而不从 DN 现解析，见 ``_group_picks_from_rows``。
_CN_ROLE = Qt.ItemDataRole.UserRole + 1


def _fill_group_rows(table: "_MiniTable", groups: list[DirObject]) -> None:
    """把组列表填进一张 4 列表格（组 / 作用域 / 类型 / DN）。

    ⚠️ 2026-09-16：原先有**两个**调用方 —— ``AddToGroupPanel``（单选：把对象
       加进一个组）与 ``PermissionGroupsPanel``（多选：挑若干组进权限组清单）。
       后一个随「共享盘权限」一起销掉了，现在**只剩一个调用方**。
       仍然留在模块级，是因为它与 ``_group_picks_from_rows`` / ``_group_dns_from_rows``
       是**成套**的（同一条"填表 → 取选中项"的口径，靠第 4 列 DN 把 DN 与 CN
       分开存）—— 拆成面板私有的反而会把表格列序的知识散到两处。

    第 4 列（DN）把 DN 与 CN 分别塞进两个角色里 —— 取选中项时读它们，
    不读单元格文本（列宽写死过，文本随时可能被截）。
    """
    table.setRowCount(len(groups))
    for row, obj in enumerate(groups):
        table.setItem(row, 0, QTableWidgetItem(obj.title or "—"))
        table.setItem(row, 1, QTableWidgetItem(obj.scope_label() or "—"))
        table.setItem(row, 2, QTableWidgetItem(obj.category_label() or "—"))
        item = QTableWidgetItem(obj.dn)
        item.setData(Qt.ItemDataRole.UserRole, obj.dn)
        item.setData(_CN_ROLE, obj.title or "")
        item.setToolTip(obj.dn)
        table.setItem(row, 3, item)


def _group_picks_from_rows(table: "_MiniTable",
                           column: int = 3) -> list[tuple[str, str]]:
    """读出组表格里**选中行**的 ``(DN, 名字)``（按行序，去重）。

    ``名字`` 是填表时**从 AD 读到的 CN**（``_fill_group_rows`` 一并写进
    ``_CN_ROLE``），**不是**在这里从 DN 现解析出来的 —— 这不是偷懒：
    DN 的 RDN 值可以带转义（``CN=技术部\\,资料``），字符串切分要么把
    转义反斜杠留在显示名里，要么把名字切一半。读 AD 给的 CN 是零解析、
    零歧义的那条路。

    DN 才是落点，名字只给人看 —— 所以两者分开取，别指望名字能反推 DN。
    """
    rows = sorted({i.row() for i in table.selectedIndexes() if i.isValid()})
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for row in rows:
        item = table.item(row, column)
        if item is None:
            continue
        dn = str(item.data(Qt.ItemDataRole.UserRole) or "")
        if not dn or dn.casefold() in seen:
            continue
        seen.add(dn.casefold())
        out.append((dn, str(item.data(_CN_ROLE) or "")))
    return out


def _group_dns_from_rows(table: "_MiniTable", column: int = 3) -> list[str]:
    """只要 DN 的投影（``AddToGroupPanel`` 用；它不关心显示名）。"""
    return [dn for dn, _name in _group_picks_from_rows(table, column)]


class LogonHoursGrid(QWidget):
    """7×24 登录时间网格（F13）。

    显示与输入都按**本地时间**（与 ADUC 的体验一致）；
    本地 ⇄ UTC 的位图换算只在边界做（`utils.logon_hours_shift`），
    网格本身不碰任何时区知识 —— 单测才有得写。
    """

    CELL_W = 21
    CELL_H = 17
    _DAYS = ("周日", "周一", "周二", "周三", "周四", "周五", "周六")

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._cells: list[bool] = [True] * LOGON_HOURS_CELLS
        self._drag_state: bool | None = None
        self.setMouseTracking(False)
        self.setMinimumSize(self.CELL_W * 24 + 36, self.CELL_H * 7 + 22)

    # ---------- 数据 ----------

    def cells(self) -> list[bool]:
        return list(self._cells)

    def set_cells(self, cells: list[bool]) -> None:
        self._cells = list(cells)
        self.update()

    def set_all(self, value: bool) -> None:
        self._cells = [value] * LOGON_HOURS_CELLS
        self.update()

    # ---------- 绘制 ----------

    def paintEvent(self, event) -> None:            # noqa: N802 - Qt 回调
        painter = QPainter(self)
        w, h = self.CELL_W, self.CELL_H
        base = self.palette().color(self.palette().ColorRole.Base)
        on_color = QColor("#4F46E5")
        off_color = QColor(base.red(), base.green(), base.blue())
        border = QColor(128, 128, 128, 90)
        text = self.palette().color(self.palette().ColorRole.WindowText)

        painter.setFont(self._small_font())
        painter.setPen(QColor(text.red(), text.green(), text.blue(), 150))
        # 顶部小时刻度（每 6 小时一个标注）
        for hour in range(0, 24, 6):
            painter.drawText(QRect(36 + hour * w, 0, w * 3, 14),
                             int(Qt.AlignmentFlag.AlignLeft
                                 | Qt.AlignmentFlag.AlignVCenter),
                             f"{hour:02d}")
        top = 16
        for day in range(7):
            painter.setPen(QColor(text.red(), text.green(), text.blue(), 170))
            painter.drawText(QRect(0, top + day * h, 34, h),
                             int(Qt.AlignmentFlag.AlignRight
                                 | Qt.AlignmentFlag.AlignVCenter),
                             self._DAYS[day])
        painter.setPen(Qt.PenStyle.NoPen)
        for index, is_on in enumerate(self._cells):
            day, hour = divmod(index, 24)
            rect = QRect(36 + hour * w, top + day * h, w - 1, h - 1)
            painter.setBrush(on_color if is_on else off_color)
            painter.setPen(border)
            painter.drawRect(rect)

    def _small_font(self):
        from PyQt6.QtGui import QFont

        font = QFont()
        font.setPixelSize(9)
        return font

    # ---------- 交互（点按 + 拖动刷） ----------

    def _cell_at(self, pos) -> int | None:
        x, y = pos.x() - 36, pos.y() - 16
        if x < 0 or y < 0:
            return None
        hour, day = x // self.CELL_W, y // self.CELL_H
        if hour >= 24 or day >= 7:
            return None
        return day * 24 + hour

    def mousePressEvent(self, event) -> None:       # noqa: N802 - Qt 回调
        index = self._cell_at(event.position().toPoint())
        if index is None:
            return
        self._drag_state = not self._cells[index]
        self._cells[index] = self._drag_state
        self.update()

    def mouseMoveEvent(self, event) -> None:        # noqa: N802 - Qt 回调
        if self._drag_state is None:
            return
        index = self._cell_at(event.position().toPoint())
        if index is not None and self._cells[index] != self._drag_state:
            self._cells[index] = self._drag_state
            self.update()

    def mouseReleaseEvent(self, event) -> None:     # noqa: N802 - Qt 回调
        self._drag_state = None


class ObjectPropertyPanel(InlinePanel):
    """对象属性面板 —— 按对象类型动态出页签，可写回。

    对齐 ADUC 的属性对话框：用户 = 常规/地址/账户/配置文件/电话/组织/隶属于；
    组多一个「成员」页（组最有用的功能）；计算机 = 常规/账户/隶属于；
    联系人 = 常规/电话/组织/隶属于。

    面板**不含网络逻辑**：读用 ``load(obj, attrs)``，写用 ``collect()``
    打包交回页面异步执行（内联不弹窗、树始终可见的既定铁律）。
    """

    # 组成员页 / 隶属于页的事件，全部交给页面异步执行
    load_members_requested = pyqtSignal(str)          # 组 DN
    search_objects_requested = pyqtSignal(str)        # 关键字
    remove_members_requested = pyqtSignal(list)       # 成员 DN 列表
    add_members_requested = pyqtSignal(list)          # 成员 DN 列表
    remove_membership_requested = pyqtSignal(str)     # 从该组移出（memberOf DN）
    add_to_group_requested = pyqtSignal()             # 请求打开「添加到组」面板
    #: 面板内的"说一句"。面板自己没有状态栏，交给页面统一显示
    #: （页面把它接到 `notify`）。
    #: 🔴 存在的理由：本面板**没有** `notify` 可用，于是几处"没选中就 nothing"
    #:    只能静默 —— 而"按钮亮着、点了没反应"会被读成工具卡住了。
    #:    加这一个信号，那些入口就都能说话，纪律也就只有一份实现。
    notice = pyqtSignal(str)
    #: 请求页面检查这个登录名是否已被占用（与 `CreateUserPanel.check_sam` 同义）。
    #: 面板自己**不含网络逻辑**，所以只能发信号请页面去查。
    check_sam = pyqtSignal(str)

    #: 「隶属于」页底部那句固定说明 —— **只留一份**（模板那行原来把它内联在
    #: `_build_memberof_tab` 里，而三态提示要拼在它前面 ⇒ 拼一次就会有两份）。
    _MEMBEROF_NOTE = ("主要组（如 Domain Users）不在这张表里，也不能从这里移除 —— "
                      "需要先在别处更换用户的主要组。")

    def __init__(self, parent: QWidget | None = None):
        super().__init__("属性", parent)
        self.set_ok_text("保存")
        self.cancel_button.hide()

        self._obj: DirObject | None = None
        #: 当前装载对象的 DN —— 异步结果回来时的**归属判据**。
        #: 面板是共享单例：请求在飞的时候用户换了对象，旧结果必须丢掉，
        #: 否则 A 的属性会挂在 B 名下显示，而「保存」就在旁边。
        self._loaded_dn: str = ""
        self._attrs: dict[str, list[str]] = {}
        self._fields: dict[str, QLineEdit] = {}       # 属性名小写 → 输入框
        self._saved_values: dict[str, str] = {}       # 属性名小写 → 装载时的值
        self._pending_attr_changes: list[AttributeChange] = []   # 属性编辑器队列
        self._editor_attr = ""                        # 编辑器当前选中的属性
        # ---- 登录名（sAMAccountName）相关状态 ----
        # 面板是**共享单例**：每次 `load()` 都必须清干净，否则给组/OU 装载时
        # 会读到上一个用户留下的输入框与勾选框（collect() 就会拿错值）。
        self._sam_edit: QLineEdit | None = None       # 权威输入框（collect 只读它）
        self._sam_status: QLabel | None = None        # 它的「可用/已占用」状态
        self._sam_edits: list[QLineEdit] = []         # 常规页 + 账户页的两个入口
        #: 占用检查的**闸门状态**：empty / invalid / checking / ok / taken / unknown。
        #: 与屏幕文字一起由 `_set_sam_verdict` 写（分开写必然漂）。
        self._sam_verdict = ""
        self._sync_upn: QCheckBox | None = None       # 「改登录名时同步更新 UPN」
        self._upn_sync_note: QLabel | None = None     # 同步与否的**原因**

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.body.addWidget(self.tabs, 1)

        self._summary = hint_label("")
        self.body.addWidget(self._summary)

    # ---------- 装载 ----------

    def load(self, obj: DirObject, attrs: dict[str, list[str]]) -> None:
        self._obj = obj
        self._loaded_dn = (obj.dn if obj is not None else "") or ""
        self._attrs = attrs or {}
        self._fields.clear()
        self._saved_values.clear()
        self._pending_attr_changes = []
        self._editor_attr = ""
        # 共享单例：上一次装载留下的登录名控件/勾选框必须**先清掉**再重建，
        # 否则给组、OU、联系人装载时会沿用上一个用户的输入框（collect() 读错对象）。
        self._sam_edit = None
        self._sam_status = None
        self._sam_edits = []
        self._sam_verdict = ""
        self._sync_upn = None
        self._upn_sync_note = None

        kind = obj.kind
        self.set_title(f"{obj.kind_label()}属性 · {obj.title or obj.sam}")

        while self.tabs.count():
            widget = self.tabs.widget(0)
            self.tabs.removeTab(0)
            widget.deleteLater()

        is_group = kind == ObjectKind.GROUP
        is_computer = kind == ObjectKind.COMPUTER
        is_user = kind == ObjectKind.USER

        # ---- 常规 ----
        general_fields = list(_TAB_FIELDS["常规"])
        if is_computer:
            # 计算机的 DNS 名 / 系统由机器自己注册，展示但不提供编辑
            general_fields = [_attr_field("描述", "description"),
                              _attr_field("位置", "location")]
        if is_group:
            general_fields = [_attr_field("描述", "description"),
                              _attr_field("电子邮件", "mail")]
        tab, form = self._add_tab("常规")
        if is_group:
            # 组名与 sAMAccountName 也是同一个属性：显示值取「本次读回的真值」，
            # 列表行快照 `obj.sam` 只作兜底 —— 保存后回读走的是
            # `ObjectTableModel.update_rows`（**替换**行对象），面板里存的那个
            # `_obj` 从头到尾没人更新过，取它就会一直显示保存前的旧值。
            self._add_readonly(form, "组名(2000 前)",
                               self._live_attr("sAMAccountName", obj.sam))
        if is_computer:
            self._add_readonly(form, "计算机名", obj.cn or obj.sam)
            self._add_readonly(form, "DNS 名称", obj.dns_host_name or "（机器加域后自动注册）")
            self._add_readonly(form, "操作系统", (obj.os or "—") + " " + (obj.os_version or ""))
        for label, attr, placeholder in general_fields:
            self._add_field(form, label, attr, placeholder)
        if is_user:
            # D-19：这里原来是个**只读框**（`_add_readonly(…, obj.sam)`），
            # 全项目再没有第二个入口能改 sAMAccountName ⇒ 使用者只能绕到
            # 「属性编辑器」页手改。现在与账户页共用同一个可编辑构造。
            self._add_sam_field(form, "登录名")
        # ⚠️ 布局已由 _add_tab 接好（page.setLayout(_wrap_form(form))）。
        #    这里再 setLayout 一次 → Qt 警告「already has a layout」+
        #    QFormLayout「already has a parent」，且第二个包装布局被丢弃
        #    （每次打开属性面板刷 6+ 条警告的根因，2026-09-12 消息钩子抓到）。

        # ---- 其余文本页签（按类型出） ----
        plain_tabs: list[str] = []
        if is_user:
            plain_tabs = ["地址", "电话", "组织", "配置文件"]
        elif kind == ObjectKind.CONTACT:
            plain_tabs = ["电话", "组织"]
        for name in plain_tabs:
            tab, form = self._add_tab(name)
            for label, attr, placeholder in _TAB_FIELDS[name]:
                self._add_field(form, label, attr, placeholder)

        # ---- 账户（用户 / 计算机） ----
        if is_user or is_computer:
            self._build_account_tab(is_user)

        # ---- 登录时间 / 拨入（F13 / F15，只对用户有意义） ----
        if is_user:
            self._build_logon_hours_tab()
            self._build_dialin_tab()

        # ---- 属性编辑器（F11，四类对象都有） ----
        self._build_attr_editor_tab()

        # ---- 对象（对齐 ADUC「高级功能 → 对象」页签） ----
        self._build_object_tab()

        # ---- 成员（组） ----
        if is_group:
            self._build_members_tab()

        # ---- 隶属于（有账号的对象和组都可能挂在别的组下） ----
        if kind != ObjectKind.CONTACT:
            self._build_memberof_tab()

        summary_bits = [f"{obj.kind_label()}　{obj.title or obj.sam}"]
        if obj.dn:
            summary_bits.append(obj.dn)
        self._summary.setText("　·　".join(summary_bits))

    # ---------- 归属校验（异步结果防错配） ----------

    def loaded_dn(self) -> str:
        """面板当前显示的是**哪个对象**（空串 = 没装任何对象）。"""
        return self._loaded_dn

    def _stale(self, dn: str) -> bool:
        """这份异步结果是不是属于「已经被切走」的旧对象？

        ⚠️ 不校验就会**写错对象**：面板是共享单例，用户在请求飞行中点了
        另一个对象，旧结果一到就贴到新对象名下 —— 用户看到的是旧值、
        按的却是新对象的「保存」/「移出成员」。空 ``dn`` 视为「调用方没
        声明归属」，按兼容处理放行（老调用点不至于静默失效）。
        """
        if not dn or not self._loaded_dn:
            return False
        return dn.casefold() != self._loaded_dn.casefold()

    # ---------- 页签构建 ----------

    def _add_tab(self, title: str) -> tuple[QWidget, QFormLayout]:
        page = QWidget()
        form = _form()
        page.setLayout(_wrap_form(form))
        self.tabs.addTab(page, title)
        return page, form

    def _add_field(self, form: QFormLayout, label: str, attr: str,
                   placeholder: str) -> None:
        value = _first_attr(self._attrs, attr)
        if attr == "department":
            # 部门从**目录里实际存在的 OU**里选（也可手输）——
            # 自由文本必然和 OU 结构脱节，填出没人认的部门名。
            edit = self._make_department_combo(placeholder, value)
        else:
            edit = QLineEdit()
            edit.setPlaceholderText(placeholder)
            if value:
                edit.setText(value)
        form.addRow(_labeled(label), edit)
        self._fields[attr.casefold()] = edit
        self._saved_values[attr.casefold()] = value

    def _make_department_combo(self, placeholder: str,
                               value: str = "") -> QComboBox:
        combo = QComboBox()
        combo.setEditable(True)
        combo.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        combo.addItem("")            # 首位留空 —— 也能把部门清掉
        combo.lineEdit().setPlaceholderText(
            placeholder or "可选（从现有部门选，或直接输入）")
        for name in getattr(self, "_department_options", []):
            if combo.findText(name) < 0:
                combo.addItem(name)
        if value:
            combo.setEditText(value)
        self._department_combo = combo
        return combo

    def set_department_options(self, names: list[str]) -> None:
        """填充部门下拉候选（页面异步读到 OU 清单后调用）。"""
        self._department_options = [n for n in (names or []) if n]
        combo = getattr(self, "_department_combo", None)
        if combo is None:
            return
        current = combo.currentText().strip()
        while combo.count() > 1:
            combo.removeItem(combo.count() - 1)
        for name in self._department_options:
            if combo.findText(name) < 0:
                combo.addItem(name)
        if current:
            combo.setEditText(current)

    def _add_readonly(self, form: QFormLayout, label: str, value: str) -> None:
        edit = QLineEdit(value or "—")
        edit.setReadOnly(True)
        form.addRow(_labeled(label), edit)

    # ---------- 登录名（sAMAccountName）：真值来源 / 输入框 / 归属 ----------

    def _live_attr(self, name: str, fallback: str = "") -> str:
        """只读展示与输入框初值的**唯一真值来源**。

        优先级：**本次读回的属性** > 传入的兜底（通常是列表行快照 ``obj.xxx``）。

        ⚠️ 为什么不能直接用 ``obj.sam``：`_obj` 是**打开面板那一刻**列表行里的
        对象快照，而保存后的回读走 `ObjectTableModel.update_rows` —— 那里是
        **替换**行对象，面板里存的这个从头到尾没人更新过。于是"在账户页改完
        登录名，常规页与「2000 前」两栏仍显示旧值"（主理人 2026-09-16 实测）。

        返回空串 = 两边都没有值 —— 由调用方决定怎么显示（`_add_readonly` 显示「—」）。
        """
        return _first_attr(self._attrs, name) or (fallback or "").strip()

    def _add_sam_field(self, form: QFormLayout, label: str) -> QLineEdit:
        """「登录名」(``sAMAccountName``) 输入框 —— 常规页与账户页**共用这一份**。

        ADUC 对同一个属性有两种叫法（「登录名」/「登录名(2000 前)」），两个
        页签都给入口，所以构造**必须**只有一份：取值来源、字符预检、占用检查、
        登记进 `_fields` / `_saved_values` 的方式各写一遍必然漂移。

        返回权威输入框。
        """
        value = self._live_attr("sAMAccountName",
                                self._obj.sam if self._obj is not None else "")
        edit = QLineEdit(value)
        edit.setMaxLength(SAM_MAX_LENGTH)
        edit.setPlaceholderText("如 zhangsan（≤20 字符，英文数字与 . -）")
        status = QLabel("")
        status.setMinimumWidth(52)

        row = QWidget()
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.addWidget(edit, 1)
        row_layout.addWidget(status)
        form.addRow(_labeled(label), row)

        if not self._sam_edits:
            # 第一个创建的当**权威**：`collect()` 只读它，占用检查只由它发起
            self._sam_edit = edit
            self._sam_status = status
            self._fields["samaccountname"] = edit
            self._saved_values["samaccountname"] = value
            edit.textChanged.connect(self._on_sam_changed)
        else:
            # 其余是**镜像**：只负责把用户的输入推给权威输入框（显示由权威回推）。
            # ⚠️ 只给权威那一个接 `_on_sam_changed` —— 两个都接的话，一次按键会
            #    发起两次占用检查（镜像的 setText 同样会发 textChanged）。
            edit.textChanged.connect(
                lambda text, mirror=edit: self._push_sam_to_authority(text, mirror))
            self._sam_edit.textChanged.connect(edit.setText)
        self._sam_edits.append(edit)
        return edit

    def _push_sam_to_authority(self, text: str, mirror: QLineEdit) -> None:
        """镜像输入框把用户的输入推给权威输入框。

        ``QLineEdit.setText`` 在文本相同时**不发** textChanged ⇒ 天然收敛，
        不会来回震荡。
        """
        authority = self._sam_edit
        if authority is None or authority is mirror:
            return
        if authority.text() != text:
            authority.setText(text)

    def _on_sam_changed(self, text: str) -> None:
        """登录名改动：本地字符预检（共享判据）+ 异步占用检查（带归属）。"""
        if apply_sam_precheck(self._sam_status, text):
            value = text.strip()
            saved = self._saved_values.get("samaccountname", "")
            if value.casefold() == (saved or "").casefold():
                # 就是本对象当前的登录名 —— 不可能与自己撞名：别白跑一趟域控，
                # 更不许报「已占用」（那会让人以为一保存就要冲突）。
                self._set_sam_verdict("ok", "可用", "ok")
            else:
                self._set_sam_verdict("checking", "检查中…", "muted")
                self.check_sam.emit(value)
        else:
            # `apply_sam_precheck` 已经把文字写好了（空 / 字符非法），
            # 这里只把**闸门状态**对齐 —— 两者必须一起变，见 `_set_sam_verdict`。
            self._set_sam_verdict(
                "invalid" if text.strip() else "empty", None)
        self._refresh_upn_sync_note()

    def _set_sam_verdict(self, verdict: str, text: str | None,
                         level: str = "muted") -> None:
        """登录名的**闸门状态**与屏幕文字一起写（唯一出口）。

        `_sam_gate_error` 拿这个状态决定要不要在本地拦住保存 —— 状态与文字
        分开写迟早会漂（屏幕上写着"已占用"、闸门却以为"可用"）。
        ``text=None`` = 文字已由别处写好（`apply_sam_precheck`），只更新状态。
        """
        self._sam_verdict = verdict
        if text is not None and self._sam_status is not None:
            _set_sam_status(self._sam_status, text, level)

    def set_sam_result_for(self, sam: str, taken: bool) -> None:
        """占用检查的**结论**回来了（异步，必须带归属）。

        不判归属就会露在脸上：使用者边打边查，前一个名字的「可用」会追上来
        盖住当前名字的状态 —— 看到「可用」就保存，撞名了也不知道为什么。
        """
        if not self._sam_input_matches(sam):
            return
        self._set_sam_verdict("taken" if taken else "ok",
                              "已占用" if taken else "可用",
                              "danger" if taken else "ok")

    def set_sam_check_failed_for(self, sam: str) -> None:
        """占用检查本身失败（如域控不可达）—— 状态置为"未知"，**不拦保存**。

        拦在这里等于"域控一抖就谁都存不了"；真正撞名时域控自己会拒绝，
        不该由一条查不动的预检来决定能不能保存。
        """
        if not self._sam_input_matches(sam):
            return
        self._set_sam_verdict("unknown", "检查失败", "warn")
        if self._sam_status is not None:
            self._sam_status.setToolTip("登录名占用检查失败，未能确认是否可用")

    def _sam_input_matches(self, sam: str) -> bool:
        """这份异步结论是不是当前输入框里那个名字的（共享归属判据）。"""
        if self._sam_edit is None:
            return False
        return sam_status_applies(self._sam_edit.text(), sam)

    def _sam_gate_error(self) -> str:
        """登录名的**本地闸门**：返回空串 = 放行，否则是拦住保存的中文原因。

        走 `collect()["errors"]` 这条既有通道：页面拿到非空 errors 就**不发起
        任何写入**（见 `BrowserPage._submit_property_save`），所以闸门在这里
        判定即可，不必让页面认识登录名。
        """
        edit = self._fields.get("samaccountname")
        if edit is None:
            return ""                       # 这个对象类型没有登录名入口
        new = edit.text().strip()
        if new == self._saved_values.get("samaccountname", ""):
            return ""                       # 没改，不关我的事
        if not new:
            return "「登录名」不能清空 —— sAMAccountName 是账号的登录标识"
        reason = validate_sam_chars(new)
        if reason:
            return "「登录名」：" + reason
        if self._sam_verdict == "taken":
            return f"登录名「{new}」已被占用，请换一个"
        return ""

    # ---------- 登录名 → UPN 同步（可选，默认不勾） ----------

    def _synced_upn(self, new_sam: str) -> tuple[str, str]:
        """「改登录名时同步更新 UPN 前缀」的**唯一判据**。

        :return: ``(要写进 userPrincipalName 的值, 不同步的原因)`` ——
                 能同步时原因是空串；不能同步时值是空串（**调用方不许写 UPN**）。
        """
        old_sam = self._saved_values.get("samaccountname", "")
        old_upn = self._saved_values.get("userprincipalname", "")
        if not new_sam or new_sam == old_sam:
            return "", "登录名没有改动"
        if not old_upn:
            return "", "这个账号还没有 UPN（属性为空），没有可保留的后缀"
        if "@" not in old_upn:
            return "", f"原 UPN「{old_upn}」不含 @ 后缀，无法确定该保留什么"
        prefix, _, suffix = old_upn.partition("@")
        if prefix.casefold() != (old_sam or "").casefold():
            return "", (f"原 UPN「{old_upn}」的前缀不是旧登录名「{old_sam}」——"
                        f"两者本来就不是同一套命名，跟着改等于篡改你设过的 UPN")
        return f"{new_sam}@{suffix}", ""

    def _upn_edited_by_hand(self) -> bool:
        """UPN 输入框是否被手工改过（改过就以手工值为准，不自动覆盖）。"""
        edit = self._fields.get("userprincipalname")
        if edit is None:
            return False
        return edit.text().strip() != self._saved_values.get("userprincipalname", "")

    def _refresh_upn_sync_note(self) -> None:
        """把「勾了同步，但这次不会同步」的**原因**摆在脸上。

        不许偷偷改（默认不勾，且只在判据成立时才写 UPN），也不许偷偷不改
        （勾了却什么都没发生、也不解释，是最坏的一种）。
        """
        note, sync = self._upn_sync_note, self._sync_upn
        if note is None or sync is None:
            return
        if not sync.isChecked():
            note.setText("")
            return
        if self._upn_edited_by_hand():
            note.setText("UPN 已手工改动，以手工值为准，不再自动同步")
            return
        new_sam = self._sam_edit.text().strip() if self._sam_edit is not None else ""
        target, reason = self._synced_upn(new_sam)
        note.setText(f"保存时会把 UPN 一并改为 {target}" if target
                     else f"不会同步 UPN：{reason}")

    def _build_account_tab(self, is_user: bool) -> None:
        from utils import UF_DONT_EXPIRE_PASSWORD

        obj = self._obj
        tab, form = self._add_tab("账户")

        if is_user:
            # 「登录名(2000 前)」= sAMAccountName，与常规页的「登录名」**同一个属性**
            # （ADUC 的两种叫法都保留，但必须是同一份实现、并且互相镜像 ——
            # 否则在常规页改完切到账户页看到的还是旧值，而 collect() 只读一个）。
            sam_edit = self._add_sam_field(form, "登录名(2000 前)")
            self._add_field(form, "登录名(UPN)", "userPrincipalName",
                            f"{sam_edit.text() or '登录名'}@域名")
            # UPN 被手工改动时也要刷新下面的提示：不然提示还写着"会把 UPN 改为 …"，
            # 而实际保存用的是手工值 —— 提示与实际行为不一致就是在说谎。
            self._fields["userprincipalname"].textChanged.connect(
                self._refresh_upn_sync_note)

            # 可选同步（默认**不勾**）：登录名与 UPN 是**两个**属性，ADUC 改
            # sAMAccountName 不会动 userPrincipalName —— 想一起改必须显式要求。
            self._sync_upn = QCheckBox("改登录名时同步更新 UPN 前缀")
            self._sync_upn.setChecked(False)
            self._sync_upn.setToolTip(
                "只在原 UPN 的前缀正好等于旧登录名时才会同步；否则保持原样，"
                "并在下面说明原因（绝不偷偷改另一个属性）")
            self._sync_upn.toggled.connect(self._refresh_upn_sync_note)
            form.addRow(_labeled(""), self._sync_upn)
            self._upn_sync_note = hint_label("")
            form.addRow(_labeled(""), self._upn_sync_note)

            # ---- 账户过期 ----
            raw_expiry = _first_attr(self._attrs, "accountExpires")
            self._expiry_never = QCheckBox("永不过期")
            expiry_dt = _filetime_to_datetime(raw_expiry)
            self._expiry_never.setChecked(expiry_dt is None)
            self._expiry_pick = QDateTimeEdit()
            self._expiry_pick.setCalendarPopup(True)
            self._expiry_pick.setDisplayFormat("yyyy-MM-dd HH:mm")
            if expiry_dt is not None:
                self._expiry_pick.setDateTime(QDateTime(expiry_dt))
            else:
                self._expiry_pick.setDateTime(
                    QDateTime.currentDateTime().addYears(1))
            self._expiry_never.toggled.connect(
                lambda on: self._expiry_pick.setEnabled(not on))
            self._expiry_pick.setEnabled(expiry_dt is not None)
            expiry_row = QWidget()
            row = QHBoxLayout(expiry_row)
            row.setContentsMargins(0, 0, 0, 0)
            row.addWidget(self._expiry_pick, 1)
            form.addRow(_labeled("账户过期"), self._expiry_never)
            form.addRow(_labeled("过期时间"), expiry_row)
            self._saved_values["__expiry"] = raw_expiry
            # 🔴 `""` = 这个属性**没读到**，与"永不过期"是两件事（2026-09-17 改）。
            #    旧写法只判 `expiry_dt is None`，而 `_filetime_to_datetime("")`
            #    也是 `None` ⇒ **"读不到"被显示成"勾上了永不过期"**。
            #    这一页是**写入口**：使用者看到勾着，以为策略已经设好，
            #    其实什么都没读到；而收集器的差分逻辑还会把"未知"翻成一条
            #    具体日期（`new_never=False != old_never=True` ⇒ 写"一年后过期"）。
            self._expiry_unknown = not raw_expiry
            if self._expiry_unknown:
                _mark_checkbox_unknown(
                    self._expiry_never,
                    "读不到 accountExpires 属性，无法判断当前的账户过期设置。"
                    "为避免把「未知」写成一条具体策略，该开关与其时间框已停用；"
                    "请刷新后重试。")
                self._expiry_pick.setEnabled(False)

            # ---- 两个密码开关 ----
            # 🔴 读不到 `userAccountControl` ⇒ **不许**按"未勾选"显示（2026-09-17 改）。
            #    旧写法 `int(_first_attr(...) or 0)`：读不到 ⇒ 0 ⇒ 未勾选 ⇒ 显示成
            #    **"会过期"**，而真实值可能是"永不过期" —— **方向正好相反**。
            #    这是写入口，使用者顺手一存就真的把策略改掉了。
            raw_uac = _first_attr(self._attrs, "userAccountControl")
            uac_value = text_to_int(raw_uac)
            self._pwd_never_unknown = uac_value is None
            self._pwd_never = QCheckBox("密码永不过期")
            self._pwd_never.setChecked(
                False if uac_value is None
                else bool(uac_value & UF_DONT_EXPIRE_PASSWORD))
            form.addRow(_labeled("密码策略"), self._pwd_never)
            self._saved_values["__pwd_never"] = str(self._pwd_never.isChecked())
            if self._pwd_never_unknown:
                _mark_checkbox_unknown(
                    self._pwd_never,
                    "读不到 userAccountControl 属性，无法判断当前的密码策略。"
                    "为避免改错方向，该开关已停用；请刷新后重试。")

            # 🔴 同一个形状的第 8 处（2026-09-17 顺手发现并一并修）：
            #    旧写法 `_first_attr(...) == "0"` 把"读不到"（空串）与
            #    "pwdLastSet 是 0"（真的要求下次登录改密）混成同一个 `False`。
            raw_pwd_last_set = _first_attr(self._attrs, "pwdLastSet")
            self._must_change_unknown = not raw_pwd_last_set
            self._must_change = QCheckBox("下次登录必须修改密码")
            self._must_change.setChecked(raw_pwd_last_set == "0")
            form.addRow(_labeled(""), self._must_change)
            self._saved_values["__must_change"] = str(self._must_change.isChecked())
            if self._must_change_unknown:
                _mark_checkbox_unknown(
                    self._must_change,
                    "读不到 pwdLastSet 属性，无法判断是否要求下次登录改密。"
                    "为避免改错方向，该开关已停用；请刷新后重试。")

            # ---- 登录到（工作站限制，F14） ----
            ws_raw = ",".join(_parse_workstations(
                lookup_attr(self._attrs, "userWorkstations")))
            self._ws_limit = QCheckBox("限制只允许登录到下列工作站（逗号分隔）")
            self._ws_edit = QLineEdit()
            self._ws_edit.setPlaceholderText("如 PC-FIN-01, PC-FIN-02（空 = 不限制）")
            self._ws_edit.setText(ws_raw)
            self._ws_limit.setChecked(bool(ws_raw))
            self._ws_edit.setEnabled(bool(ws_raw))
            self._ws_limit.toggled.connect(self._ws_edit.setEnabled)
            form.addRow(_labeled("登录到"), self._ws_limit)
            form.addRow(_labeled("工作站"), self._ws_edit)
            self._saved_values["__ws"] = ws_raw
        else:
            # 计算机：登录名（`PC-01$`）与 cn/dNSHostName 绑在一起，
            # 只改它会把这台机器搞成"cn 与 sAMAccountName 不一致"——
            # 保持只读，但取值同样走真值来源。
            self._add_readonly(form, "登录名",
                               self._live_attr("sAMAccountName", obj.sam))
            self._add_readonly(form, "账号状态",
                               account_state_label(obj.enabled))
            self._saved_values["__expiry"] = _first_attr(self._attrs, "accountExpires")
            # 计算机的过期编辑关闭（改机器过期时间没有运维场景，别给误操作入口）
            self._expiry_never = None
            self._expiry_pick = None
            self._pwd_never = None
            self._must_change = None
            # 这三个 `unknown` 标记跟着一起清掉：上面三个控件是 `None`，
            # 收集器本来就跳过；留着 True 会让下一个人读代码时以为还有意义。
            self._expiry_unknown = False
            self._pwd_never_unknown = False
            self._must_change_unknown = False
            self._ws_limit = None
            self._ws_edit = None

        hint = ("重命名 / 移动 / 启用禁用请用右键菜单；"
                "「登录名」是 sAMAccountName（登录 Windows 用的 2000 前格式账号名，"
                "≤20 字符），「登录名(UPN)」是 userPrincipalName —— "
                "「那是另一个属性」：改登录名「不会」动 UPN，也不会改「名称」(cn)，"
                "想一并改 UPN 请勾上面的同步项。"
                if is_user else
                "重置计算机账户 / 启用禁用请用右键菜单。")
        tab.layout().addWidget(hint_label(hint))

    def _build_logon_hours_tab(self) -> None:
        """登录时间（F13）。显示按本地时间，换算在保存时统一做。"""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        self._hours_grid = LogonHoursGrid()
        # 位图是二进制属性，不能从通用属性表（字符串化）解析 ——
        # 由页面通过 `fill_logon_hours()` 异步喂进来。
        self._hours_grid.set_all(True)
        layout.addWidget(self._hours_grid, 1)
        self._hours_hint = hint_label("正在读取登录时间…")
        layout.addWidget(self._hours_hint)

        buttons = QHBoxLayout()
        allow = QPushButton("全部允许")
        allow.clicked.connect(lambda: self._hours_grid.set_all(True))
        deny = QPushButton("全部拒绝")
        deny.clicked.connect(lambda: self._hours_grid.set_all(False))
        clear = QPushButton("清除限制")
        clear.clicked.connect(self._on_clear_hours_limit)
        for w in (allow, deny, clear):
            w.setCursor(Qt.CursorShape.PointingHandCursor)
            buttons.addWidget(w)
        buttons.addStretch(1)
        layout.addLayout(buttons)
        # 初始状态三件套：初始格子（本地序）、初始是否"未限制"、当前是否要求清除
        self._hours_initial_cells = self._hours_grid.cells()
        self._hours_initial_cleared = True
        self._hours_cleared = True
        self._hours_loaded = False
        self.tabs.addTab(page, "登录时间")

    def fill_logon_hours(self, raw: bytes | None, dn: str = "") -> None:
        """页面读回位图后调用。``None`` = 未限制。

        ``dn`` = 这次读取是为哪个对象发起的。用户在飞行中换了账号时
        A 的位图**不能**落进 B 的格子 —— 否则一按保存就把 A 的登录时间
        写到 B 身上（用户报的「每个功能都要审查」正是这一类）。
        """
        if self._obj is None or self._obj.kind != ObjectKind.USER:
            return
        if self._stale(dn):
            return
        offset = _local_utc_offset_minutes()
        utc_cells = logon_hours_from_bytes(raw)
        if utc_cells is None:
            self._hours_grid.set_all(True)
            # ⚠️ `_hours_hint` 是**纯文本** QLabel（`ui_widgets.hint_label`，
            #    没有 setTextFormat）⇒ 文案里不许写 `**`，否则界面上原样显示星号。
            #    守这条的是
            #    `tests/test_source_hygiene.py::TestNoMarkdownMarkersInProductionLiterals`。
            self._hours_hint.setText(
                "当前未设置登录时间限制（全时允许）。下表按本地时间显示；"
                "保存时自动换算为域控的 UTC 位图。")
        else:
            self._hours_grid.set_cells(logon_hours_shift(utc_cells, -offset))
            self._hours_hint.setText(
                "下表按本地时间显示（与 ADUC 一致），保存时自动换算为 UTC。")
        self._hours_initial_cells = self._hours_grid.cells()
        self._hours_initial_cleared = utc_cells is None
        self._hours_cleared = utc_cells is None
        self._hours_loaded = True

    def _on_clear_hours_limit(self) -> None:
        """清除限制 = 删掉 logonHours 属性（全时允许）。"""
        self._hours_grid.set_all(True)
        self._hours_cleared = True

    def _build_dialin_tab(self) -> None:
        """拨入（F15）。三态 + 回拨，与 ADUC「网络访问权限」对齐。"""
        page = QWidget()
        form = _form()

        dialin = self._read_dialin_attrs()
        self._dialin_mode = QComboBox()
        self._dialin_mode.addItem("允许访问")
        self._dialin_mode.addItem("拒绝访问")
        self._dialin_mode.addItem("由 NPS 网络策略控制")
        allow = dialin.get("allow")
        self._dialin_mode.setCurrentIndex(
            0 if allow is True else 1 if allow is False else 2)
        form.addRow(_labeled("网络访问"), self._dialin_mode)

        callback = dialin.get("callback", "") or ""
        self._callback_on = QCheckBox("总是回拨到以下号码")
        self._callback_on.setChecked(bool(callback))
        self._callback_edit = QLineEdit()
        self._callback_edit.setPlaceholderText("回拨号码，如 0755-12345678")
        self._callback_edit.setText(callback)
        self._callback_edit.setEnabled(bool(callback))
        self._callback_on.toggled.connect(self._callback_edit.setEnabled)
        form.addRow(_labeled("回拨"), self._callback_on)
        form.addRow(_labeled("回拨号码"), self._callback_edit)

        page.setLayout(_wrap_form(form))
        self.tabs.addTab(page, "拨入")
        self._dialin_tab = page
        page.layout().addWidget(hint_label(
            "「由 NPS 网络策略控制」= 删除 msNPAllowDialin，由域的 RADIUS/"
            "网络策略决定 —— 没配 NPS 的域选这个等同拒绝。\n"
            "改这些设置影响 VPN / 远程访问，请先确认策略再保存。"))

    def _read_dialin_attrs(self) -> dict[str, Any]:
        allow_raw = _first_attr(self._attrs, "msNPAllowDialin")
        if allow_raw == "":
            allow: Any = None
        else:
            allow = str(allow_raw).strip().upper() == "TRUE"
        return {"allow": allow,
                "callback": _first_attr(self._attrs, "msRADIUSCallbackNumber")}

    def _build_attr_editor_tab(self) -> None:
        """属性编辑器（F11）。

        **两道判据、各管一件事**（缺一不可，别合并）：

        * `models.is_attribute_writable` —— 这个属性**政策上**允不允许写
          （黑名单 / 托管属性），数据层说了算；
        * `utils.has_text_write_back_form` —— 这个属性**在通用文本框里**有没有
          能原样写回去的文本形态；没有的话（如 `logonHours` 是 21 字节位图）
          这一格不提供文本编辑，提示指向专用入口。

        ⚠️ 后一条**不是**把属性塞进黑名单：`is_attribute_writable` 仍然说它可写、
           仍然挂着提示 —— 只是**它只有一个写入口**（专用面板）。
        """
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        self.attr_table = _MiniTable(["属性", "说明", "值"], widths=[150, 170],
                                     single=True)
        self.attr_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows)
        self.attr_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers)
        self.attr_table.itemSelectionChanged.connect(self._on_editor_attr_picked)
        layout.addWidget(self.attr_table, 1)

        self.attr_edit = QPlainTextEdit()
        self.attr_edit.setPlaceholderText(
            "选中上面的属性后在此编辑。多值属性一行一个值；\n"
            "清空全部内容并加入队列 = 删除该属性。")
        self.attr_edit.setMaximumHeight(96)
        layout.addWidget(self.attr_edit)

        buttons = QHBoxLayout()
        queue_btn = QPushButton("加入改动队列")
        queue_btn.clicked.connect(self._on_queue_attr_change)
        remove_btn = QPushButton("撤销队列中选中项")
        remove_btn.clicked.connect(self._on_unqueue_attr_change)
        for w in (queue_btn, remove_btn):
            w.setCursor(Qt.CursorShape.PointingHandCursor)
            buttons.addWidget(w)
        buttons.addStretch(1)
        layout.addLayout(buttons)

        self.attr_queue_table = _MiniTable(["待保存的改动"])
        self.attr_queue_table.setMaximumHeight(88)
        layout.addWidget(self.attr_queue_table)
        layout.addWidget(hint_label(
            "⚠️ 改错属性可能导致账号无法登录。对象 SID / GUID / objectClass 等"
            "系统属性被列入黑名单，后端会拒绝写入。"))
        self.tabs.addTab(page, "属性编辑器")
        self._fill_attr_editor()

    def _build_object_tab(self) -> None:
        """对象页签（对齐 ADUC「高级功能 → 对象」）。

        展示不常改但排查问题必看的系统元数据：DN、类别、类继承链、
        创建/修改时间。GUID/SID 只有真的读到才展示 —— 演示模式不装。
        """
        obj = self._obj
        tab, form = self._add_tab("对象")

        self._add_readonly(form, "可分辨名称 (DN)", obj.dn or "—")

        category = _first_attr(self._attrs, "objectCategory")
        self._add_readonly(form, "对象类别",
                           category or obj.kind_label() or "—")

        classes = ", ".join(str(v) for v in (self._attrs.get("objectClass")
                                             or []))
        self._add_readonly(form, "对象类（继承链）", classes or "—")

        for attr, label in (("whenCreated", "创建时间"),
                            ("whenChanged", "最近修改")):
            raw = _first_attr(self._attrs, attr)
            dt = ad_generalized_time_to_dt(raw) if raw else None
            shown = dt.strftime("%Y-%m-%d %H:%M:%S") if dt else (raw or "—")
            self._add_readonly(form, label, shown)

        for attr, label in (("objectGUID", "对象 GUID"),
                            ("objectSid", "对象 SID")):
            raw = _first_attr(self._attrs, attr)
            if raw:
                self._add_readonly(form, label, str(raw))

        # 布局已由 _add_tab 接好 —— 同 load() 里的说明，禁止重复 setLayout。

    def _fill_attr_editor(self) -> None:
        """把当前属性表灌进编辑器表格。

        列布局：**属性 / 说明 / 值** —— 对齐 ADUC 属性编辑器去掉「语法」列
        （中文说明对使用者信息量更大）。语法信息不丢，收进属性名的悬浮提示。
        """
        rows = sorted(self._attrs.items(), key=lambda kv: kv[0].casefold())
        self.attr_table.setRowCount(len(rows))
        for row, (name, values) in enumerate(rows):
            name_item = QTableWidgetItem(name)
            name_item.setData(Qt.ItemDataRole.UserRole, name)
            tip = f"{name}\n语法：{_attr_syntax(name, values)}"
            # 🔴 这一格**不提供文本编辑**时，把「为什么 / 去哪里改」挂在名字上 ——
            #    进这个页签的人多半先扫属性名，不必先点一下才发现不能改。
            if not has_text_write_back_form(name):
                tip += f"\n⚠️ {self._text_form_pointer(name)}"
            name_item.setToolTip(tip)
            self.attr_table.setItem(row, 0, name_item)

            doc = _ATTR_DOCS.get(name.casefold(), "—")
            doc_item = QTableWidgetItem(doc)
            doc_item.setToolTip(doc)
            self.attr_table.setItem(row, 1, doc_item)

            joined = "; ".join(str(v) for v in values)
            if len(joined) > 120:
                joined = joined[:117] + "…"
            value_item = QTableWidgetItem(joined)
            # ⚠️ 值列这一格显示的是**摘要/文本形态**，不是"原样能写回去的值"——
            #    它在下面 `_on_editor_attr_picked` / `_on_queue_attr_change` 两处
            #    都被拒（**两道门**：预填与入队），所以显示摘要不构成误导。
            value_tip = "\n".join(str(v) for v in values)
            if not has_text_write_back_form(name):
                value_tip += f"\n\n⚠️ {self._text_form_pointer(name)}"
            value_item.setToolTip(value_tip)
            self.attr_table.setItem(row, 2, value_item)
        self._refresh_attr_queue_table()

    @staticmethod
    def _text_form_pointer(name: str) -> str:
        """「这一格为什么不提供文本编辑」+「该去哪里改」——**唯一**一处说法。

        🔴 判据只认**属性名**（`utils.has_text_write_back_form`）：这个属性的
           写入形态是 AD 的**原始字节**（`logonHours` 就是 21 字节位图），
           **不是文本**；通用文本编辑器**没有能写回去的文本形态**，所以这里
           不提供文本编辑。
        ⚠️ 这**不是**"塞黑名单"（`models.is_attribute_writable` 仍然说它可写、
           仍然挂着提示），而是**这个属性只有一个写入口** —— 专用面板。
        ⚠️ **不许**为它发明一种文本格式（十六进制串之类）来"让格子变得能写"：
           那是自造一个 AD 与 ADUC 都不认的中间语言。
        """
        where = ATTRIBUTE_MANAGED.get(name.casefold(), "") or "它自己的专用面板。"
        return (f"「{name}」的写入形态是 AD 的原始字节，「不是文本」 —— "
                f"通用文本编辑器没有能写回去的文本形态，所以这里不提供文本编辑。"
                f"请改专用入口：{where}")

    def _on_editor_attr_picked(self) -> None:
        rows = sorted({i.row() for i in self.attr_table.selectedIndexes()
                       if i.isValid()})
        if not rows:
            return
        item = self.attr_table.item(rows[0], 0)
        if item is None or not item.data(Qt.ItemDataRole.UserRole):
            return
        name = item.data(Qt.ItemDataRole.UserRole)
        self._editor_attr = name
        # 没有文本写回形态的属性：**不预填**。预填等于把摘要当成"它的值"摆进
        # 编辑框，使用者什么都不改直接点「加入队列」就会把摘要排进写入队列 ——
        # 这正是 2026-09-16 那条缺陷（`D-20` 的第二个面）。
        if not has_text_write_back_form(name):
            self.attr_edit.setPlainText("")
            self._set_editor_hint(self._text_form_pointer(name))
            return
        values = lookup_attr(self._attrs, name)
        self.attr_edit.setPlainText(
            "\n".join(str(v) for v in values) if values else "")

    def _on_queue_attr_change(self) -> None:
        """把编辑框内容登记为一条改动（保存按钮统一提交）。"""
        name = (self._editor_attr or "").strip()
        if not name:
            self._set_editor_hint("请先在表格里选中一个属性。")
            return
        allowed, reason = is_attribute_writable(name)
        if not allowed:
            self._set_editor_hint(f"「{name}」不允许在这里改：{reason}")
            return
        # 🔴 **第二道门**（第一道在 `_on_editor_attr_picked` 的"不预填"）：
        #    光靠不预填挡不住"先选中它、再往编辑框里手打一段文本"这条路。
        #    没有文本写回形态的属性在这里**一律拒**，提示指向它的专用入口。
        if not has_text_write_back_form(name):
            self._set_editor_hint(self._text_form_pointer(name))
            return
        lines = [ln.strip() for ln in
                 self.attr_edit.toPlainText().splitlines() if ln.strip()]
        change = AttributeChange(name, lines)
        self._pending_attr_changes = [
            c for c in self._pending_attr_changes
            if c.attribute.casefold() != name.casefold()]
        self._pending_attr_changes.append(change)
        note = f"（提示：{reason}）" if reason else ""
        self._set_editor_hint(
            f"已把「{change}」加入队列{note} —— 点左下「保存」才会真正写入。")
        self._refresh_attr_queue_table(change)

    def _on_unqueue_attr_change(self) -> None:
        rows = sorted({i.row() for i in self.attr_queue_table.selectedIndexes()
                       if i.isValid()})
        if not rows:
            return
        self._pending_attr_changes.pop(min(rows[-1], len(self._pending_attr_changes) - 1), None)
        self._refresh_attr_queue_table()

    def _refresh_attr_queue_table(self, highlight: AttributeChange | None = None) -> None:
        items = [str(c) for c in self._pending_attr_changes]
        self.attr_queue_table.setRowCount(len(items))
        for row, text in enumerate(items):
            self.attr_queue_table.setItem(row, 0, QTableWidgetItem(text))

    def _set_editor_hint(self, text: str) -> None:
        self._summary.setText(text)

    def _build_members_tab(self) -> None:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        self.member_table = _MiniTable(["名称", "类型", "登录名"], widths=[190, 80])
        layout.addWidget(self.member_table, 1)

        buttons = QHBoxLayout()
        add = QPushButton("添加成员…")
        add.clicked.connect(lambda: self._member_mode(True))
        remove = QPushButton("移除选中成员")
        remove.clicked.connect(self._on_remove_members)
        self.member_reload = QPushButton("刷新成员")
        self.member_reload.clicked.connect(self._on_reload_members)
        for w in (add, remove, self.member_reload):
            w.setCursor(Qt.CursorShape.PointingHandCursor)
            buttons.addWidget(w)
        buttons.addStretch(1)
        layout.addLayout(buttons)

        # ---- 添加成员的行内搜索区（内联，不弹窗） ----
        self.member_add_box = QWidget()
        add_layout = QVBoxLayout(self.member_add_box)
        add_layout.setContentsMargins(0, 0, 0, 0)
        add_layout.setSpacing(6)
        self.member_search = SearchLineEdit("输入名称 / 登录名搜索用户、组、计算机…")
        self.member_search.submitted.connect(self.search_objects_requested.emit)
        add_layout.addWidget(self.member_search)
        self.member_search_table = _MiniTable(
            ["名称", "类型", "登录名", "DN"], widths=[170, 80, 110])
        self.member_search_table.doubleClicked.connect(self._on_add_searched)
        add_layout.addWidget(self.member_search_table, 1)
        add_buttons = QHBoxLayout()
        add_ok = QPushButton("加入选中项")
        add_ok.clicked.connect(self._on_add_searched)
        back = QPushButton("返回成员列表")
        back.clicked.connect(lambda: self._member_mode(False))
        add_buttons.addWidget(add_ok)
        add_buttons.addWidget(back)
        add_buttons.addStretch(1)
        add_layout.addLayout(add_buttons)
        self.member_add_box.setVisible(False)
        layout.addWidget(self.member_add_box)

        self.tabs.addTab(page, "成员")
        self._member_mode(False)

    def _member_mode(self, adding: bool) -> None:
        self.member_add_box.setVisible(adding)
        self.member_table.setVisible(not adding)
        self.member_reload.setVisible(not adding)
        if adding:
            self.member_search.setFocus()

    def _on_reload_members(self) -> None:
        # 用 _loaded_dn 而不是 _obj.dn：两者同源，但 _loaded_dn 是「这张表
        # 属于谁」的唯一权威 —— 以后加面板复用也只会有一处真相。
        if self._obj is not None and self._loaded_dn:
            self.load_members_requested.emit(self._loaded_dn)

    @staticmethod
    def _selected_dns(table: QTableWidget, column: int) -> list[str]:
        """表里选中行的 DN 列表 —— **唯一一份**实现。

        取 DN 靠的是第 `column` 列 `UserRole` 里存的 DN（显示文本会被截断、
        也可能重名，不能当标识用）。
        ⚠️ 之所以抽出来：以前"选中→DN"这段在三个入口里各写一遍，而它们
        **都没写 else** —— 同一个判据抄三遍就会漏三遍。现在处理函数与
        "要不要置灰按钮"共用这一个。
        """
        rows = sorted({i.row() for i in table.selectedIndexes() if i.isValid()})
        out: list[str] = []
        for row in rows:
            item = table.item(row, column)
            if item is not None and item.data(Qt.ItemDataRole.UserRole):
                out.append(item.data(Qt.ItemDataRole.UserRole))
        return out

    def _on_remove_members(self) -> None:
        dns = self._selected_dns(self.member_table, 2)
        if dns:
            self.remove_members_requested.emit(dns)
            return
        # 没选中 ⇒ **必须说一句**（双击也走这里，置灰拦不住双击）。
        self.notice.emit("请先在成员列表里选中要移除的成员。")

    def _on_add_searched(self, *_args) -> None:
        dns = self._selected_dns(self.member_search_table, 3)
        if dns:
            self.add_members_requested.emit(dns)
            return
        self.notice.emit("请先在搜索结果里选中要加入的账号。")

    # ---------- 成员表填充（页面异步取回后调用） ----------

    def fill_members(self, members: list[DirObject], dn: str = "") -> None:
        """``dn`` = 这次成员读取是为哪个组发起的（见 ``_stale``）。

        不校验的后果不是「显示错」这么轻：A 组的成员显示在 B 组的成员页里，
        用户点「移出选中」→ 被移出的其实是 **A 组的成员**，而操作目标写的是 B。
        """
        if self._stale(dn):
            return
        self.member_table.setRowCount(len(members))
        for row, obj in enumerate(members):
            self.member_table.setItem(row, 0, QTableWidgetItem(obj.title or "—"))
            self.member_table.setItem(row, 1, QTableWidgetItem(obj.kind_label()))
            item = QTableWidgetItem(obj.sam or "—")
            item.setData(Qt.ItemDataRole.UserRole, obj.dn)
            item.setToolTip(obj.dn)
            self.member_table.setItem(row, 2, item)
        if self._obj is not None:
            self._summary.setText(
                f"{self._obj.kind_label()}　{self._obj.title}"
                f"　·　成员 {len(members)} 个")

    def fill_member_search(self, results: list[DirObject], dn: str = "") -> None:
        """搜索结果填充（排除组自己）。``dn`` = 这次搜索为哪个组发起。"""
        if self._stale(dn):
            return
        self_dn = self._loaded_dn.casefold()
        results = [o for o in results if o.dn.casefold() != self_dn]
        self.member_search_table.setRowCount(len(results))
        for row, obj in enumerate(results):
            self.member_search_table.setItem(
                row, 0, QTableWidgetItem(obj.title or "—"))
            self.member_search_table.setItem(
                row, 1, QTableWidgetItem(obj.kind_label()))
            self.member_search_table.setItem(
                row, 2, QTableWidgetItem(obj.sam or "—"))
            item = QTableWidgetItem(obj.dn)
            item.setData(Qt.ItemDataRole.UserRole, obj.dn)
            item.setToolTip(obj.dn)
            self.member_search_table.setItem(row, 3, item)

    def fill_memberof(self, dns: list[str] | None, dn: str = "") -> None:
        """「隶属于」表的填充（属性读回后由页面调用）。

        ``dns=None`` = **没有读到** memberOf（属性整个不在读数里 / 这次读取失败）
        —— 与「不属于任何组」**不是一回事**，两种情形必须分开说。
        合并的后果正是本项目记过的那条：**把「取数失败」当成「证据成立」**，
        于是"域控没返回这个属性"被显示成"这个账号不属于任何组"。

        ``dn`` = 这次读取是为哪个对象发起的（见 ``_stale``）。面板是共享单例，
        用户在请求飞行中点了另一个对象时，A 的组列表**不能**贴到 B 名下 ——
        否则用户看到的是 A 的组、按的却是 B 的「移出选中组」。
        """
        if self._stale(dn):
            return
        rows = [] if dns is None else list(dns)
        self.memberof_table.setRowCount(len(rows))
        for row, group_dn in enumerate(rows):
            label = QTableWidgetItem(group_dn.split(",")[0].split("=", 1)[-1])
            item = QTableWidgetItem(group_dn)
            item.setData(Qt.ItemDataRole.UserRole, group_dn)
            item.setToolTip(group_dn)
            self.memberof_table.setItem(row, 0, label)
            self.memberof_table.setItem(row, 1, item)
        self._set_memberof_hint(dns, len(rows))

    def _set_memberof_hint(self, dns: list[str] | None, count: int) -> None:
        """三态提示：未读到 / 不属于任何组 / 共 N 个组。

        ⚠️ 前两态**必须分开**（见 `fill_memberof`）—— 空表本身说明不了任何事，
        旁边那句提示才是用户唯一可判断的依据。

        ⚠️⚠️ 这里落的是**纯文本** `QLabel`（`ui_widgets.hint_label`，
        没有 `setTextFormat`，**不认 Markdown**）⇒ **文案里不许写 `**` 之类标记**，
        否则界面上原样显示成星号（2026-09-17 看截图才发现：判据当时全绿，
        因为它只断言了"三种提示互不相同"，没断言"文案里没有标记"）。
        守这条的是
        `tests/test_source_hygiene.py::TestNoMarkdownMarkersInProductionLiterals`。
        """
        if dns is None:
            status = ("⚠️ 没有读到 memberOf 属性 —— 可能是本机这次读取失败，"
                      "也可能是域控没返回它。点「刷新」(F5) 重试。")
        elif count:
            status = f"共 {count} 个组。"
        else:
            status = "该对象不属于任何组（域控返回了空的 memberOf）。"
        self.memberof_hint.setText(f"{status}　{self._MEMBEROF_NOTE}")

    def _build_memberof_tab(self) -> None:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        self.memberof_table = _MiniTable(["所属组", "DN"], widths=[190])
        layout.addWidget(self.memberof_table, 1)
        buttons = QHBoxLayout()
        # ⚠️ 两个按钮都留引用：① 判据要按得到（`tests/test_ui_smoke.py`）；
        #    ② 「添加到组…」此前是个**哑按钮** —— 信号发出去没人接，
        #    点下去什么都不发生（那正是"按钮亮着、点了没反应"那一类）。
        self.memberof_remove_button = QPushButton("移出选中组")
        self.memberof_remove_button.clicked.connect(self._on_remove_membership)
        self.memberof_add_button = QPushButton("添加到组…")
        self.memberof_add_button.clicked.connect(self.add_to_group_requested.emit)
        for w in (self.memberof_add_button, self.memberof_remove_button):
            w.setCursor(Qt.CursorShape.PointingHandCursor)
            buttons.addWidget(w)
        buttons.addStretch(1)
        layout.addLayout(buttons)
        self.memberof_hint = hint_label("")
        layout.addWidget(self.memberof_hint)
        self._set_memberof_hint(None, 0)      # 未填充前如实说"还没读到"
        self.tabs.addTab(page, "隶属于")

    def _on_remove_membership(self) -> None:
        dns = self._selected_dns(self.memberof_table, 1)
        if dns:
            # ⚠️ 单选语义：这条入口一次只移出一个组（后端也只收一个 DN），
            #    多选时用**第一行**，并把"只处理了第一个"说清楚。
            self.remove_membership_requested.emit(dns[0])
            if len(dns) > 1:
                self.notice.emit("一次只能移出一个组，已按第一行处理。")
            return
        self.notice.emit("请先在「隶属于」列表里选中要移出的组。")

    # ---------- 收集（页面点「保存」后调用） ----------

    def collect(self) -> dict:
        """打包全部改动。返回::

            {"changes": [AttributeChange...],      # 普通属性
             "expiry": datetime|None|NOT_SET,      # 账户过期
             "pwd_never": bool|NOT_SET,            # 密码永不过期
             "must_change": bool|NOT_SET}          # 下次登录必须改密
        """
        changes: list[AttributeChange] = []
        for attr_low, edit in self._fields.items():
            new = (edit.currentText() if isinstance(edit, QComboBox)
                   else edit.text()).strip()
            old = self._saved_values.get(attr_low, "")
            if new == old:
                continue
            # 小写键 → 真实属性名（modify_object 的黑名单按真实名比对）
            attr = next((name for name in _ALL_WRITABLE
                         if name.casefold() == attr_low), attr_low)
            changes.append(AttributeChange(attr, ([new] if new else [])))

        # ---- 登录名 → UPN 同步（可选勾选，默认不勾）----
        # 判据全在 `_synced_upn`：只有「原 UPN 前缀 == 旧登录名」这一种情况才动
        # UPN。手工改过 UPN 时以手工值为准 —— 勾选框不该覆盖使用者当面写的值。
        if (getattr(self, "_sync_upn", None) is not None
                and self._sync_upn.isChecked()
                and self._sam_edit is not None
                and not self._upn_edited_by_hand()):
            target, _reason = self._synced_upn(self._sam_edit.text().strip())
            if target:
                changes.append(
                    AttributeChange("userPrincipalName", [target]))

        # 属性编辑器（F11）队列里的改动优先级更高：同名属性覆盖常规页的编辑
        for editor_change in self._pending_attr_changes:
            changes = [c for c in changes
                       if c.attribute.casefold()
                       != editor_change.attribute.casefold()]
            changes.append(editor_change)

        expiry: Any = NOT_SET
        if getattr(self, "_expiry_never", None) is not None:
            if getattr(self, "_expiry_unknown", False):
                # 🔴 基线是"读不到" ⇒ **一条改动都不发**（2026-09-17 改）。
                # ❗ 老实说：这一支在 Qt 的三态语义下**恰好**也不会误发 ——
                #    基线空串让 `old_never = True`，而 `PartiallyChecked` 的
                #    `isChecked()` **也是 `True`** ⇒ 两边相等 ⇒ 不产生改动。
                #    但那是**巧合**：它依赖 Qt 对 `PartiallyChecked` 的解释。
                #    守卫写在这里是为了**不依赖那个巧合** —— 谁把三态换成
                #    `setChecked(False)`（看起来更"显然"的写法），差分立刻会发出
                #    一个**编出来的到期日**（一年后）写进 AD。
                pass
            else:
                old_dt = _filetime_to_datetime(self._saved_values.get("__expiry", ""))
                old_never = old_dt is None
                new_never = self._expiry_never.isChecked()
                new_dt = (self._expiry_pick.dateTime().toPyDateTime()
                          if self._expiry_pick is not None else None)
                if new_never != old_never or (
                        not new_never and not old_never and new_dt != old_dt):
                    expiry = None if new_never else new_dt

        pwd_never: Any = NOT_SET
        if getattr(self, "_pwd_never", None) is not None:
            if getattr(self, "_pwd_never_unknown", False):
                # 🔴 这一支是**真的负载**（不像 expiry 那位有巧合兜着）：
                #    基线记的是"标成未知**之前**的 `isChecked()`"（`False`），
                #    而 `_mark_checkbox_unknown` 把它置成 `PartiallyChecked`
                #    之后 `isChecked()` 变成 **`True`** ⇒ 不加守卫就会发出
                #    `pwd_never=True` —— 一个编出来的密码策略写进 AD。
                #    （2026-09-17 变异自验实测：把守卫拿掉，这条路径确实误发。）
                pass
            elif str(self._pwd_never.isChecked()) != \
                    self._saved_values.get("__pwd_never", ""):
                pwd_never = self._pwd_never.isChecked()

        must_change: Any = NOT_SET
        if getattr(self, "_must_change", None) is not None:
            if getattr(self, "_must_change_unknown", False):
                # 同 `_pwd_never`：基线 `"False"` 与标记后的 `True` 不等，
                # 不加守卫就会发出 `must_change=True`。
                pass
            elif str(self._must_change.isChecked()) != \
                    self._saved_values.get("__must_change", ""):
                must_change = self._must_change.isChecked()

        # ---- 登录到（工作站限制，F14）----
        workstations: Any = NOT_SET
        errors: list[str] = []
        if getattr(self, "_ws_edit", None) is not None:
            new_ws = self._ws_edit.text().strip()
            old_ws = self._saved_values.get("__ws", "")
            if self._ws_limit is not None and not self._ws_limit.isChecked():
                new_ws = ""
            if new_ws != old_ws:
                names, reason = validate_workstation_names(new_ws)
                if reason:
                    errors.append("「登录到」：" + reason)
                else:
                    workstations = names        # 空列表 = 清除限制

        # ---- 登录名（sAMAccountName）本地闸门 ----
        # 字符非法 / 已占用 / 清空 ⇒ 走 **errors 这条既有通道**：页面见到非空
        # errors 就一个写入都不发起（`BrowserPage._submit_property_save`），
        # 所以不必让页面认识登录名，也不必新造一条"拦截"路径。
        sam_error = self._sam_gate_error()
        if sam_error:
            errors.append(sam_error)

        # ---- 登录时间（F13）----
        logon_hours: Any = NOT_SET
        if getattr(self, "_hours_grid", None) is not None:
            cells = self._hours_grid.cells()
            if cells != self._hours_initial_cells:
                if self._hours_cleared and all(cells):
                    logon_hours = None          # 全允许 = 清除限制（删属性）
                else:
                    offset = _local_utc_offset_minutes()
                    logon_hours = logon_hours_to_bytes(
                        logon_hours_shift(cells, offset))
            elif self._hours_cleared != self._hours_initial_cleared:
                logon_hours = None

        # ---- 拨入（F15）----
        dialin: Any = NOT_SET
        if getattr(self, "_dialin_mode", None) is not None:
            mode = self._dialin_mode.currentIndex()
            new_allow: bool | None = (True if mode == 0
                                      else False if mode == 1 else None)
            new_callback = (self._callback_edit.text().strip()
                            if self._callback_on.isChecked() else "")
            old_dialin = self._read_dialin_attrs()
            if new_allow != old_dialin["allow"] or \
                    new_callback != (old_dialin["callback"] or ""):
                dialin = {"allow": new_allow, "callback": new_callback}

        return {"changes": changes, "expiry": expiry,
                "pwd_never": pwd_never, "must_change": must_change,
                "workstations": workstations, "logon_hours": logon_hours,
                "dialin": dialin, "errors": errors}


#: collect() 里把小写属性名映射回真实属性名用的清单。
#: ⚠️ `sAMAccountName` **必须**在这个清单里：常规页 / 账户页的登录名输入框是
#: 以 `"samaccountname"` 为键登记的（大小写不敏感地找输入框），少了它，
#: `collect()` 只能把原始小写名写进 `AttributeChange`（属性名大小写不对，
#: 审计与 `_ALL_WRITABLE` 的"真实属性名"契约就都对不上了）。
_ALL_WRITABLE = [f[1] for fields in _TAB_FIELDS.values() for f in fields] + \
                ["sAMAccountName", "userPrincipalName", "location", "managedBy"]


def _wrap_form(form: QFormLayout) -> QVBoxLayout:
    """页签页的布局：表单在上，剩余空间垫底（防副标题式撑爆的旧坑）。"""
    layout = QVBoxLayout()
    layout.setContentsMargins(8, 8, 8, 8)
    layout.setSpacing(8)
    layout.addLayout(form)
    layout.addStretch(1)
    return layout


def _local_utc_offset_minutes() -> int:
    """本机相对 UTC 的偏移（分钟）。东八区 = +480。"""
    from datetime import datetime as _dt

    offset = _dt.now().astimezone().utcoffset()
    return int(offset.total_seconds() // 60) if offset else 0


def _parse_workstations(values: list[str]) -> list[str]:
    """userWorkstations 属性值 → 名单（属性是逗号分隔的单值串）。"""
    out: list[str] = []
    for value in values:
        for piece in str(value).split(","):
            piece = piece.strip()
            if piece and piece not in out:
                out.append(piece)
    return out


# ============================================================================
# 重命名 / 移动 / 加组 / 新建计算机 / 新建联系人
# ============================================================================

class RenamePanel(InlinePanel):
    """重命名（只改 RDN，与 ADUC 行为一致）。"""

    def __init__(self, parent: QWidget | None = None):
        super().__init__("重命名", parent)
        self.set_ok_text("重命名")
        self._sam = ""

        self.name = QLineEdit()
        form = _form()
        form.addRow(_labeled("新名称"), self.name)
        self.body.addLayout(form)

        self.sync_sam = QCheckBox("同步计算机登录名（推荐）")
        self.sync_sam.setChecked(True)
        self.sync_sam.setVisible(False)
        self.body.addWidget(self.sync_sam)
        self.hint = hint_label(
            "AD 的重命名只改「名称」—— 用户的登录名不会跟着变"
            "（ADUC 也是这个行为）。")
        self.body.addWidget(self.hint)
        self.body.addStretch(1)

    def load(self, obj: DirObject) -> None:
        self._dn = obj.dn
        self._kind = obj.kind
        # 账号名留一份：提交时要带给后端写审计（`target_sam`）。
        # 只传 DN 的话，日志里「对谁做的」这一栏是空的。
        self._sam = obj.sam or ""
        self.set_title(f"重命名 · {obj.title or obj.sam}")
        self.set_subtitle(obj.dn)
        self.name.setText(obj.cn or obj.title or obj.sam)
        self.sync_sam.setVisible(obj.kind == ObjectKind.COMPUTER)
        self.name.setFocus()
        self.name.selectAll()

    def account_name(self) -> str:
        """被重命名对象的登录名（提交时带回去写审计）。"""
        return self._sam

    def values(self) -> tuple[str, str, bool]:
        return self._dn, self._kind, self.sync_sam.isChecked()


class MovePanel(InlinePanel):
    """移动到其它容器。目标 = **左侧树当前选中的节点**（实时可见）。"""

    def __init__(self, parent: QWidget | None = None):
        super().__init__("移动到…", parent)
        self.set_ok_text("移动")
        self._dns: list[str] = []
        self._rows: list[DirObject] = []

        self.target_label = QLabel("（尚未选择）")
        self.target_label.setStyleSheet("font-weight: 600;")
        form = _form()
        form.addRow(_labeled("目标容器"), self.target_label)
        self.body.addLayout(form)
        self.body.addWidget(hint_label(          # 纯文本 QLabel ⇒ 文案里不许写 `**`
            "在左侧目录树中点选目标部门，这里会实时跟着变。\n"
            "组成员关系、管理者等引用由 AD 自动更新，移动是安全的。"))
        self.body.addStretch(1)

    def load(self, objects: list[DirObject]) -> None:
        """装载**要移动的对象本身**（不只是 DN）。

        ⚠️ 必须收对象而不是 DN：`sAMAccountName` 要一路带到后端 ——
        审计日志靠它记「对谁做的」，批量结果列表也靠它显示账号名。
        之前这里只收 DN，调用方于是就地造了一批只带 DN 的替身，
        账号名在那一刻就丢了。
        """
        self._rows = list(objects)
        self._dns = [o.dn for o in self._rows]
        count = len(self._dns)
        self.set_subtitle(f"将移动 {count} 个对象" if count > 1
                          else f"将移动：{self._rows[0].title or self._dns[0]}"
                          if self._rows else "")

    def rows(self) -> list[DirObject]:
        """装载进来的对象（提交时按这一份走，不读"表格现在选了什么"）。"""
        return list(self._rows)

    def set_target(self, dn: str, title: str) -> None:
        self._target_dn = dn
        self.target_label.setText(f"{title}　（{dn}）")

    def values(self) -> tuple[list[str], str]:
        return self._dns, getattr(self, "_target_dn", "")


class AddToGroupPanel(InlinePanel):
    """添加到组：搜索组 → 选中 → 加入（内联两步，不弹窗）。"""

    search_requested = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None):
        super().__init__("添加到组…", parent)
        self.set_ok_text("加入选中组")
        self._member_dns: list[str] = []

        self.search = SearchLineEdit("输入组名搜索（支持名称 / 登录名）")
        self.search.submitted.connect(self.search_requested.emit)
        self.body.addWidget(self.search)

        self.table = _MiniTable(["组", "作用域", "类型", "DN"],
                                widths=[170, 90, 90])
        self.table.doubleClicked.connect(self.accepted.emit)
        self.body.addWidget(self.table, 1)
        self.body.addStretch(0)

    def load(self, member_dns: list[str]) -> None:
        self._member_dns = list(member_dns)
        count = len(self._member_dns)
        self.set_subtitle(
            f"将把 {count} 个对象加入所选组" if count > 1
            else f"将把「{self._member_dns[0].split(',')[0] if self._member_dns else ''}」加入所选组")
        self.search.setFocus()

    def fill_groups(self, groups: list[DirObject]) -> None:
        _fill_group_rows(self.table, groups)

    def selected_group_dn(self) -> str:
        """选中的目标组 DN（未选中返回空串）。

        表格是多选，但这里的语义是「把成员加进**一个**组」——
        取行序最靠前的那一个（与 ADUC 的对象选择器一致）。
        """
        dns = _group_dns_from_rows(self.table)
        return dns[0] if dns else ""

    def member_dns(self) -> list[str]:
        return list(self._member_dns)


class NewComputerPanel(InlinePanel):
    """预创建计算机账号（先建号、后加域）。"""

    def __init__(self, parent: QWidget | None = None):
        super().__init__("新建计算机账号", parent)
        self.set_ok_text("创建")

        self.name = QLineEdit()
        self.name.setPlaceholderText("如 PC-FINANCE-02（≤15 字符）")
        self.description = QLineEdit()
        self.description.setPlaceholderText("可选")

        form = _form()
        form.addRow(_labeled("计算机名"), self.name)
        form.addRow(_labeled("描述"), self.description)
        self.body.addLayout(form)
        self.body.addWidget(hint_label(          # 纯文本 QLabel ⇒ 文案里不许写 `**`
            "登录名会自动按「计算机名$」生成（AD 的硬性要求）。\n"
            "创建的是待加域账号 —— 机器完成加域后，密码与 DNS 名由它自己注册。"))
        self.body.addStretch(1)

    def set_target(self, parent_dn: str, parent_title: str) -> None:
        self.set_subtitle(f"将创建在　{parent_title}　之下")

    def reset(self) -> None:
        self.name.clear()
        self.description.clear()

    def values(self) -> tuple[str, str]:
        return self.name.text().strip(), self.description.text().strip()


class NewContactPanel(InlinePanel):
    """新建联系人（外部收件人 / 厂商通讯录）。"""

    def __init__(self, parent: QWidget | None = None):
        super().__init__("新建联系人", parent)
        self.set_ok_text("创建")

        self.name = QLineEdit()
        self.name.setPlaceholderText("如 供应商-顺丰")
        self.mail = QLineEdit()
        self.mail.setPlaceholderText("可选，如 corp@example.com")
        self.description = QLineEdit()
        self.description.setPlaceholderText("可选")

        form = _form()
        form.addRow(_labeled("名称"), self.name)
        form.addRow(_labeled("邮箱"), self.mail)
        form.addRow(_labeled("描述"), self.description)
        self.body.addLayout(form)
        self.body.addStretch(1)

    def set_target(self, parent_dn: str, parent_title: str) -> None:
        self.set_subtitle(f"将创建在　{parent_title}　之下")

    def reset(self) -> None:
        self.name.clear()
        self.mail.clear()
        self.description.clear()

    def values(self) -> tuple[str, str, str]:
        return (self.name.text().strip(), self.mail.text().strip(),
                self.description.text().strip())



def _settings_text(result: Any, settings: Any) -> str:
    """把「改过哪些设置」的结果渲染成只读文本。

    🔒 放在面板层、且**只吃结果对象**：`ui_*` 零 LDAP/COM —— 这里不碰网络、
    不解析任何字节。解析与 ADMX 对照在 `gpo_settings.py` 里早已做完。
    """
    label = getattr(result, "display_name", "") or "这个 GPO"
    items = list(getattr(settings, "items", ()) or ())
    files = tuple(getattr(settings, "files", ()) or ())
    empty_files = tuple(getattr(settings, "empty_files", ()) or ())
    missing_files = tuple(getattr(settings, "missing_files", ()) or ())
    failed = tuple(getattr(settings, "failed", ()) or ())
    conclusive = bool(getattr(settings, "is_conclusive", False))

    grouped = _group_by_scope(items)
    lines: list[str] = []
    if items:
        parts = ["%s %d" % (_scope_word(group), len(group))
                 for group in grouped.values()]
        lines.append("「%s」改过 %d 项设置（%s）。" % (label, len(items), " · ".join(parts)))
    elif conclusive:
        lines.append("「%s」没有改过任何设置。" % label)
    else:
        lines.append("「%s」这次什么都没读到。" % label)
    lines.append("")

    lines.append("【我们看了哪些文件】读到 %d 个 · 空文件 %d 个 · 位置不存在 %d 个 · 读失败 %d 个"
                 % (len(files), len(empty_files), len(missing_files), len(failed)))
    if not conclusive:
        lines.append("⚠️ 一个文件都没读成功 ⇒ 不能因此说「没有改过设置」，"
                     "只能说这次什么都没看到。")
    if missing_files:
        lines.append("· 位置不存在：%s" % "；".join(missing_files))
        lines.append("  （可能这个 GPO 确实没配这一侧，也可能我们算错了路径。）")
    for one in failed:
        lines.append("⚠️ 这一份读失败了，清单里少看了它：%s" % one)
    if not getattr(result, "admx_available", True):
        lines.append("⚠️ 本机 ADMX 对照不可用（读到 0 条策略）—— 下面那些"
                     "「ADMX 里找不到归属」不代表它们是第三方设置，是我们没原料。")
    where = getattr(result, "gpo_dir", "") or ""
    if where:
        lines.append("· 位置：%s" % where)
    lines.append("")

    if not items:
        lines.append("（没有可列出的记录。）")
    for group in grouped.values():
        lines.append("── %s ──" % _scope_word(group))
        lines.extend(_scope_lines(group))
        lines.append("")

    lines.append("（只读）这份清单由本工具自己解 Registry.pol 得到；"
                 "「看设置摘要」那份 HTML 由 GPMC 生成，两者不是一回事。")
    return "\n".join(lines)


def _group_by_scope(items: list) -> dict:
    """按作用域分组，**保持记录原来的顺序**（机器侧在前 —— 文件就是那个顺序读的）。"""
    groups: dict = {}
    for item in items:
        groups.setdefault(getattr(item, "scope", ""), []).append(item)
    return groups


def _scope_word(group: list) -> str:
    """作用域的界面用词。

    ⚠️ 从**条目**上取（`SettingItem.scope_label` 是单一映射源），面板不另写一份
    映射表 —— 两份映射表就会有两份真相。
    """
    first = group[0] if group else None
    word = getattr(first, "scope_label", "") if first is not None else ""
    return word or getattr(first, "scope", "") or "（未知作用域）"


def _scope_lines(group: list) -> list[str]:
    """一个作用域内部的排版：先按 ADMX 分类路径分组，找不到归属的**单独一档**。"""
    by_category: dict = {}
    orphan: list = []
    for item in group:
        if getattr(item, "explained", False):
            path = tuple(getattr(item, "category_path", ()) or ())
            by_category.setdefault(path, []).append(item)
        else:
            orphan.append(item)

    out: list[str] = []
    for path, entries in by_category.items():
        out.append("  [%s]" % (" › ".join(path) if path else "（ADMX 里没有分类路径）"))
        for item in entries:
            out.append("    " + _setting_line(item))
    if orphan:
        out.append("  [ADMX 里找不到归属]（盘上确实有这些记录，本机 ADMX 解释不了）")
        for item in orphan:
            out.append("    " + _setting_line(item))
    return out


def _setting_line(item: Any) -> str:
    """一条设置一行：名字 —— 状态（值）。"""
    state = getattr(item, "state_label", "") or ""
    value = getattr(item, "value_display", "") or ""
    text = "· %s" % (getattr(item, "label", "") or "（无名值）")
    if state:
        text += " —— %s" % state
    if value:
        text += "（值：%s）" % value
    problem = getattr(item, "value_problem", "") or ""
    if problem:
        text += " ⚠️ 值解释不了，上面是原始字节：%s" % problem
    return text


#: 哪些段的值里**空 = 一种意思**（要在界面上说清，不能只显示一个空白）。
#: `[Privilege Rights]` 的空值含义来自 `gpo_security_backend.split_principals()`
#: 的实测结论（`defltbase.inf` 里有 8 个这样的键）。
_EMPTY_MEANS_NONE_SECTIONS = frozenset({"Privilege Rights"})


def _security_text(result: Any, security: Any) -> str:
    """把「这个 GPO 的安全策略」渲染成只读文本。

    🔒 与 `_settings_text` 同一条纪律：**只吃结果对象** —— `ui_*` 零 LDAP/COM，
    这里不碰网络、不解析任何字节（解字节在 `gpo_security_backend.py`，
    「文件在哪儿 / 读得到吗」在 `gpo_security.py`）。

    🔑 界面**不翻译键名**：显示的就是文件里的键名本身（`MinimumPasswordLength`）。
    那是**文件真实内容**，不是"没做完的占位" —— 本机确实有权威词表
    （`%SystemRoot%\\inf\\sceregvl.inf`），但把键名翻成中文是**另一条解析线**，
    见 `gpo_security.py` 模块头第 2 条。
    """
    label = getattr(result, "display_name", "") or "这个 GPO"
    files = tuple(getattr(security, "files", ()) or ())
    missing = tuple(getattr(security, "missing_files", ()) or ())
    failed = tuple(getattr(security, "failed", ()) or ())
    conclusive = bool(getattr(security, "is_conclusive", False))
    sections = tuple(getattr(security, "sections", ()) or ())
    unknown_lines = tuple(getattr(security, "unknown_lines", ()) or ())
    template = getattr(security, "template", None)

    lines: list[str] = []
    if files:
        lines.append("「%s」的安全策略：%d 段 / %d 项。"
                     % (label, len(sections),
                        getattr(security, "entry_count", 0)))
    elif conclusive:
        lines.append("「%s」没有配安全策略。" % label)
    else:
        lines.append("「%s」这次什么都没读到。" % label)
    lines.append("")

    # ---- 会不会生效 ----
    # ⚠️ 这一句**只有读到过模板时才有对象**（`GpoSecurity.cse_is_relevant`）。
    #    没有模板却印一句「不会被应用」，使用者会去找一份**根本不存在的策略**，
    #    找不到就当成缺陷报上来。这条语义在数据层钉死，面板不自己判 files 空不空。
    if getattr(security, "cse_is_relevant", False):
        lines.append("【会不会生效】%s" % getattr(security, "cse_label", "说不清"))
        reason = getattr(security, "cse_reason", "") or ""
        if reason:
            lines.append("  " + reason)
        lines.append("")

    # ---- 我们看了哪些文件 ----
    lines.append("【我们看了哪些文件】读到 %d 个 · 位置不存在 %d 个 · 读失败 %d 个"
                 % (len(files), len(missing), len(failed)))
    if not conclusive:
        lines.append("⚠️ 一个文件都没读成功 ⇒ 「不能说」这条 GPO 没有安全策略，"
                     "只能说这次什么都没看到。")
    for one in missing:
        lines.append("· 位置不存在：%s" % one)
        lines.append("  （这条 GPO 就是没有安全策略文件 —— 真域里很常见，"
                     "是正常结果，不是读失败。）")
    for one in failed:
        lines.append("⚠️ 这一份读失败了，等于我们少看了它：%s" % one)
    for one in files:
        lines.append("· 读到：%s" % one)
    if template is not None:
        lines.append("  · 编码 %s（%s BOM） · 行尾 %s · md5 %s"
                     % (getattr(template, "codec", "?") or "?",
                        "带" if getattr(template, "has_bom", False) else "无",
                        getattr(template, "line_ending", "?") or "?",
                        (getattr(template, "md5", "") or "")[:12]))
    lines.append("")

    # ---- 逐段列出 ----
    if not sections:
        lines.append("（没有可列出的设置。）")
    for section in sections:
        name = getattr(section, "name", "") or ""
        entries = tuple(getattr(section, "entries", ()) or ())
        known = bool(getattr(section, "known", False))
        label_word = getattr(section, "label", "") or name
        head = "── %s ──" % label_word
        if not known:
            head += "（本工具没有这一段的中文名，段名原样列出）"
        lines.append(head)
        if name in _EMPTY_MEANS_NONE_SECTIONS:
            lines.append("   （值为空 = 「没有人」有这项权限；"
                         "与「这一行不在文件里」是两回事。）")
        for entry in entries:
            lines.append("  " + _security_line(entry))
        lines.append("")

    # ---- 认不出的行 ----
    if unknown_lines:
        lines.append("── 认不出的行（「原样保留」，没有被修改、也不会被跳过）──")
        for entry in unknown_lines:
            lines.append("  %s" % (getattr(entry, "key", "") or ""))
        lines.append("")

    where = getattr(result, "gpo_dir", "") or ""
    if where:
        lines.append("· 位置：%s" % where)
    lines.append("（只读）上面是文件里「写的键名本身」，本工具不把它们翻成中文 ——"
                 "那是文件的真实内容，不是占位。")
    # ⚠️ 这一句只在**真的印了上面那一行**时才印：没有模板时谈"会不会生效"
    #    是在说一件没有对象的事（演示域冒烟时实测过："内网更新源"那条
    #    会被印成在解释一行根本不存在的话）。
    if getattr(security, "cse_is_relevant", False):
        lines.append("「会不会生效」那一句是本工具自己算的"
                     "（GPC 属性 `gPCMachineExtensionNames` 里有没有安全扩展）——"
                     "GPMC 界面上看不到它。")
    return "\n".join(lines)


def _security_line(entry: Any) -> str:
    """安全策略里的一条 `键 = 值`（**认不出的行也走这里**）。"""
    key = getattr(entry, "key", "") or "（无名键）"
    value = getattr(entry, "value", "") or ""
    text = "%s = %s" % (key, value if value else "（空）")
    extra: list[str] = []
    reg_name = getattr(entry, "reg_type_name", "") or ""
    if reg_name:
        extra.append(reg_name)
    kinds = tuple(getattr(entry, "principal_kinds", ()) or ())
    if kinds:
        counted: dict[str, int] = {}
        for kind in kinds:
            counted[kind] = counted.get(kind, 0) + 1
        extra.append("%d 个主体（%s）"
                     % (len(kinds),
                        "、".join("%s ×%d" % (k, n)
                                  for k, n in counted.items())))
    if extra:
        text += "　［%s］" % " · ".join(extra)
    if not getattr(entry, "known", True):
        text += "　⚠️ 这一行本工具认不出，原样保留（没有被修改）"
    return text


class GpoPanel(InlinePanel):
    """组策略（**只读**）—— 域级功能，全内联、不弹窗。

    形态::

        [刷新列表]  [按名称搜索 GPO ______] [查找]
        ┌──────────────────────────────────────────────┐
        │ 名称              │ 修改时间      │ 版本      │
        ├──────────────────────────────────────────────┤
        └──────────────────────────────────────────────┘
        [看链接位置]  [看改过哪些设置]  [看安全策略]  [看设置摘要]
        ┌ 结果（只读） ────────────────────────────────┐
        └──────────────────────────────────────────────┘

    ⚠️ 这一档**只读**：没有新建 / 链接 / 删除 / 改设置的入口。
    写 GPO 是需求文档第 5、6 项的事 —— 混进来会让"随手点一下"的代价
    从「查一下」变成「不可逆地改了域策略」。
    （2026-09-18 主理人裁定：组策略**只做看得见** ⇒ 上面这几件事**不做**，
    不是"还没做"。写侧实现已整体移出仓库归档。）

    ⚠️ **哪些入口依赖 RSAT（GPMC）** —— 这一栏决定"没装 RSAT 的机器上能用到哪"：

    ==========================  ==============  ==================================
    入口                          要 RSAT 吗       走什么
    ==========================  ==============  ==================================
    「刷新列表」/「查找」           **不要**        LDAP（`gpo_ldap.py`）
    「看改过哪些设置」              **不要**        SYSVOL 的 `Registry.pol`（自己解）
    「看安全策略」                  **不要**        SYSVOL 的 `GptTmpl.inf`（自己解）
    「看链接位置」/「看设置摘要」    **要**          GPMC 的 COM
    ==========================  ==============  ==================================

    ⇒ 没装 RSAT 时**面板照常打开**，只有后两个按钮置灰（`set_engine_available`）。

    ⚠️ 面板**不碰 COM**（`ui_*` 零 LDAP/COM 是红线）：只收集输入、发信号、
    展示页面喂进来的结果对象。**引擎在不在也是页面告诉它的**，它自己不去探。

    ⚠️ 「看设置摘要」里的 HTML 是 **GPMC 生成**的，面板只显示、**不解析**；
    而「看改过哪些设置」是**我们自包含**的那条路（`gpo_settings.py` 自己解
    `Registry.pol` ＋ 对 ADMX 归属，**不需要 RSAT/GPMC**），面板同样只显示。

    ⚠️ **归属判据**：面板是共享单例，而"看链接""看设置""看安全策略""看摘要"都是
    异步的 —— 发起时取号（`begin()`），回调时对号（`is_current()`）。
    请求在飞时使用者换了选中项，旧结果必须**丢掉**：本项目吃过「A 的结果
    贴在 B 名下」的亏（复核记录见 ``记忆-审查/02-判据模式与已发现缺陷.md``
    的"结果贴错对象"家族）。
    ⇒ 请求要的东西（GUID、那条扩展名属性）一律在**发起时**从选中行取快照
    （`selected_guid()` / `selected_extension_names()`），**不许**在回调里
    再读一遍面板"现在显示谁"。

    ⚠️ 组策略**生效**要客户端 `gpupdate /force` + 重新登录 ——
    工具里看不到"效果"，这是组策略本身的特性，不是缺陷，所以写在副标题里。
    """

    #: 点「刷新列表」（只读）
    refresh_requested = pyqtSignal()
    #: 点「查找」，参数是关键词（空串 = 全部）
    search_requested = pyqtSignal(str)
    #: 点「看链接位置」，参数是 GPO 的 GUID
    links_requested = pyqtSignal(str)
    #: 点「看设置摘要」，参数是 GPO 的 GUID
    report_requested = pyqtSignal(str)
    #: 点「看改过哪些设置」，参数是 GPO 的 GUID
    settings_requested = pyqtSignal(str)
    #: 点「看安全策略」，参数是 ``(GPO 的 GUID, gPCMachineExtensionNames 原文)``。
    #:
    #: ⚠️ 第二个参数刻意声明成 ``object`` 而**不是** ``str``：那条属性的取值
    #: 有**三态**，而 `None`（= 这次没拿到这个属性 ⇒ 结论只能是"说不清"）
    #: 与 `""`（= 拿到了、对象上没登记 ⇒ "不会被应用"）是**两件事**。
    #: 写成 `pyqtSignal(str)` 会让信号层**悄悄**把 `None` 变成 `""` ——
    #: 那正好是 `cse_verdict()` 存在的全部理由被抹掉，而**界面上看着一切正常**。
    security_requested = pyqtSignal(str, object)

    def __init__(self, parent: QWidget | None = None):
        super().__init__("组策略（只读）", parent)
        self.set_subtitle(
            "列出域里的组策略对象、它链在哪些位置、以及设置摘要。\n"
            "⚠️ 这一档只读 —— 新建 / 链接 / 删除 / 改设置都不在这里做。\n"
            "⚠️ 组策略生效要客户端执行 gpupdate /force 并重新登录，"
            "这里看不到“效果”，那是组策略本身的特性。")

        # 只读面板没有"确定"这个语义 —— 留着它会让人以为这里能改东西。
        self.ok_button.hide()
        self.cancel_button.setText("关闭")

        #: 归属判据：发起时取号、回调时对号。
        self._request_id = 0
        #: 当前表格里的 GPO 列表 —— `selected_guid()` 靠**行号索引**它取值，
        #: 所以必须与表格同源、同序。
        self._gpos: list[Any] = []

        # ---- 工具行 ----
        self.refresh_button = make_button("刷新列表")
        self.refresh_button.clicked.connect(self.refresh_requested.emit)
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("按名称搜索 GPO（留空 = 全部）")
        self.search_edit.returnPressed.connect(self._emit_search)
        self.search_button = make_button("查找")
        self.search_button.clicked.connect(self._emit_search)
        tools = QHBoxLayout()
        tools.setSpacing(6)
        tools.addWidget(self.refresh_button)
        tools.addWidget(self.search_edit, 1)
        tools.addWidget(self.search_button)
        self.body.addLayout(tools)

        # ---- 引擎缺失时的常驻说明（默认藏起来）----
        # ⚠️ 不能把这句话写进 `result` 那个文本框：它会被列表 / 链接 / 摘要
        #    的结果反复覆盖，说明会跟着消失 —— 而"这台机器少装了东西"
        #    是**一直成立**的事实，不是某一次操作的结果。
        self.engine_notice = hint_label("")
        self.engine_notice.hide()
        self.body.addWidget(self.engine_notice)

        #: GPMC 引擎在不在。**由页面告知**（面板自己不探 —— 它不碰 COM）。
        self._gpmc_available = True

        # ---- 列表 ----
        self.table = _MiniTable(["名称", "修改时间", "版本"], [250, 150],
                                single=True)
        self.table.itemSelectionChanged.connect(self._on_selection_changed)
        self.body.addWidget(self.table, 1)

        # ---- 动作 ----
        self.links_button = make_button("看链接位置")
        self.links_button.clicked.connect(self._emit_links)
        self.settings_button = make_button("看改过哪些设置")
        self.settings_button.clicked.connect(self._emit_settings)
        self.security_button = make_button("看安全策略")
        self.security_button.clicked.connect(self._emit_security)
        self.report_button = make_button("看设置摘要")
        self.report_button.clicked.connect(self._emit_report)
        actions = QHBoxLayout()
        actions.setSpacing(6)
        actions.addWidget(self.links_button)
        actions.addWidget(self.settings_button)
        actions.addWidget(self.security_button)
        actions.addWidget(self.report_button)
        actions.addStretch(1)
        self.body.addLayout(actions)

        # ---- 结果（只读）----
        # 用 QTextBrowser 而不是 QPlainTextEdit：设置摘要是 GPMC 生成的
        # **HTML**，纯文本框会把它当字符串糊出来。
        self.result = QTextBrowser()
        self.result.setReadOnly(True)
        self.result.setMinimumHeight(150)
        self.result.setPlaceholderText(
            "点「刷新列表」载入域里的组策略；选中一条后可以看它链在哪些位置、"
            "改过哪些设置、安全策略、或者看它的设置摘要。")
        self.body.addWidget(self.result, 1)

    # ---------------------------------------------------------------- 输入

    def search_text(self) -> str:
        return self.search_edit.text().strip()

    def selected_guid(self) -> str:
        """当前选中行的 GPO GUID。没选中 / 表格与列表不同步 ⇒ 空串。"""
        row = self.table.currentRow()
        if row < 0 or row >= len(self._gpos):
            return ""
        return self._gpos[row].guid or ""

    def selected_label(self) -> str:
        row = self.table.currentRow()
        if row < 0 or row >= len(self._gpos):
            return ""
        return self._gpos[row].label

    def selected_extension_names(self) -> str | None:
        """当前选中那条 GPO 的 `gPCMachineExtensionNames`（**发起时才读**）。

        ⚠️ 与 `selected_guid()` 一样是**发起时**的快照，不许拖到回调里再读 ——
        请求在飞的时候使用者可能已经换了选中项，那时读到的是**另一条 GPO 的**
        属性（本项目记过的「A 的结果贴在 B 名下」家族）。

        🔴 **原样返回，一个兜底都不许加** —— 这里原来写的是
        ``getattr(..., "") or ""``，而那句 `or ""` 是一处**真缺陷**
        （2026-09-18 探针实测，读数如下）：

        | 行上的属性原文 | 面板发出去的 | 结论 |
        |---|---|---|
        | `None`（GPMC 那条路，`gpo_backend.GpoInfo` 的默认值） | 被改成 `""` | 从「说不清」翻成「不会被应用」 |
        | `""`（`gpo_ldap._to_gpo()`：问过域控、回"没有值"） | `""` | 「不会被应用」（**对**） |
        | GUID 串 | 原样 | 按有没有安全 CSE 判 |

        ⇒ 整条三态链（`GpoInfo` → 面板 → 信号 → `workers` → `cse_verdict`）
        就在**最后一跳**被抹平，而界面上看不出任何异常 —— 那正是 `or 0` 家族
        （把"取数失败"当成"证据成立"），也正是使用者最会当真的一句话。
        判据：`tests/test_ui_gpo_panel.py` 的
        `test_the_security_signal_keeps_the_attribute_three_states_apart`。

        ⚠️ 没有选中行时返回 `None`（**不是** `""`）：`""` 是一句**有内容的结论**
        （"对象上确实没登记"），而"我们没有这一行"根本不是结论。
        那一路 `selected_guid()` 同样返回 `""`，`_emit_security()` 会先把它
        拦下来（连 GUID 都没有就直接说话了，根本不会发信号），
        所以这个取值不会流到界面上去 —— 判据
        `test_a_missing_row_is_not_a_claim_that_the_object_has_no_value`。
        """
        row = self.table.currentRow()
        if row < 0 or row >= len(self._gpos):
            return None
        # ⚠️ 默认值 `None`（**不是** `""`）：属性整个不存在 = 这条路没提供它
        #    ⇒ 结论只能是「说不清」。写成 `""` 就是替一个我们没读到的东西下结论。
        return getattr(self._gpos[row], "machine_extension_names", None)

    # 归属：发起时取号、回调时对号。
    def begin(self) -> int:
        self._request_id += 1
        return self._request_id

    def is_current(self, request_id: int) -> bool:
        return request_id == self._request_id

    def set_engine_available(self, ok: bool, note: str = "") -> None:
        """本机有没有 GPMC 引擎（RSAT）。由页面告知。

        ⚠️ **不通过也不许锁面板**：列表（LDAP）与「看改过哪些设置」
        （自己解 `Registry.pol`）都**不依赖 GPMC** —— 把整个面板锁掉，
        等于把这条功能线**本来要服务**的那些机器排除在外。
        只有真需要 GPMC 的两件事（看链接位置 / 看设置摘要）才置灰。

        ⚠️ 为什么置灰而不是"让它点了再报错"：`gpo_engine_available()` 的注释
        写着「界面在打开面板前调它 —— 没装 RSAT 就直接说清楚，**别让人点了
        才发现**」。置灰 + 常驻说明就是那句话的落地形态。
        """
        self._gpmc_available = bool(ok)
        self.engine_notice.setText("" if ok else (note or ""))
        self.engine_notice.setVisible(not ok and bool(note))
        for widget in (self.links_button, self.report_button):
            widget.setToolTip("" if ok else (note or ""))
        self._apply_enabled()

    def _apply_enabled(self, busy: bool = False) -> None:
        """统一算控件可用性 —— **只有这一处**开关控件。

        分两处写（`set_busy` 一处、引擎一处）必然打架：`set_busy(False)`
        会把"因为没装 RSAT 而灰着"的按钮顺手点亮。
        """
        for widget in (self.refresh_button, self.search_button, self.search_edit,
                       self.links_button, self.settings_button,
                       self.security_button, self.report_button, self.table):
            widget.setEnabled(not busy)
        if not self._gpmc_available:
            self.links_button.setEnabled(False)
            self.report_button.setEnabled(False)

    def set_busy(self, busy: bool, note: str = "") -> None:
        self._apply_enabled(busy)
        if note:
            self.result.setPlainText(note)

    # ---------------------------------------------------------- 结果展示

    def show_gpos(self, result: Any) -> None:
        """填充 GPO 列表。

        ⚠️ 填表要 `blockSignals` —— `setRowCount` / `setItem` 会连带触发
        `itemSelectionChanged`，把结果区反复清空（甚至在填完前清一次），
        使用者会看到"刚点出来的结果自己没了"。
        """
        self._gpos = list(getattr(result, "gpos", []) or [])
        self.table.blockSignals(True)
        try:
            self.table.setRowCount(len(self._gpos))
            for row, gpo in enumerate(self._gpos):
                name = QTableWidgetItem(gpo.label)
                name.setData(Qt.ItemDataRole.UserRole, gpo.guid or "")
                name.setToolTip(gpo.guid or "")
                self.table.setItem(row, 0, name)
                self.table.setItem(row, 1, QTableWidgetItem(gpo.modified or "—"))
                self.table.setItem(
                    row, 2,
                    QTableWidgetItem("用户 %s / 计算机 %s"
                                     % (gpo.user_version, gpo.computer_version)))
            self.table.clearSelection()
            self.table.setCurrentCell(-1, -1)
        finally:
            self.table.blockSignals(False)

        if not self._gpos:
            # ⚠️ 空**不是**失败 —— 域里可能真没有 GPO。两者在界面上必须长得不一样。
            self.result.setPlainText(
                "这个域里没有找到组策略对象。\n"
                "（空结果是正常情况 —— 比如新建的域还没配过任何策略。）")
        else:
            self.result.setPlainText(
                "共 %d 个组策略对象（域：%s）。选中一条后可以看链接位置或设置摘要。"
                % (len(self._gpos), getattr(result, "domain", "") or "未知"))

    def show_links(self, soms: list, gpo_label: str) -> None:
        """展示某个 GPO 链在哪些位置。"""
        if not soms:
            self.result.setPlainText(
                "「%s」没有被链接到任何位置。\n"
                "（链接到域 / 站点 / OU 上才会生效；没链接的 GPO 只是存在那里。）"
                % (gpo_label or "这个 GPO"))
            return
        lines = ["「%s」链接在 %d 个位置：" % (gpo_label or "这个 GPO", len(soms)), ""]
        for som in soms:
            blocked = "（已阻止继承）" if getattr(som, "inheritance_blocked", False) else ""
            lines.append("· [%s] %s%s" % (getattr(som, "kind_label", "?"),
                                          som.name or som.path, blocked))
            lines.append("    %s" % som.path)
        self.result.setPlainText("\n".join(lines))

    def show_report(self, text: str, gpo_label: str, fmt: str = "html") -> None:
        """展示设置摘要。

        ⚠️ 这份 HTML 由 **GPMC 自己**解析 `registry.pol` 生成 —— 面板只显示，
        不解析、不改写。

        ⚠️ 别把上面那句读成"本项目一行 `registry.pol` 都不解析"：我们**另有
        一条自包含的路**（不需要 RSAT / GPMC），下面 `show_settings` 就是它的
        出口；格式实现在 `preg_backend.py` / `gpo_settings.py`
        （候选库 `registrypol` 被证会**静默毁数据**，已留证据）。
        """
        if not text:
            self.result.setPlainText("GPMC 返回了空的设置摘要。")
            return
        if (fmt or "").lower() == "xml":
            # XML 当纯文本看更清楚（渲染成 HTML 反而丢结构）。
            self.result.setPlainText(text)
        else:
            self.result.setHtml(text)

    def show_settings(self, result: Any) -> None:
        """展示「这个 GPO **改过哪些设置**」（我们自己解 `Registry.pol` 的结果）。

        ⚠️ 三种"看起来都像没设置"的情形**必须在界面上长得不一样**：

        | 情形 | 界面该说什么 |
        |---|---|
        | 确实没配过（文件是空的） | 「没有改过任何设置」 |
        | 我们**没读到**（读失败 / 一个文件都没成功） | 「这次什么都没读到」 |
        | ADMX 对照**不可用** | 「找不到归属**不代表**是第三方设置」 |

        三者混成一句，使用者就会拿"我们没原料"当成"域里没有"。
        """
        settings = getattr(result, "settings", None)
        if settings is None:
            self.result.setPlainText("没有拿到这条组策略的设置清单。")
            return
        self.result.setPlainText(_settings_text(result, settings))

    def show_security(self, result: Any) -> None:
        """展示「这个 GPO 的**安全策略**」（`GptTmpl.inf`：密码 / 锁定 / 审核 / 权限）。

        ⚠️ 与 `show_settings` 一样，四种"看起来都像没东西"的情形必须在界面上
        长得**不一样**（`_security_text` 逐个分开写）：

        | 情形 | 界面该说什么 |
        |---|---|
        | 这条 GPO 就是没配安全策略（文件不存在） | 「没有配安全策略」（**正常结果**） |
        | 文件在、但读不动 / 0 字节 / 解析失败 | 「这一份读失败了，等于我们少看了它」 |
        | 一个文件都没读成功 | 「不能说没有配安全策略，只能说这次什么都没看到」 |
        | 模板在、但 GPC 没登记安全扩展 | 「不会被应用」＋ 为什么（**别处看不到的一句**） |

        ⚠️ 最后一句**只在读到过模板时才印**（判据在 `GpoSecurity.cse_is_relevant`，
        不在面板里）—— 没有模板却印"不会被应用"，使用者会去找一份不存在的策略。
        """
        security = getattr(result, "security", None)
        if security is None:
            self.result.setPlainText("没有拿到这条组策略的安全策略。")
            return
        self.result.setPlainText(_security_text(result, security))

    def show_error(self, message: str) -> None:
        self.result.setPlainText("【出错】" + (message or "未知错误"))

    # ------------------------------------------------------------ 内部

    def _emit_search(self) -> None:
        self.search_requested.emit(self.search_text())

    def _emit_links(self) -> None:
        guid = self.selected_guid()
        if guid:
            self.links_requested.emit(guid)
            return
        self._say_pick_one("看链接位置")

    def _emit_report(self) -> None:
        guid = self.selected_guid()
        if guid:
            self.report_requested.emit(guid)
            return
        self._say_pick_one("看设置摘要")

    def _emit_settings(self) -> None:
        guid = self.selected_guid()
        if guid:
            self.settings_requested.emit(guid)
            return
        self._say_pick_one("看改过哪些设置")

    def _emit_security(self) -> None:
        """发「看安全策略」请求：GUID ＋ 那条扩展名属性**发起时的**原文。

        ⚠️ 扩展名必须**跟着请求一起发出去**，不许让页面在回调里去问面板 ——
        请求在飞时使用者可能已经换了选中项。
        """
        guid = self.selected_guid()
        if guid:
            self.security_requested.emit(guid, self.selected_extension_names())
            return
        self._say_pick_one("看安全策略")

    def _say_pick_one(self, action: str) -> None:
        """没选中就**把话说在结果区里**（本面板没有 toast 通道）。

        ⚠️ 不许静默 return：按钮亮着、点了没反应，会被读成工具卡住了。
        这两个按钮**不做 enable 管理**（与工具栏一致），所以只能靠说话。
        """
        self.result.setPlainText(
            f"请先在上面的列表里选中一条组策略，再点「{action}」。")

    def _on_selection_changed(self) -> None:
        """换了选中项 ⇒ 上一轮的结果**不再代表现在选的东西**，先清掉。

        不清的话，选中 B 时屏幕上还留着 A 的链接位置 —— 那比空白更糟：
        它会让人以为 B 链在 A 的位置上。
        """
        self.result.clear()
        self.result.setPlaceholderText(
            "点「看链接位置」「看改过哪些设置」「看安全策略」或「看设置摘要」"
            "查看这条 GPO。")
