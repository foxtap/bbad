# -*- coding: utf-8 -*-
"""
config.py —— 配置读写（T03）

设计要点：
  * 配置放 ``%APPDATA%\\AD域管理工具\\config.json``，**不放 exe 同目录**
    （exe 常在 U 盘/共享盘，写权限与便携性都不稳）。
  * 写入用「临时文件 + 原子替换」，避免断电写坏配置。
  * 明文密码**不落盘**（红线）；可选「记住密码」走 Windows DPAPI 加密。
  * 出厂模板里所有域相关字段都是空串（红线）。
  * 每条连接记录带一个**身份**（``ConnConfig.id``）：记录与密文按**身份**
    配对，不按**下标**。下标在插入/删除/重排之后会指到别人身上（见 `_resolve`）。
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from models import AppConfig, ConnConfig
from utils import AdToolError, get_logger

__all__ = [
    "APP_DIR_NAME",
    "app_dir",
    "config_path",
    "logs_dir",
    "ConfigStore",
    "protect_secret",
    "unprotect_secret",
    "dpapi_available",
]

_log = get_logger("config")

APP_DIR_NAME = "AD域管理工具"
_CONFIG_FILENAME = "config.json"


# ============================================================================
# 路径
# ============================================================================

def app_dir() -> str:
    """应用数据目录：``%APPDATA%\\AD域管理工具``。

    源码模式与打包后的 exe 模式**共用同一份配置**，形态切换不丢连接配置。
    """
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    path = os.path.join(base, APP_DIR_NAME)
    os.makedirs(path, exist_ok=True)
    return path


def config_path() -> str:
    return os.path.join(app_dir(), _CONFIG_FILENAME)


def logs_dir() -> str:
    path = os.path.join(app_dir(), "logs")
    os.makedirs(path, exist_ok=True)
    return path


# ============================================================================
# DPAPI（可选记住密码）
# ============================================================================

def dpapi_available() -> bool:
    """DPAPI 只有 Windows + pywin32 可用。"""
    try:
        import win32crypt  # noqa: F401
    except Exception:
        return False
    return True


def protect_secret(plain: str) -> str:
    """把密码用 DPAPI 加密成 base64 字符串。

    ⚠️ 诚实说明：DPAPI 默认作用域是「当前 Windows 用户 + 当前机器」。
       别人拿到这台机器的这个账号就能解开；但把 config.json 拷到另一台机器解不开。
       它防的是「配置文件被顺走」，**不防「本机被入侵」**。
    """
    if not plain:
        return ""
    try:
        import win32crypt
    except Exception as exc:  # pragma: no cover - 非 Windows 环境
        raise AdToolError("当前环境不支持 DPAPI 加密，无法记住密码。") from exc
    try:
        blob = win32crypt.CryptProtectData(
            plain.encode("utf-8"), APP_DIR_NAME, None, None, None, 0
        )
        return base64.b64encode(blob).decode("ascii")
    except Exception as exc:
        raise AdToolError("密码加密失败，请改用「每次输入」方式。") from exc


def unprotect_secret(b64: str) -> str:
    """解开 DPAPI 密文。失败时返回空串（不抛异常，让使用者重新输入即可）。"""
    if not b64:
        return ""
    try:
        import win32crypt
        blob = base64.b64decode(b64)
        _, data = win32crypt.CryptUnprotectData(blob, None, None, None, 0)
        return data.decode("utf-8")
    except Exception as exc:  # pragma: no cover - 依赖 Windows 环境
        _log.warning("DPAPI 解密失败（可能换了机器或账号）：%s", type(exc).__name__)
        return ""


# ============================================================================
# 配置存储
# ============================================================================

def _new_connection_id() -> str:
    """给一条连接配置分配一个**不会重复**的身份。

    用 uuid4 而不是"自增序号 / 名字 / IP"：序号要靠一个**全局计数器**才不撞
    （而这个文件可能被两台机器的两份进程同时读写）；名字和 IP 都是使用者
    随手能改的字段，拿它们当身份，改一次就等于换了个人 —— 密文会对不上号。
    """
    return uuid.uuid4().hex


@dataclass
class StoredConnection:
    """配置文件里的一条连接记录（含可选的加密密码）。

    ⚠️ 密文（``credential_blob``）与记录**在同一条里**，配对靠
    ``config.id`` —— 这就是"身份"存在的全部目的：不再让密文和记录
    分别待在两个列表里、靠下标维持对齐。
    """

    config: ConnConfig
    save_password: bool = False
    credential_blob: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = self.config.to_dict()
        data["save_password"] = self.save_password
        data["credential_blob"] = self.credential_blob
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "StoredConnection":
        return cls(
            config=ConnConfig.from_dict(data),
            save_password=bool(data.get("save_password")),
            credential_blob=data.get("credential_blob") or None,
        )


class ConfigStore:
    """配置文件的读写门面。"""

    def __init__(self, path: str | None = None):
        self.path = path or config_path()
        self.app = AppConfig()
        #: 记录以**身份**（`ConnConfig.id`）为键。⚠️ 它不再是一个与
        #: `app.connections` **并列**的列表（那样两者必须始终保持同序，
        #: 而"同序"没有任何东西守着 —— 见 `_resolve`）。
        self._stored: dict[str, StoredConnection] = {}

    # ---------- 键解析 ----------

    def _resolve(self, key: int | str) -> StoredConnection | None:
        """把**对外键**解析成一条记录 —— **全类唯一**的「键 → 记录」解析点。

        两种键形态都收（对外 ``int | str`` 兼容）：

        * ``int`` —— **下标**（旧接口的兼容形态）：按保存顺序取第 ``key`` 条；
        * ``str`` —— **身份**（``ConnConfig.id``，权威形态）。

        为什么这里必须是唯一一处：密文与记录的配对过去靠**下标**维持
        （``self._stored[i]`` 配 ``app.connections[i]``），下标一旦错位
        （中间插/删、并发改、外面直接动 ``app.connections``），就会把 A 域
        的域管密码装到 B 域的记录上 —— **连错域，而且一声不响**。
        解析只在这一处做，别处一律拿身份说话。

        ⚠️ 序号形态（``int``）是**留给老调用方的**，新代码不许再用：
        "第 3 条"在列表变动之后就未必是刚才那条了。
        """
        if isinstance(key, bool):      # ⚠️ bool 是 int 的子类：True 会被当成 1
            return None
        if isinstance(key, int):
            ordered = list(self._stored.values())
            return ordered[key] if 0 <= key < len(ordered) else None
        return self._stored.get(str(key or "").strip())

    def _sync_connections(self) -> None:
        """把 ``app.connections`` 重新对齐到 ``_stored`` 的**投影**。

        ``app.connections`` 仍是对外的列表形态（序列化、界面遍历都用它），
        但它**不再是另一份真相**：改动一律走本类的方法，每次改完由这里重建。
        这样"两份列表会不会不同序"这个问题**从机制上消失**（它不是靠纪律维持的）。
        """
        self.app.connections = [s.config for s in self._stored.values()]

    # ---------- 读写 ----------

    def _quarantine(self, what: str) -> None:
        """把**读不了的**配置文件改名留证，然后由调用方回退空模板。

        🔴 只回退、不备份是**不可逆**的：回退之后任意一次 `save()`（连上一条
           配置、切个主题、增删一条连接都会调它）就会把空模板原子替换上去
           —— 盘上那份**就永远没了**，连同里面所有连接的 DPAPI 密文
           （密文的解钥绑在"当前这台机器 + 这个 Windows 账号"上，
           文件一没，等于那些密码也一起没了）。

        所以先改名成 ``config.json.bad-<时间戳>``：

        * 改名**成功** ⇒ 落 ERROR 并**写出备份路径**，使用者知道去哪儿找；
        * 改名**失败** ⇒ 也**不许抛**（那会把"配置读不了"升级成"程序起不来"），
          但必须落 ERROR 说清"它随时可能被下一次保存覆盖" —— 这是最后一道
          能提醒他的机会，**不能静默**。
        """
        # ⚠️ 只对**普通文件**改名。路径指向目录时（`ConfigStore(某目录)` 这种
        #    用法，测试里就有），`os.replace` 会把整个目录搬走 ——
        #    那就不是"留证"，是**帮倒忙**。
        if not os.path.isfile(self.path):
            _log.error("配置路径不是一个普通文件，不做改名留证：%s", self.path)
            return
        backup = f"{self.path}.bad-{datetime.now():%Y%m%d-%H%M%S}"
        try:
            os.replace(self.path, backup)
        except OSError as exc:
            _log.error(
                "配置文件%s，且「改名留证也失败了」（%s）⇒ %s 随时可能被下一次"
                "保存覆盖，请手工把它拷走。", what, exc, self.path)
            return
        _log.error("配置文件%s，已改名留证：%s（回退空模板，原内容仍可从该文件找回）",
                   what, backup)

    def load(self) -> AppConfig:
        """读取配置。文件不存在/损坏时返回**空模板**，不抛异常。

        ⚠️ 损坏时**先留证再回退**（见 `_quarantine`）—— 回退本身没问题，
           问题是"回退之后那份坏文件还在不在"。
        """
        if not os.path.exists(self.path):
            _log.info("配置文件不存在，使用空模板：%s", self.path)
            self.app = AppConfig()
            self._stored = {}
            return self.app

        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except json.JSONDecodeError as exc:
            self._quarantine(f"JSON 损坏（{exc}）")
            self.app = AppConfig()
            self._stored = {}
            return self.app
        except OSError as exc:
            self._quarantine(f"读取失败（{exc}）")
            self.app = AppConfig()
            self._stored = {}
            return self.app

        self._stored = {}
        needs_identity = False
        for item in (raw.get("connections") or []):
            stored = StoredConnection.from_dict(item)
            ident = stored.config.id
            if not ident or ident in self._stored:
                # 没身份的 = 本切片之前写下的配置（迁移）；身份重复的 =
                # 手改过或从别处拷来的文件 —— 两种都当场补一个新身份。
                # ⚠️ 重复那一支**必须**拆开：dict 会把前一条**顶掉**，
                #    那等于静默丢一条配置（比"改坏"更难发现）。
                ident = _new_connection_id()
                stored.config.id = ident
                needs_identity = True
            self._stored[ident] = stored
        self.app = AppConfig.from_dict(raw)
        self._sync_connections()
        if needs_identity:
            self._persist_identity_migration()
        return self.app

    def _persist_identity_migration(self) -> None:
        """把刚补上的身份**落盘**。

        ⚠️ 不落盘 = 迁移不幂等：每次启动都会给同一条配置换一个新身份，
        而身份是要拿去当键用的（远端的接入信息、密文都挂在它下面）。
        `load()` 的契约是"读不进来就回退空模板、**不抛异常**"，所以落盘失败
        这里只记一条日志 —— 下次启动会重试（读的时候发现还是没身份）。
        """
        try:
            self.save()
        except (AdToolError, OSError) as exc:
            _log.warning("连接配置身份迁移未能落盘，下次启动会重试：%s", exc)

    def save(self) -> None:
        """原子写入配置。

        ⚠️ 明文密码永不落盘。只有 ``save_password=True`` 的连接才会带
           ``credential_blob``（DPAPI 密文）。
        """
        payload: dict[str, Any] = self.app.to_dict()
        payload["connections"] = []
        seen: set[str] = set()
        for cfg in self.app.connections:
            # 🔴 密文按**身份**取，不按**位置**取 —— 这是本轮改动的要害。
            #    旧写法是 `self._stored[i]` 配 `app.connections[i]`：两份列表
            #    一旦不同序，A 的密文就装到 B 的配置上（连错域、且无声）。
            stored = self._stored.get(cfg.id) if cfg.id and cfg.id not in seen else None
            if stored is None:
                # 没身份 / 身份跟前面某条撞车的记录：当场补一个新身份。
                # ⚠️ 撞车**必须**拆开 —— 以身份为键的字典撞键是**静默覆盖**，
                #    那等于静默丢掉一条配置（比"改坏"更难被发现）。
                cfg.id = _new_connection_id()
                stored = StoredConnection(config=cfg)
            seen.add(cfg.id)
            stored.config = cfg
            if not stored.save_password:
                stored.credential_blob = None          # 关掉开关就立刻清掉密文
            payload["connections"].append(stored.to_dict())

        directory = os.path.dirname(self.path) or "."
        os.makedirs(directory, exist_ok=True)

        tmp_fd, tmp_path = tempfile.mkstemp(dir=directory, suffix=".tmp")
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, self.path)            # 原子替换
        except OSError as exc:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise AdToolError(f"配置保存失败：{exc}") from exc

        # 同步内存态：以**身份**为键重建，列表形态是它的投影。
        # ⚠️ 重建而不是"就地改" —— 对象与盘上那份保持一致（含被丢弃的孤儿记录）。
        self._stored = {c["id"]: StoredConnection.from_dict(c)
                        for c in payload["connections"]}
        self._sync_connections()

    # ---------- 连接管理 ----------

    def list_connections(self) -> list[ConnConfig]:
        return list(self.app.connections)

    def _assert_name_is_free(self, name: str, exclude_id: str | None = None) -> None:
        """名字已被**别的**记录占用 ⇒ 抛 `AdToolError`。

        「配置名**不允许重名**」是 2026-09-18 定的产品口径。理由是
        使用者拿名字认记录：连接页的列表只显示 `display_name()`（读的就是
        `name`），两条同名 ⇒ **界面上再也分不清哪条是哪条**。

        🔴 为什么必须是**一个**函数、由两条路共用：能落名字的路有**两条**
        （`add_connection` 新存 / `update_connection` 改名）。各写一份迟早
        分叉，而分叉的后果不是报错 —— 是**口径被绕过**：点第 1 条、把名字
        改成第 2 条的、连一次 ⇒ 盘上出现两条同名，而 `add_connection` 那道
        闸还"在"（看着像有保护）。2026-09-18 补的正是 update 那一半。

        空名字**不参与**去重：多条还没起名的配置是合法的（连接页在保存时
        才把空名回落成 `dc_ip`）。

        ⚠️ `exclude_id` 的默认值是 `None` 而不是 `""` —— 它表示「**不排除
        任何人**」。老配置文件里可能存在身份为空串的记录（`load()` 的身份
        迁移就是为它们写的），拿 `""` 当哨兵会把那条记录**误当成自己**
        从而漏检。
        """
        if not name:
            return
        for other in self.app.connections:
            if other.name == name and other.id != exclude_id:
                raise AdToolError(f"已存在同名配置「{name}」，请换一个名字。")

    def add_connection(self, cfg: ConnConfig, save_password: bool = False,
                       password: str = "") -> None:
        self._assert_name_is_free(cfg.name)
        # 身份由 store 分配：调用方给的 id 只有在"这个身份确实还是空的"时才认。
        # 传进来的 id 已经存在 ⇒ 那不是在加新记录，是在**顶掉**别人的记录
        # （后果就是密文对错人），一律换新身份，不覆盖。
        if not cfg.id or cfg.id in self._stored:
            cfg.id = _new_connection_id()
        blob = protect_secret(password) if (save_password and password) else None
        self._stored[cfg.id] = StoredConnection(config=cfg, save_password=save_password,
                                                credential_blob=blob)
        self._sync_connections()

    def update_connection(self, key: int | str, cfg: ConnConfig,
                          save_password: bool = False, password: str = "") -> None:
        stored = self._resolve(key)
        if stored is None:
            raise AdToolError("要更新的配置不存在，请刷新后重试。")
        # 🔴 重名判据**在这条路上也要过**（2026-09-18 补）。`update_connection`
        #    是**改名**的唯一入口（连接页的「配置名」是普通输入框）⇒ 不查就等于
        #    「不允许重名」这条口径**可以被绕过**：点第 1 条 → 把名字改成第 2 条
        #    的 → 连一次 ⇒ 盘上两条同名，界面上再也分不清哪条是哪条
        #    （列表只显示 `display_name()`），而 `add_connection` 那道闸看着
        #    还"在"。判据本身只此一份，见 `_assert_name_is_free`。
        #    ⚠️ 必须**排除自己**：原地保存（名字一个字没动）不是撞名。
        self._assert_name_is_free(cfg.name, exclude_id=stored.config.id)
        # 🔴 身份**跟着记录走**，不跟着传进来的 cfg 走：调用方（连接页表单）
        #    每次都是**重建**一个 ConnConfig，里面没有 id。这里若留空，
        #    `save()` 会给它补一个新身份 ⇒ 这条记录等于被换成了另一个人，
        #    它记着的密文当场对不上号（旧密码静默丢失）。
        cfg.id = stored.config.id
        stored.config = cfg
        stored.save_password = save_password
        if save_password and password:
            stored.credential_blob = protect_secret(password)
        elif not save_password:
            # 🔴 这一步会**不可逆地删掉**盘上的密文（DPAPI 密文一旦没了就解不回，
            #    因为它绑在"这台机器 + 这个 Windows 账号"上）。
            #    所以它**不许静默**：落一条 INFO 说清是哪条记录、被谁要求清掉的。
            #    触发它的正常路径是"使用者把「记住密码」取消勾选"——
            #    那是明确的意思表示，照做没错，只是要留痕。
            #    ⚠️ 另有一条**非正常**路径曾经走这里：连接页看到密文解不开时
            #    把复选框自动取消 ⇒ 连接成功就顺手把密文删了。那一处已修
            #    （复选框现在反映记录的**意图**，不反映"这次解开了没有"），
            #    这条日志是第二道 —— 下次再有别的路径走到这儿，日志里看得见。
            if stored.credential_blob:
                _log.info("清除连接「%s」已保存的凭据（调用方要求不再记住密码）",
                          cfg.name or cfg.dc_ip)
            stored.credential_blob = None
        self._sync_connections()

    def remove_connection(self, key: int | str) -> None:
        stored = self._resolve(key)
        if stored is None:
            raise AdToolError("要删除的配置不存在，请刷新后重试。")
        self._stored.pop(stored.config.id, None)
        self._sync_connections()

    def saved_password(self, key: int | str) -> str:
        """取出已记住的密码；未记住、认不出这条、或解不开时返回空串。"""
        stored = self._resolve(key)
        return unprotect_secret(stored.credential_blob or "") if stored else ""

    def is_password_saved(self, key: int | str) -> bool:
        """这条配置是否**真的**存着可用的密码。

        ⚠️ 判据不能只看 ``save_password`` 那个开关 —— 两者会不一致：

        1. 勾了「记住密码」但没给密码 → 密文是 ``None``；
        2. config.json 来自**另一台机器 / 另一个 Windows 账号** → 密文在，
           但 DPAPI 解不开（DPAPI 的作用域就是「当前用户 + 当前机器」）。

        只看开关，界面就会给「已记住」打勾而密码框是空的：使用者以为密码
        已经备好，一点连接却报「请填写绑定账号密码」—— 而且他不会想到
        是配置文件换过机器。
        """
        stored = self._resolve(key)
        if stored is None:
            return False
        return bool(stored.save_password
                    and unprotect_secret(stored.credential_blob or ""))

    def wants_password_saved(self, key: int | str) -> bool:
        """「记住密码」的开关本身（**不**校验密文是否可用）。

        只用来给出**解释性提示**：开关开着但密码拿不到，就该告诉使用者
        为什么，而不是静默留在"打勾了却没有密码"的状态里。
        """
        stored = self._resolve(key)
        return bool(stored and stored.save_password)

    def has_password_blob(self, key: int | str) -> bool:
        """密文**存在**吗（不判断能不能解开）。

        只用来把提示说准：「压根没存过」与「存了但换了机器解不开」
        是两件不同的事，混成一句话就等于没说。
        """
        stored = self._resolve(key)
        return bool(stored and stored.credential_blob)

    def remember_password_enabled(self, key: int | str) -> bool:
        return self.is_password_saved(key)

    # ---------- 新建用户的默认密码 ----------

    def has_default_password(self) -> bool:
        return bool(self.app.default_password_blob)

    def default_password(self) -> str:
        """取「默认密码」明文；没设过或解不开（换机器/换账号）返回空串。"""
        return unprotect_secret(self.app.default_password_blob or "")

    def set_default_password(self, plain: str) -> None:
        """设置 / 清除新建用户的默认密码。

        走与「记住密码」同一条 DPAPI 通道 —— **明文不落盘**，
        密码只以密文形式存在 ``%APPDATA%\\AD域管理工具\\config.json``。
        传空串 = 清除。
        """
        self.app.default_password_blob = protect_secret(plain) if plain else ""
        self.save()
