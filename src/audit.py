# -*- coding: utf-8 -*-
"""
audit.py —— 本地操作审计日志（T03）

格式：**JSONL**（一行一条 JSON），按月分文件，UTF-8 无 BOM。

为什么不用 CSV：AD 属性值里可能出现逗号、引号、换行，CSV 转义太容易翻车。

🔒 四条写入铁律：
  1. 成功和失败**都要记**。只记成功等于没有审计。
  2. 失败也要**先落日志再抛异常**。
  3. 日志写入失败**不能吞掉原操作结果** —— 要显式告知使用者。
  4. **detail / before / after 全字段脱敏**（见 ``write()``）。口令最容易从
     属性字典漏出去，只脱敏 detail 是假脱敏。
"""

from __future__ import annotations

import csv
import json
import os
import socket
import threading
from datetime import datetime, timedelta
from typing import Any, Iterable

from utils import defuse_csv_cell, get_logger, now_iso, redact, redact_obj

__all__ = [
    "APP_VERSION", "AuditLog", "OP_LABELS",
    "OP_UNLOCK", "OP_ENABLE", "OP_DISABLE", "OP_RESET_PASSWORD",
    "OP_CREATE_USER", "OP_CREATE_OU", "OP_CREATE_GROUP",
    "OP_DELETE", "OP_MOVE", "OP_RENAME", "OP_UPDATE", "OP_UPDATE_OU",
    "OP_ADD_MEMBER", "OP_REMOVE_MEMBER",
    "OP_CREATE_COMPUTER", "OP_CREATE_CONTACT", "OP_RESET_COMPUTER",
]

APP_VERSION = "1.0.0"

# 操作类型常量
OP_UNLOCK = "unlock"
OP_ENABLE = "enable"
OP_DISABLE = "disable"
OP_RESET_PASSWORD = "reset_password"
OP_CREATE_USER = "create_user"
OP_CREATE_OU = "create_ou"
OP_CREATE_GROUP = "create_group"

# --- ADUC 对齐新增 ---
OP_DELETE = "delete"                    # 删除对象（用户/组/计算机/联系人/OU）
OP_MOVE = "move"                        # 移动到其它容器
OP_RENAME = "rename"                    # 重命名（只改 RDN）
OP_UPDATE = "update"                    # 修改属性（含属性编辑器）
OP_UPDATE_OU = "update_ou"              # 修改组织单位属性（名称/描述）
OP_ADD_MEMBER = "add_member"            # 加入组
OP_REMOVE_MEMBER = "remove_member"      # 移出组
OP_CREATE_COMPUTER = "create_computer"  # 新建计算机
OP_CREATE_CONTACT = "create_contact"    # 新建联系人
OP_RESET_COMPUTER = "reset_computer"    # 重置计算机账号

OP_LABELS: dict[str, str] = {
    OP_UNLOCK: "解锁账号",
    OP_ENABLE: "启用账号",
    OP_DISABLE: "禁用账号",
    OP_RESET_PASSWORD: "重置密码",
    OP_CREATE_USER: "新建用户",
    OP_CREATE_OU: "新建组织单位",
    OP_CREATE_GROUP: "新建组",
    OP_DELETE: "删除对象",
    OP_MOVE: "移动到容器",
    OP_RENAME: "重命名对象",
    OP_UPDATE: "修改属性",
    OP_UPDATE_OU: "修改组织单位",
    OP_ADD_MEMBER: "加入组",
    OP_REMOVE_MEMBER: "移出组",
    OP_CREATE_COMPUTER: "新建计算机",
    OP_CREATE_CONTACT: "新建联系人",
    OP_RESET_COMPUTER: "重置计算机账号",
}

_log = get_logger("audit")


def _local_ip() -> str:
    """取本机出口 IP。用 UDP connect 技巧，**不做 DNS 解析**。失败返回空串。"""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("10.255.255.255", 1))
        return sock.getsockname()[0]
    except OSError:
        return ""
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


class AuditLog:
    """审计日志写入器。线程安全（批量操作在 QThread 里跑）。"""

    def __init__(self, log_dir: str, keep_days: int = 180,
                 dc_ip: str = "", domain: str = "", operator: str = ""):
        self.log_dir = log_dir
        self.keep_days = keep_days
        self.dc_ip = dc_ip
        self.domain = domain
        self.operator = operator
        self._lock = threading.Lock()
        os.makedirs(self.log_dir, exist_ok=True)

    # ---------- 上下文 ----------

    def bind_context(self, dc_ip: str = "", domain: str = "",
                     operator: str = "") -> None:
        """切换当前操作的域控上下文。

        工具是多域通用的，不记 ``dc_ip`` 事后根本对不上账。
        """
        self.dc_ip = dc_ip or ""
        self.domain = domain or ""
        self.operator = operator or ""

    # ---------- 路径 ----------

    def file_for(self, when: datetime | None = None) -> str:
        when = when or datetime.now()
        return os.path.join(self.log_dir, f"audit-{when:%Y-%m}.jsonl")

    # ---------- 写入 ----------

    def write(self, op: str, target_sam: str = "", target_dn: str = "",
              result: str = "success", detail: str = "",
              before: dict[str, Any] | None = None,
              after: dict[str, Any] | None = None,
              secrets: Iterable[str] = ()) -> bool:
        """写一条审计记录。返回是否写入成功。

        ``secrets`` 里传本次操作的口令（明文），**绝不会**出现在日志里。

        🔒 脱敏覆盖 **detail / before / after 三处**，缺一不可：``before`` /
        ``after`` 是属性字典，口令会藏在「某个属性的值」里 —— 有人在
        ``description`` 里粘了密码、或属性值本身就是 ``unicodePwd``。
        只对 ``detail`` 脱敏等于把口令原样落盘（已踩过一次，日志里躺着
        「创建用户失败并已自动回滚（密码 HeMei@2026#init …）」）。
        """
        # secrets 声明是 Iterable（可能是生成器），先固化一次 —— 三个字段
        # 各迭代一遍会把生成器耗尽，导致 detail 之外的字段静默失去保护
        secret_tuple = tuple(s for s in (secrets or ()) if s)
        entry = {
            "ts": now_iso(),
            "dc_ip": self.dc_ip,
            "domain": self.domain,
            "op": op,
            "op_label": OP_LABELS.get(op, op),
            "target_sam": target_sam,
            "target_dn": target_dn,
            "operator": self.operator,
            "result": "success" if result == "success" else "failed",
            "detail": redact(detail, *secret_tuple),
            "before": redact_obj(before, *secret_tuple),
            "after": redact_obj(after, *secret_tuple),
            "client_ip": _local_ip(),
            "app_version": APP_VERSION,
        }
        line = json.dumps(entry, ensure_ascii=False)
        try:
            with self._lock:
                with open(self.file_for(), "a", encoding="utf-8", newline="\n") as fh:
                    fh.write(line + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
            return True
        except OSError as exc:
            # 不抛异常：调用方要能先完成业务再决定如何提示
            _log.error("审计日志写入失败：%s", exc)
            return False

    def write_or_warn(self, *args, **kwargs) -> str | None:
        """写日志；失败时返回一句中文警告文案，成功返回 None。

        用法：
            warn = audit.write_or_warn(...)
            if warn: 提示使用者「操作成功，但审计日志写入失败」
        """
        if self.write(*args, **kwargs):
            return None
        return "操作已完成，但审计日志写入失败（磁盘可能已满或无写入权限）。"

    # ---------- 读取 ----------

    def read(self, limit: int = 200, op: str = "", target: str = "",
             since: datetime | None = None,
             until: datetime | None = None) -> list[dict[str, Any]]:
        """倒序读取审计记录（最新的在前）。"""
        entries: list[dict[str, Any]] = []
        for path in self._all_files_desc():
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                        except json.JSONDecodeError:
                            continue          # 跳过断电截断的半行
                        if not self._match(entry, op, target, since, until):
                            continue
                        entries.append(entry)
            except OSError as exc:
                _log.warning("读取审计日志失败 %s：%s", path, exc)
                continue
            entries.sort(key=lambda e: e.get("ts", ""), reverse=True)
            if len(entries) >= limit:
                break
        return entries[:limit]

    # ---------- 导出 ----------

    def export_csv(self, dest_path: str, entries: list[dict[str, Any]] | None = None) -> int:
        """导出为 CSV（Excel 可直接打开）。返回导出条数。

        🔒 **每一个数据单元格都要过 `defuse_csv_cell`** ——
        `csv.writer` 只保证 CSV 的**语法**，不阻止 Excel 把以
        `=` `+` `-` `@` 开头的单元格当**公式执行**。而这里的 `target_dn` /
        `operator` / `detail` 都是外部可控输入（DN 里就带 `=`！），
        导出后用 Excel 打开就会中招（CWE-1236 / OWASP A03）。
        """
        rows = entries if entries is not None else self.read(limit=100000)
        columns = ["ts", "dc_ip", "domain", "op_label", "target_sam", "target_dn",
                   "operator", "result", "detail"]
        try:
            # utf-8-sig 带 BOM，Excel 打开中文才不乱码
            with open(dest_path, "w", encoding="utf-8-sig", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore")
                writer.writeheader()
                for row in rows:
                    writer.writerow(
                        {k: defuse_csv_cell(row.get(k, "")) for k in columns})
        except OSError as exc:
            from utils import AdToolError
            raise AdToolError(f"日志导出失败：{exc}") from exc
        return len(rows)

    # ---------- 维护 ----------

    def purge_old(self) -> int:
        """删除超过 ``keep_days`` 的月份文件。返回删除数量。"""
        if self.keep_days <= 0:
            return 0
        cutoff = datetime.now() - timedelta(days=self.keep_days)
        removed = 0
        try:
            names = os.listdir(self.log_dir)
        except OSError:
            return 0
        for name in names:
            if not (name.startswith("audit-") and name.endswith(".jsonl")):
                continue
            month = name[len("audit-"):-len(".jsonl")]
            try:
                stamp = datetime.strptime(month, "%Y-%m")
            except ValueError:
                continue
            # 该月最后一天 + 1 天，早于 cutoff 才删
            if stamp.replace(day=28) + timedelta(days=5) < cutoff:
                try:
                    os.remove(os.path.join(self.log_dir, name))
                    removed += 1
                except OSError:
                    pass
        return removed

    # ---------- 内部 ----------

    def _all_files_desc(self) -> list[str]:
        try:
            names = sorted(
                (n for n in os.listdir(self.log_dir)
                 if n.startswith("audit-") and n.endswith(".jsonl")),
                reverse=True,
            )
        except OSError:
            return []
        return [os.path.join(self.log_dir, n) for n in names]

    @staticmethod
    def _match(entry: dict[str, Any], op: str, target: str,
               since: datetime | None, until: datetime | None) -> bool:
        if op and entry.get("op") != op:
            return False
        if target:
            needle = target.lower()
            if (needle not in str(entry.get("target_sam", "")).lower()
                    and needle not in str(entry.get("target_dn", "")).lower()):
                return False
        ts = entry.get("ts", "")
        if since and ts < since.isoformat():
            return False
        if until and ts > until.isoformat():
            return False
        return True
