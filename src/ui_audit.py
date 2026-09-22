# -*- coding: utf-8 -*-
"""
ui_audit.py —— 操作日志查看器（T10c）

**非模态**独立窗口：日志是"边看边操作"的东西，
做成模态框会逼使用者每次想看日志都得先关掉手上的操作。

为什么必须存在这个窗口：这个工具能改密码、能启用禁用账号。
出了事要能回答「谁、什么时候、在哪台域控、把谁、从什么改成了什么」。
"""

from __future__ import annotations

from datetime import datetime

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QComboBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from audit import OP_LABELS, AuditLog
from ui_widgets import Colors, hint_label, make_button
from utils import breadcrumb

__all__ = ["AuditWindow"]


class AuditWindow(QDialog):
    """操作日志窗口。"""

    COLUMNS = ["时间", "操作", "目标", "结果", "详情"]

    def __init__(self, audit: AuditLog, parent: QWidget | None = None):
        super().__init__(parent)
        self.audit = audit
        self.setWindowTitle("操作日志")
        self.setModal(False)
        self.resize(940, 560)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(9)

        filters = QHBoxLayout()
        filters.setSpacing(8)

        self.op_combo = QComboBox()
        self.op_combo.addItem("全部操作", "")
        for key, label in OP_LABELS.items():
            self.op_combo.addItem(label, key)
        self.op_combo.currentIndexChanged.connect(self.reload)
        filters.addWidget(self.op_combo)

        self.search = QLineEdit()
        self.search.setPlaceholderText("按账号或 DN 筛选")
        self.search.setClearButtonEnabled(True)
        self.search.returnPressed.connect(self.reload)
        filters.addWidget(self.search, 1)

        refresh = QPushButton("刷新")
        refresh.clicked.connect(self.reload)
        filters.addWidget(refresh)

        export = make_button("导出 CSV")
        export.clicked.connect(self._export)
        filters.addWidget(export)
        layout.addLayout(filters)

        self.table = QTableWidget(0, len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table, 1)

        self.status = QLabel("")
        layout.addWidget(self.status)

        self.hint = hint_label(
            "日志按 JSONL 逐行追加写入，UTF-8 编码，位于应用数据目录的 logs 下。"
            "日志里不会出现任何密码明文。")
        layout.addWidget(self.hint)

        self.reload()

    # ==================================================================

    def reload(self) -> None:
        op = self.op_combo.currentData() or ""
        target = self.search.text().strip()
        entries = self.audit.read(limit=2000, op=op, target=target)

        self.table.setRowCount(len(entries))
        for index, entry in enumerate(entries):
            failed = entry.get("result") != "success"
            values = [
                _short_time(entry.get("ts", "")),
                entry.get("op_label", ""),
                entry.get("target_sam") or entry.get("target_dn", ""),
                "失败" if failed else "成功",
                entry.get("detail", ""),
            ]
            for column, text in enumerate(values):
                item = QTableWidgetItem(str(text))
                item.setToolTip(
                    f"域控：{entry.get('dc_ip', '')}　域：{entry.get('domain', '')}\n"
                    f"操作者：{entry.get('operator', '')}\n"
                    f"DN：{entry.get('target_dn', '')}\n"
                    f"客户端 IP：{entry.get('client_ip', '')}")
                if column == 3:
                    item.setForeground(QColor(Colors.DANGER if failed else Colors.OK))
                self.table.setItem(index, column, item)

        failed_count = sum(1 for e in entries if e.get("result") != "success")
        self.status.setText(f"共 {len(entries)} 条记录，其中失败 {failed_count} 条。"
                            f"（最多显示最近 2000 条）")

    def _export(self) -> None:
        default = f"AD操作日志_{datetime.now():%Y%m%d_%H%M}.csv"
        # 原生文件对话框 = 输入同步的 COM 调用，进出各记一条面包屑（见 utils.breadcrumb）
        breadcrumb("打开导出对话框（操作日志）")
        path, _ = QFileDialog.getSaveFileName(self, "导出操作日志", default,
                                              "CSV 文件 (*.csv)")
        breadcrumb("导出对话框已关闭（操作日志）")
        if not path:
            return
        op = self.op_combo.currentData() or ""
        entries = self.audit.read(limit=100000, op=op,
                                  target=self.search.text().strip())
        try:
            count = self.audit.export_csv(path, entries)
        except Exception as exc:                     # noqa: BLE001
            self.status.setText(f"导出失败：{exc}")
            self.status.setStyleSheet(f"color: {Colors.DANGER};")
            return
        self.status.setText(f"已导出 {count} 条到 {path}")
        self.status.setStyleSheet(f"color: {Colors.OK};")


def _short_time(iso: str) -> str:
    """``2026-09-11T09:25:20.123+08:00`` → ``09-11 09:25:20``。

    保留到秒：审计场景下"哪一秒"往往就是关键信息。
    """
    if not iso:
        return ""
    try:
        stamp = datetime.fromisoformat(iso)
    except ValueError:
        return iso
    return stamp.strftime("%m-%d %H:%M:%S")
