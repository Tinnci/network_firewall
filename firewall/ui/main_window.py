#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import time
from typing import List, Union, Set  # Added Union, Set
import re
import logging

from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QLabel,
    QLineEdit,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QMessageBox,
    QCheckBox,
    QGroupBox,
    QFormLayout,
    QHeaderView,
    QSpinBox,
    QTextEdit,
    QListWidget,
    QListWidgetItem,
    QFileDialog,
)
from PyQt6.QtCore import QTimer, pyqtSlot
from PyQt6.QtGui import QColor

from ..core.firewall import Firewall

# Get logger for UI module
logger = logging.getLogger("MainWindowUI")


class MainWindow(QMainWindow):
    """防火墙主窗口"""

    def __init__(self, parent=None):
        super().__init__(parent)

        # 创建防火墙实例
        self.firewall = Firewall()

        # 设置窗口基本属性
        self.setWindowTitle("简易防火墙")
        self.setMinimumSize(800, 600)

        # 记录上次更新时间以优化定时器处理
        self.last_update_time = 0
        self.update_interval = 1000  # 毫秒

        # 创建UI组件
        self._create_ui()

        # 设置更新定时器 (只更新状态和规则，不再更新日志)
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self._update_status)
        self.update_timer.start(1000)  # 每秒更新一次状态

        # Connect the log signal from Firewall instance
        self.firewall.log_signal.connect(self._add_log_entry)

        # Initial load of rules into UI
        self._update_rule_lists()
        # Initial load of settings into UI
        self._load_advanced_settings()

    def _create_ui(self):
        """创建UI组件"""
        # 创建中央窗口部件
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)

        # 创建主布局
        main_layout = QVBoxLayout(central_widget)

        # 创建控制面板
        control_panel = self._create_control_panel()
        main_layout.addWidget(control_panel)

        # 创建标签页控件
        self.tab_widget = QTabWidget(self)

        # 创建各个标签页
        self.tab_widget.addTab(self._create_ip_filter_tab(), "IP过滤")
        self.tab_widget.addTab(self._create_port_filter_tab(), "端口过滤")
        self.tab_widget.addTab(self._create_content_filter_tab(), "内容过滤")
        self.tab_widget.addTab(self._create_performance_tab(), "性能监控")
        self.tab_widget.addTab(self._create_advanced_settings_tab(), "高级设置")
        self.tab_widget.addTab(self._create_log_tab(), "日志")

        main_layout.addWidget(self.tab_widget)

    def _create_control_panel(self) -> QWidget:
        """创建控制面板"""
        group_box = QGroupBox("控制面板")
        layout = QVBoxLayout(group_box)
        status_layout = QHBoxLayout()
        status_box = QGroupBox("状态信息")
        status_box_layout = QVBoxLayout(status_box)

        self.status_label = QLabel("状态: 已停止")
        status_box_layout.addWidget(self.status_label)
        self.stats_label = QLabel("总处理: 0 | 拦截: 0 | 放行: 0")
        status_box_layout.addWidget(self.stats_label)
        self.resource_label = QLabel("CPU: 0% | 内存: 0%")
        status_box_layout.addWidget(self.resource_label)
        status_layout.addWidget(status_box, stretch=3)

        controls_box = QGroupBox("控制选项")
        controls_layout = QVBoxLayout(controls_box)
        protocol_layout = QHBoxLayout()
        protocol_layout.addWidget(QLabel("允许协议:"))
        self.tcp_checkbox = QCheckBox("TCP")
        self.tcp_checkbox.setChecked(True)
        self.tcp_checkbox.toggled.connect(
            lambda checked: self.firewall.set_protocol_filter("tcp", checked)
        )
        protocol_layout.addWidget(self.tcp_checkbox)
        self.udp_checkbox = QCheckBox("UDP")
        self.udp_checkbox.setChecked(True)
        self.udp_checkbox.toggled.connect(
            lambda checked: self.firewall.set_protocol_filter("udp", checked)
        )
        protocol_layout.addWidget(self.udp_checkbox)
        controls_layout.addLayout(protocol_layout)

        button_layout = QHBoxLayout()
        self.start_button = QPushButton("启动防火墙")
        self.start_button.clicked.connect(self._toggle_firewall)
        self.start_button.setMinimumHeight(40)
        button_layout.addWidget(self.start_button)
        self.restart_button = QPushButton("重启防火墙")
        self.restart_button.clicked.connect(self._restart_firewall)
        button_layout.addWidget(self.restart_button)
        controls_layout.addLayout(button_layout)
        status_layout.addWidget(controls_box, stretch=2)
        layout.addLayout(status_layout)
        return group_box

    def _create_ip_filter_tab(self) -> QWidget:
        """创建IP过滤标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        blacklist_group = QGroupBox("IP黑名单")
        blacklist_layout = QVBoxLayout(blacklist_group)
        bl_input_layout = QHBoxLayout()
        self.bl_ip_input = QLineEdit()
        self.bl_ip_input.setPlaceholderText("输入IP地址或CIDR...")
        bl_input_layout.addWidget(self.bl_ip_input)
        bl_add_button = QPushButton("添加")
        bl_add_button.clicked.connect(self._add_ip_to_blacklist)
        bl_input_layout.addWidget(bl_add_button)
        blacklist_layout.addLayout(bl_input_layout)
        self.bl_ip_list = QListWidget()
        self.bl_ip_list.itemDoubleClicked.connect(self._remove_ip_from_blacklist)
        blacklist_layout.addWidget(self.bl_ip_list)
        bl_button_layout = QHBoxLayout()
        bl_import_button = QPushButton("导入列表")
        bl_import_button.clicked.connect(lambda: self._import_ip_list("blacklist"))
        bl_button_layout.addWidget(bl_import_button)
        bl_export_button = QPushButton("导出列表")
        bl_export_button.clicked.connect(lambda: self._export_ip_list("blacklist"))
        bl_button_layout.addWidget(bl_export_button)
        blacklist_layout.addLayout(bl_button_layout)

        whitelist_group = QGroupBox("IP白名单")
        whitelist_layout = QVBoxLayout(whitelist_group)
        wl_input_layout = QHBoxLayout()
        self.wl_ip_input = QLineEdit()
        self.wl_ip_input.setPlaceholderText("输入IP地址或CIDR...")
        wl_input_layout.addWidget(self.wl_ip_input)
        wl_add_button = QPushButton("添加")
        wl_add_button.clicked.connect(self._add_ip_to_whitelist)
        wl_input_layout.addWidget(wl_add_button)
        whitelist_layout.addLayout(wl_input_layout)
        self.wl_ip_list = QListWidget()
        self.wl_ip_list.itemDoubleClicked.connect(self._remove_ip_from_whitelist)
        whitelist_layout.addWidget(self.wl_ip_list)
        wl_button_layout = QHBoxLayout()
        wl_import_button = QPushButton("导入列表")
        wl_import_button.clicked.connect(lambda: self._import_ip_list("whitelist"))
        wl_button_layout.addWidget(wl_import_button)
        wl_export_button = QPushButton("导出列表")
        wl_export_button.clicked.connect(lambda: self._export_ip_list("whitelist"))
        wl_button_layout.addWidget(wl_export_button)
        whitelist_layout.addLayout(wl_button_layout)

        main_layout = QHBoxLayout()
        main_layout.addWidget(blacklist_group)
        main_layout.addWidget(whitelist_group)
        layout.addLayout(main_layout)
        return widget

    def _create_port_filter_tab(self) -> QWidget:
        """创建端口过滤标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        blacklist_group = QGroupBox("端口黑名单")
        blacklist_layout = QVBoxLayout(blacklist_group)
        bl_input_layout = QHBoxLayout()
        self.bl_port_input = QLineEdit()
        self.bl_port_input.setPlaceholderText("输入端口或范围 (e.g., 80, 8000-8080)")
        bl_input_layout.addWidget(self.bl_port_input)
        bl_add_button = QPushButton("添加")
        bl_add_button.clicked.connect(self._add_port_to_blacklist)
        bl_input_layout.addWidget(bl_add_button)
        blacklist_layout.addLayout(bl_input_layout)
        self.bl_port_list = QListWidget()
        self.bl_port_list.itemDoubleClicked.connect(self._remove_port_from_blacklist)
        blacklist_layout.addWidget(self.bl_port_list)

        whitelist_group = QGroupBox("端口白名单")
        whitelist_layout = QVBoxLayout(whitelist_group)
        wl_input_layout = QHBoxLayout()
        self.wl_port_input = QLineEdit()
        self.wl_port_input.setPlaceholderText("输入端口或范围 (e.g., 443, 10000-11000)")
        wl_input_layout.addWidget(self.wl_port_input)
        wl_add_button = QPushButton("添加")
        wl_add_button.clicked.connect(self._add_port_to_whitelist)
        wl_input_layout.addWidget(wl_add_button)
        whitelist_layout.addLayout(wl_input_layout)
        self.wl_port_list = QListWidget()
        self.wl_port_list.itemDoubleClicked.connect(self._remove_port_from_whitelist)
        whitelist_layout.addWidget(self.wl_port_list)

        main_layout = QHBoxLayout()
        main_layout.addWidget(blacklist_group)
        main_layout.addWidget(whitelist_group)
        layout.addLayout(main_layout)
        return widget

    def _create_content_filter_tab(self) -> QWidget:
        """创建内容过滤标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        filter_group = QGroupBox("内容过滤 (正则表达式)")
        filter_layout = QVBoxLayout(filter_group)
        input_layout = QHBoxLayout()
        self.content_filter_input = QLineEdit()
        self.content_filter_input.setPlaceholderText("输入要过滤的正则表达式...")
        input_layout.addWidget(self.content_filter_input)
        add_button = QPushButton("添加")
        add_button.clicked.connect(self._add_content_filter)
        input_layout.addWidget(add_button)
        filter_layout.addLayout(input_layout)
        self.content_filter_list = QListWidget()
        self.content_filter_list.itemDoubleClicked.connect(self._remove_content_filter)
        filter_layout.addWidget(self.content_filter_list)
        layout.addWidget(filter_group)
        help_label = QLabel(
            "说明: 内容过滤将匹配数据包载荷 (按 UTF-8 解码，忽略错误)。\n"
            "支持 Python 正则表达式语法。\n"
            "双击列表中的项目可以移除该规则。\n"
            "注意: 复杂或过多的规则可能会影响性能。"
        )
        layout.addWidget(help_label)
        return widget

    def _create_performance_tab(self) -> QWidget:
        """创建性能监控标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        stats_group = QGroupBox("性能统计")
        stats_layout = QFormLayout(stats_group)
        self.perf_total_packets = QLabel("0")
        stats_layout.addRow("总处理数据包:", self.perf_total_packets)
        self.perf_dropped_packets = QLabel("0")
        stats_layout.addRow("已拦截数据包:", self.perf_dropped_packets)
        self.perf_passed_packets = QLabel("0")
        stats_layout.addRow("已放行数据包:", self.perf_passed_packets)
        self.perf_error_packets = QLabel("0")
        stats_layout.addRow("处理错误计数:", self.perf_error_packets)
        self.perf_packets_per_second = QLabel("0.00")
        stats_layout.addRow("每秒处理数据包:", self.perf_packets_per_second)
        self.perf_win_error_87 = QLabel("0")
        stats_layout.addRow("WinError 87计数:", self.perf_win_error_87)
        self.perf_queue_size = QLabel("N/A")
        stats_layout.addRow("处理队列大小:", self.perf_queue_size)
        layout.addWidget(stats_group)

        resource_group = QGroupBox("系统资源使用")
        resource_layout = QFormLayout(resource_group)
        self.resource_cpu = QLabel("0%")
        resource_layout.addRow("CPU使用率:", self.resource_cpu)
        self.resource_memory = QLabel("0%")
        resource_layout.addRow("内存使用率:", self.resource_memory)
        self.resource_network_in = QLabel("0 KB")
        resource_layout.addRow("网络接收 (累计):", self.resource_network_in)
        self.resource_network_out = QLabel("0 KB")
        resource_layout.addRow("网络发送 (累计):", self.resource_network_out)
        layout.addWidget(resource_group)

        diagnosis_group = QGroupBox("详细统计/诊断")
        diagnosis_layout = QVBoxLayout(diagnosis_group)
        self.diagnosis_text = QTextEdit()
        self.diagnosis_text.setReadOnly(True)
        self.diagnosis_text.setPlaceholderText("点击“获取详细统计”按钮查看...")
        diagnosis_layout.addWidget(self.diagnosis_text)
        diagnosis_button = QPushButton("获取详细统计")
        diagnosis_button.clicked.connect(self._run_diagnosis)
        diagnosis_layout.addWidget(diagnosis_button)
        layout.addWidget(diagnosis_group)
        return widget

    def _create_advanced_settings_tab(self) -> QWidget:
        """创建高级设置标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        perf_group = QGroupBox("性能优化设置")
        perf_layout = QFormLayout(perf_group)

        self.use_queue_model_checkbox = QCheckBox()
        self.use_queue_model_checkbox.toggled.connect(
            lambda checked: self._update_performance_setting("use_queue_model", checked)
        )
        perf_layout.addRow("使用队列模型:", self.use_queue_model_checkbox)
        self.num_workers_spinbox = QSpinBox()
        self.num_workers_spinbox.setRange(1, os.cpu_count() or 4)
        self.num_workers_spinbox.valueChanged.connect(
            lambda value: self._update_performance_setting("num_workers", value)
        )
        perf_layout.addRow("工作线程数:", self.num_workers_spinbox)
        self.use_packet_pool_checkbox = QCheckBox()
        self.use_packet_pool_checkbox.toggled.connect(
            lambda checked: self._update_performance_setting("use_packet_pool", checked)
        )
        perf_layout.addRow("使用数据包对象池:", self.use_packet_pool_checkbox)
        self.packet_pool_size_spinbox = QSpinBox()
        self.packet_pool_size_spinbox.setRange(10, 1000)
        self.packet_pool_size_spinbox.setSingleStep(10)
        self.packet_pool_size_spinbox.valueChanged.connect(
            lambda value: self._update_performance_setting("packet_pool_size", value)
        )
        perf_layout.addRow("对象池大小:", self.packet_pool_size_spinbox)
        self.skip_local_packets_checkbox = QCheckBox()
        self.skip_local_packets_checkbox.toggled.connect(
            lambda checked: self._update_performance_setting(
                "skip_local_packets", checked
            )
        )
        perf_layout.addRow("跳过本地回环包:", self.skip_local_packets_checkbox)
        self.allow_private_network_checkbox = QCheckBox()
        self.allow_private_network_checkbox.toggled.connect(
            lambda checked: self._update_performance_setting(
                "allow_private_network", checked
            )
        )
        perf_layout.addRow("允许私有网络互通:", self.allow_private_network_checkbox)
        layout.addWidget(perf_group)

        control_group = QGroupBox("高级控制设置")
        control_layout = QFormLayout(control_group)
        restart_windivert_button = QPushButton("重启WinDivert")
        restart_windivert_button.clicked.connect(self._restart_windivert)
        control_layout.addRow("WinDivert问题修复:", restart_windivert_button)
        layout.addWidget(control_group)

        apply_button = QPushButton("应用设置")
        apply_button.clicked.connect(self._apply_advanced_settings)
        layout.addWidget(apply_button)
        return widget

    def _create_log_tab(self) -> QWidget:
        """创建日志标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        self.log_table = QTableWidget()
        self.log_table.setColumnCount(8)
        self.log_table.setHorizontalHeaderLabels(
            [
                "时间",
                "源IP",
                "目标IP",
                "源端口",
                "目标端口",
                "协议",
                "动作",
                "大小(字节)",
            ]
        )
        header = self.log_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        self.log_table.setAlternatingRowColors(True)
        layout.addWidget(self.log_table)
        button_layout = QHBoxLayout()
        clear_button = QPushButton("清除显示")
        clear_button.clicked.connect(self._clear_log_table)
        button_layout.addWidget(clear_button)
        layout.addLayout(button_layout)
        return widget

    def _toggle_firewall(self):
        """切换防火墙启动/停止状态"""
        if self.firewall.is_running:
            if self.firewall.stop():
                self.start_button.setText("启动防火墙")
                self.status_label.setText("状态: 已停止")
                QMessageBox.information(self, "提示", "防火墙已停止")
        else:
            if self.firewall.start():
                self.start_button.setText("停止防火墙")
                self.status_label.setText("状态: 运行中")
                QMessageBox.information(self, "提示", "防火墙已启动")
            else:
                QMessageBox.critical(
                    self, "错误", "防火墙启动失败，请检查是否以管理员权限运行"
                )

    def _update_status(self):
        """更新状态和统计信息"""
        current_time = time.time()
        time_diff = current_time - self.last_update_time
        if time_diff < (self.update_interval / 1000):
            return
        self.last_update_time = current_time

        try:
            status = self.firewall.get_status()
            if status["running"]:
                stats = status.get("processor_stats", {})
                self.stats_label.setText(
                    f"总处理: {stats.get('total_processed', 0)} | "
                    f"拦截: {stats.get('dropped', 0)} | "
                    f"放行: {stats.get('passed', 0)}"
                )
                detailed_stats = self.firewall.get_detailed_stats()
                system_resources = detailed_stats.get("system_resources", {})
                self.resource_label.setText(
                    f"CPU: {system_resources.get('cpu_percent', 0):.1f}% | "
                    f"内存: {system_resources.get('memory_percent', 0):.1f}%"
                )
                self._update_performance_tab(stats, detailed_stats)
            else:
                self.stats_label.setText("总处理: 0 | 拦截: 0 | 放行: 0")
                self.resource_label.setText("CPU: 0% | 内存: 0%")
                self._update_performance_tab({}, {})
            self._update_rule_lists()
        except Exception as e:

            print(f"更新状态时出错: {e}")
            logger.error(f"Error in UI update status: {e}", exc_info=True)

    def _update_performance_tab(self, processor_stats, detailed_stats):
        """更新性能监控标签页"""
        try:
            self.perf_total_packets.setText(
                str(processor_stats.get("total_processed", 0))
            )
            self.perf_dropped_packets.setText(str(processor_stats.get("dropped", 0)))
            self.perf_passed_packets.setText(str(processor_stats.get("passed", 0)))
            self.perf_error_packets.setText(str(processor_stats.get("errors", 0)))
            self.perf_win_error_87.setText(
                str(processor_stats.get("win_error_87_count", 0))
            )

            pps = detailed_stats.get("packets_per_second", 0.0)
            self.perf_packets_per_second.setText(f"{pps:.2f}")

            queue_size = processor_stats.get("queue_size")
            queue_label = self.perf_queue_size.parentWidget().findChild(
                QLabel, "处理队列大小:"
            )  # Find label - might be fragile
            if queue_size is not None:
                self.perf_queue_size.setText(str(queue_size))
                self.perf_queue_size.setVisible(True)
                if queue_label:
                    queue_label.setVisible(True)
            else:
                self.perf_queue_size.setText("N/A")
                self.perf_queue_size.setVisible(False)
                if queue_label:
                    queue_label.setVisible(False)

            resources = detailed_stats.get("system_resources", {})
            self.resource_cpu.setText(f"{resources.get('cpu_percent', 0):.1f}%")
            self.resource_memory.setText(f"{resources.get('memory_percent', 0):.1f}%")

            io_counters = resources.get("io_counters", {})
            bytes_recv_kb = io_counters.get("bytes_recv", 0) / 1024
            bytes_sent_kb = io_counters.get("bytes_sent", 0) / 1024
            self.resource_network_in.setText(f"{bytes_recv_kb:.2f} KB")
            self.resource_network_out.setText(f"{bytes_sent_kb:.2f} KB")

        except Exception as e:
            logger.error(f"Error updating performance tab: {e}", exc_info=True)

    def _run_diagnosis(self):
        """获取并显示详细统计信息"""
        try:
            detailed_stats = self.firewall.get_detailed_stats()
            diag_text = "详细统计信息:\n\n"
            for key, value in detailed_stats.items():
                if isinstance(value, dict):
                    diag_text += f"{key}:\n"
                    for sub_key, sub_value in value.items():
                        if isinstance(sub_value, (int, float)):
                            diag_text += (
                                f"  {sub_key}: {sub_value:,.2f}\n"
                                if isinstance(sub_value, float)
                                else f"  {sub_key}: {sub_value:,}\n"
                            )
                        else:
                            diag_text += f"  {sub_key}: {sub_value}\n"
                else:
                    if isinstance(value, (int, float)):
                        diag_text += (
                            f"{key}: {value:,.2f}\n"
                            if isinstance(value, float)
                            else f"{key}: {value:,}\n"
                        )
                    else:
                        diag_text += f"{key}: {value}\n"
            self.diagnosis_text.setText(diag_text)
        except Exception as e:
            logger.error(f"Error getting detailed stats for UI: {e}", exc_info=True)
            self.diagnosis_text.setText(f"获取详细统计时出错: {str(e)}")

    @pyqtSlot(str)
    def _add_log_entry(self, log_message: str):
        """Slot to receive log messages via signal and add them to the table."""
        max_rows = 500
        try:
            packet_log_pattern = re.compile(
                r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})\s+-\s+([\w.]+)\s+-\s+(DEBUG|INFO|WARNING|ERROR|CRITICAL)\s+-\s+"
                r"Packet (放行|拦截):\s+"
                r"Proto=(\w+),\s+"
                r"Src=([\w.:\[\]]+):([\w*]+),\s+"
                r"Dst=([\w.:\[\]]+):([\w*]+),\s+"
                r"Size=(\d+)"
            )
            general_log_pattern = re.compile(
                r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})\s+-\s+([\w.]+)\s+-\s+(DEBUG|INFO|WARNING|ERROR|CRITICAL)\s+-\s+(.*)"
            )

            log_message = log_message.strip()
            if not log_message:
                return

            self.log_table.insertRow(0)
            packet_match = packet_log_pattern.match(log_message)

            if packet_match:
                (
                    time_str,
                    logger_name,
                    level,
                    action,
                    protocol,
                    src_ip,
                    src_port,
                    dst_ip,
                    dst_port,
                    size,
                ) = packet_match.groups()
                display_time = time_str.split(",")[0]
                self.log_table.setItem(0, 0, QTableWidgetItem(display_time))
                self.log_table.setItem(0, 1, QTableWidgetItem(src_ip))
                self.log_table.setItem(0, 2, QTableWidgetItem(dst_ip))
                self.log_table.setItem(0, 3, QTableWidgetItem(src_port))
                self.log_table.setItem(0, 4, QTableWidgetItem(dst_port))
                self.log_table.setItem(0, 5, QTableWidgetItem(protocol))
                action_item = QTableWidgetItem(action)
                action_item.setForeground(
                    QColor("red") if action == "拦截" else QColor("green")
                )
                self.log_table.setItem(0, 6, action_item)
                self.log_table.setItem(0, 7, QTableWidgetItem(size))
            else:
                general_match = general_log_pattern.match(log_message)
                if general_match:
                    time_str, logger_name, level, message = general_match.groups()
                    display_time = time_str.split(",")[0]
                    self.log_table.setItem(0, 0, QTableWidgetItem(display_time))
                    full_message = f"[{logger_name}] {message.strip()}"
                    message_item = QTableWidgetItem(full_message)
                    if level == "ERROR" or level == "CRITICAL":
                        message_item.setForeground(QColor("darkRed"))
                    elif level == "WARNING":
                        message_item.setForeground(QColor("darkOrange"))
                    self.log_table.setItem(0, 1, message_item)
                    self.log_table.setSpan(0, 1, 1, self.log_table.columnCount() - 1)
                else:
                    self.log_table.setItem(0, 0, QTableWidgetItem(log_message))
                    self.log_table.setSpan(0, 0, 1, self.log_table.columnCount())

            if self.log_table.rowCount() > max_rows:
                self.log_table.removeRow(self.log_table.rowCount() - 1)

        except Exception as e:
            print(f"Error adding log entry to UI: {e}")
            logger.error(f"Error adding log entry to UI: {e}", exc_info=True)
            try:
                self.log_table.insertRow(0)
                error_item = QTableWidgetItem(f"UI Log Error: {e}")
                error_item.setForeground(QColor("magenta"))
                self.log_table.setItem(0, 0, error_item)
                self.log_table.setSpan(0, 0, 1, self.log_table.columnCount())
                if self.log_table.rowCount() > max_rows:
                    self.log_table.removeRow(self.log_table.rowCount() - 1)
            except:
                pass

    def _restart_firewall(self):
        """重启防火墙"""
        if self.firewall.is_running:
            if not self.firewall.stop():
                QMessageBox.warning(self, "警告", "停止防火墙失败")
                return
        QApplication.processEvents()
        time.sleep(1)
        if self.firewall.start():
            self.start_button.setText("停止防火墙")
            self.status_label.setText("状态: 运行中")
            QMessageBox.information(self, "提示", "防火墙已重启")
        else:
            self.start_button.setText("启动防火墙")
            self.status_label.setText("状态: 已停止")
            QMessageBox.critical(self, "错误", "防火墙重启失败")

    def _restart_windivert(self):
        """重启WinDivert驱动"""
        if not self.firewall.is_running:
            QMessageBox.warning(self, "警告", "防火墙未运行，无法重启WinDivert")
            return
        if self.firewall.restart_windivert():
            QMessageBox.information(self, "提示", "WinDivert已重启")
        else:
            QMessageBox.critical(self, "错误", "WinDivert重启失败")

    def _load_advanced_settings(self):
        """加载高级设置并更新UI"""
        try:
            settings = self.firewall.performance_settings
            self.use_queue_model_checkbox.setChecked(
                settings.get("use_queue_model", False)
            )
            self.num_workers_spinbox.setValue(settings.get("num_workers", 2))
            self.use_packet_pool_checkbox.setChecked(
                settings.get("use_packet_pool", True)
            )
            self.packet_pool_size_spinbox.setValue(
                settings.get("packet_pool_size", 100)
            )
            self.skip_local_packets_checkbox.setChecked(
                settings.get("skip_local_packets", True)
            )
            self.allow_private_network_checkbox.setChecked(
                settings.get("allow_private_network", True)
            )
        except Exception as e:
            logger.error(f"Failed to load settings into UI: {e}", exc_info=True)
            QMessageBox.warning(self, "警告", f"加载设置失败: {str(e)}")

    def _update_performance_setting(self, key, value):
        """Slot to update a setting in the central dict when a UI control changes."""
        try:
            if key in self.firewall.performance_settings:
                self.firewall.performance_settings[key] = value
                logger.debug(f"UI updated performance_settings: {key} = {value}")
            else:
                logger.warning(f"UI tried to update unknown setting: {key}")
        except Exception as e:
            logger.error(
                f"Error updating performance setting from UI: {e}", exc_info=True
            )
            QMessageBox.warning(self, "警告", f"更新设置项 '{key}' 失败: {str(e)}")

    def _apply_advanced_settings(self):
        """应用高级设置到防火墙核心"""
        try:
            self.firewall.update_performance_settings(
                self.firewall.performance_settings
            )
            QMessageBox.information(
                self,
                "提示",
                "设置已应用。\n某些设置（如队列模型、工作线程数）可能需要重启防火墙才能完全生效。",
            )
        except Exception as e:
            logger.error(f"Failed to apply settings: {e}", exc_info=True)
            QMessageBox.critical(self, "错误", f"应用设置失败: {str(e)}")

    def _clear_log_table(self):
        """清除日志表格内容"""
        self.log_table.setRowCount(0)

    def _update_rule_lists(self):
        """更新所有规则列表UI"""
        try:
            rules = self.firewall.rule_manager.get_rules()
            self._update_list_widget(self.bl_ip_list, rules.get("ip_blacklist", set()))
            self._update_list_widget(self.wl_ip_list, rules.get("ip_whitelist", set()))
            self._update_list_widget(
                self.bl_port_list, rules.get("port_blacklist", set())
            )
            self._update_list_widget(
                self.wl_port_list, rules.get("port_whitelist", set())
            )
            self._update_list_widget(
                self.content_filter_list, rules.get("content_filters", [])
            )
        except Exception as e:
            logger.error(f"Error updating rule lists in UI: {e}", exc_info=True)

    def _update_list_widget(self, list_widget: QListWidget, items: Union[Set, List]):
        """高效地更新列表控件内容"""
        try:
            current_items_text = {
                list_widget.item(i).text() for i in range(list_widget.count())
            }
            new_items_text = {str(item) for item in items}
            items_to_add = new_items_text - current_items_text
            items_to_remove = current_items_text - new_items_text

            if items_to_remove:
                rows_to_remove = []
                for i in range(list_widget.count()):
                    try:  # Add inner try-except for item access
                        if list_widget.item(i).text() in items_to_remove:
                            rows_to_remove.append(i)
                    except AttributeError:
                        pass  # Ignore if item is None
                for i in sorted(rows_to_remove, reverse=True):
                    list_widget.takeItem(i)
            if items_to_add:
                list_widget.addItems(sorted(list(items_to_add)))
        except Exception as e:
            logger.error(
                f"Error updating list widget '{list_widget.objectName()}': {e}",
                exc_info=True,
            )

    # --- Rule Management UI Slots ---
    def _add_ip_to_blacklist(self):
        ip = self.bl_ip_input.text().strip()
        if ip:
            if self.firewall.add_ip_to_blacklist(ip):
                self.bl_ip_input.clear()
            else:
                QMessageBox.warning(self, "添加失败", f"无效的IP/CIDR或添加失败: {ip}")

    def _remove_ip_from_blacklist(self, item: QListWidgetItem):
        ip = item.text()
        if not self.firewall.remove_ip_from_blacklist(ip):
            QMessageBox.warning(self, "移除失败", f"移除IP失败: {ip}")

    def _add_ip_to_whitelist(self):
        ip = self.wl_ip_input.text().strip()
        if ip:
            if self.firewall.add_ip_to_whitelist(ip):
                self.wl_ip_input.clear()
            else:
                QMessageBox.warning(self, "添加失败", f"无效的IP/CIDR或添加失败: {ip}")

    def _remove_ip_from_whitelist(self, item: QListWidgetItem):
        ip = item.text()
        if not self.firewall.remove_ip_from_whitelist(ip):
            QMessageBox.warning(self, "移除失败", f"移除IP失败: {ip}")

    def _add_port_to_blacklist(self):
        port_str = self.bl_port_input.text().strip()
        if port_str:
            if self.firewall.add_port_to_blacklist(port_str):
                self.bl_port_input.clear()
            else:
                QMessageBox.warning(
                    self,
                    "添加失败",
                    f"添加端口/范围失败: '{port_str}'. 请输入有效端口 (0-65535) 或范围 (e.g., 8000-8080)。",
                )

    def _remove_port_from_blacklist(self, item: QListWidgetItem):
        port_str = item.text()
        if not self.firewall.remove_port_from_blacklist(port_str):
            QMessageBox.warning(self, "移除失败", f"移除端口/范围失败: {port_str}")

    def _add_port_to_whitelist(self):
        port_str = self.wl_port_input.text().strip()
        if port_str:
            if self.firewall.add_port_to_whitelist(port_str):
                self.wl_port_input.clear()
            else:
                QMessageBox.warning(
                    self,
                    "添加失败",
                    f"添加端口/范围失败: '{port_str}'. 请输入有效端口 (0-65535) 或范围 (e.g., 10000-11000)。",
                )

    def _remove_port_from_whitelist(self, item: QListWidgetItem):
        port_str = item.text()
        if not self.firewall.remove_port_from_whitelist(port_str):
            QMessageBox.warning(self, "移除失败", f"移除端口/范围失败: {port_str}")

    def _add_content_filter(self):
        pattern = self.content_filter_input.text().strip()
        if pattern:
            if self.firewall.add_content_filter(pattern):
                self.content_filter_input.clear()
            else:
                QMessageBox.warning(
                    self,
                    "添加失败",
                    f"添加内容过滤规则失败 (可能是无效的正则表达式): {pattern}",
                )

    def _remove_content_filter(self, item: QListWidgetItem):
        pattern = item.text()
        if not self.firewall.remove_content_filter(pattern):
            QMessageBox.warning(self, "移除失败", f"移除内容过滤规则失败: {pattern}")

    # --- Import/Export UI Slots ---
    def _import_ip_list(self, list_type: str):
        if list_type not in ["blacklist", "whitelist"]:
            return
        filename, _ = QFileDialog.getOpenFileName(
            self,
            f"导入IP {list_type.capitalize()}",
            "",
            "文本文件 (*.txt);;所有文件 (*)",
        )
        if filename:
            try:
                success, imported_count, invalid_count = (
                    self.firewall.rule_manager.import_ip_list(list_type, filename)
                )
                if success:
                    message = f"成功从 {os.path.basename(filename)} 导入 {imported_count} 个IP/CIDR 到 {list_type}。"
                    if invalid_count > 0:
                        message += f"\n发现并忽略了 {invalid_count} 个无效条目。"
                    QMessageBox.information(self, "导入成功", message)
                    self._update_rule_lists()
                else:
                    QMessageBox.critical(
                        self,
                        "导入失败",
                        "从文件导入IP列表时发生错误。请检查日志获取详细信息。",
                    )
            except Exception as e:
                logger.error(
                    f"Error during IP list import UI action: {e}", exc_info=True
                )
                QMessageBox.critical(self, "导入错误", f"导入过程中发生意外错误: {e}")

    def _export_ip_list(self, list_type: str):
        if list_type not in ["blacklist", "whitelist"]:
            return
        default_filename = f"ip_{list_type}.txt"
        filename, _ = QFileDialog.getSaveFileName(
            self,
            f"导出IP {list_type.capitalize()}",
            default_filename,
            "文本文件 (*.txt);;所有文件 (*)",
        )
        if filename:
            try:
                success = self.firewall.rule_manager.export_ip_list(list_type, filename)
                if success:
                    QMessageBox.information(
                        self, "导出成功", f"IP {list_type} 已成功导出到\n{filename}"
                    )
                else:
                    QMessageBox.critical(
                        self,
                        "导出失败",
                        "导出IP列表到文件时发生错误。请检查日志获取详细信息。",
                    )
            except Exception as e:
                logger.error(
                    f"Error during IP list export UI action: {e}", exc_info=True
                )
                QMessageBox.critical(self, "导出错误", f"导出过程中发生意外错误: {e}")

    def closeEvent(self, event):
        """窗口关闭事件"""
        logger.info("Close event received. Stopping firewall...")
        if self.firewall.is_running:
            self.firewall.stop()
        self.update_timer.stop()
        logger.info("UI Timer stopped.")
        event.accept()
        logger.info("Exiting application.")
        QApplication.quit()
