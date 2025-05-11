#!/usr/bin/env python
# -*- coding: utf-8 -*-

from typing import Dict
import logging

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QLabel, QPushButton, QCheckBox, QGroupBox, QSpinBox,
    QHeaderView
)
from PyQt6.QtCore import pyqtSignal
from PyQt6.QtGui import QColor, QBrush

# Import config
from ...config import CONFIG

logger = logging.getLogger('TrafficMonitorTab')

class TrafficMonitorTab(QWidget):
    """流量监控标签页，用于实时显示防火墙输入输出流量"""
    
    # 信号定义
    clear_traffic_requested = pyqtSignal()
    pause_monitoring_toggled = pyqtSignal(bool)
    traffic_table_refreshed_signal = pyqtSignal()
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.paused = False
        # Read max_rows from config
        try:
            # Assuming a similar structure as LogTab, maybe ui.traffic_max_rows
            # Let's use the same key as LogTab for now, or add a new one to config if needed.
            self.max_rows = int(CONFIG['ui'].get('log_max_rows', 100)) # Default to 100 if not found
        except (ValueError, TypeError):
            logger.warning("Invalid max_rows in config for traffic monitor, using default 100.")
            self.max_rows = 100
            
        self.filtered_protocols = set()  # 用于过滤特定协议
        self.packet_history = []  # 存储所有接收到的数据包信息 (用于过滤重建)
        self.stats_counters = { # 用于增量统计
            "total": 0, "inbound": 0, "outbound": 0,
            "tcp": 0, "udp": 0, "icmp": 0, "dropped": 0
        }
        
        # 创建UI组件
        self._create_ui()
        
    def _create_ui(self):
        """创建UI组件"""
        main_layout = QVBoxLayout(self)
        
        # 控制面板
        control_panel = QGroupBox("流量监控控制")
        control_layout = QHBoxLayout(control_panel)
        
        # 协议过滤
        filter_group = QGroupBox("协议过滤")
        filter_layout = QHBoxLayout(filter_group)
        self.tcp_checkbox = QCheckBox("TCP")
        self.tcp_checkbox.setChecked(True)
        self.tcp_checkbox.toggled.connect(self._update_protocol_filter)
        self.udp_checkbox = QCheckBox("UDP")
        self.udp_checkbox.setChecked(True)
        self.udp_checkbox.toggled.connect(self._update_protocol_filter)
        self.icmp_checkbox = QCheckBox("ICMP") # Keep ICMP checkbox for future
        self.icmp_checkbox.setChecked(True)
        self.icmp_checkbox.toggled.connect(self._update_protocol_filter)
        filter_layout.addWidget(self.tcp_checkbox)
        filter_layout.addWidget(self.udp_checkbox)
        filter_layout.addWidget(self.icmp_checkbox)
        control_layout.addWidget(filter_group)
        
        # 方向过滤
        direction_group = QGroupBox("方向过滤")
        direction_layout = QHBoxLayout(direction_group)
        self.inbound_checkbox = QCheckBox("入站")
        self.inbound_checkbox.setChecked(True)
        self.inbound_checkbox.toggled.connect(self._update_direction_filter)
        self.outbound_checkbox = QCheckBox("出站")
        self.outbound_checkbox.setChecked(True)
        self.outbound_checkbox.toggled.connect(self._update_direction_filter)
        direction_layout.addWidget(self.inbound_checkbox)
        direction_layout.addWidget(self.outbound_checkbox)
        control_layout.addWidget(direction_group)
        
        # 刷新速率 (Keep UI element, but functionality moved from MainWindow)
        refresh_group = QGroupBox("刷新速率(ms)")
        refresh_layout = QHBoxLayout(refresh_group)
        self.refresh_rate = QSpinBox()
        self.refresh_rate.setRange(500, 5000)
        self.refresh_rate.setSingleStep(100)
        self.refresh_rate.setValue(1000)
        self.refresh_rate.valueChanged.connect(self._update_refresh_rate)
        refresh_layout.addWidget(self.refresh_rate)
        control_layout.addWidget(refresh_group)
        
        # 控制按钮
        button_group = QGroupBox("操作")
        button_layout = QHBoxLayout(button_group)
        self.pause_button = QPushButton("暂停")
        self.pause_button.setCheckable(True)
        self.pause_button.toggled.connect(self._toggle_pause)
        self.clear_button = QPushButton("清除")
        self.clear_button.clicked.connect(self._clear_traffic)
        button_layout.addWidget(self.pause_button)
        button_layout.addWidget(self.clear_button)
        control_layout.addWidget(button_group)
        
        main_layout.addWidget(control_panel)
        
        # 统计摘要
        stats_group = QGroupBox("流量统计")
        stats_layout = QHBoxLayout(stats_group)
        self.total_packets_label = QLabel("总数据包: 0")
        self.inbound_packets_label = QLabel("入站包: 0")
        self.outbound_packets_label = QLabel("出站包: 0")
        self.tcp_packets_label = QLabel("TCP包: 0")
        self.udp_packets_label = QLabel("UDP包: 0")
        self.dropped_packets_label = QLabel("已拦截: 0")
        stats_layout.addWidget(self.total_packets_label)
        stats_layout.addWidget(self.inbound_packets_label)
        stats_layout.addWidget(self.outbound_packets_label)
        stats_layout.addWidget(self.tcp_packets_label)
        stats_layout.addWidget(self.udp_packets_label)
        stats_layout.addWidget(self.dropped_packets_label)
        main_layout.addWidget(stats_group)
        
        # 数据包表格
        self.traffic_table = QTableWidget()
        self.traffic_table.setColumnCount(8)
        self.traffic_table.setHorizontalHeaderLabels(["时间", "方向", "协议", "源地址", "源端口", "目标地址", "目标端口", "状态"])
        self.traffic_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents) # Resize based on content initially
        self.traffic_table.horizontalHeader().setStretchLastSection(False) # Don't stretch last section initially
        # Allow interactive resize
        self.traffic_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        # Set specific columns to stretch
        self.traffic_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch) # Source Address
        self.traffic_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch) # Dest Address
        self.traffic_table.setAlternatingRowColors(True)
        self.traffic_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers) # Read-only
        self.traffic_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows) # Select whole rows

        main_layout.addWidget(self.traffic_table)
        
        # 初始化方向和协议过滤
        self.direction_filter = {"inbound": True, "outbound": True}
        self._update_protocol_filter()

    def _update_protocol_filter(self):
        """更新协议过滤设置"""
        self.protocol_filter = {
            "tcp": self.tcp_checkbox.isChecked(),
            "udp": self.udp_checkbox.isChecked(),
            "icmp": self.icmp_checkbox.isChecked()
        }
        self._refresh_table()
        
    def _update_direction_filter(self):
        """更新方向过滤设置"""
        self.direction_filter = {
            "inbound": self.inbound_checkbox.isChecked(),
            "outbound": self.outbound_checkbox.isChecked()
        }
        self._refresh_table()
        
    def _update_refresh_rate(self, value):
        """更新刷新速率"""
        pass  # 此方法会在MainWindow中连接到定时器更新
        
    def _toggle_pause(self, paused):
        """切换暂停/恢复状态"""
        self.paused = paused
        self.pause_button.setText("恢复" if paused else "暂停")
        self.pause_monitoring_toggled.emit(paused)
        
    def _clear_traffic(self):
        """清除流量记录"""
        self.packet_history = []
        self.traffic_table.setRowCount(0)
        self._reset_stats_counters() # Reset counters
        self._update_stats_labels() # Update labels to 0
        self.clear_traffic_requested.emit() # Emit signal if needed elsewhere
        
    def _reset_stats_counters(self):
        """重置内部统计计数器"""
        self.stats_counters = {
            "total": 0, "inbound": 0, "outbound": 0,
            "tcp": 0, "udp": 0, "icmp": 0, "dropped": 0
        }
        
    def _update_stats_labels(self):
        """使用内部计数器更新统计标签"""
        self.total_packets_label.setText(f"总数据包: {self.stats_counters['total']}")
        self.inbound_packets_label.setText(f"入站包: {self.stats_counters['inbound']}")
        self.outbound_packets_label.setText(f"出站包: {self.stats_counters['outbound']}")
        self.tcp_packets_label.setText(f"TCP包: {self.stats_counters['tcp']}")
        self.udp_packets_label.setText(f"UDP包: {self.stats_counters['udp']}")
        # self.icmp_packets_label.setText(f"ICMP包: {self.stats_counters['icmp']}") # Add if ICMP label exists
        self.dropped_packets_label.setText(f"已拦截: {self.stats_counters['dropped']}")

    def add_packet(self, packet_info: Dict):
        """添加一个数据包到监控列表并更新UI（优化版）
        
        Args:
            packet_info: 包含数据包信息的字典
        """
        if self.paused:
            return
            
        # 1. 添加到历史记录 (仍然需要完整历史用于过滤)
        self.packet_history.append(packet_info)
        # Limit history size reasonably (e.g., 2-5 times max_rows) to avoid memory issues
        history_limit = self.max_rows * 3 
        if len(self.packet_history) > history_limit:
            self.packet_history = self.packet_history[-history_limit:]
            
        # 2. 增量更新统计计数器
        self.stats_counters["total"] += 1
        direction = packet_info.get("direction", "").lower()
        protocol = packet_info.get("protocol", "").lower()
        action = packet_info.get("action", "")

        if direction == "入站": self.stats_counters["inbound"] += 1
        elif direction == "出站": self.stats_counters["outbound"] += 1
        
        if protocol == "tcp": self.stats_counters["tcp"] += 1
        elif protocol == "udp": self.stats_counters["udp"] += 1
        elif protocol == "icmp": self.stats_counters["icmp"] += 1 # Assuming ICMP might be added

        if action == "拦截": self.stats_counters["dropped"] += 1
        
        # 3. 更新统计标签
        self._update_stats_labels()

        # 4. 检查当前过滤器是否允许显示此数据包
        if not self.protocol_filter.get(protocol, True): # Default to True if protocol not in filter (e.g., ICMP initially)
            return
        if not self.direction_filter.get(direction, True): # Default to True if direction unknown
             return

        # 5. 如果过滤器通过，则添加到表格末尾
        row_position = self.traffic_table.rowCount()
        self.traffic_table.insertRow(row_position)
        self._populate_row(row_position, packet_info) # Use helper function

        # 6. 检查并移除超出限制的行 (从顶部移除)
        if self.traffic_table.rowCount() > self.max_rows:
            self.traffic_table.removeRow(0)

        # 7. 滚动到最新行
        self.traffic_table.scrollToBottom()

    def _populate_row(self, row: int, packet: Dict):
        """填充表格的指定行"""
        # 设置时间
        time_item = QTableWidgetItem(packet.get("time", ""))
        self.traffic_table.setItem(row, 0, time_item)
        
        # 设置方向
        direction = packet.get("direction", "")
        direction_item = QTableWidgetItem(direction)
        self.traffic_table.setItem(row, 1, direction_item)
        
        # 设置协议
        protocol_item = QTableWidgetItem(packet.get("protocol", ""))
        self.traffic_table.setItem(row, 2, protocol_item)
        
        # 设置源地址和端口
        src_addr_item = QTableWidgetItem(packet.get("src_addr", ""))
        self.traffic_table.setItem(row, 3, src_addr_item)
        src_port_item = QTableWidgetItem(str(packet.get("src_port", "")))
        self.traffic_table.setItem(row, 4, src_port_item)
        
        # 设置目标地址和端口
        dst_addr_item = QTableWidgetItem(packet.get("dst_addr", ""))
        self.traffic_table.setItem(row, 5, dst_addr_item)
        dst_port_item = QTableWidgetItem(str(packet.get("dst_port", "")))
        self.traffic_table.setItem(row, 6, dst_port_item)
        
        # 设置状态(通过/拦截)
        status = packet.get("action", "未知")
        status_item = QTableWidgetItem(status)
        
        # 根据状态设置颜色
        if status == "拦截":
            status_item.setBackground(QBrush(QColor(255, 200, 200)))  # 浅红色
        elif status == "放行":
            status_item.setBackground(QBrush(QColor(200, 255, 200)))  # 浅绿色
            
        self.traffic_table.setItem(row, 7, status_item)

    def _refresh_table(self):
        """根据过滤条件完全重建表格内容 (仅在过滤器更改时调用)"""
        self.traffic_table.setRowCount(0) # Clear table first
        
        # Filter and display
        self.traffic_table.setRowCount(0) # Clear existing rows
        
        # Determine which packets to show based on filters
        packets_to_display = []
        for packet in reversed(self.packet_history): # Show newest first
            if len(packets_to_display) >= self.max_rows: 
                break # Limit displayed rows for performance
            
            proto = packet.get("protocol", "").lower()
            direction = packet.get("direction", "").lower()
            
            # Protocol filter
            if not self.protocol_filter.get(proto, True):
                continue
            
            # Direction filter
            if (direction == "入站" and not self.direction_filter["inbound"]) or \
               (direction == "出站" and not self.direction_filter["outbound"]):
                continue
                
            packets_to_display.append(packet)

        # Populate table with filtered packets
        self.traffic_table.setRowCount(len(packets_to_display))
        for i, packet_data in enumerate(packets_to_display):
            self._populate_row(i, packet_data)
            
        self._update_stats_labels() # Update stats based on full history
        self.traffic_table_refreshed_signal.emit() # Emit signal
