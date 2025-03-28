#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget, 
    QTableWidgetItem, QHeaderView
)
from PyQt6.QtCore import pyqtSlot
from PyQt6.QtGui import QColor

class LogTab(QWidget):
    """日志标签页的UI和更新逻辑"""
    # No signals needed from this tab currently, clear is handled internally

    def __init__(self, parent=None):
        super().__init__(parent)
        self._create_ui()

    def _create_ui(self):
        """创建此标签页的UI组件"""
        layout = QVBoxLayout(self)
        
        # --- Log Table ---
        self.log_table = QTableWidget()
        self.log_table.setColumnCount(8) 
        self.log_table.setHorizontalHeaderLabels([
            "时间", "源IP", "目标IP", "源端口", "目标端口", 
            "协议", "动作", "大小(字节)"
        ])
        header = self.log_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True) 
        self.log_table.setAlternatingRowColors(True) 
        layout.addWidget(self.log_table)
        
        # --- Control Buttons ---
        button_layout = QHBoxLayout()
        clear_button = QPushButton("清除显示") 
        clear_button.clicked.connect(self.clear_log_table) # Connect to internal method
        button_layout.addWidget(clear_button)
        # Add stretch to push button to the left or add spacer
        button_layout.addStretch(1) 
        layout.addLayout(button_layout)

    # --- Public Slot for Adding Log Entries ---
    @pyqtSlot(str) 
    def add_log_entry(self, log_message: str):
        """Slot to receive log messages via signal and add them to the table."""
        max_rows = 500 # Limit table rows for performance
        try:
            # Regex patterns (copied from MainWindow)
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
            if not log_message: return

            self.log_table.insertRow(0)
            packet_match = packet_log_pattern.match(log_message)
            
            if packet_match:
                (time_str, logger_name, level, action, protocol, 
                 src_ip, src_port, dst_ip, dst_port, size) = packet_match.groups()
                display_time = time_str.split(',')[0] 
                self.log_table.setItem(0, 0, QTableWidgetItem(display_time))
                self.log_table.setItem(0, 1, QTableWidgetItem(src_ip))
                self.log_table.setItem(0, 2, QTableWidgetItem(dst_ip))
                self.log_table.setItem(0, 3, QTableWidgetItem(src_port))
                self.log_table.setItem(0, 4, QTableWidgetItem(dst_port))
                self.log_table.setItem(0, 5, QTableWidgetItem(protocol))
                action_item = QTableWidgetItem(action)
                action_item.setForeground(QColor('red') if action == '拦截' else QColor('green'))
                self.log_table.setItem(0, 6, action_item)
                self.log_table.setItem(0, 7, QTableWidgetItem(size))
            else:
                general_match = general_log_pattern.match(log_message) 
                if general_match:
                     time_str, logger_name, level, message = general_match.groups()
                     display_time = time_str.split(',')[0]
                     self.log_table.setItem(0, 0, QTableWidgetItem(display_time))
                     full_message = f"[{logger_name}] {message.strip()}" 
                     message_item = QTableWidgetItem(full_message) 
                     if level == "ERROR" or level == "CRITICAL": message_item.setForeground(QColor('darkRed'))
                     elif level == "WARNING": message_item.setForeground(QColor('darkOrange')) 
                     self.log_table.setItem(0, 1, message_item)
                     self.log_table.setSpan(0, 1, 1, self.log_table.columnCount() - 1) 
                else:
                     # Fallback for unparseable lines
                     self.log_table.setItem(0, 0, QTableWidgetItem(log_message))
                     self.log_table.setSpan(0, 0, 1, self.log_table.columnCount())

            # Limit table rows
            if self.log_table.rowCount() > max_rows:
                self.log_table.removeRow(self.log_table.rowCount() - 1)

        except Exception as e:
            # Avoid crashing the UI due to logging errors
            print(f"Error adding log entry to LogTab UI: {e}")
            # Optionally add a simple error message to the table itself
            try:
                self.log_table.insertRow(0)
                error_item = QTableWidgetItem(f"UI Log Error: {e}")
                error_item.setForeground(QColor('magenta'))
                self.log_table.setItem(0, 0, error_item)
                self.log_table.setSpan(0, 0, 1, self.log_table.columnCount())
                if self.log_table.rowCount() > max_rows:
                    self.log_table.removeRow(self.log_table.rowCount() - 1)
            except: pass # Nested try-except

    # --- Public Method for Clearing Table ---
    def clear_log_table(self): 
        """清除日志表格内容"""
        self.log_table.setRowCount(0)
        # Optionally show a message box, but might be better handled by main window if needed
        # QMessageBox.information(self, "日志清除", "日志显示已清除。")
