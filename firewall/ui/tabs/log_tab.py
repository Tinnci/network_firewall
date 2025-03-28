#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import logging # Added for logger

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget, 
    QTableWidgetItem, QHeaderView, QAbstractItemView
)
from PyQt6.QtCore import pyqtSlot
from PyQt6.QtGui import QColor

# Import config
from ...config import CONFIG

# Get logger for this tab
logger = logging.getLogger('LogTabUI')

# Column Constants
COL_TIME = 0
COL_SRC_IP = 1
COL_DST_IP = 2
COL_SRC_PORT = 3
COL_DST_PORT = 4
COL_PROTOCOL = 5
COL_ACTION = 6
COL_SIZE = 7

class LogTab(QWidget):
    """日志标签页的UI和更新逻辑"""
    # No signals needed from this tab currently, clear is handled internally

    def __init__(self, parent=None):
        super().__init__(parent)
        # Read max rows from config
        try:
            self.max_rows = int(CONFIG['ui'].get('log_max_rows', 500))
        except (ValueError, TypeError):
            logger.warning("Invalid log_max_rows in config, using default 500.")
            self.max_rows = 500
            
        self._create_ui()

    def _create_ui(self):
        """创建此标签页的UI组件"""
        layout = QVBoxLayout(self)
        
        # --- Log Table ---
        self.log_table = QTableWidget()
        self.log_table.setColumnCount(8) # Keep 8 columns
        self.log_table.setHorizontalHeaderLabels([
            "时间", "源IP", "目标IP", "源端口", "目标端口", 
            "协议", "动作", "大小(字节)"
        ])
        header = self.log_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive) # Allow user resize
        header.setStretchLastSection(True) # Stretch last column
        self.log_table.setAlternatingRowColors(True)
        self.log_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers) # Make read-only
        self.log_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows) # Select whole rows
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
    # Changed slot to accept dict instead of str
    @pyqtSlot(dict) 
    def add_log_entry(self, log_entry: dict):
        """Slot to receive structured log data via signal and add it to the table."""
        try:
            # Determine log type from the received dictionary
            log_type = log_entry.get('log_type', 'general')
            packet_info = log_entry.get('packet_info') # May be None
            
            # Insert row at the bottom for better performance
            current_row_count = self.log_table.rowCount()
            self.log_table.insertRow(current_row_count) 

            if log_type == 'packet' and packet_info:
                # Extract data from packet_info dictionary
                display_time = log_entry.get('timestamp', '').split(',')[0] # Use timestamp from log_entry
                action = packet_info.get('action', '未知') # Assuming action is added to packet_info
                protocol = packet_info.get('protocol', 'N/A')
                src_ip = packet_info.get('src_addr', 'N/A')
                src_port = str(packet_info.get('src_port', 'N/A'))
                dst_ip = packet_info.get('dst_addr', 'N/A')
                dst_port = str(packet_info.get('dst_port', 'N/A'))
                size = str(packet_info.get('payload_size', 'N/A'))

                self.log_table.setItem(current_row_count, COL_TIME, QTableWidgetItem(display_time))
                self.log_table.setItem(current_row_count, COL_SRC_IP, QTableWidgetItem(src_ip))
                self.log_table.setItem(current_row_count, COL_DST_IP, QTableWidgetItem(dst_ip))
                self.log_table.setItem(current_row_count, COL_SRC_PORT, QTableWidgetItem(src_port))
                self.log_table.setItem(current_row_count, COL_DST_PORT, QTableWidgetItem(dst_port))
                self.log_table.setItem(current_row_count, COL_PROTOCOL, QTableWidgetItem(protocol))
                
                action_item = QTableWidgetItem(action)
                # Color based on action (assuming '拦截' and '放行')
                if action == '拦截': action_item.setForeground(QColor('red'))
                elif action == '放行': action_item.setForeground(QColor('green'))
                self.log_table.setItem(current_row_count, COL_ACTION, action_item)
                
                self.log_table.setItem(current_row_count, COL_SIZE, QTableWidgetItem(size))
            
            else: # General log or fallback
                display_time = log_entry.get('timestamp', '').split(',')[0]
                level = log_entry.get('levelname', 'INFO')
                logger_name = log_entry.get('name', 'Unknown')
                message = log_entry.get('message', log_entry.get('formatted_message', 'Invalid log entry')) # Use raw message or formatted as fallback

                self.log_table.setItem(current_row_count, COL_TIME, QTableWidgetItem(display_time))
                
                full_message = f"[{logger_name}] {message.strip()}" 
                message_item = QTableWidgetItem(full_message) 
                
                # Set color based on level
                if level == "ERROR" or level == "CRITICAL": message_item.setForeground(QColor('darkRed'))
                elif level == "WARNING": message_item.setForeground(QColor('darkOrange')) 
                
                self.log_table.setItem(current_row_count, COL_SRC_IP, message_item) # Put message in first data column
                # Span the message across remaining columns
                self.log_table.setSpan(current_row_count, COL_SRC_IP, 1, self.log_table.columnCount() - 1) 

            # Limit table rows - remove from the top if limit exceeded
            if self.log_table.rowCount() > self.max_rows:
                self.log_table.removeRow(0) # Remove the oldest entry (top row)

            # Scroll to the bottom to show the latest entry
            self.log_table.scrollToBottom()

        except Exception as e:
            # Avoid crashing the UI due to logging errors
            logger.error(f"Error adding log entry to LogTab UI: {e}", exc_info=True)
            # Optionally add a simple error message to the table itself
            try:
                current_row_count = self.log_table.rowCount()
                self.log_table.insertRow(current_row_count)
                error_item = QTableWidgetItem(f"UI Log Error: {e}")
                error_item.setForeground(QColor('magenta'))
                self.log_table.setItem(current_row_count, COL_TIME, error_item)
                self.log_table.setSpan(current_row_count, COL_TIME, 1, self.log_table.columnCount())
                if self.log_table.rowCount() > self.max_rows:
                    self.log_table.removeRow(0) # Remove oldest if limit exceeded
                self.log_table.scrollToBottom()
            except Exception as inner_e: 
                logger.error(f"Failed to add error message to log table: {inner_e}")


    # --- DEPRECATED: Old parsing logic (kept for reference, but not used) ---
    def _add_log_entry_from_string(self, log_message: str):
        """DEPRECATED: Parses string log messages."""
        try:
            # Regex patterns (copied from old version)
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

            # Insert row at the bottom
            current_row_count = self.log_table.rowCount()
            self.log_table.insertRow(current_row_count)
            
            packet_match = packet_log_pattern.match(log_message)
            
            if packet_match:
                (time_str, logger_name, level, action, protocol, 
                 src_ip, src_port, dst_ip, dst_port, size) = packet_match.groups()
                display_time = time_str.split(',')[0] 
                self.log_table.setItem(current_row_count, COL_TIME, QTableWidgetItem(display_time))
                self.log_table.setItem(current_row_count, COL_SRC_IP, QTableWidgetItem(src_ip))
                self.log_table.setItem(current_row_count, COL_DST_IP, QTableWidgetItem(dst_ip))
                self.log_table.setItem(current_row_count, COL_SRC_PORT, QTableWidgetItem(src_port))
                self.log_table.setItem(current_row_count, COL_DST_PORT, QTableWidgetItem(dst_port))
                self.log_table.setItem(current_row_count, COL_PROTOCOL, QTableWidgetItem(protocol))
                action_item = QTableWidgetItem(action)
                action_item.setForeground(QColor('red') if action == '拦截' else QColor('green'))
                self.log_table.setItem(current_row_count, COL_ACTION, action_item)
                self.log_table.setItem(current_row_count, COL_SIZE, QTableWidgetItem(size))
            else:
                general_match = general_log_pattern.match(log_message) 
                if general_match:
                     time_str, logger_name, level, message = general_match.groups()
                     display_time = time_str.split(',')[0]
                     self.log_table.setItem(current_row_count, COL_TIME, QTableWidgetItem(display_time))
                     full_message = f"[{logger_name}] {message.strip()}" 
                     message_item = QTableWidgetItem(full_message) 
                     if level == "ERROR" or level == "CRITICAL": message_item.setForeground(QColor('darkRed'))
                     elif level == "WARNING": message_item.setForeground(QColor('darkOrange')) 
                     self.log_table.setItem(current_row_count, COL_SRC_IP, message_item)
                     self.log_table.setSpan(current_row_count, COL_SRC_IP, 1, self.log_table.columnCount() - 1) 
                else:
                     # Fallback for unparseable lines
                     self.log_table.setItem(current_row_count, COL_TIME, QTableWidgetItem(log_message))
                     self.log_table.setSpan(current_row_count, COL_TIME, 1, self.log_table.columnCount())

            # Limit table rows - remove from top
            if self.log_table.rowCount() > self.max_rows:
                self.log_table.removeRow(0)

            # Scroll to bottom
            self.log_table.scrollToBottom()

        except Exception as e:
            logger.error(f"Error adding log entry (string) to LogTab UI: {e}", exc_info=True)
            # Fallback error display
            try:
                current_row_count = self.log_table.rowCount()
                self.log_table.insertRow(current_row_count)
                error_item = QTableWidgetItem(f"UI Log Error (str): {e}")
                error_item.setForeground(QColor('magenta'))
                self.log_table.setItem(current_row_count, COL_TIME, error_item)
                self.log_table.setSpan(current_row_count, COL_TIME, 1, self.log_table.columnCount())
                if self.log_table.rowCount() > self.max_rows:
                    self.log_table.removeRow(0)
                self.log_table.scrollToBottom()
            except: pass

    # --- Public Method for Clearing Table ---
    def clear_log_table(self): 
        """清除日志表格内容"""
        self.log_table.setRowCount(0)
        # Optionally show a message box, but might be better handled by main window if needed
        # QMessageBox.information(self, "日志清除", "日志显示已清除。")
