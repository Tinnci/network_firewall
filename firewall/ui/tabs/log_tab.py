#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import logging # Added for logger
import csv # Added for CSV export

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget, 
    QTableWidgetItem, QHeaderView, QAbstractItemView, QLabel, QLineEdit, QComboBox,
    QFileDialog, QMessageBox # Added QFileDialog and QMessageBox
)
from PyQt6.QtCore import pyqtSlot, pyqtSignal
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
COL_DETAILS = 8

class LogTab(QWidget):
    """日志标签页的UI和更新逻辑"""
    log_entry_added_signal = pyqtSignal(dict) # New signal

    def __init__(self, parent=None):
        super().__init__(parent)
        self.all_log_entries_buffer = []  # Buffer to store all log entry dicts
        self.current_filters = {}       # Dictionary to store active filter values
        # Read max rows from config
        try:
            self.max_rows = int(CONFIG['ui'].get('log_max_rows', 500))
        except (ValueError, TypeError):
            logger.warning("Invalid log_max_rows in config, using default 500.")
            self.max_rows = 500
            
        self._create_ui()
        self._init_filters() # Initialize filter data model
        self._apply_current_filters_to_ui_controls() # Sync UI with data model
        self._populate_table_from_buffer() # Initial population based on default filters

    def _init_filters(self):
        """Initialize and store default/empty filter values in the data model."""
        self.current_filters = {
            'src_ip': '',
            'dst_ip': '',
            'src_port': '',
            'dst_port': '',
            'protocol': 'All',
            'action': '拦截'  # Default action filter to '拦截'
        }

    def _apply_current_filters_to_ui_controls(self):
        """Set UI filter controls to match values in self.current_filters."""
        self.src_ip_filter.setText(self.current_filters.get('src_ip', ''))
        self.dst_ip_filter.setText(self.current_filters.get('dst_ip', ''))
        self.src_port_filter.setText(self.current_filters.get('src_port', ''))
        self.dst_port_filter.setText(self.current_filters.get('dst_port', ''))
        self.protocol_filter_combo.setCurrentText(self.current_filters.get('protocol', 'All'))
        self.action_filter_combo.setCurrentText(self.current_filters.get('action', 'All'))

    def _read_ui_controls_to_current_filters(self):
        """Update self.current_filters based on the current state of UI controls."""
        self.current_filters['src_ip'] = self.src_ip_filter.text().strip()
        self.current_filters['dst_ip'] = self.dst_ip_filter.text().strip()
        self.current_filters['src_port'] = self.src_port_filter.text().strip()
        self.current_filters['dst_port'] = self.dst_port_filter.text().strip()
        self.current_filters['protocol'] = self.protocol_filter_combo.currentText()
        self.current_filters['action'] = self.action_filter_combo.currentText()

    def _create_ui(self):
        """创建此标签页的UI组件"""
        main_layout = QVBoxLayout(self)

        # --- Filter Controls --- 
        filter_group_layout = QHBoxLayout()

        self.src_ip_filter = QLineEdit(); self.src_ip_filter.setPlaceholderText("源IP")
        self.dst_ip_filter = QLineEdit(); self.dst_ip_filter.setPlaceholderText("目标IP")
        self.src_port_filter = QLineEdit(); self.src_port_filter.setPlaceholderText("源端口")
        self.dst_port_filter = QLineEdit(); self.dst_port_filter.setPlaceholderText("目标端口")

        self.protocol_filter_combo = QComboBox()
        self.protocol_filter_combo.addItems(["All", "TCP", "UDP", "ICMP", "Other"])
        self.action_filter_combo = QComboBox()
        self.action_filter_combo.addItems(["All", "拦截", "放行", "未知"])

        filter_group_layout.addWidget(QLabel("过滤:"))
        filter_group_layout.addWidget(self.src_ip_filter)
        filter_group_layout.addWidget(self.dst_ip_filter)
        filter_group_layout.addWidget(self.src_port_filter)
        filter_group_layout.addWidget(self.dst_port_filter)
        filter_group_layout.addWidget(self.protocol_filter_combo)
        filter_group_layout.addWidget(self.action_filter_combo)
        
        apply_button = QPushButton("应用过滤器")
        apply_button.clicked.connect(self._on_apply_filters_clicked)
        reset_button = QPushButton("重置过滤器")
        reset_button.clicked.connect(self._on_reset_filters_clicked)
        filter_group_layout.addWidget(apply_button)
        filter_group_layout.addWidget(reset_button)
        filter_group_layout.addStretch(1)

        main_layout.addLayout(filter_group_layout)
        
        # --- Log Table ---
        self.log_table = QTableWidget()
        self.log_table.setColumnCount(9) # Updated from 8 to 9
        self.log_table.setHorizontalHeaderLabels([
            "时间", "源IP", "目标IP", "源端口", "目标端口", 
            "协议", "动作", "大小(字节)", "详情/原因" # Added "详情/原因"
        ])
        header = self.log_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive) # Allow user resize
        header.setStretchLastSection(True) # Stretch last column
        self.log_table.setAlternatingRowColors(True)
        self.log_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers) # Make read-only
        self.log_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows) # Select whole rows
        main_layout.addWidget(self.log_table)
        
        # --- Control Buttons ---
        bottom_button_layout = QHBoxLayout()
        clear_button = QPushButton("清除显示和日志") 
        clear_button.clicked.connect(self.clear_log_display_and_buffer) # Connect to internal method
        bottom_button_layout.addWidget(clear_button)

        export_csv_button = QPushButton("导出过滤后日志 (CSV)") # New Button
        export_csv_button.clicked.connect(self._export_filtered_logs_to_csv) # Connect to new method
        bottom_button_layout.addWidget(export_csv_button) # Add to layout

        # Add stretch to push button to the left or add spacer
        bottom_button_layout.addStretch(1) 
        main_layout.addLayout(bottom_button_layout)

    def _on_apply_filters_clicked(self):
        # Logic to read filter values from UI and store them
        # Then call _populate_table_from_buffer
        logger.debug("Apply filters clicked")
        self._read_ui_controls_to_current_filters() # Update data model from UI
        self._populate_table_from_buffer()

    def _on_reset_filters_clicked(self):
        # Logic to clear filter UI elements and self.current_filters
        # Then call _populate_table_from_buffer
        logger.debug("Reset filters clicked")
        self._init_filters() # Reset data model to defaults (Action: '拦截')
        self._apply_current_filters_to_ui_controls() # Sync UI to new defaults
        self._populate_table_from_buffer()

    def _matches_filters(self, log_entry_dict: dict) -> bool:
        """检查给定的日志字典是否匹配当前激活的过滤器。"""
        # Helper to check if a filter value is set and if it matches the log field
        def field_matches(log_value, filter_value):
            if not filter_value: # Filter not set for this field
                return True
            return filter_value.lower() in str(log_value).lower()

        # Helper for combo box 'All' option
        def combo_matches(log_value, filter_value):
            if filter_value == "All":
                return True
            return str(log_value).lower() == filter_value.lower()

        log_type = log_entry_dict.get('log_type', 'general')
        packet_info = log_entry_dict.get('packet_info')

        if log_type == 'packet' and packet_info:
            if not field_matches(packet_info.get('src_addr'), self.current_filters['src_ip']):
                return False
            if not field_matches(packet_info.get('dst_addr'), self.current_filters['dst_ip']):
                return False
            if not field_matches(packet_info.get('src_port'), self.current_filters['src_port']):
                return False
            if not field_matches(packet_info.get('dst_port'), self.current_filters['dst_port']):
                return False
            if not combo_matches(packet_info.get('protocol'), self.current_filters['protocol']):
                return False
            if not combo_matches(packet_info.get('action'), self.current_filters['action']):
                return False
        elif log_type == 'general': # For general logs, we might only filter by content if desired, or always show
            # For now, let's say general logs are not filtered by packet-specific filters
            # or we could try to match message content if a general text filter was added.
            # If action filter is set and not 'All', general logs won't match unless they have an action field.
            if self.current_filters['action'] != 'All': 
                return False # General logs don't have an 'action' field in the same way packets do
            # Apply other filters if they are very generic (e.g. a global text search, not implemented here)
            pass
        else: # Unknown log type
            return False # Or True if we want to show unknown types by default
        
        return True

    def _populate_table_from_buffer(self):
        """清空表格，然后遍历内部日志缓冲区，将匹配过滤器的条目重新添加到表格中。"""
        self.log_table.setRowCount(0) # Clear the table first
        
        # Iterate over a copy of the buffer if modification during iteration is a concern (not here)
        for log_dict in self.all_log_entries_buffer:
            if self._matches_filters(log_dict):
                current_row_count = self.log_table.rowCount()
                # self.log_table.insertRow(current_row_count) # _add_log_dict_to_table will insert
                self._add_log_dict_to_table(log_dict, current_row_count) 
                # Row count limit is handled by _add_log_dict_to_table via buffer pruning
        
        self.log_table.scrollToBottom()
        logger.debug(f"Table repopulated. Displaying {self.log_table.rowCount()} rows.")

    def _add_log_dict_to_table(self, log_entry: dict, row_position: int):
        """将单个日志字典的内容格式化并插入到表格的指定行。"""
        try:
            self.log_table.insertRow(row_position) # Insert new row

            log_type = log_entry.get('log_type', 'general')
            packet_info = log_entry.get('packet_info')

            if log_type == 'packet' and packet_info:
                display_time = log_entry.get('timestamp', '').split(',')[0]
                action = packet_info.get('action', '未知')
                protocol = packet_info.get('protocol', 'N/A')
                src_ip = packet_info.get('src_addr', 'N/A')
                src_port = str(packet_info.get('src_port', 'N/A'))
                dst_ip = packet_info.get('dst_addr', 'N/A')
                dst_port = str(packet_info.get('dst_port', 'N/A'))
                size = str(packet_info.get('payload_size', 'N/A'))
                # Предполагается, что details правилоа информация хранится в 'reason_details'
                details = packet_info.get('reason_details', 'N/A') 

                self.log_table.setItem(row_position, COL_TIME, QTableWidgetItem(display_time))
                self.log_table.setItem(row_position, COL_SRC_IP, QTableWidgetItem(src_ip))
                self.log_table.setItem(row_position, COL_DST_IP, QTableWidgetItem(dst_ip))
                self.log_table.setItem(row_position, COL_SRC_PORT, QTableWidgetItem(src_port))
                self.log_table.setItem(row_position, COL_DST_PORT, QTableWidgetItem(dst_port))
                self.log_table.setItem(row_position, COL_PROTOCOL, QTableWidgetItem(protocol))
                
                action_item = QTableWidgetItem(action)
                if action == '拦截': action_item.setForeground(QColor('red'))
                elif action == '放行': action_item.setForeground(QColor('green'))
                self.log_table.setItem(row_position, COL_ACTION, action_item)
                self.log_table.setItem(row_position, COL_SIZE, QTableWidgetItem(size))
                self.log_table.setItem(row_position, COL_DETAILS, QTableWidgetItem(details)) # New column for details/reason
            
            else: # General log or fallback
                display_time = log_entry.get('timestamp', '').split(',')[0]
                level = log_entry.get('levelname', 'INFO')
                logger_name = log_entry.get('name', 'Unknown')
                message = log_entry.get('message', log_entry.get('formatted_message', 'Invalid log entry'))

                self.log_table.setItem(row_position, COL_TIME, QTableWidgetItem(display_time))
                full_message = f"[{logger_name}] {message.strip()}" 
                message_item = QTableWidgetItem(full_message) 
                if level == "ERROR" or level == "CRITICAL": message_item.setForeground(QColor('darkRed'))
                elif level == "WARNING": message_item.setForeground(QColor('darkOrange')) 
                self.log_table.setItem(row_position, COL_SRC_IP, message_item)
                self.log_table.setSpan(row_position, COL_SRC_IP, 1, self.log_table.columnCount() - 1) 
            
            # Note: Row limiting for the *display* is implicitly handled by only adding filtered items
            # from a buffer that is already limited by self.max_rows.
            # If self.all_log_entries_buffer grows beyond self.max_rows, oldest are removed.
            # When _populate_table_from_buffer is called, it shows max_rows (or fewer if filtered).

        except Exception as e:
            logger.error(f"Error in _add_log_dict_to_table: {e}", exc_info=True)
            # Fallback error display in table
            try:
                self.log_table.setItem(row_position, COL_TIME, QTableWidgetItem(f"UI Log Error: {e}"))
                self.log_table.setSpan(row_position, COL_TIME, 1, self.log_table.columnCount())
            except Exception as inner_e: 
                logger.error(f"Failed to add error message to log table (inner): {inner_e}")

    # --- Public Slot for Adding Log Entries --- 
    @pyqtSlot(dict) 
    def add_log_entry(self, log_entry: dict):
        """Slot to receive structured log data, add to buffer, and update table if matches filters."""
        # 1. Add to internal buffer
        self.all_log_entries_buffer.append(log_entry)

        # 2. Prune buffer if it exceeds max_rows (remove from the beginning - oldest)
        if len(self.all_log_entries_buffer) > self.max_rows:
            self.all_log_entries_buffer.pop(0)

        # 3. If the new entry matches current filters, add it to the visible table
        if self._matches_filters(log_entry):
            current_row_count = self.log_table.rowCount()
            # If adding this row makes visible rows exceed max_rows, remove from top of table
            if current_row_count >= self.max_rows: # Use >= because we are about to add one
                if self.log_table.rowCount() > 0: # Ensure table is not empty
                    self.log_table.removeRow(0)
                    current_row_count -=1 # Adjust because a row was removed
            
            self._add_log_dict_to_table(log_entry, current_row_count)
            self.log_table.scrollToBottom()
        
        self.log_entry_added_signal.emit(log_entry) # Emit signal regardless of filter match

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

    def clear_log_display_and_buffer(self):
        """清除日志表格内容、内部缓冲区并重置过滤器。"""
        self.log_table.setRowCount(0)
        self.all_log_entries_buffer = []
        # Reset filter UI
        self.src_ip_filter.clear()
        self.dst_ip_filter.clear()
        self.src_port_filter.clear()
        self.dst_port_filter.clear()
        self.protocol_filter_combo.setCurrentIndex(0) # All
        self.action_filter_combo.setCurrentIndex(0) # All
        self._init_filters() # Reset stored filters
        logger.info("Log display, buffer, and filters cleared.")

        # Optionally show a message box, but might be better handled by main window if needed
        # QMessageBox.information(self, "日志清除", "日志显示已清除。")

    def _export_filtered_logs_to_csv(self):
        """导出当前通过过滤器显示的日志条目到CSV文件。"""
        if not self.all_log_entries_buffer:
            QMessageBox.information(self, "导出日志", "没有日志可导出。")
            return

        # 获取当前应用的过滤器所筛选出的日志
        # Note: _populate_table_from_buffer updates the visible table,
        # but for export, we should re-filter the whole buffer to ensure consistency.
        filtered_logs_to_export = [
            log_entry for log_entry in self.all_log_entries_buffer if self._matches_filters(log_entry)
        ]

        if not filtered_logs_to_export:
            QMessageBox.information(self, "导出日志", "当前过滤器下没有匹配的日志可导出。")
            return

        parent_window = self.window() 
        file_path, _ = QFileDialog.getSaveFileName(
            parent_window, 
            "导出过滤后的日志为CSV", 
            "", 
            "CSV 文件 (*.csv);;所有文件 (*)"
        )

        if not file_path:
            return 

        headers = [
            "Timestamp", "Log Type", "Source IP", "Source Port", 
            "Destination IP", "Destination Port", "Protocol", "Action", 
            "Size (Bytes)", "Details/Reason" # Changed from "Details/Message"
        ]

        try:
            with open(file_path, 'w', newline='', encoding='utf-8-sig') as csvfile:
                writer = csv.writer(csvfile) # Use csv.writer for list-based rows
                writer.writerow(headers) # Write the header row

                for log_entry in filtered_logs_to_export:
                    # Prepare a list for the row in the order of headers
                    row_list = [''] * len(headers) # Initialize with empty strings
                    
                    row_list[headers.index("Timestamp")] = log_entry.get('timestamp', '').split(',')[0] # Get only date-time part
                    row_list[headers.index("Log Type")] = log_entry.get('log_type', 'general')
                    
                    packet_info = log_entry.get('packet_info')
                    if log_entry.get('log_type') == 'packet' and packet_info:
                        row_list[headers.index("Source IP")] = packet_info.get('src_addr', '')
                        row_list[headers.index("Source Port")] = str(packet_info.get('src_port', ''))
                        row_list[headers.index("Destination IP")] = packet_info.get('dst_addr', '')
                        row_list[headers.index("Destination Port")] = str(packet_info.get('dst_port', ''))
                        row_list[headers.index("Protocol")] = packet_info.get('protocol', '')
                        row_list[headers.index("Action")] = packet_info.get('action', '')
                        row_list[headers.index("Size (Bytes)")] = str(packet_info.get('payload_size', ''))
                        # Details/Message can remain empty for packet logs if desired
                        row_list[headers.index("Details/Reason")] = packet_info.get('reason_details', '') # Store reason for packets
                    else: # General log
                        # For general logs, the main content is usually in 'message' or 'formatted_message'
                        message_content = log_entry.get('message', log_entry.get('formatted_message', ''))
                        logger_name = log_entry.get('name', 'Unknown')
                        level = log_entry.get('levelname', 'INFO')
                        row_list[headers.index("Details/Reason")] = f"[{level}] [{logger_name}] {message_content.strip()}"
                    
                    writer.writerow(row_list)
            
            QMessageBox.information(self, "导出成功", f"过滤后的日志已成功导出到:\\n{file_path}")

        except IOError as e:
            logger.error(f"导出日志到CSV时发生IO错误: {e}", exc_info=True)
            QMessageBox.critical(self, "导出失败", f"无法写入文件: {file_path}\\n错误: {e}")
        except Exception as e:
            logger.error(f"导出日志到CSV时发生未知错误: {e}", exc_info=True)
            QMessageBox.critical(self, "导出失败", f"导出日志时发生意外错误: {e}")
