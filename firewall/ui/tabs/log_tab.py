#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import logging # Added for logger
import csv # Added for CSV export
import os # Added for environment variable access
import datetime # For generating timestamped filenames if only a directory is provided

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget, 
    QTableWidgetItem, QHeaderView, QAbstractItemView, QLabel, QLineEdit, QComboBox,
    QFileDialog, QMessageBox # Added QFileDialog and QMessageBox
)
from PyQt6.QtCore import pyqtSlot, pyqtSignal, Qt # Added Qt
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
            
            first_item_for_data = None # To store the item where we'll set UserRole data

            if log_type == 'packet' and packet_info:
                display_time = log_entry.get('timestamp', '').split(',')[0]
                action = packet_info.get('action', '未知')
                protocol = packet_info.get('protocol', 'N/A')
                src_ip = packet_info.get('src_addr', 'N/A')
                src_port = str(packet_info.get('src_port', 'N/A'))
                dst_ip = packet_info.get('dst_addr', 'N/A')
                dst_port = str(packet_info.get('dst_port', 'N/A'))
                size = str(packet_info.get('payload_size', 'N/A'))
                details = packet_info.get('reason_details', 'N/A')

                time_item = QTableWidgetItem(display_time)
                self.log_table.setItem(row_position, COL_TIME, time_item)
                first_item_for_data = time_item

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
                self.log_table.setItem(row_position, COL_DETAILS, QTableWidgetItem(details))
            
            else: # General log or fallback
                display_time = log_entry.get('timestamp', '').split(',')[0]
                level = log_entry.get('levelname', 'INFO')
                logger_name = log_entry.get('name', 'Unknown')
                message = log_entry.get('message', log_entry.get('formatted_message', 'Invalid log entry'))

                time_item = QTableWidgetItem(display_time)
                self.log_table.setItem(row_position, COL_TIME, time_item)
                first_item_for_data = time_item

                full_message = f"[{logger_name}] {message.strip()}" 
                message_item = QTableWidgetItem(full_message) 
                if level == "ERROR" or level == "CRITICAL": message_item.setForeground(QColor('darkRed'))
                elif level == "WARNING": message_item.setForeground(QColor('darkOrange')) 
                self.log_table.setItem(row_position, COL_SRC_IP, message_item)
                self.log_table.setSpan(row_position, COL_SRC_IP, 1, self.log_table.columnCount() - 1) 
            
            # Store the original log_entry dict with the row for accurate export
            if first_item_for_data:
                first_item_for_data.setData(Qt.ItemDataRole.UserRole, log_entry)

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
        self.action_filter_combo.setCurrentIndex(0) # All -> No, keep default as '拦截' as per init
        self._init_filters() # Reset stored filters (action will be '拦截')
        self._apply_current_filters_to_ui_controls() # Ensure UI reflects this
        logger.info("Log display, buffer, and filters cleared.")

        # Optionally show a message box, but might be better handled by main window if needed
        # QMessageBox.information(self, "日志清除", "日志显示已清除。")

    def _export_filtered_logs_to_csv(self):
        """导出当前通过过滤器显示的日志条目到CSV文件。"""

        # 1. Check environment variable to completely disable export during testing
        disable_export_env_var = os.environ.get('FIREWALL_TESTING_NO_CSV_EXPORT', '0').lower()
        if disable_export_env_var in ['1', 'true', 'yes']:
            logger.info("FIREWALL_TESTING_NO_CSV_EXPORT is set. Skipping CSV export for this run.")
            return

        # 2. Prepare log entries to be exported (from visible table rows)
        visible_log_entries = []
        for i in range(self.log_table.rowCount()):
            item = self.log_table.item(i, COL_TIME) 
            if item:
                log_entry_data = item.data(Qt.ItemDataRole.UserRole)
                if isinstance(log_entry_data, dict):
                    visible_log_entries.append(log_entry_data)
                else:
                    logger.warning(f"Row {i} in log table is missing original log_entry data for export or data is not a dict.")
            else:
                logger.warning(f"Row {i} in log table has no item in the first column for export.")

        if not visible_log_entries:
            # Only show message box if not in an automated export mode
            if not os.environ.get('FIREWALL_AUTO_EXPORT_CSV_PATH'):
                QMessageBox.information(self, "导出日志", "表格中没有可见的日志可导出。")
            else:
                logger.info("Automated CSV export: No visible log entries to export.")
            return

        # 3. Determine file path: either from env var or QFileDialog
        file_path = None
        auto_export_path_str = os.environ.get('FIREWALL_AUTO_EXPORT_CSV_PATH')

        if auto_export_path_str:
            # Ensure the path is absolute or handle relative paths appropriately
            # For simplicity, assume it's an absolute path or relative to CWD
            # If it's a directory, generate a filename. If it's a file, use it.
            if os.path.isdir(auto_export_path_str):
                # It's a directory, create a filename
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"firewall_log_export_{timestamp}.csv"
                file_path = os.path.join(auto_export_path_str, filename)
                logger.info(f"Automated CSV export: FIREWALL_AUTO_EXPORT_CSV_PATH is a directory. Using generated filename: {file_path}")
            elif not os.path.isdir(os.path.dirname(auto_export_path_str)) and os.path.dirname(auto_export_path_str) != '':
                 # It's a file path but its directory doesn't exist
                 logger.warning(f"Automated CSV export: Directory for specified path '{auto_export_path_str}' does not exist. Falling back to manual dialog.")
                 # Fall through to QFileDialog
            else: # Assume it's a full file path
                file_path = auto_export_path_str
                logger.info(f"Automated CSV export: Using FIREWALL_AUTO_EXPORT_CSV_PATH as file path: {file_path}")
            
            # Ensure directory exists for the determined file_path
            if file_path:
                try:
                    export_dir = os.path.dirname(file_path)
                    if export_dir: # Check if export_dir is not empty (e.g. for relative filenames in CWD)
                        os.makedirs(export_dir, exist_ok=True)
                except Exception as e:
                    logger.error(f"Automated CSV export: Failed to create directory {os.path.dirname(file_path)}: {e}. Aborting auto export.")
                    # Optionally fall back to QFileDialog or just return
                    if not os.environ.get('FIREWALL_AUTO_EXPORT_CSV_PATH'): # Avoid infinite loop if QFileDialog also fails
                         QMessageBox.critical(self, "导出失败", f"无法创建导出目录: {os.path.dirname(file_path)}\n错误: {e}")
                    return # Stop export if directory creation fails in auto mode

        if not file_path: # If auto_export_path_str was not set or was invalid, or dir creation failed and it decided to not proceed
            parent_window = self.window() 
            file_path_tuple = QFileDialog.getSaveFileName( # QFileDialog.getSaveFileName returns a tuple
                parent_window, 
                "导出过滤后的日志为CSV", 
                "", 
                "CSV 文件 (*.csv);;所有文件 (*)"
            )
            file_path = file_path_tuple[0] if file_path_tuple else None


        if not file_path: # User cancelled or no valid path
            logger.info("CSV export cancelled by user or no valid path provided.")
            return 

        # 4. Write to CSV
        headers = [
            "Timestamp", "Log Type", "Source IP", "Source Port", 
            "Destination IP", "Destination Port", "Protocol", "Action", 
            "Size (Bytes)", "Details/Reason"
        ]

        try:
            with open(file_path, 'w', newline='', encoding='utf-8-sig') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(headers)

                for log_entry in visible_log_entries:
                    row_list = [''] * len(headers)
                    
                    row_list[headers.index("Timestamp")] = log_entry.get('timestamp', '').split(',')[0]
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
                        row_list[headers.index("Details/Reason")] = packet_info.get('reason_details', '')
                    else: 
                        message_content = log_entry.get('message', log_entry.get('formatted_message', ''))
                        logger_name = log_entry.get('name', 'Unknown')
                        level = log_entry.get('levelname', 'INFO')
                        row_list[headers.index("Details/Reason")] = f"[{level}] [{logger_name}] {message_content.strip()}"
                    
                    writer.writerow(row_list)
            
            success_message = f"当前显示的日志已成功导出到:\n{file_path}"
            logger.info(success_message)
            if not auto_export_path_str: # Only show message box if not in automated mode
                QMessageBox.information(self, "导出成功", success_message)

        except IOError as e:
            logger.error(f"导出日志到CSV时发生IO错误: {e}", exc_info=True)
            if not auto_export_path_str:
                QMessageBox.critical(self, "导出失败", f"无法写入文件: {file_path}\n错误: {e}")
        except Exception as e:
            logger.error(f"导出日志到CSV时发生未知错误: {e}", exc_info=True)
            if not auto_export_path_str:
                QMessageBox.critical(self, "导出失败", f"导出日志时发生意外错误: {e}")

    def export_buffered_logs_for_automation(self, file_path_or_dir: str, filter_override: dict = None):
        """
        Exports logs directly from the all_log_entries_buffer, bypassing UI table visibility.
        Allows for optional filter overrides for automation purposes.
        If filter_override is None, all buffered logs are exported.
        The file_path_or_dir argument can be a directory (a timestamped CSV will be created inside) 
        or a full file path.
        """
        logger.info(f"Automated CSV export (from buffer) initiated for path/directory: {file_path_or_dir}")
        logger.info(f"Automated CSV export: Buffer size at start: {len(self.all_log_entries_buffer)}") # 新增日志
        if filter_override: # 新增日志
            logger.info(f"Automated CSV export: Applying filter override: {filter_override}")

        _actual_file_path: str
        if os.path.isdir(file_path_or_dir):
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            # Use a slightly different name for generated files to distinguish from other export functions
            filename = f"buffered_auto_export_{timestamp}.csv"
            _actual_file_path = os.path.join(file_path_or_dir, filename)
            logger.info(f"Provided path '{file_path_or_dir}' is a directory. Actual export file path: {_actual_file_path}")
        else:
            _actual_file_path = file_path_or_dir
            logger.info(f"Provided path '{file_path_or_dir}' is treated as a full file path. Actual export file path: {_actual_file_path}")

        # Ensure the parent directory for _actual_file_path exists
        try:
            export_dir = os.path.dirname(_actual_file_path)
            if export_dir: # handles case where _actual_file_path is just a filename (dir is '')
                os.makedirs(export_dir, exist_ok=True)
        except Exception as e:
            msg = f"无法创建导出目录: {os.path.dirname(_actual_file_path)}\n错误: {e}"
            QMessageBox.critical(self, "导出失败", msg)
            logger.error(f"Automated CSV export (from buffer): Failed to create directory for '{_actual_file_path}'. {msg}", exc_info=True)
            return

        if not self.all_log_entries_buffer:
            logger.info(f"Automated CSV export (from buffer): No log entries in buffer to export to {_actual_file_path}.")
            # Optionally create an empty CSV with headers or just do nothing
            try:
                with open(_actual_file_path, 'w', newline='', encoding='utf-8') as csvfile: # Use _actual_file_path
                    writer = csv.writer(csvfile)
                    # Write headers (same as your other export)
                    headers = ["Timestamp", "Log Type", "Source IP", "Source Port", 
                               "Destination IP", "Destination Port", "Protocol", "Action", 
                               "Size (Bytes)", "Details/Reason"] # Adjust if needed
                    writer.writerow(headers)
                logger.info(f"Automated CSV export (from buffer): Empty CSV with headers created at {_actual_file_path} as buffer was empty.")
            except Exception as e:
                # Use QMessageBox as this function might be called in a context where UI is available (e.g. closeEvent)
                QMessageBox.critical(self, "导出失败", f"创建空的CSV文件失败: {_actual_file_path}\n错误: {e}")
                logger.error(f"Automated CSV export (from buffer): Error creating empty CSV at {_actual_file_path}: {e}", exc_info=True)
            return

        # Determine effective filters
        effective_filters = self.current_filters.copy()
        if filter_override is not None:
            effective_filters.update(filter_override)
        else:
            effective_filters = {
                'src_ip': '', 'dst_ip': '', 'src_port': '', 'dst_port': '',
                'protocol': 'All', 'action': 'All'
            }
        
        original_filters = self.current_filters
        self.current_filters = effective_filters

        try:
            with open(_actual_file_path, 'w', newline='', encoding='utf-8') as csvfile: # Use _actual_file_path
                writer = csv.writer(csvfile)
                headers = ["Timestamp", "Log Type", "Source IP", "Source Port", 
                           "Destination IP", "Destination Port", "Protocol", "Action", 
                           "Size (Bytes)", "Details/Reason"] # Adjust if your dict keys are different
                writer.writerow(headers)

                exported_count = 0
                matched_filter_count = 0 # 新增计数器
                for log_entry_dict in self.all_log_entries_buffer:
                    if self._matches_filters(log_entry_dict):
                        matched_filter_count += 1 # 增加匹配计数
                        row_data = []
                        # Extract data according to headers from log_entry_dict
                        # This needs careful mapping based on your log_entry_dict structure
                        row_data.append(log_entry_dict.get('timestamp', ''))
                        row_data.append(log_entry_dict.get('log_type', 'general'))
                        
                        packet_info = log_entry_dict.get('packet_info', {})
                        row_data.append(str(packet_info.get('src_addr', '')))
                        row_data.append(str(packet_info.get('src_port', '')))
                        row_data.append(str(packet_info.get('dst_addr', '')))
                        row_data.append(str(packet_info.get('dst_port', '')))
                        row_data.append(str(packet_info.get('protocol', '')))
                        row_data.append(str(packet_info.get('action', '')))
                        row_data.append(str(packet_info.get('size', ''))) # Ensure this key matches your packet_info structure for size
                        # Check for reason_details first, then reason, then message for broader compatibility
                        details_or_reason = packet_info.get('reason_details', packet_info.get('reason', log_entry_dict.get('message', '')))
                        row_data.append(str(details_or_reason))
                        
                        writer.writerow(row_data)
                        exported_count +=1
                
                logger.info(f"Automated CSV export: Total entries in buffer: {len(self.all_log_entries_buffer)}, Matched filter: {matched_filter_count}, Exported: {exported_count}") # 新增详细日志

                if exported_count > 0:
                    QMessageBox.information(self, "导出成功", f"已将 {exported_count} 条日志导出到: {_actual_file_path}")
                    logger.info(f"Automated CSV export (from buffer): Successfully exported {exported_count} log entries to {_actual_file_path}")
                else:
                    # This case means buffer had entries, but none matched the automation filters
                    logger.info(f"Automated CSV export (from buffer): Buffer was not empty, but no log entries matched automation filters. Exported 0 entries to {_actual_file_path} (headers only).")
                    QMessageBox.warning(self, "导出注意", f"日志缓冲区中有条目，但没有条目匹配自动化导出过滤器。已在 {_actual_file_path} 创建CSV（仅表头）。")


        except Exception as e:
            QMessageBox.critical(self, "导出失败", f"导出日志到CSV失败: {_actual_file_path}\n错误: {e}")
            logger.error(f"Automated CSV export (from buffer): Failed to export logs to {_actual_file_path}: {e}", exc_info=True)
        finally:
            self.current_filters = original_filters # Restore original filters
