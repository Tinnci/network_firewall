#!/usr/bin/env python
# -*- coding: utf-8 -*-

from typing import Set

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit, 
    QListWidget, QListWidgetItem, QGroupBox
)
from PyQt6.QtCore import pyqtSignal

# Import the utility function
from ..ui_utils import update_list_widget_content

class IpFilterTab(QWidget):
    """IP过滤标签页的UI和基本交互"""
    # Signals to request actions from the main window
    add_blacklist_requested = pyqtSignal(str)
    remove_blacklist_requested = pyqtSignal(str)
    add_whitelist_requested = pyqtSignal(str)
    remove_whitelist_requested = pyqtSignal(str)
    import_list_requested = pyqtSignal(str) # list_type: 'blacklist' or 'whitelist'
    export_list_requested = pyqtSignal(str) # list_type: 'blacklist' or 'whitelist'

    def __init__(self, parent=None):
        super().__init__(parent)
        self._create_ui()

    def _create_ui(self):
        """创建此标签页的UI组件"""
        layout = QVBoxLayout(self)
        
        # --- Blacklist Group ---
        blacklist_group = QGroupBox("IP黑名单")
        blacklist_layout = QVBoxLayout(blacklist_group)
        
        bl_input_layout = QHBoxLayout()
        self.bl_ip_input = QLineEdit()
        self.bl_ip_input.setPlaceholderText("输入IP地址或CIDR...")
        bl_input_layout.addWidget(self.bl_ip_input)
        bl_add_button = QPushButton("添加")
        bl_add_button.clicked.connect(self._on_add_blacklist) # Connect to internal slot
        bl_input_layout.addWidget(bl_add_button)
        blacklist_layout.addLayout(bl_input_layout)
        
        self.bl_ip_list = QListWidget()
        self.bl_ip_list.itemDoubleClicked.connect(self._on_remove_blacklist) # Connect to internal slot
        blacklist_layout.addWidget(self.bl_ip_list)

        bl_button_layout = QHBoxLayout()
        bl_import_button = QPushButton("导入列表")
        bl_import_button.clicked.connect(lambda: self.import_list_requested.emit('blacklist')) # Emit signal
        bl_button_layout.addWidget(bl_import_button)
        bl_export_button = QPushButton("导出列表")
        bl_export_button.clicked.connect(lambda: self.export_list_requested.emit('blacklist')) # Emit signal
        bl_button_layout.addWidget(bl_export_button)
        blacklist_layout.addLayout(bl_button_layout)
        
        # --- Whitelist Group ---
        whitelist_group = QGroupBox("IP白名单")
        whitelist_layout = QVBoxLayout(whitelist_group)
        
        wl_input_layout = QHBoxLayout()
        self.wl_ip_input = QLineEdit()
        self.wl_ip_input.setPlaceholderText("输入IP地址或CIDR...")
        wl_input_layout.addWidget(self.wl_ip_input)
        wl_add_button = QPushButton("添加")
        wl_add_button.clicked.connect(self._on_add_whitelist) # Connect to internal slot
        wl_input_layout.addWidget(wl_add_button)
        whitelist_layout.addLayout(wl_input_layout)
        
        self.wl_ip_list = QListWidget()
        self.wl_ip_list.itemDoubleClicked.connect(self._on_remove_whitelist) # Connect to internal slot
        whitelist_layout.addWidget(self.wl_ip_list)

        wl_button_layout = QHBoxLayout()
        wl_import_button = QPushButton("导入列表")
        wl_import_button.clicked.connect(lambda: self.import_list_requested.emit('whitelist')) # Emit signal
        wl_button_layout.addWidget(wl_import_button)
        wl_export_button = QPushButton("导出列表")
        wl_export_button.clicked.connect(lambda: self.export_list_requested.emit('whitelist')) # Emit signal
        wl_button_layout.addWidget(wl_export_button)
        whitelist_layout.addLayout(wl_button_layout)
        
        # --- Add groups to main layout ---
        main_h_layout = QHBoxLayout()
        main_h_layout.addWidget(blacklist_group)
        main_h_layout.addWidget(whitelist_group)
        layout.addLayout(main_h_layout)

    # --- Internal Slots to Emit Signals ---
    def _on_add_blacklist(self):
        ip = self.bl_ip_input.text().strip()
        if ip:
            self.add_blacklist_requested.emit(ip)
            # Clearing input is now responsibility of main window after successful add
            # self.bl_ip_input.clear() 

    def _on_remove_blacklist(self, item: QListWidgetItem):
        ip = item.text()
        self.remove_blacklist_requested.emit(ip)
        # Removing item from list is now responsibility of main window after successful removal

    def _on_add_whitelist(self):
        ip = self.wl_ip_input.text().strip()
        if ip:
            self.add_whitelist_requested.emit(ip)
            # self.wl_ip_input.clear()

    def _on_remove_whitelist(self, item: QListWidgetItem):
        ip = item.text()
        self.remove_whitelist_requested.emit(ip)

    # --- Public Methods for UI Update ---
    def update_lists(self, blacklist_items: Set[str], whitelist_items: Set[str]):
        """更新黑名单和白名单列表显示"""
        update_list_widget_content(self.bl_ip_list, blacklist_items)
        update_list_widget_content(self.wl_ip_list, whitelist_items)

    def clear_blacklist_input(self):
        """清空黑名单输入框"""
        self.bl_ip_input.clear()

    def clear_whitelist_input(self):
        """清空白名单输入框"""
        self.wl_ip_input.clear()
