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

class PortFilterTab(QWidget):
    """端口过滤标签页的UI和基本交互"""
    # Signals to request actions from the main window
    add_blacklist_requested = pyqtSignal(str)
    remove_blacklist_requested = pyqtSignal(str)
    add_whitelist_requested = pyqtSignal(str)
    remove_whitelist_requested = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._create_ui()

    def _create_ui(self):
        """创建此标签页的UI组件"""
        layout = QVBoxLayout(self)
        
        # --- Blacklist Group ---
        blacklist_group = QGroupBox("端口黑名单")
        blacklist_layout = QVBoxLayout(blacklist_group)
        
        bl_input_layout = QHBoxLayout()
        self.bl_port_input = QLineEdit() 
        self.bl_port_input.setPlaceholderText("输入端口或范围 (e.g., 80, 8000-8080)")
        bl_input_layout.addWidget(self.bl_port_input)
        bl_add_button = QPushButton("添加")
        bl_add_button.clicked.connect(self._on_add_blacklist)
        bl_input_layout.addWidget(bl_add_button)
        blacklist_layout.addLayout(bl_input_layout)
        
        self.bl_port_list = QListWidget()
        self.bl_port_list.itemDoubleClicked.connect(self._on_remove_blacklist)
        blacklist_layout.addWidget(self.bl_port_list)
        
        # --- Whitelist Group ---
        whitelist_group = QGroupBox("端口白名单")
        whitelist_layout = QVBoxLayout(whitelist_group)
        
        wl_input_layout = QHBoxLayout()
        self.wl_port_input = QLineEdit() 
        self.wl_port_input.setPlaceholderText("输入端口或范围 (e.g., 443, 10000-11000)")
        wl_input_layout.addWidget(self.wl_port_input)
        wl_add_button = QPushButton("添加")
        wl_add_button.clicked.connect(self._on_add_whitelist)
        wl_input_layout.addWidget(wl_add_button)
        whitelist_layout.addLayout(wl_input_layout)
        
        self.wl_port_list = QListWidget()
        self.wl_port_list.itemDoubleClicked.connect(self._on_remove_whitelist)
        whitelist_layout.addWidget(self.wl_port_list)
        
        # --- Add groups to main layout ---
        main_h_layout = QHBoxLayout()
        main_h_layout.addWidget(blacklist_group)
        main_h_layout.addWidget(whitelist_group)
        layout.addLayout(main_h_layout)

    # --- Internal Slots to Emit Signals ---
    def _on_add_blacklist(self):
        port_str = self.bl_port_input.text().strip()
        if port_str:
            self.add_blacklist_requested.emit(port_str)

    def _on_remove_blacklist(self, item: QListWidgetItem):
        port_str = item.text()
        self.remove_blacklist_requested.emit(port_str)

    def _on_add_whitelist(self):
        port_str = self.wl_port_input.text().strip()
        if port_str:
            self.add_whitelist_requested.emit(port_str)

    def _on_remove_whitelist(self, item: QListWidgetItem):
        port_str = item.text()
        self.remove_whitelist_requested.emit(port_str)

    # --- Public Methods for UI Update ---
    def update_lists(self, blacklist_items: Set[str], whitelist_items: Set[str]):
        """更新黑名单和白名单列表显示"""
        update_list_widget_content(self.bl_port_list, blacklist_items)
        update_list_widget_content(self.wl_port_list, whitelist_items)

    def clear_blacklist_input(self):
        """清空黑名单输入框"""
        self.bl_port_input.clear()

    def clear_whitelist_input(self):
        """清空白名单输入框"""
        self.wl_port_input.clear()
