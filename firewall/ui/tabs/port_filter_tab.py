#!/usr/bin/env python
# -*- coding: utf-8 -*-

from typing import Set

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit, 
    QListWidget, QListWidgetItem, QGroupBox
)
from PyQt6.QtCore import pyqtSignal

class PortFilterTab(QWidget):
    """端口过滤标签页的UI和基本交互"""
    # Signals to request actions from the main window
    add_blacklist_requested = pyqtSignal(str)
    remove_blacklist_requested = pyqtSignal(str)
    add_whitelist_requested = pyqtSignal(str)
    remove_whitelist_requested = pyqtSignal(str)
    lists_updated_signal = pyqtSignal()

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
        self._update_list_widget(self.bl_port_list, blacklist_items)
        self._update_list_widget(self.wl_port_list, whitelist_items)
        self.lists_updated_signal.emit()

    def clear_blacklist_input(self):
        """清空黑名单输入框"""
        self.bl_port_input.clear()

    def clear_whitelist_input(self):
        """清空白名单输入框"""
        self.wl_port_input.clear()

    def _update_list_widget(self, list_widget: QListWidget, items: Set[str]):
        """高效地更新列表控件内容"""
        # Copied from IpFilterTab, consider moving to a UI utility
        try: 
            current_items_text = {list_widget.item(i).text() for i in range(list_widget.count())}
            new_items_text = items # Already a set of strings

            items_to_add = new_items_text - current_items_text
            items_to_remove = current_items_text - new_items_text

            if items_to_remove:
                rows_to_remove = []
                for i in range(list_widget.count()):
                     try: 
                         if list_widget.item(i).text() in items_to_remove:
                             rows_to_remove.append(i)
                     except AttributeError: pass 
                for i in sorted(rows_to_remove, reverse=True):
                    list_widget.takeItem(i)
            if items_to_add:
                list_widget.addItems(sorted(list(items_to_add))) 
        except Exception as e:
             print(f"Error updating Port list widget '{list_widget.objectName()}': {e}")
