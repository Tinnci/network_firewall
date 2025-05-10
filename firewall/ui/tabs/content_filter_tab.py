#!/usr/bin/env python
# -*- coding: utf-8 -*-

from typing import List

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QLineEdit, 
    QListWidget, QListWidgetItem, QGroupBox
)
from PyQt6.QtCore import pyqtSignal

class ContentFilterTab(QWidget):
    """内容过滤标签页的UI和基本交互"""
    # Signals to request actions from the main window
    add_filter_requested = pyqtSignal(str)
    remove_filter_requested = pyqtSignal(str)
    list_updated_signal = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._create_ui()

    def _create_ui(self):
        """创建此标签页的UI组件"""
        layout = QVBoxLayout(self)
        
        filter_group = QGroupBox("内容过滤 (正则表达式)")
        filter_layout = QVBoxLayout(filter_group)
        
        input_layout = QHBoxLayout()
        self.content_filter_input = QLineEdit()
        self.content_filter_input.setPlaceholderText("输入要过滤的正则表达式...")
        input_layout.addWidget(self.content_filter_input)
        add_button = QPushButton("添加")
        add_button.clicked.connect(self._on_add_filter)
        input_layout.addWidget(add_button)
        filter_layout.addLayout(input_layout)
        
        self.content_filter_list = QListWidget()
        self.content_filter_list.itemDoubleClicked.connect(self._on_remove_filter)
        filter_layout.addWidget(self.content_filter_list)
        
        layout.addWidget(filter_group)
        
        help_label = QLabel(
            "说明: 内容过滤将匹配数据包载荷 (按 UTF-8 解码，忽略错误)。\n"
            "支持 Python 正则表达式语法。\n"
            "双击列表中的项目可以移除该规则。\n"
            "注意: 复杂或过多的规则可能会影响性能。"
        )
        layout.addWidget(help_label)

    # --- Internal Slots to Emit Signals ---
    def _on_add_filter(self):
        pattern = self.content_filter_input.text().strip()
        if pattern:
            self.add_filter_requested.emit(pattern)

    def _on_remove_filter(self, item: QListWidgetItem):
        pattern = item.text()
        self.remove_filter_requested.emit(pattern)

    # --- Public Methods for UI Update ---
    def update_list(self, filter_items: List[str]):
        """更新内容过滤规则列表显示"""
        self._update_list_widget(self.content_filter_list, filter_items)
        self.list_updated_signal.emit()

    def clear_input(self):
        """清空输入框"""
        self.content_filter_input.clear()

    def _update_list_widget(self, list_widget: QListWidget, items: List[str]):
        """高效地更新列表控件内容"""
        # Copied from IpFilterTab, consider moving to a UI utility
        try: 
            current_items_text = {list_widget.item(i).text() for i in range(list_widget.count())}
            # Convert list to set for efficient comparison
            new_items_text = set(items) 

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
             print(f"Error updating Content Filter list widget '{list_widget.objectName()}': {e}")
