#!/usr/bin/env python
# -*- coding: utf-8 -*-

from typing import List

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QLineEdit, 
    QListWidget, QListWidgetItem, QGroupBox
)
from PyQt6.QtCore import pyqtSignal

# Import the utility function
from ..ui_utils import update_list_widget_content

class ContentFilterTab(QWidget):
    """内容过滤标签页的UI和基本交互"""
    # Signals to request actions from the main window
    add_filter_requested = pyqtSignal(str)
    remove_filter_requested = pyqtSignal(str)

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
        update_list_widget_content(self.content_filter_list, filter_items)

    def clear_input(self):
        """清空输入框"""
        self.content_filter_input.clear()
