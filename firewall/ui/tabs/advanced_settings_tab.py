#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from typing import Dict, Any

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QCheckBox, QGroupBox, QFormLayout, 
    QSpinBox
)
from PyQt6.QtCore import pyqtSignal

class AdvancedSettingsTab(QWidget):
    """高级设置标签页的UI和交互"""
    # Signal to request applying settings in main window
    apply_settings_requested = pyqtSignal(dict)
    # Signal to request restarting WinDivert
    restart_windivert_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_settings: Dict[str, Any] = {} # Store local copy
        self._create_ui()

    def _create_ui(self):
        """创建此标签页的UI组件"""
        layout = QVBoxLayout(self)
        
        # --- Performance Optimization Group ---
        perf_group = QGroupBox("性能优化设置")
        perf_layout = QFormLayout(perf_group)
        
        # Processor settings
        self.use_queue_model_checkbox = QCheckBox()
        self.use_queue_model_checkbox.toggled.connect(lambda checked: self._setting_changed('use_queue_model', checked))
        perf_layout.addRow("使用队列模型:", self.use_queue_model_checkbox)

        self.num_workers_spinbox = QSpinBox()
        self.num_workers_spinbox.setRange(1, os.cpu_count() or 4) 
        self.num_workers_spinbox.valueChanged.connect(lambda value: self._setting_changed('num_workers', value))
        perf_layout.addRow("工作线程数:", self.num_workers_spinbox)

        self.use_packet_pool_checkbox = QCheckBox()
        self.use_packet_pool_checkbox.toggled.connect(lambda checked: self._setting_changed('use_packet_pool', checked))
        perf_layout.addRow("使用数据包对象池:", self.use_packet_pool_checkbox)

        self.packet_pool_size_spinbox = QSpinBox()
        self.packet_pool_size_spinbox.setRange(10, 1000)
        self.packet_pool_size_spinbox.setSingleStep(10)
        self.packet_pool_size_spinbox.valueChanged.connect(lambda value: self._setting_changed('packet_pool_size', value))
        perf_layout.addRow("对象池大小:", self.packet_pool_size_spinbox)

        # Analyzer settings
        self.skip_local_packets_checkbox = QCheckBox()
        self.skip_local_packets_checkbox.toggled.connect(lambda checked: self._setting_changed('skip_local_packets', checked))
        perf_layout.addRow("跳过本地回环包:", self.skip_local_packets_checkbox)
        
        self.allow_private_network_checkbox = QCheckBox()
        self.allow_private_network_checkbox.toggled.connect(lambda checked: self._setting_changed('allow_private_network', checked))
        perf_layout.addRow("允许私有网络互通:", self.allow_private_network_checkbox)
        
        layout.addWidget(perf_group)
        
        # --- Advanced Control Group ---
        control_group = QGroupBox("高级控制设置")
        control_layout = QFormLayout(control_group)
        
        restart_windivert_button = QPushButton("重启WinDivert")
        restart_windivert_button.clicked.connect(self.restart_windivert_requested) # Emit signal
        control_layout.addRow("WinDivert问题修复:", restart_windivert_button)
        layout.addWidget(control_group)
        
        # --- Apply Button ---
        apply_button = QPushButton("应用设置")
        # Emit signal with the current settings when clicked
        apply_button.clicked.connect(lambda: self.apply_settings_requested.emit(self.current_settings)) 
        layout.addWidget(apply_button)

    # --- Internal Slot ---
    def _setting_changed(self, key: str, value: Any):
        """当UI控件值改变时，更新本地存储的设置字典"""
        self.current_settings[key] = value

    # --- Public Methods for UI Update ---
    def load_settings(self, settings: Dict[str, Any]):
        """从外部加载设置并更新UI控件"""
        self.current_settings = settings.copy() # Store a copy
        try:
            # Update Processor settings UI
            self.use_queue_model_checkbox.setChecked(self.current_settings.get('use_queue_model', False))
            self.num_workers_spinbox.setValue(self.current_settings.get('num_workers', 2))
            self.use_packet_pool_checkbox.setChecked(self.current_settings.get('use_packet_pool', True))
            self.packet_pool_size_spinbox.setValue(self.current_settings.get('packet_pool_size', 100))
            # Update Analyzer settings UI
            self.skip_local_packets_checkbox.setChecked(self.current_settings.get('skip_local_packets', True)) 
            self.allow_private_network_checkbox.setChecked(self.current_settings.get('allow_private_network', True)) 
        except Exception as e:
            print(f"Error loading settings into Advanced Settings Tab UI: {e}")
            # Optionally show a message box or log the error
