#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QTableWidget, QTableWidgetItem,
    QTabWidget, QMessageBox, QCheckBox, QGroupBox, QFormLayout,
    QHeaderView, QSpinBox, QTextEdit, QListWidget, QListWidgetItem
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QModelIndex
from PyQt6.QtGui import QIcon, QColor

from ..core.firewall import Firewall


class MainWindow(QMainWindow):
    """防火墙主窗口"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        # 创建防火墙实例
        self.firewall = Firewall()
        
        # 设置窗口基本属性
        self.setWindowTitle("简易防火墙")
        self.setMinimumSize(800, 600)
        
        # 创建UI组件
        self._create_ui()
        
        # 设置更新定时器
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self._update_status)
        self.update_timer.start(1000)  # 每秒更新一次状态
        
    def _create_ui(self):
        """创建UI组件"""
        # 创建中央窗口部件
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        
        # 创建主布局
        main_layout = QVBoxLayout(central_widget)
        
        # 创建控制面板
        control_panel = self._create_control_panel()
        main_layout.addWidget(control_panel)
        
        # 创建标签页控件
        self.tab_widget = QTabWidget(self)
        
        # 创建各个标签页
        self.tab_widget.addTab(self._create_ip_filter_tab(), "IP过滤")
        self.tab_widget.addTab(self._create_port_filter_tab(), "端口过滤")
        self.tab_widget.addTab(self._create_content_filter_tab(), "内容过滤")
        self.tab_widget.addTab(self._create_log_tab(), "日志")
        
        main_layout.addWidget(self.tab_widget)
        
    def _create_control_panel(self) -> QWidget:
        """创建控制面板
        
        Returns:
            QWidget: 控制面板组件
        """
        # 创建控制面板组
        group_box = QGroupBox("控制面板")
        layout = QHBoxLayout(group_box)
        
        # 创建状态标签
        self.status_label = QLabel("状态: 已停止")
        layout.addWidget(self.status_label)
        
        # 创建统计信息标签
        self.stats_label = QLabel("总数据包: 0 | 拦截: 0 | 放行: 0")
        layout.addWidget(self.stats_label)
        
        # 弹性空间
        layout.addStretch()
        
        # 创建协议过滤选项
        self.tcp_checkbox = QCheckBox("TCP")
        self.tcp_checkbox.setChecked(True)
        self.tcp_checkbox.toggled.connect(lambda checked: self.firewall.set_protocol_filter("tcp", checked))
        layout.addWidget(self.tcp_checkbox)
        
        self.udp_checkbox = QCheckBox("UDP")
        self.udp_checkbox.setChecked(True)
        self.udp_checkbox.toggled.connect(lambda checked: self.firewall.set_protocol_filter("udp", checked))
        layout.addWidget(self.udp_checkbox)
        
        # 创建启动/停止按钮
        self.start_button = QPushButton("启动防火墙")
        self.start_button.clicked.connect(self._toggle_firewall)
        layout.addWidget(self.start_button)
        
        return group_box
        
    def _create_ip_filter_tab(self) -> QWidget:
        """创建IP过滤标签页
        
        Returns:
            QWidget: IP过滤标签页
        """
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 创建黑名单和白名单组
        blacklist_group = QGroupBox("IP黑名单")
        blacklist_layout = QVBoxLayout(blacklist_group)
        
        # 添加IP输入和按钮
        bl_input_layout = QHBoxLayout()
        self.bl_ip_input = QLineEdit()
        self.bl_ip_input.setPlaceholderText("输入IP地址...")
        bl_input_layout.addWidget(self.bl_ip_input)
        
        bl_add_button = QPushButton("添加")
        bl_add_button.clicked.connect(self._add_ip_to_blacklist)
        bl_input_layout.addWidget(bl_add_button)
        
        blacklist_layout.addLayout(bl_input_layout)
        
        # 黑名单列表
        self.bl_ip_list = QListWidget()
        self.bl_ip_list.itemDoubleClicked.connect(self._remove_ip_from_blacklist)
        blacklist_layout.addWidget(self.bl_ip_list)
        
        # 创建白名单组
        whitelist_group = QGroupBox("IP白名单")
        whitelist_layout = QVBoxLayout(whitelist_group)
        
        # 添加IP输入和按钮
        wl_input_layout = QHBoxLayout()
        self.wl_ip_input = QLineEdit()
        self.wl_ip_input.setPlaceholderText("输入IP地址...")
        wl_input_layout.addWidget(self.wl_ip_input)
        
        wl_add_button = QPushButton("添加")
        wl_add_button.clicked.connect(self._add_ip_to_whitelist)
        wl_input_layout.addWidget(wl_add_button)
        
        whitelist_layout.addLayout(wl_input_layout)
        
        # 白名单列表
        self.wl_ip_list = QListWidget()
        self.wl_ip_list.itemDoubleClicked.connect(self._remove_ip_from_whitelist)
        whitelist_layout.addWidget(self.wl_ip_list)
        
        # 添加到主布局
        main_layout = QHBoxLayout()
        main_layout.addWidget(blacklist_group)
        main_layout.addWidget(whitelist_group)
        layout.addLayout(main_layout)
        
        return widget
        
    def _create_port_filter_tab(self) -> QWidget:
        """创建端口过滤标签页
        
        Returns:
            QWidget: 端口过滤标签页
        """
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 创建黑名单和白名单组
        blacklist_group = QGroupBox("端口黑名单")
        blacklist_layout = QVBoxLayout(blacklist_group)
        
        # 添加端口输入和按钮
        bl_input_layout = QHBoxLayout()
        self.bl_port_input = QSpinBox()
        self.bl_port_input.setRange(0, 65535)
        self.bl_port_input.setValue(80)
        bl_input_layout.addWidget(self.bl_port_input)
        
        bl_add_button = QPushButton("添加")
        bl_add_button.clicked.connect(self._add_port_to_blacklist)
        bl_input_layout.addWidget(bl_add_button)
        
        blacklist_layout.addLayout(bl_input_layout)
        
        # 黑名单列表
        self.bl_port_list = QListWidget()
        self.bl_port_list.itemDoubleClicked.connect(self._remove_port_from_blacklist)
        blacklist_layout.addWidget(self.bl_port_list)
        
        # 创建白名单组
        whitelist_group = QGroupBox("端口白名单")
        whitelist_layout = QVBoxLayout(whitelist_group)
        
        # 添加端口输入和按钮
        wl_input_layout = QHBoxLayout()
        self.wl_port_input = QSpinBox()
        self.wl_port_input.setRange(0, 65535)
        self.wl_port_input.setValue(443)
        wl_input_layout.addWidget(self.wl_port_input)
        
        wl_add_button = QPushButton("添加")
        wl_add_button.clicked.connect(self._add_port_to_whitelist)
        wl_input_layout.addWidget(wl_add_button)
        
        whitelist_layout.addLayout(wl_input_layout)
        
        # 白名单列表
        self.wl_port_list = QListWidget()
        self.wl_port_list.itemDoubleClicked.connect(self._remove_port_from_whitelist)
        whitelist_layout.addWidget(self.wl_port_list)
        
        # 添加到主布局
        main_layout = QHBoxLayout()
        main_layout.addWidget(blacklist_group)
        main_layout.addWidget(whitelist_group)
        layout.addLayout(main_layout)
        
        return widget
        
    def _create_content_filter_tab(self) -> QWidget:
        """创建内容过滤标签页
        
        Returns:
            QWidget: 内容过滤标签页
        """
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 创建内容过滤组
        filter_group = QGroupBox("内容过滤")
        filter_layout = QVBoxLayout(filter_group)
        
        # 添加内容输入和按钮
        input_layout = QHBoxLayout()
        self.content_filter_input = QLineEdit()
        self.content_filter_input.setPlaceholderText("输入要过滤的内容...")
        input_layout.addWidget(self.content_filter_input)
        
        add_button = QPushButton("添加")
        add_button.clicked.connect(self._add_content_filter)
        input_layout.addWidget(add_button)
        
        filter_layout.addLayout(input_layout)
        
        # 过滤规则列表
        self.content_filter_list = QListWidget()
        self.content_filter_list.itemDoubleClicked.connect(self._remove_content_filter)
        filter_layout.addWidget(self.content_filter_list)
        
        # 添加到主布局
        layout.addWidget(filter_group)
        
        # 添加使用说明
        help_label = QLabel(
            "说明: 内容过滤将匹配数据包载荷中的文本内容。\n"
            "双击列表中的项目可以移除该规则。\n"
            "注意: 内容过滤可能会影响性能，请谨慎使用。"
        )
        layout.addWidget(help_label)
        
        return widget
        
    def _create_log_tab(self) -> QWidget:
        """创建日志标签页
        
        Returns:
            QWidget: 日志标签页
        """
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 创建日志表格
        self.log_table = QTableWidget()
        self.log_table.setColumnCount(8)
        self.log_table.setHorizontalHeaderLabels([
            "时间", "源IP", "目标IP", "源端口", "目标端口", 
            "协议", "动作", "大小(字节)"
        ])
        
        # 设置表格属性
        header = self.log_table.horizontalHeader()
        # 在PyQt6中，为了兼容不同版本，使用以下设置方式
        try:
            header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        except:
            # 降级处理，适配较老版本的PyQt6
            header.setSectionResizeMode(QHeaderView.SectionResizeMode.Stretch)
        
        layout.addWidget(self.log_table)
        
        # 添加控制按钮
        button_layout = QHBoxLayout()
        
        clear_button = QPushButton("清除日志")
        clear_button.clicked.connect(self._clear_logs)
        button_layout.addWidget(clear_button)
        
        refresh_button = QPushButton("刷新")
        refresh_button.clicked.connect(self._update_logs)
        button_layout.addWidget(refresh_button)
        
        layout.addLayout(button_layout)
        
        return widget
        
    def _toggle_firewall(self):
        """切换防火墙启动/停止状态"""
        if self.firewall.is_running:
            # 停止防火墙
            if self.firewall.stop():
                self.start_button.setText("启动防火墙")
                self.status_label.setText("状态: 已停止")
                QMessageBox.information(self, "提示", "防火墙已停止")
        else:
            # 启动防火墙
            if self.firewall.start():
                self.start_button.setText("停止防火墙")
                self.status_label.setText("状态: 运行中")
                QMessageBox.information(self, "提示", "防火墙已启动")
            else:
                QMessageBox.critical(self, "错误", "防火墙启动失败，请检查是否以管理员权限运行")
    
    def _update_status(self):
        """更新状态和统计信息"""
        status = self.firewall.get_status()
        
        # 更新统计信息
        if status['running']:
            stats = status['stats']
            self.stats_label.setText(
                f"总数据包: {stats['total_packets']} | "
                f"拦截: {stats['dropped_packets']} | "
                f"放行: {stats['passed_packets']}"
            )
            
        # 更新日志
        self._update_logs()
        
        # 更新规则列表
        self._update_rule_lists()
        
    def _update_logs(self):
        """更新日志表格"""
        logs = self.firewall.get_logs()
        
        # 设置表格行数
        self.log_table.setRowCount(len(logs))
        
        # 填充日志数据
        for i, log in enumerate(reversed(logs)):
            if isinstance(log, dict):
                # 时间
                if 'time' in log:
                    time_str = datetime.fromtimestamp(log['time']).strftime('%Y-%m-%d %H:%M:%S')
                    self.log_table.setItem(i, 0, QTableWidgetItem(time_str))
                
                # IP地址
                if 'src_ip' in log:
                    self.log_table.setItem(i, 1, QTableWidgetItem(log['src_ip']))
                if 'dst_ip' in log:
                    self.log_table.setItem(i, 2, QTableWidgetItem(log['dst_ip']))
                
                # 端口
                if 'src_port' in log:
                    self.log_table.setItem(i, 3, QTableWidgetItem(str(log['src_port'])))
                if 'dst_port' in log:
                    self.log_table.setItem(i, 4, QTableWidgetItem(str(log['dst_port'])))
                
                # 协议
                if 'protocol' in log:
                    self.log_table.setItem(i, 5, QTableWidgetItem(log['protocol']))
                
                # 动作
                if 'action' in log:
                    action_item = QTableWidgetItem(log['action'])
                    if log['action'] == '拦截':
                        action_item.setForeground(QColor('red'))
                    else:
                        action_item.setForeground(QColor('green'))
                    self.log_table.setItem(i, 6, action_item)
                
                # 大小
                if 'packet_size' in log:
                    self.log_table.setItem(i, 7, QTableWidgetItem(str(log['packet_size'])))
            elif isinstance(log, str):
                # 文本日志
                self.log_table.setItem(i, 0, QTableWidgetItem(
                    datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                ))
                text_item = QTableWidgetItem(log)
                text_item.setForeground(QColor('blue'))
                self.log_table.setItem(i, 1, text_item)
                
    def _clear_logs(self):
        """清除日志"""
        self.firewall.logs = []
        self.log_table.setRowCount(0)
        
    def _update_rule_lists(self):
        """更新规则列表"""
        rules = self.firewall.rule_manager.get_rules()
        
        # 更新IP黑名单
        self._update_list_widget(self.bl_ip_list, rules['ip_blacklist'])
        
        # 更新IP白名单
        self._update_list_widget(self.wl_ip_list, rules['ip_whitelist'])
        
        # 更新端口黑名单
        self._update_list_widget(self.bl_port_list, rules['port_blacklist'])
        
        # 更新端口白名单
        self._update_list_widget(self.wl_port_list, rules['port_whitelist'])
        
        # 更新内容过滤规则
        self._update_list_widget(self.content_filter_list, rules['content_filters'])
        
    def _update_list_widget(self, list_widget, items):
        """更新列表控件内容，避免重复添加
        
        Args:
            list_widget: 列表控件
            items: 项目列表
        """
        # 获取当前列表内容
        current_items = set()
        for i in range(list_widget.count()):
            current_items.add(list_widget.item(i).text())
            
        # 添加新项目
        for item in items:
            item_str = str(item)
            if item_str not in current_items:
                list_widget.addItem(item_str)
                
        # 移除已删除的项目
        items_set = set(str(item) for item in items)
        for i in range(list_widget.count() - 1, -1, -1):
            if list_widget.item(i).text() not in items_set:
                list_widget.takeItem(i)
    
    # IP黑白名单操作
    def _add_ip_to_blacklist(self):
        """添加IP到黑名单"""
        ip = self.bl_ip_input.text().strip()
        if ip:
            if self.firewall.add_ip_to_blacklist(ip):
                self.bl_ip_input.clear()
            else:
                QMessageBox.warning(self, "警告", f"无效的IP地址: {ip}")
                
    def _remove_ip_from_blacklist(self, item):
        """从黑名单移除IP"""
        ip = item.text()
        if self.firewall.remove_ip_from_blacklist(ip):
            self.bl_ip_list.takeItem(self.bl_ip_list.row(item))
            
    def _add_ip_to_whitelist(self):
        """添加IP到白名单"""
        ip = self.wl_ip_input.text().strip()
        if ip:
            if self.firewall.add_ip_to_whitelist(ip):
                self.wl_ip_input.clear()
            else:
                QMessageBox.warning(self, "警告", f"无效的IP地址: {ip}")
                
    def _remove_ip_from_whitelist(self, item):
        """从白名单移除IP"""
        ip = item.text()
        if self.firewall.remove_ip_from_whitelist(ip):
            self.wl_ip_list.takeItem(self.wl_ip_list.row(item))
            
    # 端口黑白名单操作
    def _add_port_to_blacklist(self):
        """添加端口到黑名单"""
        port = self.bl_port_input.value()
        if self.firewall.add_port_to_blacklist(port):
            # 不需要清除，让用户继续添加其他端口
            pass
        else:
            QMessageBox.warning(self, "警告", f"添加端口失败: {port}")
            
    def _remove_port_from_blacklist(self, item):
        """从黑名单移除端口"""
        try:
            port = int(item.text())
            if self.firewall.remove_port_from_blacklist(port):
                self.bl_port_list.takeItem(self.bl_port_list.row(item))
        except ValueError:
            pass
            
    def _add_port_to_whitelist(self):
        """添加端口到白名单"""
        port = self.wl_port_input.value()
        if self.firewall.add_port_to_whitelist(port):
            # 不需要清除，让用户继续添加其他端口
            pass
        else:
            QMessageBox.warning(self, "警告", f"添加端口失败: {port}")
            
    def _remove_port_from_whitelist(self, item):
        """从白名单移除端口"""
        try:
            port = int(item.text())
            if self.firewall.remove_port_from_whitelist(port):
                self.wl_port_list.takeItem(self.wl_port_list.row(item))
        except ValueError:
            pass
            
    # 内容过滤操作
    def _add_content_filter(self):
        """添加内容过滤规则"""
        pattern = self.content_filter_input.text().strip()
        if pattern:
            if self.firewall.add_content_filter(pattern):
                self.content_filter_input.clear()
            else:
                QMessageBox.warning(self, "警告", f"添加内容过滤规则失败: {pattern}")
                
    def _remove_content_filter(self, item):
        """移除内容过滤规则"""
        pattern = item.text()
        if self.firewall.remove_content_filter(pattern):
            self.content_filter_list.takeItem(self.content_filter_list.row(item))
            
    def closeEvent(self, event):
        """窗口关闭事件"""
        # 停止防火墙
        if self.firewall.is_running:
            self.firewall.stop()
        
        # 停止定时器
        self.update_timer.stop()
        
        # 接受关闭事件
        event.accept() 