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
        
        # 记录上次更新时间以优化定时器处理
        self.last_update_time = 0
        self.update_interval = 1000  # 毫秒
        
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
        self.tab_widget.addTab(self._create_performance_tab(), "性能监控")
        self.tab_widget.addTab(self._create_advanced_settings_tab(), "高级设置")
        self.tab_widget.addTab(self._create_log_tab(), "日志")
        
        main_layout.addWidget(self.tab_widget)
        
    def _create_control_panel(self) -> QWidget:
        """创建控制面板
        
        Returns:
            QWidget: 控制面板组件
        """
        # 创建控制面板组
        group_box = QGroupBox("控制面板")
        layout = QVBoxLayout(group_box)
        
        # 创建状态和控制的水平布局
        status_layout = QHBoxLayout()
        
        # 创建状态标签
        status_box = QGroupBox("状态信息")
        status_box_layout = QVBoxLayout(status_box)
        
        self.status_label = QLabel("状态: 已停止")
        status_box_layout.addWidget(self.status_label)
        
        # 创建统计信息标签
        self.stats_label = QLabel("总数据包: 0 | 拦截: 0 | 放行: 0")
        status_box_layout.addWidget(self.stats_label)
        
        # 添加资源使用情况标签
        self.resource_label = QLabel("CPU: 0% | 内存: 0%")
        status_box_layout.addWidget(self.resource_label)
        
        status_layout.addWidget(status_box, stretch=3)
        
        # 创建控制选项的分组框
        controls_box = QGroupBox("控制选项")
        controls_layout = QVBoxLayout(controls_box)
        
        # 创建协议过滤布局
        protocol_layout = QHBoxLayout()
        protocol_layout.addWidget(QLabel("允许协议:"))
        
        self.tcp_checkbox = QCheckBox("TCP")
        self.tcp_checkbox.setChecked(True)
        self.tcp_checkbox.toggled.connect(lambda checked: self.firewall.set_protocol_filter("tcp", checked))
        protocol_layout.addWidget(self.tcp_checkbox)
        
        self.udp_checkbox = QCheckBox("UDP")
        self.udp_checkbox.setChecked(True)
        self.udp_checkbox.toggled.connect(lambda checked: self.firewall.set_protocol_filter("udp", checked))
        protocol_layout.addWidget(self.udp_checkbox)
        
        controls_layout.addLayout(protocol_layout)
        
        # 创建启动/停止按钮
        button_layout = QHBoxLayout()
        
        self.start_button = QPushButton("启动防火墙")
        self.start_button.clicked.connect(self._toggle_firewall)
        self.start_button.setMinimumHeight(40)  # 更大的按钮
        button_layout.addWidget(self.start_button)
        
        self.restart_button = QPushButton("重启防火墙")
        self.restart_button.clicked.connect(self._restart_firewall)
        button_layout.addWidget(self.restart_button)
        
        controls_layout.addLayout(button_layout)
        
        status_layout.addWidget(controls_box, stretch=2)
        
        # 添加状态和控制布局到主布局
        layout.addLayout(status_layout)
        
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
        
    def _create_performance_tab(self) -> QWidget:
        """创建性能监控标签页
        
        Returns:
            QWidget: 性能监控标签页
        """
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 创建性能统计区域
        stats_group = QGroupBox("性能统计")
        stats_layout = QFormLayout(stats_group)
        
        # 添加详细统计信息
        self.perf_total_packets = QLabel("0")
        stats_layout.addRow("总处理数据包:", self.perf_total_packets)
        
        self.perf_dropped_packets = QLabel("0")
        stats_layout.addRow("已拦截数据包:", self.perf_dropped_packets)
        
        self.perf_passed_packets = QLabel("0")
        stats_layout.addRow("已放行数据包:", self.perf_passed_packets)
        
        self.perf_error_packets = QLabel("0")
        stats_layout.addRow("处理错误数据包:", self.perf_error_packets)
        
        self.perf_packets_per_second = QLabel("0")
        stats_layout.addRow("每秒处理数据包:", self.perf_packets_per_second)
        
        self.perf_win_error_87 = QLabel("0")
        stats_layout.addRow("WinError 87计数:", self.perf_win_error_87)
        
        layout.addWidget(stats_group)
        
        # 创建系统资源使用情况区域
        resource_group = QGroupBox("系统资源使用")
        resource_layout = QFormLayout(resource_group)
        
        self.resource_cpu = QLabel("0%")
        resource_layout.addRow("CPU使用率:", self.resource_cpu)
        
        self.resource_memory = QLabel("0%")
        resource_layout.addRow("内存使用率:", self.resource_memory)
        
        self.resource_network_in = QLabel("0 KB/s")
        resource_layout.addRow("网络流入:", self.resource_network_in)
        
        self.resource_network_out = QLabel("0 KB/s")
        resource_layout.addRow("网络流出:", self.resource_network_out)
        
        layout.addWidget(resource_group)
        
        # 添加问题诊断区域
        diagnosis_group = QGroupBox("问题诊断")
        diagnosis_layout = QVBoxLayout(diagnosis_group)
        
        self.diagnosis_text = QTextEdit()
        self.diagnosis_text.setReadOnly(True)
        diagnosis_layout.addWidget(self.diagnosis_text)
        
        diagnosis_button = QPushButton("运行诊断")
        diagnosis_button.clicked.connect(self._run_diagnosis)
        diagnosis_layout.addWidget(diagnosis_button)
        
        layout.addWidget(diagnosis_group)
        
        return widget
        
    def _create_advanced_settings_tab(self) -> QWidget:
        """创建高级设置标签页
        
        Returns:
            QWidget: 高级设置标签页
        """
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # 性能优化设置
        perf_group = QGroupBox("性能优化设置")
        perf_layout = QFormLayout(perf_group)
        
        # 使用批处理模式
        self.use_batch_mode = QCheckBox()
        self.use_batch_mode.setChecked(True)
        self.use_batch_mode.toggled.connect(lambda checked: self._update_adaptive_setting('use_batch_mode', checked))
        perf_layout.addRow("使用批处理模式:", self.use_batch_mode)
        
        # 批处理大小
        self.batch_size = QSpinBox()
        self.batch_size.setRange(1, 50)
        self.batch_size.setValue(5)
        self.batch_size.valueChanged.connect(lambda value: self._update_adaptive_setting('batch_size', value))
        perf_layout.addRow("批处理大小:", self.batch_size)
        
        # 跳过大型数据包
        self.skip_large_packets = QCheckBox()
        self.skip_large_packets.setChecked(False)
        self.skip_large_packets.toggled.connect(lambda checked: self._update_adaptive_setting('skip_large_packets', checked))
        perf_layout.addRow("跳过大型数据包:", self.skip_large_packets)
        
        # 大型数据包阈值
        self.large_packet_threshold = QSpinBox()
        self.large_packet_threshold.setRange(500, 5000)
        self.large_packet_threshold.setValue(1460)
        self.large_packet_threshold.setSingleStep(100)
        self.large_packet_threshold.valueChanged.connect(lambda value: self._update_adaptive_setting('large_packet_threshold', value))
        perf_layout.addRow("大型数据包阈值(字节):", self.large_packet_threshold)
        
        # 跳过本地数据包
        self.skip_local_packets = QCheckBox()
        self.skip_local_packets.setChecked(True)
        self.skip_local_packets.toggled.connect(lambda checked: self._update_adaptive_setting('skip_local_packets', checked))
        perf_layout.addRow("跳过本地数据包:", self.skip_local_packets)
        
        # 允许本地网络通信
        self.allow_private_network = QCheckBox()
        self.allow_private_network.setChecked(True)
        self.allow_private_network.toggled.connect(lambda checked: self._update_adaptive_setting('allow_private_network', checked))
        perf_layout.addRow("允许本地网络通信:", self.allow_private_network)
        
        layout.addWidget(perf_group)
        
        # 高级控制设置
        control_group = QGroupBox("高级控制设置")
        control_layout = QFormLayout(control_group)
        
        # 重启WinDivert
        restart_windivert_button = QPushButton("重启WinDivert")
        restart_windivert_button.clicked.connect(self._restart_windivert)
        control_layout.addRow("WinDivert问题修复:", restart_windivert_button)
        
        layout.addWidget(control_group)
        
        # 应用设置按钮
        apply_button = QPushButton("应用设置")
        apply_button.clicked.connect(self._apply_advanced_settings)
        layout.addWidget(apply_button)
        
        # 读取当前设置并更新UI
        self._load_advanced_settings()
        
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
        current_time = time.time()
        time_diff = current_time - self.last_update_time
        
        # 限制更新频率，避免UI过载
        if time_diff < (self.update_interval / 1000):
            return
            
        self.last_update_time = current_time
        
        # 获取防火墙状态
        try:
            status = self.firewall.get_status()
            
            # 更新统计信息
            if status['running']:
                stats = status['stats']
                self.stats_label.setText(
                    f"总数据包: {stats.get('total_packets', 0)} | "
                    f"拦截: {stats.get('dropped_packets', 0)} | "
                    f"放行: {stats.get('passed_packets', 0)}"
                )
                
                # 更新资源使用情况
                if 'diagnosis' in status and 'system_resources' in status['diagnosis']:
                    resources = status['diagnosis']['system_resources']
                    self.resource_label.setText(
                        f"CPU: {resources.get('cpu_percent', 0)}% | "
                        f"内存: {resources.get('memory_percent', 0)}%"
                    )
                
                # 更新性能监控标签页
                self._update_performance_tab(stats, status)
            
            # 更新日志
            self._update_logs()
            
            # 更新规则列表
            self._update_rule_lists()
        except Exception as e:
            # 错误处理更健壮
            import traceback
            print(f"更新状态时出错: {e}")
            print(traceback.format_exc())
        
    def _update_performance_tab(self, stats, status):
        """更新性能监控标签页
        
        Args:
            stats: 统计信息
            status: 防火墙状态
        """
        try:
            # 更新基本统计数据
            self.perf_total_packets.setText(str(stats.get('total_packets', 0)))
            self.perf_dropped_packets.setText(str(stats.get('dropped_packets', 0)))
            self.perf_passed_packets.setText(str(stats.get('passed_packets', 0)))
            self.perf_error_packets.setText(str(stats.get('error_packets', 0)))
            self.perf_win_error_87.setText(str(stats.get('win_error_87_count', 0)))
            
            # 计算每秒处理数据包数
            if 'start_time' in stats and stats['total_packets'] > 0:
                running_time = time.time() - stats['start_time']
                packets_per_second = stats['total_packets'] / max(1, running_time)
                self.perf_packets_per_second.setText(f"{packets_per_second:.2f}")
            
            # 更新系统资源使用情况
            if 'diagnosis' in status and 'system_resources' in status['diagnosis']:
                resources = status['diagnosis']['system_resources']
                
                self.resource_cpu.setText(f"{resources.get('cpu_percent', 0)}%")
                self.resource_memory.setText(f"{resources.get('memory_percent', 0)}%")
                
                # 更新网络IO信息
                if 'io_counters' in resources:
                    io = resources['io_counters']
                    # 转换为KB/s
                    bytes_recv = io.get('bytes_recv', 0) / 1024
                    bytes_sent = io.get('bytes_sent', 0) / 1024
                    self.resource_network_in.setText(f"{bytes_recv:.2f} KB/s")
                    self.resource_network_out.setText(f"{bytes_sent:.2f} KB/s")
            
            # 更新诊断信息
            if 'diagnosis' in status:
                diagnosis = status['diagnosis']
                
                # 构建诊断文本
                diag_text = "系统诊断结果:\n\n"
                
                if 'windivert_status' in diagnosis:
                    status_map = {
                        'normal': '正常',
                        'problematic': '有问题',
                        'not_registered': '未注册',
                        'unknown': '未知'
                    }
                    diag_text += f"WinDivert状态: {status_map.get(diagnosis['windivert_status'], '未知')}\n"
                
                if 'recommendations' in diagnosis and diagnosis['recommendations']:
                    diag_text += "\n推荐操作:\n"
                    for i, rec in enumerate(diagnosis['recommendations'], 1):
                        diag_text += f"{i}. {rec}\n"
                
                if 'win87_error_ratio' in diagnosis:
                    diag_text += f"\nWinError 87错误比例: {diagnosis['win87_error_ratio']:.2%}\n"
                
                if 'success_ratio' in diagnosis:
                    diag_text += f"数据包处理成功率: {diagnosis['success_ratio']:.2%}\n"
                
                self.diagnosis_text.setText(diag_text)
        except Exception as e:
            import traceback
            print(f"更新性能监控标签页时出错: {e}")
            print(traceback.format_exc())
            
    def _run_diagnosis(self):
        """运行系统诊断"""
        try:
            detailed_stats = self.firewall.get_detailed_stats()
            diagnosis = self.firewall.packet_filter._diagnose_problem()
            
            # 显示诊断结果
            diag_text = "系统诊断结果:\n\n"
            
            # 添加WinDivert状态
            if 'windivert_status' in diagnosis:
                status_map = {
                    'normal': '正常',
                    'problematic': '有问题',
                    'not_registered': '未注册',
                    'unknown': '未知'
                }
                diag_text += f"WinDivert状态: {status_map.get(diagnosis['windivert_status'], '未知')}\n"
            
            # 添加详细统计
            diag_text += f"\n详细统计:\n"
            diag_text += f"总处理数据包: {detailed_stats.get('total_packets', 0)}\n"
            diag_text += f"已拦截数据包: {detailed_stats.get('dropped_packets', 0)}\n"
            diag_text += f"已放行数据包: {detailed_stats.get('passed_packets', 0)}\n"
            diag_text += f"处理错误数据包: {detailed_stats.get('error_packets', 0)}\n"
            
            if 'packets_per_second' in detailed_stats:
                diag_text += f"每秒处理数据包: {detailed_stats['packets_per_second']:.2f}\n"
            
            # 添加推荐操作
            if 'recommendations' in diagnosis and diagnosis['recommendations']:
                diag_text += "\n推荐操作:\n"
                for i, rec in enumerate(diagnosis['recommendations'], 1):
                    diag_text += f"{i}. {rec}\n"
            
            # 添加错误类型统计
            if 'error_types' in diagnosis:
                diag_text += "\n错误类型统计:\n"
                for error_type, count in diagnosis['error_types'].items():
                    diag_text += f"{error_type}: {count}次\n"
            
            # 系统资源使用情况
            if 'system_resources' in detailed_stats:
                resources = detailed_stats['system_resources']
                diag_text += f"\n系统资源使用情况:\n"
                diag_text += f"CPU使用率: {resources.get('cpu_percent', 0)}%\n"
                diag_text += f"内存使用率: {resources.get('memory_percent', 0)}%\n"
            
            # 更新诊断文本
            self.diagnosis_text.setText(diag_text)
            
        except Exception as e:
            import traceback
            self.diagnosis_text.setText(f"运行诊断时出错: {str(e)}\n\n{traceback.format_exc()}")
            
    def _restart_firewall(self):
        """重启防火墙"""
        # 先停止防火墙
        if self.firewall.is_running:
            if not self.firewall.stop():
                QMessageBox.warning(self, "警告", "停止防火墙失败")
                return
        
        # 等待资源释放
        QApplication.processEvents()
        time.sleep(1)
        
        # 重新启动防火墙
        if self.firewall.start():
            self.start_button.setText("停止防火墙")
            self.status_label.setText("状态: 运行中")
            QMessageBox.information(self, "提示", "防火墙已重启")
        else:
            self.start_button.setText("启动防火墙")
            self.status_label.setText("状态: 已停止")
            QMessageBox.critical(self, "错误", "防火墙重启失败")
            
    def _restart_windivert(self):
        """重启WinDivert驱动"""
        if not self.firewall.is_running:
            QMessageBox.warning(self, "警告", "防火墙未运行，无法重启WinDivert")
            return
            
        # 尝试重启WinDivert
        if self.firewall.restart_windivert():
            QMessageBox.information(self, "提示", "WinDivert已重启")
        else:
            QMessageBox.critical(self, "错误", "WinDivert重启失败")
            
    def _load_advanced_settings(self):
        """加载高级设置"""
        try:
            settings = self.firewall.performance_settings
            
            # 更新UI元素
            self.use_batch_mode.setChecked(settings.get('use_batch_mode', True))
            self.batch_size.setValue(settings.get('batch_size', 5))
            self.skip_large_packets.setChecked(settings.get('skip_large_packets', False))
            self.large_packet_threshold.setValue(settings.get('large_packet_threshold', 1460))
            self.skip_local_packets.setChecked(settings.get('skip_local_packets', True))
            self.allow_private_network.setChecked(settings.get('allow_private_network', True))
        except Exception as e:
            QMessageBox.warning(self, "警告", f"加载设置失败: {str(e)}")
            
    def _update_adaptive_setting(self, key, value):
        """更新自适应设置项
        
        Args:
            key: 设置项键名
            value: 设置项值
        """
        try:
            # 仅更新内存中的设置，不立即应用
            if hasattr(self.firewall, 'performance_settings'):
                self.firewall.performance_settings[key] = value
        except Exception as e:
            QMessageBox.warning(self, "警告", f"更新设置项失败: {str(e)}")
            
    def _apply_advanced_settings(self):
        """应用高级设置"""
        try:
            # 更新防火墙的性能设置
            settings = {
                'use_batch_mode': self.use_batch_mode.isChecked(),
                'batch_size': self.batch_size.value(),
                'skip_large_packets': self.skip_large_packets.isChecked(),
                'large_packet_threshold': self.large_packet_threshold.value(),
                'skip_local_packets': self.skip_local_packets.isChecked(),
                'allow_private_network': self.allow_private_network.isChecked()
            }
            
            # 应用设置
            self.firewall.update_performance_settings(settings)
            
            QMessageBox.information(self, "提示", "设置已应用")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"应用设置失败: {str(e)}")
        
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