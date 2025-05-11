#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import time
from typing import Dict # Added Any
import logging 

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QTabWidget, QMessageBox, QCheckBox, QGroupBox, QFileDialog
)
# Import QObject and pyqtSignal for custom signals
from PyQt6.QtCore import QTimer, pyqtSlot, pyqtSignal

from ..core.firewall import Firewall
# Import new tab classes
from .tabs.ip_filter_tab import IpFilterTab
from .tabs.port_filter_tab import PortFilterTab
from .tabs.content_filter_tab import ContentFilterTab
from .tabs.performance_tab import PerformanceTab
from .tabs.advanced_settings_tab import AdvancedSettingsTab
from .tabs.log_tab import LogTab
from .tabs.traffic_monitor_tab import TrafficMonitorTab  # 导入新的流量监控标签页

# Get logger for UI module
logger = logging.getLogger('MainWindowUI')

class MainWindow(QMainWindow):
    """防火墙主窗口"""
    # Define signals to safely update UI from other threads
    log_entry_received = pyqtSignal(dict)
    traffic_packet_received = pyqtSignal(dict)
    # rules_ui_updated_signal = pyqtSignal() # New signal for rule UI updates
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        self.firewall = Firewall()
        self.setWindowTitle("简易防火墙")
        self.setMinimumSize(800, 600)
        self.last_update_time = 0
        self.update_interval = 1000  # ms
        # Removed self.traffic_update_interval

        # Create UI components (now instantiates tab widgets)
        self._create_ui()
        
        # Setup timer for status and rule list updates
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self._update_status)
        self.update_timer.start(1000)
        
        # Removed traffic_timer setup

        # Connect signals from core and tabs
        self._connect_signals()
        
        # Initial load of data into UI
        self._update_rule_lists()
        self._load_advanced_settings()
        
        # 注册数据包处理回调
        self.firewall.register_packet_callback(self._handle_packet)

    def _create_ui(self):
        """创建UI组件，包括实例化和添加标签页"""
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Create control panel (remains in MainWindow)
        self.control_panel = self._create_control_panel() 
        main_layout.addWidget(self.control_panel)

        # Create Tab Widget
        self.tab_widget = QTabWidget(self)
        
        # Instantiate Tab Widgets
        self.ip_filter_tab = IpFilterTab()
        self.port_filter_tab = PortFilterTab()
        self.content_filter_tab = ContentFilterTab()
        self.performance_tab = PerformanceTab()
        self.advanced_settings_tab = AdvancedSettingsTab()
        self.log_tab = LogTab()
        self.traffic_monitor_tab = TrafficMonitorTab()  # 实例化流量监控标签页

        # Add Tabs
        self.tab_widget.addTab(self.ip_filter_tab, "IP过滤")
        self.tab_widget.addTab(self.port_filter_tab, "端口过滤")
        self.tab_widget.addTab(self.content_filter_tab, "内容过滤")
        self.tab_widget.addTab(self.traffic_monitor_tab, "流量监控")  # 添加流量监控标签页
        self.tab_widget.addTab(self.performance_tab, "性能监控")
        self.tab_widget.addTab(self.advanced_settings_tab, "高级设置")
        self.tab_widget.addTab(self.log_tab, "日志")
        
        main_layout.addWidget(self.tab_widget)

    def _connect_signals(self):
        """连接所有信号和槽"""
        # --- Core Firewall Signals ---
        # Connect core log signal to a MainWindow slot that emits a UI-safe signal
        self.firewall.log_signal.connect(self._handle_core_log_signal)
        # Connect the UI-safe signal to the LogTab slot
        self.log_entry_received.connect(self.log_tab.add_log_entry)

        # Connect the UI-safe traffic signal to the TrafficMonitorTab slot
        self.traffic_packet_received.connect(self.traffic_monitor_tab.add_packet)

        # Connect the rules updated signal from Firewall core to the UI update method
        self.firewall.rules_updated_signal.connect(self._update_rule_lists)

        # --- Tab Signals ---
        # IP Filter Tab signals
        self.ip_filter_tab.add_blacklist_requested.connect(self._add_ip_to_blacklist)
        self.ip_filter_tab.remove_blacklist_requested.connect(self._remove_ip_from_blacklist)
        self.ip_filter_tab.add_whitelist_requested.connect(self._add_ip_to_whitelist)
        self.ip_filter_tab.remove_whitelist_requested.connect(self._remove_ip_from_whitelist)
        self.ip_filter_tab.import_list_requested.connect(self._import_ip_list)
        self.ip_filter_tab.export_list_requested.connect(self._export_ip_list)

        # Port Filter Tab signals
        self.port_filter_tab.add_blacklist_requested.connect(self._add_port_to_blacklist)
        self.port_filter_tab.remove_blacklist_requested.connect(self._remove_port_from_blacklist)
        self.port_filter_tab.add_whitelist_requested.connect(self._add_port_to_whitelist)
        self.port_filter_tab.remove_whitelist_requested.connect(self._remove_port_from_whitelist)

        # Content Filter Tab signals
        self.content_filter_tab.add_filter_requested.connect(self._add_content_filter)
        self.content_filter_tab.remove_filter_requested.connect(self._remove_content_filter)

        # Performance Tab signals
        self.performance_tab.run_diagnosis_requested.connect(self._run_diagnosis)

        # Advanced Settings Tab signals
        self.advanced_settings_tab.apply_settings_requested.connect(self._apply_advanced_settings)
        self.advanced_settings_tab.restart_windivert_requested.connect(self._restart_windivert)
        
        # 流量监控标签页信号
        self.traffic_monitor_tab.clear_traffic_requested.connect(self._clear_traffic_monitor) # Keep clear connection
        # Removed connections for pause_monitoring_toggled and refresh_rate.valueChanged

    # --- 流量监控相关方法 ---
    def _handle_packet(self, packet_info: Dict, passed: bool):
        """处理从防火墙接收的数据包信息
        
        Args:
            packet_info: 数据包信息字典
            passed: 是否放行
        """
        # 准备添加到流量监控的数据包信息
        monitor_info = packet_info.copy()
        
        # 添加时间戳
        monitor_info["time"] = time.strftime("%H:%M:%S")
        
        # 添加方向信息 (修正：从 packet_info 获取 'direction')
        # 'direction' 键的值应为 'inbound' 或 'outbound' (来自 get_packet_info)
        direction_from_core = packet_info.get('direction', 'unknown').lower()
        if direction_from_core == 'outbound':
             monitor_info["direction"] = "出站"
        elif direction_from_core == 'inbound':
             monitor_info["direction"] = "入站"
        else:
             monitor_info["direction"] = "未知" # Fallback
            
        # 添加动作信息
        monitor_info["action"] = "放行" if passed else "拦截"
        
        # 发送到流量监控标签页 - CHANGE: Emit signal instead of direct call
        self.traffic_packet_received.emit(monitor_info)

    # Slot to handle log signal from core firewall (potentially different thread)
    @pyqtSlot(dict)
    def _handle_core_log_signal(self, log_entry: dict):
        """Receives log entry from core and emits a signal safe for UI thread."""
        # Simply emit the signal, Qt handles thread marshalling via QueuedConnection (default)
        self.log_entry_received.emit(log_entry)

    # Removed _update_traffic_monitor method
        
    def _clear_traffic_monitor(self):
        """清除流量监控数据 (Slot connected from TrafficMonitorTab)"""
        # This method might still be useful if MainWindow needs to coordinate
        # clearing across multiple components or interact with the core.
        # For now, it just logs. If TrafficMonitorTab handles everything,
        # this connection could potentially be removed too.
        logger.info("清除流量监控数据请求已收到。")
        # If TrafficMonitorTab handles its own clearing, no further action needed here.
        
    # Removed _toggle_traffic_monitoring method
            
    # Removed _set_traffic_update_interval method

    # --- Control Panel Creation (Remains in MainWindow) ---
    def _create_control_panel(self) -> QWidget:
        """创建控制面板"""
        # (Code is identical to the previous version, just ensure self. references are correct)
        group_box = QGroupBox("控制面板")
        layout = QVBoxLayout(group_box)
        status_layout = QHBoxLayout()
        status_box = QGroupBox("状态信息")
        status_box_layout = QVBoxLayout(status_box)
        
        self.status_label = QLabel("状态: 已停止")
        status_box_layout.addWidget(self.status_label)
        self.stats_label = QLabel("总处理: 0 | 拦截: 0 | 放行: 0") 
        status_box_layout.addWidget(self.stats_label)
        self.resource_label = QLabel("CPU: 0% | 内存: 0%")
        status_box_layout.addWidget(self.resource_label)
        status_layout.addWidget(status_box, stretch=3)
        
        controls_box = QGroupBox("控制选项")
        controls_layout = QVBoxLayout(controls_box)
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
        
        button_layout = QHBoxLayout()
        self.start_button = QPushButton("启动防火墙")
        self.start_button.clicked.connect(self._toggle_firewall)
        self.start_button.setMinimumHeight(40)
        button_layout.addWidget(self.start_button)
        self.restart_button = QPushButton("重启防火墙")
        self.restart_button.clicked.connect(self._restart_firewall)
        button_layout.addWidget(self.restart_button)
        controls_layout.addLayout(button_layout)
        status_layout.addWidget(controls_box, stretch=2)
        layout.addLayout(status_layout)
        return group_box

    # Removed _create_*_tab methods as they are now in separate classes

    # --- Core Logic Slots ---
    def _toggle_firewall(self):
        """切换防火墙启动/停止状态"""
        if self.firewall.is_running:
            if self.firewall.stop():
                self.start_button.setText("启动防火墙")
                self.status_label.setText("状态: 已停止")
                QMessageBox.information(self, "提示", "防火墙已停止")
        else:
            if self.firewall.start():
                self.start_button.setText("停止防火墙")
                self.status_label.setText("状态: 运行中")
                QMessageBox.information(self, "提示", "防火墙已启动")
            else:
                QMessageBox.critical(self, "错误", "防火墙启动失败，请检查是否以管理员权限运行")
    
    def _restart_firewall(self):
        """重启防火墙"""
        if self.firewall.is_running:
            if not self.firewall.stop():
                QMessageBox.warning(self, "警告", "停止防火墙失败")
                return
        QApplication.processEvents()
        time.sleep(1)
        if self.firewall.start():
            self.start_button.setText("停止防火墙")
            self.status_label.setText("状态: 运行中")
            QMessageBox.information(self, "提示", "防火墙已重启")
        else:
            self.start_button.setText("启动防火墙")
            self.status_label.setText("状态: 已停止")
            QMessageBox.critical(self, "错误", "防火墙重启失败")
            
    def _restart_windivert(self):
        """重启WinDivert驱动 (Slot connected from AdvancedSettingsTab)"""
        if not self.firewall.is_running:
            QMessageBox.warning(self, "警告", "防火墙未运行，无法重启WinDivert")
            return
        if self.firewall.restart_windivert():
            QMessageBox.information(self, "提示", "WinDivert已重启")
        else:
            QMessageBox.critical(self, "错误", "WinDivert重启失败")

    # --- Status Update Logic ---
    def _update_status(self):
        """更新状态和统计信息 (Called by timer)"""
        current_time = time.time()
        time_diff = current_time - self.last_update_time
        if time_diff < (self.update_interval / 1000):
            return
        self.last_update_time = current_time
        
        try:
            status = self.firewall.get_status()
            if status['running']:
                stats = status.get('processor_stats', {}) 
                self.stats_label.setText(
                    f"总处理: {stats.get('total_processed', 0)} | " 
                    f"拦截: {stats.get('dropped', 0)} | " 
                    f"放行: {stats.get('passed', 0)}"
                )
                # Get detailed stats once for resource usage and performance tab
                detailed_stats = self.firewall.get_detailed_stats() 
                system_resources = detailed_stats.get('system_resources', {})
                self.resource_label.setText(
                    f"CPU: {system_resources.get('cpu_percent', 0):.1f}% | " 
                    f"内存: {system_resources.get('memory_percent', 0):.1f}%" 
                )
                # Update performance tab UI
                self.performance_tab.update_performance_stats(stats, detailed_stats) 
            else:
                 self.stats_label.setText("总处理: 0 | 拦截: 0 | 放行: 0")
                 self.resource_label.setText("CPU: 0% | 内存: 0%")
                 self.performance_tab.update_performance_stats({}, {}) # Clear performance tab
            
            # Update rule lists in relevant tabs
            # self._update_rule_lists() 
        except Exception as e:
            print(f"更新状态时出错: {e}")
            logger.error(f"Error in UI update status: {e}", exc_info=True) 

    # Removed _update_performance_tab (logic moved to PerformanceTab.update_performance_stats)
    
    @pyqtSlot() # Mark as slot
    def _run_diagnosis(self):
        """获取并显示详细统计信息 (Slot connected from PerformanceTab)"""
        try:
            detailed_stats = self.firewall.get_detailed_stats()
            diag_text = "详细统计信息:\n\n"
            for key, value in detailed_stats.items():
                 if isinstance(value, dict):
                      diag_text += f"{key}:\n"
                      for sub_key, sub_value in value.items():
                           if isinstance(sub_value, (int, float)):
                               diag_text += f"  {sub_key}: {sub_value:,.2f}\n" if isinstance(sub_value, float) else f"  {sub_key}: {sub_value:,}\n"
                           else:
                               diag_text += f"  {sub_key}: {sub_value}\n"
                 else:
                      if isinstance(value, (int, float)):
                           diag_text += f"{key}: {value:,.2f}\n" if isinstance(value, float) else f"{key}: {value:,}\n"
                      else:
                           diag_text += f"{key}: {value}\n"
            # Display results in the performance tab's text area
            self.performance_tab.display_diagnosis_results(diag_text) 
        except Exception as e:
            logger.error(f"Error getting detailed stats for UI: {e}", exc_info=True)
            self.performance_tab.display_diagnosis_results(f"获取详细统计时出错: {str(e)}")

    # Removed _add_log_entry (Signal connected directly to LogTab._add_log_entry)
    # Removed _clear_logs (Handled by LogTab.clear_log_table)

    # --- Settings Logic ---
    def _load_advanced_settings(self):
        """加载高级设置并传递给高级设置标签页"""
        try:
            settings = self.firewall.performance_settings
            self.advanced_settings_tab.load_settings(settings)
        except Exception as e:
            logger.error(f"Failed to load settings into Advanced Settings Tab: {e}", exc_info=True)
            QMessageBox.warning(self, "警告", f"加载设置失败: {str(e)}")
            
    @pyqtSlot(dict) # Mark as slot receiving dict
    def _apply_advanced_settings(self, settings_dict: Dict):
        """应用高级设置到防火墙核心 (Slot connected from AdvancedSettingsTab)"""
        try:
            # Pass the settings received from the tab to the firewall
            self.firewall.update_performance_settings(settings_dict) 
            QMessageBox.information(self, "提示", "设置已应用。\n某些设置（如队列模型、工作线程数）可能需要重启防火墙才能完全生效。")
            # Reload settings into the tab to confirm they were stored (optional)
            self._load_advanced_settings() 
        except Exception as e:
            logger.error(f"Failed to apply settings: {e}", exc_info=True)
            QMessageBox.critical(self, "错误", f"应用设置失败: {str(e)}")
        
    # Removed _update_adaptive_setting (Logic moved to AdvancedSettingsTab._setting_changed)

    # --- Rule Update Logic ---
    def _update_rule_lists(self):
        """更新所有规则列表UI (Calls methods on tab widgets)"""
        try: 
            rules = self.firewall.rule_manager.get_rules()
            self.ip_filter_tab.update_lists(rules.get('ip_blacklist', set()), rules.get('ip_whitelist', set()))
            self.port_filter_tab.update_lists(rules.get('port_blacklist', set()), rules.get('port_whitelist', set()))
            self.content_filter_tab.update_list(rules.get('content_filters', []))
            # self.rules_ui_updated_signal.emit() # Emit signal after all tab updates are called
        except Exception as e:
             logger.error(f"Error updating rule lists in UI: {e}", exc_info=True) 

    # Removed _update_list_widget (Logic moved to individual tab classes)

    # --- Rule Management Slots (Connected from Tabs) ---
    @pyqtSlot(str)
    def _add_ip_to_blacklist(self, ip: str):
        if self.firewall.add_ip_to_blacklist(ip): 
            self.ip_filter_tab.clear_blacklist_input()
            # Rule list update handled by timer
        else: 
            QMessageBox.warning(self, "添加失败", f"无效的IP/CIDR或添加失败: {ip}")
                
    @pyqtSlot(str)
    def _remove_ip_from_blacklist(self, ip: str):
        if not self.firewall.remove_ip_from_blacklist(ip): 
            QMessageBox.warning(self, "移除失败", f"移除IP失败: {ip}")
        # Rule list update handled by timer

    @pyqtSlot(str)
    def _add_ip_to_whitelist(self, ip: str):
        if self.firewall.add_ip_to_whitelist(ip): 
            self.ip_filter_tab.clear_whitelist_input()
        else: 
            QMessageBox.warning(self, "添加失败", f"无效的IP/CIDR或添加失败: {ip}")
                
    @pyqtSlot(str)
    def _remove_ip_from_whitelist(self, ip: str):
        if not self.firewall.remove_ip_from_whitelist(ip): 
            QMessageBox.warning(self, "移除失败", f"移除IP失败: {ip}")
            
    @pyqtSlot(str)
    def _add_port_to_blacklist(self, port_str: str):
        if self.firewall.add_port_to_blacklist(port_str): 
            self.port_filter_tab.clear_blacklist_input() 
        else: 
            QMessageBox.warning(self, "添加失败", f"添加端口/范围失败: '{port_str}'. 请输入有效端口 (0-65535) 或范围 (e.g., 8000-8080)。")
            
    @pyqtSlot(str)
    def _remove_port_from_blacklist(self, port_str: str):
        if not self.firewall.remove_port_from_blacklist(port_str): 
            QMessageBox.warning(self, "移除失败", f"移除端口/范围失败: {port_str}")
            
    @pyqtSlot(str)
    def _add_port_to_whitelist(self, port_str: str):
        if self.firewall.add_port_to_whitelist(port_str): 
            self.port_filter_tab.clear_whitelist_input() 
        else: 
            QMessageBox.warning(self, "添加失败", f"添加端口/范围失败: '{port_str}'. 请输入有效端口 (0-65535) 或范围 (e.g., 10000-11000)。")
            
    @pyqtSlot(str)
    def _remove_port_from_whitelist(self, port_str: str):
        if not self.firewall.remove_port_from_whitelist(port_str): 
            QMessageBox.warning(self, "移除失败", f"移除端口/范围失败: {port_str}")
            
    @pyqtSlot(str)
    def _add_content_filter(self, pattern: str):
        if self.firewall.add_content_filter(pattern): 
            self.content_filter_tab.clear_input()
        else: 
            QMessageBox.warning(self, "添加失败", f"添加内容过滤规则失败 (可能是无效的正则表达式): {pattern}")
                
    @pyqtSlot(str)
    def _remove_content_filter(self, pattern: str):
        if not self.firewall.remove_content_filter(pattern): 
            QMessageBox.warning(self, "移除失败", f"移除内容过滤规则失败: {pattern}")

    # --- Import/Export Slots (Still makes sense to handle file dialogs here) ---
    @pyqtSlot(str)
    def _import_ip_list(self, list_type: str):
        if list_type not in ["blacklist", "whitelist"]: return
        filename, _ = QFileDialog.getOpenFileName(self, f"导入IP {list_type.capitalize()}", "", "文本文件 (*.txt);;所有文件 (*)")
        if filename:
            try:
                success, imported_count, invalid_count = self.firewall.rule_manager.import_ip_list(list_type, filename)
                if success:
                    message = f"成功从 {os.path.basename(filename)} 导入 {imported_count} 个IP/CIDR 到 {list_type}。"
                    if invalid_count > 0: message += f"\n发现并忽略了 {invalid_count} 个无效条目。"
                    QMessageBox.information(self, "导入成功", message)
                    self._update_rule_lists() # Refresh UI list immediately
                else:
                    QMessageBox.critical(self, "导入失败", "从文件导入IP列表时发生错误。请检查日志获取详细信息。")
            except Exception as e:
                 logger.error(f"Error during IP list import UI action: {e}", exc_info=True)
                 QMessageBox.critical(self, "导入错误", f"导入过程中发生意外错误: {e}")

    @pyqtSlot(str)
    def _export_ip_list(self, list_type: str):
        if list_type not in ["blacklist", "whitelist"]: return
        default_filename = f"ip_{list_type}.txt"
        filename, _ = QFileDialog.getSaveFileName(self, f"导出IP {list_type.capitalize()}", default_filename, "文本文件 (*.txt);;所有文件 (*)")
        if filename:
            try:
                success = self.firewall.rule_manager.export_ip_list(list_type, filename)
                if success:
                    QMessageBox.information(self, "导出成功", f"IP {list_type} 已成功导出到\n{filename}")
                else:
                    QMessageBox.critical(self, "导出失败", "导出IP列表到文件时发生错误。请检查日志获取详细信息。")
            except Exception as e:
                 logger.error(f"Error during IP list export UI action: {e}", exc_info=True)
                 QMessageBox.critical(self, "导出错误", f"导出过程中发生意外错误: {e}")

    # --- Window Close Event ---
    def closeEvent(self, event):
        """处理关闭事件，确保防火墙停止"""
        logger.info("Close event received. Stopping firewall...")
        # Stop UI timers first to prevent them from firing during/after core shutdown
        try:
            if self.update_timer.isActive():
                self.update_timer.stop()
                logger.info("UI Timers stopped.")
                # Removed traffic_timer stop
        except Exception as e:
            logger.error(f"Error stopping UI timers: {e}")

        # Check for automated CSV export environment variable
        auto_export_path_env = os.getenv('FIREWALL_AUTO_EXPORT_CSV_PATH')
        if auto_export_path_env:
            logger.info(f"FIREWALL_AUTO_EXPORT_CSV_PATH is set to '{auto_export_path_env}'. Triggering CSV export on close.")
            try:
                if hasattr(self.log_tab, 'export_buffered_logs_for_automation'):
                    # Define filters to export only intercepted logs, ignoring other UI filter states for automation
                    automation_filters = {
                        'action': '拦截', # Only intercepted logs
                        'protocol': 'All',    # All protocols
                        'src_ip': '',         # No source IP filter
                        'dst_ip': '',         # No destination IP filter
                        'src_port': '',       # No source port filter
                        'dst_port': ''        # No destination port filter
                    }
                    self.log_tab.export_buffered_logs_for_automation(auto_export_path_env, filter_override=automation_filters)
                    logger.info(f"Automated CSV export (from buffer, action: 拦截) initiated from MainWindow.closeEvent to {auto_export_path_env}.")
                else:
                    logger.warning("LogTab does not have 'export_buffered_logs_for_automation' method. Automated CSV export cannot proceed as intended.")
                    # Fallback or error logging if the intended method is not available.
                    # Depending on requirements, you might attempt the old method or simply log that the specific export failed.
                    # For now, just log the warning. If _export_filtered_logs_to_csv were to be called here,
                    # it would still likely result in "no visible entries".

            except Exception as e:
                logger.error(f"Error during automated CSV export from MainWindow.closeEvent: {e}", exc_info=True)
        
        if self.firewall:
            self.firewall.stop()
            logger.info("Firewall stopped from MainWindow.closeEvent.")
        
        logger.info("Exiting application.")
        event.accept()
