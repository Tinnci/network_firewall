#!/usr/bin/env python
# -*- coding: utf-8 -*-

from typing import Dict

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QLabel, QGroupBox, QFormLayout, 
    QTextEdit
)
from PyQt6.QtCore import pyqtSignal

class PerformanceTab(QWidget):
    """性能监控标签页的UI和更新逻辑"""
    # Signal to request diagnosis/detailed stats from main window
    run_diagnosis_requested = pyqtSignal() 

    def __init__(self, parent=None):
        super().__init__(parent)
        self._create_ui()

    def _create_ui(self):
        """创建此标签页的UI组件"""
        layout = QVBoxLayout(self)
        
        # --- Performance Stats Group ---
        stats_group = QGroupBox("性能统计")
        stats_layout = QFormLayout(stats_group)
        
        self.perf_total_packets = QLabel("0")
        stats_layout.addRow("总处理数据包:", self.perf_total_packets)
        self.perf_dropped_packets = QLabel("0")
        stats_layout.addRow("已拦截数据包:", self.perf_dropped_packets)
        self.perf_passed_packets = QLabel("0")
        stats_layout.addRow("已放行数据包:", self.perf_passed_packets)
        self.perf_error_packets = QLabel("0")
        stats_layout.addRow("处理错误计数:", self.perf_error_packets)
        self.perf_packets_per_second = QLabel("0.00")
        stats_layout.addRow("每秒处理数据包:", self.perf_packets_per_second)
        self.perf_win_error_87 = QLabel("0")
        stats_layout.addRow("WinError 87计数:", self.perf_win_error_87)
        self.perf_queue_size = QLabel("N/A") 
        stats_layout.addRow("处理队列大小:", self.perf_queue_size)
        layout.addWidget(stats_group)
        
        # --- System Resources Group ---
        resource_group = QGroupBox("系统资源使用")
        resource_layout = QFormLayout(resource_group)
        self.resource_cpu = QLabel("0%")
        resource_layout.addRow("CPU使用率:", self.resource_cpu)
        self.resource_memory = QLabel("0%")
        resource_layout.addRow("内存使用率:", self.resource_memory)
        self.resource_network_in = QLabel("0 KB") 
        resource_layout.addRow("网络接收 (累计):", self.resource_network_in)
        self.resource_network_out = QLabel("0 KB") 
        resource_layout.addRow("网络发送 (累计):", self.resource_network_out)
        layout.addWidget(resource_group)
        
        # --- Diagnosis Group ---
        diagnosis_group = QGroupBox("详细统计/诊断")
        diagnosis_layout = QVBoxLayout(diagnosis_group)
        self.diagnosis_text = QTextEdit()
        self.diagnosis_text.setReadOnly(True)
        self.diagnosis_text.setPlaceholderText("点击“获取详细统计”按钮查看...")
        diagnosis_layout.addWidget(self.diagnosis_text)
        diagnosis_button = QPushButton("获取详细统计") 
        diagnosis_button.clicked.connect(self.run_diagnosis_requested) # Emit signal
        diagnosis_layout.addWidget(diagnosis_button)
        layout.addWidget(diagnosis_group)

    # --- Public Methods for UI Update ---
    def update_performance_stats(self, processor_stats: Dict, detailed_stats: Dict):
        """更新性能统计和资源使用标签"""
        try:
            # Update basic stats using keys from processor_stats
            self.perf_total_packets.setText(str(processor_stats.get('total_processed', 0)))
            self.perf_dropped_packets.setText(str(processor_stats.get('dropped', 0)))
            self.perf_passed_packets.setText(str(processor_stats.get('passed', 0)))
            self.perf_error_packets.setText(str(processor_stats.get('errors', 0)))
            self.perf_win_error_87.setText(str(processor_stats.get('win_error_87_count', 0)))
            
            # Update packets per second (from detailed_stats)
            pps = detailed_stats.get('packets_per_second', 0.0)
            self.perf_packets_per_second.setText(f"{pps:.2f}")

            # Update queue size
            queue_size = processor_stats.get('queue_size')
            queue_label = self.findChild(QLabel, "处理队列大小:") # Find label dynamically
            if queue_size is not None:
                 self.perf_queue_size.setText(str(queue_size))
                 self.perf_queue_size.setVisible(True)
                 if queue_label: queue_label.setVisible(True) 
            else:
                 self.perf_queue_size.setText("N/A")
                 self.perf_queue_size.setVisible(False)
                 if queue_label: queue_label.setVisible(False)

            # Update system resources (from detailed_stats)
            resources = detailed_stats.get('system_resources', {})
            self.resource_cpu.setText(f"{resources.get('cpu_percent', 0):.1f}%")
            self.resource_memory.setText(f"{resources.get('memory_percent', 0):.1f}%")
            
            io_counters = resources.get('io_counters', {})
            bytes_recv_kb = io_counters.get('bytes_recv', 0) / 1024
            bytes_sent_kb = io_counters.get('bytes_sent', 0) / 1024
            self.resource_network_in.setText(f"{bytes_recv_kb:.2f} KB") 
            self.resource_network_out.setText(f"{bytes_sent_kb:.2f} KB") 
            
        except Exception as e:
            print(f"Error updating performance tab UI: {e}") # Use print or logger if available

    def display_diagnosis_results(self, text: str):
        """显示诊断或详细统计结果"""
        self.diagnosis_text.setText(text)
