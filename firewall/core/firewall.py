#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import time
import psutil
from typing import Dict, List, Tuple, Optional, Callable

from .packet_filter import PacketFilter
from .rule_manager import RuleManager


class Firewall:
    """防火墙主类"""
    
    def __init__(self, rules_file: str = 'rules.yaml'):
        """初始化防火墙
        
        Args:
            rules_file: 规则文件路径
        """
        # 创建规则管理器
        self.rule_manager = RuleManager(rules_file)
        
        # 创建数据包过滤器
        self.packet_filter = PacketFilter()
        
        # 状态
        self.is_running = False
        
        # 数据包处理回调
        self.packet_callback = None
        
        # 日志记录
        self.logs = []
        self.max_logs = 1000  # 最多保存1000条日志
        
        # 性能配置
        self.performance_settings = {
            'use_batch_mode': True,          # 是否使用批量接收模式
            'use_queue_model': False,        # 是否使用队列模型
            'num_workers': 2,                # 工作线程数
            'packet_pool_size': 100,         # 数据包对象池大小
            'skip_local_packets': True,      # 是否跳过本地数据包
            'skip_large_packets': False,     # 是否跳过大型数据包
            'large_packet_threshold': 1460,  # 大型数据包阈值(字节)
            'allow_private_network': True,   # 允许本地网络通信
            'batch_size': 5,                 # 批处理大小
            'batch_wait_time': 100,          # 批处理等待时间(毫秒)
        }
        
    def start(self) -> bool:
        """启动防火墙
        
        Returns:
            bool: 是否启动成功
        """
        if self.is_running:
            return True
            
        # 加载规则
        rules = self.rule_manager.get_rules()
        
        # 设置过滤器规则
        self.packet_filter.ip_blacklist = rules['ip_blacklist']
        self.packet_filter.ip_whitelist = rules['ip_whitelist']
        self.packet_filter.port_blacklist = rules['port_blacklist']
        self.packet_filter.port_whitelist = rules['port_whitelist']
        self.packet_filter.content_filters = rules['content_filters']
        self.packet_filter.protocol_filter = rules['protocol_filter']
        
        # 应用性能配置到过滤器
        self._apply_performance_settings()
        
        # 注册数据包回调
        self.packet_filter.register_packet_callback(self._on_packet)
        
        # 启动过滤器
        result = self.packet_filter.start()
        if result:
            self.is_running = True
            self._add_log("防火墙已启动")
        
        return result
        
    def stop(self) -> bool:
        """停止防火墙
        
        Returns:
            bool: 是否停止成功
        """
        if not self.is_running:
            return True
            
        # 停止过滤器
        self.packet_filter.stop()
        self.is_running = False
        self._add_log("防火墙已停止")
        
        return True
        
    def _apply_performance_settings(self):
        """将性能设置应用到过滤器"""
        # 复制设置到过滤器的自适应设置
        for key, value in self.performance_settings.items():
            self.packet_filter.adaptive_settings[key] = value
        
        # 设置工作线程数
        self.packet_filter.num_workers = self.performance_settings.get('num_workers', 2)
        
        # 设置对象池大小
        self.packet_filter.MAX_POOL_SIZE = self.performance_settings.get('packet_pool_size', 100)
    
    def update_performance_settings(self, new_settings: Dict) -> bool:
        """更新性能设置
        
        Args:
            new_settings: 新的性能设置
            
        Returns:
            bool: 是否更新成功
        """
        # 更新设置
        for key, value in new_settings.items():
            if key in self.performance_settings:
                self.performance_settings[key] = value
        
        # 如果防火墙正在运行，应用新设置
        if self.is_running:
            self._apply_performance_settings()
            self._add_log("已更新性能设置")
            
        return True
        
    def get_status(self) -> Dict:
        """获取防火墙状态
        
        Returns:
            Dict: 状态信息
        """
        status = {
            'running': self.is_running,
            'stats': self.packet_filter.get_stats() if self.is_running else {},
            'rules': self.rule_manager.get_rules(),
            'performance_settings': self.performance_settings,
        }
        
        # 添加诊断信息
        if self.is_running:
            try:
                status['diagnosis'] = self.packet_filter._diagnose_problem()
            except:
                status['diagnosis'] = {'error': '获取诊断信息失败'}
        
        return status
        
    def restart(self) -> bool:
        """重启防火墙
        
        Returns:
            bool: 是否重启成功
        """
        self.stop()
        time.sleep(1)  # 等待资源释放
        return self.start()
        
    def restart_windivert(self) -> bool:
        """重启WinDivert实例
        
        Returns:
            bool: 是否重启成功
        """
        if not self.is_running:
            return False
            
        return self.packet_filter._restart_windivert()
        
    def get_detailed_stats(self) -> Dict:
        """获取详细的统计信息
        
        Returns:
            Dict: 详细统计信息
        """
        if not self.is_running:
            return {}
            
        basic_stats = self.packet_filter.get_stats()
        
        # 添加额外的统计信息
        detailed_stats = {
            **basic_stats,
            'packet_types': self.packet_filter.packet_type_stats,
            'error_tracking': self.packet_filter.error_tracking,
            'adaptive_settings': self.packet_filter.adaptive_settings,
        }
        
        # 添加性能指标
        try:
            # 计算每秒处理的数据包数
            if basic_stats['total_packets'] > 0 and 'start_time' in basic_stats:
                running_time = time.time() - basic_stats['start_time']
                detailed_stats['packets_per_second'] = basic_stats['total_packets'] / max(1, running_time)
                
            # 添加系统资源使用情况
            detailed_stats['system_resources'] = {
                'cpu_percent': psutil.cpu_percent(interval=None),
                'memory_percent': psutil.virtual_memory().percent,
                'io_counters': {k: v for k, v in psutil.net_io_counters()._asdict().items()}
            }
        except:
            pass
            
        return detailed_stats
        
    def register_packet_callback(self, callback: Callable):
        """注册数据包处理回调
        
        Args:
            callback: 回调函数，接收 (packet, action) 参数
        """
        self.packet_callback = callback
        
    def _on_packet(self, packet, should_pass: bool):
        """数据包处理回调
        
        Args:
            packet: 数据包对象
            should_pass: 是否放行
        """
        # 构建日志信息
        log_entry = {
            'time': time.time(),
            'src_ip': packet.src_addr if hasattr(packet, 'src_addr') else None,
            'dst_ip': packet.dst_addr if hasattr(packet, 'dst_addr') else None,
            'src_port': packet.src_port if hasattr(packet, 'src_port') else None,
            'dst_port': packet.dst_port if hasattr(packet, 'dst_port') else None,
            'protocol': 'TCP' if packet.tcp is not None else ('UDP' if packet.udp is not None else 'Unknown'),
            'action': '放行' if should_pass else '拦截',
            'packet_size': len(packet.payload) if hasattr(packet, 'payload') and packet.payload else 0
        }
        
        # 添加到日志
        self._add_log(log_entry)
        
        # 触发外部回调
        if self.packet_callback:
            self.packet_callback(packet, should_pass)
            
        # 如果开启了数据包池，将处理完的数据包放回池中
        if self.performance_settings.get('use_packet_pool', True):
            try:
                self.packet_filter.return_packet_to_pool(packet)
            except:
                pass
            
    def _add_log(self, log_entry):
        """添加日志
        
        Args:
            log_entry: 日志条目
        """
        self.logs.append(log_entry)
        
        # 限制日志条数
        if len(self.logs) > self.max_logs:
            self.logs = self.logs[-self.max_logs:]
            
    def get_logs(self, count: int = 100) -> List:
        """获取最近的日志
        
        Args:
            count: 获取的日志条数
            
        Returns:
            List: 日志列表
        """
        return self.logs[-count:]
        
    # IP黑白名单管理
    def add_ip_to_blacklist(self, ip: str) -> bool:
        """添加IP到黑名单
        
        Args:
            ip: IP地址
            
        Returns:
            bool: 是否添加成功
        """
        result = self.rule_manager.add_ip_to_blacklist(ip)
        if result and self.is_running:
            self.packet_filter.add_ip_to_blacklist(ip)
            self._add_log(f"添加IP {ip} 到黑名单")
        return result
        
    def remove_ip_from_blacklist(self, ip: str) -> bool:
        """从黑名单移除IP
        
        Args:
            ip: IP地址
            
        Returns:
            bool: 是否移除成功
        """
        result = self.rule_manager.remove_ip_from_blacklist(ip)
        if result and self.is_running:
            self.packet_filter.remove_ip_from_blacklist(ip)
            self._add_log(f"从黑名单移除IP {ip}")
        return result
        
    def add_ip_to_whitelist(self, ip: str) -> bool:
        """添加IP到白名单
        
        Args:
            ip: IP地址
            
        Returns:
            bool: 是否添加成功
        """
        result = self.rule_manager.add_ip_to_whitelist(ip)
        if result and self.is_running:
            self.packet_filter.add_ip_to_whitelist(ip)
            self._add_log(f"添加IP {ip} 到白名单")
        return result
        
    def remove_ip_from_whitelist(self, ip: str) -> bool:
        """从白名单移除IP
        
        Args:
            ip: IP地址
            
        Returns:
            bool: 是否移除成功
        """
        result = self.rule_manager.remove_ip_from_whitelist(ip)
        if result and self.is_running:
            self.packet_filter.remove_ip_from_whitelist(ip)
            self._add_log(f"从白名单移除IP {ip}")
        return result
        
    # 端口黑白名单管理
    def add_port_to_blacklist(self, port: int) -> bool:
        """添加端口到黑名单
        
        Args:
            port: 端口号
            
        Returns:
            bool: 是否添加成功
        """
        result = self.rule_manager.add_port_to_blacklist(port)
        if result and self.is_running:
            self.packet_filter.add_port_to_blacklist(port)
            self._add_log(f"添加端口 {port} 到黑名单")
        return result
        
    def remove_port_from_blacklist(self, port: int) -> bool:
        """从黑名单移除端口
        
        Args:
            port: 端口号
            
        Returns:
            bool: 是否移除成功
        """
        result = self.rule_manager.remove_port_from_blacklist(port)
        if result and self.is_running:
            self.packet_filter.remove_port_from_blacklist(port)
            self._add_log(f"从黑名单移除端口 {port}")
        return result
        
    def add_port_to_whitelist(self, port: int) -> bool:
        """添加端口到白名单
        
        Args:
            port: 端口号
            
        Returns:
            bool: 是否添加成功
        """
        result = self.rule_manager.add_port_to_whitelist(port)
        if result and self.is_running:
            self.packet_filter.add_port_to_whitelist(port)
            self._add_log(f"添加端口 {port} 到白名单")
        return result
        
    def remove_port_from_whitelist(self, port: int) -> bool:
        """从白名单移除端口
        
        Args:
            port: 端口号
            
        Returns:
            bool: 是否移除成功
        """
        result = self.rule_manager.remove_port_from_whitelist(port)
        if result and self.is_running:
            self.packet_filter.remove_port_from_whitelist(port)
            self._add_log(f"从白名单移除端口 {port}")
        return result
        
    # 内容过滤管理
    def add_content_filter(self, pattern: str) -> bool:
        """添加内容过滤规则
        
        Args:
            pattern: 内容匹配模式
            
        Returns:
            bool: 是否添加成功
        """
        result = self.rule_manager.add_content_filter(pattern)
        if result and self.is_running:
            self.packet_filter.add_content_filter(pattern)
            self._add_log(f"添加内容过滤规则: {pattern}")
        return result
        
    def remove_content_filter(self, pattern: str) -> bool:
        """移除内容过滤规则
        
        Args:
            pattern: 内容匹配模式
            
        Returns:
            bool: 是否移除成功
        """
        result = self.rule_manager.remove_content_filter(pattern)
        if result and self.is_running:
            self.packet_filter.remove_content_filter(pattern)
            self._add_log(f"移除内容过滤规则: {pattern}")
        return result
        
    # 协议过滤管理
    def set_protocol_filter(self, protocol: str, enabled: bool) -> bool:
        """设置协议过滤
        
        Args:
            protocol: 协议名称(tcp/udp)
            enabled: 是否启用
            
        Returns:
            bool: 是否设置成功
        """
        if protocol.lower() not in ['tcp', 'udp']:
            return False
            
        # 更新规则管理器
        rules = self.rule_manager.get_rules()
        rules['protocol_filter'][protocol.lower()] = enabled
        self.rule_manager.save_rules(rules)
        
        # 如果防火墙正在运行，更新过滤器
        if self.is_running:
            self.packet_filter.protocol_filter[protocol.lower()] = enabled
            self._add_log(f"已{'启用' if enabled else '禁用'} {protocol.upper()} 协议过滤")
            
        return True
        
    def update_performance_settings(self, new_settings: Dict) -> bool:
        """更新性能设置
        
        Args:
            new_settings: 新的性能设置
            
        Returns:
            bool: 是否更新成功
        """
        # 更新设置
        for key, value in new_settings.items():
            if key in self.performance_settings:
                self.performance_settings[key] = value
        
        # 如果防火墙正在运行，应用新设置
        if self.is_running:
            self._apply_performance_settings()
            self._add_log("已更新性能设置")
            
        return True 