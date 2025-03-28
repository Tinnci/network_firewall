#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import time
import psutil
from typing import Dict, List, Tuple, Optional, Callable
import logging # Added import
import re # Added import

from .packet_filter import PacketFilter
from .rule_manager import RuleManager

# Configure logging
log_file = os.path.join(os.getcwd(), 'firewall.log')
# Ensure the log directory exists (useful if log file is in a subdirectory)
os.makedirs(os.path.dirname(log_file), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file, encoding='utf-8'),
        # logging.StreamHandler() # Optional: Keep console output if needed
    ]
)
# Separate logger for this module
logger = logging.getLogger('FirewallCore')


class Firewall:
    """防火墙主类"""
    
    def __init__(self, rules_file: str = 'rules.yaml'):
        """初始化防火墙
        
        Args:
            rules_file: 规则文件路径
        """
        logger.info("Initializing Firewall...")
        # 创建规则管理器
        self.rule_manager = RuleManager(rules_file)
        logger.info(f"RuleManager initialized with file: {rules_file}")
        
        # 创建数据包过滤器
        self.packet_filter = PacketFilter()
        logger.info("PacketFilter initialized.")
        
        # 状态
        self.is_running = False
        
        # 数据包处理回调
        self.packet_callback = None
        
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
        logger.info(f"Default performance settings: {self.performance_settings}")
        
        # TODO: 添加统计信息持久化存储功能
        
    def start(self) -> bool:
        """启动防火墙
        
        Returns:
            bool: 是否启动成功
        """
        if self.is_running:
            logger.warning("Firewall is already running.")
            return True
            
        logger.info("Starting Firewall...")
        # 加载规则
        rules = self.rule_manager.get_rules()
        logger.info("Rules loaded.")
        
        # 设置过滤器规则
        self.packet_filter.ip_blacklist = rules['ip_blacklist']
        self.packet_filter.ip_whitelist = rules['ip_whitelist']
        self.packet_filter.port_blacklist = rules['port_blacklist']
        self.packet_filter.port_whitelist = rules['port_whitelist']
        self.packet_filter.content_filters = rules['content_filters']
        self.packet_filter.protocol_filter = rules['protocol_filter']
        logger.info("Rules applied to PacketFilter.")
        
        # 应用性能配置到过滤器
        self._apply_performance_settings()
        
        # 注册数据包回调
        self.packet_filter.register_packet_callback(self._on_packet)
        logger.info("Packet callback registered.")
        
        # 启动过滤器
        logger.info("Attempting to start PacketFilter...")
        result = self.packet_filter.start()
        if result:
            self.is_running = True
            self._add_log("防火墙已启动", level=logging.INFO)
            logger.info("PacketFilter started successfully. Firewall is running.")
        else:
            logger.error("Failed to start PacketFilter. Firewall startup aborted.")
        
        return result
        
    def stop(self) -> bool:
        """停止防火墙
        
        Returns:
            bool: 是否停止成功
        """
        if not self.is_running:
            logger.warning("Firewall is not running.")
            return True
            
        logger.info("Stopping Firewall...")
        # 停止过滤器
        self.packet_filter.stop()
        self.is_running = False
        self._add_log("防火墙已停止", level=logging.INFO)
        logger.info("Firewall stopped.")
        
        return True
        
    def _apply_performance_settings(self):
        """将性能设置应用到过滤器"""
        logger.debug("Applying performance settings to PacketFilter...")
        # 复制设置到过滤器的自适应设置
        for key, value in self.performance_settings.items():
            if hasattr(self.packet_filter, 'adaptive_settings') and key in self.packet_filter.adaptive_settings:
                 self.packet_filter.adaptive_settings[key] = value
                 logger.debug(f"Set adaptive_settings['{key}'] = {value}")
            else:
                 logger.warning(f"Key '{key}' not found in packet_filter.adaptive_settings")

        # 设置工作线程数
        if hasattr(self.packet_filter, 'num_workers'):
            self.packet_filter.num_workers = self.performance_settings.get('num_workers', 2)
            logger.debug(f"Set num_workers = {self.packet_filter.num_workers}")

        # 设置对象池大小
        if hasattr(self.packet_filter, 'MAX_POOL_SIZE'):
            self.packet_filter.MAX_POOL_SIZE = self.performance_settings.get('packet_pool_size', 100)
            logger.debug(f"Set MAX_POOL_SIZE = {self.packet_filter.MAX_POOL_SIZE}")
        logger.debug("Performance settings applied.")

    def update_performance_settings(self, new_settings: Dict) -> bool:
        """更新性能设置
        
        Args:
            new_settings: 新的性能设置
            
        Returns:
            bool: 是否更新成功
        """
        logger.info(f"Updating performance settings: {new_settings}")
        updated = False
        # 更新设置
        for key, value in new_settings.items():
            if key in self.performance_settings:
                if self.performance_settings[key] != value:
                    self.performance_settings[key] = value
                    logger.debug(f"Updated setting: {key} = {value}")
                    updated = True
            else:
                logger.warning(f"Attempted to update unknown setting: {key}")
        
        # 如果防火墙正在运行，应用新设置
        if self.is_running and updated:
            self._apply_performance_settings()
            self._add_log("已更新性能设置", level=logging.INFO)
            logger.info("Applied updated performance settings.")
        elif not updated:
            logger.info("No changes detected in performance settings.")
            
        return True
        
    def get_status(self) -> Dict:
        """获取防火墙状态
        
        Returns:
            Dict: 状态信息
        """
        # logger.debug("Getting firewall status...") # Too frequent, maybe remove
        status = {
            'running': self.is_running,
            'stats': self.packet_filter.get_stats() if self.is_running else {},
            'rules': self.rule_manager.get_rules(),
            'performance_settings': self.performance_settings,
        }
        
        # 添加诊断信息
        if self.is_running:
            try:
                # logger.debug("Getting diagnosis info...") # Too frequent
                status['diagnosis'] = self.packet_filter._diagnose_problem()
            except Exception as e:
                logger.error(f"Failed to get diagnosis info: {e}")
                status['diagnosis'] = {'error': '获取诊断信息失败'}
        
        return status
        
    def restart(self) -> bool:
        """重启防火墙
        
        Returns:
            bool: 是否重启成功
        """
        logger.info("Restarting Firewall...")
        self.stop()
        logger.info("Waiting for resources to release...")
        time.sleep(1)  # 等待资源释放
        result = self.start()
        if result:
            logger.info("Firewall restarted successfully.")
        else:
            logger.error("Firewall restart failed.")
        return result
        
    def restart_windivert(self) -> bool:
        """重启WinDivert实例
        
        Returns:
            bool: 是否重启成功
        """
        if not self.is_running:
            logger.warning("Cannot restart WinDivert, Firewall is not running.")
            return False
            
        logger.info("Attempting to restart WinDivert via PacketFilter...")
        result = self.packet_filter._restart_windivert()
        if result:
            logger.info("WinDivert restarted successfully.")
        else:
            logger.error("WinDivert restart failed.")
        return result
        
    def get_detailed_stats(self) -> Dict:
        """获取详细的统计信息
        
        Returns:
            Dict: 详细统计信息
        """
        if not self.is_running:
            # logger.debug("Cannot get detailed stats, Firewall is not running.") # Too frequent
            return {}
            
        # logger.debug("Getting detailed stats...") # Too frequent
        basic_stats = self.packet_filter.get_stats()
        
        # 添加额外的统计信息
        detailed_stats = {
            **basic_stats,
            'packet_types': self.packet_filter.packet_type_stats if hasattr(self.packet_filter, 'packet_type_stats') else {},
            'error_tracking': self.packet_filter.error_tracking if hasattr(self.packet_filter, 'error_tracking') else {},
            'adaptive_settings': self.packet_filter.adaptive_settings if hasattr(self.packet_filter, 'adaptive_settings') else {},
        }
        
        # 添加性能指标
        try:
            # 计算每秒处理的数据包数
            if basic_stats.get('total_packets', 0) > 0 and 'start_time' in basic_stats:
                running_time = time.time() - basic_stats['start_time']
                detailed_stats['packets_per_second'] = basic_stats['total_packets'] / max(1, running_time)
                
            # 添加系统资源使用情况
            detailed_stats['system_resources'] = {
                'cpu_percent': psutil.cpu_percent(interval=None),
                'memory_percent': psutil.virtual_memory().percent,
                'io_counters': {k: v for k, v in psutil.net_io_counters()._asdict().items()}
            }
        except Exception as e:
            logger.warning(f"Could not get performance metrics: {e}")
            pass
            
        # TODO: 添加历史统计数据存储与趋势分析功能 (Lower Priority)
        # TODO: 添加网络流量图表数据生成功能 (Lower Priority)
            
        return detailed_stats
        
    def register_packet_callback(self, callback: Callable):
        """注册数据包处理回调
        
        Args:
            callback: 回调函数，接收 (packet, action) 参数
        """
        self.packet_callback = callback
        logger.info("External packet callback registered.")
        
    def _on_packet(self, packet, should_pass: bool):
        """数据包处理回调 - 由 PacketFilter 调用
        
        Args:
            packet: 数据包对象
            should_pass: 是否放行
        """
        action = '放行' if should_pass else '拦截'
        protocol = 'TCP' if hasattr(packet, 'tcp') and packet.tcp else ('UDP' if hasattr(packet, 'udp') and packet.udp else 'Unknown')
        src_ip = packet.src_addr if hasattr(packet, 'src_addr') else 'N/A'
        dst_ip = packet.dst_addr if hasattr(packet, 'dst_addr') else 'N/A'
        src_port = packet.src_port if hasattr(packet, 'src_port') else 'N/A'
        dst_port = packet.dst_port if hasattr(packet, 'dst_port') else 'N/A'
        size = len(packet.payload) if hasattr(packet, 'payload') and packet.payload else 0

        log_message = (
            f"Packet {action}: Proto={protocol}, Src={src_ip}:{src_port}, "
            f"Dst={dst_ip}:{dst_port}, Size={size}"
        )
        
        # 添加到日志文件
        self._add_log(log_message, level=logging.DEBUG) # Log packet details as DEBUG
        
        # 触发外部回调 (e.g., for UI updates)
        if self.packet_callback:
            try:
                self.packet_callback(packet, should_pass)
            except Exception as e:
                logger.error(f"Error in external packet callback: {e}")
            
        # 如果开启了数据包池，将处理完的数据包放回池中
        if self.performance_settings.get('use_packet_pool', True):
            try:
                if hasattr(self.packet_filter, 'return_packet_to_pool'):
                    self.packet_filter.return_packet_to_pool(packet)
            except Exception as e:
                # Log error but don't crash
                logger.warning(f"Error returning packet to pool: {e}")
                pass
            
    def _add_log(self, message: str, level=logging.INFO):
        """添加日志到文件
        
        Args:
            message: 日志消息
            level: 日志级别 (e.g., logging.INFO, logging.WARNING)
        """
        if level == logging.DEBUG:
            logger.debug(message)
        elif level == logging.INFO:
            logger.info(message)
        elif level == logging.WARNING:
            logger.warning(message)
        elif level == logging.ERROR:
            logger.error(message)
        elif level == logging.CRITICAL:
            logger.critical(message)
        else:
            logger.info(message) # Default to INFO
            
    # IP黑白名单管理
    def add_ip_to_blacklist(self, ip: str) -> bool:
        """添加IP到黑名单
        
        Args:
            ip: IP地址
            
        Returns:
            bool: 是否添加成功
        """
        logger.info(f"Attempting to add IP {ip} to blacklist...")
        result = self.rule_manager.add_ip_to_blacklist(ip)
        if result:
            if self.is_running and hasattr(self.packet_filter, 'add_ip_to_blacklist'):
                self.packet_filter.add_ip_to_blacklist(ip)
            self._add_log(f"添加IP {ip} 到黑名单", level=logging.INFO)
            logger.info(f"Successfully added IP {ip} to blacklist.")
        else:
             logger.warning(f"Failed to add IP {ip} to blacklist (RuleManager).")
        return result
        
    def remove_ip_from_blacklist(self, ip: str) -> bool:
        """从黑名单移除IP
        
        Args:
            ip: IP地址
            
        Returns:
            bool: 是否移除成功
        """
        logger.info(f"Attempting to remove IP {ip} from blacklist...")
        result = self.rule_manager.remove_ip_from_blacklist(ip)
        if result:
            if self.is_running and hasattr(self.packet_filter, 'remove_ip_from_blacklist'):
                self.packet_filter.remove_ip_from_blacklist(ip)
            self._add_log(f"从黑名单移除IP {ip}", level=logging.INFO)
            logger.info(f"Successfully removed IP {ip} from blacklist.")
        else:
            logger.warning(f"Failed to remove IP {ip} from blacklist (RuleManager).")
        return result
        
    def add_ip_to_whitelist(self, ip: str) -> bool:
        """添加IP到白名单
        
        Args:
            ip: IP地址
            
        Returns:
            bool: 是否添加成功
        """
        logger.info(f"Attempting to add IP {ip} to whitelist...")
        result = self.rule_manager.add_ip_to_whitelist(ip)
        if result:
            if self.is_running and hasattr(self.packet_filter, 'add_ip_to_whitelist'):
                self.packet_filter.add_ip_to_whitelist(ip)
            self._add_log(f"添加IP {ip} 到白名单", level=logging.INFO)
            logger.info(f"Successfully added IP {ip} to whitelist.")
        else:
            logger.warning(f"Failed to add IP {ip} to whitelist (RuleManager).")
        return result
        
    def remove_ip_from_whitelist(self, ip: str) -> bool:
        """从白名单移除IP
        
        Args:
            ip: IP地址
            
        Returns:
            bool: 是否移除成功
        """
        logger.info(f"Attempting to remove IP {ip} from whitelist...")
        result = self.rule_manager.remove_ip_from_whitelist(ip)
        if result:
            if self.is_running and hasattr(self.packet_filter, 'remove_ip_from_whitelist'):
                self.packet_filter.remove_ip_from_whitelist(ip)
            self._add_log(f"从白名单移除IP {ip}", level=logging.INFO)
            logger.info(f"Successfully removed IP {ip} from whitelist.")
        else:
            logger.warning(f"Failed to remove IP {ip} from whitelist (RuleManager).")
        return result
        
    # TODO: 添加IP地址范围和CIDR格式支持 (Partially done in PacketFilter, needs RuleManager validation)
    # TODO: 添加IP地理位置显示功能 (Lower Priority)
        
    # 端口黑白名单管理
    def add_port_to_blacklist(self, port: int) -> bool:
        """添加端口到黑名单
        
        Args:
            port: 端口号
            
        Returns:
            bool: 是否添加成功
        """
        logger.info(f"Attempting to add port {port} to blacklist...")
        result = self.rule_manager.add_port_to_blacklist(port)
        if result:
            if self.is_running and hasattr(self.packet_filter, 'add_port_to_blacklist'):
                self.packet_filter.add_port_to_blacklist(port)
            self._add_log(f"添加端口 {port} 到黑名单", level=logging.INFO)
            logger.info(f"Successfully added port {port} to blacklist.")
        else:
            logger.warning(f"Failed to add port {port} to blacklist (RuleManager).")
        return result
        
    def remove_port_from_blacklist(self, port: int) -> bool:
        """从黑名单移除端口
        
        Args:
            port: 端口号
            
        Returns:
            bool: 是否移除成功
        """
        logger.info(f"Attempting to remove port {port} from blacklist...")
        result = self.rule_manager.remove_port_from_blacklist(port)
        if result:
            if self.is_running and hasattr(self.packet_filter, 'remove_port_from_blacklist'):
                self.packet_filter.remove_port_from_blacklist(port)
            self._add_log(f"从黑名单移除端口 {port}", level=logging.INFO)
            logger.info(f"Successfully removed port {port} from blacklist.")
        else:
            logger.warning(f"Failed to remove port {port} from blacklist (RuleManager).")
        return result
        
    def add_port_to_whitelist(self, port: int) -> bool:
        """添加端口到白名单
        
        Args:
            port: 端口号
            
        Returns:
            bool: 是否添加成功
        """
        logger.info(f"Attempting to add port {port} to whitelist...")
        result = self.rule_manager.add_port_to_whitelist(port)
        if result:
            if self.is_running and hasattr(self.packet_filter, 'add_port_to_whitelist'):
                self.packet_filter.add_port_to_whitelist(port)
            self._add_log(f"添加端口 {port} 到白名单", level=logging.INFO)
            logger.info(f"Successfully added port {port} to whitelist.")
        else:
            logger.warning(f"Failed to add port {port} to whitelist (RuleManager).")
        return result
        
    def remove_port_from_whitelist(self, port: int) -> bool:
        """从白名单移除端口
        
        Args:
            port: 端口号
            
        Returns:
            bool: 是否移除成功
        """
        logger.info(f"Attempting to remove port {port} from whitelist...")
        result = self.rule_manager.remove_port_from_whitelist(port)
        if result:
            if self.is_running and hasattr(self.packet_filter, 'remove_port_from_whitelist'):
                self.packet_filter.remove_port_from_whitelist(port)
            self._add_log(f"从白名单移除端口 {port}", level=logging.INFO)
            logger.info(f"Successfully removed port {port} from whitelist.")
        else:
            logger.warning(f"Failed to remove port {port} from whitelist (RuleManager).")
        return result
        
    # TODO: 添加常用端口服务名称显示功能 (Lower Priority)
        
    # 内容过滤管理
    def add_content_filter(self, pattern: str) -> bool:
        """添加内容过滤规则
        
        Args:
            pattern: 内容匹配模式
            
        Returns:
            bool: 是否添加成功
        """
        logger.info(f"Attempting to add content filter: {pattern}")
        result = self.rule_manager.add_content_filter(pattern)
        if result:
            if self.is_running and hasattr(self.packet_filter, 'add_content_filter'):
                self.packet_filter.add_content_filter(pattern)
                # Recompile filters in packet_filter if running
                if hasattr(self.packet_filter, 'compiled_filters'):
                    try:
                        self.packet_filter.compiled_filters = [re.compile(p) for p in self.packet_filter.content_filters]
                        logger.debug("Recompiled content filters in PacketFilter.")
                    except Exception as e:
                         logger.error(f"Failed to recompile content filters: {e}")

            self._add_log(f"添加内容过滤规则: {pattern}", level=logging.INFO)
            logger.info(f"Successfully added content filter: {pattern}")
        else:
            logger.warning(f"Failed to add content filter: {pattern} (RuleManager).")
        return result
        
    def remove_content_filter(self, pattern: str) -> bool:
        """移除内容过滤规则
        
        Args:
            pattern: 内容匹配模式
            
        Returns:
            bool: 是否移除成功
        """
        logger.info(f"Attempting to remove content filter: {pattern}")
        result = self.rule_manager.remove_content_filter(pattern)
        if result:
            if self.is_running and hasattr(self.packet_filter, 'remove_content_filter'):
                self.packet_filter.remove_content_filter(pattern)
                 # Recompile filters in packet_filter if running
                if hasattr(self.packet_filter, 'compiled_filters'):
                    try:
                        self.packet_filter.compiled_filters = [re.compile(p) for p in self.packet_filter.content_filters]
                        logger.debug("Recompiled content filters in PacketFilter.")
                    except Exception as e:
                         logger.error(f"Failed to recompile content filters: {e}")

            self._add_log(f"移除内容过滤规则: {pattern}", level=logging.INFO)
            logger.info(f"Successfully removed content filter: {pattern}")
        else:
            logger.warning(f"Failed to remove content filter: {pattern} (RuleManager).")
        return result
        
    # TODO: 添加正则表达式高级匹配功能 (Partially done, needs UI/RuleManager validation)
    # TODO: 添加内容过滤规则测试功能 (Lower Priority)
    # TODO: 添加预设内容过滤模板功能 (Lower Priority)
        
    # 协议过滤管理
    def set_protocol_filter(self, protocol: str, enabled: bool) -> bool:
        """设置协议过滤
        
        Args:
            protocol: 协议名称(tcp/udp)
            enabled: 是否启用
            
        Returns:
            bool: 是否设置成功
        """
        proto_lower = protocol.lower()
        if proto_lower not in ['tcp', 'udp']:
            logger.warning(f"Invalid protocol specified for filtering: {protocol}")
            return False
            
        logger.info(f"Setting {proto_lower.upper()} protocol filter to {'enabled' if enabled else 'disabled'}.")
        # 更新规则管理器
        rules = self.rule_manager.get_rules()
        if rules['protocol_filter'].get(proto_lower) != enabled:
            rules['protocol_filter'][proto_lower] = enabled
            self.rule_manager.save_rules(rules)
            
            # 如果防火墙正在运行，更新过滤器
            if self.is_running and hasattr(self.packet_filter, 'protocol_filter'):
                self.packet_filter.protocol_filter[proto_lower] = enabled
                self._add_log(f"已{'启用' if enabled else '禁用'} {protocol.upper()} 协议过滤", level=logging.INFO)
                logger.info(f"Applied {proto_lower.upper()} protocol filter change to running PacketFilter.")
            return True
        else:
            logger.info(f"{proto_lower.upper()} protocol filter already set to {'enabled' if enabled else 'disabled'}.")
        return True # Return true even if no change was made
        
    # TODO: 添加更多协议支持(如ICMP、DNS等) (Lower Priority)
    # TODO: 添加协议级别的高级过滤功能 (Lower Priority)
        
    # TODO: 添加自动性能调优功能 (Lower Priority)
    # TODO: 添加性能设置配置文件保存/加载功能 (Lower Priority)
    # TODO: 添加设置预设模板功能(如高性能模式、节能模式等) (Lower Priority)
