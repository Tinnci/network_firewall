#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
import logging
import threading # Added import
from typing import Dict, Optional, Any, Union, Callable
from PyQt6.QtCore import QObject # Keep QObject inheritance for signals

# Import from local modules
from .rule_manager import RuleManager
from .packet_interceptor import PacketInterceptor
from .packet_analyzer import PacketAnalyzer
from .packet_processor import PacketProcessor
# Import from utils
from ..utils.logging_utils import setup_logging, SignalHandler 
from ..utils.performance_utils import get_system_resource_usage
# Import config
from ..config import CONFIG 

# Setup logging and get the signal handler instance
# This still needs to be called somewhere, ideally main.py, but keep here for now
# Ensure it uses the config
signal_handler_instance: SignalHandler = setup_logging()

# Get logger for this module
logger = logging.getLogger('FirewallCore')


class Firewall(QObject):
    """防火墙主类，协调各个组件"""
    # 使用传递的信号而不是直接引用
    log_signal = signal_handler_instance.log_signal

    def __init__(self, rules_file: Optional[str] = None): # Allow overriding rules file path
        """初始化防火墙"""
        super().__init__()
        # Save the signal handler instance, but don't create strong references
        # self.signal_handler = signal_handler_instance 

        logger.info("正在初始化防火墙...")
        
        # Use rules file path from config if not provided
        if rules_file is None:
            rules_file = CONFIG['rules'].get('rules_file', 'rules.yaml')
            
        # 创建规则管理器
        self.rule_manager = RuleManager(rules_file)
        logger.debug(f"使用文件初始化RuleManager: {rules_file}")

        # 创建核心组件
        self.interceptor = PacketInterceptor()
        self.analyzer = PacketAnalyzer()
        self.processor = PacketProcessor(self.interceptor, self.analyzer)
        logger.debug("已初始化Interceptor、Analyzer和Processor。")

        # 状态
        self.is_running = False

        # 性能配置 (Load defaults from config)
        self.performance_settings = CONFIG['performance'].copy()
        logger.debug(f"默认性能设置: {self.performance_settings}")
        
        # 数据包回调
        self.packet_callback = None

        # 规则动态加载相关
        self.rule_monitor_thread: Optional[threading.Thread] = None
        self.rule_monitor_stop_event = threading.Event()
        self.rule_check_interval = CONFIG['rules'].get('reload_check_interval_seconds', 5) # Default 5 seconds

        # TODO: 添加统计信息持久化存储功能
        
    def __del__(self):
        """在对象销毁时清理资源"""
        try:
            self.log_signal = None
        except:
            pass

    def start(self) -> bool:
        """启动防火墙"""
        if self.is_running:
            logger.warning("防火墙已经在运行中。")
            return True

        logger.info("正在启动防火墙...")
        # 加载并应用规则
        rules = self.rule_manager.get_rules() # Initial load
        self.analyzer.set_rules(rules)
        logger.debug("规则已加载并应用于Analyzer。")

        # 应用性能配置
        self._apply_performance_settings() 

        # 启动处理器 
        self.processor.start()

        # 启动拦截器 
        interceptor_cfg = CONFIG.get('interceptor', {})
        filter_str = interceptor_cfg.get('filter_string', "tcp or udp")
        if self.interceptor.start(filter_string=filter_str):
            self.is_running = True
            logger.info("防火墙已启动")
            # 启动规则监控线程
            self.rule_monitor_stop_event.clear()
            self.rule_monitor_thread = threading.Thread(target=self._rule_monitoring_loop, daemon=True)
            self.rule_monitor_thread.name = "RuleMonitorThread"
            self.rule_monitor_thread.start()
            logger.info(f"规则文件监控线程已启动，检查间隔: {self.rule_check_interval} 秒。")
            return True
        else:
            logger.error("无法启动包拦截器。防火墙启动中止。")
            self.processor.stop() 
            return False

    def stop(self) -> bool:
        """停止防火墙"""
        if not self.is_running:
            logger.warning("防火墙未运行。")
            return True

        logger.info("正在停止防火墙...")
        # 停止规则监控线程
        if self.rule_monitor_thread and self.rule_monitor_thread.is_alive():
            logger.debug("正在停止规则文件监控线程...")
            self.rule_monitor_stop_event.set()
            self.rule_monitor_thread.join(timeout=self.rule_check_interval + 1) # Wait a bit longer than interval
            if self.rule_monitor_thread.is_alive():
                logger.warning("规则文件监控线程未能正常停止。")
            else:
                logger.info("规则文件监控线程已停止。")
        self.rule_monitor_thread = None

        self.interceptor.stop()
        self.processor.stop()

        self.is_running = False
        logger.info("防火墙已停止")
        return True

    def _rule_monitoring_loop(self):
        """定期检查规则文件是否有变动，并按需重载。"""
        logger.info("规则监控循环已启动。")
        while not self.rule_monitor_stop_event.is_set():
            try:
                if self.rule_manager.check_and_reload_rules():
                    logger.info("防火墙检测到规则已更新，正在应用到分析器...")
                    self._update_analyzer_rules()
                    # Log applied rules summary here as well
                    if self.analyzer: # Check if analyzer exists
                        rules_summary = {
                            'ip_blacklist_size': len(self.analyzer.ip_blacklist),
                            'ip_whitelist_size': len(self.analyzer.ip_whitelist),
                            'port_blacklist_size': len(self.analyzer.port_blacklist),
                            'port_whitelist_size': len(self.analyzer.port_whitelist),
                            'content_filters_count': len(self.analyzer.content_filters),
                            'protocol_filter': self.analyzer.protocol_filter
                        }
                        logger.info(f"Firewall: Analyzer rules updated with: {rules_summary}")
                    else:
                        logger.warning("Firewall: Analyzer not available for logging summary after update.")
            except Exception as e:
                logger.error(f"规则监控循环中发生错误: {e}", exc_info=True)
            
            # Wait for the specified interval or until stop event is set
            # self.rule_monitor_stop_event.wait() returns True if event set, False on timeout
            # We want to loop as long as event is NOT set, so check it before wait or after timeout.
            if self.rule_monitor_stop_event.wait(timeout=self.rule_check_interval):
                break # Event was set, exit loop
        logger.info("规则监控循环已停止。")

    def _apply_performance_settings(self):
        """将性能设置应用到相关组件"""
        logger.debug("Applying performance settings...")
        # Apply settings to Analyzer
        analyzer_settings = {
            'allow_private_network': self.performance_settings.get('allow_private_network', True),
            'skip_local_packets': self.performance_settings.get('skip_local_packets', True),
        }
        self.analyzer.set_settings(analyzer_settings)

        # Apply settings to Processor
        processor_settings = {
            'use_queue_model': self.performance_settings.get('use_queue_model', False),
            'num_workers': self.performance_settings.get('num_workers', 2),
            'use_packet_pool': self.performance_settings.get('use_packet_pool', True),
            'max_pool_size': self.performance_settings.get('packet_pool_size', 100), 
        }
        self.processor.set_settings(processor_settings)

        # Apply settings to Interceptor (if applicable)
        interceptor_cfg = CONFIG.get('interceptor', {})
        interceptor_settings = {
             'queue_len': interceptor_cfg.get('queue_len', 8192),
             'queue_time': interceptor_cfg.get('queue_time', 2000),
        }
        # Assuming interceptor might have a method like this in the future
        if hasattr(self.interceptor, '_configure_windivert_params'):
             # This needs modification in interceptor to accept params
             # For now, interceptor uses its own defaults or config directly if modified
             pass 
             # self.interceptor._configure_windivert_params(**interceptor_settings) 

        logger.debug("Performance settings applied to components.")

    def update_performance_settings(self, new_settings: Dict) -> bool:
        """更新性能设置"""
        logger.info(f"Updating performance settings: {new_settings}")
        updated = False
        # Use default config as the reference for valid keys
        valid_keys = CONFIG['performance'].keys() 
        for key, value in new_settings.items():
            if key in valid_keys: # Check against valid keys from default config
                if self.performance_settings.get(key) != value:
                    self.performance_settings[key] = value
                    logger.debug(f"Updated setting: {key} = {value}")
                    updated = True
            else:
                logger.warning(f"Attempted to update unknown or non-performance setting: {key}")

        if updated:
            self._apply_performance_settings() # Re-apply all settings
            logger.info("Applied updated performance settings.")
        else:
            logger.info("No changes detected in performance settings.")

        return True

    def get_status(self) -> Dict[str, Any]:
        """获取防火墙状态"""
        status = {
            'running': self.is_running,
            'rules': self.rule_manager.get_rules(),
            'performance_settings': self.performance_settings,
            'processor_stats': self.processor.get_stats() if self.processor else {},
        }
        return status

    def restart(self) -> bool:
        """重启防火墙"""
        logger.info("Restarting Firewall...")
        self.stop()
        logger.debug("Waiting for resources to release...")
        time.sleep(1)
        result = self.start()
        if result:
            logger.info("Firewall restarted successfully.")
        else:
            logger.error("Firewall restart failed.")
        return result

    def restart_windivert(self) -> bool:
        """重启WinDivert实例 (via Interceptor)"""
        if not self.is_running:
            logger.warning("Cannot restart WinDivert, Firewall is not running.")
            return False

        logger.info("Attempting to restart WinDivert via Interceptor...")
        result = self.interceptor.restart_windivert()
        if result:
            logger.info("WinDivert restarted successfully via Interceptor.")
        else:
            logger.error("WinDivert restart failed via Interceptor.")
        return result

    def get_detailed_stats(self) -> Dict[str, Any]:
        """获取详细的统计信息"""
        if not self.is_running:
            return {}

        processor_stats = self.processor.get_stats()
        detailed_stats = {
            **processor_stats,
        }
        detailed_stats['system_resources'] = get_system_resource_usage()

        try:
            total_processed = processor_stats.get('total_processed', 0)
            start_time = processor_stats.get('start_time', 0)
            if total_processed > 0 and start_time > 0:
                running_time = time.time() - start_time
                detailed_stats['packets_per_second'] = total_processed / max(1, running_time)
            else:
                 detailed_stats['packets_per_second'] = 0.0
        except Exception as e:
             logger.warning(f"Could not calculate packets per second: {e}")
             detailed_stats['packets_per_second'] = 0.0

        return detailed_stats

    # --- Rule Management Methods ---

    def _update_analyzer_rules(self):
        """Helper to push current rules from RuleManager to Analyzer"""
        if self.analyzer:
            try:
                current_rules_from_manager = self.rule_manager.get_rules()
                # Log summary of rules being pushed to analyzer
                rules_summary_to_push = {
                    'ip_blacklist_size': len(current_rules_from_manager.get('ip_blacklist', set())),
                    'ip_whitelist_size': len(current_rules_from_manager.get('ip_whitelist', set())),
                    'port_blacklist_size': len(current_rules_from_manager.get('port_blacklist', set())),
                    'port_whitelist_size': len(current_rules_from_manager.get('port_whitelist', set())),
                    'content_filters_count': len(current_rules_from_manager.get('content_filters', [])),
                    'protocol_filter': current_rules_from_manager.get('protocol_filter', {})
                }
                logger.debug(f"Firewall: Pushing rules to Analyzer: {rules_summary_to_push}")
                self.analyzer.set_rules(current_rules_from_manager)
            except Exception as e:
                 logger.error(f"Failed to update analyzer rules: {e}")

    def add_ip_to_blacklist(self, ip: str) -> bool:
        logger.debug(f"Firewall: Adding IP {ip} to blacklist...")
        result = self.rule_manager.add_ip_to_blacklist(ip)
        if result:
            self._update_analyzer_rules()
            # logger.info(f"IP {ip} added to blacklist.") # RuleManager logs this
        return result

    def remove_ip_from_blacklist(self, ip: str) -> bool:
        logger.debug(f"Firewall: Removing IP {ip} from blacklist...")
        result = self.rule_manager.remove_ip_from_blacklist(ip)
        if result:
            self._update_analyzer_rules()
            # logger.info(f"IP {ip} removed from blacklist.")
        return result

    def add_ip_to_whitelist(self, ip: str) -> bool:
        logger.debug(f"Firewall: Adding IP {ip} to whitelist...")
        result = self.rule_manager.add_ip_to_whitelist(ip)
        if result:
            self._update_analyzer_rules()
            # logger.info(f"IP {ip} added to whitelist.")
        return result

    def remove_ip_from_whitelist(self, ip: str) -> bool:
        logger.debug(f"Firewall: Removing IP {ip} from whitelist...")
        result = self.rule_manager.remove_ip_from_whitelist(ip)
        if result:
            self._update_analyzer_rules()
            # logger.info(f"IP {ip} removed from whitelist.")
        return result

    def add_port_to_blacklist(self, port: Union[int, str]) -> bool:
        logger.debug(f"Firewall: Adding port/range {port} to blacklist...")
        result = self.rule_manager.add_port_to_blacklist(port)
        if result:
            self._update_analyzer_rules()
            # logger.info(f"Port/range {port} added to blacklist.")
        return result

    def remove_port_from_blacklist(self, port: Union[int, str]) -> bool:
        logger.debug(f"Firewall: Removing port/range {port} from blacklist...")
        result = self.rule_manager.remove_port_from_blacklist(port)
        if result:
            self._update_analyzer_rules()
            # logger.info(f"Port/range {port} removed from blacklist.")
        return result

    def add_port_to_whitelist(self, port: Union[int, str]) -> bool:
        logger.debug(f"Firewall: Adding port/range {port} to whitelist...")
        result = self.rule_manager.add_port_to_whitelist(port)
        if result:
            self._update_analyzer_rules()
            # logger.info(f"Port/range {port} added to whitelist.")
        return result

    def remove_port_from_whitelist(self, port: Union[int, str]) -> bool:
        logger.debug(f"Firewall: Removing port/range {port} from whitelist...")
        result = self.rule_manager.remove_port_from_whitelist(port)
        if result:
            self._update_analyzer_rules()
            # logger.info(f"Port/range {port} removed from whitelist.")
        return result

    def add_content_filter(self, pattern: str) -> bool:
        logger.debug(f"Firewall: Adding content filter '{pattern}'...")
        result = self.rule_manager.add_content_filter(pattern)
        if result:
            self._update_analyzer_rules()
            # logger.info(f"Content filter '{pattern}' added.")
        return result

    def remove_content_filter(self, pattern: str) -> bool:
        logger.debug(f"Firewall: Removing content filter '{pattern}'...")
        result = self.rule_manager.remove_content_filter(pattern)
        if result:
            self._update_analyzer_rules()
            # logger.info(f"Content filter '{pattern}' removed.")
        return result

    def set_protocol_filter(self, protocol: str, enabled: bool) -> bool:
        logger.debug(f"Firewall: Setting {protocol.upper()} filter to {enabled}...")
        result = self.rule_manager.set_protocol_filter(protocol, enabled)
        if result:
             self._update_analyzer_rules()
             # logger.info(f"{protocol.upper()} filter set to {enabled}.") # RuleManager logs this
        return result

    def register_packet_callback(self, callback: Callable[[Dict, bool], None]):
        """注册数据包处理回调，用于UI实时显示数据包信息
        
        Args:
            callback: 回调函数，接收两个参数：packet_info(Dict)和passed(bool)
        """
        self.packet_callback = callback
        self.processor.register_processed_packet_callback(callback)
        logger.debug("已注册数据包处理回调函数")
        return True
