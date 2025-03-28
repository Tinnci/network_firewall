#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
import logging
from typing import Dict, Any, Union # Added Union
from PyQt6.QtCore import QObject # Keep QObject inheritance for signals

# Import from local modules
from .rule_manager import RuleManager
from .packet_interceptor import PacketInterceptor
from .packet_analyzer import PacketAnalyzer
from .packet_processor import PacketProcessor
# Import from utils
from ..utils.logging_utils import setup_logging, SignalHandler
from ..utils.performance_utils import get_system_resource_usage

# Setup logging and get the signal handler instance
# Consider moving this call to main.py
signal_handler_instance: SignalHandler = setup_logging()

# Get logger for this module
logger = logging.getLogger('FirewallCore')


class Firewall(QObject):
    """防火墙主类，协调各个组件"""
    log_signal = signal_handler_instance.log_signal

    def __init__(self, rules_file: str = 'rules.yaml'):
        """初始化防火墙"""
        super().__init__()

        logger.info("Initializing Firewall...")
        # 创建规则管理器
        self.rule_manager = RuleManager(rules_file)
        logger.debug(f"RuleManager initialized with file: {rules_file}")

        # 创建核心组件
        self.interceptor = PacketInterceptor()
        self.analyzer = PacketAnalyzer()
        self.processor = PacketProcessor(self.interceptor, self.analyzer)
        logger.debug("Interceptor, Analyzer, and Processor initialized.")

        # 状态
        self.is_running = False

        # 性能配置 (Central place for settings)
        self.performance_settings = {
            # Interceptor settings (currently not directly configurable in Interceptor)
            # 'use_batch_mode': True, # Example if Interceptor supported it
            # 'batch_size': 5,
            # 'batch_wait_time': 100,
            # Processor settings
            'use_queue_model': False,
            'num_workers': 2,
            'use_packet_pool': True,
            'packet_pool_size': 100, # Used for max_pool_size in Processor
            # Analyzer settings
            'skip_local_packets': True,
            'allow_private_network': True,
            # Settings not directly mapped currently
            # 'skip_large_packets': False,
            # 'large_packet_threshold': 1460,
        }
        logger.debug(f"Default performance settings: {self.performance_settings}")

        # Connect processor's callback (optional, if Firewall needs to react)
        # self.processor.register_processed_packet_callback(self._on_packet_processed)

        # TODO: 添加统计信息持久化存储功能

    def start(self) -> bool:
        """启动防火墙"""
        if self.is_running:
            logger.warning("Firewall is already running.")
            return True

        logger.info("Starting Firewall...")
        # 加载并应用规则
        rules = self.rule_manager.get_rules()
        self.analyzer.set_rules(rules)
        logger.debug("Rules loaded and applied to Analyzer.")

        # 应用性能配置
        self._apply_performance_settings() # Apply settings to relevant components

        # 启动处理器 (which might start worker threads)
        self.processor.start()

        # 启动拦截器 (which starts the main packet loop)
        # Pass the filter string if needed, default is "tcp or udp"
        if self.interceptor.start():
            self.is_running = True
            logger.info("防火墙已启动")
            logger.info("Interceptor started successfully. Firewall is running.")
            return True
        else:
            logger.error("Failed to start Packet Interceptor. Firewall startup aborted.")
            self.processor.stop() # Stop processor if interceptor failed
            return False

    def stop(self) -> bool:
        """停止防火墙"""
        if not self.is_running:
            logger.warning("Firewall is not running.")
            return True

        logger.info("Stopping Firewall...")
        # 停止拦截器 (stops receiving new packets)
        self.interceptor.stop()
        # 停止处理器 (stops worker threads and processing queue)
        self.processor.stop()

        self.is_running = False
        logger.info("防火墙已停止")
        logger.info("Firewall stopped.")
        return True

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
            'max_pool_size': self.performance_settings.get('packet_pool_size', 100), # Use packet_pool_size for max_pool_size
        }
        self.processor.set_settings(processor_settings)

        # Apply settings to Interceptor (if applicable in the future)
        # interceptor_settings = { ... }
        # self.interceptor.set_settings(interceptor_settings)

        logger.debug("Performance settings applied to components.")

    def update_performance_settings(self, new_settings: Dict) -> bool:
        """更新性能设置"""
        logger.info(f"Updating performance settings: {new_settings}")
        updated = False
        for key, value in new_settings.items():
            if key in self.performance_settings:
                if self.performance_settings[key] != value:
                    self.performance_settings[key] = value
                    logger.debug(f"Updated setting: {key} = {value}")
                    updated = True
            else:
                logger.warning(f"Attempted to update unknown setting: {key}")

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
            # Add interceptor/analyzer stats if they expose them
            # 'interceptor_stats': self.interceptor.get_stats() if self.interceptor else {},
            # 'analyzer_stats': self.analyzer.get_stats() if self.analyzer else {},
        }
        # Add diagnosis info (needs adaptation)
        # status['diagnosis'] = self._get_diagnosis()
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
        # The interceptor now handles its own restart logic
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
            # Add other component stats if needed
        }

        # Add system resource usage
        detailed_stats['system_resources'] = get_system_resource_usage()

        # Calculate packets per second based on processor stats
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
                self.analyzer.set_rules(self.rule_manager.get_rules())
            except Exception as e:
                 logger.error(f"Failed to update analyzer rules: {e}")

    def add_ip_to_blacklist(self, ip: str) -> bool:
        logger.debug(f"Firewall: Adding IP {ip} to blacklist...")
        result = self.rule_manager.add_ip_to_blacklist(ip)
        if result:
            self._update_analyzer_rules()
            logger.info(f"IP {ip} added to blacklist.")
        return result

    def remove_ip_from_blacklist(self, ip: str) -> bool:
        logger.debug(f"Firewall: Removing IP {ip} from blacklist...")
        result = self.rule_manager.remove_ip_from_blacklist(ip)
        if result:
            self._update_analyzer_rules()
            logger.info(f"IP {ip} removed from blacklist.")
        return result

    def add_ip_to_whitelist(self, ip: str) -> bool:
        logger.debug(f"Firewall: Adding IP {ip} to whitelist...")
        result = self.rule_manager.add_ip_to_whitelist(ip)
        if result:
            self._update_analyzer_rules()
            logger.info(f"IP {ip} added to whitelist.")
        return result

    def remove_ip_from_whitelist(self, ip: str) -> bool:
        logger.debug(f"Firewall: Removing IP {ip} from whitelist...")
        result = self.rule_manager.remove_ip_from_whitelist(ip)
        if result:
            self._update_analyzer_rules()
            logger.info(f"IP {ip} removed from whitelist.")
        return result

    def add_port_to_blacklist(self, port: Union[int, str]) -> bool:
        logger.debug(f"Firewall: Adding port/range {port} to blacklist...")
        result = self.rule_manager.add_port_to_blacklist(port)
        if result:
            self._update_analyzer_rules()
            logger.info(f"Port/range {port} added to blacklist.")
        return result

    def remove_port_from_blacklist(self, port: Union[int, str]) -> bool:
        logger.debug(f"Firewall: Removing port/range {port} from blacklist...")
        result = self.rule_manager.remove_port_from_blacklist(port)
        if result:
            self._update_analyzer_rules()
            logger.info(f"Port/range {port} removed from blacklist.")
        return result

    def add_port_to_whitelist(self, port: Union[int, str]) -> bool:
        logger.debug(f"Firewall: Adding port/range {port} to whitelist...")
        result = self.rule_manager.add_port_to_whitelist(port)
        if result:
            self._update_analyzer_rules()
            logger.info(f"Port/range {port} added to whitelist.")
        return result

    def remove_port_from_whitelist(self, port: Union[int, str]) -> bool:
        logger.debug(f"Firewall: Removing port/range {port} from whitelist...")
        result = self.rule_manager.remove_port_from_whitelist(port)
        if result:
            self._update_analyzer_rules()
            logger.info(f"Port/range {port} removed from whitelist.")
        return result

    def add_content_filter(self, pattern: str) -> bool:
        logger.debug(f"Firewall: Adding content filter '{pattern}'...")
        result = self.rule_manager.add_content_filter(pattern)
        if result:
            self._update_analyzer_rules()
            logger.info(f"Content filter '{pattern}' added.")
        return result

    def remove_content_filter(self, pattern: str) -> bool:
        logger.debug(f"Firewall: Removing content filter '{pattern}'...")
        result = self.rule_manager.remove_content_filter(pattern)
        if result:
            self._update_analyzer_rules()
            logger.info(f"Content filter '{pattern}' removed.")
        return result

    def set_protocol_filter(self, protocol: str, enabled: bool) -> bool:
        logger.debug(f"Firewall: Setting {protocol.upper()} filter to {enabled}...")
        result = self.rule_manager.set_protocol_filter(protocol, enabled)
        if result:
             self._update_analyzer_rules()
             logger.info(f"{protocol.upper()} filter set to {enabled}.")
        return result

    # TODO: Adapt diagnosis logic if needed
    # def _get_diagnosis(self) -> Dict:
    #    # Combine diagnosis from interceptor/analyzer/processor if they provide it
    #    pass
