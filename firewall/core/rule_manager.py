#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import logging
import re
import time
from typing import Dict, Any, Tuple, Union, Optional

# Import from local subpackage and utils
from .rules import rule_storage, rule_validator
from ..utils.network_utils import is_valid_ip_or_cidr, is_valid_port_or_range

logger = logging.getLogger('RuleManager')

class RuleManager:
    """
    过滤规则管理器。
    协调规则的加载、验证、内存管理和持久化。
    """
    
    def __init__(self, rules_file: str = 'rules.yaml'):
        """
        初始化规则管理器。
        
        Args:
            rules_file: 规则文件的路径。
        """
        self.rules_file = rules_file
        self.rules: Dict[str, Any] = {} # Initialize as empty dict
        self.last_rules_file_mtime: Optional[float] = None
        self._load_and_validate_rules()

    def _get_rules_file_mtime(self) -> Optional[float]:
        """安全地获取规则文件的最后修改时间。"""
        if not os.path.exists(self.rules_file):
            return None
        try:
            return os.path.getmtime(self.rules_file)
        except OSError as e:
            logger.warning(f"获取规则文件 '{self.rules_file}' 修改时间失败: {e}")
            return None

    def _load_and_validate_rules(self):
        """加载并验证规则，如果失败则使用默认规则。"""
        logger.debug(f"RuleManager: Attempting to load rules from '{self.rules_file}'")
        raw_data = rule_storage.load_rules_from_file(self.rules_file)
        default_data = rule_storage.load_default_rules_data()
        
        if raw_data is None:
            logger.warning("无法从文件加载规则，将使用默认规则。")
            self.rules = rule_validator.validate_rules(default_data, default_data) 
            self._save_rules_to_storage() 
        else:
            self.rules = rule_validator.validate_rules(raw_data, default_data)
        
        # Log summary of loaded rules (be careful with large rule sets)
        logger.debug(f"RuleManager: Rules loaded. IP Blacklist size: {len(self.rules.get('ip_blacklist', []))}, Content Filters count: {len(self.rules.get('content_filters', []))}")

        # Update mtime after loading/saving
        self.last_rules_file_mtime = self._get_rules_file_mtime()
        if self.last_rules_file_mtime is None and os.path.exists(self.rules_file):
            # If file was created by save_rules_to_storage, mtime might be None initially if get_mtime failed before creation.
            # Try to get it again.
            self.last_rules_file_mtime = self._get_rules_file_mtime()

    def _save_rules_to_storage(self) -> bool:
        """将当前内存中的规则保存到存储。"""
        success = rule_storage.save_rules_to_file(self.rules_file, self.rules)
        if success:
            self.last_rules_file_mtime = self._get_rules_file_mtime() # Update mtime after successful save
        return success

    def check_and_reload_rules(self) -> bool:
        """
        检查规则文件是否有变动，如果有则重新加载。
        返回:
            bool: 如果规则被重新加载则返回 True，否则 False。
        """
        current_mtime = self._get_rules_file_mtime()

        if current_mtime is None:
            # Rule file might have been deleted.
            if self.last_rules_file_mtime is not None: # It existed before
                logger.warning(f"规则文件 '{self.rules_file}' 已被删除。将尝试加载默认规则。")
                self._load_and_validate_rules() # This will load defaults and save, updating mtime
                return True # Rules were reloaded (to defaults)
            # If it never existed or was already gone, nothing to do.
            return False

        if self.last_rules_file_mtime is None or current_mtime != self.last_rules_file_mtime:
            logger.info(f"规则文件 '{self.rules_file}' 已更改 (mtime: {current_mtime} vs {self.last_rules_file_mtime})，正在重新加载...")
            self._load_and_validate_rules()
            logger.info("规则已成功重新加载。")
            return True
        return False

    def get_rules(self) -> Dict[str, Any]:
        """获取当前内存中的规则 (包含集合等内部使用的数据结构)。"""
        return self.rules
        
    # --- Rule Manipulation Methods ---
    # These methods modify the in-memory self.rules and then save.

    def add_ip_to_blacklist(self, ip: str) -> bool:
        if not is_valid_ip_or_cidr(ip): 
            logger.warning(f"尝试添加无效的IP/CIDR到黑名单: {ip}")
            return False
        if ip not in self.rules['ip_blacklist']:
            self.rules['ip_blacklist'].add(ip)
            if self._save_rules_to_storage():
                logger.info(f"IP/CIDR '{ip}' 已添加到黑名单并保存。")
                return True
            else:
                # Rollback memory change if save failed? Optional.
                self.rules['ip_blacklist'].discard(ip) 
                return False
        else:
            logger.info(f"IP/CIDR '{ip}' 已存在于黑名单中。")
            return True 
            
    def remove_ip_from_blacklist(self, ip: str) -> bool:
        if ip in self.rules['ip_blacklist']:
            self.rules['ip_blacklist'].discard(ip) # Use discard to avoid error if not present
            if self._save_rules_to_storage():
                logger.info(f"IP/CIDR '{ip}' 已从黑名单移除并保存。")
                return True
            else:
                # Rollback?
                # self.rules['ip_blacklist'].add(ip) 
                return False
        else:
             logger.info(f"IP/CIDR '{ip}' 不在黑名单中。")
             return True # Consider removal of non-existent item a success

    def add_ip_to_whitelist(self, ip: str) -> bool:
        if not is_valid_ip_or_cidr(ip): 
            logger.warning(f"尝试添加无效的IP/CIDR到白名单: {ip}")
            return False
        if ip not in self.rules['ip_whitelist']:
            self.rules['ip_whitelist'].add(ip)
            if self._save_rules_to_storage():
                logger.info(f"IP/CIDR '{ip}' 已添加到白名单并保存。")
                return True
            else:
                self.rules['ip_whitelist'].discard(ip)
                return False
        else:
            logger.info(f"IP/CIDR '{ip}' 已存在于白名单中。")
            return True

    def remove_ip_from_whitelist(self, ip: str) -> bool:
        if ip in self.rules['ip_whitelist']:
            self.rules['ip_whitelist'].discard(ip)
            if self._save_rules_to_storage():
                logger.info(f"IP/CIDR '{ip}' 已从白名单移除并保存。")
                return True
            else:
                # self.rules['ip_whitelist'].add(ip)
                return False
        else:
            logger.info(f"IP/CIDR '{ip}' 不在白名单中。")
            return True

    def add_port_to_blacklist(self, port: Union[int, str]) -> bool:
        port_str = str(port)
        if not is_valid_port_or_range(port_str): 
            logger.warning(f"尝试添加无效的端口/范围到黑名单: {port_str}")
            return False
        if port_str not in self.rules['port_blacklist']:
            self.rules['port_blacklist'].add(port_str)
            if self._save_rules_to_storage():
                logger.info(f"端口/范围 '{port_str}' 已添加到黑名单并保存。")
                return True
            else:
                self.rules['port_blacklist'].discard(port_str)
                return False
        else:
            logger.info(f"端口/范围 '{port_str}' 已存在于黑名单中。")
            return True

    def remove_port_from_blacklist(self, port: Union[int, str]) -> bool:
        port_str = str(port)
        if port_str in self.rules['port_blacklist']:
            self.rules['port_blacklist'].discard(port_str)
            if self._save_rules_to_storage():
                logger.info(f"端口/范围 '{port_str}' 已从黑名单移除并保存。")
                return True
            else:
                # self.rules['port_blacklist'].add(port_str)
                return False
        else:
            logger.info(f"端口/范围 '{port_str}' 不在黑名单中。")
            return True

    def add_port_to_whitelist(self, port: Union[int, str]) -> bool:
        port_str = str(port)
        if not is_valid_port_or_range(port_str): 
            logger.warning(f"尝试添加无效的端口/范围到白名单: {port_str}")
            return False
        if port_str not in self.rules['port_whitelist']:
            self.rules['port_whitelist'].add(port_str)
            if self._save_rules_to_storage():
                logger.info(f"端口/范围 '{port_str}' 已添加到白名单并保存。")
                return True
            else:
                self.rules['port_whitelist'].discard(port_str)
                return False
        else:
            logger.info(f"端口/范围 '{port_str}' 已存在于白名单中。")
            return True

    def remove_port_from_whitelist(self, port: Union[int, str]) -> bool:
        port_str = str(port)
        if port_str in self.rules['port_whitelist']:
            self.rules['port_whitelist'].discard(port_str)
            if self._save_rules_to_storage():
                logger.info(f"端口/范围 '{port_str}' 已从白名单移除并保存。")
                return True
            else:
                # self.rules['port_whitelist'].add(port_str)
                return False
        else:
            logger.info(f"端口/范围 '{port_str}' 不在白名单中。")
            return True

    def add_content_filter(self, pattern: str) -> bool:
        if not isinstance(pattern, str) or not pattern:
             logger.warning("尝试添加空的或非字符串内容过滤器。")
             return False
        try:
            re.compile(pattern) # Validate regex before adding
        except re.error as regex_err:
            logger.error(f"添加内容过滤规则失败: 无效的正则表达式 '{pattern}' - {regex_err}")
            return False
            
        if pattern not in self.rules['content_filters']:
            self.rules['content_filters'].append(pattern)
            if self._save_rules_to_storage():
                logger.info(f"内容过滤规则 '{pattern}' 已添加并保存。")
                return True
            else:
                self.rules['content_filters'].remove(pattern) # Rollback
                return False
        else:
            logger.info(f"内容过滤规则 '{pattern}' 已存在。")
            return True

    def remove_content_filter(self, pattern: str) -> bool:
        if pattern in self.rules['content_filters']:
            self.rules['content_filters'].remove(pattern)
            if self._save_rules_to_storage():
                logger.info(f"内容过滤规则 '{pattern}' 已移除并保存。")
                return True
            else:
                self.rules['content_filters'].append(pattern) # Rollback
                return False
        else:
            logger.info(f"内容过滤规则 '{pattern}' 不存在。")
            return True
            
    def set_protocol_filter(self, protocol: str, enabled: bool) -> bool:
        proto_lower = protocol.lower()
        if proto_lower not in ['tcp', 'udp']:
            logger.warning(f"无效的协议用于过滤: {protocol}")
            return False
        if not isinstance(enabled, bool):
             logger.warning(f"无效的启用值 (非布尔值) for protocol filter '{protocol}': {enabled}")
             return False

        if self.rules['protocol_filter'].get(proto_lower) != enabled:
            self.rules['protocol_filter'][proto_lower] = enabled
            if self._save_rules_to_storage():
                logger.info(f"{proto_lower.upper()} 协议过滤已设置为 {enabled} 并保存。")
                return True
            else:
                # Rollback
                self.rules['protocol_filter'][proto_lower] = not enabled 
                return False
        else:
            logger.info(f"{proto_lower.upper()} 协议过滤已是 {enabled}。")
            return True

    # --- Import/Export Methods ---
    # These still make sense here as they operate on the rule set as a whole

    def export_ip_list(self, list_type: str, filename: str) -> bool:
        """导出IP列表到文件 (一行一个IP/CIDR)"""
        if list_type not in ['blacklist', 'whitelist']:
            logger.error(f"无效的列表类型用于导出: {list_type}")
            return False
            
        key = f"ip_{list_type}"
        if key not in self.rules:
             logger.error(f"规则中未找到列表: {key}")
             return False

        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)
            with open(filename, 'w', encoding='utf-8') as f:
                # Sort for consistency
                sorted_list = sorted(list(self.rules[key]))
                for ip in sorted_list:
                    f.write(f"{ip}\n")
            logger.info(f"IP {list_type} 已成功导出到 {filename}")
            return True
        except Exception as e:
            logger.error(f"导出IP {list_type} 到 {filename} 时出错: {e}")
            return False

    def import_ip_list(self, list_type: str, filename: str) -> Tuple[bool, int, int]:
        """从文件导入IP列表 (一行一个IP/CIDR)，返回 (成功状态, 导入数量, 无效数量)"""
        if list_type not in ['blacklist', 'whitelist']:
            logger.error(f"无效的列表类型用于导入: {list_type}")
            return False, 0, 0
            
        key = f"ip_{list_type}"
        if key not in self.rules:
             logger.error(f"规则中未找到列表: {key}")
             return False, 0, 0

        imported_count = 0
        invalid_count = 0
        added_ips = set()

        try:
            if not os.path.isfile(filename):
                 logger.error(f"导入文件不存在: {filename}")
                 return False, 0, 0

            with open(filename, 'r', encoding='utf-8') as f:
                for line in f:
                    ip = line.strip()
                    if not ip or ip.startswith('#'): # Skip empty lines and comments
                        continue
                        
                    if is_valid_ip_or_cidr(ip): 
                        if ip not in self.rules[key]:
                            added_ips.add(ip)
                            # Don't increment count until save succeeds
                    else:
                        invalid_count += 1
                        logger.warning(f"导入时跳过无效IP/CIDR: {ip}")
            
            if added_ips:
                original_set = self.rules[key].copy() # Keep original for potential rollback
                self.rules[key].update(added_ips)
                if self._save_rules_to_storage():
                    imported_count = len(added_ips)
                    logger.info(f"成功从 {filename} 导入 {imported_count} 个IP/CIDR到 {list_type}。")
                else:
                    # Rollback memory change if save failed
                    self.rules[key] = original_set 
                    logger.error("保存导入的规则失败，内存更改已回滚。")
                    return False, 0, invalid_count
            else:
                 logger.info(f"从 {filename} 未导入新的IP/CIDR到 {list_type}。")

            if invalid_count > 0:
                 logger.warning(f"导入过程中发现 {invalid_count} 个无效条目。")

            return True, imported_count, invalid_count
            
        except Exception as e:
            logger.error(f"从 {filename} 导入IP {list_type} 时出错: {e}")
            return False, 0, invalid_count

    # Removed _load_rules, save_rules (using _save_rules_to_storage), 
    # _load_default_rules, _validate_loaded_rules
    # Removed validation methods (_is_valid_ip_or_cidr, _is_valid_port_or_range)
