#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import logging
import re
import time
import yaml # Added import for yaml
from typing import Dict, Any, Tuple, Union, Optional

# Import from utils
from ..utils.network_utils import is_valid_ip_or_cidr, is_valid_port_or_range

# Logger for the helper functions (will resolve to firewall.core.rule_manager)
_helper_logger = logging.getLogger(__name__)

# --- Functions moved from rule_storage.py ---

def _load_default_rules_data() -> Dict[str, Any]:
    """
    返回表示默认规则的 Python 字典 (使用列表)。
    """
    return {
        'ip_blacklist': [],
        'ip_whitelist': [],
        'port_blacklist': [],
        'port_whitelist': [],
        'content_filters': [],
        'protocol_filter': {"tcp": True, "udp": True}
    }

def _load_rules_from_file(filepath: str) -> Optional[Dict[str, Any]]:
    """
    从指定的 YAML 文件加载原始规则数据。

    Args:
        filepath: 规则文件的路径。

    Returns:
        包含原始规则数据的字典，如果文件不存在或解析失败则返回 None。
    """
    if not os.path.isfile(filepath):
        _helper_logger.warning(f"规则文件不存在: {filepath}")
        return None
        
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            rules_data = yaml.safe_load(f)
            if not isinstance(rules_data, dict):
                 _helper_logger.error(f"规则文件格式无效 (不是字典): {filepath}")
                 return None
            _helper_logger.info(f"从文件加载原始规则数据: {filepath}")
            return rules_data
    except yaml.YAMLError as e:
        _helper_logger.error(f"解析规则文件时出错 (YAML 错误): {filepath} - {e}")
        return None
    except Exception as e:
        _helper_logger.error(f"加载规则文件时发生未知错误: {filepath} - {e}")
        return None

def _save_rules_to_file(filepath: str, rules: Dict[str, Any]) -> bool:
    """
    将规则字典保存到指定的 YAML 文件。
    注意：输入字典中的集合应在此函数调用前转换为列表。

    Args:
        filepath: 要保存到的文件路径。
        rules: 包含规则的字典 (集合应已转换为列表)。

    Returns:
        bool: 是否保存成功。
    """
    try:
        # 确保目录存在
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        
        # 准备要写入的数据 (确保集合已转换为排序列表)
        rules_data_to_save = {}
        for key, value in rules.items():
            if isinstance(value, set):
                rules_data_to_save[key] = sorted(list(value))
            else:
                rules_data_to_save[key] = value # Assume other types (list, dict) are serializable

        with open(filepath, 'w', encoding='utf-8') as f:
            yaml.dump(rules_data_to_save, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
            
        _helper_logger.info(f"规则已成功保存到: {filepath}")
        return True
    except Exception as e:
        _helper_logger.error(f"保存规则文件时出错: {filepath} - {e}")
        return False

# --- Functions moved from rule_validator.py ---

def _validate_rules(rules_data: Dict[str, Any], default_rules_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    验证从存储加载的原始规则数据，并将其转换为内部使用的、经过验证的数据结构。

    Args:
        rules_data: 从文件加载的原始规则字典。
        default_rules_data: 用于获取默认值的默认规则字典。

    Returns:
        包含经过验证和转换的数据（例如，集合）的新字典。
    """
    validated_rules = {} # Start with an empty dict

    # Validate IP lists
    for key in ['ip_blacklist', 'ip_whitelist']:
        raw_list_candidate = rules_data.get(key) # Get from file data first
        default_list_for_key = default_rules_data.get(key, [])

        if raw_list_candidate is None: # Key was not in file
            _helper_logger.debug(f"Validator: Key '{key}' not found in rules_data. Using default: {default_list_for_key}")
            raw_list = default_list_for_key
        else:
            raw_list = raw_list_candidate
        
        _helper_logger.info(f"Validator: For IP key '{key}', raw_list from rules_data (or default if key missing) is: {raw_list}, Type: {type(raw_list)}")

        if not isinstance(raw_list, list):
             _helper_logger.warning(f"规则 '{key}' 格式无效 (不是列表，实际类型: {type(raw_list)})，使用默认值。 Raw data was: {raw_list}")
             raw_list = default_list_for_key # Revert to default (empty list from default_rules_data)
             
        valid_ips = {ip for ip in raw_list if isinstance(ip, str) and is_valid_ip_or_cidr(ip)}
        invalid_count = len(raw_list) - len(valid_ips)
        if invalid_count > 0:
            _helper_logger.warning(f"加载规则时发现 {invalid_count} 个无效的IP/CIDR条目在 '{key}' 中，已忽略。")
        validated_rules[key] = valid_ips # Store as set

    # Validate Port lists
    for key in ['port_blacklist', 'port_whitelist']:
        raw_list_candidate = rules_data.get(key) # Get from file data first
        default_list_for_key = default_rules_data.get(key, [])

        if raw_list_candidate is None: # Key was not in file
            _helper_logger.debug(f"Validator: Key '{key}' not found in rules_data. Using default: {default_list_for_key}")
            raw_list = default_list_for_key
        else:
            raw_list = raw_list_candidate

        _helper_logger.info(f"Validator: For Port key '{key}', raw_list from rules_data (or default if key missing) is: {raw_list}, Type: {type(raw_list)}")

        if not isinstance(raw_list, list):
             _helper_logger.warning(f"规则 '{key}' 格式无效 (不是列表，实际类型: {type(raw_list)})，使用默认值。 Raw data was: {raw_list}")
             raw_list = default_list_for_key # Revert to default (empty list from default_rules_data)
             
        # Convert items to string for validation, handle potential non-string items gracefully
        items_as_str = []
        for item in raw_list:
             if isinstance(item, (str, int)):
                 items_as_str.append(str(item))
             else:
                 _helper_logger.warning(f"在 '{key}' 中发现非字符串/整数类型的无效端口条目: {item} (类型: {type(item)})，已忽略。")

        valid_ports = {item_str for item_str in items_as_str if is_valid_port_or_range(item_str)}
        invalid_count = len(items_as_str) - len(valid_ports)
        if invalid_count > 0:
            _helper_logger.warning(f"加载规则时发现 {invalid_count} 个无效的端口/范围条目在 '{key}' 中，已忽略。")
        validated_rules[key] = valid_ports # Store as set of strings

    # Validate Content Filters
    raw_content_filters_candidate = rules_data.get('content_filters')
    default_content_filters = default_rules_data.get('content_filters', [])

    if raw_content_filters_candidate is None: # Key was not in file
        _helper_logger.debug(f"Validator: Key 'content_filters' not found in rules_data. Using default: {default_content_filters}")
        raw_content_filters = default_content_filters
    else:
        raw_content_filters = raw_content_filters_candidate

    _helper_logger.info(f"Validator: For Content Filters key 'content_filters', raw_list from rules_data (or default if key missing) is: {raw_content_filters}, Type: {type(raw_content_filters)}")
    
    if not isinstance(raw_content_filters, list):
        _helper_logger.warning(f"规则 'content_filters' 格式无效 (不是列表，实际类型: {type(raw_content_filters)})，使用默认值。 Raw data was: {raw_content_filters}")
        raw_content_filters = default_content_filters # Revert to default (empty list from default_rules_data)
        
    valid_filters = []
    invalid_count = 0
    for f in raw_content_filters:
        if isinstance(f, str):
            try:
                re.compile(f)
                valid_filters.append(f)
            except re.error as e:
                 _helper_logger.warning(f"加载规则时发现无效的内容过滤正则表达式 '{f}': {e}，已忽略。")
                 invalid_count += 1
        else:
            _helper_logger.warning(f"加载规则时发现无效的内容过滤器条目（非字符串）: {f}，已忽略。")
            invalid_count += 1
    validated_rules['content_filters'] = valid_filters # Store as list

    # Validate Protocol Filter
    raw_protocol_filter = rules_data.get('protocol_filter', default_rules_data.get('protocol_filter', {}))
    if not isinstance(raw_protocol_filter, dict):
         _helper_logger.warning("规则 'protocol_filter' 格式无效 (不是字典)，使用默认值。")
         raw_protocol_filter = default_rules_data.get('protocol_filter', {})
         
    valid_proto_filter = default_rules_data.get('protocol_filter', {"tcp": True, "udp": True}).copy() # Start with default
    for proto, enabled in raw_protocol_filter.items():
        if isinstance(proto, str) and proto.lower() in ['tcp', 'udp']:
            if isinstance(enabled, bool):
                valid_proto_filter[proto.lower()] = enabled
            else:
                 _helper_logger.warning(f"加载规则时发现无效的协议过滤值 (非布尔值) for '{proto}': {enabled}，已忽略。")
        else:
            _helper_logger.warning(f"加载规则时发现无效的协议过滤键: {proto}，已忽略。")
    validated_rules['protocol_filter'] = valid_proto_filter

    _helper_logger.debug("规则数据验证和转换完成。")
    return validated_rules

# Logger for the RuleManager class
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
        raw_data = _load_rules_from_file(self.rules_file) # Use internal function
        default_data = _load_default_rules_data() # Use internal function
        
        if raw_data is None:
            logger.warning("无法从文件加载规则，将使用默认规则 (当前内存中)。磁盘上的文件 (如果存在) 将不会被默认规则覆盖，除非有明确的保存操作。")
            self.rules = _validate_rules(default_data, default_data) # Use internal function
        else:
            self.rules = _validate_rules(raw_data, default_data) # Use internal function
        
        logger.info(f"RuleManager._load_and_validate_rules: Current self.rules summary: "
                    f"IP Blacklist: {len(self.rules.get('ip_blacklist', set()))}, "
                    f"IP Whitelist: {len(self.rules.get('ip_whitelist', set()))}, "
                    f"Port Blacklist: {len(self.rules.get('port_blacklist', set()))}, "
                    f"Port Whitelist: {len(self.rules.get('port_whitelist', set()))}, "
                    f"Content Filters: {len(self.rules.get('content_filters', []))}, "
                    f"Protocol Filter: {self.rules.get('protocol_filter', {})}")

        self.last_rules_file_mtime = self._get_rules_file_mtime()
        if self.last_rules_file_mtime is None and os.path.exists(self.rules_file):
            self.last_rules_file_mtime = self._get_rules_file_mtime()

    def _save_rules_to_storage(self) -> bool:
        """将当前内存中的规则保存到存储。"""
        success = _save_rules_to_file(self.rules_file, self.rules) # Use internal function
        if success:
            self.last_rules_file_mtime = self._get_rules_file_mtime()
        return success

    def check_and_reload_rules(self) -> bool:
        """
        检查规则文件是否有变动，如果有则重新加载。
        返回:
            bool: 如果规则被重新加载则返回 True，否则 False。
        """
        current_mtime = self._get_rules_file_mtime()

        if current_mtime is None:
            if self.last_rules_file_mtime is not None:
                logger.warning(f"规则文件 '{self.rules_file}' 已被删除。将尝试加载默认规则。")
                self._load_and_validate_rules()
                return True
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
                self.rules['ip_blacklist'].discard(ip) 
                return False
        else:
            logger.info(f"IP/CIDR '{ip}' 已存在于黑名单中。")
            return True 
            
    def remove_ip_from_blacklist(self, ip: str) -> bool:
        if ip in self.rules['ip_blacklist']:
            self.rules['ip_blacklist'].discard(ip)
            if self._save_rules_to_storage():
                logger.info(f"IP/CIDR '{ip}' 已从黑名单移除并保存。")
                return True
            else:
                return False
        else:
             logger.info(f"IP/CIDR '{ip}' 不在黑名单中。")
             return True

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
                return False
        else:
            logger.info(f"端口/范围 '{port_str}' 不在白名单中。")
            return True

    def add_content_filter(self, pattern: str) -> bool:
        if not isinstance(pattern, str) or not pattern:
             logger.warning("尝试添加空的或非字符串内容过滤器。")
             return False
        try:
            re.compile(pattern)
        except re.error as regex_err:
            logger.error(f"添加内容过滤规则失败: 无效的正则表达式 '{pattern}' - {regex_err}")
            return False
            
        if pattern not in self.rules['content_filters']:
            self.rules['content_filters'].append(pattern)
            if self._save_rules_to_storage():
                logger.info(f"内容过滤规则 '{pattern}' 已添加并保存。")
                return True
            else:
                self.rules['content_filters'].remove(pattern)
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
                self.rules['content_filters'].append(pattern)
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
                self.rules['protocol_filter'][proto_lower] = not enabled 
                return False
        else:
            logger.info(f"{proto_lower.upper()} 协议过滤已是 {enabled}。")
            return True

    # --- Import/Export Methods ---

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
            os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)
            with open(filename, 'w', encoding='utf-8') as f:
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
                    if not ip or ip.startswith('#'):
                        continue
                        
                    if is_valid_ip_or_cidr(ip): 
                        if ip not in self.rules[key]:
                            added_ips.add(ip)
                    else:
                        invalid_count += 1
                        logger.warning(f"导入时跳过无效IP/CIDR: {ip}")
            
            if added_ips:
                original_set = self.rules[key].copy()
                self.rules[key].update(added_ips)
                if self._save_rules_to_storage():
                    imported_count = len(added_ips)
                    logger.info(f"成功从 {filename} 导入 {imported_count} 个IP/CIDR到 {list_type}。")
                else:
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
