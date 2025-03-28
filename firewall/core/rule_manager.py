#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import yaml
from typing import Dict, List, Set, Any, Optional, Tuple # Added Tuple
import ipaddress
import re
import logging # Added import

# Configure logging for RuleManager
logger = logging.getLogger('RuleManager')


class RuleManager:
    """过滤规则管理器"""
    
    def __init__(self, rules_file: str = 'rules.yaml'):
        """初始化规则管理器
        
        Args:
            rules_file: 规则文件路径
        """
        self.rules_file = rules_file
        self.rules = self._load_default_rules()
        
        # 如果规则文件存在，加载规则
        if os.path.isfile(rules_file):
            try:
                self.rules = self._load_rules()
            except Exception as e:
                logger.error(f"加载规则文件失败: {e}, 使用默认规则")
                
        # TODO: 添加规则版本控制功能 (Lower Priority)
        # TODO: 添加规则备份和恢复功能 (Lower Priority)
        
    def _load_default_rules(self) -> Dict:
        """加载默认规则
        
        Returns:
            Dict: 默认规则
        """
        return {
            'ip_blacklist': set(),
            'ip_whitelist': set(),
            'port_blacklist': set(),
            'port_whitelist': set(),
            'content_filters': [],
            'protocol_filter': {"tcp": True, "udp": True}
        }
        
    def _load_rules(self) -> Dict:
        """从文件加载规则
        
        Returns:
            Dict: 加载的规则
        """
        try:
            with open(self.rules_file, 'r', encoding='utf-8') as f:
                rules_data = yaml.safe_load(f)
                
                # 转换为适当的数据结构
                rules = {
                    'ip_blacklist': set(rules_data.get('ip_blacklist', [])),
                    'ip_whitelist': set(rules_data.get('ip_whitelist', [])),
                    'port_blacklist': set(rules_data.get('port_blacklist', [])),
                    'port_whitelist': set(rules_data.get('port_whitelist', [])),
                    'content_filters': rules_data.get('content_filters', []),
                    'protocol_filter': rules_data.get('protocol_filter', {"tcp": True, "udp": True})
                }
                
                # Validate loaded rules
                rules = self._validate_loaded_rules(rules)
                logger.info(f"成功加载并验证规则文件: {self.rules_file}")
                return rules
        except Exception as e:
            logger.error(f"加载规则文件时出错: {e}")
            return self._load_default_rules()
            
        # TODO: 添加规则格式错误处理 (Partially done in _validate_loaded_rules)
        
    def save_rules(self, rules: Dict = None) -> bool:
        """保存规则到文件
        
        Args:
            rules: 要保存的规则，默认为当前规则
            
        Returns:
            bool: 是否保存成功
        """
        if rules is None:
            rules = self.rules
            
        try:
            # 转换为可序列化的数据结构
            rules_data = {
                'ip_blacklist': list(rules['ip_blacklist']),
                'ip_whitelist': list(rules['ip_whitelist']),
                'port_blacklist': list(rules['port_blacklist']),
                'port_whitelist': list(rules['port_whitelist']),
                'content_filters': rules['content_filters'],
                'protocol_filter': rules['protocol_filter']
            }
            
            # 确保目录存在
            os.makedirs(os.path.dirname(os.path.abspath(self.rules_file)), exist_ok=True)
            
            with open(self.rules_file, 'w', encoding='utf-8') as f:
                yaml.dump(rules_data, f, default_flow_style=False)
                
            self.rules = rules
            logger.info(f"规则已成功保存到: {self.rules_file}")
            return True
        except Exception as e:
            logger.error(f"保存规则文件时出错: {e}")
            return False
            
        # TODO: 添加规则保存自动备份功能 (Lower Priority)
        # TODO: 添加规则变更日志记录功能 (Lower Priority)
        
    def get_rules(self) -> Dict:
        """获取当前规则
        
        Returns:
            Dict: 当前规则
        """
        return self.rules
        
    def update_rules(self, new_rules: Dict) -> bool:
        """更新规则
        
        Args:
            new_rules: 新规则字典
            
        Returns:
            bool: 是否更新成功
        """
        try:
            # 更新IP黑白名单
            if 'ip_blacklist' in new_rules:
                self.rules['ip_blacklist'] = set(new_rules['ip_blacklist'])
                
            if 'ip_whitelist' in new_rules:
                self.rules['ip_whitelist'] = set(new_rules['ip_whitelist'])
                
            # 更新端口黑白名单
            if 'port_blacklist' in new_rules:
                self.rules['port_blacklist'] = set(new_rules['port_blacklist'])
                
            if 'port_whitelist' in new_rules:
                self.rules['port_whitelist'] = set(new_rules['port_whitelist'])
                
            # 更新内容过滤规则
            if 'content_filters' in new_rules:
                self.rules['content_filters'] = new_rules['content_filters']
                
            # 更新协议过滤规则
            if 'protocol_filter' in new_rules:
                self.rules['protocol_filter'] = new_rules['protocol_filter']
                
            # 保存更新后的规则
            return self.save_rules()
        except Exception as e:
            logger.error(f"更新规则失败: {e}")
            return False
            
    def _is_valid_ip_or_cidr(self, ip_str: str) -> bool:
        """验证字符串是否为有效的IPv4/IPv6地址或CIDR块"""
        try:
            # 尝试解析为单个IP地址
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            try:
                # 尝试解析为IP网络 (CIDR)
                ipaddress.ip_network(ip_str, strict=False) # strict=False 允许主机位非零
                return True
            except ValueError:
                logger.warning(f"无效的IP或CIDR格式: {ip_str}")
                return False

    def _is_valid_port_or_range(self, port_str: str) -> bool:
        """验证字符串是否为有效的端口号或端口范围 (e.g., 80, 8000-8080)"""
        if isinstance(port_str, int): # Allow integers directly
             return 0 <= port_str <= 65535
        if not isinstance(port_str, str):
            return False
            
        if '-' in port_str:
            # Range check
            parts = port_str.split('-')
            if len(parts) == 2:
                try:
                    start = int(parts[0])
                    end = int(parts[1])
                    if 0 <= start <= 65535 and 0 <= end <= 65535 and start <= end:
                        return True
                except ValueError:
                    pass # Invalid integer format
        else:
            # Single port check
            try:
                port = int(port_str)
                if 0 <= port <= 65535:
                    return True
            except ValueError:
                pass # Invalid integer format
                
        logger.warning(f"无效的端口或范围格式: {port_str}")
        return False

    def _validate_loaded_rules(self, rules: Dict) -> Dict:
        """验证从文件加载的规则的有效性"""
        validated_rules = self._load_default_rules() # Start with defaults

        # Validate IP lists
        for key in ['ip_blacklist', 'ip_whitelist']:
            if key in rules:
                valid_ips = {ip for ip in rules[key] if isinstance(ip, str) and self._is_valid_ip_or_cidr(ip)}
                invalid_count = len(rules[key]) - len(valid_ips)
                if invalid_count > 0:
                    logger.warning(f"加载规则时发现 {invalid_count} 个无效的IP/CIDR条目在 {key} 中，已忽略。")
                validated_rules[key] = valid_ips

        # Validate Port lists (now allows strings for ranges)
        for key in ['port_blacklist', 'port_whitelist']:
             if key in rules:
                # Convert all items to string first for consistent validation
                items_str = [str(item) for item in rules[key]]
                valid_ports = {item for item in items_str if self._is_valid_port_or_range(item)}
                invalid_count = len(items_str) - len(valid_ports)
                if invalid_count > 0:
                    logger.warning(f"加载规则时发现 {invalid_count} 个无效的端口/范围条目在 {key} 中，已忽略。")
                validated_rules[key] = valid_ports # Store validated strings

        # Validate Content Filters (basic check for string type)
        if 'content_filters' in rules:
            valid_filters = [f for f in rules['content_filters'] if isinstance(f, str)]
            invalid_count = len(rules['content_filters']) - len(valid_filters)
            if invalid_count > 0:
                 logger.warning(f"加载规则时发现 {invalid_count} 个无效的内容过滤器条目（非字符串），已忽略。")
            validated_rules['content_filters'] = valid_filters
            # Further regex validation could be added here if needed

        # Validate Protocol Filter
        if 'protocol_filter' in rules and isinstance(rules['protocol_filter'], dict):
            valid_proto_filter = {}
            for proto, enabled in rules['protocol_filter'].items():
                if isinstance(proto, str) and proto.lower() in ['tcp', 'udp'] and isinstance(enabled, bool):
                    valid_proto_filter[proto.lower()] = enabled
                else:
                    logger.warning(f"加载规则时发现无效的协议过滤条目: {proto}={enabled}，已忽略。")
            validated_rules['protocol_filter'] = valid_proto_filter
        
        return validated_rules

    # IP黑白名单管理
    def add_ip_to_blacklist(self, ip: str) -> bool:
        """添加IP到黑名单
        
        Args:
            ip: IP地址或CIDR
            
        Returns:
            bool: 是否添加成功
        """
        if not self._is_valid_ip_or_cidr(ip):
            return False
            
        try:
            if ip not in self.rules['ip_blacklist']:
                self.rules['ip_blacklist'].add(ip)
                self.save_rules()
                logger.info(f"IP/CIDR '{ip}' 已添加到黑名单。")
                return True
            else:
                logger.info(f"IP/CIDR '{ip}' 已存在于黑名单中。")
                return True # Already exists, consider it success
        except Exception as e:
            logger.error(f"添加IP到黑名单时出错: {e}")
            return False
            
    def remove_ip_from_blacklist(self, ip: str) -> bool:
        """从黑名单移除IP
        
        Args:
            ip: IP地址或CIDR
            
        Returns:
            bool: 是否移除成功
        """
        try:
            if ip in self.rules['ip_blacklist']:
                self.rules['ip_blacklist'].remove(ip)
                self.save_rules()
                logger.info(f"IP/CIDR '{ip}' 已从黑名单移除。")
            else:
                 logger.info(f"IP/CIDR '{ip}' 不在黑名单中。")
            return True
        except Exception as e:
            logger.error(f"从黑名单移除IP时出错: {e}")
            return False
            
    def add_ip_to_whitelist(self, ip: str) -> bool:
        """添加IP到白名单
        
        Args:
            ip: IP地址或CIDR
            
        Returns:
            bool: 是否添加成功
        """
        if not self._is_valid_ip_or_cidr(ip):
            return False
            
        try:
            if ip not in self.rules['ip_whitelist']:
                self.rules['ip_whitelist'].add(ip)
                self.save_rules()
                logger.info(f"IP/CIDR '{ip}' 已添加到白名单。")
                return True
            else:
                logger.info(f"IP/CIDR '{ip}' 已存在于白名单中。")
                return True # Already exists, consider it success
        except Exception as e:
            logger.error(f"添加IP到白名单时出错: {e}")
            return False
            
    def remove_ip_from_whitelist(self, ip: str) -> bool:
        """从白名单移除IP
        
        Args:
            ip: IP地址或CIDR
            
        Returns:
            bool: 是否移除成功
        """
        try:
            if ip in self.rules['ip_whitelist']:
                self.rules['ip_whitelist'].remove(ip)
                self.save_rules()
                logger.info(f"IP/CIDR '{ip}' 已从白名单移除。")
            else:
                logger.info(f"IP/CIDR '{ip}' 不在白名单中。")
            return True
        except Exception as e:
            logger.error(f"从白名单移除IP时出错: {e}")
            return False
            
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
                        
                    if self._is_valid_ip_or_cidr(ip):
                        if ip not in self.rules[key]:
                            added_ips.add(ip)
                            imported_count += 1
                    else:
                        invalid_count += 1
                        logger.warning(f"导入时跳过无效IP/CIDR: {ip}")
            
            if added_ips:
                self.rules[key].update(added_ips)
                self.save_rules()
                logger.info(f"成功从 {filename} 导入 {imported_count} 个IP/CIDR到 {list_type}。")
            else:
                 logger.info(f"从 {filename} 未导入新的IP/CIDR到 {list_type}。")

            if invalid_count > 0:
                 logger.warning(f"导入过程中发现 {invalid_count} 个无效条目。")

            return True, imported_count, invalid_count
            
        except Exception as e:
            logger.error(f"从 {filename} 导入IP {list_type} 时出错: {e}")
            return False, 0, invalid_count

    # TODO: 添加IP地址范围验证功能 (Lower Priority - CIDR done)
    # TODO: 添加IP地理位置支持 (Lower Priority)
            
    # 端口黑白名单管理
    def add_port_to_blacklist(self, port: int) -> bool:
        """添加端口到黑名单
        
        Args:
            port: 端口号或范围字符串 (e.g., 80, "8000-8080")
            
        Returns:
            bool: 是否添加成功
        """
        port_str = str(port) # Ensure string format
        if not self._is_valid_port_or_range(port_str):
            return False
            
        try:
            if port_str not in self.rules['port_blacklist']:
                self.rules['port_blacklist'].add(port_str)
                self.save_rules()
                logger.info(f"端口/范围 '{port_str}' 已添加到黑名单。")
                return True
            else:
                logger.info(f"端口/范围 '{port_str}' 已存在于黑名单中。")
                return True # Already exists
        except Exception as e:
            logger.error(f"添加端口/范围到黑名单时出错: {e}")
            return False
            
    def remove_port_from_blacklist(self, port: int) -> bool:
        """从黑名单移除端口
        
        Args:
            port: 端口号或范围字符串
            
        Returns:
            bool: 是否移除成功
        """
        port_str = str(port) # Ensure string format
        try:
            if port_str in self.rules['port_blacklist']:
                self.rules['port_blacklist'].remove(port_str)
                self.save_rules()
                logger.info(f"端口/范围 '{port_str}' 已从黑名单移除。")
            else:
                logger.info(f"端口/范围 '{port_str}' 不在黑名单中。")
            return True
        except Exception as e:
            logger.error(f"从黑名单移除端口/范围时出错: {e}")
            return False
            
    def add_port_to_whitelist(self, port: int) -> bool:
        """添加端口到白名单
        
        Args:
            port: 端口号或范围字符串
            
        Returns:
            bool: 是否添加成功
        """
        port_str = str(port) # Ensure string format
        if not self._is_valid_port_or_range(port_str):
            return False
            
        try:
            if port_str not in self.rules['port_whitelist']:
                self.rules['port_whitelist'].add(port_str)
                self.save_rules()
                logger.info(f"端口/范围 '{port_str}' 已添加到白名单。")
                return True
            else:
                logger.info(f"端口/范围 '{port_str}' 已存在于白名单中。")
                return True # Already exists
        except Exception as e:
            logger.error(f"添加端口/范围到白名单时出错: {e}")
            return False
            
    def remove_port_from_whitelist(self, port: int) -> bool:
        """从白名单移除端口
        
        Args:
            port: 端口号或范围字符串
            
        Returns:
            bool: 是否移除成功
        """
        port_str = str(port) # Ensure string format
        try:
            if port_str in self.rules['port_whitelist']:
                self.rules['port_whitelist'].remove(port_str)
                self.save_rules()
                logger.info(f"端口/范围 '{port_str}' 已从白名单移除。")
            else:
                logger.info(f"端口/范围 '{port_str}' 不在白名单中。")
            return True
        except Exception as e:
            logger.error(f"从白名单移除端口/范围时出错: {e}")
            return False
            
    # TODO: 添加端口分组管理功能 (Lower Priority)
    # TODO: 添加常用服务端口预设功能 (Lower Priority)
            
    # 内容过滤规则管理
    def add_content_filter(self, pattern: str) -> bool:
        """添加内容过滤规则
        
        Args:
            pattern: 内容匹配模式
            
        Returns:
            bool: 是否添加成功
        """
        try:
            if pattern and pattern not in self.rules['content_filters']:
                # 验证正则表达式有效性
                re.compile(pattern)
                self.rules['content_filters'].append(pattern)
                self.save_rules()
                logger.info(f"内容过滤规则 '{pattern}' 已存在。")
                return True # Already exists
            return True
        except re.error as regex_err:
            logger.error(f"添加内容过滤规则失败: 无效的正则表达式 '{pattern}' - {regex_err}")
            return False
        except Exception as e:
            logger.error(f"添加内容过滤规则时出错: {e}")
            return False
            
    def remove_content_filter(self, pattern: str) -> bool:
        """移除内容过滤规则
        
        Args:
            pattern: 内容匹配模式
            
        Returns:
            bool: 是否移除成功
        """
        try:
            if pattern in self.rules['content_filters']:
                self.rules['content_filters'].remove(pattern)
                self.save_rules()
            else:
                logger.info(f"内容过滤规则 '{pattern}' 不存在。")
            return True
        except Exception as e:
            logger.error(f"移除内容过滤规则时出错: {e}")
            return False
            
    # TODO: 添加高级模式匹配功能 (Lower Priority)
    # TODO: 添加内容过滤规则分类功能 (Lower Priority)
    # TODO: 添加内容过滤规则优先级功能 (Lower Priority)
        
    def set_protocol_filter(self, protocol: str, enabled: bool) -> bool:
        """设置协议过滤规则
        
        Args:
            protocol: 协议名称（tcp/udp）
            enabled: 是否启用
            
        Returns:
            bool: 是否设置成功
        """
        if protocol.lower() in self.rules['protocol_filter']:
            self.rules['protocol_filter'][protocol.lower()] = enabled
            return self.save_rules()
        return False
