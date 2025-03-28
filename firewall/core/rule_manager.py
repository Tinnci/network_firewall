#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import yaml
from typing import Dict, List, Set, Any, Optional


class RuleManager:
    """过滤规则管理器"""
    
    def __init__(self, rules_file: str = 'rules.yaml'):
        """初始化规则管理器
        
        Args:
            rules_file: 规则文件路径
        """
        self.rules_file = rules_file
        self.rules = {
            'ip_blacklist': set(),
            'ip_whitelist': set(),
            'port_blacklist': set(),
            'port_whitelist': set(),
            'content_filters': [],
            'protocol_filter': {'tcp': True, 'udp': True}
        }
        
        # 尝试加载规则
        self.load_rules()
        
    def load_rules(self) -> bool:
        """从文件加载规则
        
        Returns:
            bool: 是否加载成功
        """
        try:
            if not os.path.exists(self.rules_file):
                return False
                
            with open(self.rules_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                
            if not data:
                return False
                
            # 加载IP黑白名单
            if 'ip_blacklist' in data:
                self.rules['ip_blacklist'] = set(data['ip_blacklist'])
                
            if 'ip_whitelist' in data:
                self.rules['ip_whitelist'] = set(data['ip_whitelist'])
                
            # 加载端口黑白名单
            if 'port_blacklist' in data:
                self.rules['port_blacklist'] = set(data['port_blacklist'])
                
            if 'port_whitelist' in data:
                self.rules['port_whitelist'] = set(data['port_whitelist'])
                
            # 加载内容过滤规则
            if 'content_filters' in data:
                self.rules['content_filters'] = data['content_filters']
                
            # 加载协议过滤规则
            if 'protocol_filter' in data:
                self.rules['protocol_filter'] = data['protocol_filter']
                
            return True
        except Exception as e:
            print(f"加载规则文件失败: {e}")
            return False
            
    def save_rules(self) -> bool:
        """保存规则到文件
        
        Returns:
            bool: 是否保存成功
        """
        try:
            # 转换集合为列表以便YAML序列化
            data = {
                'ip_blacklist': list(self.rules['ip_blacklist']),
                'ip_whitelist': list(self.rules['ip_whitelist']),
                'port_blacklist': list(self.rules['port_blacklist']),
                'port_whitelist': list(self.rules['port_whitelist']),
                'content_filters': self.rules['content_filters'],
                'protocol_filter': self.rules['protocol_filter']
            }
            
            with open(self.rules_file, 'w', encoding='utf-8') as f:
                yaml.dump(data, f, default_flow_style=False)
                
            return True
        except Exception as e:
            print(f"保存规则文件失败: {e}")
            return False
            
    def get_rules(self) -> Dict:
        """获取当前规则
        
        Returns:
            Dict: 当前规则字典
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
            print(f"更新规则失败: {e}")
            return False
            
    def add_ip_to_blacklist(self, ip: str) -> bool:
        """添加IP到黑名单
        
        Args:
            ip: IP地址
            
        Returns:
            bool: 是否添加成功
        """
        self.rules['ip_blacklist'].add(ip)
        return self.save_rules()
        
    def remove_ip_from_blacklist(self, ip: str) -> bool:
        """从黑名单移除IP
        
        Args:
            ip: IP地址
            
        Returns:
            bool: 是否移除成功
        """
        if ip in self.rules['ip_blacklist']:
            self.rules['ip_blacklist'].remove(ip)
            return self.save_rules()
        return False
        
    def add_ip_to_whitelist(self, ip: str) -> bool:
        """添加IP到白名单
        
        Args:
            ip: IP地址
            
        Returns:
            bool: 是否添加成功
        """
        self.rules['ip_whitelist'].add(ip)
        return self.save_rules()
        
    def remove_ip_from_whitelist(self, ip: str) -> bool:
        """从白名单移除IP
        
        Args:
            ip: IP地址
            
        Returns:
            bool: 是否移除成功
        """
        if ip in self.rules['ip_whitelist']:
            self.rules['ip_whitelist'].remove(ip)
            return self.save_rules()
        return False
        
    def add_port_to_blacklist(self, port: int) -> bool:
        """添加端口到黑名单
        
        Args:
            port: 端口号
            
        Returns:
            bool: 是否添加成功
        """
        self.rules['port_blacklist'].add(port)
        return self.save_rules()
        
    def remove_port_from_blacklist(self, port: int) -> bool:
        """从黑名单移除端口
        
        Args:
            port: 端口号
            
        Returns:
            bool: 是否移除成功
        """
        if port in self.rules['port_blacklist']:
            self.rules['port_blacklist'].remove(port)
            return self.save_rules()
        return False
        
    def add_port_to_whitelist(self, port: int) -> bool:
        """添加端口到白名单
        
        Args:
            port: 端口号
            
        Returns:
            bool: 是否添加成功
        """
        self.rules['port_whitelist'].add(port)
        return self.save_rules()
        
    def remove_port_from_whitelist(self, port: int) -> bool:
        """从白名单移除端口
        
        Args:
            port: 端口号
            
        Returns:
            bool: 是否移除成功
        """
        if port in self.rules['port_whitelist']:
            self.rules['port_whitelist'].remove(port)
            return self.save_rules()
        return False
        
    def add_content_filter(self, pattern: str) -> bool:
        """添加内容过滤规则
        
        Args:
            pattern: 内容匹配模式
            
        Returns:
            bool: 是否添加成功
        """
        if pattern not in self.rules['content_filters']:
            self.rules['content_filters'].append(pattern)
            return self.save_rules()
        return False
        
    def remove_content_filter(self, pattern: str) -> bool:
        """移除内容过滤规则
        
        Args:
            pattern: 内容匹配模式
            
        Returns:
            bool: 是否移除成功
        """
        if pattern in self.rules['content_filters']:
            self.rules['content_filters'].remove(pattern)
            return self.save_rules()
        return False
        
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