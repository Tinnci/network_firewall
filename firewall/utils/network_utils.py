#!/usr/bin/env python
# -*- coding: utf-8 -*-

import ipaddress
import logging
from typing import Union, Tuple

logger = logging.getLogger(__name__) # Use module-specific logger

def is_valid_ip_or_cidr(ip_str: str) -> bool:
    """验证字符串是否为有效的IPv4/IPv6地址或CIDR块"""
    if not isinstance(ip_str, str):
        return False
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
            # Log only if validation fails, reduces noise compared to logging in RuleManager
            # logger.warning(f"无效的IP或CIDR格式: {ip_str}") 
            return False

def is_valid_port_or_range(port_input: Union[int, str]) -> bool:
    """验证输入是否为有效的端口号 (0-65535) 或端口范围字符串 (e.g., "8000-8080")"""
    if isinstance(port_input, int):
         return 0 <= port_input <= 65535

    if not isinstance(port_input, str):
        return False

    port_str = port_input.strip()
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
            
    # Log only if validation fails
    # logger.warning(f"无效的端口或范围格式: {port_input}")
    return False

def parse_port_rule(rule: str) -> Union[int, Tuple[int, int], None]:
    """
    解析端口规则字符串 (e.g., "80", "8000-8080") 并返回整数或元组。
    如果无效则返回 None。
    """
    if not isinstance(rule, str):
        return None

    rule = rule.strip()
    if '-' in rule:
        parts = rule.split('-')
        if len(parts) == 2:
            try:
                start = int(parts[0])
                end = int(parts[1])
                if 0 <= start <= 65535 and 0 <= end <= 65535 and start <= end:
                    return (start, end)
            except ValueError:
                pass
    else:
        try:
            port = int(rule)
            if 0 <= port <= 65535:
                return port
        except ValueError:
            pass
    # Log only if parsing fails
    # logger.warning(f"无法解析无效的端口规则: {rule}")
    return None

def is_private_ip(ip_str: str) -> bool:
    """判断IP字符串是否为私有地址或回环地址"""
    if not isinstance(ip_str, str):
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False

# Example usage:
# if __name__ == "__main__":
#     print(f"192.168.1.1 valid? {is_valid_ip_or_cidr('192.168.1.1')}")
#     print(f"10.0.0.0/8 valid? {is_valid_ip_or_cidr('10.0.0.0/8')}")
#     print(f"invalid-ip valid? {is_valid_ip_or_cidr('invalid-ip')}")
#     print(f"80 valid? {is_valid_port_or_range(80)}")
#     print(f"'8080' valid? {is_valid_port_or_range('8080')}")
#     print(f"'8000-9000' valid? {is_valid_port_or_range('8000-9000')}")
#     print(f"70000 valid? {is_valid_port_or_range(70000)}")
#     print(f"'abc' valid? {is_valid_port_or_range('abc')}")
#     print(f"Parse '80': {parse_port_rule('80')}")
#     print(f"Parse '8000-8080': {parse_port_rule('8000-8080')}")
#     print(f"Parse 'invalid': {parse_port_rule('invalid')}")
#     print(f"127.0.0.1 private? {is_private_ip('127.0.0.1')}")
#     print(f"192.168.1.100 private? {is_private_ip('192.168.1.100')}")
#     print(f"8.8.8.8 private? {is_private_ip('8.8.8.8')}")
