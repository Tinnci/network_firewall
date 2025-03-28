#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import yaml
import logging
from typing import Dict, Any, Optional # Added Optional

logger = logging.getLogger(__name__)

def load_default_rules_data() -> Dict[str, Any]:
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

def load_rules_from_file(filepath: str) -> Optional[Dict[str, Any]]:
    """
    从指定的 YAML 文件加载原始规则数据。

    Args:
        filepath: 规则文件的路径。

    Returns:
        包含原始规则数据的字典，如果文件不存在或解析失败则返回 None。
    """
    if not os.path.isfile(filepath):
        logger.warning(f"规则文件不存在: {filepath}")
        return None
        
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            rules_data = yaml.safe_load(f)
            if not isinstance(rules_data, dict):
                 logger.error(f"规则文件格式无效 (不是字典): {filepath}")
                 return None
            logger.info(f"从文件加载原始规则数据: {filepath}")
            return rules_data
    except yaml.YAMLError as e:
        logger.error(f"解析规则文件时出错 (YAML 错误): {filepath} - {e}")
        return None
    except Exception as e:
        logger.error(f"加载规则文件时发生未知错误: {filepath} - {e}")
        return None

def save_rules_to_file(filepath: str, rules: Dict[str, Any]) -> bool:
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
            
        logger.info(f"规则已成功保存到: {filepath}")
        return True
    except Exception as e:
        logger.error(f"保存规则文件时出错: {filepath} - {e}")
        return False

# Example usage:
# if __name__ == "__main__":
#     test_file = "test_rules.yaml"
#     default_data = load_default_rules_data()
#     print("Default Rules Data:", default_data)
    
#     # Test saving
#     test_rules = {
#         'ip_blacklist': ['1.1.1.1', '2.2.2.2'],
#         'ip_whitelist': ['192.168.1.1'],
#         'port_blacklist': ['22', '23'],
#         'port_whitelist': ['80', '443'],
#         'content_filters': ['bad', 'evil'],
#         'protocol_filter': {'tcp': False, 'udp': True}
#     }
#     if save_rules_to_file(test_file, test_rules):
#         print(f"Saved test rules to {test_file}")

#         # Test loading
#         loaded_data = load_rules_from_file(test_file)
#         if loaded_data:
#             print("Loaded Rules Data:", loaded_data)
#             assert loaded_data == test_rules # Basic check
#         else:
#             print(f"Failed to load {test_file}")
            
#         # Clean up
#         # os.remove(test_file)
#     else:
#         print(f"Failed to save {test_file}")

#     # Test loading non-existent file
#     print("Loading non-existent file:", load_rules_from_file("non_existent.yaml"))
