#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import re
from typing import Dict, Any

# Import from utils
from ...utils.network_utils import is_valid_ip_or_cidr, is_valid_port_or_range

logger = logging.getLogger(__name__)

def validate_rules(rules_data: Dict[str, Any], default_rules_data: Dict[str, Any]) -> Dict[str, Any]:
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
            logger.debug(f"Validator: Key '{key}' not found in rules_data. Using default: {default_list_for_key}")
            raw_list = default_list_for_key
        else:
            raw_list = raw_list_candidate
        
        logger.info(f"Validator: For IP key '{key}', raw_list from rules_data (or default if key missing) is: {raw_list}, Type: {type(raw_list)}")

        if not isinstance(raw_list, list):
             logger.warning(f"规则 '{key}' 格式无效 (不是列表，实际类型: {type(raw_list)})，使用默认值。 Raw data was: {raw_list}")
             raw_list = default_list_for_key # Revert to default (empty list from default_rules_data)
             
        valid_ips = {ip for ip in raw_list if isinstance(ip, str) and is_valid_ip_or_cidr(ip)}
        invalid_count = len(raw_list) - len(valid_ips)
        if invalid_count > 0:
            logger.warning(f"加载规则时发现 {invalid_count} 个无效的IP/CIDR条目在 '{key}' 中，已忽略。")
        validated_rules[key] = valid_ips # Store as set

    # Validate Port lists
    for key in ['port_blacklist', 'port_whitelist']:
        raw_list_candidate = rules_data.get(key) # Get from file data first
        default_list_for_key = default_rules_data.get(key, [])

        if raw_list_candidate is None: # Key was not in file
            logger.debug(f"Validator: Key '{key}' not found in rules_data. Using default: {default_list_for_key}")
            raw_list = default_list_for_key
        else:
            raw_list = raw_list_candidate

        logger.info(f"Validator: For Port key '{key}', raw_list from rules_data (or default if key missing) is: {raw_list}, Type: {type(raw_list)}")

        if not isinstance(raw_list, list):
             logger.warning(f"规则 '{key}' 格式无效 (不是列表，实际类型: {type(raw_list)})，使用默认值。 Raw data was: {raw_list}")
             raw_list = default_list_for_key # Revert to default (empty list from default_rules_data)
             
        # Convert items to string for validation, handle potential non-string items gracefully
        items_as_str = []
        for item in raw_list:
             if isinstance(item, (str, int)):
                 items_as_str.append(str(item))
             else:
                 logger.warning(f"在 '{key}' 中发现非字符串/整数类型的无效端口条目: {item} (类型: {type(item)})，已忽略。")

        valid_ports = {item for item in items_as_str if is_valid_port_or_range(item)}
        invalid_count = len(items_as_str) - len(valid_ports)
        if invalid_count > 0:
            logger.warning(f"加载规则时发现 {invalid_count} 个无效的端口/范围条目在 '{key}' 中，已忽略。")
        validated_rules[key] = valid_ports # Store as set of strings

    # Validate Content Filters
    raw_content_filters_candidate = rules_data.get('content_filters')
    default_content_filters = default_rules_data.get('content_filters', [])

    if raw_content_filters_candidate is None: # Key was not in file
        logger.debug(f"Validator: Key 'content_filters' not found in rules_data. Using default: {default_content_filters}")
        raw_content_filters = default_content_filters
    else:
        raw_content_filters = raw_content_filters_candidate

    logger.info(f"Validator: For Content Filters key 'content_filters', raw_list from rules_data (or default if key missing) is: {raw_content_filters}, Type: {type(raw_content_filters)}")
    
    if not isinstance(raw_content_filters, list):
        logger.warning(f"规则 'content_filters' 格式无效 (不是列表，实际类型: {type(raw_content_filters)})，使用默认值。 Raw data was: {raw_content_filters}")
        raw_content_filters = default_content_filters # Revert to default (empty list from default_rules_data)
        
    valid_filters = []
    invalid_count = 0
    for f in raw_content_filters:
        if isinstance(f, str):
            # Optionally validate regex here, though Analyzer does it during compilation
            try:
                re.compile(f)
                valid_filters.append(f)
            except re.error as e:
                 logger.warning(f"加载规则时发现无效的内容过滤正则表达式 '{f}': {e}，已忽略。")
                 invalid_count += 1
        else:
            logger.warning(f"加载规则时发现无效的内容过滤器条目（非字符串）: {f}，已忽略。")
            invalid_count += 1
    validated_rules['content_filters'] = valid_filters # Store as list

    # Validate Protocol Filter
    raw_protocol_filter = rules_data.get('protocol_filter', default_rules_data.get('protocol_filter', {}))
    if not isinstance(raw_protocol_filter, dict):
         logger.warning("规则 'protocol_filter' 格式无效 (不是字典)，使用默认值。")
         raw_protocol_filter = default_rules_data.get('protocol_filter', {})
         
    valid_proto_filter = default_rules_data.get('protocol_filter', {"tcp": True, "udp": True}).copy() # Start with default
    for proto, enabled in raw_protocol_filter.items():
        if isinstance(proto, str) and proto.lower() in ['tcp', 'udp']:
            if isinstance(enabled, bool):
                valid_proto_filter[proto.lower()] = enabled
            else:
                 logger.warning(f"加载规则时发现无效的协议过滤值 (非布尔值) for '{proto}': {enabled}，已忽略。")
        else:
            logger.warning(f"加载规则时发现无效的协议过滤键: {proto}，已忽略。")
    validated_rules['protocol_filter'] = valid_proto_filter

    logger.debug("规则数据验证和转换完成。")
    return validated_rules

# Example usage:
# if __name__ == "__main__":
#     from rule_storage import load_default_rules_data
    
#     logging.basicConfig(level=logging.DEBUG)
    
#     default_data = load_default_rules_data()
    
#     test_data_good = {
#         'ip_blacklist': ['1.1.1.1', '10.0.0.0/8'],
#         'ip_whitelist': ['192.168.1.1'],
#         'port_blacklist': ['22', '1000-1024', 135],
#         'port_whitelist': [80, '443'],
#         'content_filters': ['test', r'valid\s+regex'],
#         'protocol_filter': {'tcp': False, 'udp': True}
#     }
    
#     test_data_bad = {
#         'ip_blacklist': ['1.1.1.1', 'invalid-ip', 999],
#         'ip_whitelist': set(['192.168.1.1']), # Wrong type initially
#         'port_blacklist': ['22', 'bad-range', 70000],
#         'port_whitelist': [80, None],
#         'content_filters': ['test', 123, r'[invalid'],
#         'protocol_filter': {'tcp': 'yes', 'icmp': True}
#     }

#     print("\n--- Validating Good Data ---")
#     validated_good = validate_rules(test_data_good, default_data)
#     print(validated_good)
#     assert isinstance(validated_good['ip_blacklist'], set)
#     assert isinstance(validated_good['port_blacklist'], set)
#     assert '1000-1024' in validated_good['port_blacklist']
#     assert '135' in validated_good['port_blacklist']

#     print("\n--- Validating Bad Data ---")
#     validated_bad = validate_rules(test_data_bad, default_data)
#     print(validated_bad)
#     assert 'invalid-ip' not in validated_bad['ip_blacklist']
#     assert 999 not in validated_bad['ip_blacklist'] # Should not be there as it's not str
#     assert isinstance(validated_bad['ip_whitelist'], set) # Should be corrected to set
#     assert 'bad-range' not in validated_bad['port_blacklist']
#     assert '70000' not in validated_bad['port_blacklist']
#     assert None not in validated_bad['port_whitelist'] # Should not be there
#     assert 123 not in validated_bad['content_filters']
#     assert r'[invalid' not in validated_bad['content_filters']
#     assert validated_bad['protocol_filter']['tcp'] is True # Should revert to default
#     assert 'icmp' not in validated_bad['protocol_filter']
