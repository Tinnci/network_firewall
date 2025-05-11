# tests/test_port_filtering.py
import pytest
import time
import re
from .helpers import rule_helper, network_helper, log_parser
from .screenshots import screenshot_util

# 常用的测试目标和端口
# 对于端口黑名单，我们会尝试连接到一个通常可访问的外部服务端口
# TEST_EXTERNAL_HOST = "www.example.com" # 用于测试 HTTP/HTTPS
# 或者使用IP地址，如 "93.184.216.34" for example.com, "8.8.8.8" for Google DNS
TEST_EXTERNAL_HOST_IP = "220.181.38.148" # Baidu IP
TEST_HTTP_PORT = 80
TEST_HTTPS_PORT = 443

# 对于端口范围测试，可能需要一个本地服务器，或者测试到外部已知行为的端口范围
# 这里我们假设防火墙能够拦截出站到特定端口的连接
TEST_RANGE_TARGET_HOST = "127.0.0.1" # 或者外部主机
TEST_RANGE_PORT_START = 8000
TEST_RANGE_PORT_BLOCKED_IN_RANGE = TEST_RANGE_PORT_START + 1 # e.g., 8001
TEST_RANGE_PORT_END = TEST_RANGE_PORT_START + 80 # e.g., 8080
TEST_RANGE_PORT_ALLOWED_OUTSIDE = TEST_RANGE_PORT_END + 1 # e.g., 8081


@pytest.mark.usefixtures("manage_rules")
def test_port_blacklist_http(manage_rules):
    """测试端口黑名单功能 - 拦截HTTP的80端口 (用例 3.1)"""
    print("\\n开始测试: 端口黑名单 - HTTP (80)")

    # 1. 设置规则: 将80端口加入黑名单
    current_rules = rule_helper.get_default_rules()
    current_rules['port_blacklist'] = [TEST_HTTP_PORT]
    current_rules['protocol_filter']['tcp'] = True # 确保TCP允许，以便测试端口
    rule_helper.apply_rules(current_rules)
    rules_applied_log = log_parser.wait_for_log_entry(r"Firewall: Analyzer rules updated with:", timeout_seconds=7)
    assert rules_applied_log, "防火墙规则更新日志未在超时时间内找到。"

    # 2. 操作: 尝试通过HTTP访问网站 (连接到80端口)
    connection_attempted = network_helper.send_tcp_packet(TEST_EXTERNAL_HOST_IP, TEST_HTTP_PORT)
    print(f"尝试连接到 {TEST_EXTERNAL_HOST_IP}:{TEST_HTTP_PORT} (HTTP): {'连接尝试成功发出' if connection_attempted else '连接尝试失败/超时'}")

    expected_log_pattern = rf"拦截动作: 端口黑名单, 命中端口: {TEST_HTTP_PORT}.*目标IP: {re.escape(TEST_EXTERNAL_HOST_IP)}"
    log_found = log_parser.wait_for_log_entry(expected_log_pattern, timeout_seconds=7)
    screenshot_util.take_screenshot("port_blacklist_http_end")

    # 3. 预期结果验证
    # 主要验证是日志中是否有拦截记录。send_tcp_packet可能因目标无服务或网络问题返回False。
    assert log_found, f"预期在日志中找到针对端口 {TEST_HTTP_PORT} (目标IP: {TEST_EXTERNAL_HOST_IP}) 的拦截记录。模式: {expected_log_pattern}"
    print(f"端口黑名单 - HTTP (80) 测试成功。找到拦截日志。")

@pytest.mark.usefixtures("manage_rules")
def test_port_whitelist_https_only(manage_rules):
    """测试端口白名单功能 - 仅允许HTTPS的443端口 (用例 3.2)"""
    print("\\n开始测试: 端口白名单 - 仅HTTPS (443)")

    # 1. 设置规则: 仅将443端口加入白名单
    current_rules = rule_helper.get_default_rules()
    current_rules['port_whitelist'] = [TEST_HTTPS_PORT]
    # 为了清晰地测试白名单的排他性，我们明确阻止HTTP端口，或依赖防火墙默认阻止不在白名单的端口
    # current_rules['port_blacklist'] = [TEST_HTTP_PORT] # 可选：如果需要显式黑名单
    current_rules['protocol_filter']['tcp'] = True
    rule_helper.apply_rules(current_rules)
    rules_applied_log = log_parser.wait_for_log_entry(r"Firewall: Analyzer rules updated with:", timeout_seconds=7)
    assert rules_applied_log, "防火墙规则更新日志未在超时时间内找到。"

    # 2. 操作
    # 尝试HTTPS (应该允许)
    https_allowed_by_firewall = network_helper.send_tcp_packet(TEST_EXTERNAL_HOST_IP, TEST_HTTPS_PORT)
    print(f"尝试连接到 {TEST_EXTERNAL_HOST_IP}:{TEST_HTTPS_PORT} (HTTPS): {'防火墙允许发出请求' if https_allowed_by_firewall else '请求失败/超时 (需检查日志)'}")

    # 尝试HTTP (应该禁止，因为不在白名单)
    network_helper.send_tcp_packet(TEST_EXTERNAL_HOST_IP, TEST_HTTP_PORT) # 发送请求以触发日志
    
    # 验证HTTP被拦截 (因为不在白名单)
    http_block_pattern = rf"拦截动作: 端口未在白名单, .*目标IP: {re.escape(TEST_EXTERNAL_HOST_IP)}, .*目标端口: {TEST_HTTP_PORT}"
    http_block_log_found = log_parser.wait_for_log_entry(http_block_pattern, timeout_seconds=7)
    
    # 验证HTTPS没有因为"端口未在白名单"而被拦截
    https_not_in_whitelist_pattern = rf"拦截动作: 端口未在白名单, .*目标IP: {re.escape(TEST_EXTERNAL_HOST_IP)}, .*目标端口: {TEST_HTTPS_PORT}"
    https_block_log_absent = not log_parser.wait_for_log_entry(https_not_in_whitelist_pattern, timeout_seconds=3, check_interval=0.5) # 短暂检查，预期找不到

    screenshot_util.take_screenshot("port_whitelist_https_end")

    # 3. 预期结果验证
    assert https_allowed_by_firewall, f"对端口 {TEST_HTTPS_PORT} (HTTPS) 的连接防火墙层面应允许发出，但send_tcp_packet返回False (可能网络或目标服务问题)。"
    assert http_block_log_found, f"预期在日志中找到针对端口 {TEST_HTTP_PORT} (HTTP) 因'未在白名单'而被拦截的记录。模式: {http_block_pattern}"
    assert https_block_log_absent, f"不应在日志中找到针对端口 {TEST_HTTPS_PORT} (HTTPS) 因'未在白名单'而被拦截的记录。"
    print("端口白名单 - 仅HTTPS (443) 测试成功。")

@pytest.mark.usefixtures("manage_rules")
def test_port_range_blacklist(manage_rules):
    """测试端口范围黑名单功能 (用例 3.3)"""
    range_to_block_str = f"{TEST_RANGE_PORT_START}-{TEST_RANGE_PORT_END}"
    print(f"\\n开始测试: 端口范围黑名单 - {range_to_block_str}")

    # 1. 设置规则: 将端口范围加入黑名单
    current_rules = rule_helper.get_default_rules()
    current_rules['port_blacklist'] = [range_to_block_str] 
    current_rules['protocol_filter']['tcp'] = True
    rule_helper.apply_rules(current_rules)
    rules_applied_log = log_parser.wait_for_log_entry(r"Firewall: Analyzer rules updated with:", timeout_seconds=7)
    assert rules_applied_log, "防火墙规则更新日志未在超时时间内找到。"

    # 2. 操作
    # 尝试连接到范围内的端口 (应该禁止)
    network_helper.send_tcp_packet(TEST_RANGE_TARGET_HOST, TEST_RANGE_PORT_BLOCKED_IN_RANGE)
    blocked_log_pattern = rf"拦截动作: 端口黑名单, 命中端口: {TEST_RANGE_PORT_BLOCKED_IN_RANGE}.*目标IP: {re.escape(TEST_RANGE_TARGET_HOST)}"
    log_for_blocked_port_found = log_parser.wait_for_log_entry(blocked_log_pattern, timeout_seconds=7)

    # 尝试连接到范围外的端口 (应该允许)
    allowed_port_connection_attempted = network_helper.send_tcp_packet(TEST_RANGE_TARGET_HOST, TEST_RANGE_PORT_ALLOWED_OUTSIDE)
    # 检查针对范围外端口的 *黑名单* 拦截日志 (预期不出现)
    allowed_port_mistakenly_blocked_pattern = rf"拦截动作: 端口黑名单, 命中端口: {TEST_RANGE_PORT_ALLOWED_OUTSIDE}.*目标IP: {re.escape(TEST_RANGE_TARGET_HOST)}"
    log_for_allowed_port_absent = not log_parser.wait_for_log_entry(allowed_port_mistakenly_blocked_pattern, timeout_seconds=3, check_interval=0.5)

    screenshot_util.take_screenshot(f"port_range_blacklist_end")

    # 3. 预期结果验证
    assert log_for_blocked_port_found, f"预期在日志中找到针对端口 {TEST_RANGE_PORT_BLOCKED_IN_RANGE} (在范围 {range_to_block_str} 内，目标IP: {TEST_RANGE_TARGET_HOST}) 的拦截记录。模式: {blocked_log_pattern}"
    assert allowed_port_connection_attempted, f"对端口 {TEST_RANGE_PORT_ALLOWED_OUTSIDE} (在范围 {range_to_block_str} 外) 的连接防火墙层面应允许发出，但send_tcp_packet返回False (可能目标服务不在线)。"
    assert log_for_allowed_port_absent, f"不应在日志中找到针对端口 {TEST_RANGE_PORT_ALLOWED_OUTSIDE} (范围外) 因端口范围黑名单规则导致的拦截记录。"
    print(f"端口范围黑名单 - {range_to_block_str} 测试成功。") 