# --- tests/test_content_filtering.py ---
import pytest
import re # 需要导入re
from .helpers import rule_helper, network_helper, log_parser
from .screenshots import screenshot_util

# 假设本机IP和未被防火墙其他规则限制的端口
TEST_LOCAL_HOST = "127.0.0.1"
TEST_LOCAL_PORT = 12345 # 选择一个不常用的端口

@pytest.mark.usefixtures("manage_rules")
def test_content_filter_simple_match_block(manage_rules):
    """测试内容过滤 - 简单字符串匹配导致拦截 (用例 4.1)"""
    print("\n开始测试: 内容过滤 - 简单字符串匹配拦截")

    keyword_to_block = "testkeyword_auto"

    # 1. 设置规则: 添加内容过滤规则
    current_rules = rule_helper.get_default_rules()
    current_rules['content_filters'] = [keyword_to_block]
    # 确保协议和端口允许，以便测试内容过滤本身
    current_rules['protocol_filter']['udp'] = True
    current_rules['protocol_filter']['tcp'] = False
    current_rules['port_blacklist'] = []
    current_rules['port_whitelist'] = [] # 清空白名单，避免干扰
    rule_helper.apply_rules(current_rules)
    rules_applied_log = log_parser.wait_for_log_entry(r"Firewall: Analyzer rules updated with:", timeout_seconds=7)
    assert rules_applied_log, "防火墙规则更新日志未在超时时间内找到。"

    # 2. 操作: 发送包含关键字的数据包
    payload_with_keyword = f"some data before {keyword_to_block} and after".encode('utf-8')
    # 发送数据包，用于触发内容过滤拦截
    network_helper.send_udp_packet(TEST_LOCAL_HOST, TEST_LOCAL_PORT, payload_with_keyword)

    # 预期拦截日志
    expected_log_pattern = rf"拦截动作: 内容过滤, 规则: {re.escape(keyword_to_block)}.*源IP: {re.escape(TEST_LOCAL_HOST)}.*目标IP: {re.escape(TEST_LOCAL_HOST)}"
    # 注意：如果防火墙日志不记录127.0.0.1之间的源/目标IP，可以简化pattern
    log_found = log_parser.wait_for_log_entry(expected_log_pattern, timeout_seconds=7, max_lines_to_check=100)
    screenshot_util.take_screenshot("content_filter_block_end")

    # 3. 预期结果验证
    assert log_found, f"预期在日志中找到因内容过滤 '{keyword_to_block}' 而拦截的记录。模式: {expected_log_pattern}"
    print("内容过滤 - 简单字符串匹配拦截测试成功: 找到拦截记录。")

@pytest.mark.usefixtures("manage_rules")
def test_content_filter_no_match_allow(manage_rules):
    """测试内容过滤 - 不匹配内容时允许通过 (用例 4.3)"""
    print("\n开始测试: 内容过滤 - 不匹配内容时允许")

    keyword_to_block = "testkeyword_auto_specific" # 使用一个特定的关键字

    # 1. 设置规则: 添加内容过滤规则
    current_rules = rule_helper.get_default_rules()
    current_rules['content_filters'] = [keyword_to_block]
    current_rules['protocol_filter']['tcp'] = True
    current_rules['port_blacklist'] = []
    current_rules['port_whitelist'] = []
    rule_helper.apply_rules(current_rules)
    rules_applied_log = log_parser.wait_for_log_entry(r"Firewall: Analyzer rules updated with:", timeout_seconds=7)
    assert rules_applied_log, "防火墙规则更新日志未在超时时间内找到。"

    # 2. 操作: 发送不包含关键字的数据包
    payload_without_keyword = "some other data without the special keyword".encode('utf-8')
    connection_sent = network_helper.send_tcp_packet(TEST_LOCAL_HOST, TEST_LOCAL_PORT, payload_without_keyword)

    # 验证没有因该关键字拦截的日志
    # 我们需要等待一段时间，以确保如果有拦截日志，它会被写入
    # 然后检查在整个日志（或最近的日志）中是否没有出现该拦截模式
    non_expected_log_pattern = rf"拦截动作: 内容过滤, 规则: {re.escape(keyword_to_block)}"
    log_is_absent = not log_parser.wait_for_log_entry(non_expected_log_pattern, timeout_seconds=3, check_interval=0.5, max_lines_to_check=100)
    # timeout_seconds 设为较短的值，因为我们预期找不到它。

    screenshot_util.take_screenshot("content_filter_allow_end")

    # 3. 预期结果验证
    assert log_is_absent, f"不应在日志中找到因内容过滤 '{keyword_to_block}' 而拦截的记录，因为载荷不匹配。"
    # connection_sent 只表示发送尝试，不代表一定通过或被防火墙处理。主要依赖日志。
    # assert connection_sent, "预期数据包能够发出，因为内容不匹配过滤规则。"
    print("内容过滤 - 不匹配内容时允许测试成功。")
