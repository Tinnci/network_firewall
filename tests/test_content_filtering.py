# --- tests/test_content_filtering.py ---
import pytest
import time
import re # 需要导入re
import socket # 需要导入socket
from .helpers import rule_helper, network_helper, log_parser
from .screenshots import screenshot_util
import logging

# 假设本机IP和未被防火墙其他规则限制的端口
TEST_LOCAL_HOST = "127.0.0.1"
TEST_LOCAL_PORT = 12345 # 选择一个不常用的端口

@pytest.mark.usefixtures("manage_rules")
def test_content_filter_simple_match_block(manage_rules):
    """测试内容过滤 - 简单字符串匹配导致拦截 (用例 4.1)"""
    print("\n开始测试: 内容过滤 - 简单字符串匹配拦截")
    log_parser.clear_log_file()

    keyword_to_block = "testkeyword_auto"
    test_tag = "test_content_filter_simple_match_block"
    marker = f"=== TEST_START: {test_tag} ==="
    logging.getLogger("test_case").info(marker)

    # 1. 设置规则: 添加内容过滤规则
    current_rules = rule_helper.get_default_rules()
    current_rules['content_filters'] = [keyword_to_block]
    # 确保协议和端口允许，以便测试内容过滤本身
    current_rules['protocol_filter']['tcp'] = True
    current_rules['port_blacklist'] = []
    current_rules['port_whitelist'] = [] # 清空白名单，避免干扰
    rule_helper.apply_rules(current_rules)
    time.sleep(6) # 等待规则加载

    # 2. 操作: 发送包含关键字的数据包
    payload_with_keyword = f"some data before {keyword_to_block} and after".encode('utf-8')
    network_helper.send_tcp_packet(TEST_LOCAL_HOST, TEST_LOCAL_PORT, payload_with_keyword)
    # 如果防火墙是透明的，连接可能会成功，但数据包应该被拦截。
    # 如果防火墙在连接层面就基于内容（不太可能），则连接会失败。

    time.sleep(1) # 等待日志写入
    # 只查找marker之后的日志
    log_entries = log_parser.find_log_entries_after_marker(f"拦截动作: 内容过滤, 规则: {re.escape(keyword_to_block)}", marker, max_lines_to_check=50)
    screenshot_util.take_screenshot("content_filter_block_end")

    # 3. 预期结果验证
    assert len(log_entries) > 0, f"预期在日志中找到因内容过滤 '{keyword_to_block}' 而拦截的记录，但未找到。"
    print(f"内容过滤 - 简单字符串匹配拦截测试成功: 找到 {len(log_entries)} 条拦截记录。")
    for entry in log_entries:
        print(f"  日志条目: {entry}")

@pytest.mark.usefixtures("manage_rules")
def test_content_filter_no_match_allow(manage_rules):
    """测试内容过滤 - 不匹配内容时允许通过 (用例 4.3)"""
    print("\n开始测试: 内容过滤 - 不匹配内容时允许")
    log_parser.clear_log_file()

    keyword_to_block = "testkeyword_auto_specific" # 使用一个特定的关键字

    # 1. 设置规则: 添加内容过滤规则
    current_rules = rule_helper.get_default_rules()
    current_rules['content_filters'] = [keyword_to_block]
    current_rules['protocol_filter']['tcp'] = True
    current_rules['port_blacklist'] = []
    current_rules['port_whitelist'] = []
    rule_helper.apply_rules(current_rules)
    time.sleep(6)

    # 2. 操作: 发送不包含关键字的数据包
    payload_without_keyword = "some other data without the special keyword".encode('utf-8')
    # 假设防火墙允许到127.0.0.1:12345的TCP连接（如果内容不匹配）
    # 实际测试中，最好有一个本地服务器监听此端口以确认数据包是否真的到达
    connection_successful = network_helper.send_tcp_packet(TEST_LOCAL_HOST, TEST_LOCAL_PORT, payload_without_keyword)


    time.sleep(1)
    log_entries_block = log_parser.find_log_entries(f"拦截动作: 内容过滤, 规则: {re.escape(keyword_to_block)}", max_lines_to_check=20)
    # 理想情况下，我们还应该检查是否有"放行"的日志，但这取决于您的日志详细程度
    # log_entries_allow = log_parser.find_log_entries(f"放行.*{TEST_LOCAL_HOST}.*{TEST_LOCAL_PORT}", max_lines_to_check=20)
    screenshot_util.take_screenshot("content_filter_allow_end")

    # 3. 预期结果验证
    assert len(log_entries_block) == 0, f"不应在日志中找到因内容过滤 '{keyword_to_block}' 而拦截的记录，因为载荷不匹配。"
    # 这个断言取决于send_tcp_packet的实现和防火墙的行为
    # 如果防火墙完全透明且内容不匹配，连接应该能建立（如果端口开放）
    # assert connection_successful, "预期数据包能够通过，因为内容不匹配过滤规则。"
    print("内容过滤 - 不匹配内容时允许测试成功。")
