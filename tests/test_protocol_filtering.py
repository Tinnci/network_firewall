# Placeholder for protocol filtering tests

import pytest
import re
from .helpers import rule_helper, network_helper, log_parser
from .screenshots import screenshot_util

# 用于测试的目标IP和端口，确保它们在测试环境中是可访问的（如果协议允许）
# 例如，可以使用公共DNS服务器进行UDP测试，使用公共网站进行TCP测试
# 为简单起见，我们可能尝试连接到本地回环地址上的特定端口，
# 或者使用一个已知的外部可达服务。
# 这里的关键是防火墙规则是否按预期工作，而不是目标服务是否真的响应。
TEST_TARGET_HOST = "220.181.38.148" # Baidu IP, for both TCP and UDP attempts
TEST_TCP_PORT = 53 # DNS over TCP
TEST_UDP_PORT = 53 # DNS over UDP
# 另一个选项是使用 network_helper.can_access_url 对于TCP测试，
# 但这依赖于HTTP服务，对于纯粹的协议测试，直接发送TCP/UDP包更底层。

@pytest.mark.usefixtures("manage_rules")
def test_protocol_filter_allow_tcp_block_udp(manage_rules):
    """测试协议过滤：允许TCP，禁止UDP (用例 1.1)"""
    print("\n开始测试: 协议过滤 - 允许TCP，禁止UDP")

    # 1. 设置规则
    current_rules = rule_helper.get_default_rules()
    current_rules['protocol_filter']['tcp'] = True
    current_rules['protocol_filter']['udp'] = False
    rule_helper.apply_rules(current_rules)
    rules_applied_log = log_parser.wait_for_log_entry(r"Firewall: Analyzer rules updated with:", timeout_seconds=7)
    assert rules_applied_log, "防火墙规则更新日志未在超时时间内找到。"

    # 2. 操作
    # 尝试TCP (应该允许)
    network_helper.send_tcp_packet(TEST_TARGET_HOST, TEST_TCP_PORT)
    print(f"尝试TCP连接到 {TEST_TARGET_HOST}:{TEST_TCP_PORT}: 请求已发送 (防火墙应允许)")

    # 尝试UDP (应该禁止)
    network_helper.send_udp_packet(TEST_TARGET_HOST, TEST_UDP_PORT, payload=b"test_udp_blocked")
    print(f"尝试发送UDP包到 {TEST_TARGET_HOST}:{TEST_UDP_PORT}")

    udp_block_pattern = rf"拦截动作: 协议过滤 UDP, .*目标IP: {re.escape(TEST_TARGET_HOST)}, .*目标端口: {TEST_UDP_PORT}"
    udp_block_log_found = log_parser.wait_for_log_entry(udp_block_pattern, timeout_seconds=7)

    # 确保TCP没有因为"协议过滤 TCP"而被错误拦截
    tcp_mistakenly_blocked_pattern = rf"拦截动作: 协议过滤 TCP, .*目标IP: {re.escape(TEST_TARGET_HOST)}, .*目标端口: {TEST_TCP_PORT}"
    tcp_block_log_absent = not log_parser.wait_for_log_entry(tcp_mistakenly_blocked_pattern, timeout_seconds=3, check_interval=0.5)

    screenshot_util.take_screenshot("protocol_tcp_allowed_udp_blocked")

    # 3. 预期结果验证
    assert udp_block_log_found, f"预期UDP包到 {TEST_TARGET_HOST}:{TEST_UDP_PORT} 会被协议过滤器拦截，但未找到相应日志。模式: {udp_block_pattern}"
    assert tcp_block_log_absent, f"不应出现TCP包到 {TEST_TARGET_HOST}:{TEST_TCP_PORT} 被协议过滤器拦截的日志。"
    print("协议过滤 - 允许TCP，禁止UDP 测试成功。找到UDP拦截日志，且无TCP拦截日志。")

@pytest.mark.usefixtures("manage_rules")
def test_protocol_filter_allow_udp_block_tcp(manage_rules):
    """测试协议过滤：允许UDP，禁止TCP (用例 1.2)"""
    print("\n开始测试: 协议过滤 - 允许UDP，禁止TCP")

    # 1. 设置规则
    current_rules = rule_helper.get_default_rules()
    current_rules['protocol_filter']['tcp'] = False
    current_rules['protocol_filter']['udp'] = True
    rule_helper.apply_rules(current_rules)
    rules_applied_log = log_parser.wait_for_log_entry(r"Firewall: Analyzer rules updated with:", timeout_seconds=7)
    assert rules_applied_log, "防火墙规则更新日志未在超时时间内找到。"

    # 2. 操作
    # 尝试UDP (应该允许)
    udp_sent_successfully = network_helper.send_udp_packet(TEST_TARGET_HOST, TEST_UDP_PORT, payload=b"test_udp_allowed")
    print(f"尝试发送UDP包到 {TEST_TARGET_HOST}:{TEST_UDP_PORT}: {'发送操作成功' if udp_sent_successfully else '发送操作失败'}")

    # 尝试TCP (应该禁止)
    network_helper.send_tcp_packet(TEST_TARGET_HOST, TEST_TCP_PORT) # 发送请求以触发日志

    tcp_block_pattern = rf"拦截动作: 协议过滤 TCP, .*目标IP: {re.escape(TEST_TARGET_HOST)}, .*目标端口: {TEST_TCP_PORT}"
    tcp_block_log_found = log_parser.wait_for_log_entry(tcp_block_pattern, timeout_seconds=7)

    # 确保UDP没有因为"协议过滤 UDP"而被错误拦截
    udp_mistakenly_blocked_pattern = rf"拦截动作: 协议过滤 UDP, .*目标IP: {re.escape(TEST_TARGET_HOST)}, .*目标端口: {TEST_UDP_PORT}"
    udp_block_log_absent = not log_parser.wait_for_log_entry(udp_mistakenly_blocked_pattern, timeout_seconds=3, check_interval=0.5)

    screenshot_util.take_screenshot("protocol_udp_allowed_tcp_blocked")

    # 3. 预期结果验证
    # udp_sent_successfully 仅表示 socket.sendto 未引发直接错误。
    # 主要的验证是日志中没有UDP拦截记录，并且有TCP拦截记录。
    assert tcp_block_log_found, f"预期在日志中找到TCP包到 {TEST_TARGET_HOST}:{TEST_TCP_PORT} 被拦截的记录。模式: {tcp_block_pattern}"
    assert udp_block_log_absent, f"不应在日志中找到UDP包到 {TEST_TARGET_HOST}:{TEST_UDP_PORT} 因'协议过滤 UDP'被错误拦截的记录。"
    print("协议过滤 - 允许UDP，禁止TCP 测试成功。找到TCP拦截日志。")