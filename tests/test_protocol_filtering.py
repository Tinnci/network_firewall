# Placeholder for protocol filtering tests

import pytest
import time
import re
from .helpers import rule_helper, network_helper, log_parser
from .screenshots import screenshot_util

# 用于测试的目标IP和端口，确保它们在测试环境中是可访问的（如果协议允许）
# 例如，可以使用公共DNS服务器进行UDP测试，使用公共网站进行TCP测试
# 为简单起见，我们可能尝试连接到本地回环地址上的特定端口，
# 或者使用一个已知的外部可达服务。
# 这里的关键是防火墙规则是否按预期工作，而不是目标服务是否真的响应。
TEST_TARGET_HOST = "8.8.8.8" # Google DNS, for both TCP and UDP attempts
TEST_TCP_PORT = 53 # DNS over TCP
TEST_UDP_PORT = 53 # DNS over UDP
# 另一个选项是使用 network_helper.can_access_url 对于TCP测试，
# 但这依赖于HTTP服务，对于纯粹的协议测试，直接发送TCP/UDP包更底层。

@pytest.mark.usefixtures("manage_rules")
def test_protocol_filter_allow_tcp_block_udp(manage_rules):
    """测试协议过滤：允许TCP，禁止UDP (用例 1.1)"""
    print("\\n开始测试: 协议过滤 - 允许TCP，禁止UDP")
    log_parser.clear_log_file()

    # 1. 设置规则
    current_rules = rule_helper.get_default_rules()
    current_rules['protocol_filter']['tcp'] = True
    current_rules['protocol_filter']['udp'] = False
    rule_helper.apply_rules(current_rules)
    time.sleep(2) # 等待规则加载

    # 2. 操作
    # 尝试TCP (应该允许)
    tcp_success = network_helper.send_tcp_packet(TEST_TARGET_HOST, TEST_TCP_PORT)
    print(f"尝试TCP连接到 {TEST_TARGET_HOST}:{TEST_TCP_PORT}: {'成功' if tcp_success else '失败'}")

    # 尝试UDP (应该禁止)
    # send_udp_packet 返回 True 表示发送成功，不代表接收成功或未被拦截
    # 我们需要检查日志来确认拦截
    network_helper.send_udp_packet(TEST_TARGET_HOST, TEST_UDP_PORT, payload=b"test_udp_blocked")
    print(f"尝试发送UDP包到 {TEST_TARGET_HOST}:{TEST_UDP_PORT}")

    time.sleep(1) # 等待日志
    # 假设UDP拦截日志包含 "UDP" 和 "拦截"
    # 注意：日志模式需要根据实际防火墙日志格式调整
    # 例如: "拦截 UDP ... DstPort=53"
    # 或更通用: "拦截.*UDP.*{TEST_TARGET_HOST}.*{TEST_UDP_PORT}"
    udp_block_logs = log_parser.find_log_entries(f"拦截.*UDP.*{TEST_TARGET_HOST}.*{TEST_UDP_PORT}", max_lines_to_check=50)
    tcp_allow_logs = log_parser.find_log_entries(f"放行.*TCP.*{TEST_TARGET_HOST}.*{TEST_TCP_PORT}", max_lines_to_check=50) # 可选

    screenshot_util.take_screenshot("protocol_tcp_allowed_udp_blocked")

    # 3. 预期结果验证
    assert tcp_success, f"TCP通信到 {TEST_TARGET_HOST}:{TEST_TCP_PORT} 应被允许，但失败了。"
    assert len(udp_block_logs) > 0, f"预期在日志中找到UDP包到 {TEST_TARGET_HOST}:{TEST_UDP_PORT} 被拦截的记录。"
    # 可选：如果允许的TCP通信也有日志，可以检查
    # assert len(tcp_allow_logs) > 0, f"预期在日志中找到TCP包到 {TEST_TARGET_HOST}:{TEST_TCP_PORT} 被放行的记录。"
    print(f"协议过滤 - 允许TCP，禁止UDP 测试成功。找到 {len(udp_block_logs)} 条UDP拦截日志。")

@pytest.mark.usefixtures("manage_rules")
def test_protocol_filter_allow_udp_block_tcp(manage_rules):
    """测试协议过滤：允许UDP，禁止TCP (用例 1.2)"""
    print("\\n开始测试: 协议过滤 - 允许UDP，禁止TCP")
    log_parser.clear_log_file()

    # 1. 设置规则
    current_rules = rule_helper.get_default_rules()
    current_rules['protocol_filter']['tcp'] = False
    current_rules['protocol_filter']['udp'] = True
    rule_helper.apply_rules(current_rules)
    time.sleep(2) # 等待规则加载

    # 2. 操作
    # 尝试UDP (应该允许)
    # 注意: send_udp_packet总是返回True如果发送操作本身不抛异常
    # 我们需要一个方法来验证UDP是否真的通过（例如，本地UDP服务器响应或检查日志中没有拦截记录）
    # 为简单起见，我们假设如果规则允许UDP，它会通过，并且不会有拦截日志。
    udp_sent = network_helper.send_udp_packet(TEST_TARGET_HOST, TEST_UDP_PORT, payload=b"test_udp_allowed")
    print(f"尝试发送UDP包到 {TEST_TARGET_HOST}:{TEST_UDP_PORT}: {'发送成功' if udp_sent else '发送失败'}")


    # 尝试TCP (应该禁止)
    tcp_success = network_helper.send_tcp_packet(TEST_TARGET_HOST, TEST_TCP_PORT)
    print(f"尝试TCP连接到 {TEST_TARGET_HOST}:{TEST_TCP_PORT}: {'成功' if tcp_success else '失败'}")


    time.sleep(1) # 等待日志
    tcp_block_logs = log_parser.find_log_entries(f"拦截.*TCP.*{TEST_TARGET_HOST}.*{TEST_TCP_PORT}", max_lines_to_check=50)
    udp_allow_logs = log_parser.find_log_entries(f"放行.*UDP.*{TEST_TARGET_HOST}.*{TEST_UDP_PORT}", max_lines_to_check=50) # 可选，如果放行有日志
    udp_block_check_logs = log_parser.find_log_entries(f"拦截.*UDP.*{TEST_TARGET_HOST}.*{TEST_UDP_PORT}", max_lines_to_check=50) # 确保没有UDP拦截日志


    screenshot_util.take_screenshot("protocol_udp_allowed_tcp_blocked")

    # 3. 预期结果验证
    assert not tcp_success, f"TCP通信到 {TEST_TARGET_HOST}:{TEST_TCP_PORT} 应被禁止，但成功了。"
    assert len(tcp_block_logs) > 0, f"预期在日志中找到TCP包到 {TEST_TARGET_HOST}:{TEST_TCP_PORT} 被拦截的记录。"
    assert len(udp_block_check_logs) == 0, f"不应在日志中找到UDP包到 {TEST_TARGET_HOST}:{TEST_UDP_PORT} 被拦截的记录。"
    # 可选：如果允许的UDP通信也有特定日志
    # assert len(udp_allow_logs) > 0, f"预期在日志中找到UDP包到 {TEST_TARGET_HOST}:{TEST_UDP_PORT} 被放行的记录。"
    print(f"协议过滤 - 允许UDP，禁止TCP 测试成功。找到 {len(tcp_block_logs)} 条TCP拦截日志。")