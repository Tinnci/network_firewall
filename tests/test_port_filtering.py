# tests/test_port_filtering.py
import pytest
import time
import re
from .helpers import rule_helper, network_helper, log_parser
from .screenshots import screenshot_util

# 常用的测试目标和端口
# 对于端口黑名单，我们会尝试连接到一个通常可访问的外部服务端口
TEST_EXTERNAL_HOST = "www.example.com" # 用于测试 HTTP/HTTPS
# 或者使用IP地址，如 "93.184.216.34" for example.com, "8.8.8.8" for Google DNS
TEST_HTTP_PORT = 80
TEST_HTTPS_PORT = 443

# 对于端口范围测试，可能需要一个本地服务器，或者测试到外部已知行为的端口范围
# 这里我们假设防火墙能够拦截出站到特定端口的连接
TEST_RANGE_TARGET_HOST = "127.0.0.1" # 或者外部主机
TEST_RANGE_PORT_START = 8000
TEST_RANGE_PORT_BLOCKED = 8001 # 在范围 8000-8080 内
TEST_RANGE_PORT_ALLOWED = 8081 # 在范围外


@pytest.mark.usefixtures("manage_rules")
def test_port_blacklist_http(manage_rules):
    """测试端口黑名单功能 - 阻止HTTP的80端口 (用例 3.1)"""
    print("\\n开始测试: 端口黑名单 - HTTP (80)")
    log_parser.clear_log_file()

    # 1. 设置规则: 将80端口加入黑名单
    current_rules = rule_helper.get_default_rules()
    current_rules['port_blacklist'] = [TEST_HTTP_PORT]
    current_rules['protocol_filter']['tcp'] = True # 确保TCP允许，以便测试端口
    rule_helper.apply_rules(current_rules)
    time.sleep(6)

    # 2. 操作: 尝试通过HTTP访问网站 (连接到80端口)
    # network_helper.can_access_url 会尝试GET请求，如果端口不通，会返回False
    # http_allowed = network_helper.can_access_url(f"http://{TEST_EXTERNAL_HOST}")
    # 或者直接尝试TCP连接
    connection_blocked = not network_helper.send_tcp_packet(TEST_EXTERNAL_HOST, TEST_HTTP_PORT)
    print(f"尝试连接到 {TEST_EXTERNAL_HOST}:{TEST_HTTP_PORT} (HTTP): {'成功拦截' if connection_blocked else '未拦截/可连接'}")

    time.sleep(1)
    # 日志模式示例: "拦截 TCP ... DstPort=80"
    log_entries = log_parser.find_log_entries(f"拦截.*DstPort={TEST_HTTP_PORT}", max_lines_to_check=50)
    screenshot_util.take_screenshot("port_blacklist_http_end")

    # 3. 预期结果验证
    assert connection_blocked, f"对端口 {TEST_HTTP_PORT} 的连接应被阻止，但似乎成功了。"
    assert len(log_entries) > 0, f"预期在日志中找到针对端口 {TEST_HTTP_PORT} 的拦截记录。"
    print(f"端口黑名单 - HTTP (80) 测试成功。找到 {len(log_entries)} 条拦截日志。")

@pytest.mark.usefixtures("manage_rules")
def test_port_whitelist_https_only(manage_rules):
    """测试端口白名单功能 - 仅允许HTTPS的443端口 (用例 3.2)"""
    print("\\n开始测试: 端口白名单 - 仅HTTPS (443)")
    log_parser.clear_log_file()

    # 1. 设置规则: 仅将443端口加入白名单 (假设白名单优先且具有排他性，或黑名单其他常用端口)
    current_rules = rule_helper.get_default_rules()
    current_rules['port_whitelist'] = [TEST_HTTPS_PORT]
    # 为确保测试有效，可以明确地将HTTP端口加入黑名单，或者依赖白名单的排他性
    # current_rules['port_blacklist'] = [TEST_HTTP_PORT] # 如果白名单不是完全排他性
    current_rules['protocol_filter']['tcp'] = True
    rule_helper.apply_rules(current_rules)
    time.sleep(6)

    # 2. 操作
    # 尝试HTTPS (应该允许)
    https_allowed = network_helper.send_tcp_packet(TEST_EXTERNAL_HOST, TEST_HTTPS_PORT)
    print(f"尝试连接到 {TEST_EXTERNAL_HOST}:{TEST_HTTPS_PORT} (HTTPS): {'成功' if https_allowed else '失败'}")

    # 尝试HTTP (应该禁止)
    http_blocked = not network_helper.send_tcp_packet(TEST_EXTERNAL_HOST, TEST_HTTP_PORT)
    print(f"尝试连接到 {TEST_EXTERNAL_HOST}:{TEST_HTTP_PORT} (HTTP): {'成功拦截' if http_blocked else '未拦截/可连接'}")

    time.sleep(1)
    http_block_logs = log_parser.find_log_entries(f"拦截.*DstPort={TEST_HTTP_PORT}", max_lines_to_check=50)
    # 可选：检查HTTPS允许的日志，如果存在这类日志
    # https_allow_logs = log_parser.find_log_entries(f"放行.*DstPort={TEST_HTTPS_PORT}", max_lines_to_check=50)

    screenshot_util.take_screenshot("port_whitelist_https_end")

    # 3. 预期结果验证
    assert https_allowed, f"对端口 {TEST_HTTPS_PORT} (HTTPS) 的连接应被允许，但失败了。"
    assert http_blocked, f"对端口 {TEST_HTTP_PORT} (HTTP) 的连接应被阻止 (因白名单限制)，但似乎成功了。"
    assert len(http_block_logs) > 0, f"预期在日志中找到针对端口 {TEST_HTTP_PORT} (HTTP) 的拦截记录。"
    print("端口白名单 - 仅HTTPS (443) 测试成功。")

@pytest.mark.usefixtures("manage_rules")
def test_port_range_blacklist(manage_rules):
    """测试端口范围黑名单功能 (用例 3.3)"""
    range_to_block = f"{TEST_RANGE_PORT_START}-{TEST_RANGE_PORT_START + 80}" # e.g., "8000-8080"
    print(f"\\n开始测试: 端口范围黑名单 - {range_to_block}")
    log_parser.clear_log_file()

    # 1. 设置规则: 将端口范围加入黑名单
    current_rules = rule_helper.get_default_rules()
    # 假设 rule_helper 或防火墙能正确解析 "8000-8080" 这样的范围字符串
    # 或者，如果规则文件直接支持列表，则需要相应调整 apply_rules
    # 这里我们假设 'port_blacklist' 可以包含范围字符串，或者防火墙逻辑会处理
    current_rules['port_blacklist'] = [range_to_block] 
    current_rules['protocol_filter']['tcp'] = True
    rule_helper.apply_rules(current_rules)
    time.sleep(6)

    # 2. 操作
    # 尝试连接到范围内的端口 (应该禁止)
    port_in_range_blocked = not network_helper.send_tcp_packet(TEST_RANGE_TARGET_HOST, TEST_RANGE_PORT_BLOCKED)
    print(f"尝试连接到 {TEST_RANGE_TARGET_HOST}:{TEST_RANGE_PORT_BLOCKED} (在黑名单范围 {range_to_block} 内): {'成功拦截' if port_in_range_blocked else '未拦截/可连接'}")

    # 尝试连接到范围外的端口 (应该允许，假设没有其他规则阻止)
    port_out_of_range_allowed = network_helper.send_tcp_packet(TEST_RANGE_TARGET_HOST, TEST_RANGE_PORT_ALLOWED)
    print(f"尝试连接到 {TEST_RANGE_TARGET_HOST}:{TEST_RANGE_PORT_ALLOWED} (在黑名单范围 {range_to_block} 外): {'成功' if port_out_of_range_allowed else '失败'}")

    time.sleep(1)
    # 检查范围内端口的拦截日志
    blocked_log_pattern = f"拦截.*DstPort={TEST_RANGE_PORT_BLOCKED}" 
    # 如果防火墙对范围端口的日志记录特定方式，可能需要调整 pattern
    # 例如，如果日志明确提到规则是基于范围的，可以搜索类似 "拦截.*端口范围.*{range_to_block}"
    logs_for_blocked_port = log_parser.find_log_entries(blocked_log_pattern, max_lines_to_check=50)
    # 确保范围外端口没有被意外拦截 (基于此规则)
    logs_for_allowed_port_check = log_parser.find_log_entries(f"拦截.*DstPort={TEST_RANGE_PORT_ALLOWED}", max_lines_to_check=20)

    screenshot_util.take_screenshot(f"port_range_blacklist_end")

    # 3. 预期结果验证
    assert port_in_range_blocked, f"对端口 {TEST_RANGE_PORT_BLOCKED} (在范围 {range_to_block} 内) 的连接应被阻止。"
    assert len(logs_for_blocked_port) > 0, f"预期在日志中找到针对端口 {TEST_RANGE_PORT_BLOCKED} (在范围 {range_to_block} 内) 的拦截记录。"
    assert port_out_of_range_allowed, f"对端口 {TEST_RANGE_PORT_ALLOWED} (在范围 {range_to_block} 外) 的连接应被允许。"
    assert len(logs_for_allowed_port_check) == 0, f"不应在日志中找到针对端口 {TEST_RANGE_PORT_ALLOWED} (在范围 {range_to_block} 外) 因该规则导致的拦截记录。"
    print(f"端口范围黑名单 - {range_to_block} 测试成功。") 