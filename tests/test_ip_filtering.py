# --- tests/test_ip_filtering.py ---
import pytest
import time
import socket
import re
from .helpers import rule_helper, network_helper, log_parser
from .screenshots import screenshot_util # 导入截图工具

# 假设有一个公共可访问的IP用于测试黑名单，例如 example.com 的 IP
# 在实际测试中，最好使用您控制的测试服务器或本地虚拟机IP
# TEST_EXTERNAL_IP_TO_BLACKLIST = "93.184.216.34" # example.com
# TEST_ACCESSIBLE_URL_BLACKLIST = f"http://{TEST_EXTERNAL_IP_TO_BLACKLIST}"

# 使用一个更可靠的、通常可访问的公共DNS服务器IP进行测试
# 注意：直接访问IP的HTTP服务可能不可用，这里主要测试网络层是否能通
# 更可靠的测试是尝试访问该IP上的已知服务（如DNS的53端口）
# 或者，在防火墙日志中查找拦截记录
TEST_EXTERNAL_IP_TO_BLACKLIST = "220.181.38.148" # Baidu IP
TEST_ACCESSIBLE_URL_WHITELIST = "http://www.baidu.com" # 用于白名单测试，尽管我们主要测IP
TEST_EXTERNAL_IP_FOR_WHITELIST_TARGET = "114.114.114.114" # Public DNS in China

@pytest.mark.usefixtures("manage_rules") # 应用 manage_rules fixture
def test_ip_blacklist(manage_rules): # manage_rules fixture 会自动应用
    """测试IP黑名单功能 (用例 2.1)"""
    print("\n开始测试: IP黑名单")
    log_parser.clear_log_file() # 清空日志以便检查

    # 1. 设置规则：将TEST_EXTERNAL_IP_TO_BLACKLIST加入黑名单
    current_rules = rule_helper.get_default_rules()
    current_rules['ip_blacklist'] = [TEST_EXTERNAL_IP_TO_BLACKLIST]
    rule_helper.apply_rules(current_rules)
    rules_applied_log_found = log_parser.wait_for_log_entry(r"Firewall: Analyzer rules updated with:", timeout_seconds=7)
    assert rules_applied_log_found, "防火墙规则更新日志未在超时时间内找到。"

    # 2. 操作：主动向被黑名单的IP发送一个数据包
    target_port = 53 # DNS port
    print(f"主动尝试发送TCP包到黑名单IP {TEST_EXTERNAL_IP_TO_BLACKLIST} 的{target_port}端口")
    network_helper.send_tcp_packet(TEST_EXTERNAL_IP_TO_BLACKLIST, target_port)

    print("等待预期的拦截日志条目...")
    # 精确匹配针对我们发送的包的拦截日志
    expected_log_pattern = rf"拦截动作: IP黑名单, 命中IP: {re.escape(TEST_EXTERNAL_IP_TO_BLACKLIST)}.*目标IP: {re.escape(TEST_EXTERNAL_IP_TO_BLACKLIST)}.*目标端口: {target_port}"
    log_found = log_parser.wait_for_log_entry(expected_log_pattern, timeout_seconds=7, max_lines_to_check=250)
    screenshot_util.take_screenshot("ip_blacklist_test_end") # 测试结束时截图

    # 3. 预期结果验证
    assert log_found, f"预期在日志中找到针对IP {TEST_EXTERNAL_IP_TO_BLACKLIST}:{target_port} 的特定拦截记录，但未在超时时间内找到。模式: {expected_log_pattern}"
    print(f"IP黑名单测试成功: 在日志中找到了针对 {TEST_EXTERNAL_IP_TO_BLACKLIST}:{target_port} 的拦截记录。")


@pytest.mark.usefixtures("manage_rules")
def test_ip_whitelist_over_blacklist(manage_rules):
    """测试IP白名单优先于黑名单 (部分对应 用例 2.2)"""
    print("\n开始测试: IP白名单优先于黑名单")
    log_parser.clear_log_file()

    # 1. 设置规则:
    #    - 将 TEST_EXTERNAL_IP_FOR_WHITELIST_TARGET 加入黑名单
    #    - 将 TEST_EXTERNAL_IP_FOR_WHITELIST_TARGET 加入白名单 (白名单应优先)
    current_rules = rule_helper.get_default_rules()
    current_rules['ip_blacklist'] = [TEST_EXTERNAL_IP_FOR_WHITELIST_TARGET]
    current_rules['ip_whitelist'] = [TEST_EXTERNAL_IP_FOR_WHITELIST_TARGET]
    rule_helper.apply_rules(current_rules)
    rules_applied_log_found_wl = log_parser.wait_for_log_entry(r"Firewall: Analyzer rules updated with:", timeout_seconds=7)
    assert rules_applied_log_found_wl, "防火墙规则更新日志未在超时时间内找到 (白名单测试)。"

    # 2. 操作: 尝试访问该IP上的服务 (例如，尝试建立TCP连接)
    target_whitelist_port = 80
    # connection_allowed 表示防火墙层面允许了连接，实际连接可能因服务器无响应而失败
    connection_allowed = network_helper.send_tcp_packet(TEST_EXTERNAL_IP_FOR_WHITELIST_TARGET, target_whitelist_port)
    print(f"尝试连接到白名单IP {TEST_EXTERNAL_IP_FOR_WHITELIST_TARGET}:{target_whitelist_port} (同时在黑名单中): {'成功发出请求 (防火墙未拦截)' if connection_allowed else '请求失败 (可能网络原因或目标无服务，需检查日志确认防火墙行为)'}")

    time.sleep(1) # 给日志一点时间写入，以防万一有意外的拦截日志
    log_entries_block = log_parser.find_log_entries(f"拦截动作: IP黑名单, 命中IP: {re.escape(TEST_EXTERNAL_IP_FOR_WHITELIST_TARGET)}", max_lines_to_check=50)
    screenshot_util.take_screenshot("ip_whitelist_test_end")

    # 3. 预期结果验证
    # 如果目标服务不在线，send_tcp_packet 仍可能返回False (超时)，但这不代表防火墙拦截。
    # 主要的验证是日志中没有黑名单拦截记录。
    # assert connection_allowed, f"预期防火墙允许连接到IP {TEST_EXTERNAL_IP_FOR_WHITELIST_TARGET}:{target_whitelist_port} (因白名单优先)，但 network_helper.send_tcp_packet 返回 False。这可能是网络问题或目标服务不在线，但防火墙层面应已放行。"
    assert len(log_entries_block) == 0, f"不应在日志中找到针对IP {TEST_EXTERNAL_IP_FOR_WHITELIST_TARGET} 的拦截记录 (因白名单优先)。"
    print("IP白名单优先于黑名单测试成功。")
