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
TEST_EXTERNAL_IP_TO_BLACKLIST = "8.8.8.8" # Google DNS
TEST_ACCESSIBLE_URL_WHITELIST = "http://www.google.com" # 用于白名单测试
TEST_EXTERNAL_IP_FOR_WHITELIST_TARGET = "1.1.1.1" # Cloudflare DNS, 用于测试白名单是否覆盖黑名单

@pytest.mark.usefixtures("manage_rules") # 应用 manage_rules fixture
def test_ip_blacklist(manage_rules): # manage_rules fixture 会自动应用
    """测试IP黑名单功能 (用例 2.1)"""
    print("\n开始测试: IP黑名单")
    log_parser.clear_log_file() # 清空日志以便检查

    # 1. 设置规则：将TEST_EXTERNAL_IP_TO_BLACKLIST加入黑名单
    current_rules = rule_helper.get_default_rules()
    current_rules['ip_blacklist'] = [TEST_EXTERNAL_IP_TO_BLACKLIST]
    rule_helper.apply_rules(current_rules)
    time.sleep(2) # 等待防火墙加载新规则

    # 2. 操作：尝试访问该IP (这里用ping的替代，尝试建立TCP连接到常见端口)
    # 注意: network_helper.can_access_url 可能因为目标IP没有HTTP服务而失败
    # 更可靠的是检查防火墙日志是否有拦截记录
    # connection_blocked = not network_helper.send_tcp_packet(TEST_EXTERNAL_IP_TO_BLACKLIST, 80)
    # print(f"尝试连接到黑名单IP {TEST_EXTERNAL_IP_TO_BLACKLIST}: {'成功拦截' if connection_blocked else '未拦截'}")

    # 替代操作：尝试ping (虽然防火墙可能不处理ICMP，但可以作为网络层尝试)
    # import subprocess
    # try:
    #     subprocess.check_output(["ping", "-n", "1", "-w", "1000", TEST_EXTERNAL_IP_TO_BLACKLIST])
    #     ping_successful = True
    # except subprocess.CalledProcessError:
    #     ping_successful = False
    # print(f"Ping {TEST_EXTERNAL_IP_TO_BLACKLIST}: {'可达' if ping_successful else '不可达/超时'}")

    # 关键验证：检查防火墙日志
    # 假设防火墙日志中对于IP黑名单拦截会有类似 "拦截" 和 IP地址 的记录
    # 这里的模式需要根据您实际的日志格式来调整
    # 示例日志格式: "Packet 拦截: ... Src=X.X.X.X ... Dst=Y.Y.Y.Y ... Reason=IP Blacklist"
    # 或者更通用的 "拦截 ... 8.8.8.8"
    time.sleep(1) # 给日志一点时间写入
    # 尝试访问一个依赖该IP的服务，例如DNS查询，如果防火墙拦截了8.8.8.8，DNS会失败
    try:
        socket.gethostbyname("test.nonexistent-domain-for-firewall-test.com") # 这会尝试使用系统DNS
    except socket.gaierror:
        print("DNS查询失败，可能因为黑名单IP被拦截 (预期行为)")
        pass


    log_entries = log_parser.find_log_entries(f"拦截.*{re.escape(TEST_EXTERNAL_IP_TO_BLACKLIST)}", max_lines_to_check=50)
    screenshot_util.take_screenshot("ip_blacklist_test_end") # 测试结束时截图

    # 3. 预期结果验证
    assert len(log_entries) > 0, f"预期在日志中找到针对IP {TEST_EXTERNAL_IP_TO_BLACKLIST} 的拦截记录，但未找到。"
    print(f"IP黑名单测试成功: 在日志中找到 {len(log_entries)} 条拦截记录。")
    for entry in log_entries:
        print(f"  日志条目: {entry}")


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
    time.sleep(2)

    # 2. 操作: 尝试访问该IP上的服务 (例如，尝试建立TCP连接)
    # 假设1.1.1.1的80端口是可访问的，或者至少防火墙不会因为黑名单拦截它
    connection_allowed = network_helper.send_tcp_packet(TEST_EXTERNAL_IP_FOR_WHITELIST_TARGET, 80)
    print(f"尝试连接到白名单IP {TEST_EXTERNAL_IP_FOR_WHITELIST_TARGET} (同时在黑名单中): {'成功连接' if connection_allowed else '连接失败'}")

    time.sleep(1)
    log_entries_block = log_parser.find_log_entries(f"拦截.*{re.escape(TEST_EXTERNAL_IP_FOR_WHITELIST_TARGET)}", max_lines_to_check=20)
    log_entries_allow = log_parser.find_log_entries(f"放行.*{re.escape(TEST_EXTERNAL_IP_FOR_WHITELIST_TARGET)}.*Whitelist", max_lines_to_check=20) # 假设白名单放行有特定日志
    screenshot_util.take_screenshot("ip_whitelist_test_end")

    # 3. 预期结果验证
    assert connection_allowed, f"预期能够连接到IP {TEST_EXTERNAL_IP_FOR_WHITELIST_TARGET} (因白名单优先)，但连接失败。"
    assert len(log_entries_block) == 0, f"不应在日志中找到针对IP {TEST_EXTERNAL_IP_FOR_WHITELIST_TARGET} 的拦截记录 (因白名单优先)。"
    # 可选：如果白名单放行有特定日志，可以验证
    # assert len(log_entries_allow) > 0, f"应在日志中找到针对IP {TEST_EXTERNAL_IP_FOR_WHITELIST_TARGET} 的白名单放行记录。"
    print("IP白名单优先于黑名单测试成功。")
