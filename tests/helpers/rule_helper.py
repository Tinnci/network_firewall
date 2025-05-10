# tests/helpers/rule_helper.py
import yaml
import shutil
import os
from typing import Dict, Any

RULES_FILE_PATH = 'rules.yaml' # 假设在项目根目录
BACKUP_RULES_FILE_PATH = 'rules.yaml.backup'

def backup_rules():
    """备份当前的rules.yaml文件"""
    if os.path.exists(RULES_FILE_PATH):
        shutil.copyfile(RULES_FILE_PATH, BACKUP_RULES_FILE_PATH)
        print(f"规则文件已备份到 {BACKUP_RULES_FILE_PATH}")

def restore_rules():
    """恢复备份的rules.yaml文件"""
    if os.path.exists(BACKUP_RULES_FILE_PATH):
        shutil.copyfile(BACKUP_RULES_FILE_PATH, RULES_FILE_PATH)
        os.remove(BACKUP_RULES_FILE_PATH)
        print(f"规则文件已从备份恢复")

def get_default_rules() -> Dict[str, Any]:
    """获取一份默认的空规则结构，用于测试"""
    return {
        'ip_blacklist': [],
        'ip_whitelist': [],
        'port_blacklist': [],
        'port_whitelist': [],
        'content_filters': [],
        'protocol_filter': {'tcp': True, 'udp': True}
    }

def apply_rules(rules_config: Dict[str, Any]):
    """将指定的规则配置写入rules.yaml文件"""
    try:
        with open(RULES_FILE_PATH, 'w', encoding='utf-8') as f:
            yaml.dump(rules_config, f, default_flow_style=False, allow_unicode=True)
        print(f"测试规则已应用到 {RULES_FILE_PATH}")
        # 此处可能需要短暂延时或发送信号给防火墙以重新加载规则
        # import time
        # time.sleep(1) # 简单的延时，实际中可能需要更可靠的机制
    except Exception as e:
        print(f"应用规则失败: {e}")

# --- tests/helpers/network_helper.py ---
import socket
import requests
import time

def can_access_url(url: str, timeout: int = 5) -> bool:
    """尝试访问一个URL，返回是否成功"""
    try:
        response = requests.get(url, timeout=timeout)
        return response.status_code == 200
    except requests.RequestException:
        return False

def send_tcp_packet(host: str, port: int, payload: bytes = b"test_data") -> bool:
    """发送一个简单的TCP数据包，返回是否能建立连接"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2) # 短暂超时
            s.connect((host, port))
            s.sendall(payload)
        return True
    except (socket.error, socket.timeout):
        return False

def send_udp_packet(host: str, port: int, payload: bytes = b"test_data") -> bool:
    """发送一个UDP数据包 (注意：UDP是无连接的，发送成功不代表对方收到或允许)"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(payload, (host, port))
        return True # 发送即认为操作完成
    except socket.error:
        return False

# --- tests/helpers/log_parser.py ---
import re
import os
from typing import List, Optional

LOG_FILE_PATH = 'logs/firewall.log' # 假设在项目根目录下的logs文件夹

def find_log_entries(pattern: str, max_lines_to_check: int = 100) -> List[str]:
    """
    在防火墙日志文件的最后N行中查找匹配特定模式的条目。
    Args:
        pattern: 正则表达式模式.
        max_lines_to_check: 从文件末尾检查的最大行数.
    Returns:
        匹配的日志条目列表.
    """
    matched_entries = []
    if not os.path.exists(LOG_FILE_PATH):
        print(f"日志文件未找到: {LOG_FILE_PATH}")
        return matched_entries

    try:
        with open(LOG_FILE_PATH, 'r', encoding='utf-8') as f:
            # 读取所有行，然后取最后N行，避免读取非常大的文件时内存问题
            # 对于非常大的日志，可以考虑更优化的读取方式
            lines = f.readlines()
            lines_to_check = lines[-max_lines_to_check:]
            for line in lines_to_check:
                if re.search(pattern, line, re.IGNORECASE):
                    matched_entries.append(line.strip())
    except Exception as e:
        print(f"解析日志文件时出错: {e}")
    return matched_entries

def clear_log_file():
    """清空日志文件内容，用于测试前准备"""
    if os.path.exists(LOG_FILE_PATH):
        try:
            with open(LOG_FILE_PATH, 'w', encoding='utf-8') as f:
                f.write("") # 写入空字符串以清空
            print(f"日志文件已清空: {LOG_FILE_PATH}")
        except Exception as e:
            print(f"清空日志文件失败: {e}")


# --- tests/screenshots/screenshot_util.py ---
# 需要安装 mss 和 Pillow: pip install mss Pillow
import mss
import mss.tools
from PIL import Image
import time
import os

SCREENSHOT_DIR = 'tests/screenshots'

def take_screenshot(filename_prefix: str = "firewall_ui_test") -> Optional[str]:
    """
    截取整个屏幕的截图并保存。
    Args:
        filename_prefix: 截图文件名的前缀.
    Returns:
        截图文件路径，如果失败则返回None.
    """
    if not os.path.exists(SCREENSHOT_DIR):
        os.makedirs(SCREENSHOT_DIR)

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    filename = f"{filename_prefix}_{timestamp}.png"
    filepath = os.path.join(SCREENSHOT_DIR, filename)

    try:
        with mss.mss() as sct:
            # 截取所有显示器合并的图像
            sct_img = sct.grab(sct.monitors[0]) # sct.monitors[0] 是整个虚拟屏幕
            # 将 BGRA 转换为 RGBA (Pillow期望的格式)
            img = Image.frombytes("RGB", (sct_img.width, sct_img.height), sct_img.rgb, "raw", "BGR")
            # 保存截图
            img.save(filepath)
            print(f"截图已保存到: {filepath}")
            return filepath
    except Exception as e:
        print(f"截图失败: {e}")
        return None

# 示例：截取特定窗口区域 (更复杂，需要知道窗口句柄或精确坐标)
# def capture_window_region(hwnd, region_coordinates, filename):
#     # 这部分高度依赖操作系统和具体UI库，mss可以直接截取屏幕区域
#     # region_coordinates = {'top': 40, 'left': 0, 'width': 800, 'height': 600} # 示例
#     try:
#         with mss.mss() as sct:
#             sct_img = sct.grab(region_coordinates)
#             mss.tools.to_png(sct_img.rgb, sct_img.size, output=filename)
#             print(f"区域截图已保存: {filename}")
#             return filename
#     except Exception as e:
#         print(f"区域截图失败: {e}")
#         return None

if __name__ == '__main__':
    # 测试截图功能
    # 确保防火墙UI是可见的，或者至少有一个窗口可以截图
    time.sleep(2) # 等待2秒，确保有东西可截
    screenshot_path = take_screenshot("test_capture")
    if screenshot_path:
        print(f"测试截图成功: {screenshot_path}")
    else:
        print("测试截图失败")
