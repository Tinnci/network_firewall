import re
import os
from typing import List, Optional
import time

# 假设日志文件在项目根目录下的logs文件夹中
LOG_FILE_PATH = 'logs/firewall.log'

def find_log_entries(pattern: str, max_lines_to_check: int = 4000) -> List[str]:
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
            # 读取所有行，然后取最后N行
            # 对于非常大的日志文件，可以考虑更优化的逐行倒读方式
            lines = f.readlines()
            lines_to_check = lines[-max_lines_to_check:]
            for line in reversed(lines_to_check): # 从最新的日志开始检查通常更有效率
                if re.search(pattern, line, re.IGNORECASE):
                    matched_entries.append(line.strip())
            matched_entries.reverse() # 保持原始顺序（如果需要）
    except Exception as e:
        print(f"解析日志文件时出错: {e}")
    return matched_entries

def find_log_entries_after_marker(pattern: str, marker: str, max_lines_to_check: int = 4000) -> List[str]:
    """
    在日志文件中，从指定标记之后查找匹配特定模式的条目。
    Args:
        pattern: 正则表达式模式.
        marker: 日志中的唯一标记字符串.
        max_lines_to_check: 从文件末尾检查的最大行数.
    Returns:
        匹配的日志条目列表.
    """
    matched_entries = []
    found_marker = False
    if not os.path.exists(LOG_FILE_PATH):
        print(f"日志文件未找到: {LOG_FILE_PATH}")
        return matched_entries

    try:
        with open(LOG_FILE_PATH, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            lines_to_check = lines[-max_lines_to_check:]
            for line in lines_to_check:
                if not found_marker and marker in line:
                    found_marker = True
                    continue
                if found_marker and re.search(pattern, line, re.IGNORECASE):
                    matched_entries.append(line.strip())
    except Exception as e:
        print(f"解析日志文件时出错: {e}")
    return matched_entries

def clear_log_file():
    """清空日志文件内容，用于测试前准备"""
    if not os.path.exists(os.path.dirname(LOG_FILE_PATH)):
        try:
            os.makedirs(os.path.dirname(LOG_FILE_PATH))
            print(f"日志目录已创建: {os.path.dirname(LOG_FILE_PATH)}")
        except Exception as e:
            print(f"创建日志目录失败: {e}")
            # 如果目录创建失败，后续打开文件可能也会失败，但还是尝试一下

    if os.path.exists(LOG_FILE_PATH):
        try:
            with open(LOG_FILE_PATH, 'w', encoding='utf-8') as f:
                f.write("") # 写入空字符串以清空
            print(f"日志文件已清空: {LOG_FILE_PATH}")
        except Exception as e:
            print(f"清空日志文件失败: {e}")
    else:
        # 如果日志文件不存在，也打印一条消息，因为测试可能期望它被创建和清空
        print(f"日志文件 {LOG_FILE_PATH} 不存在，将被视为空白。尝试创建空日志文件。")
        try:
            with open(LOG_FILE_PATH, 'w', encoding='utf-8') as f:
                f.write("")
            print(f"已创建空的日志文件: {LOG_FILE_PATH}")
        except Exception as e:
            print(f"创建空日志文件失败: {e}")

def wait_for_log_entry(pattern: str, timeout_seconds: int, max_lines_to_check: int = 4000, check_interval: float = 0.2) -> bool:
    """
    在指定的超时时间内等待日志文件中出现匹配特定模式的条目。

    Args:
        pattern: 正则表达式模式。
        timeout_seconds: 等待的超时时间 (秒)。
        max_lines_to_check: 每次检查时从文件末尾读取的最大行数。
        check_interval: 检查日志文件的时间间隔 (秒)。

    Returns:
        bool: 如果在超时时间内找到匹配的条目则返回 True，否则返回 False。
    """
    start_time = time.time()
    if not os.path.exists(LOG_FILE_PATH):
        print(f"日志文件在 wait_for_log_entry 开始时未找到: {LOG_FILE_PATH}")
        # 等待文件被创建
        while not os.path.exists(LOG_FILE_PATH) and (time.time() - start_time) < timeout_seconds:
            time.sleep(check_interval)
        if not os.path.exists(LOG_FILE_PATH):
            print(f"日志文件在 {timeout_seconds} 秒内未创建: {LOG_FILE_PATH}")
            return False

    while (time.time() - start_time) < timeout_seconds:
        try:
            with open(LOG_FILE_PATH, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                lines_to_check = lines[-max_lines_to_check:]
                for line in reversed(lines_to_check): # 从新到旧检查
                    if re.search(pattern, line):
                        print(f"wait_for_log_entry: 找到匹配 '{pattern}' 的日志: {line.strip()}")
                        return True
        except FileNotFoundError:
            # 文件可能在检查间隙被删除和重建
            print(f"wait_for_log_entry: 尝试读取时日志文件未找到: {LOG_FILE_PATH}")
        except Exception as e:
            print(f"wait_for_log_entry: 解析日志文件时出错: {e}")
        
        time.sleep(check_interval)
    
    print(f"wait_for_log_entry: 超时 {timeout_seconds} 秒后仍未找到匹配 '{pattern}' 的日志。")
    return False
