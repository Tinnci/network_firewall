import re
import os
from typing import List, Optional

# 假设日志文件在项目根目录下的logs文件夹中
LOG_FILE_PATH = 'logs/firewall.log'

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
