import re
import os
from typing import List
import time
import logging # Added for log_marker

# 假设日志文件在项目根目录下的logs文件夹中
LOG_FILE_PATH = 'logs/firewall.log'
logger = logging.getLogger("log_parser_helper") # Logger for this helper

# --- 新增：文件操作辅助函数与重试逻辑 ---
MAX_FILE_ACCESS_RETRIES = 5
FILE_ACCESS_RETRY_DELAY = 0.2 # seconds

def _open_log_file_with_retry(mode='r', encoding='utf-8'):
    """尝试以重试方式打开日志文件。"""
    last_exception = None
    for attempt in range(MAX_FILE_ACCESS_RETRIES):
        try:
            return open(LOG_FILE_PATH, mode, encoding=encoding)
        except (IOError, PermissionError) as e:
            last_exception = e
            # logger.debug(f"LogParser: Attempt {attempt + 1} to open {LOG_FILE_PATH} in mode '{mode}' failed: {e}. Retrying in {FILE_ACCESS_RETRY_DELAY}s...")
            time.sleep(FILE_ACCESS_RETRY_DELAY)
    if last_exception:
        # logger.error(f"LogParser: Failed to open {LOG_FILE_PATH} in mode '{mode}' after {MAX_FILE_ACCESS_RETRIES} attempts. Last error: {last_exception}")
        raise last_exception # Re-raise the last encountered exception
    return None # Should not be reached if MAX_FILE_ACCESS_RETRIES > 0

def _read_log_lines_with_retry() -> List[str]:
    """尝试以重试方式读取日志文件的所有行。"""
    last_exception = None
    if not os.path.exists(LOG_FILE_PATH):
        # logger.warning(f"LogParser: Log file {LOG_FILE_PATH} does not exist during read attempt.")
        return []
        
    for attempt in range(MAX_FILE_ACCESS_RETRIES):
        try:
            with open(LOG_FILE_PATH, 'r', encoding='utf-8') as f:
                return f.readlines()
        except (IOError, PermissionError, FileNotFoundError) as e: # Added FileNotFoundError here too
            last_exception = e
            # logger.debug(f"LogParser: Attempt {attempt + 1} to read {LOG_FILE_PATH} failed: {e}. Retrying in {FILE_ACCESS_RETRY_DELAY}s...")
            if isinstance(e, FileNotFoundError): # If file not found mid-operation, maybe it was just cleared/rotated
                if attempt < MAX_FILE_ACCESS_RETRIES -1: # Only retry if not the last attempt
                    time.sleep(FILE_ACCESS_RETRY_DELAY)
                    continue 
                else: # If it's the last attempt and still not found, treat as empty or error
                    break 
            time.sleep(FILE_ACCESS_RETRY_DELAY)

    if last_exception:
        logger.error(f"LogParser: Failed to read {LOG_FILE_PATH} after {MAX_FILE_ACCESS_RETRIES} attempts. Last error: {last_exception}")
        # Depending on strictness, could raise last_exception or return empty list
    return []

def log_marker(marker_text: str):
    """向主日志文件写入一个标记行。"""
    try:
        # 使用项目统一的日志配置，或者一个简单的文件写入
        # 为了确保它能被pytest捕获，并且与防火墙日志在同一个文件，直接写入比较简单
        # Appending is generally less prone to conflicts than writing ('w')
        with _open_log_file_with_retry(mode='a') as f:
            if f:
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                f.write(f"{timestamp},{int(time.time()*1000)%1000:03d} - MARKER - INFO - {marker_text}\\n")
            else:
                print(f"LogParser: Failed to open log file for marker after retries: {marker_text}")
        # logger.info(marker_text) # This would go to console if logger is configured for that
    except Exception as e:
        print(f"写入日志标记 '{marker_text}' 到 {LOG_FILE_PATH} 失败 (even with retries): {e}")

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
    # if not os.path.exists(LOG_FILE_PATH): # Handled by _read_log_lines_with_retry
    #     print(f"日志文件未找到: {LOG_FILE_PATH}")
    #     return matched_entries

    try:
        # with open(LOG_FILE_PATH, 'r', encoding='utf-8') as f: # Replaced with retry logic
            # 读取所有行，然后取最后N行
            # 对于非常大的日志文件，可以考虑更优化的逐行倒读方式
        lines = _read_log_lines_with_retry()
        if not lines: # If read failed or file is empty
            return matched_entries
            
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
    # if not os.path.exists(LOG_FILE_PATH): # Handled by _read_log_lines_with_retry
    #     print(f"日志文件未找到: {LOG_FILE_PATH}")
    #     return matched_entries

    try:
        # with open(LOG_FILE_PATH, 'r', encoding='utf-8') as f: # Replaced
        lines = _read_log_lines_with_retry()
        if not lines:
            return matched_entries
            
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

def count_all_log_entries(pattern: str) -> int:
    """扫描整个日志文件，计算匹配给定正则表达式模式的条目总数。"""
    count = 0
    # if not os.path.exists(LOG_FILE_PATH): # Handled by _read_log_lines_with_retry
    #     print(f"日志文件不存在: {LOG_FILE_PATH}")
    #     return 0
    try:
        # with open(LOG_FILE_PATH, 'r', encoding='utf-8') as f: # Replaced
        lines = _read_log_lines_with_retry()
        if not lines:
            return 0
        for line in lines:
            if re.search(pattern, line):
                count += 1
    # except FileNotFoundError: # Covered by retry logic / _read_log_lines_with_retry returning empty
    #     print(f"打开日志文件时未找到 (可能在计数过程中被删除): {LOG_FILE_PATH}")
    #     return 0 
    except Exception as e:
        print(f"读取或解析日志文件 {LOG_FILE_PATH} 时出错 (after retries): {e}")
    return count

def count_log_entries_after_last_marker(pattern_to_count: str, marker_pattern: str) -> int:
    """
    计算在日志文件中最后一个匹配 marker_pattern 的标记行之后，
    出现了多少行匹配 pattern_to_count。
    如果未找到 marker_pattern，则从文件开头开始计数。
    """
    count = 0
    last_marker_line_num = -1

    # if not os.path.exists(LOG_FILE_PATH): # Handled by _read_log_lines_with_retry
    #     print(f"日志文件不存在: {LOG_FILE_PATH}")
    #     return 0

    try:
        # with open(LOG_FILE_PATH, 'r', encoding='utf-8') as f: # Replaced
        #     lines = f.readlines()
        lines = _read_log_lines_with_retry()
        if not lines:
            if last_marker_line_num == -1: # Check moved here
                 print(f"警告: 在 {LOG_FILE_PATH} 中未找到标记 '{marker_pattern}' (且日志无法读取或为空)。已从头计数 '{pattern_to_count}' 结果为0。")
            return 0
        
        # 1. 找到最后一个标记的位置 (从后向前搜索效率更高)
        for i in range(len(lines) - 1, -1, -1):
            if re.search(marker_pattern, lines[i]):
                last_marker_line_num = i
                break
        
        # 2. 如果找到了标记，则从标记后的下一行开始计数
        start_index = last_marker_line_num + 1 if last_marker_line_num != -1 else 0
        
        for i in range(start_index, len(lines)):
            if re.search(pattern_to_count, lines[i]):
                count += 1
        
        if last_marker_line_num == -1:
            print(f"警告: 在 {LOG_FILE_PATH} 中未找到标记 '{marker_pattern}'。已从头计数 '{pattern_to_count}'。")

    except FileNotFoundError:
        print(f"打开日志文件时未找到: {LOG_FILE_PATH}")
        return 0
    except Exception as e:
        print(f"读取或解析日志文件 {LOG_FILE_PATH} 时出错 (after retries): {e}")
    return count

def clear_log_file():
    """清空日志文件内容，如果文件不存在则创建它。"""
    # Ensure directory exists (this part is fine as it's usually a one-off)
    log_dir = os.path.dirname(LOG_FILE_PATH)
    if log_dir and not os.path.exists(log_dir): # Check if log_dir is not empty
        try:
            os.makedirs(log_dir)
            print(f"日志目录已创建: {log_dir}")
        except Exception as e:
            print(f"创建日志目录失败: {e}")
            # If directory creation fails, subsequent file operations will likely fail

    # Attempt to clear the file with retry
    last_exception = None
    for attempt in range(MAX_FILE_ACCESS_RETRIES):
        try:
            with open(LOG_FILE_PATH, 'w', encoding='utf-8') as f:
                f.write("") # 写入空字符串以清空
            # logger.info(f"LogParser: Log file {LOG_FILE_PATH} cleared on attempt {attempt + 1}.")
            print(f"日志文件已清空: {LOG_FILE_PATH}")
            return # Success
        except (IOError, PermissionError) as e:
            last_exception = e
            # logger.debug(f"LogParser: Attempt {attempt + 1} to clear {LOG_FILE_PATH} failed: {e}. Retrying...")
            time.sleep(FILE_ACCESS_RETRY_DELAY)
            
    if last_exception:
        print(f"清空日志文件失败 (after {MAX_FILE_ACCESS_RETRIES} retries): {LOG_FILE_PATH}, Error: {last_exception}")

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
    # Initial check for log file existence can also use a small wait
    # if not os.path.exists(LOG_FILE_PATH):
    #     logger.warning(f"LogParser: Log file {LOG_FILE_PATH} does not exist at start of wait_for_log_entry.")
        # Wait for file to be created, but _read_log_lines_with_retry handles this internally now.

    while (time.time() - start_time) < timeout_seconds:
        try:
            # with open(LOG_FILE_PATH, 'r', encoding='utf-8') as f: # Replaced
            #     lines = f.readlines()
            lines = _read_log_lines_with_retry() # This now handles retries and initial existence
            if not lines and (time.time() - start_time) < timeout_seconds: # File might be temporarily empty or unreadable
                time.sleep(check_interval)
                continue

            lines_to_check = lines[-max_lines_to_check:]
            for line in reversed(lines_to_check): # 从新到旧检查
                if re.search(pattern, line):
                    print(f"wait_for_log_entry: 找到匹配 '{pattern}' 的日志: {line.strip()}")
                    return True
        except FileNotFoundError:
            # 文件可能在检查间隙被删除和重建
            print(f"wait_for_log_entry: 尝试读取时日志文件未找到: {LOG_FILE_PATH}")
        except Exception as e: # Catch broader exceptions if _read_log_lines_with_retry raises something unexpected
            print(f"wait_for_log_entry: 解析日志文件时出错 (after retries in read): {e}")
        
        time.sleep(check_interval)
    
    print(f"wait_for_log_entry: 超时 {timeout_seconds} 秒后仍未找到匹配 '{pattern}' 的日志。")
    return False
