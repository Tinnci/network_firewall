#!/usr/bin/env python
# -*- coding: utf-8 -*-

import psutil
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

def get_system_resource_usage() -> Dict[str, Any]:
    """
    获取当前系统资源使用情况 (CPU, 内存, 网络IO)。

    Returns:
        Dict[str, Any]: 包含资源使用信息的字典。
                       例如: {'cpu_percent': 10.5, 'memory_percent': 45.2,
                              'io_counters': {'bytes_sent': ..., 'bytes_recv': ...}}
                       如果获取失败则返回空字典。
    """
    try:
        cpu_percent = psutil.cpu_percent(interval=None)
        memory_info = psutil.virtual_memory()
        net_io = psutil.net_io_counters()

        return {
            'cpu_percent': cpu_percent,
            'memory_percent': memory_info.percent,
            'io_counters': net_io._asdict() if net_io else {} # Convert namedtuple to dict
        }
    except Exception as e:
        logger.warning(f"获取系统资源使用情况时出错: {e}")
        return {}

# Example usage:
# if __name__ == "__main__":
#     resources = get_system_resource_usage()
#     if resources:
#         print("System Resource Usage:")
#         print(f"  CPU: {resources['cpu_percent']}%")
#         print(f"  Memory: {resources['memory_percent']}%")
#         print(f"  Net IO: {resources['io_counters']}")
#     else:
#         print("Failed to get system resource usage.")
