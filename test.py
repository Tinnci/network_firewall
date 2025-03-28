#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import time

# 添加当前目录到系统路径以便导入
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

from firewall.core.packet_filter import PacketFilter

def main():
    print("=" * 50)
    print("开始测试PacketFilter类 - 日志重复问题修复测试")
    print("=" * 50)
    
    print("\n第一次初始化PacketFilter...")
    # 创建过滤器实例
    pf = PacketFilter()
    print("过滤器初始化完成")
    
    print("\n第一次启动过滤器...")
    # 启动过滤器
    result = pf.start()
    print(f"过滤器启动结果: {result}")
    
    # 等待一段时间
    print("\n等待2秒...")
    time.sleep(2)
    
    print("\n停止过滤器...")
    # 停止过滤器
    pf.stop()
    print("过滤器已停止")
    
    print("\n第二次启动相同实例...")
    # 再次启动，验证是否会重复记录
    result = pf.start()
    print(f"过滤器启动结果: {result}")
    
    print("\n验证是否能正确处理参数错误...")
    # 等待用户输入
    input("按回车键停止过滤器...")
    
    # 停止过滤器
    pf.stop()
    print("过滤器已停止")
    
    print("\n测试完成！")

if __name__ == "__main__":
    main() 