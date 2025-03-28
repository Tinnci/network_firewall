#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
网络防火墙主程序
"""

import os
import sys
import ctypes
import traceback

from PyQt6.QtWidgets import QApplication, QMessageBox
from PyQt6.QtCore import Qt

from firewall.ui.main_window import MainWindow


def is_admin():
    """检查程序是否以管理员权限运行
    
    Returns:
        bool: 是否拥有管理员权限
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def main():
    """主函数"""
    # 检查管理员权限
    if not is_admin():
        # 非管理员权限运行时显示警告
        if len(sys.argv) <= 1 or sys.argv[1] != '--no-admin-check':
            # 在PyQt6中，高DPI缩放默认启用，不需要手动设置AA_EnableHighDpiScaling
            app = QApplication(sys.argv)
            
            # 弹出管理员权限警告
            result = QMessageBox.warning(
                None,
                "权限不足",
                "防火墙需要管理员权限才能正常运行。\n"
                "是否以管理员身份重新启动程序？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if result == QMessageBox.StandardButton.Yes:
                # 尝试以管理员权限重启程序
                try:
                    if sys.platform == 'win32':
                        # Windows环境下重启为管理员权限
                        ctypes.windll.shell32.ShellExecuteW(
                            None, "runas", sys.executable, " ".join(sys.argv), None, 1
                        )
                except:
                    QMessageBox.critical(
                        None,
                        "错误",
                        "无法以管理员身份启动程序。"
                    )
                return
            else:
                # 用户选择不以管理员身份运行，使用--no-admin-check参数重启
                args = sys.argv.copy()
                args.append('--no-admin-check')
                try:
                    if sys.platform == 'win32':
                        os.execv(sys.executable, ['python'] + args)
                except:
                    pass
                return
    
    # 创建QApplication实例
    # 在PyQt6中，高DPI缩放默认启用
    app = QApplication(sys.argv)
    
    # 设置应用信息
    app.setApplicationName("简易防火墙")
    app.setApplicationVersion("1.0.0")
    
    # 创建主窗口
    window = MainWindow()
    window.show()
    
    # 运行应用程序
    sys.exit(app.exec())


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        # 捕获异常并显示
        # 在PyQt6中，高DPI缩放默认启用
        app = QApplication(sys.argv)
        
        error_message = f"程序遇到错误:\n{str(e)}\n\n{traceback.format_exc()}"
        QMessageBox.critical(None, "错误", error_message)
        
        # 退出程序
        sys.exit(1) 