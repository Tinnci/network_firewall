#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
网络防火墙主程序
"""

import os
import sys
import ctypes
import traceback
import logging # Added logging import

from PyQt6.QtWidgets import QApplication, QMessageBox
from PyQt6.QtCore import Qt

# Import necessary components
from firewall.ui.main_window import MainWindow
from firewall.utils.logging_utils import SignalHandler, clear_signal_handler_on_exit # 导入清理函数

# Get root logger for handler removal
root_logger = logging.getLogger()

def is_admin():
    """检查程序是否以管理员权限运行"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def remove_signal_handler():
    """从根日志记录器中移除SignalHandler实例并清理"""
    # 使用全局函数清理SignalHandler
    clear_signal_handler_on_exit()
    
    # 为兼容性保留旧实现，但不再是主要机制
    handler_to_remove = None
    for handler in root_logger.handlers[:]:  # 使用切片复制列表以防止迭代过程中修改
        if isinstance(handler, SignalHandler):
            handler_to_remove = handler
            # 从处理程序列表中移除
            root_logger.removeHandler(handler_to_remove)
            root_logger.info(f"已移除SignalHandler: {handler_to_remove}")
            # 清理资源
            try:
                if hasattr(handler_to_remove, 'prepare_for_exit'):
                    handler_to_remove.prepare_for_exit()
                elif hasattr(handler_to_remove, 'close'):
                    handler_to_remove.close()
            except Exception as e:
                root_logger.warning(f"关闭SignalHandler时出错: {e}")
            break  # 只移除第一个找到的


def main():
    """主函数"""
    # 检查管理员权限
    if not is_admin():
        # 非管理员权限运行时显示警告
        if len(sys.argv) <= 1 or sys.argv[1] != '--no-admin-check':
            # Create QApplication *before* QMessageBox
            app = QApplication(sys.argv) 
            
            # Create a temporary MainWindow instance to ensure logging (and signal handler) is set up
            # We need the handler instance to remove it later.
            # This isn't ideal, ideally logging setup is independent of UI creation.
            # Consider refactoring logging setup call out of Firewall.__init__ later.
            try:
                temp_window = MainWindow() 
                # Access the handler via the instance if needed, though removing by type is safer
                # handler_instance = temp_window.firewall.signal_handler 
            except Exception as init_err:
                 # If MainWindow init fails, we might not be able to remove handler easily
                 print(f"警告: 无法创建临时MainWindow以移除处理程序: {init_err}")
                 # Proceed without guaranteed handler removal in this edge case

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
                        # 在启动管理员权限程序前先移除SignalHandler
                        remove_signal_handler()
                        ctypes.windll.shell32.ShellExecuteW(
                            None, "runas", sys.executable, " ".join(sys.argv), None, 1
                        )
                        sys.exit(0) # Clean exit for the old process
                except Exception as e:
                    QMessageBox.critical(None, "错误", f"无法以管理员身份启动程序: {e}")
                # If ShellExecuteW fails or we are not on win32, exit normally
                remove_signal_handler() # Attempt removal even on failure
                sys.exit(1) # Exit with error code
            else:
                # 用户选择不以管理员身份运行
                # No need to restart with --no-admin-check, just proceed
                # remove_signal_handler() # Remove handler before proceeding in non-admin mode
                # sys.exit(0) # Exit the process that showed the dialog
                # Let the main part of the script run below, but it will likely fail later.
                # Or, show a message and exit cleanly.
                QMessageBox.information(None, "提示", "程序将在没有管理员权限的情况下继续运行，部分功能可能受限。")
                # Fall through to run the app without admin rights (as requested by user)
                pass # Let the rest of the main function execute

    # --- Main Application Execution ---
    # Create QApplication instance (might be created already if admin check failed and user chose No)
    # Use instance() to get the existing instance if available
    app = QApplication.instance() 
    if app is None:
        app = QApplication(sys.argv)

    # 设置应用信息
    app.setApplicationName("简易防火墙")
    app.setApplicationVersion("1.0.0")
    
    # 创建主窗口
    window = MainWindow()
    window.show()
    
    # 运行应用程序
    exit_code = app.exec()
    # Ensure handler is removed on normal exit too
    remove_signal_handler() 
    sys.exit(exit_code)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        # Log the exception before showing the message box
        logging.getLogger('main').critical(f"未处理的异常: {e}", exc_info=True)
        
        # Attempt to show message box, but might fail if QApplication isn't running
        try:
            app = QApplication.instance() 
            if app is None: # Create if not exists, needed for QMessageBox
                 app = QApplication(sys.argv)
            
            error_message = f"程序遇到严重错误:\n{str(e)}\n\n请查看日志文件获取详细信息。\n\n{traceback.format_exc()}"
            QMessageBox.critical(None, "严重错误", error_message)
        except Exception as mb_err:
             print(f"严重错误: {e}\n{traceback.format_exc()}")
             print(f"此外，无法显示错误消息框: {mb_err}")

        # Ensure handler is removed even on crash exit
        remove_signal_handler() 
        sys.exit(1)
