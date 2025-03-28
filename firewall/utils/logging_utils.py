#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import logging
import logging.handlers
import atexit
from PyQt6.QtCore import QObject, pyqtSignal

# --- Signal Handler for UI ---
class SignalHandler(logging.Handler, QObject):
    """Custom logging handler that emits a signal."""
    log_signal = pyqtSignal(str)

    def __init__(self, level=logging.NOTSET):
        super().__init__(level)
        QObject.__init__(self) # Initialize QObject
        # 设置属性以防止在关闭时flush
        self.flushOnClose = False
        
    def emit(self, record):
        try:
            msg = self.format(record)
            self.log_signal.emit(msg)
        except Exception:
            self.handleError(record)
            
    def prepare_for_exit(self):
        """在程序退出前安全清理资源"""
        # 将信号对象设为None以断开循环引用
        self.log_signal = None
        # 确保不会在退出时flush
        self.flushOnClose = False
            
    def close(self):
        """重写close方法确保安全清理"""
        try:
            self.prepare_for_exit()
        except:
            pass
        super().close()

# 全局变量存储handler实例，方便访问
_signal_handler_instance = None

def clear_signal_handler_on_exit():
    """在程序退出前执行，确保信号处理器被正确清理"""
    global _signal_handler_instance
    if _signal_handler_instance is not None:
        try:
            # 首先从root logger中移除
            root_logger = logging.getLogger()
            if _signal_handler_instance in root_logger.handlers:
                root_logger.removeHandler(_signal_handler_instance)
            
            # 安全清理资源
            _signal_handler_instance.prepare_for_exit()
            _signal_handler_instance = None
        except Exception as e:
            # 捕获但不抛出异常，避免影响其他退出处理
            print(f"清理SignalHandler时出错: {e}")

def setup_logging() -> SignalHandler:
    """
    Configures logging for the firewall application.

    Sets up a rotating file handler and a signal handler for the UI.

    Returns:
        SignalHandler: The configured signal handler instance.
    """
    global _signal_handler_instance
    
    LOG_DIR = "logs"
    LOG_FILE = os.path.join(LOG_DIR, "firewall.log")
    os.makedirs(LOG_DIR, exist_ok=True)

    # Define log format
    log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Get root logger and set level to DEBUG to capture everything
    root_logger = logging.getLogger()
    # Clear existing handlers to avoid duplicates if script is re-run or module reloaded
    if root_logger.hasHandlers():
        root_logger.handlers.clear()
    root_logger.setLevel(logging.DEBUG) # Capture all levels

    # Create Rotating File Handler
    file_handler = logging.handlers.RotatingFileHandler(
        LOG_FILE,
        maxBytes=10*1024*1024, # 10 MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setLevel(logging.INFO) # File logs INFO and above
    file_handler.setFormatter(log_formatter)
    root_logger.addHandler(file_handler)

    # Create Signal Handler instance
    signal_handler = SignalHandler()
    signal_handler.setLevel(logging.DEBUG) # UI receives DEBUG and above
    signal_handler.setFormatter(log_formatter)
    root_logger.addHandler(signal_handler) # Add signal handler to root logger
    
    # 存储信号处理器实例到全局变量
    _signal_handler_instance = signal_handler
    
    # 注册退出时的清理函数
    atexit.register(clear_signal_handler_on_exit)

    # Optional: Add a StreamHandler for console output during development
    # console_handler = logging.StreamHandler()
    # console_handler.setLevel(logging.DEBUG)
    # console_handler.setFormatter(log_formatter)
    # root_logger.addHandler(console_handler)

    logging.getLogger('root').info("日志系统设置完成。") # Log that setup is done

    return signal_handler

# Example usage (for testing purposes, usually called from main application entry point)
# if __name__ == "__main__":
#     sh = setup_logging()
#     logging.getLogger("TestLogger").info("This is an info message.")
#     logging.getLogger("TestLogger").debug("This is a debug message.")
#     logging.getLogger("TestLogger").warning("This is a warning message.")
