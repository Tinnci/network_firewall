#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import logging
import logging.handlers
import atexit
import datetime
from PyQt6.QtCore import QObject, pyqtSignal

# Import config
from ..config import CONFIG
# --- Signal Handler for UI ---
class SignalHandler(logging.Handler, QObject):
    """Custom logging handler that emits a dictionary signal."""
    # Changed signal type from str to dict
    log_signal = pyqtSignal(dict)

    def __init__(self, level=logging.NOTSET):
        super().__init__(level)
        QObject.__init__(self) # Initialize QObject
        # 设置属性以防止在关闭时flush
        self.flushOnClose = False
        
    def emit(self, record: logging.LogRecord):
        """Emit a dictionary containing structured log information."""
        try:
            log_entry = {
                # Standard fields
                "timestamp": getattr(record, 'asctime', datetime.datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]), # Use formatted time if available, else create it
                "name": record.name,
                "levelno": record.levelno,
                "levelname": record.levelname,
                "message": record.getMessage(), # Get the formatted message
                "pathname": record.pathname,
                "lineno": record.lineno,
                # Potential custom fields from 'extra'
                "log_type": getattr(record, 'log_type', 'general'), # Default to 'general'
                "packet_info": getattr(record, 'packet_info', None), # Will be None if not provided
            }
            # Add formatted full message for potential fallback display
            log_entry["formatted_message"] = self.format(record)

            self.log_signal.emit(log_entry)
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
    
    # Get config values
    log_cfg = CONFIG['logging']
    log_dir = log_cfg.get("log_dir", "logs")
    log_filename = log_cfg.get("log_filename", "firewall.log")
    log_file = os.path.join(log_dir, log_filename)
    os.makedirs(log_dir, exist_ok=True)

    # Define log format from config
    log_format = log_cfg.get("format", '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    log_formatter = logging.Formatter(log_format)

    # Get root logger and set level to DEBUG to capture everything
    root_logger = logging.getLogger()
    if root_logger.hasHandlers():
        root_logger.handlers.clear()
    root_logger.setLevel(logging.DEBUG) # Capture all levels

    # Create Rotating File Handler using config values
    max_bytes = log_cfg.get("max_bytes", 10 * 1024 * 1024)
    backup_count = log_cfg.get("backup_count", 5)
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding='utf-8'
    )
    file_level = log_cfg.get("file_level", logging.INFO)
    file_handler.setLevel(file_level) 
    file_handler.setFormatter(log_formatter)
    root_logger.addHandler(file_handler)

    # Create Signal Handler instance using config values
    signal_handler = SignalHandler()
    signal_level = log_cfg.get("signal_level", logging.DEBUG)
    signal_handler.setLevel(signal_level) 
    signal_handler.setFormatter(log_formatter)
    root_logger.addHandler(signal_handler) 
    
    # Store the handler instance globally
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
