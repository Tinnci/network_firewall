#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import time
import threading
import logging
import platform
import subprocess
from typing import Optional, Callable

import pydivert

# Get logger instance
logger = logging.getLogger('PacketInterceptor')

class PacketInterceptor:
    """负责与WinDivert交互，拦截和发送网络数据包"""

    # Class variable to track if system info has been logged
    system_info_logged = False

    def __init__(self):
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.divert: Optional[pydivert.WinDivert] = None
        self.packet_handler_callback: Optional[Callable[[pydivert.Packet], None]] = None
        self.error_callback: Optional[Callable[[Exception], None]] = None
        self._log_system_info() # Log system info on first instantiation

    def register_packet_handler(self, callback: Callable[[pydivert.Packet], None]):
        """注册一个回调函数，用于处理接收到的数据包"""
        self.packet_handler_callback = callback

    def register_error_handler(self, callback: Callable[[Exception], None]):
        """注册一个回调函数，用于处理拦截过程中的错误"""
        self.error_callback = callback

    def start(self, filter_string: str = "tcp or udp") -> bool:
        """启动数据包拦截"""
        if self.running:
            logger.warning("Packet interceptor is already running.")
            return True

        logger.info("Starting packet interceptor...")
        try:
            # Validate filter syntax
            check_result = pydivert.WinDivert.check_filter(filter_string)
            if not check_result[0]:
                logger.error(f"WinDivert filter syntax error: {check_result[2]} at position {check_result[1]}")
                return False
            logger.debug(f"Using WinDivert filter: {filter_string}")

            # Create and open WinDivert handle
            self.divert = pydivert.WinDivert(filter=filter_string, layer=pydivert.Layer.NETWORK)
            self.divert.open()
            self.running = True

            # Configure WinDivert parameters
            self._configure_windivert_params()

            # Start the packet handling thread
            self.thread = threading.Thread(target=self._receive_loop)
            self.thread.daemon = True
            self.thread.start()
            logger.info("Packet interceptor started successfully.")
            return True
        except Exception as e:
            logger.error(f"Failed to start packet interceptor: {e}")
            if self.divert:
                try:
                    self.divert.close()
                except:
                    pass # Ignore errors during cleanup on failure
            self.running = False
            self.divert = None
            return False

    def stop(self):
        """停止数据包拦截"""
        if not self.running:
            logger.warning("Packet interceptor is not running.")
            return True

        logger.info("Stopping packet interceptor...")
        self.running = False # Signal the loop to stop

        # Close WinDivert handle (this should interrupt recv)
        if self.divert:
            try:
                self.divert.close()
                logger.debug("WinDivert handle closed.")
            except Exception as e:
                logger.error(f"Error closing WinDivert handle: {e}")
            self.divert = None

        # Wait for the thread to finish
        if self.thread:
            try:
                self.thread.join(timeout=2.0) # Wait up to 2 seconds
                if self.thread.is_alive():
                    logger.warning("Packet receive thread did not terminate gracefully.")
            except Exception as e:
                 logger.error(f"Error joining receive thread: {e}")
            self.thread = None

        logger.info("Packet interceptor stopped.")
        return True

    def send(self, packet: pydivert.Packet, recalculate_checksum: bool = True):
        """发送数据包"""
        if not self.running or not self.divert:
            logger.warning("Interceptor not running or handle closed, cannot send packet.")
            return
        try:
            self.divert.send(packet, recalculate_checksum=recalculate_checksum)
        except Exception as e:
            logger.error(f"Error sending packet: {e}")
            if self.error_callback:
                self.error_callback(e)
            # Re-raise or handle specific errors (like WinError 87) if needed upstream

    def _receive_loop(self):
        """主循环，用于接收数据包并调用回调"""
        logger.debug("Packet receive loop started.")
        while self.running:
            try:
                if not self.divert: # Check if handle is valid
                    logger.warning("WinDivert handle is not open in receive loop.")
                    time.sleep(0.1)
                    continue

                packet = self.divert.recv() # Blocking call
                
                if not self.running: # Check again after recv returns (might be interrupted by close)
                    break 
                    
                if packet:
                    if self.packet_handler_callback:
                        try:
                            self.packet_handler_callback(packet)
                        except Exception as handler_exc:
                             logger.error(f"Error in registered packet handler callback: {handler_exc}")
                             if self.error_callback:
                                 self.error_callback(handler_exc)
                else:
                    # recv might return None if handle is closed or timeout occurs (if timeout is set)
                    logger.debug("divert.recv() returned None.")
                    # Add a small sleep to prevent tight loop if recv continuously returns None
                    time.sleep(0.001)

            except Exception as e:
                if self.running: # Only log errors if we are supposed to be running
                    logger.error(f"Error in packet receive loop: {e}")
                    if self.error_callback:
                        self.error_callback(e)
                    # Optional: Add logic for too many errors (e.g., attempt restart or stop)
                    time.sleep(0.1) # Avoid spamming logs on continuous errors
                else:
                    # Expected error if stop() closed the handle during recv()
                    logger.debug(f"Receive loop exiting due to expected error after stop: {e}")
                    break # Exit loop cleanly

        logger.debug("Packet receive loop finished.")

    def _configure_windivert_params(self):
        """配置WinDivert参数"""
        if not self.divert:
            return
        try:
            from pydivert import Param
            queue_len = 8192
            queue_time = 2000 # ms
            self.divert.set_param(Param.QUEUE_LEN, queue_len)
            self.divert.set_param(Param.QUEUE_TIME, queue_time)
            logger.info(f"WinDivert queue length set to {queue_len}, queue time to {queue_time}ms")
            # Optional: Validate params were set using get_param
            # current_len = self.divert.get_param(Param.QUEUE_LEN)
            # current_time = self.divert.get_param(Param.QUEUE_TIME)
            # logger.debug(f"Verified WinDivert params: QUEUE_LEN={current_len}, QUEUE_TIME={current_time}")
        except Exception as e:
            logger.warning(f"Failed to configure WinDivert parameters: {e}. Using defaults.")

    def _log_system_info(self):
        """记录系统信息和WinDivert状态 (只记录一次)"""
        if PacketInterceptor.system_info_logged:
            logger.debug("System info already logged, skipping.")
            return

        logger.info("=" * 50)
        logger.info("System Information:")
        try:
            logger.info(f"  OS: {platform.platform()}")
            logger.info(f"  Python: {platform.python_version()}")
            logger.info(f"  Arch: {platform.architecture()}")
        except Exception as e:
             logger.warning(f"  Could not retrieve basic system info: {e}")

        logger.info("PyDivert Information:")
        try:
            logger.info(f"  PyDivert Version: {pydivert.__version__}")
        except Exception as e:
            logger.warning(f"  Could not retrieve PyDivert version: {e}")

        logger.info("WinDivert Driver Status:")
        try:
            is_registered = pydivert.WinDivert.is_registered()
            logger.info(f"  Driver Registered: {is_registered}")
            if not is_registered:
                 logger.warning("  WinDivert driver is not registered. Filtering will likely fail.")

            # Check service status (best effort)
            try:
                result = subprocess.run(['sc', 'query', 'WinDivert1.3'], capture_output=True, text=True, timeout=3, encoding='utf-8', errors='ignore')
                if result.returncode == 0:
                    logger.info("  Service Status:")
                    for line in result.stdout.splitlines():
                        if any(key in line for key in ['STATE', 'TYPE']):
                            logger.info(f"    {line.strip()}")
                else:
                    logger.debug(f"  Could not query WinDivert service (might not be installed or named differently): {result.stderr.strip()}")
            except Exception as e:
                logger.warning(f"  Error querying WinDivert service: {e}")

            # Check DLL path and details
            try:
                from pydivert.windivert_dll import DLL_PATH
                logger.info(f"  DLL Path: {DLL_PATH}")
                if os.path.exists(DLL_PATH):
                    logger.info(f"    DLL Size: {os.path.getsize(DLL_PATH)} bytes")
                    logger.info(f"    DLL Modified: {time.ctime(os.path.getmtime(DLL_PATH))}")
                else:
                    logger.warning(f"    DLL file not found at path: {DLL_PATH}")
            except Exception as e:
                logger.warning(f"  Error checking WinDivert DLL details: {e}")

        except Exception as e:
            logger.error(f"  Failed to check WinDivert status: {e}")

        logger.info("=" * 50)
        PacketInterceptor.system_info_logged = True

    def restart_windivert(self) -> bool:
        """尝试重启WinDivert实例"""
        logger.info("Attempting to restart WinDivert...")
        current_filter = self.divert.filter if self.divert else "tcp or udp"
        was_running = self.running
        
        # Stop the current instance first
        self.stop() 
        time.sleep(1) # Give resources time to release

        # Attempt to start a new instance
        if self.start(filter_string=current_filter):
             logger.info("WinDivert restarted successfully.")
             return True
        else:
             logger.error("WinDivert restart failed.")
             # If it was running before, try to restore the previous state (stopped)
             self.running = False 
             return False

# Example usage:
# def my_packet_handler(packet):
#     print(f"Received packet: {packet.src_addr}:{packet.src_port} -> {packet.dst_addr}:{packet.dst_port}")
#     # In a real scenario, pass to analyzer/processor, then maybe send back
#     # interceptor.send(packet) 

# def my_error_handler(error):
#      print(f"Interceptor error: {error}")

# if __name__ == "__main__":
#     logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
#     interceptor = PacketInterceptor()
#     interceptor.register_packet_handler(my_packet_handler)
#     interceptor.register_error_handler(my_error_handler)
    
#     if interceptor.start():
#         print("Interceptor started. Press Ctrl+C to stop.")
#         try:
#             while True:
#                 time.sleep(1)
#         except KeyboardInterrupt:
#             print("Stopping interceptor...")
#             interceptor.stop()
#             print("Interceptor stopped.")
#     else:
#         print("Failed to start interceptor.")
