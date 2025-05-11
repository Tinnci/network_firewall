#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import time
import queue
import threading
from typing import Dict, Optional, Callable

import pydivert

# Import local components
from .packet_interceptor import PacketInterceptor
from .packet_analyzer import PacketAnalyzer

# Get logger instance
logger = logging.getLogger('PacketProcessor')

class PacketProcessor:
    """负责处理数据包（发送、丢弃、统计）并管理处理流程"""

    def __init__(self, interceptor: PacketInterceptor, analyzer: PacketAnalyzer):
        self.interceptor = interceptor
        self.analyzer = analyzer
        self.running = False

        # Processing queue and workers (optional, can be enabled via settings)
        self.packet_queue = queue.Queue(maxsize=1000)
        self.worker_threads: list[threading.Thread] = []
        self.num_workers = 2

        # Packet pool (optional)
        self.packet_pool: list[pydivert.Packet] = []
        self.max_pool_size = 100

        # Statistics
        self.stats = {
            "total_processed": 0,
            "dropped": 0,
            "passed": 0,
            "errors": 0,
            "win_error_87_count": 0,
            "rebuild_success": 0,
            "rebuild_failure": 0,
            "start_time": 0,
            "last_packet_time": 0,
        }
        # More detailed stats can be added if needed (e.g., packet types)

        # Settings
        self.settings = {
            'use_queue_model': False,
            'num_workers': 2,
            'use_packet_pool': True,
            'max_pool_size': 100,
            # Add other relevant settings if processor needs them
        }

        # External callback for processed packets (e.g., for logging/UI)
        self.processed_packet_callback: Optional[Callable[[Dict, bool], None]] = None

        # Register the main processing method with the interceptor
        self.interceptor.register_packet_handler(self.handle_packet)
        self.interceptor.register_error_handler(self._handle_interceptor_error)

    def set_settings(self, settings: Dict):
        """更新处理器使用的设置"""
        self.settings.update(settings)
        self.num_workers = self.settings.get('num_workers', 2)
        self.max_pool_size = self.settings.get('max_pool_size', 100)
        # Adjust worker threads if queue model is toggled while running
        if self.running:
            self._update_worker_threads()
        logger.debug(f"PacketProcessor settings updated: {self.settings}")

    def register_processed_packet_callback(self, callback: Callable[[Dict, bool], None]):
        """注册回调，在数据包处理（放行/拦截）后调用"""
        self.processed_packet_callback = callback

    def start(self):
        """启动处理器（主要是启动工作线程，如果使用队列模型）"""
        if self.running:
            logger.warning("Packet processor is already running.")
            return
        self.running = True
        self.stats["start_time"] = time.time()
        self._update_worker_threads() # Start workers if needed
        logger.info("Packet processor started.")

    def stop(self):
        """停止处理器（主要是停止工作线程）"""
        if not self.running:
            logger.warning("Packet processor is not running.")
            return
        self.running = False
        # Signal and wait for worker threads to finish
        logger.debug("Signaling worker threads to stop...")
        self.packet_queue.join() # Wait for queue to be empty
        for worker in self.worker_threads:
             worker.join(timeout=1.0)
        self.worker_threads = []
        logger.info("Packet processor stopped.")

    def _update_worker_threads(self):
        """根据设置启动或停止工作线程"""
        use_queue = self.settings.get('use_queue_model', False)

        # Stop existing workers if queue model is disabled or num_workers changed
        if not use_queue or len(self.worker_threads) != self.num_workers:
            if self.worker_threads:
                 logger.info("Stopping existing worker threads...")
                 # Signal running flag is enough, join happens in stop() or here if needed immediately
                 # For simplicity, rely on stop() to join them.
                 self.worker_threads = [] # Clear the list

        # Start new workers if queue model is enabled and workers aren't running
        if use_queue and not self.worker_threads:
            logger.info(f"Starting {self.num_workers} packet processing worker threads...")
            for i in range(self.num_workers):
                worker = threading.Thread(target=self._worker_loop, name=f"ProcessorWorker-{i}")
                worker.daemon = True
                worker.start()
                self.worker_threads.append(worker)

    def handle_packet(self, packet: pydivert.Packet):
        """处理从拦截器接收到的数据包"""
        if not self.running:
            return # Ignore packets if processor is stopped

        # Use packet from pool if available and enabled
        pooled_packet = self._get_packet_from_pool()
        if pooled_packet:
             # How to reuse? Need to copy data? PyDivert packets might not be easily reusable.
             # For now, let's not reuse pooled packets directly for processing, just for allocation.
             # We'll return the original packet to the pool later if needed.
             pass # Placeholder

        # Analyze the packet
        should_pass, reason_str = self.analyzer.should_pass(packet)

        # Process based on queue model setting
        if self.settings.get('use_queue_model', False):
            try:
                self.packet_queue.put((packet, should_pass, reason_str), block=False)
            except queue.Full:
                logger.warning("Packet processing queue is full. Processing directly.")
                self._process_action(packet, should_pass, reason_str)
        else:
            # Process directly in the interceptor's thread
            self._process_action(packet, should_pass, reason_str)

    def _worker_loop(self):
        """工作线程循环，处理队列中的数据包"""
        logger.debug(f"Worker thread started: {threading.current_thread().name}")
        while self.running:
            try:
                packet, should_pass, reason_str = self.packet_queue.get(timeout=0.5)
                self._process_action(packet, should_pass, reason_str)
                self.packet_queue.task_done()
            except queue.Empty:
                continue # Continue waiting if queue is empty
            except Exception as e:
                 logger.error(f"Error in packet processing worker: {e}", exc_info=True)
                 # Avoid continuous errors by sleeping briefly
                 time.sleep(0.1)
        logger.debug(f"Worker thread finished: {threading.current_thread().name}")

    def _process_action(self, packet: pydivert.Packet, should_pass: bool, reason_details: str):
        """执行数据包的最终动作（发送或丢弃）并更新统计"""
        self.stats["total_processed"] += 1
        self.stats["last_packet_time"] = time.time()
        
        packet_info_full = self.analyzer.get_packet_info(packet) # Get full info
        packet_info_full['action'] = "放行" if should_pass else "拦截"
        packet_info_full['reason_details'] = reason_details # Store the reason

        # The reason_for_action for logging message can be simplified as it's now in reason_details
        reason_for_logging_msg = reason_details 

        try:
            if should_pass:
                # Attempt to send the packet safely
                logger.debug(f"决定放行: 源={packet_info_full['src_addr']}:{packet_info_full['src_port']}, 目标={packet_info_full['dst_addr']}:{packet_info_full['dst_port']}, 协议={packet_info_full['protocol']}, 原因: {reason_for_logging_msg}", extra={'log_type': 'packet', 'packet_info': packet_info_full})
                self._send_packet_safe(packet)
                self.stats["passed"] += 1
            else:
                # Just update stats for dropped packets
                logger.info(f"决定拦截: 源={packet_info_full['src_addr']}:{packet_info_full['src_port']}, 目标={packet_info_full['dst_addr']}:{packet_info_full['dst_port']}, 协议={packet_info_full['protocol']}, 原因: {reason_for_logging_msg}", extra={'log_type': 'packet', 'packet_info': packet_info_full})
                self.stats["dropped"] += 1

            # Trigger external callback after action is taken (or decided)
            if self.processed_packet_callback:
                try:
                    self.processed_packet_callback(packet_info_full, should_pass)
                except Exception as cb_exc:
                    logger.error(f"Error in processed_packet_callback: {cb_exc}")

        except Exception as e:
            self.stats["errors"] += 1
            action_taken_for_log = "放行" if should_pass else "拦截"
            logger.error(f"Failed to process packet action ({action_taken_for_log}): {e}", exc_info=True)
            # Optionally trigger error callback here too
            # if self.error_callback: self.error_callback(e)

        finally:
            # Return packet to pool if enabled
            if self.settings.get('use_packet_pool', True):
                self._return_packet_to_pool(packet)

    def _send_packet_safe(self, packet: pydivert.Packet):
        """安全地发送数据包，包含WinError 87处理"""
        try:
            # Basic validation (optional, interceptor might do this)
            if not packet or not hasattr(packet, 'raw') or len(packet.raw) < 20:
                 logger.warning("Attempted to send invalid packet.")
                 self.stats["errors"] += 1
                 return

            # Recalculate checksums unless it's loopback
            recalc = not getattr(packet, 'is_loopback', False)
            if recalc and hasattr(packet, 'recalculate_checksums'):
                 try:
                     packet.recalculate_checksums()
                 except Exception as chksum_err:
                      logger.warning(f"Checksum recalculation failed (sending anyway): {chksum_err}")

            # Send via interceptor
            self.interceptor.send(packet, recalculate_checksum=recalc)

        except Exception as send_err:
            # Handle WinError 87 specifically
            if "[WinError 87]" in str(send_err) and hasattr(packet, 'raw'):
                logger.warning("WinError 87 detected, attempting rebuild workaround...")
                self.stats["win_error_87_count"] += 1
                try:
                    # Create a new packet object from raw data
                    # This sometimes helps with internal state issues in PyDivert
                    new_packet = pydivert.Packet(packet.raw, packet.interface, packet.direction)
                    # Send the new packet, explicitly disable checksum recalc
                    self.interceptor.send(new_packet, recalculate_checksum=False)
                    self.stats["rebuild_success"] += 1
                    logger.info("Successfully sent packet after rebuild workaround.")
                except Exception as rebuild_err:
                    self.stats["rebuild_failure"] += 1
                    logger.error(f"Rebuild workaround failed: {rebuild_err}")
                    raise rebuild_err # Re-raise the error after logging failure
            else:
                # Re-raise other send errors
                raise send_err

    def _handle_interceptor_error(self, error: Exception):
        """处理来自拦截器的错误"""
        # Log the error, potentially update stats or trigger recovery
        logger.error(f"Received error from PacketInterceptor: {error}")
        self.stats["errors"] += 1
        # Add more sophisticated error handling if needed

    def _get_packet_from_pool(self) -> Optional[pydivert.Packet]:
        """从对象池获取数据包对象 (如果启用)"""
        if self.settings.get('use_packet_pool', True) and self.packet_pool:
            try:
                return self.packet_pool.pop()
            except IndexError:
                return None # Pool was empty
        return None

    def _return_packet_to_pool(self, packet: pydivert.Packet):
        """将数据包对象返回到对象池 (如果启用且未满)"""
        if self.settings.get('use_packet_pool', True) and len(self.packet_pool) < self.max_pool_size:
            # Optional: Reset packet state if necessary before pooling
            # if hasattr(packet, '_cached_properties'):
            #     packet._cached_properties.clear()
            self.packet_pool.append(packet)

    def get_stats(self) -> Dict:
        """获取当前的统计信息"""
        current_stats = self.stats.copy()
        total_processed = current_stats["passed"] + current_stats["dropped"]
        if total_processed > 0:
            current_stats["error_rate"] = current_stats["errors"] / total_processed
        else:
            current_stats["error_rate"] = 0.0
        # Add queue size if using queue model
        if self.settings.get('use_queue_model', False):
             current_stats["queue_size"] = self.packet_queue.qsize()
        return current_stats
