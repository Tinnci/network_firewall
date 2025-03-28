#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import time
import threading
import ipaddress
import logging
import platform
import subprocess
import queue
import psutil
import re
from typing import List, Dict, Set, Tuple, Optional, Union, Callable

import pydivert
from ctypes import c_void_p, create_string_buffer, memmove

# Get logger instance (configuration should happen elsewhere, e.g., firewall.py or main.py)
logger = logging.getLogger('PacketFilter')
# Set default level for this specific logger if needed, but basicConfig is avoided
# logger.setLevel(logging.DEBUG) 

class PacketFilter:
    """数据包过滤器核心类"""
    
    def __init__(self):
        """初始化过滤器"""
        self.running = False
        self.thread = None
        self.divert = None
        
        # 系统信息日志标识，防止重复记录
        self.system_info_logged = False
        
        # 记录系统信息和WinDivert状态，帮助诊断问题
        self._log_system_info()
        
        # 过滤规则
        self.ip_blacklist: Set[str] = set()
        self.ip_whitelist: Set[str] = set()
        self.port_blacklist: Set[str] = set() # Changed to Set[str] for ranges
        self.port_whitelist: Set[str] = set() # Changed to Set[str] for ranges
        self.protocol_filter = {"tcp": True, "udp": True}
        self.content_filters: List[str] = []
        self.compiled_filters = []  # 预编译的正则表达式
        
        # 数据包处理队列
        self.packet_queue = queue.Queue(maxsize=1000)
        self.worker_threads = []
        self.num_workers = 2  # 工作线程数
        
        # 数据包对象池
        self.packet_pool = []
        self.MAX_POOL_SIZE = 100
        
        # 统计信息
        self.stats = {
            "total_packets": 0,
            "dropped_packets": 0,
            "passed_packets": 0,
            "last_packet_time": 0,
            "error_packets": 0,      # 发生错误的数据包计数
            "win_error_87_count": 0, # WinError 87 特定错误计数
            "local_packets_skipped": 0,  # 跳过处理的本地回环数据包
            "rebuild_success": 0,     # 重建数据包成功次数
            "rebuild_failure": 0,      # 重建数据包失败次数
            "batch_processed": 0,     # 批量处理的数据包数
        }
        
        # 错误跟踪
        self.error_tracking = {
            'last_errors': [],      # 最近的错误信息
            'error_types': {},      # 错误类型统计
            'problematic_hosts': {} # 主机IP及其引发的错误次数
        }
        
        # 自适应策略
        self.adaptive_settings = {
            'skip_local_packets': True,    # 跳过本地大数据包处理
            'skip_large_packets': False,   # 跳过所有大数据包
            'large_packet_threshold': 1460, # 大数据包阈值
            'batch_size': 5,              # 批量处理大小
            'batch_wait_time': 100,       # 批量等待时间(ms)
            'use_packet_pool': True,      # 是否使用对象池
            'allow_private_network': True, # 是否允许本地网络通信
        }
        
        # 数据包类型统计
        self.packet_type_stats = {
            'df_packets': 0,           # 带DF标志的数据包
            'large_packets': 0,        # 大型数据包（>1000字节）
            'local_packets': 0,        # 本地回环数据包
            'problematic_packets': 0,  # 识别为问题的数据包
            'batched_packets': 0,      # 批量处理的数据包
        }
        
        # 回调函数
        self.packet_callback: Optional[Callable] = None
        
        # 日志记录控制
        self.log_every_n_packets = 100  # 每N个数据包记录一次
        
        # 资源监控
        self.last_resource_check = 0
        self.resource_check_interval = 30  # 30秒检查一次
        
        logger.info("数据包过滤器初始化完成")
        
        # TODO: 添加配置文件加载功能，支持从配置文件初始化过滤器 (Lower Priority)
        # TODO: 添加流量分析模块，实现异常流量监测 (Lower Priority)
    
    def start(self):
        """启动数据包过滤"""
        if self.running:
            return
        
        logger.info("正在启动数据包过滤器...")
        
        # 仅在首次启动或系统信息未记录时记录系统信息
        if not self.system_info_logged:
            self._log_system_info()
        
        # 预编译内容过滤规则
        try:
            self.compiled_filters = [re.compile(pattern) for pattern in self.content_filters]
            logger.info(f"预编译了 {len(self.compiled_filters)} 个内容过滤规则。")
        except re.error as e:
             logger.error(f"内容过滤规则编译失败: {e} - 请检查规则格式。")
             # Decide if startup should fail or continue without content filtering
             # For now, continue without content filtering
             self.compiled_filters = []
        except Exception as e:
             logger.error(f"预编译内容过滤规则时发生未知错误: {e}")
             self.compiled_filters = []

        # 构建符合WinDivert语法的过滤器字符串
        filter_string = "tcp or udp"
        
        try:
            # 验证过滤器语法正确性 - 使用PyDivert API标准方法
            check_result = pydivert.WinDivert.check_filter(filter_string)
            if not check_result[0]:
                logger.error(f"过滤器语法错误: {check_result[2]} 位置: {check_result[1]}")
                return False
            
            # 记录过滤器
            logger.debug(f"使用过滤规则: {filter_string}")
            
            # 创建WinDivert对象 - 按照API文档标准创建
            self.divert = pydivert.WinDivert(
                filter=filter_string,        # 过滤器字符串
                layer=pydivert.Layer.NETWORK # 在网络层拦截数据包
            )
            
            # 使用API打开WinDivert句柄
            self.divert.open()
            self.running = True
            
            # 配置WinDivert参数
            self._configure_windivert_params()
            
            # 记录启动信息
            logger.info("数据包过滤器已启动")
            logger.info(f"自适应策略配置: {self.adaptive_settings}")
            
            # 初始化统计时间
            self.stats["start_time"] = time.time()
            
            # 启动工作线程
            if self.adaptive_settings.get('use_queue_model', False):
                # 启动工作线程池处理队列中的数据包
                for i in range(self.num_workers):
                    worker = threading.Thread(target=self._packet_processor_worker)
                    worker.daemon = True
                    worker.start()
                    self.worker_threads.append(worker)
                logger.info(f"已启动 {self.num_workers} 个工作线程处理数据包")
            
            # 启动过滤线程
            self.thread = threading.Thread(target=self._packet_handler)
            self.thread.daemon = True
            self.thread.start()
            
            return True
        except Exception as e:
            logger.error(f"启动过滤器失败: {e}")
            self.running = False
            return False
            
        # TODO: 添加自动异常恢复机制 (Lower Priority)
        # TODO: 添加多网卡支持功能 (Lower Priority)
    
    def stop(self):
        """停止数据包过滤"""
        if not self.running:
            return True
            
        self.running = False
        logger.info("正在停止数据包过滤器...")
        
        # 关闭WinDivert句柄
        if self.divert:
            try:
                self.divert.close()
                logger.info("已关闭WinDivert句柄")
            except Exception as e:
                logger.error(f"关闭WinDivert句柄时出错: {e}")
            
        # 等待主处理线程结束
        if self.thread:
            self.thread.join(timeout=1.0)
            self.thread = None
            
        # 等待工作线程结束
        for worker in self.worker_threads:
            worker.join(timeout=0.5)
        self.worker_threads = []
        
        logger.info("数据包过滤器已停止")
        return True
    
    def _packet_handler(self):
        """数据包处理主循环"""
        error_count = 0
        error_limit = 50  # 最多记录50个错误
        consecutive_errors = 0  # 连续错误计数
        max_consecutive_errors = 10  # 最大连续错误数
        
        # 错误类型计数，避免同类错误重复记录
        error_type_counts = {}
        max_error_per_type = 5  # 每类错误最多记录5条
        
        logger.info("数据包处理线程已启动")
        
        while self.running:
            try:
                # 检查系统资源
                self._monitor_resources()
                
                # 决定是单包接收还是批量接收
                if self.adaptive_settings.get('use_batch_mode', True):
                    # 批量接收数据包
                    try:
                        # 使用Divert1.3的批量接收功能
                        batch_size = self.adaptive_settings['batch_size']
                        wait_time = self.adaptive_settings['batch_wait_time']
                        
                        # 实现批量接收
                        packets = []
                        start_time = time.time()
                        while len(packets) < batch_size and (time.time() - start_time) * 1000 < wait_time:
                            try:
                                packet = self.divert.recv(timeout=int(wait_time / batch_size))
                                if packet:
                                    packets.append(packet)
                            except Exception as recv_err:
                                if "timeout" in str(recv_err).lower():
                                    # 超时是正常的，继续收集
                                    continue
                                else:
                                    # 其他错误需要记录
                                    logger.error(f"批量接收数据包时出错: {recv_err}")
                                    break
                                    
                        # 处理收集到的数据包
                        if packets:
                            logger.debug(f"批量接收到 {len(packets)} 个数据包")
                            self.stats["batch_processed"] += len(packets)
                            self.packet_type_stats['batched_packets'] += len(packets)
                            
                            for packet in packets:
                                self._process_single_packet(packet, error_count, error_limit, consecutive_errors)
                                consecutive_errors = 0  # 成功处理后重置连续错误计数
                    except Exception as batch_err:
                        logger.error(f"批量处理过程出错: {batch_err}")
                        # 出错时退回到单包处理模式
                        self.adaptive_settings['use_batch_mode'] = False
                        logger.warning("已禁用批量处理模式，切换到单包处理")
                else:
                    # 单包接收和处理
                    packet = self.divert.recv()
                    self._process_single_packet(packet, error_count, error_limit, consecutive_errors)
                    consecutive_errors = 0  # 成功处理后重置连续错误计数
                
                # 周期性检查和调整策略
                if self.stats["total_packets"] % 1000 == 0:
                    self._adjust_adaptive_settings()
                    self._adjust_logging_level()
                
            except Exception as e:
                if self.running:  # 只有在运行状态才打印错误
                    consecutive_errors += 1
                    
                    # 错误类型统计和日志控制
                    error_type = type(e).__name__
                    if error_type not in error_type_counts:
                        error_type_counts[error_type] = 0
                    error_type_counts[error_type] += 1
                    
                    if error_type_counts[error_type] <= max_error_per_type:
                        # 只打印前几次错误，避免日志爆炸
                        logger.error(f"处理数据包时出错: {e}")
                    elif error_type_counts[error_type] == max_error_per_type + 1:
                        # 第max_error_per_type+1次报错时，提示后续错误将被抑制
                        logger.warning(f"错误类型 {error_type} 已达到最大记录次数，后续相同错误将被抑制")
                    elif error_type_counts[error_type] % 100 == 0:
                        # 每100次报错提示一次当前计数
                        logger.warning(f"错误类型 {error_type} 已发生 {error_type_counts[error_type]} 次")
                    
                    # 连续错误过多时考虑重启服务
                    if consecutive_errors > max_consecutive_errors * 2:
                        logger.critical(f"检测到过多连续错误({consecutive_errors}个)，尝试重启WinDivert")
                        self._restart_windivert()
                        consecutive_errors = 0  # 重启后重置错误计数
                        
                    # 暂停一小段时间，避免错误循环消耗CPU
                    time.sleep(0.1)
                    
        # TODO: 添加更智能的错误处理机制 (Lower Priority)
        # TODO: 添加错误自动恢复策略 (Lower Priority)
    
    def _process_single_packet(self, packet, error_count, error_limit, consecutive_errors):
        """处理单个数据包的主逻辑"""
        self.stats["total_packets"] += 1
        self.stats["last_packet_time"] = time.time()
        
        # 记录数据包信息（仅记录部分数据包，避免日志过大）
        if self.stats["total_packets"] % self.log_every_n_packets == 0:
            packet_info = self._get_packet_info(packet)
            logger.debug(f"接收到第 {self.stats['total_packets']} 个数据包: {packet_info}")
        
        # 进行对象指针检查
        if hasattr(packet, 'raw') and hasattr(packet.raw, '_obj'):
            ptr = c_void_p(packet.raw._obj)
            if ptr.value is None:
                logger.warning("检测到空指针数据包，跳过处理")
                self.stats["error_packets"] += 1
                return
        
        # 判断是否应该放行此数据包
        should_pass = self._should_pass_packet(packet)
        
        if self.adaptive_settings.get('use_queue_model', False):
            # 使用队列模型时，将数据包放入队列由工作线程处理
            try:
                self.packet_queue.put((packet, should_pass), block=False)
            except queue.Full:
                # 队列已满，直接处理
                logger.warning("数据包队列已满，直接处理")
                self._process_packet_action(packet, should_pass)
        else:
            # 直接处理数据包
            self._process_packet_action(packet, should_pass)

    def _packet_processor_worker(self):
        """工作线程函数，从队列中获取和处理数据包"""
        logger.info(f"数据包处理工作线程已启动: {threading.current_thread().name}")
        
        while self.running:
            try:
                # 从队列获取数据包
                packet, should_pass = self.packet_queue.get(timeout=0.5)
                
                # 处理数据包
                self._process_packet_action(packet, should_pass)
                
                # 标记任务完成
                self.packet_queue.task_done()
            except queue.Empty:
                # 队列为空，继续等待
                continue
            except Exception as e:
                logger.error(f"工作线程处理数据包出错: {e}")
                # 继续处理下一个，不要让一个错误停止线程
                continue
    
    def _process_packet_action(self, packet, should_pass):
        """处理数据包的具体动作（发送或丢弃）"""
        try:
            # 处理数据包
            if should_pass:
                self._send_packet_safe(packet)
            else:
                # 丢弃数据包
                self.stats["dropped_packets"] += 1
            
            # 回调通知
            if self.packet_callback:
                self.packet_callback(packet, should_pass)
                
            # 记录统计数据
            if self.stats["total_packets"] % 5000 == 0:
                logger.info(f"数据包类型分布 - DF标志: {self.packet_type_stats['df_packets']}, "
                            f"大型数据包: {self.packet_type_stats['large_packets']}, "
                            f"本地回环: {self.packet_type_stats['local_packets']}, "
                            f"问题数据包: {self.packet_type_stats['problematic_packets']}, "
                            f"批量处理: {self.packet_type_stats['batched_packets']}")
        except Exception as e:
            self.stats["error_packets"] += 1
            self._handle_error(e, "处理数据包动作时出错")
    
    def _send_packet_safe(self, packet):
        """安全发送数据包，包含错误处理和重试逻辑"""
        try:
            # 记录本地回环TCP数据包的详细信息，辅助调试
            is_local_tcp = (
                packet.tcp is not None and 
                hasattr(packet, 'src_addr') and hasattr(packet, 'dst_addr') and
                packet.src_addr == '127.0.0.1' and packet.dst_addr == '127.0.0.1'
            )
            
            # 特殊处理本地回环TCP大数据包
            if is_local_tcp and hasattr(packet, 'payload') and packet.payload and len(packet.payload) > 1000:
                # 只记录统计，不实际发送 - 本地回环流量不处理也能正常通信
                logger.info(f"跳过处理本地回环大型TCP数据包: src_port={packet.src_port}, dst_port={packet.dst_port}, size={len(packet.payload)}")
                self.stats["passed_packets"] += 1
                self.stats["local_packets_skipped"] += 1
                return
            
            # 根据自适应策略处理大数据包
            if (self.adaptive_settings['skip_large_packets'] and 
                hasattr(packet, 'payload') and packet.payload and 
                len(packet.payload) > self.adaptive_settings['large_packet_threshold']):
                logger.info(f"根据自适应策略跳过处理大型数据包: size={len(packet.payload)}")
                self.stats["passed_packets"] += 1
                return
            
            # 验证数据包有效性
            if not self._validate_packet(packet):
                logger.warning("数据包验证失败，跳过发送")
                self.stats["error_packets"] += 1
                return
            
            # 简化的数据包处理逻辑
            try:
                # 根据数据包类型决定是否重新计算校验和
                recalc_checksum = True
                
                # 本地回环数据包无需重新计算校验和
                if hasattr(packet, 'is_loopback') and packet.is_loopback:
                    recalc_checksum = False
                
                # 重新计算校验和
                if recalc_checksum and hasattr(packet, 'recalculate_checksums'):
                    try:
                        packet.recalculate_checksums()
                    except Exception as chksum_err:
                        logger.warning(f"重新计算校验和失败: {chksum_err}")
                
                # 使用标准API发送数据包
                self.divert.send(packet, recalculate_checksum=recalc_checksum)
                self.stats["passed_packets"] += 1
                
            except Exception as send_err:
                # 处理WinError 87错误 - 简化错误处理逻辑
                if "[WinError 87]" in str(send_err) and hasattr(packet, 'raw'):
                    logger.warning("检测到WinError 87参数错误，尝试使用重建数据包方式规避")
                    try:
                        # 创建新的数据包对象
                        new_packet = pydivert.Packet(
                            packet.raw,
                            packet.interface,
                            packet.direction
                        )
                        # 发送新数据包，不重新计算校验和
                        self.divert.send(new_packet, recalculate_checksum=False)
                        self.stats["passed_packets"] += 1
                        self.stats["rebuild_success"] += 1
                    except Exception as rebuild_err:
                        # 记录重建失败并增加统计
                        self.stats["rebuild_failure"] += 1
                        logger.error(f"重建并发送数据包失败: {rebuild_err}")
                        # 将错误向上传递
                        raise rebuild_err
                else:
                    # 非WinError 87错误直接抛出
                    raise send_err
                    
        except Exception as e:
            # 错误统计
            if "[WinError 87]" in str(e):
                self.stats["win_error_87_count"] += 1
            
            # 更新问题主机统计
            if hasattr(packet, 'src_addr') and hasattr(packet, 'dst_addr'):
                for ip in [packet.src_addr, packet.dst_addr]:
                    if ip not in self.error_tracking['problematic_hosts']:
                        self.error_tracking['problematic_hosts'][ip] = 1
                    else:
                        self.error_tracking['problematic_hosts'][ip] += 1
            
            # 保存最近错误
            if len(self.error_tracking['last_errors']) < 5:
                self.error_tracking['last_errors'].append(str(e))
            
            # 记录详细数据包信息
            self._log_detailed_packet_info(packet)
                
            # 抛出错误让上层处理
            raise e
    
    def _send_with_aligned_buffer(self, packet, recalculate_checksum=True):
        """使用内存对齐的缓冲区发送数据包，避免WinError 87"""
        # 创建字节对齐的缓冲区
        aligned_buff = create_string_buffer(len(packet.raw))
        
        # 拷贝数据到新缓冲区
        if hasattr(packet.raw, 'tobytes'):
            # memoryview或bytearray
            memmove(aligned_buff, packet.raw.tobytes(), len(packet.raw))
        else:
            # bytes或其他类型
            memmove(aligned_buff, packet.raw, len(packet.raw))
        
        # 创建新的数据包对象
        from pydivert import Packet
        new_packet = Packet(
            aligned_buff.raw[:len(packet.raw)],
            packet.interface,
            packet.direction
        )
        
        # 发送新数据包
        self.divert.send(new_packet, recalculate_checksum=recalculate_checksum)
    
    def _validate_packet(self, packet):
        """验证数据包完整性和有效性"""
        if not packet or not hasattr(packet, 'raw'):
            return False
        
        # 检查基本大小
        if len(packet.raw) < 20:
            return False
        
        # 验证IP头部
        if hasattr(packet, 'ip') and packet.ip:
            # 检查协议版本
            if hasattr(packet.ip, 'version'):
                version = packet.ip.version
                if version != 4 and version != 6:
                    return False
        
        # 检查端口有效性
        if hasattr(packet, 'src_port') and packet.src_port is not None:
            if packet.src_port < 0 or packet.src_port > 65535:
                return False
                
        if hasattr(packet, 'dst_port') and packet.dst_port is not None:
            if packet.dst_port < 0 or packet.dst_port > 65535:
                return False
        
        return True
    
    def _monitor_resources(self):
        """监控系统资源使用情况"""
        current_time = time.time()
        if current_time - self.last_resource_check < self.resource_check_interval:
            return
            
        self.last_resource_check = current_time
        
        try:
            # 获取CPU和内存使用情况
            cpu_percent = psutil.cpu_percent(interval=None)
            memory_info = psutil.virtual_memory()
            
            # 记录资源使用情况
            if cpu_percent > 80 or memory_info.percent > 90:
                logger.warning(f"系统资源紧张: CPU {cpu_percent}%, 内存 {memory_info.percent}%")
                
                # 根据资源情况调整处理策略
                if cpu_percent > 90:
                    # CPU使用率过高，降低处理负载
                    self.adaptive_settings['batch_size'] = max(1, self.adaptive_settings.get('batch_size', 5) - 1)
                    self.adaptive_settings['skip_large_packets'] = True
                    logger.info(f"CPU使用率过高，调整批处理大小为{self.adaptive_settings['batch_size']}，开启跳过大数据包")
                    
            # 记录正常资源使用情况
            elif self.stats["total_packets"] % 10000 == 0:
                logger.info(f"系统资源使用: CPU {cpu_percent}%, 内存 {memory_info.percent}%")
                
        except Exception as e:
            logger.error(f"监控系统资源时出错: {e}")
            
        # TODO: 添加自动资源优化功能 (Lower Priority)
        # TODO: 添加在资源超限时自动降级处理机制 (Lower Priority)
    
    def _adjust_logging_level(self):
        """基于错误率自适应调整日志级别"""
        if self.stats["total_packets"] < 1000:
            return
            
        error_rate = self.stats["error_packets"] / self.stats["total_packets"]
        
        # 根据错误率调整日志级别
        if error_rate > 0.1:  # 错误率超过10%
            logging.getLogger('PacketFilter').setLevel(logging.DEBUG)
            self.log_every_n_packets = 10  # 更频繁地记录
            logger.info(f"错误率较高({error_rate:.2%})，调整为DEBUG级别日志，每10个包记录一次")
        elif error_rate < 0.01:  # 错误率低于1%
            logging.getLogger('PacketFilter').setLevel(logging.INFO)
            self.log_every_n_packets = 500  # 减少日志频率
            logger.info(f"错误率较低({error_rate:.2%})，调整为INFO级别日志，每500个包记录一次")
    
    def _get_packet_info(self, packet) -> str:
        """获取数据包的基本信息"""
        try:
            info = {}
            
            # 基本信息
            if hasattr(packet, 'src_addr'):
                info['src_addr'] = packet.src_addr
            if hasattr(packet, 'dst_addr'):
                info['dst_addr'] = packet.dst_addr
            if hasattr(packet, 'src_port'):
                info['src_port'] = packet.src_port
            if hasattr(packet, 'dst_port'):
                info['dst_port'] = packet.dst_port
                
            # 协议信息
            info['tcp'] = packet.tcp is not None
            info['udp'] = packet.udp is not None
            
            # 数据包大小
            if hasattr(packet, 'payload'):
                info['payload_size'] = len(packet.payload) if packet.payload else 0
                
            return str(info)
        except Exception as e:
            return f"无法获取数据包信息: {e}"
    
    def _log_detailed_packet_info(self, packet):
        """记录详细的数据包信息，用于诊断参数错误"""
        try:
            logger.debug("详细数据包信息记录开始 ======")
            
            # 检查基本属性
            logger.debug(f"数据包类型: {type(packet)}")
            logger.debug(f"数据包属性: {dir(packet)}")
            
            # 检查IP层属性
            if hasattr(packet, 'ip'):
                logger.debug(f"IP层: {packet.ip}")
                if packet.ip:
                    logger.debug(f"IP层属性: {dir(packet.ip)}")
                    
                    # 检查IP头部特殊标志
                    if hasattr(packet.ip, 'flags'):
                        logger.debug(f"IP标志: {packet.ip.flags}")
                    if hasattr(packet.ip, 'df'):
                        logger.debug(f"DF标志: {packet.ip.df}")
                    if hasattr(packet.ip, 'mf'):
                        logger.debug(f"MF标志: {packet.ip.mf}")
                    if hasattr(packet.ip, 'fragment'):
                        logger.debug(f"分片标志: {packet.ip.fragment}")
            
            # 检查TCP/UDP属性
            if hasattr(packet, 'tcp') and packet.tcp:
                logger.debug(f"TCP层: {packet.tcp}")
                logger.debug(f"TCP层属性: {dir(packet.tcp)}")
                
                # 检查TCP标志
                tcp_flags = []
                for flag in ['syn', 'ack', 'fin', 'rst', 'psh', 'urg', 'ece', 'cwr']:
                    if hasattr(packet.tcp, flag) and getattr(packet.tcp, flag):
                        tcp_flags.append(flag.upper())
                logger.debug(f"TCP标志: {' '.join(tcp_flags)}")
            
            if hasattr(packet, 'udp') and packet.udp:
                logger.debug(f"UDP层: {packet.udp}")
                logger.debug(f"UDP层属性: {dir(packet.udp)}")
            
            # 检查方向和接口
            if hasattr(packet, 'direction'):
                logger.debug(f"方向: {'入站' if packet.direction == 1 else '出站'}")
            if hasattr(packet, 'interface'):
                logger.debug(f"接口: {packet.interface}")
            
            # 检查原始数据
            if hasattr(packet, 'raw'):
                logger.debug(f"原始数据大小: {len(packet.raw)}")
                # 检查内存指针
                if hasattr(packet.raw, '_obj'):
                    ptr = c_void_p(packet.raw._obj)
                    logger.debug(f"内存指针: {ptr.value}")
            
            # 检查有效载荷
            if hasattr(packet, 'payload') and packet.payload:
                payload_len = len(packet.payload)
                logger.debug(f"载荷大小: {payload_len}")
                if payload_len > 0:
                    # 只显示前20字节，避免日志过大
                    hex_preview = ' '.join([f'{b:02x}' for b in packet.payload[:20]])
                    logger.debug(f"载荷预览(前20字节): {hex_preview}")
                    
                    # 尝试解码为文本
                    try:
                        text_preview = packet.payload[:100].decode('utf-8', errors='replace')
                        logger.debug(f"载荷文本预览: {text_preview}")
                    except:
                        pass
            
            logger.debug("详细数据包信息记录结束 ======")
        except Exception as e:
            logger.error(f"记录详细数据包信息时出错: {e}")
    
    def _should_pass_packet(self, packet) -> bool:
        """根据过滤规则判断是否应该放行数据包
        
        Args:
            packet: 数据包对象
            
        Returns:
            bool: 是否放行
        """
        try:
            # 基本有效性检查
            if not hasattr(packet, 'tcp') and not hasattr(packet, 'udp'):
                logger.warning("发现无效数据包(缺少tcp/udp属性)，默认放行")
                return True
            
            # 检查是否为可能导致错误的数据包类型
            if self._is_problematic_packet(packet):
                logger.info("检测到可能导致问题的数据包类型，默认放行")
                return True
                
            # 协议过滤
            if packet.tcp is not None and not self.protocol_filter.get("tcp", True):
                return False
            
            if packet.udp is not None and not self.protocol_filter.get("udp", True):
                return False
            
            # 检查IP地址是否有效
            if not hasattr(packet, 'src_addr') or not hasattr(packet, 'dst_addr'):
                return True
                
            # IP地址过滤
            src_ip = packet.src_addr
            dst_ip = packet.dst_addr
            
            # 检查是否为私有IP地址
            try:
                src_is_private = self._is_private_ip(src_ip)
                dst_is_private = self._is_private_ip(dst_ip)
                
                # 根据策略处理私有IP
                if self.adaptive_settings.get('allow_private_network', True) and src_is_private and dst_is_private:
                    # 两端都是私有IP，允许本地网络通信
                    if self.stats["total_packets"] % 1000 == 0:
                        logger.debug(f"允许本地网络通信: {src_ip} -> {dst_ip}")
                    return True
            except Exception as ip_err:
                logger.debug(f"检查私有IP时出错: {ip_err}")
            
            # 白名单优先级高于黑名单
            if self.ip_whitelist:
                if src_ip in self.ip_whitelist or dst_ip in self.ip_whitelist:
                    return True
                    
                # 增加对CIDR格式的支持
                for whitelist_ip in self.ip_whitelist:
                    if '/' in whitelist_ip:  # CIDR格式
                        try:
                            cidr_net = ipaddress.ip_network(whitelist_ip, strict=False)
                            if (ipaddress.ip_address(src_ip) in cidr_net or 
                                ipaddress.ip_address(dst_ip) in cidr_net):
                                return True
                        except Exception as cidr_err:
                            logger.debug(f"CIDR白名单检查出错: {cidr_err}")
                    
            # 黑名单过滤    
            if self.ip_blacklist:
                if src_ip in self.ip_blacklist or dst_ip in self.ip_blacklist:
                    return False
                
                # 增加对CIDR格式的支持
                for blacklist_ip in self.ip_blacklist:
                    if '/' in blacklist_ip:  # CIDR格式
                        try:
                            cidr_net = ipaddress.ip_network(blacklist_ip, strict=False)
                            if (ipaddress.ip_address(src_ip) in cidr_net or 
                                ipaddress.ip_address(dst_ip) in cidr_net):
                                return False
                        except Exception as cidr_err:
                            logger.debug(f"CIDR黑名单检查出错: {cidr_err}")
            
            # 检查端口是否有效
            src_port = packet.src_port if hasattr(packet, 'src_port') else None
            dst_port = packet.dst_port if hasattr(packet, 'dst_port') else None
            if src_port is None or dst_port is None:
                return True # Cannot filter if ports are missing
                
            # 端口过滤 (Handles ranges)
            # 白名单优先级高于黑名单
            if self.port_whitelist:
                 # Check if either source or destination port matches any whitelist rule
                if self._check_port_rules(src_port, self.port_whitelist) or \
                   self._check_port_rules(dst_port, self.port_whitelist):
                    # logger.debug(f"端口 {src_port} 或 {dst_port} 在白名单中，放行")
                    return True
                    
            # 黑名单过滤    
            if self.port_blacklist:
                 # Check if either source or destination port matches any blacklist rule
                if self._check_port_rules(src_port, self.port_blacklist) or \
                   self._check_port_rules(dst_port, self.port_blacklist):
                    # logger.debug(f"端口 {src_port} 或 {dst_port} 在黑名单中，拦截")
                    return False
                    
            # 内容过滤 - 使用预编译的正则表达式提高效率
            if (self.content_filters or self.compiled_filters) and hasattr(packet, 'payload'):
                payload = packet.payload
                if payload:
                    # 转换为字符串以便于匹配
                    try:
                        payload_str = payload.decode('utf-8', errors='ignore')
                        
                        # 使用预编译的正则表达式
                        if self.compiled_filters:
                            for pattern in self.compiled_filters:
                                if pattern.search(payload_str):
                                    logger.debug(f"内容过滤匹配: {pattern.pattern}")
                                    return False
                        
                        # 兼容普通字符串匹配 (Removed as RuleManager now ensures strings)
                        # for filter_pattern in self.content_filters:
                        #     if isinstance(filter_pattern, str) and filter_pattern in payload_str:
                        #         logger.debug(f"内容过滤匹配: {filter_pattern}")
                        #         return False
                    except UnicodeDecodeError:
                        # 二进制数据解码失败，尝试作为二进制匹配 (Less common, keep?)
                        # logger.debug("Payload could not be decoded as UTF-8 for content filtering.")
                        pass # Or maybe try matching bytes if rules allow bytes?
                    except Exception as decode_err:
                        logger.debug(f"内容过滤解码出错: {decode_err}")
            
            # 默认放行
            return True
        except Exception as e:
            # 出现异常时，记录错误并默认放行
            logger.error(f"过滤数据包时出错: {e}")
            return True
            
        # TODO: 添加应用层协议过滤功能 (Lower Priority)
        # TODO: 添加按流量特征过滤功能 (Lower Priority)
        # TODO: 添加基于机器学习的异常行为检测功能 (Lower Priority)

    def _parse_port_rule(self, rule: str) -> Union[int, Tuple[int, int], None]:
        """解析端口规则字符串 (e.g., "80", "8000-8080")"""
        if '-' in rule:
            parts = rule.split('-')
            if len(parts) == 2:
                try:
                    start = int(parts[0])
                    end = int(parts[1])
                    if 0 <= start <= 65535 and 0 <= end <= 65535 and start <= end:
                        return (start, end)
                except ValueError:
                    pass
        else:
            try:
                port = int(rule)
                if 0 <= port <= 65535:
                    return port
            except ValueError:
                pass
        logger.warning(f"无法解析无效的端口规则: {rule}")
        return None

    def _check_port_rules(self, port: int, rules: Set[str]) -> bool:
        """检查端口是否匹配规则集 (包含单端口和范围)"""
        if not isinstance(port, int): # Ensure port is an integer
             return False
             
        for rule_str in rules:
            parsed_rule = self._parse_port_rule(rule_str)
            if isinstance(parsed_rule, int):
                # Single port rule
                if port == parsed_rule:
                    return True
            elif isinstance(parsed_rule, tuple):
                # Port range rule
                start, end = parsed_rule
                if start <= port <= end:
                    return True
        return False

    def _is_private_ip(self, ip_str):
        """判断IP是否为私有地址"""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private or ip.is_loopback
        except ValueError:
            return False
    
    def _is_problematic_packet(self, packet) -> bool:
        """检查是否为可能导致问题的数据包类型"""
        try:
            is_problematic = False
            
            # 检查本地回环流量
            if hasattr(packet, 'src_addr') and hasattr(packet, 'dst_addr'):
                # 从日志看，127.0.0.1上的TCP数据包特别容易出问题
                if packet.src_addr == '127.0.0.1' and packet.dst_addr == '127.0.0.1':
                    self.packet_type_stats['local_packets'] += 1
                    
                    # 本地回环数据包默认判断为问题数据包，不经过WinDivert处理
                    is_problematic = True
                    
                    # 特别注意payload较大的本地数据包
                    if hasattr(packet, 'payload') and packet.payload and len(packet.payload) > 1000:
                        logger.debug(f"检测到大于1000字节的本地回环数据包: {len(packet.payload)}字节")
                        self.packet_type_stats['large_packets'] += 1
            
            # 检查特殊情况：fragment包、无效头部等
            
            # 1. 检查分片包
            if hasattr(packet, 'ip') and packet.ip:
                # IPv4分片检查
                if hasattr(packet.ip, 'fragment') and packet.ip.fragment:
                    logger.debug("检测到IP分片数据包")
                    is_problematic = True
                
                # 检查Don't Fragment标记
                if hasattr(packet.ip, 'df') and packet.ip.df:
                    self.packet_type_stats['df_packets'] += 1
                    
                    if hasattr(packet, 'payload') and packet.payload and len(packet.payload) > 1000:
                        logger.debug("检测到带DF标志的大数据包")
                        self.packet_type_stats['large_packets'] += 1
                        is_problematic = True
                    
                # 检查特殊标记
                if hasattr(packet.ip, 'flags'):
                    # 记录标记值2可能是问题来源，但减少日志记录频率
                    if packet.ip.flags == 2:
                        # 这是DF(Don't Fragment)标记，在大型数据包上可能导致问题
                        # 只在特定条件下记录，避免日志过多
                        if self.stats["total_packets"] % 500 == 0:
                            logger.debug(f"检测到IP标记为2(DF)的数据包")
                        
                        # 只在大数据包上出现问题时才跳过
                        if hasattr(packet, 'payload') and packet.payload and len(packet.payload) > 1000:
                            self.packet_type_stats['large_packets'] += 1
                            is_problematic = True
            
            # 2. 检查数据包大小异常
            if hasattr(packet, 'raw'):
                # 过小的数据包
                if len(packet.raw) < 20:
                    logger.debug(f"数据包大小异常: {len(packet.raw)} 字节")
                    is_problematic = True
                # 接近MTU的数据包
                if 1450 <= len(packet.raw) <= 1500:
                    self.packet_type_stats['large_packets'] += 1
                    # 特别是来自回环接口且是TCP的
                    if hasattr(packet, 'is_loopback') and packet.is_loopback and packet.tcp:
                        logger.debug(f"检测到大小接近MTU的本地TCP数据包: {len(packet.raw)} 字节")
                        is_problematic = True
            
            # 3. 检查无效端口
            if (hasattr(packet, 'src_port') and packet.src_port is not None and 
                (packet.src_port < 0 or packet.src_port > 65535)):
                logger.debug(f"源端口无效: {packet.src_port}")
                is_problematic = True
                
            if (hasattr(packet, 'dst_port') and packet.dst_port is not None and 
                (packet.dst_port < 0 or packet.dst_port > 65535)):
                logger.debug(f"目标端口无效: {packet.dst_port}")
                is_problematic = True
            
            # 4. 检查特殊协议
            if not packet.tcp and not packet.udp:
                # 非TCP/UDP协议但通过了过滤器
                logger.debug("非TCP/UDP协议但通过了过滤器")
                is_problematic = True
            
            # 更新统计信息
            if is_problematic:
                self.packet_type_stats['problematic_packets'] += 1
                
            return is_problematic
        except Exception as e:
            logger.error(f"检查问题数据包时出错: {e}")
            # 如果检查过程出错，认为是问题数据包
            self.packet_type_stats['problematic_packets'] += 1
            return True
    
    def add_ip_to_blacklist(self, ip: str) -> bool:
        """添加IP到黑名单"""
        try:
            # 验证IP地址格式 (RuleManager should handle validation)
            # ipaddress.ip_address(ip)
            self.ip_blacklist.add(ip)
            return True
        except ValueError:
            return False
            
    def remove_ip_from_blacklist(self, ip: str) -> bool:
        """从黑名单移除IP"""
        if ip in self.ip_blacklist:
            self.ip_blacklist.remove(ip)
            return True
        return False
        
    def add_ip_to_whitelist(self, ip: str) -> bool:
        """添加IP到白名单"""
        try:
            # 验证IP地址格式 (RuleManager should handle validation)
            # ipaddress.ip_address(ip)
            self.ip_whitelist.add(ip)
            return True
        except ValueError:
            return False
            
    def remove_ip_from_whitelist(self, ip: str) -> bool:
        """从白名单移除IP"""
        if ip in self.ip_whitelist:
            self.ip_whitelist.remove(ip)
            return True
        return False
        
    def add_port_to_blacklist(self, port: str) -> bool: # Changed to str
        """添加端口到黑名单"""
        # Validation should be done by RuleManager
        self.port_blacklist.add(port)
        return True
            
    def remove_port_from_blacklist(self, port: str) -> bool: # Changed to str
        """从黑名单移除端口"""
        if port in self.port_blacklist:
            self.port_blacklist.remove(port)
            return True
        return False
        
    def add_port_to_whitelist(self, port: str) -> bool: # Changed to str
        """添加端口到白名单"""
        # Validation should be done by RuleManager
        self.port_whitelist.add(port)
        return True
            
    def remove_port_from_whitelist(self, port: str) -> bool: # Changed to str
        """从白名单移除端口"""
        if port in self.port_whitelist:
            self.port_whitelist.remove(port)
            return True
        return False
        
    def add_content_filter(self, pattern: str) -> bool:
        """添加内容过滤规则"""
        if pattern and pattern not in self.content_filters:
            self.content_filters.append(pattern)
            # Recompile filters immediately
            try:
                self.compiled_filters = [re.compile(p) for p in self.content_filters]
                logger.info(f"Recompiled content filters after adding: {pattern}")
            except re.error as e:
                 logger.error(f"Failed to recompile content filters after adding {pattern}: {e}")
                 # Optionally remove the invalid pattern again?
                 self.content_filters.remove(pattern)
                 return False
            return True
        return False
        
    def remove_content_filter(self, pattern: str) -> bool:
        """移除内容过滤规则"""
        if pattern in self.content_filters:
            self.content_filters.remove(pattern)
             # Recompile filters immediately
            try:
                self.compiled_filters = [re.compile(p) for p in self.content_filters]
                logger.info(f"Recompiled content filters after removing: {pattern}")
            except re.error as e:
                 # This shouldn't happen if they were valid before, but log just in case
                 logger.error(f"Failed to recompile content filters after removing {pattern}: {e}")
            return True
        return False
        
    def set_protocol_filter(self, protocol: str, enabled: bool) -> bool:
        """设置协议过滤"""
        if protocol.lower() in self.protocol_filter:
            self.protocol_filter[protocol.lower()] = enabled
            return True
        return False
        
    def get_stats(self) -> Dict:
        """获取统计信息"""
        # 添加错误率统计
        stats = self.stats.copy()
        
        total_processed = stats["passed_packets"] + stats["dropped_packets"]
        if total_processed > 0:
            stats["error_rate"] = stats["error_packets"] / total_processed
            
            # 记录一些实用的统计数据
            if self.stats["total_packets"] % 1000 == 0:
                logger.info(f"过滤器状态 - 总处理: {total_processed}, 放行: {stats['passed_packets']}, "
                            f"丢弃: {stats['dropped_packets']}, 错误: {stats['error_packets']}, "
                            f"错误率: {stats['error_rate']:.2%}")
                logger.info(f"跳过处理的本地数据包: {stats['local_packets_skipped']}, "
                            f"重建成功: {stats['rebuild_success']}, 重建失败: {stats['rebuild_failure']}")
        else:
            stats["error_rate"] = 0.0
            
        # 添加自适应策略状态
        stats["adaptive_settings"] = self.adaptive_settings.copy()
        
        # 添加Top 5错误主机
        if self.error_tracking['problematic_hosts']:
            top_hosts = sorted(
                self.error_tracking['problematic_hosts'].items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:5]
            stats["top_problematic_hosts"] = dict(top_hosts)
            
        return stats
        
    def register_packet_callback(self, callback: Callable):
        """注册数据包处理回调函数"""
        self.packet_callback = callback 

    def _adjust_adaptive_settings(self):
        """基于错误统计自动调整处理策略"""
        # 计算错误率
        total_processed = self.stats["passed_packets"] + self.stats["dropped_packets"]
        if total_processed == 0:
            return
            
        error_rate = self.stats["error_packets"] / total_processed
        
        # 检查WinError 87错误频率
        win_error_87_rate = 0
        if self.stats["error_packets"] > 0:
            win_error_87_rate = self.stats["win_error_87_count"] / self.stats["error_packets"]
            
        # 记录错误率信息
        if self.stats["total_packets"] % 1000 == 0:
            logger.info(f"错误统计 - 总错误率: {error_rate:.2%}, WinError 87比例: {win_error_87_rate:.2%}")
            
            # 如果WinError 87错误过多，考虑重启WinDivert实例
            if self.stats["win_error_87_count"] > 50 and win_error_87_rate > 0.5:
                logger.warning("检测到过多WinError 87错误，尝试重启WinDivert实例")
                # 尝试重启WinDivert实例
                self._restart_windivert()
            
            # 周期性执行系统诊断
            if self.stats["total_packets"] % 10000 == 0:
                self._diagnose_problem()
        
        # 如果错误率过高，调整策略
        if error_rate > 0.05:  # 超过5%
            logger.warning(f"错误率过高 ({error_rate:.2%})，调整处理策略")
            
            # 如果大部分错误是WinError 87，调整大数据包处理策略
            if self.stats["win_error_87_count"] > self.stats["error_packets"] * 0.8:
                if not self.adaptive_settings['skip_large_packets']:
                    self.adaptive_settings['skip_large_packets'] = True
                    logger.info("已开启跳过所有大数据包处理")
                    
                # 逐步降低大数据包阈值
                if self.adaptive_settings['large_packet_threshold'] > 1000:
                    self.adaptive_settings['large_packet_threshold'] -= 100
                    logger.info(f"已降低大数据包阈值至 {self.adaptive_settings['large_packet_threshold']} 字节")
        
        # 如果运行良好，可以尝试放宽限制
        elif error_rate < 0.01 and self.stats["total_packets"] > 10000:
            if self.adaptive_settings['skip_large_packets']:
                # 增加大数据包阈值
                if self.adaptive_settings['large_packet_threshold'] < 1460:
                    self.adaptive_settings['large_packet_threshold'] += 50
                    logger.info(f"已增加大数据包阈值至 {self.adaptive_settings['large_packet_threshold']} 字节")
                
                # 如果阈值足够高，可以取消完全跳过
                if self.adaptive_settings['large_packet_threshold'] >= 1460:
                    self.adaptive_settings['skip_large_packets'] = False
                    logger.info("已恢复处理大数据包")
        
        # 调整批处理大小
        if hasattr(self, 'stats') and 'batch_processed' in self.stats:
            batch_success_rate = self.stats["batch_processed"] / max(1, self.stats["total_packets"])
            
            if batch_success_rate > 0.95 and self.adaptive_settings['batch_size'] < 10:
                # 批处理成功率高，可以增加批量大小
                self.adaptive_settings['batch_size'] += 1
                logger.info(f"批处理成功率高，增加批处理大小至 {self.adaptive_settings['batch_size']}")
            elif batch_success_rate < 0.5 and self.adaptive_settings['batch_size'] > 2:
                # 批处理成功率低，减少批量大小
                self.adaptive_settings['batch_size'] -= 1
                logger.info(f"批处理成功率低，减少批处理大小至 {self.adaptive_settings['batch_size']}")

    def _restart_windivert(self):
        """尝试重启WinDivert以恢复正常运行"""
        logger.info("尝试重启WinDivert...")
        try:
            # 1. 关闭当前实例
            if self.divert:
                try:
                    self.divert.close()
                    logger.info("成功关闭当前WinDivert实例")
                except Exception as e:
                    logger.warning(f"关闭WinDivert实例时出错: {e}")
                
            # 2. 短暂等待系统资源释放
            time.sleep(1)
            
            # 3. 创建新实例，使用标准API参数
            filter_string = "tcp or udp"
            
            # 验证过滤器语法
            check_result = pydivert.WinDivert.check_filter(filter_string)
            if not check_result[0]:
                logger.error(f"重启时过滤器语法错误: {check_result[2]} 位置: {check_result[1]}")
                return False
            
            # 使用标准API创建WinDivert实例    
            self.divert = pydivert.WinDivert(
                filter=filter_string,
                layer=pydivert.Layer.NETWORK
            )
            logger.info("已创建新的WinDivert实例")
            
            # 4. 打开WinDivert句柄
            self.divert.open()
            logger.info("已成功打开WinDivert句柄")
            
            # 5. 重新配置参数
            self._configure_windivert_params()
            
            # 6. 重置错误计数
            self.stats["error_packets"] = 0
            self.stats["win_error_87_count"] = 0
            self.error_tracking = {
                'last_errors': [],
                'error_types': {},
                'problematic_hosts': {}
            }
            
            # 7. 调整自适应策略
            self._adjust_adaptive_settings()
            
            logger.info("WinDivert实例已成功重启")
            return True
        except Exception as e:
            logger.error(f"重启WinDivert失败: {e}")
            return False
    
    def _handle_error(self, error, context="未知上下文"):
        """统一错误处理和日志记录
        
        Args:
            error: 异常对象
            context: 错误发生的上下文描述
        """
        error_type = type(error).__name__
        error_msg = str(error)
        
        # 错误计数
        if error_type not in self.error_tracking['error_types']:
            self.error_tracking['error_types'][error_type] = 1
            log_level = logging.ERROR  # 第一次出现的错误用ERROR级别
        else:
            self.error_tracking['error_types'][error_type] += 1
            # 重复出现的错误降级为WARNING或DEBUG
            repeat_count = self.error_tracking['error_types'][error_type]
            if repeat_count <= 3:
                log_level = logging.WARNING
            elif repeat_count <= 10:
                log_level = logging.DEBUG
            elif repeat_count % 100 == 0:
                # 每100次记录一次统计
                log_level = logging.WARNING
                error_msg = f"{error_msg} (已重复出现{repeat_count}次)"
            else:
                # 其他情况不记录
                return
        
        # 记录错误
        if log_level == logging.ERROR:
            logger.error(f"{context}: {error_msg}")
        elif log_level == logging.WARNING:
            logger.warning(f"{context}: {error_msg}")
        elif log_level == logging.DEBUG:
            logger.debug(f"{context}: {error_msg}")
        
        # 保存最近的错误信息
        self.error_tracking['last_errors'].append({
            'time': time.time(),
            'type': error_type,
            'message': error_msg,
            'context': context
        })
        
        # 只保留最近的10条错误记录
        if len(self.error_tracking['last_errors']) > 10:
            self.error_tracking['last_errors'] = self.error_tracking['last_errors'][-10:]
        
        # 特殊处理WinError 87
        if "WinError 87" in error_msg:
            self.stats["win_error_87_count"] += 1
            
            # 如果WinError 87错误过多，考虑重启
            if self.stats["win_error_87_count"] >= 5 and self.stats["win_error_87_count"] % 5 == 0:
                logger.warning(f"检测到多次WinError 87错误({self.stats['win_error_87_count']}次)，将在下次出现时尝试重启WinDivert")
            
            if self.stats["win_error_87_count"] > 10:
                self._restart_windivert()
                self.stats["win_error_87_count"] = 0  # 重启后重置计数

    def _log_system_info(self):
        """记录系统信息和WinDivert状态，用于问题诊断"""
        if self.system_info_logged:
            # 如果已经记录过系统信息，则不再重复记录
            logger.debug("系统信息已记录，跳过重复记录")
            return
            
        try:
            # 记录系统信息
            logger.info("=" * 50)
            logger.info("系统信息:")
            logger.info(f"操作系统: {platform.platform()}")
            logger.info(f"Python版本: {platform.python_version()}")
            logger.info(f"处理器架构: {platform.architecture()}")
            
            # 记录PyDivert信息
            try:
                logger.info(f"PyDivert版本: {pydivert.__version__}")
            except:
                logger.warning("无法获取PyDivert版本信息")
                
            # 检查WinDivert驱动状态
            try:
                is_registered = pydivert.WinDivert.is_registered()
                logger.info(f"WinDivert驱动是否已注册: {is_registered}")
                
                # 尝试获取更多WinDivert驱动信息
                try:
                    # 使用subprocess执行sc命令查询服务信息
                    result = subprocess.run(['sc', 'query', 'WinDivert1.3'], 
                                            capture_output=True, 
                                            text=True, 
                                            timeout=3,
                                            encoding='utf-8', 
                                            errors='ignore')
                    if result.returncode == 0:
                        logger.info("WinDivert驱动服务状态:")
                        for line in result.stdout.splitlines():
                            if any(key in line for key in ['STATE', 'TYPE', 'START_TYPE', 'ERROR_CONTROL']):
                                logger.info(f"  {line.strip()}")
                    else:
                        logger.warning(f"查询WinDivert服务失败: {result.stderr}")
                except Exception as e:
                    logger.warning(f"获取WinDivert服务信息时出错: {e}")
                    
                # 检查DLL文件
                try:
                    from pydivert.windivert_dll import DLL_PATH
                    logger.info(f"WinDivert DLL路径: {DLL_PATH}")
                    if os.path.exists(DLL_PATH):
                        logger.info(f"DLL文件大小: {os.path.getsize(DLL_PATH)} 字节")
                        logger.info(f"DLL文件修改时间: {time.ctime(os.path.getmtime(DLL_PATH))}")
                    else:
                        logger.warning(f"DLL文件不存在: {DLL_PATH}")
                except Exception as e:
                    logger.warning(f"检查DLL文件时出错: {e}")
            except Exception as e:
                logger.warning(f"检查WinDivert状态时出错: {e}")
                
            logger.info("=" * 50)
            
            # 标记系统信息已记录
            self.system_info_logged = True
        except Exception as e:
            logger.error(f"记录系统信息时出错: {e}")
            # 即使出错也标记为已记录，避免连续多次记录失败
            self.system_info_logged = True

    def get_packet_from_pool(self):
        """从对象池获取一个数据包对象"""
        if self.adaptive_settings.get('use_packet_pool', True) and self.packet_pool:
            return self.packet_pool.pop()
        return None
    
    def return_packet_to_pool(self, packet):
        """将数据包对象返回到对象池"""
        if (self.adaptive_settings.get('use_packet_pool', True) and 
            len(self.packet_pool) < self.MAX_POOL_SIZE):
            # 清理对象，避免引用过多
            if hasattr(packet, '_cached_properties'):
                packet._cached_properties.clear()
            self.packet_pool.append(packet)
    
    def _diagnose_problem(self):
        """诊断WinDivert可能的问题并提供统计信息"""
        diagnosis = {
            'total_packets': self.stats.get('total_packets', 0),
            'passed_packets': self.stats.get('passed_packets', 0),
            'dropped_packets': self.stats.get('dropped_packets', 0),
            'error_packets': self.stats.get('error_packets', 0),
            'win_error_87_count': self.stats.get('win_error_87_count', 0),
            'packet_types': self.packet_type_stats,
            'error_types': self.error_tracking.get('error_types', {}),
            'windivert_status': 'normal',
            'recommendations': []
        }
        
        # 检查WinDivert是否注册
        try:
            is_registered = pydivert.WinDivert.is_registered()
            diagnosis['windivert_registered'] = is_registered
            if not is_registered:
                diagnosis['windivert_status'] = 'not_registered'
                diagnosis['recommendations'].append('注册WinDivert驱动')
        except Exception as e:
            diagnosis['windivert_status'] = 'unknown'
            diagnosis['error'] = str(e)
        
        # 检查WinError 87错误比例
        if self.stats.get('total_packets', 0) > 0:
            win87_ratio = self.stats.get('win_error_87_count', 0) / self.stats.get('total_packets', 0)
            diagnosis['win87_error_ratio'] = win87_ratio
            
            if win87_ratio > 0.1:  # 如果超过10%的数据包出现WinError 87
                diagnosis['windivert_status'] = 'problematic'
                diagnosis['recommendations'].append('尝试重启WinDivert驱动')
                diagnosis['recommendations'].append('更新PyDivert库版本')
        
        # 检查数据包处理成功率
        if self.stats.get('total_packets', 0) > 0:
            success_ratio = self.stats.get('passed_packets', 0) / self.stats.get('total_packets', 0)
            diagnosis['success_ratio'] = success_ratio
            
            if success_ratio < 0.5:  # 成功率低于50%
                diagnosis['recommendations'].append('检查数据包过滤规则')
                diagnosis['recommendations'].append('减少复杂过滤条件')
        
        # 根据统计分析提供建议
        if self.packet_type_stats.get('local_packets', 0) > self.stats.get('total_packets', 0) * 0.5:
            # 如果本地回环数据包比例过高
            diagnosis['recommendations'].append('考虑过滤掉本地回环数据包')
        
        if self.packet_type_stats.get('large_packets', 0) > self.stats.get('total_packets', 0) * 0.3:
            # 如果大型数据包比例过高
            diagnosis['recommendations'].append('考虑跳过处理大型数据包')
        
        return diagnosis
        
        # TODO: 添加自动修复建议功能 (Lower Priority)
        # TODO: 添加问题趋势分析功能 (Lower Priority)

    def _configure_windivert_params(self):
        """配置WinDivert参数，按照PyDivert API标准设置参数"""
        try:
            # 导入参数常量 - 使用API文档中定义的枚举类
            from pydivert import Param
            
            # 使用set_param方法设置参数值，按照API文档标准
            self.divert.set_param(Param.QUEUE_LEN, 8192)
            self.divert.set_param(Param.QUEUE_TIME, 2000)
            
            logger.info(f"已设置WinDivert队列长度为8192，队列时间为2000ms")
            
            # 验证参数设置是否成功
            self._validate_windivert_params()
                
        except Exception as e:
            logger.warning(f"配置WinDivert参数时发生错误: {e}")
            logger.info("将使用WinDivert默认参数配置")
            
    def _validate_windivert_params(self):
        """验证WinDivert参数是否设置成功"""
        try:
            from pydivert import Param
            
            # 获取当前参数值
            queue_len = self.divert.get_param(Param.QUEUE_LEN)
            queue_time = self.divert.get_param(Param.QUEUE_TIME)
            
            logger.debug(f"当前WinDivert参数: QUEUE_LEN={queue_len}, QUEUE_TIME={queue_time}")
                
        except Exception as e:
            logger.debug(f"验证WinDivert参数时发生错误: {e}")
            # 验证失败不影响程序运行
