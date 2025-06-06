#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import re
import ipaddress # Added import
import time # Added import
from typing import Dict, List, Set, Tuple # Added Tuple

import pydivert

# Import from local modules
from ..utils.network_utils import is_private_ip, parse_port_rule
from .. import constants as C # Import constants

# Get logger instance
logger = logging.getLogger('PacketAnalyzer')

class PacketAnalyzer:
    """负责分析数据包并根据规则决定是否放行"""

    def __init__(self):
        # Rules will be set externally
        self.ip_blacklist: Set[str] = set()
        self.ip_whitelist: Set[str] = set()
        self.port_blacklist: Set[str] = set()
        self.port_whitelist: Set[str] = set()
        self.protocol_filter: Dict[str, bool] = {C.PROTOCOL_TCP.lower(): True, C.PROTOCOL_UDP.lower(): True}
        self.content_filters: List[str] = []
        self.compiled_content_filters: List[re.Pattern] = []

        # Settings will be set externally
        self.allow_private_network: bool = True
        self.skip_local_packets: bool = True # Added setting

    def set_rules(self, rules: Dict):
        """更新分析器使用的规则"""
        self.ip_blacklist = rules.get('ip_blacklist', set())
        self.ip_whitelist = rules.get('ip_whitelist', set())
        self.port_blacklist = rules.get('port_blacklist', set())
        self.port_whitelist = rules.get('port_whitelist', set())
        self.protocol_filter = rules.get('protocol_filter', {C.PROTOCOL_TCP.lower(): True, C.PROTOCOL_UDP.lower(): True})
        self.content_filters = rules.get('content_filters', [])
        self._compile_content_filters()
        logger.debug("PacketAnalyzer rules updated.")

    def set_settings(self, settings: Dict):
        """更新分析器使用的设置"""
        self.allow_private_network = settings.get('allow_private_network', True)
        self.skip_local_packets = settings.get('skip_local_packets', True) # Update setting
        logger.debug(f"PacketAnalyzer settings updated: allow_private={self.allow_private_network}, skip_local={self.skip_local_packets}")

    def _compile_content_filters(self):
        """预编译内容过滤规则以提高效率"""
        self.compiled_content_filters = []
        invalid_patterns = []
        for pattern in self.content_filters:
            try:
                self.compiled_content_filters.append(re.compile(pattern.encode('utf-8'), re.IGNORECASE | re.DOTALL)) # Compile as bytes
            except re.error as e:
                logger.error(f"Invalid content filter regex '{pattern}': {e}")
                invalid_patterns.append(pattern)
            except Exception as e:
                 logger.error(f"Error compiling content filter '{pattern}': {e}")
                 invalid_patterns.append(pattern)
        
        # Optionally remove invalid patterns from the original list
        # for invalid in invalid_patterns:
        #     if invalid in self.content_filters:
        #         self.content_filters.remove(invalid)
                 
        logger.debug(f"Compiled {len(self.compiled_content_filters)} content filters.")

    def should_pass(self, packet: pydivert.Packet) -> Tuple[bool, str]:
        """
        根据当前规则和设置判断是否应放行此数据包。

        Args:
            packet: 要分析的数据包对象。

        Returns:
            Tuple[bool, str]: (True 表示放行，False 表示拦截, 原因字符串)。
        """
        # --- BEGIN CRITICAL DEBUG LOG ---
        logger.debug("--- ANALYZER STATE ON PACKET ---")
        logger.debug(f"IP Blacklist: {self.ip_blacklist}")
        logger.debug(f"IP Whitelist: {self.ip_whitelist}")
        logger.debug(f"Port Blacklist: {self.port_blacklist}")
        logger.debug(f"Port Whitelist: {self.port_whitelist}")
        logger.debug(f"Protocol Filter: {self.protocol_filter}")
        logger.debug(f"Content Filters (raw): {self.content_filters}")
        logger.debug(f"Content Filters (compiled count): {len(self.compiled_content_filters)}")
        logger.debug(f"Allow Private Network: {self.allow_private_network}")
        logger.debug(f"Skip Local Packets: {self.skip_local_packets}")
        packet_info_for_debug = self.get_packet_info(packet)
        logger.debug(f"Incoming Packet: Src={packet_info_for_debug.get('src_addr')}:{packet_info_for_debug.get('src_port')}, Dst={packet_info_for_debug.get('dst_addr')}:{packet_info_for_debug.get('dst_port')}, Protocol={packet_info_for_debug.get('protocol')}")
        logger.debug("--- END ANALYZER STATE ---")
        # --- END CRITICAL DEBUG LOG ---
        try:
            # 0. Skip Local Packets if configured
            # Check loopback status first as it's efficient
            if self.skip_local_packets and hasattr(packet, 'is_loopback') and packet.is_loopback:
                 # logger.debug("Skipping local loopback packet based on setting.")
                 return True, C.REASON_LOCAL_LOOPBACK_SKIPPED

            # 1. Basic Validity & Protocol Filter
            is_tcp = hasattr(packet, 'tcp') and packet.tcp is not None
            is_udp = hasattr(packet, 'udp') and packet.udp is not None

            if not is_tcp and not is_udp:
                logger.debug("Passing non-TCP/UDP packet.")
                return True, C.REASON_NON_TCP_UDP

            extracted_packet_info = self.get_packet_info(packet) # Renamed from packet_details_base

            logger.debug(f"PA_DEBUG: Checking Protocol Filter. is_tcp={is_tcp}, is_udp={is_udp}, filter={self.protocol_filter}")
            if is_tcp and not self.protocol_filter.get(C.PROTOCOL_TCP.lower(), True):
                action = C.ACTION_BLOCK
                reason = C.REASON_PROTOCOL_FILTER_TCP
                logger.debug(f"PA_DEBUG: Condition met for Protocol Filter TCP block. Reason: {reason}")
                logger.info(f"{action}动作: {reason}, 源IP: {extracted_packet_info.get('src_addr', 'N/A')}, 目标IP: {extracted_packet_info.get('dst_addr', 'N/A')}, 源端口: {extracted_packet_info.get('src_port', 'N/A')}, 目标端口: {extracted_packet_info.get('dst_port', 'N/A')}")
                return False, reason
            if is_udp and not self.protocol_filter.get(C.PROTOCOL_UDP.lower(), True):
                action = C.ACTION_BLOCK
                reason = C.REASON_PROTOCOL_FILTER_UDP
                logger.debug(f"PA_DEBUG: Condition met for Protocol Filter UDP block. Reason: {reason}")
                logger.info(f"{action}动作: {reason}, 源IP: {extracted_packet_info.get('src_addr', 'N/A')}, 目标IP: {extracted_packet_info.get('dst_addr', 'N/A')}, 源端口: {extracted_packet_info.get('src_port', 'N/A')}, 目标端口: {extracted_packet_info.get('dst_port', 'N/A')}")
                return False, reason

            # 2. IP Address Filtering
            src_ip = getattr(packet, 'src_addr', None)
            dst_ip = getattr(packet, 'dst_addr', None)

            if not src_ip or not dst_ip:
                logger.debug("Passing packet with missing IP address(es).")
                return True, C.REASON_MISSING_IP

            # Check for private network communication if allowed
            src_is_private = is_private_ip(src_ip)
            dst_is_private = is_private_ip(dst_ip)
            if self.allow_private_network and src_is_private and dst_is_private:
                # logger.debug(f"Allowing private network traffic: {src_ip} -> {dst_ip}")
                return True, C.REASON_PRIVATE_NETWORK_ALLOWED

            # Whitelist check (higher priority)
            logger.debug(f"PA_DEBUG: Checking IP Whitelist. Src IP: {src_ip}, Dst IP: {dst_ip}, Whitelist: {self.ip_whitelist}")
            is_src_whitelisted = self._check_ip_rules(src_ip, self.ip_whitelist)
            is_dst_whitelisted = self._check_ip_rules(dst_ip, self.ip_whitelist)
            logger.debug(f"PA_DEBUG: IP Whitelist check result: src_on_whitelist={is_src_whitelisted}, dst_on_whitelist={is_dst_whitelisted}")
            if is_src_whitelisted or is_dst_whitelisted:
                action = C.ACTION_ALLOW
                whitelisted_ip_for_reason = src_ip if is_src_whitelisted else dst_ip
                reason = f"{C.REASON_IP_WHITELIST} ({whitelisted_ip_for_reason})"
                # Optional: Log whitelisted packets if needed for debugging, but might be noisy
                # logger.debug(f"Packet {action}: {reason}", extra={'log_type': 'packet', 'packet_info': {**extracted_packet_info, 'action': action, 'reason': reason}})
                logger.debug(f"PA_DEBUG: Condition met for IP Whitelist pass. Reason: {reason}")
                return True, reason

            # Blacklist check
            logger.debug(f"PA_DEBUG: Checking IP Blacklist. Src IP: {src_ip}, Dst IP: {dst_ip}, Blacklist: {self.ip_blacklist}")
            is_src_blacklisted = self._check_ip_rules(src_ip, self.ip_blacklist)
            is_dst_blacklisted = self._check_ip_rules(dst_ip, self.ip_blacklist)
            logger.debug(f"PA_DEBUG: IP Blacklist check result: src_on_blacklist={is_src_blacklisted}, dst_on_blacklist={is_dst_blacklisted}")
            if is_src_blacklisted or is_dst_blacklisted:
                action = C.ACTION_BLOCK
                blocked_ip_for_reason = src_ip if is_src_blacklisted else dst_ip
                reason = f"{C.REASON_IP_BLACKLIST} ({blocked_ip_for_reason})"
                logger.debug(f"PA_DEBUG: Condition met for IP Blacklist block. Reason: {reason}")
                logger.info(f"{action}动作: {reason}, 命中IP: {blocked_ip_for_reason}, 源IP: {src_ip}, 目标IP: {dst_ip}, 源端口: {extracted_packet_info.get('src_port', 'N/A')}, 目标端口: {extracted_packet_info.get('dst_port', 'N/A')}, 协议: {extracted_packet_info.get('protocol', 'N/A')}")
                return False, reason

            # 3. Port Filtering
            src_port = getattr(packet, 'src_port', None)
            dst_port = getattr(packet, 'dst_port', None)

            if src_port is None or dst_port is None:
                # logger.debug("Passing packet with missing port(s).")
                return True, C.REASON_MISSING_PORT

            # --- MODIFICATION START: Port Whitelist Exclusivity ---
            has_port_whitelist = bool(self.port_whitelist)
            logger.debug(f"PA_DEBUG: Checking Port Whitelist Exclusivity. Src Port: {src_port}, Dst Port: {dst_port}, Whitelist: {self.port_whitelist}, HasWhitelist: {has_port_whitelist}")
            if has_port_whitelist:
                is_src_port_whitelisted = self._check_port_rules_single(src_port, self.port_whitelist)
                is_dst_port_whitelisted = self._check_port_rules_single(dst_port, self.port_whitelist)
                logger.debug(f"PA_DEBUG: Port Whitelist check result: src_on_whitelist={is_src_port_whitelisted}, dst_on_whitelist={is_dst_port_whitelisted}")

                if is_src_port_whitelisted or is_dst_port_whitelisted:
                    logger.debug("PA_DEBUG: Port is on active whitelist. Continuing checks.")
                    pass # Continue to other checks, specifically content or default pass
                else:
                    action = C.ACTION_BLOCK
                    reason = f"{C.REASON_PORT_NOT_IN_WHITELIST} (源: {src_port}, 目标: {dst_port})"
                    logger.debug(f"PA_DEBUG: Condition met for Port Not In Whitelist block. Reason: {reason}")
                    logger.info(f"{action}动作: {reason}, 源端口: {src_port}, 目标端口: {dst_port}, 源IP: {src_ip}, 目标IP: {dst_ip}, 协议: {extracted_packet_info.get('protocol', 'N/A')}")
                    return False, reason
            # --- MODIFICATION END ---

            # Whitelist check (original logic - this will now only be effectively hit if no whitelist is active or if port was on whitelist)
            # If a port whitelist is active and the packet's ports were NOT on it, we'd have returned False above.
            # If a port whitelist is active and packet's ports WERE on it, this check is redundant but harmless.
            # If no port whitelist is active, this check behaves as before.
            logger.debug(f"PA_DEBUG: Checking Port Whitelist (Standard). Src Port: {src_port}, Dst Port: {dst_port}, Whitelist: {self.port_whitelist}")
            is_src_on_standard_whitelist = self._check_port_rules_single(src_port, self.port_whitelist) # Using _single for consistency
            is_dst_on_standard_whitelist = self._check_port_rules_single(dst_port, self.port_whitelist)
            logger.debug(f"PA_DEBUG: Port Whitelist (Standard) check result: src_on_whitelist={is_src_on_standard_whitelist}, dst_on_whitelist={is_dst_on_standard_whitelist}")
            if is_src_on_standard_whitelist or is_dst_on_standard_whitelist:
                action = C.ACTION_ALLOW
                whitelisted_port_for_reason = src_port if is_src_on_standard_whitelist else dst_port
                reason = f"{C.REASON_PORT_WHITELIST} ({whitelisted_port_for_reason})"
                logger.debug(f"PA_DEBUG: Condition met for Port Whitelist (Standard) pass. Reason: {reason}")
                return True, reason

            # Blacklist check
            logger.debug(f"PA_DEBUG: Checking Port Blacklist. Src Port: {src_port}, Dst Port: {dst_port}, Blacklist: {self.port_blacklist}")
            is_src_port_blacklisted = self._check_port_rules_single(src_port, self.port_blacklist) # Using _single for consistency
            is_dst_port_blacklisted = self._check_port_rules_single(dst_port, self.port_blacklist)
            logger.debug(f"PA_DEBUG: Port Blacklist check result: src_on_blacklist={is_src_port_blacklisted}, dst_on_blacklist={is_dst_port_blacklisted}")

            if is_src_port_blacklisted or is_dst_port_blacklisted:
                action = C.ACTION_BLOCK
                blocked_port_for_reason = src_port if is_src_port_blacklisted else dst_port
                reason = f"{C.REASON_PORT_BLACKLIST} ({blocked_port_for_reason})"
                logger.debug(f"PA_DEBUG: Condition met for Port Blacklist block. Reason: {reason}")
                logger.info(f"{action}动作: {reason}, 命中端口: {blocked_port_for_reason}, 源IP: {src_ip}, 目标IP: {dst_ip}, 源端口: {src_port}, 目标端口: {dst_port}, 协议: {extracted_packet_info.get('protocol', 'N/A')}")
                return False, reason

            # 4. Content Filtering (using compiled regex on bytes)
            if self.compiled_content_filters and hasattr(packet, 'payload'):
                payload = packet.payload # This should be bytes
                if payload:
                    logger.debug(f"PA_DEBUG: Checking Content Filters. Num compiled_content_filters: {len(self.compiled_content_filters)}")
                    for pattern_idx, pattern in enumerate(self.compiled_content_filters):
                        try:
                            logger.debug(f"PA_DEBUG: Content Filter - trying pattern {pattern_idx+1}/{len(self.compiled_content_filters)}: {pattern.pattern.decode('utf-8', 'ignore')}")
                            if pattern.search(payload):
                                action = C.ACTION_BLOCK
                                pattern_str = pattern.pattern.decode('utf-8', 'ignore')
                                reason = f"{C.REASON_CONTENT_FILTER} ({pattern_str})"
                                logger.debug(f"PA_DEBUG: Condition met for Content Filter block. Reason: {reason}")
                                logger.info(f"{action}动作: {reason}, 规则: {pattern_str}, 源IP: {src_ip}, 目标IP: {dst_ip}, 源端口: {extracted_packet_info.get('src_port', 'N/A')}, 目标端口: {extracted_packet_info.get('dst_port', 'N/A')}, 协议: {extracted_packet_info.get('protocol', 'N/A')}")
                                return False, reason
                        except Exception as search_err:
                             logger.error(f"Error during content filter search with pattern '{pattern.pattern.decode('utf-8', 'ignore')}': {search_err}")


            # 5. Default Action: Pass
            # Log default passes only if debug level is very low, or not at all to reduce noise
            # action = "放行"
            # reason = "Default Action"
            # packet_details = {**packet_details_base, 'action': action, 'reason': reason}
            # logger.debug(f"Packet {action}: {reason}", extra={'log_type': 'packet', 'packet_info': packet_details})
            return True, C.REASON_DEFAULT_PASS

        except Exception as e:
            logger.error(f"Error analyzing packet: {e}", exc_info=True)
            return True, C.REASON_ANALYSIS_ERROR # Default to passing if analysis fails

    def _check_ip_rules(self, ip_to_check: str, rule_set: Set[str]) -> bool:
        """Checks if an IP address matches any rule in the given set (IPs or CIDRs)."""
        if ip_to_check in rule_set:
            return True
        try:
            ip_addr = ipaddress.ip_address(ip_to_check)
            for rule in rule_set:
                if '/' in rule: # Check CIDR rules
                    try:
                        if ip_addr in ipaddress.ip_network(rule, strict=False):
                            return True
                    except ValueError:
                        # Ignore invalid CIDR rules in the set during check
                        # logger.warning(f"Ignoring invalid CIDR rule during check: {rule}")
                        pass
        except ValueError:
             # logger.warning(f"Could not parse IP for rule check: {ip_to_check}")
             return False # Cannot check if IP is invalid
        return False

    # Added helper for single port check against a rule set for clarity in whitelist logic
    def _check_port_rules_single(self, port_to_check: int, rule_set: Set[str]) -> bool:
        """Checks if a single port matches any rule in the given set."""
        if port_to_check is None: # Should be caught earlier, but defensive
            return False
        for rule_entry in rule_set:
            parsed_rule = parse_port_rule(rule_entry)
            if isinstance(parsed_rule, int):
                if port_to_check == parsed_rule:
                    return True
            elif isinstance(parsed_rule, tuple):
                if parsed_rule[0] <= port_to_check <= parsed_rule[1]:
                    return True
        return False

    def _check_port_rules(self, port_to_check: int, rule_set: Set[str]) -> bool:
        """Checks if a port matches any rule in the given set (individual ports or ranges)."""
        # This existing function can be kept as is, or refactored if _check_port_rules_single is preferred everywhere
        # For now, the new whitelist logic uses _check_port_rules_single.
        # The original blacklist and whitelist (for pass) logic still uses this.
        if port_to_check is None:
            return False
        try: # Ensure port_to_check is an int
            port_to_check = int(port_to_check)
        except (ValueError, TypeError):
            logger.warning(f"_check_port_rules: port_to_check '{port_to_check}' is not a valid integer.")
            return False
            
        for rule_str in rule_set:
            parsed_rule = parse_port_rule(rule_str) # Use utility function
            if isinstance(parsed_rule, int):
                if port_to_check == parsed_rule:
                    return True
            elif isinstance(parsed_rule, tuple):
                start, end = parsed_rule
                if start <= port_to_check <= end:
                    return True
        return False

    def get_packet_info(self, packet: pydivert.Packet) -> Dict:
        """Extracts basic information from a packet."""
        info = {
            'timestamp': time.time(),
            'protocol': C.PROTOCOL_TCP if getattr(packet, 'tcp', None) else (C.PROTOCOL_UDP if getattr(packet, 'udp', None) else C.PROTOCOL_OTHER),
            'src_addr': getattr(packet, 'src_addr', 'N/A'),
            'dst_addr': getattr(packet, 'dst_addr', 'N/A'),
            'src_port': getattr(packet, 'src_port', 'N/A'),
            'dst_port': getattr(packet, 'dst_port', 'N/A'),
            'direction': 'inbound' if getattr(packet, 'direction', 0) == pydivert.Direction.INBOUND else 'outbound',
            'interface': getattr(packet, 'interface', 'N/A'),
            'payload_size': len(getattr(packet, 'payload', b'')),
            'is_loopback': getattr(packet, 'is_loopback', False)
        }
        # Add specific flags if needed (e.g., TCP flags)
        # if info['protocol'] == 'TCP' and packet.tcp:
        #     info['tcp_flags'] = {f: getattr(packet.tcp, f) for f in ['syn', 'ack', 'fin', 'rst', 'psh', 'urg'] if hasattr(packet.tcp, f)}
        return info
