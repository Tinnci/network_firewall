#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import re
import ipaddress # Added import
import time # Added import
from typing import Dict, List, Set

import pydivert

# Import from utils
from ..utils.network_utils import is_private_ip, parse_port_rule

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
        self.protocol_filter: Dict[str, bool] = {"tcp": True, "udp": True}
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
        self.protocol_filter = rules.get('protocol_filter', {"tcp": True, "udp": True})
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

    def should_pass(self, packet: pydivert.Packet) -> bool:
        """
        根据当前规则和设置判断是否应放行此数据包。

        Args:
            packet: 要分析的数据包对象。

        Returns:
            bool: True 表示放行，False 表示拦截。
        """
        try:
            # 0. Skip Local Packets if configured
            # Check loopback status first as it's efficient
            if self.skip_local_packets and hasattr(packet, 'is_loopback') and packet.is_loopback:
                 # logger.debug("Skipping local loopback packet based on setting.")
                 return True # Always pass loopback if skipping is enabled

            # 1. Basic Validity & Protocol Filter
            is_tcp = hasattr(packet, 'tcp') and packet.tcp is not None
            is_udp = hasattr(packet, 'udp') and packet.udp is not None

            if not is_tcp and not is_udp:
                logger.debug("Passing non-TCP/UDP packet.")
                return True # Pass non-TCP/UDP packets by default

            packet_details_base = self.get_packet_info(packet) # Get base info once

            if is_tcp and not self.protocol_filter.get("tcp", True):
                action = "拦截"
                reason = "Protocol Filter (TCP)"
                packet_details = {**packet_details_base, 'action': action, 'reason': reason}
                logger.debug(f"Packet {action}: {reason}", extra={'log_type': 'packet', 'packet_info': packet_details})
                return False
            if is_udp and not self.protocol_filter.get("udp", True):
                action = "拦截"
                reason = "Protocol Filter (UDP)"
                packet_details = {**packet_details_base, 'action': action, 'reason': reason}
                logger.debug(f"Packet {action}: {reason}", extra={'log_type': 'packet', 'packet_info': packet_details})
                return False

            # 2. IP Address Filtering
            src_ip = getattr(packet, 'src_addr', None)
            dst_ip = getattr(packet, 'dst_addr', None)

            if not src_ip or not dst_ip:
                logger.debug("Passing packet with missing IP address(es).")
                return True # Cannot filter without IPs

            # Check for private network communication if allowed
            src_is_private = is_private_ip(src_ip)
            dst_is_private = is_private_ip(dst_ip)
            if self.allow_private_network and src_is_private and dst_is_private:
                # logger.debug(f"Allowing private network traffic: {src_ip} -> {dst_ip}")
                return True

            # Whitelist check (higher priority)
            if self._check_ip_rules(src_ip, self.ip_whitelist) or self._check_ip_rules(dst_ip, self.ip_whitelist):
                action = "放行"
                reason = "IP Whitelist"
                packet_details = {**packet_details_base, 'action': action, 'reason': reason}
                # Optional: Log whitelisted packets if needed for debugging, but might be noisy
                # logger.debug(f"Packet {action}: {reason}", extra={'log_type': 'packet', 'packet_info': packet_details})
                return True

            # Blacklist check
            if self._check_ip_rules(src_ip, self.ip_blacklist) or self._check_ip_rules(dst_ip, self.ip_blacklist):
                action = "拦截"
                reason = f"IP Blacklist ({src_ip if self._check_ip_rules(src_ip, self.ip_blacklist) else dst_ip})"
                packet_details = {**packet_details_base, 'action': action, 'reason': reason}
                logger.debug(f"Packet {action}: {reason}", extra={'log_type': 'packet', 'packet_info': packet_details})
                return False

            # 3. Port Filtering
            src_port = getattr(packet, 'src_port', None)
            dst_port = getattr(packet, 'dst_port', None)

            if src_port is None or dst_port is None:
                # logger.debug("Passing packet with missing port(s).")
                return True # Cannot filter without ports

            # Whitelist check (higher priority)
            if self._check_port_rules(src_port, self.port_whitelist) or self._check_port_rules(dst_port, self.port_whitelist):
                action = "放行"
                reason = "Port Whitelist"
                packet_details = {**packet_details_base, 'action': action, 'reason': reason}
                # Optional: Log whitelisted packets if needed for debugging
                # logger.debug(f"Packet {action}: {reason}", extra={'log_type': 'packet', 'packet_info': packet_details})
                return True

            # Blacklist check
            if self._check_port_rules(src_port, self.port_blacklist) or self._check_port_rules(dst_port, self.port_blacklist):
                action = "拦截"
                reason = f"Port Blacklist ({src_port if self._check_port_rules(src_port, self.port_blacklist) else dst_port})"
                packet_details = {**packet_details_base, 'action': action, 'reason': reason}
                logger.debug(f"Packet {action}: {reason}", extra={'log_type': 'packet', 'packet_info': packet_details})
                return False

            # 4. Content Filtering (using compiled regex on bytes)
            if self.compiled_content_filters and hasattr(packet, 'payload'):
                payload = packet.payload # This should be bytes
                if payload:
                    for pattern in self.compiled_content_filters:
                        try:
                            if pattern.search(payload):
                                action = "拦截"
                                reason = f"Content Filter ({pattern.pattern.decode('utf-8', 'ignore')})"
                                packet_details = {**packet_details_base, 'action': action, 'reason': reason}
                                # Log content filter blocks at INFO level as they might be significant
                                logger.info(f"Packet {action}: {reason}", extra={'log_type': 'packet', 'packet_info': packet_details})
                                return False
                        except Exception as search_err:
                             logger.error(f"Error during content filter search with pattern '{pattern.pattern.decode('utf-8', 'ignore')}': {search_err}")


            # 5. Default Action: Pass
            # Log default passes only if debug level is very low, or not at all to reduce noise
            # action = "放行"
            # reason = "Default Action"
            # packet_details = {**packet_details_base, 'action': action, 'reason': reason}
            # logger.debug(f"Packet {action}: {reason}", extra={'log_type': 'packet', 'packet_info': packet_details})
            return True

        except Exception as e:
            logger.error(f"Error analyzing packet: {e}", exc_info=True)
            return True # Default to passing if analysis fails

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

    def _check_port_rules(self, port_to_check: int, rule_set: Set[str]) -> bool:
        """Checks if a port matches any rule in the given set (single ports or ranges)."""
        if not isinstance(port_to_check, int):
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
            'protocol': 'TCP' if getattr(packet, 'tcp', None) else ('UDP' if getattr(packet, 'udp', None) else 'Other'),
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

# Example usage:
# if __name__ == "__main__":
#     analyzer = PacketAnalyzer()
#     rules = {
#         'ip_blacklist': {'1.1.1.1', '192.168.1.0/24'},
#         'port_whitelist': {'80', '443', '8000-8080'},
#         'content_filters': ['badkeyword', r'evil\s?pattern'],
#         'protocol_filter': {'tcp': True, 'udp': False}
#     }
#     analyzer.set_rules(rules)
#     analyzer.set_settings({'allow_private_network': False, 'skip_local_packets': True})

#     # Create dummy packets for testing (requires more setup)
#     # packet1 = ... # Whitelisted port
#     # packet2 = ... # Blacklisted IP
#     # packet3 = ... # UDP packet (blocked)
#     # packet4 = ... # Contains 'badkeyword'
#     # packet5 = ... # Loopback packet

#     # print(f"Packet 1 should pass: {analyzer.should_pass(packet1)}")
#     # print(f"Packet 2 should pass: {analyzer.should_pass(packet2)}")
#     # print(f"Packet 3 should pass: {analyzer.should_pass(packet3)}")
#     # print(f"Packet 4 should pass: {analyzer.should_pass(packet4)}")
#     # print(f"Packet 5 should pass: {analyzer.should_pass(packet5)}")
