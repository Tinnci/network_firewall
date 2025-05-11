#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Constants used across the firewall application."""

# Action types
ACTION_ALLOW = "放行"
ACTION_BLOCK = "拦截"
ACTION_UNKNOWN = "未知"

# Protocol types
PROTOCOL_TCP = "TCP"
PROTOCOL_UDP = "UDP"
PROTOCOL_ICMP = "ICMP"
PROTOCOL_OTHER = "Other"
PROTOCOL_ALL = "All"

# Rule list types
RULE_TYPE_BLACKLIST = "blacklist"
RULE_TYPE_WHITELIST = "whitelist"

# Log types
LOG_TYPE_PACKET = "packet"
LOG_TYPE_GENERAL = "general"

# UI related strings (example, more can be added)
UI_STATUS_RUNNING = "状态: 运行中"
UI_STATUS_STOPPED = "状态: 已停止" 

# Rule dictionary keys
KEY_IP_BLACKLIST = "ip_blacklist"
KEY_IP_WHITELIST = "ip_whitelist"
KEY_PORT_BLACKLIST = "port_blacklist"
KEY_PORT_WHITELIST = "port_whitelist"
KEY_CONTENT_FILTERS = "content_filters"
KEY_PROTOCOL_FILTER = "protocol_filter"

# Reasons for packet decisions (used in PacketAnalyzer and logs)
REASON_LOCAL_LOOPBACK_SKIPPED = "本地回环包 (根据设置跳过)"
REASON_NON_TCP_UDP = "非 TCP/UDP 包"
REASON_PROTOCOL_FILTER_TCP = "协议过滤 (TCP)"
REASON_PROTOCOL_FILTER_UDP = "协议过滤 (UDP)"
REASON_MISSING_IP = "缺少IP地址"
REASON_PRIVATE_NETWORK_ALLOWED = "允许的私有网络通信"
REASON_IP_WHITELIST = "IP白名单"
REASON_IP_BLACKLIST = "IP黑名单"
REASON_MISSING_PORT = "缺少端口信息"
REASON_PORT_NOT_IN_WHITELIST = "端口未在白名单"
REASON_PORT_WHITELIST = "端口白名单"
REASON_PORT_BLACKLIST = "端口黑名单"
REASON_CONTENT_FILTER = "内容过滤"
REASON_DEFAULT_PASS = "符合默认放行条件"
REASON_ANALYSIS_ERROR = "分析时发生错误，默认放行"