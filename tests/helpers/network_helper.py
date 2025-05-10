import socket
import requests
import time

def can_access_url(url: str, timeout: int = 5) -> bool:
    """尝试访问一个URL，返回是否成功"""
    try:
        response = requests.get(url, timeout=timeout)
        return response.status_code == 200
    except requests.RequestException:
        return False

def send_tcp_packet(host: str, port: int, payload: bytes = b"test_data") -> bool:
    """发送一个简单的TCP数据包，返回是否能建立连接"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2) # 短暂超时
            s.connect((host, port))
            s.sendall(payload) # 发送数据
        return True
    except (socket.error, socket.timeout) as e:
        print(f"\n[network_helper.send_tcp_packet DEBUG] Socket error for {host}:{port} - Exception: {type(e).__name__}, Details: {e}\n")
        return False

def send_udp_packet(host: str, port: int, payload: bytes = b"test_data") -> bool:
    """发送一个UDP数据包 (注意：UDP是无连接的，发送成功不代表对方收到或允许)"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(payload, (host, port))
        return True # 发送即认为操作完成，不检查响应
    except socket.error:
        return False
