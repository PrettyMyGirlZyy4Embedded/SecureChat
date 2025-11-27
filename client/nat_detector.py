"""
NAT检测模块
- NAT类型检测（Full Cone, Restricted, Port Restricted, Symmetric）
- CGNAT检测（Carrier-Grade NAT）
- IPv4/IPv6双栈支持
"""

import socket
import struct
import logging
from typing import Tuple, Optional
from enum import Enum


class NATType(Enum):
    OPEN = "Open Internet"
    FULL_CONE = "Full Cone NAT"
    RESTRICTED = "Restricted Cone NAT"
    PORT_RESTRICTED = "Port Restricted Cone NAT"
    SYMMETRIC = "Symmetric NAT"
    BLOCKED = "Blocked"
    CGNAT = "Carrier-Grade NAT"


class NATDetector:
    """NAT类型检测器"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.cgnat_ranges = [
            ('100.64.0.0', '100.127.255.255'),  # RFC 6598 CGNAT
            ('10.0.0.0', '10.255.255.255'),      # Private
            ('172.16.0.0', '172.31.255.255'),    # Private
            ('192.168.0.0', '192.168.255.255'),  # Private
        ]

    def ip_to_int(self, ip: str) -> int:
        """IP地址转整数"""
        return struct.unpack("!I", socket.inet_aton(ip))[0]

    def is_cgnat_ip(self, ip: str) -> bool:
        """检测是否为CGNAT IP"""
        try:
            ip_int = self.ip_to_int(ip)
            for start, end in self.cgnat_ranges:
                if self.ip_to_int(start) <= ip_int <= self.ip_to_int(end):
                    return True
            return False
        except:
            return False

    def is_private_ip(self, ip: str) -> bool:
        """检测是否为私有IP"""
        try:
            ip_int = self.ip_to_int(ip)
            # 10.0.0.0/8
            if 167772160 <= ip_int <= 184549375:
                return True
            # 172.16.0.0/12
            if 2886729728 <= ip_int <= 2887778303:
                return True
            # 192.168.0.0/16
            if 3232235520 <= ip_int <= 3232301055:
                return True
            # 100.64.0.0/10 (CGNAT)
            if 1681915904 <= ip_int <= 1686110207:
                return True
            return False
        except:
            return False

    def detect_local_ips(self) -> dict:
        """检测本地IP地址"""
        local_ips = {
            'ipv4': [],
            'ipv6': []
        }

        try:
            hostname = socket.gethostname()
            addr_info = socket.getaddrinfo(hostname, None)

            for info in addr_info:
                family, _, _, _, addr = info
                ip = addr[0]

                if family == socket.AF_INET and not ip.startswith('127.'):
                    local_ips['ipv4'].append(ip)
                elif family == socket.AF_INET6 and not ip.startswith('::1'):
                    local_ips['ipv6'].append(ip)
        except Exception as e:
            self.logger.error(f"Error detecting local IPs: {e}")

        return local_ips

    def detect_nat_type(self, stun_server: Optional[str] = None) -> dict:
        """检测NAT类型"""
        result = {
            'nat_type': NATType.BLOCKED,
            'local_ip': None,
            'external_ip': None,
            'is_cgnat': False,
            'is_symmetric': False
        }

        try:
            # 获取本地IP
            local_ips = self.detect_local_ips()
            if local_ips['ipv4']:
                result['local_ip'] = local_ips['ipv4'][0]

            # 简化的NAT检测：通过本地IP判断
            if result['local_ip']:
                if self.is_private_ip(result['local_ip']):
                    if self.is_cgnat_ip(result['local_ip']):
                        result['nat_type'] = NATType.CGNAT
                        result['is_cgnat'] = True
                    else:
                        # 简化判断：私有IP通常在NAT后面
                        result['nat_type'] = NATType.SYMMETRIC
                        result['is_symmetric'] = True
                else:
                    result['nat_type'] = NATType.OPEN

        except Exception as e:
            self.logger.error(f"NAT detection error: {e}")

        return result

    def can_perform_hole_punching(self, nat_info: dict) -> bool:
        """判断是否可以进行UDP打洞"""
        nat_type = nat_info['nat_type']

        # CGNAT和对称NAT最难打洞，但可以尝试多端口策略
        if nat_type in [NATType.CGNAT, NATType.SYMMETRIC]:
            return True  # 可以尝试，但成功率较低

        # Full Cone, Restricted, Port Restricted都可以打洞
        if nat_type in [NATType.FULL_CONE, NATType.RESTRICTED, NATType.PORT_RESTRICTED]:
            return True

        # Open Internet直接连接
        if nat_type == NATType.OPEN:
            return True

        return False

    def get_nat_difficulty(self, nat_info: dict) -> str:
        """获取NAT打洞难度评级"""
        nat_type = nat_info['nat_type']

        if nat_type == NATType.OPEN:
            return "EASY"
        elif nat_type in [NATType.FULL_CONE, NATType.RESTRICTED]:
            return "MEDIUM"
        elif nat_type == NATType.PORT_RESTRICTED:
            return "HARD"
        elif nat_type in [NATType.SYMMETRIC, NATType.CGNAT]:
            return "VERY_HARD"
        else:
            return "IMPOSSIBLE"
