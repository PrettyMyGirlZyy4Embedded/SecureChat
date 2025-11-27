"""
UDP打洞模块
- 多端口"生日攻击"策略
- 同时从多个本地端口向对方多个端口发送
- 提高对称NAT和CGNAT环境下的打洞成功率
"""

import socket
import asyncio
import logging
import time
import random
from typing import List, Tuple, Optional


class HolePuncher:
    """UDP打洞器"""

    def __init__(self, num_ports: int = 5):
        self.num_ports = num_ports
        self.sockets: List[socket.socket] = []
        self.local_ports: List[int] = []
        self.logger = logging.getLogger(__name__)
        self.punch_success = False
        self.successful_socket = None
        self.successful_addr = None

    def create_udp_sockets(self) -> List[Tuple[socket.socket, int]]:
        """创建多个UDP套接字"""
        sockets_info = []

        for i in range(self.num_ports):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # 绑定到随机端口
            sock.bind(('0.0.0.0', 0))
            local_port = sock.getsockname()[1]

            sock.setblocking(False)

            self.sockets.append(sock)
            self.local_ports.append(local_port)
            sockets_info.append((sock, local_port))

            self.logger.debug(f"Created UDP socket on port {local_port}")

        return sockets_info

    def get_local_endpoints(self) -> List[dict]:
        """获取本地端点信息"""
        endpoints = []
        for port in self.local_ports:
            endpoints.append({
                'ip': '0.0.0.0',  # 将由信令服务器填充实际IP
                'port': port
            })
        return endpoints

    async def punch_holes(self, peer_endpoints: List[dict], duration: int = 10):
        """
        执行UDP打洞（生日攻击策略）
        从每个本地端口向每个对等端点发送数据包
        """
        self.logger.info(f"Starting hole punching to {len(peer_endpoints)} peer endpoints")

        punch_message = b"PUNCH:" + str(time.time()).encode()

        # 生日攻击：所有本地端口向所有对等端口发送
        async def send_punches():
            end_time = time.time() + duration
            while time.time() < end_time and not self.punch_success:
                for sock in self.sockets:
                    for endpoint in peer_endpoints:
                        try:
                            peer_ip = endpoint['ip']
                            peer_port = endpoint['port']
                            sock.sendto(punch_message, (peer_ip, peer_port))
                        except Exception as e:
                            self.logger.debug(f"Punch send error: {e}")
                await asyncio.sleep(0.1)

        # 监听响应
        async def receive_responses():
            end_time = time.time() + duration
            while time.time() < end_time and not self.punch_success:
                for sock in self.sockets:
                    try:
                        data, addr = sock.recvfrom(1024)
                        if data.startswith(b"PUNCH:") or data.startswith(b"PONG:"):
                            self.punch_success = True
                            self.successful_socket = sock
                            self.successful_addr = addr
                            self.logger.info(f"Hole punching successful! Connected to {addr}")
                            return
                    except BlockingIOError:
                        pass
                    except Exception as e:
                        self.logger.debug(f"Receive error: {e}")
                await asyncio.sleep(0.05)

        # 并行执行发送和接收
        await asyncio.gather(
            send_punches(),
            receive_responses()
        )

        return self.punch_success

    async def send_data(self, data: bytes):
        """通过成功的套接字发送数据"""
        if self.successful_socket and self.successful_addr:
            try:
                self.successful_socket.sendto(data, self.successful_addr)
                return True
            except Exception as e:
                self.logger.error(f"Send error: {e}")
                return False
        return False

    async def receive_data(self, timeout: float = 1.0) -> Optional[bytes]:
        """从成功的套接字接收数据"""
        if not self.successful_socket:
            return None

        end_time = time.time() + timeout
        while time.time() < end_time:
            try:
                data, addr = self.successful_socket.recvfrom(65535)
                if addr == self.successful_addr:
                    return data
            except BlockingIOError:
                await asyncio.sleep(0.01)
            except Exception as e:
                self.logger.error(f"Receive error: {e}")
                return None

        return None

    def close(self):
        """关闭所有套接字"""
        for sock in self.sockets:
            try:
                sock.close()
            except:
                pass
        self.sockets.clear()
        self.local_ports.clear()


class AdaptiveHolePuncher(HolePuncher):
    """自适应UDP打洞器 - 根据NAT类型调整策略"""

    def __init__(self, nat_type: str, num_ports: int = None):
        if num_ports is None:
            # 根据NAT类型调整端口数量
            if nat_type in ['SYMMETRIC', 'CGNAT']:
                num_ports = 10  # 对称NAT使用更多端口
            elif nat_type in ['PORT_RESTRICTED']:
                num_ports = 5
            else:
                num_ports = 3

        super().__init__(num_ports)
        self.nat_type = nat_type

    async def punch_holes(self, peer_endpoints: List[dict], duration: int = None):
        """根据NAT类型调整打洞时长"""
        if duration is None:
            if self.nat_type in ['SYMMETRIC', 'CGNAT']:
                duration = 15  # 困难NAT给更多时间
            elif self.nat_type in ['PORT_RESTRICTED']:
                duration = 10
            else:
                duration = 5

        return await super().punch_holes(peer_endpoints, duration)
