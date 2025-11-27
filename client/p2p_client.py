"""
P2P客户端主逻辑
- 集成加密、NAT检测、UDP打洞、中继回退
- 支持端到端加密通信
- 自动选择最佳连接方式
"""

import asyncio
import json
import logging
import websockets
import time
from typing import Optional, Callable
from enum import Enum

from crypto_module import CryptoManager
from nat_detector import NATDetector
from hole_puncher import AdaptiveHolePuncher


class ConnectionMode(Enum):
    DIRECT = "Direct P2P"
    RELAY = "Encrypted Relay"
    NONE = "Not Connected"


class P2PClient:
    """P2P客户端"""

    def __init__(self, client_id: str, signaling_server: str = "ws://localhost:8765"):
        self.client_id = client_id
        self.signaling_server = signaling_server
        self.logger = logging.getLogger(f"P2PClient-{client_id}")

        # 初始化模块
        self.crypto = CryptoManager(client_id)
        self.nat_detector = NATDetector()
        self.hole_puncher: Optional[AdaptiveHolePuncher] = None

        # 连接状态
        self.ws: Optional[websockets.WebSocketClientProtocol] = None
        self.peer_id: Optional[str] = None
        self.connection_mode = ConnectionMode.NONE
        self.nat_info = None

        # 回调
        self.on_message_callback: Optional[Callable] = None

    async def connect_to_signaling_server(self):
        """连接到信令服务器"""
        self.logger.info(f"Connecting to signaling server: {self.signaling_server}")
        self.ws = await websockets.connect(self.signaling_server)

        # 检测NAT类型
        self.nat_info = self.nat_detector.detect_nat_type()
        self.logger.info(f"NAT Type: {self.nat_info['nat_type'].value}")
        self.logger.info(f"Is CGNAT: {self.nat_info['is_cgnat']}")

        # 注册客户端
        await self.ws.send(json.dumps({
            'type': 'register',
            'client_id': self.client_id,
            'public_keys': self.crypto.get_public_keys(),
            'nat_info': {
                'type': self.nat_info['nat_type'].value,
                'is_cgnat': self.nat_info['is_cgnat']
            }
        }))

        response = await self.ws.recv()
        data = json.loads(response)
        if data['type'] == 'registered':
            self.logger.info("Registered with signaling server")

    async def list_online_clients(self) -> dict:
        """列出在线客户端"""
        await self.ws.send(json.dumps({
            'type': 'list_clients',
            'client_id': self.client_id
        }))

        response = await self.ws.recv()
        data = json.loads(response)
        return data.get('clients', {})

    async def connect_to_peer(self, peer_id: str):
        """连接到对等节点"""
        self.peer_id = peer_id
        self.logger.info(f"Initiating connection to {peer_id}")

        # 获取对等节点信息
        clients = await self.list_online_clients()
        if peer_id not in clients:
            self.logger.error(f"Peer {peer_id} not found")
            return False

        peer_info = clients[peer_id]

        # 执行密钥交换
        self.crypto.perform_key_exchange(
            peer_info['public_keys']['dh_key'],
            peer_info['public_keys']['verify_key']
        )
        self.logger.info("Key exchange completed")

        # 尝试UDP打洞
        success = await self.attempt_hole_punching(peer_info)

        if success:
            self.connection_mode = ConnectionMode.DIRECT
            self.logger.info("P2P connection established (Direct)")
            # 启动接收循环
            asyncio.create_task(self.receive_p2p_messages())
        else:
            self.connection_mode = ConnectionMode.RELAY
            self.logger.info("Falling back to relay mode")
            # 启动接收循环
            asyncio.create_task(self.receive_relay_messages())

        return True

    async def attempt_hole_punching(self, peer_info: dict) -> bool:
        """尝试UDP打洞"""
        self.logger.info("Attempting UDP hole punching...")

        # 创建打洞器
        nat_type = self.nat_info['nat_type'].name
        self.hole_puncher = AdaptiveHolePuncher(nat_type)
        self.hole_puncher.create_udp_sockets()

        # 获取本地端点
        local_endpoints = self.hole_puncher.get_local_endpoints()

        # 发送连接请求
        await self.ws.send(json.dumps({
            'type': 'connection_request',
            'from': self.client_id,
            'to': self.peer_id,
            'connection_info': {
                'endpoints': local_endpoints,
                'public_keys': self.crypto.get_public_keys()
            }
        }))

        # 等待对方响应
        try:
            response = await asyncio.wait_for(self.ws.recv(), timeout=15)
            data = json.loads(response)

            if data['type'] == 'connection_accepted':
                peer_endpoints = data['connection_info']['endpoints']

                # 填充对方的实际IP（在实际环境中由信令服务器提供）
                # 这里模拟本地测试，使用localhost
                for endpoint in peer_endpoints:
                    if endpoint['ip'] == '0.0.0.0':
                        endpoint['ip'] = '127.0.0.1'

                # 执行打洞
                success = await self.hole_puncher.punch_holes(peer_endpoints)
                return success

        except asyncio.TimeoutError:
            self.logger.warning("Connection request timeout")

        return False

    async def accept_connection(self, request_data: dict):
        """接受连接请求"""
        from_id = request_data['from']
        self.peer_id = from_id
        self.logger.info(f"Accepting connection from {from_id}")

        # 密钥交换
        conn_info = request_data['connection_info']
        self.crypto.perform_key_exchange(
            conn_info['public_keys']['dh_key'],
            conn_info['public_keys']['verify_key']
        )

        # 创建打洞器
        nat_type = self.nat_info['nat_type'].name
        self.hole_puncher = AdaptiveHolePuncher(nat_type)
        self.hole_puncher.create_udp_sockets()

        local_endpoints = self.hole_puncher.get_local_endpoints()

        # 发送接受响应
        await self.ws.send(json.dumps({
            'type': 'connection_accept',
            'from': self.client_id,
            'to': from_id,
            'connection_info': {
                'endpoints': local_endpoints,
                'public_keys': self.crypto.get_public_keys()
            }
        }))

        # 获取对方端点并打洞
        peer_endpoints = conn_info['endpoints']
        for endpoint in peer_endpoints:
            if endpoint['ip'] == '0.0.0.0':
                endpoint['ip'] = '127.0.0.1'

        success = await self.hole_puncher.punch_holes(peer_endpoints)

        if success:
            self.connection_mode = ConnectionMode.DIRECT
            self.logger.info("P2P connection established (Direct)")
            asyncio.create_task(self.receive_p2p_messages())
        else:
            self.connection_mode = ConnectionMode.RELAY
            self.logger.info("Using relay mode")
            asyncio.create_task(self.receive_relay_messages())

    async def send_message(self, message: str) -> bool:
        """发送加密消息"""
        if not self.peer_id:
            self.logger.error("Not connected to any peer")
            return False

        # 加密消息
        plaintext = message.encode()
        encrypted = self.crypto.encrypt_message(plaintext)

        if self.connection_mode == ConnectionMode.DIRECT:
            # 通过P2P发送
            return await self.hole_puncher.send_data(encrypted)
        elif self.connection_mode == ConnectionMode.RELAY:
            # 通过中继发送
            await self.ws.send(json.dumps({
                'type': 'relay',
                'from': self.client_id,
                'to': self.peer_id,
                'data': encrypted.hex()
            }))
            return True

        return False

    async def receive_p2p_messages(self):
        """接收P2P消息"""
        self.logger.info("Starting P2P message receiver")
        while self.connection_mode == ConnectionMode.DIRECT:
            encrypted = await self.hole_puncher.receive_data(timeout=1.0)
            if encrypted:
                plaintext = self.crypto.decrypt_message(encrypted)
                if plaintext and self.on_message_callback:
                    self.on_message_callback(plaintext.decode())
            await asyncio.sleep(0.01)

    async def receive_relay_messages(self):
        """接收中继消息"""
        self.logger.info("Starting relay message receiver")
        while self.connection_mode == ConnectionMode.RELAY:
            try:
                response = await asyncio.wait_for(self.ws.recv(), timeout=1.0)
                data = json.loads(response)

                if data['type'] == 'relay_message' and data['from'] == self.peer_id:
                    encrypted = bytes.fromhex(data['data'])
                    plaintext = self.crypto.decrypt_message(encrypted)
                    if plaintext and self.on_message_callback:
                        self.on_message_callback(plaintext.decode())

            except asyncio.TimeoutError:
                pass
            await asyncio.sleep(0.01)

    async def handle_signaling_messages(self):
        """处理信令消息"""
        try:
            async for message in self.ws:
                data = json.loads(message)
                msg_type = data['type']

                if msg_type == 'connection_request':
                    await self.accept_connection(data)

        except Exception as e:
            self.logger.error(f"Error handling signaling: {e}")

    def on_message(self, callback: Callable):
        """设置消息回调"""
        self.on_message_callback = callback

    async def disconnect(self):
        """断开连接"""
        if self.hole_puncher:
            self.hole_puncher.close()
        if self.ws:
            await self.ws.close()
        self.logger.info("Disconnected")

    def get_connection_info(self) -> dict:
        """获取连接信息"""
        return {
            'client_id': self.client_id,
            'peer_id': self.peer_id,
            'connection_mode': self.connection_mode.value,
            'nat_type': self.nat_info['nat_type'].value if self.nat_info else None,
            'is_cgnat': self.nat_info['is_cgnat'] if self.nat_info else None
        }
