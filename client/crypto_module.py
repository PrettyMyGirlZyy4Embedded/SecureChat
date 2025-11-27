"""
加密模块 - 提供端到端加密功能
- Ed25519签名身份认证
- ECDH密钥交换（前向保密）
- AES-256-GCM加密
- 序列号防重放攻击
"""

import os
import json
import time
import struct
from typing import Tuple, Optional
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class AntiReplayManager:
    """防重放攻击管理器"""

    def __init__(self, window_size: int = 1000):
        self.window_size = window_size
        self.received_seqs = set()
        self.max_seq = 0

    def check_and_update(self, seq: int) -> bool:
        """检查序列号是否有效并更新"""
        if seq <= self.max_seq - self.window_size:
            return False

        if seq in self.received_seqs:
            return False

        self.received_seqs.add(seq)
        if seq > self.max_seq:
            self.max_seq = seq

        if len(self.received_seqs) > self.window_size * 2:
            min_valid = self.max_seq - self.window_size
            self.received_seqs = {s for s in self.received_seqs if s > min_valid}

        return True


class CryptoManager:
    """加密管理器"""

    def __init__(self, identity: str):
        self.identity = identity

        # Ed25519 身份密钥对（用于签名）
        self.signing_key = Ed25519PrivateKey.generate()
        self.verify_key = self.signing_key.public_key()

        # X25519 密钥交换密钥对（用于ECDH）
        self.dh_private_key = X25519PrivateKey.generate()
        self.dh_public_key = self.dh_private_key.public_key()

        # 会话密钥
        self.session_key: Optional[bytes] = None
        self.peer_verify_key: Optional[Ed25519PublicKey] = None

        # 序列号和防重放
        self.send_seq = 0
        self.anti_replay = AntiReplayManager()

    def get_public_keys(self) -> dict:
        """获取公钥信息"""
        return {
            'identity': self.identity,
            'verify_key': self.verify_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ).hex(),
            'dh_key': self.dh_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ).hex()
        }

    def sign_data(self, data: bytes) -> bytes:
        """使用Ed25519签名数据"""
        return self.signing_key.sign(data)

    def verify_signature(self, data: bytes, signature: bytes, public_key: bytes) -> bool:
        """验证Ed25519签名"""
        try:
            verify_key = Ed25519PublicKey.from_public_bytes(public_key)
            verify_key.verify(signature, data)
            return True
        except Exception:
            return False

    def perform_key_exchange(self, peer_dh_key_hex: str, peer_verify_key_hex: str):
        """执行ECDH密钥交换"""
        peer_dh_key = X25519PublicKey.from_public_bytes(bytes.fromhex(peer_dh_key_hex))
        self.peer_verify_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(peer_verify_key_hex))

        # 计算共享密钥
        shared_secret = self.dh_private_key.exchange(peer_dh_key)

        # 使用HKDF派生会话密钥
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'p2p-secure-session'
        )
        self.session_key = hkdf.derive(shared_secret)

    def encrypt_message(self, plaintext: bytes) -> bytes:
        """使用AES-256-GCM加密消息"""
        if not self.session_key:
            raise ValueError("Session key not established")

        nonce = get_random_bytes(12)
        cipher = AES.new(self.session_key, AES.MODE_GCM, nonce=nonce)

        # 添加序列号到关联数据
        self.send_seq += 1
        associated_data = struct.pack('>Q', self.send_seq)
        cipher.update(associated_data)

        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        # 格式: seq(8) + nonce(12) + tag(16) + ciphertext
        return associated_data + nonce + tag + ciphertext

    def decrypt_message(self, encrypted: bytes) -> Optional[bytes]:
        """使用AES-256-GCM解密消息"""
        if not self.session_key:
            raise ValueError("Session key not established")

        if len(encrypted) < 36:
            return None

        # 解析消息
        seq = struct.unpack('>Q', encrypted[:8])[0]
        nonce = encrypted[8:20]
        tag = encrypted[20:36]
        ciphertext = encrypted[36:]

        # 检查序列号防重放
        if not self.anti_replay.check_and_update(seq):
            return None

        # 解密
        try:
            cipher = AES.new(self.session_key, AES.MODE_GCM, nonce=nonce)
            associated_data = encrypted[:8]
            cipher.update(associated_data)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext
        except Exception:
            return None

    def create_signed_message(self, msg_type: str, data: dict) -> str:
        """创建签名消息"""
        message = {
            'type': msg_type,
            'from': self.identity,
            'data': data,
            'timestamp': time.time()
        }

        msg_bytes = json.dumps(message, sort_keys=True).encode()
        signature = self.sign_data(msg_bytes)

        message['signature'] = signature.hex()
        return json.dumps(message)

    def verify_signed_message(self, msg_json: str) -> Optional[dict]:
        """验证签名消息"""
        try:
            message = json.loads(msg_json)
            signature = bytes.fromhex(message.pop('signature'))

            msg_bytes = json.dumps(message, sort_keys=True).encode()

            if not self.peer_verify_key:
                return None

            peer_key_bytes = self.peer_verify_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )

            if self.verify_signature(msg_bytes, signature, peer_key_bytes):
                return message
            return None
        except Exception:
            return None
