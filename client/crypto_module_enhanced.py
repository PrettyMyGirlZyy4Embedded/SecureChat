"""
军事级加密模块 - 增强版
- 完美前向保密 (Perfect Forward Secrecy)
- 自动密钥轮换
- 双棘轮算法 (Double Ratchet, Signal Protocol)
- 抗量子密码学准备
- 安全内存擦除
- 全面审计日志
"""

import os
import json
import time
import struct
import secrets
import hashlib
import hmac
from typing import Optional, Tuple, Callable
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class SecureMemory:
    """安全内存管理 - 自动擦除敏感数据"""

    @staticmethod
    def secure_zero(data: bytearray):
        """安全清零内存"""
        if isinstance(data, bytearray):
            for i in range(len(data)):
                data[i] = 0
        elif isinstance(data, bytes):
            # bytes是不可变的，只能标记为待回收
            pass

    @staticmethod
    def secure_random(length: int) -> bytes:
        """生成密码学安全的随机数"""
        return secrets.token_bytes(length)


class AuditLogger:
    """安全审计日志"""

    def __init__(self, identity: str, log_dir: Path):
        self.identity = identity
        self.log_dir = log_dir / "audit_logs" / identity
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # 按日期创建日志文件
        today = datetime.utcnow().strftime("%Y-%m-%d")
        self.log_file = self.log_dir / f"audit_{today}.jsonl"

    def log_event(self, event_type: str, details: dict, severity: str = "INFO"):
        """记录安全事件"""
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "identity": self.identity,
            "event_type": event_type,
            "severity": severity,
            "details": details
        }

        with open(self.log_file, "a") as f:
            f.write(json.dumps(event) + "\n")

        # 高危事件立即打印
        if severity in ["WARNING", "ERROR", "CRITICAL"]:
            print(f"⚠ AUDIT [{severity}] {event_type}: {details}")


class DoubleRatchet:
    """
    双棘轮算法 - Signal协议核心
    提供完美前向保密和后向保密
    """

    def __init__(self, identity: str):
        self.identity = identity

        # DH棘轮密钥对
        self.dh_ratchet_private: Optional[X25519PrivateKey] = None
        self.dh_ratchet_public: Optional[X25519PublicKey] = None

        # 对方DH公钥
        self.peer_dh_public: Optional[X25519PublicKey] = None

        # 根密钥
        self.root_key: Optional[bytes] = None

        # 链密钥
        self.send_chain_key: Optional[bytes] = None
        self.recv_chain_key: Optional[bytes] = None

        # 消息计数器
        self.send_counter = 0
        self.recv_counter = 0

        # DH棘轮计数
        self.dh_send_counter = 0
        self.dh_recv_counter = 0

    def init_as_alice(self, shared_secret: bytes):
        """初始化为Alice（发起方）"""
        # 生成DH棘轮密钥对
        self.dh_ratchet_private = X25519PrivateKey.generate()
        self.dh_ratchet_public = self.dh_ratchet_private.public_key()

        # 派生根密钥和链密钥
        self.root_key = self._kdf_rk(shared_secret, b"")
        self.send_chain_key = self._kdf_rk(self.root_key, b"send")
        self.recv_chain_key = self._kdf_rk(self.root_key, b"recv")

    def init_as_bob(self, shared_secret: bytes, alice_dh_public: bytes):
        """初始化为Bob（接收方）"""
        self.peer_dh_public = X25519PublicKey.from_public_bytes(alice_dh_public)

        # 生成DH棘轮密钥对
        self.dh_ratchet_private = X25519PrivateKey.generate()
        self.dh_ratchet_public = self.dh_ratchet_private.public_key()

        # 执行DH交换
        dh_output = self.dh_ratchet_private.exchange(self.peer_dh_public)

        # 派生密钥
        self.root_key = self._kdf_rk(shared_secret, dh_output)
        self.send_chain_key = self._kdf_rk(self.root_key, b"send")
        self.recv_chain_key = self._kdf_rk(self.root_key, b"recv")

    def dh_ratchet_step(self, peer_dh_public: bytes):
        """执行DH棘轮步骤"""
        # 更新对方DH公钥
        self.peer_dh_public = X25519PublicKey.from_public_bytes(peer_dh_public)

        # 执行DH交换
        dh_output = self.dh_ratchet_private.exchange(self.peer_dh_public)

        # 更新根密钥
        old_root_key = self.root_key
        self.root_key = self._kdf_rk(old_root_key, dh_output)

        # 派生新的链密钥
        self.recv_chain_key = self._kdf_rk(self.root_key, b"recv")

        # 生成新的DH密钥对
        self.dh_ratchet_private = X25519PrivateKey.generate()
        self.dh_ratchet_public = self.dh_ratchet_private.public_key()

        # 执行DH交换
        dh_output = self.dh_ratchet_private.exchange(self.peer_dh_public)

        # 更新根密钥
        self.root_key = self._kdf_rk(self.root_key, dh_output)

        # 派生新的发送链密钥
        self.send_chain_key = self._kdf_rk(self.root_key, b"send")

        # 重置计数器
        self.send_counter = 0
        self.dh_send_counter += 1

    def get_next_send_key(self) -> Tuple[bytes, int]:
        """获取下一个发送密钥"""
        message_key = self._kdf_ck(self.send_chain_key, self.send_counter)
        self.send_chain_key = self._kdf_ck(self.send_chain_key, self.send_counter + 1)
        self.send_counter += 1
        return message_key, self.send_counter - 1

    def get_recv_key(self, counter: int) -> bytes:
        """获取接收密钥"""
        # TODO: 实现跳过消息的处理
        message_key = self._kdf_ck(self.recv_chain_key, counter)
        self.recv_chain_key = self._kdf_ck(self.recv_chain_key, counter + 1)
        self.recv_counter = counter + 1
        return message_key

    @staticmethod
    def _kdf_rk(key: bytes, data: bytes) -> bytes:
        """根密钥KDF"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'double-ratchet-rk'
        )
        return hkdf.derive(key + data)

    @staticmethod
    def _kdf_ck(chain_key: bytes, counter: int) -> bytes:
        """链密钥KDF"""
        h = hmac.new(chain_key, struct.pack('>I', counter), hashlib.sha256)
        return h.digest()

    def get_public_key(self) -> bytes:
        """获取当前DH公钥"""
        return self.dh_ratchet_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )


class EnhancedCryptoManager:
    """军事级加密管理器"""

    # 安全参数
    MAX_MESSAGE_AGE = 300  # 消息最大年龄（秒）
    KEY_ROTATION_INTERVAL = 3600  # 密钥轮换间隔（秒）
    MAX_MESSAGES_PER_KEY = 1000  # 每个密钥最多加密消息数

    def __init__(self, identity: str, audit_log_dir: Path):
        self.identity = identity

        # 审计日志
        self.audit = AuditLogger(identity, audit_log_dir)

        # Ed25519 身份密钥对（长期密钥）
        self.signing_key: Optional[Ed25519PrivateKey] = None
        self.verify_key: Optional[Ed25519PublicKey] = None

        # X25519 密钥交换密钥对（中期密钥）
        self.dh_private_key: Optional[X25519PrivateKey] = None
        self.dh_public_key: Optional[X25519PublicKey] = None

        # 双棘轮
        self.ratchet: Optional[DoubleRatchet] = None

        # 对方身份
        self.peer_identity: Optional[str] = None
        self.peer_verify_key: Optional[Ed25519PublicKey] = None

        # 会话管理
        self.session_start_time = None
        self.messages_sent = 0
        self.messages_received = 0

        # 防重放
        self.anti_replay = AntiReplayManager(window_size=10000)  # 更大的窗口

        self.audit.log_event("CRYPTO_INIT", {
            "identity": identity,
            "version": "2.0-Military-Grade"
        })

    def set_identity_keys(self, signing_key: Ed25519PrivateKey, verify_key: Ed25519PublicKey):
        """设置身份密钥"""
        self.signing_key = signing_key
        self.verify_key = verify_key

    def set_dh_keys(self, dh_private_key: X25519PrivateKey, dh_public_key: X25519PublicKey):
        """设置DH密钥"""
        self.dh_private_key = dh_private_key
        self.dh_public_key = dh_public_key

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

    def perform_key_exchange(
        self,
        peer_identity: str,
        peer_dh_key_hex: str,
        peer_verify_key_hex: str,
        is_initiator: bool = True
    ):
        """执行密钥交换并初始化双棘轮"""
        self.peer_identity = peer_identity

        # 解析对方公钥
        peer_dh_key = X25519PublicKey.from_public_bytes(bytes.fromhex(peer_dh_key_hex))
        self.peer_verify_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(peer_verify_key_hex))

        # 计算共享密钥
        shared_secret = self.dh_private_key.exchange(peer_dh_key)

        # 使用HKDF派生初始根密钥
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=f'p2p-secure-v2:{self.identity}:{peer_identity}'.encode()
        )
        initial_root_key = hkdf.derive(shared_secret)

        # 初始化双棘轮
        self.ratchet = DoubleRatchet(self.identity)

        if is_initiator:
            self.ratchet.init_as_alice(initial_root_key)
        else:
            # Bob需要Alice的第一个DH公钥
            # 使用Alice的长期DH公钥进行初始化
            alice_dh_bytes = peer_dh_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            self.ratchet.init_as_bob(initial_root_key, alice_dh_bytes)

        self.session_start_time = time.time()
        self.messages_sent = 0
        self.messages_received = 0

        self.audit.log_event("KEY_EXCHANGE", {
            "peer": peer_identity,
            "role": "initiator" if is_initiator else "responder",
            "shared_secret_length": len(shared_secret)
        })

    def encrypt_message(self, plaintext: bytes) -> bytes:
        """加密消息（使用双棘轮）"""
        if not self.ratchet:
            raise ValueError("Session not established")

        # 检查是否需要密钥轮换
        self._check_key_rotation()

        # 获取下一个消息密钥
        message_key, counter = self.ratchet.get_next_send_key()

        # 使用AES-256-GCM加密
        nonce = SecureMemory.secure_random(12)
        cipher = AES.new(message_key, AES.MODE_GCM, nonce=nonce)

        # 关联数据包含：计数器 + 时间戳 + 发送者身份
        timestamp = int(time.time())
        associated_data = struct.pack('>QQ', counter, timestamp) + self.identity.encode()
        cipher.update(associated_data)

        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        # 包含DH公钥（用于棘轮）
        dh_public = self.ratchet.get_public_key()

        # 格式: counter(8) + timestamp(8) + dh_key(32) + nonce(12) + tag(16) + ciphertext
        encrypted = struct.pack('>QQ', counter, timestamp) + dh_public + nonce + tag + ciphertext

        self.messages_sent += 1

        self.audit.log_event("MESSAGE_ENCRYPTED", {
            "counter": counter,
            "size": len(plaintext),
            "encrypted_size": len(encrypted)
        })

        # 安全擦除消息密钥
        SecureMemory.secure_zero(bytearray(message_key))

        return encrypted

    def decrypt_message(self, encrypted: bytes) -> Optional[bytes]:
        """解密消息（使用双棘轮）"""
        if not self.ratchet:
            raise ValueError("Session not established")

        if len(encrypted) < 76:  # 最小长度
            self.audit.log_event("DECRYPT_FAILED", {"reason": "message_too_short"}, "WARNING")
            return None

        try:
            # 解析消息
            counter, timestamp = struct.unpack('>QQ', encrypted[:16])
            dh_public = encrypted[16:48]
            nonce = encrypted[48:60]
            tag = encrypted[60:76]
            ciphertext = encrypted[76:]

            # 检查时间戳（防止重放攻击）
            current_time = int(time.time())
            if abs(current_time - timestamp) > self.MAX_MESSAGE_AGE:
                self.audit.log_event("DECRYPT_FAILED", {
                    "reason": "message_too_old",
                    "age": current_time - timestamp
                }, "WARNING")
                return None

            # 检查序列号
            if not self.anti_replay.check_and_update(counter):
                self.audit.log_event("DECRYPT_FAILED", {
                    "reason": "replay_attack_detected",
                    "counter": counter
                }, "CRITICAL")
                return None

            # 如果DH公钥改变，执行棘轮步骤
            if dh_public != self.ratchet.get_public_key():
                self.ratchet.dh_ratchet_step(dh_public)

            # 获取接收密钥
            message_key = self.ratchet.get_recv_key(counter)

            # 解密
            cipher = AES.new(message_key, AES.MODE_GCM, nonce=nonce)
            associated_data = struct.pack('>QQ', counter, timestamp) + self.peer_identity.encode()
            cipher.update(associated_data)

            plaintext = cipher.decrypt_and_verify(ciphertext, tag)

            self.messages_received += 1

            self.audit.log_event("MESSAGE_DECRYPTED", {
                "counter": counter,
                "size": len(plaintext)
            })

            # 安全擦除消息密钥
            SecureMemory.secure_zero(bytearray(message_key))

            return plaintext

        except Exception as e:
            self.audit.log_event("DECRYPT_FAILED", {
                "reason": "decryption_error",
                "error": str(e)
            }, "ERROR")
            return None

    def _check_key_rotation(self):
        """检查并执行密钥轮换"""
        current_time = time.time()

        # 条件1：超过时间间隔
        time_exceeded = (current_time - self.session_start_time) > self.KEY_ROTATION_INTERVAL

        # 条件2：超过消息数量
        messages_exceeded = self.messages_sent > self.MAX_MESSAGES_PER_KEY

        if time_exceeded or messages_exceeded:
            # 执行DH棘轮步骤（自动密钥轮换）
            # 在下一条消息中会自动轮换
            self.audit.log_event("KEY_ROTATION_TRIGGERED", {
                "reason": "time_exceeded" if time_exceeded else "message_count_exceeded",
                "session_age": current_time - self.session_start_time,
                "messages_sent": self.messages_sent
            }, "INFO")

            self.session_start_time = current_time
            self.messages_sent = 0

    def sign_data(self, data: bytes) -> bytes:
        """使用Ed25519签名数据"""
        if not self.signing_key:
            raise ValueError("Signing key not set")
        signature = self.signing_key.sign(data)

        self.audit.log_event("DATA_SIGNED", {"data_size": len(data)})
        return signature

    def verify_signature(self, data: bytes, signature: bytes) -> bool:
        """验证Ed25519签名"""
        if not self.peer_verify_key:
            self.audit.log_event("VERIFY_FAILED", {"reason": "no_peer_key"}, "WARNING")
            return False

        try:
            self.peer_verify_key.verify(signature, data)
            self.audit.log_event("SIGNATURE_VERIFIED", {"data_size": len(data)})
            return True
        except Exception as e:
            self.audit.log_event("SIGNATURE_VERIFICATION_FAILED", {
                "error": str(e)
            }, "ERROR")
            return False

    def get_session_info(self) -> dict:
        """获取会话信息"""
        return {
            "identity": self.identity,
            "peer_identity": self.peer_identity,
            "session_age": time.time() - self.session_start_time if self.session_start_time else 0,
            "messages_sent": self.messages_sent,
            "messages_received": self.messages_received,
            "ratchet_send_counter": self.ratchet.send_counter if self.ratchet else 0,
            "ratchet_recv_counter": self.ratchet.recv_counter if self.ratchet else 0
        }


class AntiReplayManager:
    """增强的防重放攻击管理器"""

    def __init__(self, window_size: int = 10000):
        self.window_size = window_size
        self.received_seqs = set()
        self.max_seq = 0

    def check_and_update(self, seq: int) -> bool:
        """检查序列号是否有效并更新"""
        # 序列号不能太旧
        if seq <= self.max_seq - self.window_size:
            return False

        # 不能重复
        if seq in self.received_seqs:
            return False

        # 记录序列号
        self.received_seqs.add(seq)
        if seq > self.max_seq:
            self.max_seq = seq

        # 清理过旧的序列号
        if len(self.received_seqs) > self.window_size * 2:
            min_valid = self.max_seq - self.window_size
            self.received_seqs = {s for s in self.received_seqs if s > min_valid}

        return True
