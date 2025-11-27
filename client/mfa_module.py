"""
多因素认证 (MFA) 模块
- TOTP (Time-based One-Time Password)
- HOTP (HMAC-based One-Time Password)
- 备用恢复码
- U2F/FIDO2 硬件密钥支持准备
"""

import os
import json
import time
import hmac
import hashlib
import secrets
import base64
from pathlib import Path
from typing import List, Optional, Tuple
from datetime import datetime


class TOTPGenerator:
    """基于时间的一次性密码生成器 (RFC 6238)"""

    def __init__(self, secret: Optional[bytes] = None, period: int = 30, digits: int = 6):
        """
        初始化TOTP生成器

        Args:
            secret: 共享密钥（Base32编码），如果为None则自动生成
            period: 时间步长（秒）
            digits: OTP位数
        """
        if secret is None:
            # 生成160位（20字节）的随机密钥
            secret = secrets.token_bytes(20)

        self.secret = secret
        self.period = period
        self.digits = digits

    def generate_otp(self, timestamp: Optional[int] = None) -> str:
        """
        生成OTP

        Args:
            timestamp: Unix时间戳，如果为None使用当前时间

        Returns:
            OTP字符串
        """
        if timestamp is None:
            timestamp = int(time.time())

        # 计算时间计数器
        counter = timestamp // self.period

        return self._generate_hotp(counter)

    def verify_otp(self, otp: str, timestamp: Optional[int] = None, window: int = 1) -> bool:
        """
        验证OTP

        Args:
            otp: 待验证的OTP
            timestamp: Unix时间戳
            window: 允许的时间窗口（前后各window个period）

        Returns:
            验证是否成功
        """
        if timestamp is None:
            timestamp = int(time.time())

        counter = timestamp // self.period

        # 在时间窗口内验证
        for i in range(-window, window + 1):
            if otp == self._generate_hotp(counter + i):
                return True

        return False

    def _generate_hotp(self, counter: int) -> str:
        """生成HOTP (RFC 4226)"""
        # 将计数器转换为8字节大端序
        counter_bytes = counter.to_bytes(8, byteorder='big')

        # 计算HMAC-SHA1
        h = hmac.new(self.secret, counter_bytes, hashlib.sha1).digest()

        # 动态截断
        offset = h[-1] & 0x0F
        truncated = int.from_bytes(h[offset:offset + 4], byteorder='big') & 0x7FFFFFFF

        # 生成OTP
        otp = truncated % (10 ** self.digits)

        return str(otp).zfill(self.digits)

    def get_provisioning_uri(self, account_name: str, issuer: str = "SecureChat") -> str:
        """
        生成OTP Auth URI（用于生成二维码）

        Args:
            account_name: 账户名称
            issuer: 发行者名称

        Returns:
            otpauth:// URI
        """
        secret_b32 = base64.b32encode(self.secret).decode('utf-8').rstrip('=')

        uri = f"otpauth://totp/{issuer}:{account_name}?secret={secret_b32}&issuer={issuer}&digits={self.digits}&period={self.period}"

        return uri

    def get_secret_base32(self) -> str:
        """获取Base32编码的密钥"""
        return base64.b32encode(self.secret).decode('utf-8').rstrip('=')


class RecoveryCodeManager:
    """备用恢复码管理器"""

    def __init__(self, num_codes: int = 10, code_length: int = 8):
        """
        初始化恢复码管理器

        Args:
            num_codes: 恢复码数量
            code_length: 每个恢复码长度
        """
        self.num_codes = num_codes
        self.code_length = code_length
        self.codes: List[str] = []
        self.used_codes: set = set()

    def generate_codes(self) -> List[str]:
        """生成新的恢复码"""
        self.codes = []
        for _ in range(self.num_codes):
            # 生成随机恢复码（大写字母和数字）
            code = ''.join(
                secrets.choice('ABCDEFGHJKLMNPQRSTUVWXYZ23456789')
                for _ in range(self.code_length)
            )
            # 格式化为4-4格式（如：ABCD-EFGH）
            formatted = f"{code[:4]}-{code[4:]}"
            self.codes.append(formatted)

        self.used_codes = set()
        return self.codes.copy()

    def verify_code(self, code: str) -> bool:
        """
        验证恢复码

        Args:
            code: 待验证的恢复码

        Returns:
            验证是否成功
        """
        code = code.upper().replace(' ', '').replace('-', '')
        formatted = f"{code[:4]}-{code[4:]}"

        if formatted in self.used_codes:
            return False

        if formatted in self.codes:
            self.used_codes.add(formatted)
            return True

        return False

    def get_remaining_codes(self) -> int:
        """获取剩余可用恢复码数量"""
        return len(self.codes) - len(self.used_codes)

    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            "codes": self.codes,
            "used_codes": list(self.used_codes),
            "generated_at": datetime.utcnow().isoformat()
        }

    def from_dict(self, data: dict):
        """从字典加载"""
        self.codes = data.get("codes", [])
        self.used_codes = set(data.get("used_codes", []))


class MFAManager:
    """多因素认证管理器"""

    def __init__(self, identity: str, mfa_dir: Path):
        """
        初始化MFA管理器

        Args:
            identity: 用户身份标识
            mfa_dir: MFA配置目录
        """
        self.identity = identity
        self.mfa_dir = mfa_dir / identity
        self.mfa_dir.mkdir(parents=True, exist_ok=True)

        self.config_path = self.mfa_dir / "mfa_config.json"

        # TOTP生成器
        self.totp: Optional[TOTPGenerator] = None

        # 恢复码管理器
        self.recovery: RecoveryCodeManager = RecoveryCodeManager()

        # MFA状态
        self.enabled = False
        self.setup_completed = False

        # 加载配置
        self.load_config()

    def setup_totp(self) -> Tuple[str, str, List[str]]:
        """
        设置TOTP

        Returns:
            (secret_base32, provisioning_uri, recovery_codes)
        """
        # 生成新的TOTP密钥
        self.totp = TOTPGenerator()

        # 生成恢复码
        recovery_codes = self.recovery.generate_codes()

        # 生成provisioning URI
        uri = self.totp.get_provisioning_uri(self.identity)
        secret = self.totp.get_secret_base32()

        self.setup_completed = False

        print(f"✓ MFA setup initiated for: {self.identity}")
        print(f"  Secret: {secret}")
        print(f"  Recovery codes: {len(recovery_codes)} generated")

        return secret, uri, recovery_codes

    def verify_and_enable(self, otp: str) -> bool:
        """
        验证OTP并启用MFA

        Args:
            otp: 用户输入的OTP

        Returns:
            验证是否成功
        """
        if not self.totp:
            return False

        if self.totp.verify_otp(otp):
            self.enabled = True
            self.setup_completed = True
            self.save_config()
            print(f"✓ MFA enabled for: {self.identity}")
            return True

        print(f"✗ Invalid OTP for: {self.identity}")
        return False

    def verify_login(self, otp: str) -> Tuple[bool, str]:
        """
        验证登录时的OTP

        Args:
            otp: 用户输入的OTP或恢复码

        Returns:
            (success, message)
        """
        if not self.enabled:
            return True, "MFA not enabled"

        # 首先尝试验证TOTP
        if self.totp and self.totp.verify_otp(otp):
            print(f"✓ TOTP verification successful: {self.identity}")
            return True, "TOTP verified"

        # 尝试验证恢复码
        if self.recovery.verify_code(otp):
            remaining = self.recovery.get_remaining_codes()
            self.save_config()

            print(f"✓ Recovery code used: {self.identity} ({remaining} codes remaining)")

            if remaining == 0:
                return True, "Recovery code accepted (LAST CODE - please regenerate)"
            elif remaining <= 2:
                return True, f"Recovery code accepted ({remaining} codes remaining - please regenerate soon)"
            else:
                return True, "Recovery code accepted"

        print(f"✗ MFA verification failed: {self.identity}")
        return False, "Invalid OTP or recovery code"

    def disable_mfa(self, otp: str) -> bool:
        """
        禁用MFA

        Args:
            otp: 用户输入的OTP用于确认

        Returns:
            操作是否成功
        """
        if not self.enabled:
            return True

        # 验证OTP
        success, _ = self.verify_login(otp)
        if success:
            self.enabled = False
            self.setup_completed = False
            self.totp = None
            self.save_config()
            print(f"✓ MFA disabled for: {self.identity}")
            return True

        return False

    def regenerate_recovery_codes(self, otp: str) -> Optional[List[str]]:
        """
        重新生成恢复码

        Args:
            otp: 用户输入的OTP用于确认

        Returns:
            新的恢复码列表，如果验证失败则返回None
        """
        success, _ = self.verify_login(otp)
        if not success:
            return None

        recovery_codes = self.recovery.generate_codes()
        self.save_config()

        print(f"✓ Recovery codes regenerated for: {self.identity}")
        return recovery_codes

    def save_config(self):
        """保存MFA配置"""
        config = {
            "identity": self.identity,
            "enabled": self.enabled,
            "setup_completed": self.setup_completed,
            "totp_secret": base64.b64encode(self.totp.secret).decode() if self.totp else None,
            "recovery": self.recovery.to_dict(),
            "updated_at": datetime.utcnow().isoformat()
        }

        with open(self.config_path, 'w') as f:
            json.dump(config, f, indent=2)

        # 设置文件权限为仅所有者可读写
        os.chmod(self.config_path, 0o600)

    def load_config(self):
        """加载MFA配置"""
        if not self.config_path.exists():
            return

        with open(self.config_path, 'r') as f:
            config = json.load(f)

        self.enabled = config.get("enabled", False)
        self.setup_completed = config.get("setup_completed", False)

        # 加载TOTP
        totp_secret = config.get("totp_secret")
        if totp_secret:
            secret = base64.b64decode(totp_secret)
            self.totp = TOTPGenerator(secret=secret)

        # 加载恢复码
        recovery_data = config.get("recovery", {})
        if recovery_data:
            self.recovery.from_dict(recovery_data)

    def is_enabled(self) -> bool:
        """检查MFA是否启用"""
        return self.enabled

    def get_status(self) -> dict:
        """获取MFA状态"""
        return {
            "enabled": self.enabled,
            "setup_completed": self.setup_completed,
            "recovery_codes_remaining": self.recovery.get_remaining_codes(),
            "totp_configured": self.totp is not None
        }
