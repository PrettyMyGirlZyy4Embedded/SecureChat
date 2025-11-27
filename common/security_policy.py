"""
安全策略和输入验证模块
- 严格的输入验证
- SQL/XSS/命令注入防护
- 内容安全策略
- 数据清理
"""

import re
import html
import unicodedata
from typing import Optional, List, Dict, Tuple
from enum import Enum


class ValidationError(Exception):
    """验证错误"""
    pass


class SecurityLevel(Enum):
    """安全级别"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    MILITARY = "military"


class InputValidator:
    """输入验证器"""

    # 正则表达式模式
    USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{3,32}$')
    EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    IP_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    HEX_PATTERN = re.compile(r'^[0-9a-fA-F]+$')

    # 危险字符
    DANGEROUS_CHARS = ['<', '>', '"', "'", '&', ';', '|', '`', '$', '(', ')', '{', '}', '[', ']']

    # SQL注入关键字
    SQL_KEYWORDS = [
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER',
        'EXEC', 'EXECUTE', 'SCRIPT', 'UNION', 'OR', 'AND', '--', '/*', '*/'
    ]

    @classmethod
    def validate_username(cls, username: str, strict: bool = True) -> str:
        """
        验证用户名

        Args:
            username: 用户名
            strict: 是否严格模式

        Returns:
            清理后的用户名

        Raises:
            ValidationError: 验证失败
        """
        if not username:
            raise ValidationError("Username cannot be empty")

        # 清理空白字符
        username = username.strip()

        # 长度检查
        if len(username) < 3:
            raise ValidationError("Username too short (minimum 3 characters)")

        if len(username) > 32:
            raise ValidationError("Username too long (maximum 32 characters)")

        # 格式检查
        if strict and not cls.USERNAME_PATTERN.match(username):
            raise ValidationError(
                "Username must contain only letters, numbers, underscores and hyphens"
            )

        # 检查危险字符
        if any(char in username for char in cls.DANGEROUS_CHARS):
            raise ValidationError("Username contains dangerous characters")

        # 检查SQL注入
        username_upper = username.upper()
        if any(keyword in username_upper for keyword in cls.SQL_KEYWORDS):
            raise ValidationError("Username contains forbidden keywords")

        return username

    @classmethod
    def validate_message(cls, message: str, max_length: int = 10000) -> str:
        """
        验证聊天消息

        Args:
            message: 消息内容
            max_length: 最大长度

        Returns:
            清理后的消息

        Raises:
            ValidationError: 验证失败
        """
        if not message:
            raise ValidationError("Message cannot be empty")

        # 长度检查
        if len(message) > max_length:
            raise ValidationError(f"Message too long (maximum {max_length} characters)")

        # 检查控制字符
        if any(ord(char) < 32 and char not in ['\n', '\r', '\t'] for char in message):
            raise ValidationError("Message contains control characters")

        # 规范化Unicode
        message = unicodedata.normalize('NFKC', message)

        return message

    @classmethod
    def validate_ip_address(cls, ip: str) -> str:
        """
        验证IP地址

        Args:
            ip: IP地址

        Returns:
            验证后的IP地址

        Raises:
            ValidationError: 验证失败
        """
        if not cls.IP_PATTERN.match(ip):
            raise ValidationError("Invalid IP address format")

        # 检查每个八位组
        octets = ip.split('.')
        for octet in octets:
            value = int(octet)
            if value < 0 or value > 255:
                raise ValidationError("IP address octet out of range")

        return ip

    @classmethod
    def validate_hex_string(cls, hex_str: str, expected_length: Optional[int] = None) -> str:
        """
        验证十六进制字符串

        Args:
            hex_str: 十六进制字符串
            expected_length: 期望的字节长度

        Returns:
            验证后的十六进制字符串

        Raises:
            ValidationError: 验证失败
        """
        if not cls.HEX_PATTERN.match(hex_str):
            raise ValidationError("Invalid hexadecimal string")

        if expected_length is not None:
            actual_length = len(hex_str) // 2
            if actual_length != expected_length:
                raise ValidationError(
                    f"Hexadecimal string length mismatch (expected {expected_length} bytes, got {actual_length})"
                )

        return hex_str.lower()

    @classmethod
    def sanitize_html(cls, text: str) -> str:
        """
        清理HTML（防止XSS）

        Args:
            text: 输入文本

        Returns:
            清理后的文本
        """
        return html.escape(text)

    @classmethod
    def validate_json_keys(cls, data: dict, allowed_keys: List[str], required_keys: Optional[List[str]] = None):
        """
        验证JSON键

        Args:
            data: JSON数据
            allowed_keys: 允许的键列表
            required_keys: 必需的键列表

        Raises:
            ValidationError: 验证失败
        """
        # 检查未知键
        unknown_keys = set(data.keys()) - set(allowed_keys)
        if unknown_keys:
            raise ValidationError(f"Unknown keys: {unknown_keys}")

        # 检查必需键
        if required_keys:
            missing_keys = set(required_keys) - set(data.keys())
            if missing_keys:
                raise ValidationError(f"Missing required keys: {missing_keys}")

    @classmethod
    def validate_port(cls, port: int) -> int:
        """
        验证端口号

        Args:
            port: 端口号

        Returns:
            端口号

        Raises:
            ValidationError: 验证失败
        """
        if not isinstance(port, int):
            raise ValidationError("Port must be an integer")

        if port < 1 or port > 65535:
            raise ValidationError("Port out of range (1-65535)")

        # 检查特权端口（可选）
        if port < 1024:
            # 警告但不拒绝
            pass

        return port


class ContentFilter:
    """内容过滤器"""

    # 敏感关键字（示例）
    SENSITIVE_KEYWORDS = [
        'password', 'secret', 'private_key', 'api_key', 'token',
        'credential', 'auth', 'admin'
    ]

    @classmethod
    def contains_sensitive_info(cls, text: str) -> bool:
        """检查是否包含敏感信息"""
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in cls.SENSITIVE_KEYWORDS)

    @classmethod
    def redact_sensitive_info(cls, text: str) -> str:
        """屏蔽敏感信息"""
        # 屏蔽看起来像密钥的字符串
        text = re.sub(r'[A-Za-z0-9]{32,}', '[REDACTED]', text)

        # 屏蔽看起来像密码的字符串
        text = re.sub(r'(password|pwd|pass)\s*[:=]\s*\S+', r'\1: [REDACTED]', text, flags=re.IGNORECASE)

        return text


class SecurityPolicy:
    """安全策略"""

    # 不同安全级别的参数
    POLICY_PARAMS = {
        SecurityLevel.LOW: {
            'min_password_length': 6,
            'require_special_chars': False,
            'max_login_attempts': 10,
            'session_timeout_minutes': 480,  # 8小时
            'require_mfa': False
        },
        SecurityLevel.MEDIUM: {
            'min_password_length': 8,
            'require_special_chars': True,
            'max_login_attempts': 5,
            'session_timeout_minutes': 120,  # 2小时
            'require_mfa': False
        },
        SecurityLevel.HIGH: {
            'min_password_length': 12,
            'require_special_chars': True,
            'max_login_attempts': 3,
            'session_timeout_minutes': 60,  # 1小时
            'require_mfa': True
        },
        SecurityLevel.MILITARY: {
            'min_password_length': 16,
            'require_special_chars': True,
            'max_login_attempts': 3,
            'session_timeout_minutes': 30,  # 30分钟
            'require_mfa': True
        }
    }

    def __init__(self, level: SecurityLevel = SecurityLevel.MILITARY):
        """
        初始化安全策略

        Args:
            level: 安全级别
        """
        self.level = level
        self.params = self.POLICY_PARAMS[level]

    def validate_password(self, password: str) -> Tuple[bool, str]:
        """
        验证密码强度

        Args:
            password: 密码

        Returns:
            (是否有效, 错误消息)
        """
        min_length = self.params['min_password_length']

        if len(password) < min_length:
            return False, f"Password too short (minimum {min_length} characters)"

        # 检查字符类型
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)

        if self.params['require_special_chars']:
            has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password)

            if not (has_upper and has_lower and has_digit and has_special):
                return False, "Password must contain uppercase, lowercase, digit and special character"
        else:
            if not (has_upper and has_lower and has_digit):
                return False, "Password must contain uppercase, lowercase and digit"

        return True, "Password valid"

    def get_session_timeout(self) -> int:
        """获取会话超时时间（秒）"""
        return self.params['session_timeout_minutes'] * 60

    def get_max_login_attempts(self) -> int:
        """获取最大登录尝试次数"""
        return self.params['max_login_attempts']

    def requires_mfa(self) -> bool:
        """是否要求多因素认证"""
        return self.params['require_mfa']


class DataSanitizer:
    """数据清理器"""

    @staticmethod
    def remove_null_bytes(data: bytes) -> bytes:
        """移除空字节"""
        return data.replace(b'\x00', b'')

    @staticmethod
    def truncate_string(text: str, max_length: int, suffix: str = '...') -> str:
        """截断字符串"""
        if len(text) <= max_length:
            return text

        return text[:max_length - len(suffix)] + suffix

    @staticmethod
    def normalize_whitespace(text: str) -> str:
        """规范化空白字符"""
        # 将多个空白字符替换为单个空格
        return ' '.join(text.split())

    @staticmethod
    def remove_control_chars(text: str) -> str:
        """移除控制字符"""
        return ''.join(char for char in text if ord(char) >= 32 or char in ['\n', '\r', '\t'])


# 便捷函数
def validate_and_sanitize_username(username: str) -> str:
    """验证并清理用户名"""
    return InputValidator.validate_username(username)


def validate_and_sanitize_message(message: str) -> str:
    """验证并清理消息"""
    message = InputValidator.validate_message(message)
    message = DataSanitizer.normalize_whitespace(message)
    return message


def is_safe_input(text: str, allow_special: bool = False) -> bool:
    """检查输入是否安全"""
    try:
        if not allow_special:
            # 检查危险字符
            if any(char in text for char in InputValidator.DANGEROUS_CHARS):
                return False

        # 检查SQL注入
        text_upper = text.upper()
        if any(keyword in text_upper for keyword in InputValidator.SQL_KEYWORDS):
            return False

        return True

    except Exception:
        return False
