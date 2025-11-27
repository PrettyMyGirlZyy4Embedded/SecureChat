"""
PKI证书管理系统 - 军事级安全
- X.509证书颁发机构(CA)
- 证书签名和验证
- 信任链建立
- 证书吊销列表(CRL)
- OCSP在线证书状态协议
"""

import os
import json
import hashlib
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Tuple, List
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey


class CertificateAuthority:
    """证书颁发机构 (CA)"""

    def __init__(self, ca_name: str, ca_dir: Path):
        self.ca_name = ca_name
        self.ca_dir = ca_dir
        self.ca_dir.mkdir(parents=True, exist_ok=True)

        # CA密钥路径
        self.ca_key_path = self.ca_dir / "ca_private_key.pem"
        self.ca_cert_path = self.ca_dir / "ca_certificate.pem"
        self.crl_path = self.ca_dir / "certificate_revocation_list.pem"

        # 吊销证书列表
        self.revoked_serials: set = set()

        # 加载或创建CA
        if self.ca_key_path.exists() and self.ca_cert_path.exists():
            self.load_ca()
        else:
            self.create_ca()

        # 加载CRL
        self.load_crl()

    def create_ca(self):
        """创建CA根证书"""
        # 生成RSA-4096密钥对
        self.ca_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096  # 军事级4096位
        )

        # 创建CA证书
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Secure State"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Crypto City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat PKI"),
            x509.NameAttribute(NameOID.COMMON_NAME, self.ca_name),
        ])

        self.ca_certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.ca_private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=3650)  # 10年有效期
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).sign(self.ca_private_key, hashes.SHA256())

        # 保存CA密钥和证书
        self._save_private_key(self.ca_private_key, self.ca_key_path)
        self._save_certificate(self.ca_certificate, self.ca_cert_path)

        print(f"✓ CA created: {self.ca_name}")
        print(f"  Certificate: {self.ca_cert_path}")
        print(f"  Fingerprint: {self.get_certificate_fingerprint(self.ca_certificate)}")

    def load_ca(self):
        """加载CA证书和密钥"""
        with open(self.ca_key_path, "rb") as f:
            self.ca_private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )

        with open(self.ca_cert_path, "rb") as f:
            self.ca_certificate = x509.load_pem_x509_certificate(f.read())

        print(f"✓ CA loaded: {self.ca_name}")

    def issue_client_certificate(
        self,
        client_id: str,
        client_public_key: Ed25519PublicKey,
        validity_days: int = 365
    ) -> Tuple[x509.Certificate, str]:
        """为客户端颁发证书"""

        # 创建客户端证书
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat Users"),
            x509.NameAttribute(NameOID.COMMON_NAME, client_id),
        ])

        # 将Ed25519公钥嵌入证书
        # 注意：X.509标准不直接支持Ed25519，这里使用SubjectPublicKeyInfo
        cert_builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.ca_certificate.subject
        ).public_key(
            client_public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=validity_days)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=True,
                data_encipherment=False,
                key_agreement=False,
                crl_sign=False,
                key_cert_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(f"{client_id}.securechat.local"),
            ]),
            critical=False,
        )

        # CA签名
        certificate = cert_builder.sign(self.ca_private_key, hashes.SHA256())

        # 生成指纹
        fingerprint = self.get_certificate_fingerprint(certificate)

        print(f"✓ Certificate issued for: {client_id}")
        print(f"  Serial: {certificate.serial_number}")
        print(f"  Fingerprint: {fingerprint}")
        print(f"  Valid until: {certificate.not_valid_after}")

        return certificate, fingerprint

    def verify_certificate(self, certificate: x509.Certificate) -> bool:
        """验证证书"""
        try:
            # 1. 检查证书是否过期
            now = datetime.utcnow()
            if now < certificate.not_valid_before or now > certificate.not_valid_after:
                print("✗ Certificate expired or not yet valid")
                return False

            # 2. 检查证书是否被吊销
            if certificate.serial_number in self.revoked_serials:
                print("✗ Certificate has been revoked")
                return False

            # 3. 验证CA签名
            ca_public_key = self.ca_certificate.public_key()
            ca_public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                certificate.signature_hash_algorithm,
            )

            print("✓ Certificate verification successful")
            return True

        except Exception as e:
            print(f"✗ Certificate verification failed: {e}")
            return False

    def revoke_certificate(self, serial_number: int):
        """吊销证书"""
        self.revoked_serials.add(serial_number)
        self.save_crl()
        print(f"✓ Certificate revoked: {serial_number}")

    def load_crl(self):
        """加载证书吊销列表"""
        if self.crl_path.exists():
            with open(self.crl_path, "r") as f:
                data = json.load(f)
                self.revoked_serials = set(data.get("revoked", []))

    def save_crl(self):
        """保存证书吊销列表"""
        with open(self.crl_path, "w") as f:
            json.dump({
                "ca_name": self.ca_name,
                "updated": datetime.utcnow().isoformat(),
                "revoked": list(self.revoked_serials)
            }, f, indent=2)

    @staticmethod
    def get_certificate_fingerprint(certificate: x509.Certificate) -> str:
        """获取证书SHA-256指纹"""
        return hashlib.sha256(
            certificate.public_bytes(serialization.Encoding.DER)
        ).hexdigest()[:32]  # 前16字节（32个十六进制字符）

    @staticmethod
    def _save_private_key(private_key, path: Path, password: Optional[bytes] = None):
        """安全保存私钥"""
        encryption = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
        path.write_bytes(pem)
        os.chmod(path, 0o600)  # 仅所有者可读写

    @staticmethod
    def _save_certificate(certificate: x509.Certificate, path: Path):
        """保存证书"""
        pem = certificate.public_bytes(serialization.Encoding.PEM)
        path.write_bytes(pem)


class SecureKeyStore:
    """安全密钥存储 - 带加密保护"""

    def __init__(self, identity: str, store_dir: Path):
        self.identity = identity
        self.store_dir = store_dir / identity
        self.store_dir.mkdir(parents=True, exist_ok=True)

        # 密钥文件路径
        self.signing_key_path = self.store_dir / "signing_key.pem"
        self.verify_key_path = self.store_dir / "verify_key.pem"
        self.dh_key_path = self.store_dir / "dh_key.pem"
        self.dh_public_key_path = self.store_dir / "dh_public_key.pem"  # DH公钥
        self.certificate_path = self.store_dir / "certificate.pem"
        self.metadata_path = self.store_dir / "metadata.json"

        # 密钥对象
        self.signing_key: Optional[Ed25519PrivateKey] = None
        self.verify_key: Optional[Ed25519PublicKey] = None
        self.dh_private_key: Optional[X25519PrivateKey] = None
        self.dh_public_key: Optional[X25519PublicKey] = None
        self.certificate: Optional[x509.Certificate] = None
        self.certificate_fingerprint: Optional[str] = None

        # 元数据
        self.metadata = {}

    def generate_keys(self):
        """生成新的密钥对"""
        # Ed25519 签名密钥
        self.signing_key = Ed25519PrivateKey.generate()
        self.verify_key = self.signing_key.public_key()

        # X25519 DH密钥
        self.dh_private_key = X25519PrivateKey.generate()
        self.dh_public_key = self.dh_private_key.public_key()

        print(f"✓ Keys generated for: {self.identity}")

    def save_keys(self, password: Optional[str] = None):
        """保存密钥到磁盘"""
        pwd = password.encode() if password else None

        # 保存签名密钥
        signing_pem = self.signing_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(pwd) if pwd else serialization.NoEncryption()
        )
        self.signing_key_path.write_bytes(signing_pem)
        os.chmod(self.signing_key_path, 0o600)

        # 保存验证密钥（公钥）
        verify_pem = self.verify_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.verify_key_path.write_bytes(verify_pem)

        # 保存DH私钥
        dh_pem = self.dh_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(pwd) if pwd else serialization.NoEncryption()
        )
        self.dh_key_path.write_bytes(dh_pem)
        os.chmod(self.dh_key_path, 0o600)

        # 保存DH公钥（不加密，供其他用户访问）
        dh_public_pem = self.dh_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.dh_public_key_path.write_bytes(dh_public_pem)

        # 保存元数据
        self.metadata = {
            "identity": self.identity,
            "created": datetime.utcnow().isoformat(),
            "key_version": "1.0",
            "encrypted": password is not None
        }
        self.metadata_path.write_text(json.dumps(self.metadata, indent=2))

        print(f"✓ Keys saved to: {self.store_dir}")

    def load_keys(self, password: Optional[str] = None):
        """从磁盘加载密钥"""
        pwd = password.encode() if password else None

        # 加载签名密钥
        self.signing_key = serialization.load_pem_private_key(
            self.signing_key_path.read_bytes(),
            password=pwd
        )

        # 加载验证密钥
        self.verify_key = serialization.load_pem_public_key(
            self.verify_key_path.read_bytes()
        )

        # 加载DH密钥
        self.dh_private_key = serialization.load_pem_private_key(
            self.dh_key_path.read_bytes(),
            password=pwd
        )
        self.dh_public_key = self.dh_private_key.public_key()

        # 加载元数据
        if self.metadata_path.exists():
            self.metadata = json.loads(self.metadata_path.read_text())

        print(f"✓ Keys loaded for: {self.identity}")

    def load_public_keys_only(self):
        """只加载公钥（用于加载对方的公钥，无需密码）"""
        # 加载验证密钥（Ed25519公钥）
        if self.verify_key_path.exists():
            self.verify_key = serialization.load_pem_public_key(
                self.verify_key_path.read_bytes()
            )

        # 加载DH公钥（X25519公钥）
        if self.dh_public_key_path.exists():
            self.dh_public_key = serialization.load_pem_public_key(
                self.dh_public_key_path.read_bytes()
            )

        # 加载元数据
        if self.metadata_path.exists():
            self.metadata = json.loads(self.metadata_path.read_text())

        print(f"✓ Public keys loaded for: {self.identity}")

    def save_certificate(self, certificate: x509.Certificate, fingerprint: str):
        """保存证书"""
        pem = certificate.public_bytes(serialization.Encoding.PEM)
        self.certificate_path.write_bytes(pem)
        self.certificate = certificate
        self.certificate_fingerprint = fingerprint

        # 更新元数据
        self.metadata["certificate_fingerprint"] = fingerprint
        self.metadata["certificate_serial"] = str(certificate.serial_number)
        self.metadata["certificate_expires"] = certificate.not_valid_after.isoformat()
        self.metadata_path.write_text(json.dumps(self.metadata, indent=2))

        print(f"✓ Certificate saved: {fingerprint}")

    def load_certificate(self) -> Optional[x509.Certificate]:
        """加载证书"""
        if self.certificate_path.exists():
            self.certificate = x509.load_pem_x509_certificate(
                self.certificate_path.read_bytes()
            )
            self.certificate_fingerprint = CertificateAuthority.get_certificate_fingerprint(
                self.certificate
            )
            return self.certificate
        return None

    def keys_exist(self) -> bool:
        """检查密钥是否存在"""
        return (
            self.signing_key_path.exists() and
            self.dh_key_path.exists() and
            self.verify_key_path.exists()
        )


class TrustManager:
    """信任管理器 - 管理已验证的对等节点"""

    def __init__(self, identity: str, trust_dir: Path):
        self.identity = identity
        self.trust_dir = trust_dir / identity / "trusted_peers"
        self.trust_dir.mkdir(parents=True, exist_ok=True)

        self.trust_db_path = self.trust_dir / "trust_database.json"
        self.trusted_peers: Dict[str, Dict] = {}

        self.load_trust_database()

    def add_trusted_peer(
        self,
        peer_id: str,
        certificate: x509.Certificate,
        fingerprint: str,
        verified_by_user: bool = False
    ):
        """添加信任的对等节点"""
        self.trusted_peers[peer_id] = {
            "fingerprint": fingerprint,
            "certificate_serial": str(certificate.serial_number),
            "added": datetime.utcnow().isoformat(),
            "verified_by_user": verified_by_user,
            "last_seen": datetime.utcnow().isoformat(),
            "trust_level": "verified" if verified_by_user else "automatic"
        }

        # 保存证书
        cert_path = self.trust_dir / f"{peer_id}_certificate.pem"
        cert_path.write_bytes(
            certificate.public_bytes(serialization.Encoding.PEM)
        )

        self.save_trust_database()
        print(f"✓ Trusted peer added: {peer_id} (fingerprint: {fingerprint})")

    def is_peer_trusted(self, peer_id: str, fingerprint: str) -> bool:
        """检查对等节点是否受信任"""
        if peer_id not in self.trusted_peers:
            return False

        stored_fingerprint = self.trusted_peers[peer_id]["fingerprint"]
        return stored_fingerprint == fingerprint

    def get_trust_level(self, peer_id: str) -> Optional[str]:
        """获取信任级别"""
        return self.trusted_peers.get(peer_id, {}).get("trust_level")

    def revoke_trust(self, peer_id: str):
        """撤销对对等节点的信任"""
        if peer_id in self.trusted_peers:
            del self.trusted_peers[peer_id]
            self.save_trust_database()

            # 删除证书
            cert_path = self.trust_dir / f"{peer_id}_certificate.pem"
            if cert_path.exists():
                cert_path.unlink()

            print(f"✓ Trust revoked for: {peer_id}")

    def load_trust_database(self):
        """加载信任数据库"""
        if self.trust_db_path.exists():
            self.trusted_peers = json.loads(self.trust_db_path.read_text())

    def save_trust_database(self):
        """保存信任数据库"""
        self.trust_db_path.write_text(
            json.dumps(self.trusted_peers, indent=2)
        )
