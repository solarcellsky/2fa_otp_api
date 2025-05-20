import pyotp
import qrcode
import io
import base64
import hashlib
import os
import json
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from typing import Dict, Any, Optional
import logging

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecretEncryption:
    """
    TOTP密钥和设备令牌加密工具类
    使用AES-256-GCM加密算法
    """
    # 从环境变量获取密钥，如果不存在则使用默认值（仅用于开发环境）
    # 生产环境应使用安全的密钥管理系统
    ENCRYPTION_KEY = os.getenv('TOTP_ENCRYPTION_KEY', 'your-secret-key-must-be-32-bytes-long!')
    SALT = os.getenv('TOTP_ENCRYPTION_SALT', 'your-salt-value-here')
    
    @classmethod
    def _derive_key(cls) -> bytes:
        """
        从主密钥派生加密密钥
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256位密钥
            salt=cls.SALT.encode(),
            iterations=100000,
        )
        return kdf.derive(cls.ENCRYPTION_KEY.encode())
    
    @classmethod
    def encrypt_secret(cls, secret: str) -> str:
        """
        加密TOTP密钥或设备令牌
        """
        try:
            # 生成随机nonce
            nonce = os.urandom(12)
            
            # 派生密钥
            key = cls._derive_key()
            
            # 创建AESGCM实例
            aesgcm = AESGCM(key)
            
            # 加密数据
            ciphertext = aesgcm.encrypt(nonce, secret.encode(), None)
            
            # 将nonce和密文合并并进行base64编码
            encrypted_data = base64.b64encode(nonce + ciphertext).decode('utf-8')
            
            return encrypted_data
        except Exception as e:
            logger.error(f"加密失败: {str(e)}")
            raise ValueError(f"加密失败: {str(e)}")
    
    @classmethod
    def decrypt_secret(cls, encrypted_secret: str) -> str:
        """
        解密TOTP密钥或设备令牌
        """
        try:
            # 解码base64数据
            encrypted_data = base64.b64decode(encrypted_secret)
            
            # 提取nonce和密文
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            
            # 派生密钥
            key = cls._derive_key()
            
            # 创建AESGCM实例
            aesgcm = AESGCM(key)
            
            # 解密数据
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            return plaintext.decode('utf-8')
        except Exception as e:
            logger.error(f"解密失败: {str(e)}")
            raise ValueError(f"解密失败: {str(e)}")

class TOTPManager:
    """
    TOTP管理工具类
    负责生成和验证TOTP密钥和验证码
    """
    @staticmethod
    def generate_totp_secret() -> str:
        """
        生成新的TOTP密钥
        """
        return pyotp.random_base32()
    
    @staticmethod
    def get_totp_uri(secret: str, username: str, issuer: str = "2FA+TOTP认证系统") -> str:
        """
        生成TOTP URI，用于生成二维码
        """
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(name=username, issuer_name=issuer)
    
    @staticmethod
    def generate_qr_code(uri: str) -> str:
        """
        生成TOTP二维码图像，返回base64编码的图像数据
        """
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # 将图像转换为base64编码
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        return base64.b64encode(buffer.getvalue()).decode('utf-8')
    
    @staticmethod
    def verify_totp(secret: str, code: str) -> bool:
        """
        验证TOTP验证码
        """
        totp = pyotp.TOTP(secret)
        return totp.verify(code)

class DeviceManager:
    """
    设备管理工具类
    负责生成和验证设备标识符和令牌
    """
    @staticmethod
    def generate_device_identifier(request_info: Dict[str, Any]) -> str:
        """
        生成设备标识符
        基于IP地址和用户代理等信息
        """
        # 获取请求信息
        ip_address = request_info.get('ip_address', '')
        user_agent = request_info.get('user_agent', '')
        
        # 组合信息并哈希
        device_info = f"{ip_address}|{user_agent}"
        device_hash = hashlib.sha256(device_info.encode()).hexdigest()
        
        return device_hash
    
    @staticmethod
    def generate_device_token() -> str:
        """
        生成设备令牌
        """
        # 生成32字节的随机令牌
        token_bytes = os.urandom(32)
        return base64.b64encode(token_bytes).decode('utf-8')
    
    @staticmethod
    def calculate_expiry_date(days: int = 30) -> datetime:
        """
        计算设备令牌过期时间
        默认30天
        """
        return datetime.utcnow() + timedelta(days=days)
