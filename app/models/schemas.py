from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional, List, Dict, Any
from datetime import datetime

# 用户注册请求模型
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)
    email: EmailStr

# 用户登录请求模型
class UserLogin(BaseModel):
    username: str
    password: str

# TOTP验证请求模型
class TOTPVerify(BaseModel):
    temp_token: str
    totp_code: str = Field(..., min_length=6, max_length=6, pattern=r'^\d{6}$')
    trust_device: Optional[bool] = False
    device_name: Optional[str] = None

    @validator('device_name')
    def validate_device_name(cls, v, values):
        if values.get('trust_device') and (v is None or v.strip() == ''):
            return "未命名设备"
        return v

# TOTP密钥登录请求模型
class TOTPSecretLogin(BaseModel):
    username: str
    password: str
    totp_secret: str
    trust_device: Optional[bool] = False
    device_name: Optional[str] = None

    @validator('device_name')
    def validate_device_name(cls, v, values):
        if values.get('trust_device') and (v is None or v.strip() == ''):
            return "未命名设备"
        return v

# 设备登录请求模型
class DeviceLogin(BaseModel):
    username: str
    password: str
    device_token: str

# 用户信息响应模型
class UserInfo(BaseModel):
    user_id: int
    username: str
    email: EmailStr
    is_2fa_enabled: bool
    created_at: datetime
    updated_at: datetime

# 用户注册响应模型
class UserRegistrationResponse(BaseModel):
    user_id: int
    totp_secret: str
    totp_uri: str
    qr_code: str  # Base64编码的二维码图像

# 登录第一步响应模型
class LoginStepOneResponse(BaseModel):
    temp_token: str
    requires_2fa: bool
    expires_in: int  # 临时令牌过期时间（秒）

# 登录第二步响应模型
class LoginStepTwoResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int  # 访问令牌过期时间（秒）
    device_token: Optional[str] = None  # 设备信任令牌，仅当请求信任设备时返回

# 设备登录响应模型
class DeviceLoginResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int  # 访问令牌过期时间（秒）

# 信任设备信息模型
class TrustedDeviceInfo(BaseModel):
    id: int
    device_name: str
    last_used_at: datetime
    expires_at: datetime
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    created_at: datetime

# 信任设备列表响应模型
class TrustedDevicesResponse(BaseModel):
    devices: List[TrustedDeviceInfo]

# TOTP重置响应模型
class TOTPResetResponse(BaseModel):
    totp_secret: str
    totp_uri: str
    qr_code: str  # Base64编码的二维码图像

# 错误响应模型
class ErrorResponse(BaseModel):
    detail: str
    error_code: Optional[str] = None

# 通用消息响应模型
class MessageResponse(BaseModel):
    message: str
