from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime, Text, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import expression
from datetime import datetime, timezone

Base = declarative_base()


class User(Base):
    """用户表"""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(100), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime,
                        default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))

    # 关系
    totp_secrets = relationship("TOTPSecret",
                                back_populates="user",
                                cascade="all, delete-orphan")
    auth_sessions = relationship("AuthSession",
                                 back_populates="user",
                                 cascade="all, delete-orphan")
    auth_attempts = relationship("AuthAttempt",
                                 back_populates="user",
                                 cascade="all, delete-orphan")


class TOTPSecret(Base):
    """TOTP密钥表"""
    __tablename__ = "totp_secrets"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer,
                     ForeignKey("users.id", ondelete="CASCADE"),
                     nullable=False,
                     index=True)
    secret_key = Column(String(255), nullable=False)  # 加密存储的TOTP密钥
    is_active = Column(Boolean,
                       default=True,
                       server_default=expression.true(),
                       index=True)
    is_verified = Column(Boolean,
                         default=False,
                         server_default=expression.false())  # 是否已验证
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime,
                        default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="totp_secrets")


class AuthSession(Base):
    """认证会话表"""
    __tablename__ = "auth_sessions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer,
                     ForeignKey("users.id", ondelete="CASCADE"),
                     nullable=False,
                     index=True)
    temp_token = Column(String(255), unique=True, nullable=True, index=True)
    access_token = Column(String(255), unique=True, nullable=True, index=True)
    temp_token_expires_at = Column(DateTime, nullable=True)
    access_token_expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="auth_sessions")


class AuthAttempt(Base):
    """认证尝试记录表"""
    __tablename__ = "auth_attempts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer,
                     ForeignKey("users.id", ondelete="CASCADE"),
                     nullable=False,
                     index=True)
    ip_address = Column(String(45), nullable=True)
    success = Column(Boolean, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    user = relationship("User", back_populates="auth_attempts")


class TrustedDevice(Base):
    """信任设备表"""
    __tablename__ = "trusted_devices"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer,
                     ForeignKey("users.id", ondelete="CASCADE"),
                     nullable=False,
                     index=True)
    device_identifier = Column(String(255), nullable=False, index=True)
    device_name = Column(String(100), nullable=False)
    device_token = Column(String(255), nullable=False)
    last_used_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, nullable=False, index=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
