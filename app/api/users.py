from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from ..models.schemas import UserCreate, UserInfo, UserRegistrationResponse
from ..models.database import User, TOTPSecret
from ..db.database import get_db
from ..utils.security import SecurityManager
from ..utils.totp import TOTPManager, SecretEncryption
from ..auth.auth import get_current_user

router = APIRouter(prefix="/api/v1/users", tags=["users"])


@router.post("/register",
             response_model=UserRegistrationResponse,
             status_code=status.HTTP_201_CREATED)
def register_user(user_data: UserCreate, db: Session = Depends(get_db)):
    """
    注册新用户并生成TOTP密钥
    """
    # 检查用户名是否已存在
    existing_user = db.query(User).filter(
        User.username == user_data.username).first()
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="用户名已被使用")

    # 检查邮箱是否已存在
    existing_email = db.query(User).filter(
        User.email == user_data.email).first()
    if existing_email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="邮箱已被使用")

    # 创建新用户
    hashed_password = SecurityManager.get_password_hash(user_data.password)
    new_user = User(username=user_data.username,
                    email=user_data.email,
                    password_hash=hashed_password)

    db.add(new_user)
    db.flush()  # 获取用户ID但不提交事务

    # 生成TOTP密钥
    totp_secret = TOTPManager.generate_totp_secret()
    totp_uri = TOTPManager.get_totp_uri(totp_secret, user_data.username)
    qr_code = TOTPManager.generate_qr_code(totp_uri)

    # 加密存储TOTP密钥
    encrypted_secret = SecretEncryption.encrypt_secret(totp_secret)
    new_totp_secret = TOTPSecret(user_id=new_user.id,
                                 secret_key=encrypted_secret,
                                 is_active=True)

    db.add(new_totp_secret)
    db.commit()

    # 返回用户信息和TOTP密钥
    return {
        "user_id": new_user.id,
        "totp_secret": totp_secret,
        "totp_uri": totp_uri,
        "qr_code": qr_code
    }


@router.get("/me", response_model=UserInfo)
def get_current_user(current_user: User = Depends(get_current_user)):
    """
    获取当前认证用户的信息
    """
    # 检查用户是否启用了2FA
    is_2fa_enabled = any(secret.is_active
                         for secret in current_user.totp_secrets)

    return {
        "user_id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "is_2fa_enabled": is_2fa_enabled,
        "created_at": current_user.created_at,
        "updated_at": current_user.updated_at
    }
