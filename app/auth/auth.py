from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from ..models.schemas import UserLogin, LoginStepOneResponse, TOTPVerify, LoginStepTwoResponse, DeviceLogin, DeviceLoginResponse, TrustedDeviceInfo, TrustedDevicesResponse, MessageResponse, TOTPSecretLogin, TOTPResetResponse
from ..models.database import User, TOTPSecret, AuthSession, AuthAttempt, TrustedDevice
from ..db.database import get_db, settings
from ..utils.security import SecurityManager
from ..utils.totp import TOTPManager, SecretEncryption, DeviceManager
from fastapi.security import OAuth2PasswordBearer
from typing import List, Optional
from sqlalchemy import and_, func
import logging

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

# OAuth2密码流依赖
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/auth/verify")


# 获取当前用户的依赖函数
def get_current_user(token: str = Depends(oauth2_scheme),
                     db: Session = Depends(get_db)):
    """
    从访问令牌中获取当前用户
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="无效的认证凭据",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        # 解码令牌
        payload = SecurityManager.decode_token(token)
        user_id = payload.get("sub")
        if user_id is None:
            raise credentials_exception

        # 检查令牌是否为临时令牌
        if payload.get("temp", False):
            raise credentials_exception

        # 检查令牌是否过期
        if SecurityManager.is_token_expired(token):
            raise credentials_exception

        # 从数据库获取用户
        user = db.query(User).filter(User.id == user_id).first()
        if user is None:
            raise credentials_exception

        return user

    except ValueError:
        raise credentials_exception


@router.post("/login", response_model=LoginStepOneResponse)
def login_step_one(user_data: UserLogin,
                   request: Request,
                   db: Session = Depends(get_db)):
    """
    用户登录第一步：验证用户名和密码，返回临时令牌
    """
    # 获取客户端IP地址
    client_ip = request.client.host

    # 查找用户
    user = db.query(User).filter(User.username == user_data.username).first()

    # 检查用户是否存在
    if not user:
        # 记录失败尝试
        db.add(
            AuthAttempt(
                user_id=0,  # 用户不存在，使用0作为占位符
                ip_address=client_ip,
                success=False))
        db.commit()

        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="用户名或密码错误")

    # 检查密码是否正确
    if not SecurityManager.verify_password(user_data.password,
                                           user.password_hash):
        # 记录失败尝试
        db.add(
            AuthAttempt(user_id=user.id, ip_address=client_ip, success=False))
        db.commit()

        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="用户名或密码错误")

    # 检查是否启用了2FA
    active_totp = db.query(TOTPSecret).filter(
        TOTPSecret.user_id == user.id, TOTPSecret.is_active == True).first()

    requires_2fa = active_totp is not None

    # 创建临时令牌
    expires = timedelta(minutes=settings.TEMP_TOKEN_EXPIRE_MINUTES)
    temp_token = SecurityManager.create_temp_token(data={"sub": str(user.id)},
                                                   expires_delta=expires)

    # 保存临时令牌到数据库
    temp_token_expires = datetime.utcnow() + expires
    auth_session = AuthSession(user_id=user.id,
                               temp_token=temp_token,
                               temp_token_expires_at=temp_token_expires)
    db.add(auth_session)

    # 记录成功的登录尝试（第一步）
    db.add(AuthAttempt(user_id=user.id, ip_address=client_ip, success=True))

    db.commit()

    # 返回临时令牌和2FA状态
    return {
        "temp_token": temp_token,
        "requires_2fa": requires_2fa,
        "expires_in": settings.TEMP_TOKEN_EXPIRE_MINUTES * 60
    }


@router.post("/verify", response_model=LoginStepTwoResponse)
def verify_totp(verify_data: TOTPVerify,
                request: Request,
                db: Session = Depends(get_db)):
    """
    用户登录第二步：验证TOTP码，完成认证
    可选参数trust_device和device_name用于信任设备
    """
    # 获取客户端IP地址和用户代理
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "")

    # 解码临时令牌
    try:
        payload = SecurityManager.decode_token(verify_data.temp_token)
        user_id = payload.get("sub")

        # 检查是否为临时令牌
        if not payload.get("temp", False):
            raise ValueError("不是临时令牌")

        # 检查令牌是否过期
        if SecurityManager.is_token_expired(verify_data.temp_token):
            raise ValueError("令牌已过期")

    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail=f"无效的临时令牌: {str(e)}")

    # 查找用户和会话
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="用户不存在")

    # 查找会话
    session = db.query(AuthSession).filter(
        AuthSession.user_id == user.id,
        AuthSession.temp_token == verify_data.temp_token).first()

    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="无效的会话")

    # 查找活跃的TOTP密钥
    totp_secret = db.query(TOTPSecret).filter(
        TOTPSecret.user_id == user.id, TOTPSecret.is_active == True).first()

    if not totp_secret:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="用户未启用2FA")

    # 解密TOTP密钥
    decrypted_secret = SecretEncryption.decrypt_secret(totp_secret.secret_key)

    # 验证TOTP码
    if not TOTPManager.verify_totp(decrypted_secret, verify_data.totp_code):
        # 记录失败尝试
        db.add(
            AuthAttempt(user_id=user.id, ip_address=client_ip, success=False))
        db.commit()

        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="无效的TOTP验证码")

    # 创建访问令牌
    expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = SecurityManager.create_access_token(
        data={"sub": str(user.id)}, expires_delta=expires)

    # 更新会话
    access_token_expires = datetime.utcnow() + expires
    session.access_token = access_token
    session.access_token_expires_at = access_token_expires

    # 记录成功的登录尝试（第二步）
    db.add(AuthAttempt(user_id=user.id, ip_address=client_ip, success=True))

    # 处理设备信任
    device_token = None
    if verify_data.trust_device:
        try:
            # 生成设备标识符
            request_info = {'ip_address': client_ip, 'user_agent': user_agent}
            device_identifier = DeviceManager.generate_device_identifier(
                request_info)

            # 生成设备令牌
            raw_device_token = DeviceManager.generate_device_token()
            encrypted_device_token = SecretEncryption.encrypt_secret(
                raw_device_token)

            # 计算过期时间
            expires_at = DeviceManager.calculate_expiry_date()

            # 检查是否已存在相同设备标识符的信任设备
            existing_device = db.query(TrustedDevice).filter(
                TrustedDevice.user_id == user.id,
                TrustedDevice.device_identifier == device_identifier).first()

            if existing_device:
                # 更新现有设备
                existing_device.device_token = encrypted_device_token
                existing_device.device_name = verify_data.device_name or existing_device.device_name
                existing_device.last_used_at = datetime.utcnow()
                existing_device.expires_at = expires_at
                existing_device.ip_address = client_ip
                existing_device.user_agent = user_agent
                logger.info(
                    f"更新信任设备: user_id={user.id}, device_id={existing_device.id}"
                )
            else:
                # 创建新的信任设备
                device_name = verify_data.device_name or "未命名设备"
                new_device = TrustedDevice(user_id=user.id,
                                           device_identifier=device_identifier,
                                           device_name=device_name,
                                           device_token=encrypted_device_token,
                                           expires_at=expires_at,
                                           ip_address=client_ip,
                                           user_agent=user_agent)
                db.add(new_device)
                logger.info(
                    f"创建新信任设备: user_id={user.id}, device_name={device_name}")

            # 设置返回的设备令牌
            device_token = raw_device_token
        except Exception as e:
            logger.error(f"信任设备处理错误: {str(e)}")
            # 继续处理，不影响登录流程

    db.commit()

    # 返回访问令牌和可选的设备令牌
    response = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    }

    if device_token:
        response["device_token"] = device_token

    return response


@router.post("/device-login", response_model=DeviceLoginResponse)
def device_login(login_data: DeviceLogin,
                 request: Request,
                 db: Session = Depends(get_db)):
    """
    使用设备令牌登录，跳过TOTP验证
    """
    # 获取客户端IP地址和用户代理
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "")

    # 查找用户
    user = db.query(User).filter(User.username == login_data.username).first()

    # 检查用户是否存在
    if not user:
        # 记录失败尝试
        db.add(
            AuthAttempt(
                user_id=0,  # 用户不存在，使用0作为占位符
                ip_address=client_ip,
                success=False))
        db.commit()

        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="用户名或密码错误")

    # 检查密码是否正确
    if not SecurityManager.verify_password(login_data.password,
                                           user.password_hash):
        # 记录失败尝试
        db.add(
            AuthAttempt(user_id=user.id, ip_address=client_ip, success=False))
        db.commit()

        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="用户名或密码错误")

    # 生成设备标识符
    request_info = {'ip_address': client_ip, 'user_agent': user_agent}
    device_identifier = DeviceManager.generate_device_identifier(request_info)

    # 查找匹配的信任设备
    current_time = datetime.utcnow()
    trusted_devices = db.query(TrustedDevice).filter(
        TrustedDevice.user_id == user.id, TrustedDevice.expires_at
        > current_time).all()

    device_found = False
    for device in trusted_devices:
        try:
            # 解密设备令牌并比较
            decrypted_token = SecretEncryption.decrypt_secret(
                device.device_token)
            if decrypted_token == login_data.device_token:
                # 更新设备最后使用时间
                device.last_used_at = current_time
                device.ip_address = client_ip
                device.user_agent = user_agent
                device_found = True
                logger.info(
                    f"设备登录成功: user_id={user.id}, device_id={device.id}")
                break
        except Exception as e:
            logger.error(f"设备令牌解密错误: {str(e)}")
            # 解密失败，跳过此设备
            continue

    if not device_found:
        # 记录失败尝试
        db.add(
            AuthAttempt(user_id=user.id, ip_address=client_ip, success=False))
        db.commit()

        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="无效的设备令牌或设备未被信任")

    # 创建访问令牌
    expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = SecurityManager.create_access_token(
        data={"sub": str(user.id)}, expires_delta=expires)

    # 创建新会话
    access_token_expires = datetime.utcnow() + expires
    auth_session = AuthSession(user_id=user.id,
                               access_token=access_token,
                               access_token_expires_at=access_token_expires)
    db.add(auth_session)

    # 记录成功的登录尝试
    db.add(AuthAttempt(user_id=user.id, ip_address=client_ip, success=True))

    db.commit()

    # 返回访问令牌
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    }


@router.post("/totp-secret-login", response_model=LoginStepTwoResponse)
def login_with_totp_secret(login_data: TOTPSecretLogin,
                           request: Request,
                           db: Session = Depends(get_db)):
    """
    使用TOTP密钥直接登录（适用于丢失认证器应用的情况）
    """
    # 获取客户端IP地址
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "")

    # 查找用户
    user = db.query(User).filter(User.username == login_data.username).first()

    # 检查用户是否存在
    if not user:
        # 记录失败尝试
        db.add(
            AuthAttempt(
                user_id=0,  # 用户不存在，使用0作为占位符
                ip_address=client_ip,
                success=False))
        db.commit()

        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="用户名或密码错误")

    # 检查密码是否正确
    if not SecurityManager.verify_password(login_data.password,
                                           user.password_hash):
        # 记录失败尝试
        db.add(
            AuthAttempt(user_id=user.id, ip_address=client_ip, success=False))
        db.commit()

        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="用户名或密码错误")

    # 查找活跃的TOTP密钥
    totp_secret = db.query(TOTPSecret).filter(
        TOTPSecret.user_id == user.id, TOTPSecret.is_active == True).first()

    if not totp_secret:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="用户未启用2FA")

    # 解密TOTP密钥
    decrypted_secret = SecretEncryption.decrypt_secret(totp_secret.secret_key)

    # 验证提供的TOTP密钥是否匹配
    if decrypted_secret != login_data.totp_secret:
        # 记录失败尝试
        db.add(
            AuthAttempt(user_id=user.id, ip_address=client_ip, success=False))
        db.commit()

        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="无效的TOTP密钥")

    # 创建访问令牌
    expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = SecurityManager.create_access_token(
        data={"sub": str(user.id)}, expires_delta=expires)

    # 创建新会话
    access_token_expires = datetime.utcnow() + expires
    auth_session = AuthSession(user_id=user.id,
                               access_token=access_token,
                               access_token_expires_at=access_token_expires)
    db.add(auth_session)

    # 记录成功的登录尝试
    db.add(AuthAttempt(user_id=user.id, ip_address=client_ip, success=True))

    # 处理设备信任
    device_token = None
    if login_data.trust_device:
        try:
            # 生成设备标识符
            request_info = {'ip_address': client_ip, 'user_agent': user_agent}
            device_identifier = DeviceManager.generate_device_identifier(
                request_info)

            # 生成设备令牌
            raw_device_token = DeviceManager.generate_device_token()
            encrypted_device_token = SecretEncryption.encrypt_secret(
                raw_device_token)

            # 计算过期时间
            expires_at = DeviceManager.calculate_expiry_date()

            # 检查是否已存在相同设备标识符的信任设备
            existing_device = db.query(TrustedDevice).filter(
                TrustedDevice.user_id == user.id,
                TrustedDevice.device_identifier == device_identifier).first()

            if existing_device:
                # 更新现有设备
                existing_device.device_token = encrypted_device_token
                existing_device.device_name = login_data.device_name or existing_device.device_name
                existing_device.last_used_at = datetime.utcnow()
                existing_device.expires_at = expires_at
                existing_device.ip_address = client_ip
                existing_device.user_agent = user_agent
                logger.info(
                    f"更新信任设备: user_id={user.id}, device_id={existing_device.id}"
                )
            else:
                # 创建新的信任设备
                device_name = login_data.device_name or "未命名设备"
                new_device = TrustedDevice(user_id=user.id,
                                           device_identifier=device_identifier,
                                           device_name=device_name,
                                           device_token=encrypted_device_token,
                                           expires_at=expires_at,
                                           ip_address=client_ip,
                                           user_agent=user_agent)
                db.add(new_device)
                logger.info(
                    f"创建新信任设备: user_id={user.id}, device_name={device_name}")

            # 设置返回的设备令牌
            device_token = raw_device_token
        except Exception as e:
            logger.error(f"信任设备处理错误: {str(e)}")
            # 继续处理，不影响登录流程

    db.commit()

    # 返回访问令牌和可选的设备令牌
    response = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    }

    if device_token:
        response["device_token"] = device_token

    return response


@router.post("/verify-registration-totp", response_model=MessageResponse)
def verify_registration_totp(verify_data: TOTPVerify,
                             db: Session = Depends(get_db)):
    """
    验证注册后的TOTP设置是否正确
    """
    # 解码临时令牌
    try:
        payload = SecurityManager.decode_token(verify_data.temp_token)
        user_id = payload.get("sub")

        # 检查是否为临时令牌
        if not payload.get("temp", False):
            raise ValueError("不是临时令牌")

        # 检查令牌是否过期
        if SecurityManager.is_token_expired(verify_data.temp_token):
            raise ValueError("令牌已过期")

    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail=f"无效的临时令牌: {str(e)}")

    # 查找用户
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="用户不存在")

    # 查找活跃的TOTP密钥
    totp_secret = db.query(TOTPSecret).filter(
        TOTPSecret.user_id == user.id, TOTPSecret.is_active == True).first()

    if not totp_secret:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="用户未启用2FA")

    # 解密TOTP密钥
    decrypted_secret = SecretEncryption.decrypt_secret(totp_secret.secret_key)

    # 验证TOTP码
    if not TOTPManager.verify_totp(decrypted_secret, verify_data.totp_code):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="无效的TOTP验证码")

    # 标记TOTP已验证
    totp_secret.is_verified = True
    db.commit()

    return {"message": "TOTP验证成功，您的验证器应用已正确配置"}


@router.post("/reset-totp", response_model=TOTPResetResponse)
def reset_totp(current_user: User = Depends(get_current_user),
               db: Session = Depends(get_db)):
    """
    重置用户的TOTP密钥
    """
    # 将当前用户的所有TOTP密钥设为非活跃
    db.query(TOTPSecret).filter(TOTPSecret.user_id == current_user.id).update(
        {"is_active": False})

    # 生成新的TOTP密钥
    totp_secret = TOTPManager.generate_totp_secret()
    totp_uri = TOTPManager.get_totp_uri(totp_secret, current_user.username)
    qr_code = TOTPManager.generate_qr_code(totp_uri)

    # 加密存储TOTP密钥
    encrypted_secret = SecretEncryption.encrypt_secret(totp_secret)
    new_totp_secret = TOTPSecret(
        user_id=current_user.id,
        secret_key=encrypted_secret,
        is_active=True,
        is_verified=False  # 新密钥需要验证
    )

    # 撤销所有信任设备
    db.query(TrustedDevice).filter(
        TrustedDevice.user_id == current_user.id).delete()

    db.add(new_totp_secret)
    db.commit()

    # 返回新的TOTP密钥信息
    return {
        "totp_secret": totp_secret,
        "totp_uri": totp_uri,
        "qr_code": qr_code
    }
