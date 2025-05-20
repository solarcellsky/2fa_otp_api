from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from ..models.schemas import TrustedDeviceInfo, TrustedDevicesResponse, MessageResponse
from ..models.database import User, TrustedDevice
from ..db.database import get_db
from ..auth.auth import get_current_user
from typing import List
from datetime import datetime
import logging

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/users", tags=["users"])

@router.get("/trusted-devices", response_model=TrustedDevicesResponse)
def get_trusted_devices(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    获取当前用户的信任设备列表
    """
    # 查询当前用户的所有信任设备
    devices = db.query(TrustedDevice).filter(
        TrustedDevice.user_id == current_user.id
    ).all()
    
    # 转换为响应模型
    device_list = []
    for device in devices:
        device_list.append(TrustedDeviceInfo(
            id=device.id,
            device_name=device.device_name,
            last_used_at=device.last_used_at,
            expires_at=device.expires_at,
            ip_address=device.ip_address,
            user_agent=device.user_agent,
            created_at=device.created_at
        ))
    
    return {"devices": device_list}

@router.delete("/trusted-devices/{device_id}", response_model=MessageResponse)
def revoke_trusted_device(device_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    撤销特定设备的信任
    """
    # 查找设备
    device = db.query(TrustedDevice).filter(
        TrustedDevice.id == device_id,
        TrustedDevice.user_id == current_user.id
    ).first()
    
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="设备不存在或不属于当前用户"
        )
    
    # 删除设备
    db.delete(device)
    db.commit()
    
    logger.info(f"撤销信任设备: user_id={current_user.id}, device_id={device_id}")
    
    return {"message": "设备信任已撤销"}

@router.delete("/trusted-devices", response_model=MessageResponse)
def revoke_all_trusted_devices(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    撤销所有信任设备
    """
    # 删除当前用户的所有信任设备
    result = db.query(TrustedDevice).filter(
        TrustedDevice.user_id == current_user.id
    ).delete()
    
    db.commit()
    
    logger.info(f"撤销所有信任设备: user_id={current_user.id}, count={result}")
    
    return {"message": f"已撤销所有信任设备（共{result}个）"}
