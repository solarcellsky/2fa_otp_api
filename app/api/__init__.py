from fastapi import Depends
from ..auth.auth import get_current_user


# 修复用户API中的依赖导入问题
def get_current_user_dependency():
    return Depends(get_current_user)
