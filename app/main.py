from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session
from .db.database import engine
from .models.database import Base
from .api import users, trusted_devices
from .auth import auth

# 创建数据库表
Base.metadata.create_all(bind=engine)

# 创建FastAPI应用
app = FastAPI(title="2FA + TOTP 认证 API",
              description="基于时间的一次性密码(TOTP)双因素认证系统",
              version="1.0.0")

# 添加CORS中间件
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 在生产环境中应限制为特定域名
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 包含路由器
app.include_router(users.router)
app.include_router(trusted_devices.router)
app.include_router(auth.router)


# 速率限制中间件
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    # 在实际应用中，这里应该实现速率限制逻辑
    # 例如，使用Redis或内存缓存来跟踪请求频率
    response = await call_next(request)
    return response


# 健康检查端点
@app.get("/health")
def health_check():
    return {"status": "healthy"}


# 根端点
@app.get("/")
def read_root():
    return {
        "message": "欢迎使用2FA + TOTP认证API",
        "documentation": "/docs",
        "version": "1.0.0"
    }
