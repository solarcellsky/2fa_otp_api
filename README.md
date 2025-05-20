# 2FA + TOTP 认证系统使用文档

## 项目概述

本项目实现了一个基于时间的一次性密码(TOTP)双因素认证系统，提供RESTful API接口，使用PostgreSQL数据库存储用户信息和密钥。系统专注于核心认证逻辑，并确保代码安全性。

## 系统特点

1. **双因素认证**：结合用户名/密码和TOTP验证码进行双重验证
2. **安全存储**：使用Argon2id算法进行密码哈希，AES-256-GCM加密存储TOTP密钥
3. **防暴力破解**：记录认证尝试，支持实现速率限制
4. **完整API**：提供用户注册、登录、TOTP验证和密钥重置等功能
5. **客户端示例**：包含Python客户端调用示例

## 目录结构

```
2fa_otp_api/
├── app/                    # 主应用目录
│   ├── api/                # API路由
│   │   ├── __init__.py
│   │   └── users.py        # 用户管理API
│   ├── auth/               # 认证相关
│   │   ├── __init__.py
│   │   └── auth.py         # 认证API和逻辑
│   ├── db/                 # 数据库配置
│   │   └── database.py     # 数据库连接和设置
│   ├── models/             # 数据模型
│   │   ├── database.py     # SQLAlchemy模型
│   │   └── schemas.py      # Pydantic模型
│   ├── utils/              # 工具函数
│   │   ├── security.py     # 安全相关工具
│   │   └── totp.py         # TOTP生成和验证
│   ├── __init__.py
│   └── main.py             # FastAPI应用入口
├── api_design.md           # API设计文档
├── client_example.py       # Python客户端示例
├── requirements.txt        # 依赖列表
├── run.py                  # 启动脚本
└── todo.md                 # 任务清单
```

## 安装与配置

### 依赖安装

```bash
pip install -r requirements.txt
```

### 数据库配置

1. 创建PostgreSQL数据库：

执行 database_schema.sql

2. 配置环境变量（可创建.env文件）：

```
DATABASE_URL=postgresql://用户名:密码@localhost/totp_auth
SECRET_KEY=your-secret-key-for-jwt-token-generation
ENCRYPTION_KEY=your-32-byte-encryption-key-for-secrets
```

## 启动服务

```bash
python run.py
```

服务将在 http://localhost:8000 上运行，API文档可在 http://localhost:8000/docs 访问。

## 启动 Web 服务

```bash
python run.py web
```

服务将在 http://localhost:8081 上运行。

## API端点

### 用户管理

- **POST /api/v1/users/register**：注册新用户并生成TOTP密钥
- **GET /api/v1/users/me**：获取当前认证用户的信息

### 认证

- **POST /api/v1/auth/login**：用户登录第一步（验证用户名和密码）
- **POST /api/v1/auth/verify**：用户登录第二步（验证TOTP码）
- **POST /api/v1/auth/reset-totp**：重置用户的TOTP密钥

## 认证流程

1. **用户注册**：
   - 调用 `/api/v1/users/register` 注册新用户
   - 获取TOTP密钥和二维码
   - 使用认证器应用（如Google Authenticator）扫描二维码

2. **用户登录**：
   - 第一步：调用 `/api/v1/auth/login` 验证用户名和密码
   - 获取临时令牌
   - 第二步：调用 `/api/v1/auth/verify` 提交TOTP验证码和临时令牌
   - 获取访问令牌

3. **访问受保护资源**：
   - 使用访问令牌调用 `/api/v1/users/me` 等需要认证的API

## 客户端示例

项目包含一个完整的Python客户端示例（client_example.py），演示了如何与API交互：

```bash
python client_example.py
```

客户端示例提供以下功能：

- 注册新用户
- 登录（两步验证）
- 获取用户信息
- 重置TOTP密钥

## 安全注意事项

1. 在生产环境中，请使用强密钥和安全的环境变量管理
2. 限制API的CORS设置，只允许受信任的域名
3. 实现速率限制以防止暴力破解
4. 使用HTTPS保护API通信
5. 定期审计认证尝试记录

## 扩展建议

1. 添加电子邮件验证功能
2. 实现账户恢复机制
3. 添加管理员功能
4. 实现API密钥认证
5. 添加更多的安全日志和监控
