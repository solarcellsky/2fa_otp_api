# 2FA + TOTP 认证系统设计文档

## 系统概述

本系统实现基于时间的一次性密码(TOTP)认证机制，提供RESTful API接口，使用PostgreSQL存储数据。系统专注于核心认证逻辑，并确保代码安全性。

## API 接口设计

### 1. 用户管理接口

#### 1.1 用户注册
- **端点**: `/api/v1/users/register`
- **方法**: POST
- **功能**: 注册新用户并生成TOTP密钥
- **请求参数**:
  ```json
  {
    "username": "用户名",
    "password": "密码",
    "email": "电子邮箱"
  }
  ```
- **响应**:
  ```json
  {
    "user_id": "用户ID",
    "totp_secret": "TOTP密钥(Base32编码)",
    "totp_uri": "otpauth://totp/服务名:用户名?secret=密钥&issuer=服务名",
    "qr_code": "二维码数据(Base64编码)"
  }
  ```

#### 1.2 用户登录(第一步)
- **端点**: `/api/v1/users/login`
- **方法**: POST
- **功能**: 验证用户名和密码，返回临时令牌
- **请求参数**:
  ```json
  {
    "username": "用户名",
    "password": "密码"
  }
  ```
- **响应**:
  ```json
  {
    "temp_token": "临时令牌",
    "requires_2fa": true
  }
  ```

### 2. TOTP认证接口

#### 2.1 验证TOTP
- **端点**: `/api/v1/auth/verify`
- **方法**: POST
- **功能**: 验证TOTP码，完成第二步认证
- **请求参数**:
  ```json
  {
    "temp_token": "临时令牌",
    "totp_code": "6位TOTP验证码"
  }
  ```
- **响应**:
  ```json
  {
    "access_token": "访问令牌",
    "token_type": "Bearer",
    "expires_in": 3600
  }
  ```

#### 2.2 重置TOTP密钥
- **端点**: `/api/v1/auth/reset-totp`
- **方法**: POST
- **功能**: 重置用户的TOTP密钥(需要完整认证)
- **请求头**: `Authorization: Bearer {access_token}`
- **响应**:
  ```json
  {
    "totp_secret": "新TOTP密钥",
    "totp_uri": "新otpauth URI",
    "qr_code": "新二维码数据"
  }
  ```

### 3. 受保护资源接口

#### 3.1 获取用户信息
- **端点**: `/api/v1/users/me`
- **方法**: GET
- **功能**: 获取当前认证用户的信息
- **请求头**: `Authorization: Bearer {access_token}`
- **响应**:
  ```json
  {
    "user_id": "用户ID",
    "username": "用户名",
    "email": "电子邮箱",
    "2fa_enabled": true
  }
  ```

## 数据库设计

### 用户表 (users)
```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```

### TOTP密钥表 (totp_secrets)
```sql
CREATE TABLE totp_secrets (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    secret_key VARCHAR(255) NOT NULL,  -- 加密存储的TOTP密钥
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```

### 认证会话表 (auth_sessions)
```sql
CREATE TABLE auth_sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    temp_token VARCHAR(255) UNIQUE,
    access_token VARCHAR(255) UNIQUE,
    temp_token_expires_at TIMESTAMP WITH TIME ZONE,
    access_token_expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```

### 认证尝试记录表 (auth_attempts)
```sql
CREATE TABLE auth_attempts (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    ip_address VARCHAR(45),
    success BOOLEAN,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```

## 安全机制设计

1. **密码安全**
   - 使用Argon2id算法进行密码哈希
   - 设置适当的内存、时间和并行度参数
   - 使用随机盐值

2. **TOTP密钥安全**
   - 使用AES-256-GCM加密存储TOTP密钥
   - 密钥派生使用PBKDF2算法
   - 加密密钥不直接存储在数据库中

3. **令牌安全**
   - 使用JWT(JSON Web Token)作为访问令牌
   - 令牌包含过期时间和签名
   - 临时令牌有效期短(5分钟)

4. **防暴力破解**
   - 实现基于IP和用户名的速率限制
   - 连续失败尝试后实施指数退避策略
   - 记录认证尝试以便审计

5. **其他安全措施**
   - 实现CSRF保护
   - 设置安全的HTTP头部
   - 输入验证和参数清洗
   - 日志记录关键操作

## 认证流程

1. **用户注册流程**
   - 用户提供用户名、密码和电子邮箱
   - 系统生成随机TOTP密钥
   - 系统返回TOTP密钥和二维码，用户需保存或扫描
   - 用户使用认证器应用(如Google Authenticator)添加账户

2. **用户登录流程**
   - 第一步：用户提供用户名和密码
   - 系统验证凭据并返回临时令牌
   - 第二步：用户提供TOTP验证码和临时令牌
   - 系统验证TOTP码并返回访问令牌
   - 用户使用访问令牌访问受保护资源

3. **TOTP重置流程**
   - 用户完成完整的2FA认证
   - 用户请求重置TOTP密钥
   - 系统生成新的TOTP密钥
   - 系统返回新密钥和二维码，用户需更新认证器应用
