-- 2FA + TOTP 认证系统数据库表结构
-- PostgreSQL 数据库脚本

-- 用户表
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- TOTP密钥表
CREATE TABLE totp_secrets (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    secret_key VARCHAR(255) NOT NULL,  -- 加密存储的TOTP密钥
    is_active BOOLEAN DEFAULT TRUE,
    is_verified BOOLEAN DEFAULT FALSE, -- 是否已验证TOTP设置
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 认证会话表
CREATE TABLE auth_sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    temp_token VARCHAR(255) UNIQUE,
    access_token VARCHAR(255) UNIQUE,
    temp_token_expires_at TIMESTAMP WITH TIME ZONE,
    access_token_expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 认证尝试记录表
CREATE TABLE auth_attempts (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    ip_address VARCHAR(45),
    success BOOLEAN,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 信任设备表
CREATE TABLE trusted_devices (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    device_identifier VARCHAR(255) NOT NULL,
    device_name VARCHAR(100) NOT NULL,
    device_token VARCHAR(255) NOT NULL,
    last_used_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 创建索引以提高查询性能
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_totp_secrets_user_id ON totp_secrets(user_id);
CREATE INDEX idx_totp_secrets_is_active ON totp_secrets(is_active);
CREATE INDEX idx_auth_sessions_user_id ON auth_sessions(user_id);
CREATE INDEX idx_auth_sessions_temp_token ON auth_sessions(temp_token);
CREATE INDEX idx_auth_sessions_access_token ON auth_sessions(access_token);
CREATE INDEX idx_auth_attempts_user_id ON auth_attempts(user_id);
CREATE INDEX idx_auth_attempts_created_at ON auth_attempts(created_at);
CREATE INDEX idx_trusted_devices_user_id ON trusted_devices(user_id);
CREATE INDEX idx_trusted_devices_device_identifier ON trusted_devices(device_identifier);
CREATE INDEX idx_trusted_devices_device_token ON trusted_devices(device_token);
CREATE INDEX idx_trusted_devices_expires_at ON trusted_devices(expires_at);

-- 添加更新时间触发器
CREATE OR REPLACE FUNCTION update_modified_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- 为用户表添加更新时间触发器
CREATE TRIGGER update_users_modtime
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION update_modified_column();

-- 为TOTP密钥表添加更新时间触发器
CREATE TRIGGER update_totp_secrets_modtime
BEFORE UPDATE ON totp_secrets
FOR EACH ROW
EXECUTE FUNCTION update_modified_column();

-- 注释
COMMENT ON TABLE users IS '存储用户基本信息';
COMMENT ON TABLE totp_secrets IS '存储用户TOTP密钥信息，加密存储';
COMMENT ON TABLE auth_sessions IS '存储用户认证会话信息';
COMMENT ON TABLE auth_attempts IS '记录认证尝试，用于安全审计和防暴力破解';
COMMENT ON TABLE trusted_devices IS '存储用户信任的设备信息';

COMMENT ON COLUMN users.password_hash IS '使用Argon2id算法哈希的密码';
COMMENT ON COLUMN totp_secrets.secret_key IS '使用AES-256-GCM加密的TOTP密钥';
COMMENT ON COLUMN totp_secrets.is_verified IS '标记TOTP设置是否已通过验证';
COMMENT ON COLUMN auth_sessions.temp_token IS '临时令牌，用于2FA验证过程';
COMMENT ON COLUMN auth_sessions.access_token IS '访问令牌，用于API认证';
COMMENT ON COLUMN trusted_devices.device_identifier IS '设备唯一标识符';
COMMENT ON COLUMN trusted_devices.device_token IS '加密存储的设备信任令牌';
COMMENT ON COLUMN trusted_devices.expires_at IS '设备信任过期时间';
