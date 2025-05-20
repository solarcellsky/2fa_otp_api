-- 添加信任设备表
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

-- 创建索引
CREATE INDEX idx_trusted_devices_user_id ON trusted_devices(user_id);
CREATE INDEX idx_trusted_devices_device_identifier ON trusted_devices(device_identifier);
CREATE INDEX idx_trusted_devices_device_token ON trusted_devices(device_token);
CREATE INDEX idx_trusted_devices_expires_at ON trusted_devices(expires_at);

-- 添加注释
COMMENT ON TABLE trusted_devices IS '存储用户信任的设备信息';
COMMENT ON COLUMN trusted_devices.device_identifier IS '设备唯一标识符';
COMMENT ON COLUMN trusted_devices.device_token IS '加密存储的设备信任令牌';
COMMENT ON COLUMN trusted_devices.expires_at IS '设备信任过期时间';
