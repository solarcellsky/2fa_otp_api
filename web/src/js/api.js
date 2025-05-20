/**
 * API 客户端
 * 负责与2FA+TOTP认证API进行通信
 */
class ApiClient {
    constructor() {
        // 从本地存储获取API URL，默认为localhost:8000
        this.baseUrl = localStorage.getItem('apiUrl') || 'http://localhost:8000';
        this.accessToken = localStorage.getItem('accessToken');
        this.tokenType = localStorage.getItem('tokenType');
        this.deviceToken = localStorage.getItem('deviceToken');
    }

    /**
     * 更新API基础URL
     * @param {string} url - 新的API URL
     */
    setBaseUrl(url) {
        this.baseUrl = url;
        localStorage.setItem('apiUrl', url);
    }

    /**
     * 注册新用户
     * @param {string} username - 用户名
     * @param {string} password - 密码
     * @param {string} email - 电子邮箱
     * @returns {Promise} - 包含注册结果的Promise
     */
    async register(username, password, email) {
        const url = `${this.baseUrl}/api/v1/users/register`;
        const payload = {
            username,
            password,
            email
        };

        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(payload)
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.detail || '注册失败');
            }

            // 保存临时令牌到会话存储，用于后续TOTP验证
            sessionStorage.setItem('tempToken', data.temp_token);
            
            return data;
        } catch (error) {
            throw error;
        }
    }

    /**
     * 验证注册后的TOTP设置
     * @param {string} totpCode - 6位TOTP验证码
     * @returns {Promise} - 包含验证结果的Promise
     */
    async verifyRegistrationTotp(totpCode) {
        const url = `${this.baseUrl}/api/v1/auth/verify-registration-totp`;
        const tempToken = sessionStorage.getItem('tempToken');
        
        if (!tempToken) {
            throw new Error('临时令牌不存在，请重新注册');
        }
        
        const payload = {
            temp_token: tempToken,
            totp_code: totpCode
        };

        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(payload)
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.detail || 'TOTP验证失败');
            }

            return data;
        } catch (error) {
            throw error;
        }
    }

    /**
     * 登录第一步：验证用户名和密码
     * @param {string} username - 用户名
     * @param {string} password - 密码
     * @returns {Promise} - 包含临时令牌和2FA状态的Promise
     */
    async loginStepOne(username, password) {
        const url = `${this.baseUrl}/api/v1/auth/login`;
        const payload = {
            username,
            password
        };

        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(payload)
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.detail || '登录失败');
            }

            // 保存临时令牌到会话存储
            sessionStorage.setItem('tempToken', data.temp_token);
            // 保存用户名，用于设备登录
            localStorage.setItem('lastUsername', username);
            
            // 如果有设备令牌，尝试自动登录
            if (this.hasDeviceToken() && !data.requires_2fa) {
                // 不需要2FA，直接返回
                return data;
            }
            
            if (this.hasDeviceToken() && data.requires_2fa) {
                // 尝试使用设备令牌登录
                try {
                    const deviceLoginResult = await this.deviceLogin(username, password);
                    // 设置设备登录成功标志
                    data.device_login_success = true;
                    data.access_token = deviceLoginResult.access_token;
                    data.token_type = deviceLoginResult.token_type;
                    data.expires_in = deviceLoginResult.expires_in;
                    return data;
                } catch (deviceError) {
                    // 设备登录失败，继续普通2FA流程
                    console.log('设备登录失败，继续普通2FA流程:', deviceError.message);
                    return data;
                }
            }
            
            return data;
        } catch (error) {
            throw error;
        }
    }

    /**
     * 登录第二步：验证TOTP码
     * @param {string} totpCode - 6位TOTP验证码
     * @param {boolean} trustDevice - 是否信任此设备
     * @param {string} deviceName - 设备名称
     * @returns {Promise} - 包含访问令牌的Promise
     */
    async loginStepTwo(totpCode, trustDevice = false, deviceName = null) {
        const url = `${this.baseUrl}/api/v1/auth/verify`;
        const tempToken = sessionStorage.getItem('tempToken');
        
        if (!tempToken) {
            throw new Error('临时令牌不存在，请重新登录');
        }
        
        const payload = {
            temp_token: tempToken,
            totp_code: totpCode,
            trust_device: trustDevice
        };

        // 如果信任设备，添加设备名称
        if (trustDevice && deviceName) {
            payload.device_name = deviceName;
        }

        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(payload)
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.detail || 'TOTP验证失败');
            }

            // 保存访问令牌到本地存储
            this.accessToken = data.access_token;
            this.tokenType = data.token_type;
            localStorage.setItem('accessToken', data.access_token);
            localStorage.setItem('tokenType', data.token_type);
            
            // 如果返回了设备令牌，保存到本地存储
            if (data.device_token) {
                this.deviceToken = data.device_token;
                localStorage.setItem('deviceToken', data.device_token);
            }
            
            // 清除临时令牌
            sessionStorage.removeItem('tempToken');
            
            return data;
        } catch (error) {
            throw error;
        }
    }

    /**
     * 使用TOTP密钥直接登录（适用于丢失认证器应用的情况）
     * @param {string} username - 用户名
     * @param {string} password - 密码
     * @param {string} totpSecret - TOTP密钥
     * @param {boolean} trustDevice - 是否信任此设备
     * @param {string} deviceName - 设备名称
     * @returns {Promise} - 包含访问令牌的Promise
     */
    async loginWithTotpSecret(username, password, totpSecret, trustDevice = false, deviceName = null) {
        const url = `${this.baseUrl}/api/v1/auth/totp-secret-login`;
        
        const payload = {
            username,
            password,
            totp_secret: totpSecret,
            trust_device: trustDevice
        };

        // 如果信任设备，添加设备名称
        if (trustDevice && deviceName) {
            payload.device_name = deviceName;
        }

        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(payload)
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.detail || 'TOTP密钥登录失败');
            }

            // 保存访问令牌到本地存储
            this.accessToken = data.access_token;
            this.tokenType = data.token_type;
            localStorage.setItem('accessToken', data.access_token);
            localStorage.setItem('tokenType', data.token_type);
            
            // 如果返回了设备令牌，保存到本地存储
            if (data.device_token) {
                this.deviceToken = data.device_token;
                localStorage.setItem('deviceToken', data.device_token);
            }
            
            // 保存用户名，用于设备登录
            localStorage.setItem('lastUsername', username);
            
            return data;
        } catch (error) {
            throw error;
        }
    }

    /**
     * 使用设备令牌登录（跳过TOTP验证）
     * @param {string} username - 用户名
     * @param {string} password - 密码
     * @returns {Promise} - 包含访问令牌的Promise
     */
    async deviceLogin(username, password) {
        const url = `${this.baseUrl}/api/v1/auth/device-login`;
        const deviceToken = localStorage.getItem('deviceToken');
        
        if (!deviceToken) {
            throw new Error('设备令牌不存在，请使用标准登录');
        }
        
        const payload = {
            username,
            password,
            device_token: deviceToken
        };

        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(payload)
            });

            const data = await response.json();

            if (!response.ok) {
                // 如果设备令牌无效，清除它
                if (response.status === 401) {
                    localStorage.removeItem('deviceToken');
                    this.deviceToken = null;
                }
                throw new Error(data.detail || '设备登录失败');
            }

            // 保存访问令牌到本地存储
            this.accessToken = data.access_token;
            this.tokenType = data.token_type;
            localStorage.setItem('accessToken', data.access_token);
            localStorage.setItem('tokenType', data.token_type);
            
            return data;
        } catch (error) {
            throw error;
        }
    }

    /**
     * 获取当前用户信息
     * @returns {Promise} - 包含用户信息的Promise
     */
    async getUserInfo() {
        if (!this.accessToken) {
            throw new Error('未登录，请先登录');
        }

        const url = `${this.baseUrl}/api/v1/users/me`;

        try {
            const response = await fetch(url, {
                method: 'GET',
                headers: {
                    'Authorization': `${this.tokenType} ${this.accessToken}`
                }
            });

            const data = await response.json();

            if (!response.ok) {
                // 如果是401错误，清除令牌
                if (response.status === 401) {
                    this.logout();
                }
                throw new Error(data.detail || '获取用户信息失败');
            }

            return data;
        } catch (error) {
            throw error;
        }
    }

    /**
     * 获取信任设备列表
     * @returns {Promise} - 包含信任设备列表的Promise
     */
    async getTrustedDevices() {
        if (!this.accessToken) {
            throw new Error('未登录，请先登录');
        }

        const url = `${this.baseUrl}/api/v1/users/trusted-devices`;

        try {
            const response = await fetch(url, {
                method: 'GET',
                headers: {
                    'Authorization': `${this.tokenType} ${this.accessToken}`
                }
            });

            const data = await response.json();

            if (!response.ok) {
                // 如果是401错误，清除令牌
                if (response.status === 401) {
                    this.logout();
                }
                throw new Error(data.detail || '获取信任设备列表失败');
            }

            return data;
        } catch (error) {
            throw error;
        }
    }

    /**
     * 撤销特定设备的信任
     * @param {number} deviceId - 设备ID
     * @returns {Promise} - 包含操作结果的Promise
     */
    async revokeTrustedDevice(deviceId) {
        if (!this.accessToken) {
            throw new Error('未登录，请先登录');
        }

        const url = `${this.baseUrl}/api/v1/users/trusted-devices/${deviceId}`;

        try {
            const response = await fetch(url, {
                method: 'DELETE',
                headers: {
                    'Authorization': `${this.tokenType} ${this.accessToken}`
                }
            });

            const data = await response.json();

            if (!response.ok) {
                // 如果是401错误，清除令牌
                if (response.status === 401) {
                    this.logout();
                }
                throw new Error(data.detail || '撤销设备信任失败');
            }

            // 如果撤销的是当前设备，清除设备令牌
            if (this.deviceToken) {
                localStorage.removeItem('deviceToken');
                this.deviceToken = null;
            }

            return data;
        } catch (error) {
            throw error;
        }
    }

    /**
     * 撤销所有信任设备
     * @returns {Promise} - 包含操作结果的Promise
     */
    async revokeAllTrustedDevices() {
        if (!this.accessToken) {
            throw new Error('未登录，请先登录');
        }

        const url = `${this.baseUrl}/api/v1/users/trusted-devices`;

        try {
            const response = await fetch(url, {
                method: 'DELETE',
                headers: {
                    'Authorization': `${this.tokenType} ${this.accessToken}`
                }
            });

            const data = await response.json();

            if (!response.ok) {
                // 如果是401错误，清除令牌
                if (response.status === 401) {
                    this.logout();
                }
                throw new Error(data.detail || '撤销所有设备信任失败');
            }

            // 清除设备令牌
            localStorage.removeItem('deviceToken');
            this.deviceToken = null;

            return data;
        } catch (error) {
            throw error;
        }
    }

    /**
     * 重置TOTP密钥
     * @returns {Promise} - 包含新TOTP密钥的Promise
     */
    async resetTotp() {
        if (!this.accessToken) {
            throw new Error('未登录，请先登录');
        }

        const url = `${this.baseUrl}/api/v1/auth/reset-totp`;

        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Authorization': `${this.tokenType} ${this.accessToken}`
                }
            });

            const data = await response.json();

            if (!response.ok) {
                // 如果是401错误，清除令牌
                if (response.status === 401) {
                    this.logout();
                }
                throw new Error(data.detail || '重置TOTP失败');
            }

            // 重置TOTP会撤销所有设备信任，清除设备令牌
            localStorage.removeItem('deviceToken');
            this.deviceToken = null;

            return data;
        } catch (error) {
            throw error;
        }
    }

    /**
     * 退出登录
     */
    logout() {
        this.accessToken = null;
        this.tokenType = null;
        localStorage.removeItem('accessToken');
        localStorage.removeItem('tokenType');
        // 不清除设备令牌，以便下次可以使用设备登录
    }

    /**
     * 检查是否已登录
     * @returns {boolean} - 是否已登录
     */
    isLoggedIn() {
        return !!this.accessToken;
    }

    /**
     * 检查是否有设备令牌
     * @returns {boolean} - 是否有设备令牌
     */
    hasDeviceToken() {
        return !!this.deviceToken;
    }
}

// 创建全局API客户端实例
const apiClient = new ApiClient();
