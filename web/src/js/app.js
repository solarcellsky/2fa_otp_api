/**
 * 应用主逻辑
 * 处理UI交互和状态管理
 */
document.addEventListener('DOMContentLoaded', function() {
    // 获取DOM元素
    const registerForm = document.getElementById('registerForm');
    const registerResult = document.getElementById('registerResult');
    const registerVerifyForm = document.getElementById('registerVerifyForm');
    const qrCodeImage = document.getElementById('qrCodeImage');
    const totpSecret = document.getElementById('totpSecret');
    const goToLoginBtn = document.getElementById('goToLoginBtn');
    
    const loginForm = document.getElementById('loginForm');
    const loginStep1 = document.getElementById('loginStep1');
    const loginStep2 = document.getElementById('loginStep2');
    const loginSuccess = document.getElementById('loginSuccess');
    const totpForm = document.getElementById('totpForm');
    const backToLoginStep1 = document.getElementById('backToLoginStep1');
    const viewProfileBtn = document.getElementById('viewProfileBtn');
    
    const totpSecretLoginLink = document.getElementById('totpSecretLoginLink');
    const totpSecretLoginForm = document.getElementById('totpSecretLoginForm');
    const backToTotpBtn = document.getElementById('backToTotpBtn');
    
    const trustDeviceCheckbox = document.getElementById('trustDeviceCheckbox');
    const deviceNameGroup = document.getElementById('deviceNameGroup');
    const deviceNameInput = document.getElementById('deviceNameInput');
    
    const secretLoginTrustDeviceCheckbox = document.getElementById('secretLoginTrustDeviceCheckbox');
    const secretLoginDeviceNameGroup = document.getElementById('secretLoginDeviceNameGroup');
    const secretLoginDeviceNameInput = document.getElementById('secretLoginDeviceNameInput');
    
    const profileNotLoggedIn = document.getElementById('profileNotLoggedIn');
    const profileLoggedIn = document.getElementById('profileLoggedIn');
    const profileUserId = document.getElementById('profileUserId');
    const profileUsername = document.getElementById('profileUsername');
    const profileEmail = document.getElementById('profileEmail');
    const profile2faStatus = document.getElementById('profile2faStatus');
    const profileCreatedAt = document.getElementById('profileCreatedAt');
    const logoutBtn = document.getElementById('logoutBtn');
    
    const resetNotLoggedIn = document.getElementById('resetNotLoggedIn');
    const resetLoggedIn = document.getElementById('resetLoggedIn');
    const resetTotpBtn = document.getElementById('resetTotpBtn');
    const resetResult = document.getElementById('resetResult');
    const resetQrCodeImage = document.getElementById('resetQrCodeImage');
    const resetTotpSecret = document.getElementById('resetTotpSecret');
    
    const trustedDevicesTab = document.getElementById('trusted-devices-tab');
    const trustedDevicesNotLoggedIn = document.getElementById('trustedDevicesNotLoggedIn');
    const trustedDevicesLoggedIn = document.getElementById('trustedDevicesLoggedIn');
    const trustedDevicesList = document.getElementById('trustedDevicesList');
    const revokeAllDevicesBtn = document.getElementById('revokeAllDevicesBtn');
    
    const goToLoginFromProfile = document.getElementById('goToLoginFromProfile');
    const goToLoginFromReset = document.getElementById('goToLoginFromReset');
    const goToLoginFromDevices = document.getElementById('goToLoginFromDevices');
    
    const apiUrl = document.getElementById('apiUrl');
    const saveApiUrlBtn = document.getElementById('saveApiUrlBtn');
    
    const notificationToast = document.getElementById('notificationToast');
    const toastTitle = document.getElementById('toastTitle');
    const toastMessage = document.getElementById('toastMessage');
    
    // 初始化Bootstrap组件
    const authTabs = document.getElementById('authTabs');
    const tabs = new bootstrap.Tab(authTabs);
    const toast = new bootstrap.Toast(notificationToast);
    
    // 初始化API URL
    apiUrl.value = apiClient.baseUrl;
    
    // 检查登录状态并更新UI
    checkLoginStatus();
    
    // 信任设备复选框变更事件
    if (trustDeviceCheckbox) {
        trustDeviceCheckbox.addEventListener('change', function() {
            if (this.checked) {
                deviceNameGroup.classList.remove('d-none');
            } else {
                deviceNameGroup.classList.add('d-none');
            }
        });
    }
    
    // TOTP密钥登录的信任设备复选框变更事件
    if (secretLoginTrustDeviceCheckbox) {
        secretLoginTrustDeviceCheckbox.addEventListener('change', function() {
            if (this.checked) {
                secretLoginDeviceNameGroup.classList.remove('d-none');
            } else {
                secretLoginDeviceNameGroup.classList.add('d-none');
            }
        });
    }
    
    // 切换到TOTP密钥登录
    if (totpSecretLoginLink) {
        totpSecretLoginLink.addEventListener('click', function(e) {
            e.preventDefault();
            loginStep2.classList.add('d-none');
            totpSecretLoginForm.classList.remove('d-none');
        });
    }
    
    // 返回TOTP验证
    if (backToTotpBtn) {
        backToTotpBtn.addEventListener('click', function() {
            totpSecretLoginForm.classList.add('d-none');
            loginStep2.classList.remove('d-none');
        });
    }
    
    // 注册表单提交
    registerForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const username = document.getElementById('registerUsername').value;
        const email = document.getElementById('registerEmail').value;
        const password = document.getElementById('registerPassword').value;
        
        try {
            // 显示加载状态
            showNotification('处理中', '正在注册...');
            
            // 调用API注册
            const result = await apiClient.register(username, password, email);
            
            // 显示结果
            qrCodeImage.src = `data:image/png;base64,${result.qr_code}`;
            totpSecret.value = result.totp_secret;
            
            // 隐藏表单，显示结果和验证表单
            registerForm.classList.add('d-none');
            registerResult.classList.remove('d-none');
            
            showNotification('成功', '注册成功！请扫描二维码设置您的认证器应用，然后输入验证码进行验证。');
        } catch (error) {
            showNotification('错误', `注册失败: ${error.message}`);
        }
    });
    
    // 注册验证表单提交
    registerVerifyForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const verifyCode = document.getElementById('registerVerifyCode').value;
        
        try {
            // 显示加载状态
            showNotification('处理中', '正在验证TOTP...');
            
            // 调用API验证TOTP
            await apiClient.verifyRegistrationTotp(verifyCode);
            
            // 显示成功信息
            document.getElementById('verifySuccess').classList.remove('d-none');
            document.getElementById('verifyButton').classList.add('d-none');
            
            showNotification('成功', '验证成功！您的验证器应用已正确配置。');
        } catch (error) {
            showNotification('错误', `验证失败: ${error.message}`);
        }
    });
    
    // 前往登录按钮
    goToLoginBtn.addEventListener('click', function() {
        // 切换到登录标签
        const loginTabEl = document.querySelector('#login-tab');
        const loginTab = new bootstrap.Tab(loginTabEl);
        loginTab.show();
        
        // 重置注册表单
        registerForm.reset();
        registerForm.classList.remove('d-none');
        registerResult.classList.add('d-none');
        document.getElementById('verifySuccess').classList.add('d-none');
        document.getElementById('verifyButton').classList.remove('d-none');
    });
    
    // 登录表单提交（第一步）
    loginForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const username = document.getElementById('loginUsername').value;
        const password = document.getElementById('loginPassword').value;
        
        try {
            // 显示加载状态
            showNotification('处理中', '正在验证...');
            
            // 调用API登录第一步
            const result = await apiClient.loginStepOne(username, password);
            
            // 检查是否通过设备令牌自动登录成功
            if (result.device_login_success) {
                // 设备令牌登录成功，直接显示登录成功
                loginStep1.classList.add('d-none');
                loginSuccess.classList.remove('d-none');
                
                // 保存访问令牌
                localStorage.setItem('accessToken', result.access_token);
                localStorage.setItem('tokenType', result.token_type);
                
                // 更新登录状态
                checkLoginStatus();
                
                showNotification('成功', '设备自动登录成功！已跳过TOTP验证。');
                return;
            }
            
            // 如果需要2FA，显示第二步
            if (result.requires_2fa) {
                loginStep1.classList.add('d-none');
                loginStep2.classList.remove('d-none');
                showNotification('成功', '请输入您的TOTP验证码');
            } else {
                // 如果不需要2FA，直接显示登录成功
                loginStep1.classList.add('d-none');
                loginSuccess.classList.remove('d-none');
                showNotification('成功', '登录成功！');
                
                // 更新登录状态
                checkLoginStatus();
            }
        } catch (error) {
            showNotification('错误', `登录失败: ${error.message}`);
        }
    });
    
    // TOTP密钥登录表单提交
    totpSecretLoginForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const username = document.getElementById('secretLoginUsername').value || document.getElementById('loginUsername').value;
        const password = document.getElementById('secretLoginPassword').value || document.getElementById('loginPassword').value;
        const totpSecret = document.getElementById('secretLoginTotpSecret').value;
        const trustDevice = secretLoginTrustDeviceCheckbox.checked;
        const deviceName = secretLoginDeviceNameInput.value;
        
        try {
            // 显示加载状态
            showNotification('处理中', '正在验证...');
            
            // 调用API使用TOTP密钥登录
            await apiClient.loginWithTotpSecret(username, password, totpSecret, trustDevice, deviceName);
            
            // 显示登录成功
            totpSecretLoginForm.classList.add('d-none');
            loginSuccess.classList.remove('d-none');
            
            let successMessage = '使用TOTP密钥登录成功！';
            if (trustDevice) {
                successMessage += ' 此设备已被信任，下次登录将自动跳过TOTP验证。';
            }
            
            showNotification('成功', successMessage);
            
            // 更新登录状态
            checkLoginStatus();
        } catch (error) {
            showNotification('错误', `登录失败: ${error.message}`);
        }
    });
    
    // 返回登录第一步
    backToLoginStep1.addEventListener('click', function() {
        loginStep2.classList.add('d-none');
        loginStep1.classList.remove('d-none');
    });
    
    // TOTP验证表单提交（第二步）
    totpForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const totpCode = document.getElementById('totpCode').value;
        const trustDevice = trustDeviceCheckbox.checked;
        const deviceName = deviceNameInput.value;
        
        try {
            // 显示加载状态
            showNotification('处理中', '正在验证TOTP...');
            
            // 调用API登录第二步
            await apiClient.loginStepTwo(totpCode, trustDevice, deviceName);
            
            // 显示登录成功
            loginStep2.classList.add('d-none');
            loginSuccess.classList.remove('d-none');
            
            let successMessage = '2FA验证成功！您已成功登录。';
            if (trustDevice) {
                successMessage += ' 此设备已被信任，下次登录将自动跳过TOTP验证。';
            }
            
            showNotification('成功', successMessage);
            
            // 更新登录状态
            checkLoginStatus();
        } catch (error) {
            showNotification('错误', `TOTP验证失败: ${error.message}`);
        }
    });
    
    // 查看个人信息按钮
    viewProfileBtn.addEventListener('click', function() {
        // 切换到个人信息标签
        const profileTabEl = document.querySelector('#profile-tab');
        const profileTab = new bootstrap.Tab(profileTabEl);
        profileTab.show();
        
        // 重置登录表单
        loginForm.reset();
        totpForm.reset();
        loginStep1.classList.remove('d-none');
        loginStep2.classList.add('d-none');
        loginSuccess.classList.add('d-none');
        totpSecretLoginForm.classList.add('d-none');
        
        // 重置信任设备选项
        trustDeviceCheckbox.checked = false;
        deviceNameGroup.classList.add('d-none');
        secretLoginTrustDeviceCheckbox.checked = false;
        secretLoginDeviceNameGroup.classList.add('d-none');
    });
    
    // 前往登录按钮（从个人信息）
    goToLoginFromProfile.addEventListener('click', function() {
        // 切换到登录标签
        const loginTabEl = document.querySelector('#login-tab');
        const loginTab = new bootstrap.Tab(loginTabEl);
        loginTab.show();
    });
    
    // 前往登录按钮（从重置TOTP）
    goToLoginFromReset.addEventListener('click', function() {
        // 切换到登录标签
        const loginTabEl = document.querySelector('#login-tab');
        const loginTab = new bootstrap.Tab(loginTabEl);
        loginTab.show();
    });
    
    // 前往登录按钮（从信任设备）
    goToLoginFromDevices.addEventListener('click', function() {
        // 切换到登录标签
        const loginTabEl = document.querySelector('#login-tab');
        const loginTab = new bootstrap.Tab(loginTabEl);
        loginTab.show();
    });
    
    // 退出登录按钮
    logoutBtn.addEventListener('click', function() {
        apiClient.logout();
        checkLoginStatus();
        showNotification('成功', '您已成功退出登录');
        
        // 切换到登录标签
        const loginTabEl = document.querySelector('#login-tab');
        const loginTab = new bootstrap.Tab(loginTabEl);
        loginTab.show();
    });
    
    // 重置TOTP按钮
    resetTotpBtn.addEventListener('click', async function() {
        try {
            // 显示加载状态
            showNotification('处理中', '正在重置TOTP密钥...');
            
            // 调用API重置TOTP
            const result = await apiClient.resetTotp();
            
            // 显示结果
            resetQrCodeImage.src = `data:image/png;base64,${result.qr_code}`;
            resetTotpSecret.value = result.totp_secret;
            
            // 显示结果
            resetResult.classList.remove('d-none');
            
            showNotification('成功', 'TOTP密钥已重置！请更新您的认证器应用。所有信任设备已被撤销。');
            
            // 更新信任设备列表
            loadTrustedDevices();
        } catch (error) {
            showNotification('错误', `重置TOTP失败: ${error.message}`);
        }
    });
    
    // 撤销所有设备按钮
    revokeAllDevicesBtn.addEventListener('click', async function() {
        if (!confirm('确定要撤销所有信任设备吗？这将要求您在所有设备上重新进行TOTP验证。')) {
            return;
        }
        
        try {
            // 显示加载状态
            showNotification('处理中', '正在撤销所有信任设备...');
            
            // 调用API撤销所有信任设备
            await apiClient.revokeAllTrustedDevices();
            
            // 更新信任设备列表
            loadTrustedDevices();
            
            showNotification('成功', '所有信任设备已被撤销');
        } catch (error) {
            showNotification('错误', `撤销失败: ${error.message}`);
        }
    });
    
    // 保存API URL按钮
    saveApiUrlBtn.addEventListener('click', function() {
        const newUrl = apiUrl.value.trim();
        if (newUrl) {
            apiClient.setBaseUrl(newUrl);
            showNotification('成功', 'API URL已更新');
        } else {
            showNotification('错误', '请输入有效的API URL');
        }
    });
    
    // 标签切换事件
    document.querySelectorAll('button[data-bs-toggle="tab"]').forEach(tab => {
        tab.addEventListener('shown.bs.tab', function(event) {
            // 如果切换到个人信息或重置TOTP标签，检查登录状态
            if (event.target.id === 'profile-tab' || event.target.id === 'reset-tab') {
                updateProfileAndResetTabs();
            }
            
            // 如果切换到信任设备标签，加载信任设备列表
            if (event.target.id === 'trusted-devices-tab') {
                updateTrustedDevicesTab();
            }
        });
    });
    
    /**
     * 加载信任设备列表
     */
    async function loadTrustedDevices() {
        // 清空设备列表
        trustedDevicesList.innerHTML = '';
        
        try {
            // 获取信任设备列表
            const result = await apiClient.getTrustedDevices();
            
            if (result.devices.length === 0) {
                // 没有信任设备
                trustedDevicesList.innerHTML = `
                    <div class="alert alert-info">
                        <p>您没有信任的设备。</p>
                    </div>
                `;
                return;
            }
            
            // 创建设备列表
            result.devices.forEach(device => {
                const deviceEl = document.createElement('div');
                deviceEl.className = 'card mb-3';
                deviceEl.innerHTML = `
                    <div class="card-body">
                        <h5 class="card-title">${device.device_name}</h5>
                        <p class="card-text">
                            <small class="text-muted">最后使用: ${new Date(device.last_used_at).toLocaleString()}</small><br>
                            <small class="text-muted">过期时间: ${new Date(device.expires_at).toLocaleString()}</small><br>
                            <small class="text-muted">IP地址: ${device.ip_address || '未知'}</small>
                        </p>
                        <button class="btn btn-danger btn-sm revoke-device" data-device-id="${device.id}">撤销信任</button>
                    </div>
                `;
                trustedDevicesList.appendChild(deviceEl);
            });
            
            // 添加撤销设备事件
            document.querySelectorAll('.revoke-device').forEach(button => {
                button.addEventListener('click', async function() {
                    const deviceId = this.getAttribute('data-device-id');
                    if (!confirm('确定要撤销此设备的信任吗？')) {
                        return;
                    }
                    
                    try {
                        // 显示加载状态
                        showNotification('处理中', '正在撤销设备信任...');
                        
                        // 调用API撤销设备信任
                        await apiClient.revokeTrustedDevice(deviceId);
                        
                        // 更新信任设备列表
                        loadTrustedDevices();
                        
                        showNotification('成功', '设备信任已被撤销');
                    } catch (error) {
                        showNotification('错误', `撤销失败: ${error.message}`);
                    }
                });
            });
        } catch (error) {
            trustedDevicesList.innerHTML = `
                <div class="alert alert-danger">
                    <p>加载信任设备失败: ${error.message}</p>
                </div>
            `;
        }
    }
    
    /**
     * 检查登录状态并更新UI
     */
    function checkLoginStatus() {
        const isLoggedIn = apiClient.isLoggedIn();
        
        if (isLoggedIn) {
            // 获取用户信息
            updateProfileAndResetTabs();
            updateTrustedDevicesTab();
        } else {
            // 显示未登录状态
            profileNotLoggedIn.classList.remove('d-none');
            profileLoggedIn.classList.add('d-none');
            resetNotLoggedIn.classList.remove('d-none');
            resetLoggedIn.classList.add('d-none');
            trustedDevicesNotLoggedIn.classList.remove('d-none');
            trustedDevicesLoggedIn.classList.add('d-none');
        }
    }
    
    /**
     * 更新个人信息和重置TOTP标签
     */
    async function updateProfileAndResetTabs() {
        const isLoggedIn = apiClient.isLoggedIn();
        
        if (isLoggedIn) {
            try {
                // 获取用户信息
                const userInfo = await apiClient.getUserInfo();
                
                // 更新个人信息
                profileUserId.textContent = userInfo.user_id;
                profileUsername.textContent = userInfo.username;
                profileEmail.textContent = userInfo.email;
                profile2faStatus.textContent = userInfo.is_2fa_enabled ? '已启用' : '未启用';
                profileCreatedAt.textContent = new Date(userInfo.created_at).toLocaleString();
                
                // 显示已登录状态
                profileNotLoggedIn.classList.add('d-none');
                profileLoggedIn.classList.remove('d-none');
                resetNotLoggedIn.classList.add('d-none');
                resetLoggedIn.classList.remove('d-none');
                resetResult.classList.add('d-none');
            } catch (error) {
                // 如果获取用户信息失败，可能是令牌过期
                apiClient.logout();
                
                // 显示未登录状态
                profileNotLoggedIn.classList.remove('d-none');
                profileLoggedIn.classList.add('d-none');
                resetNotLoggedIn.classList.remove('d-none');
                resetLoggedIn.classList.add('d-none');
                
                showNotification('错误', `获取用户信息失败: ${error.message}`);
            }
        } else {
            // 显示未登录状态
            profileNotLoggedIn.classList.remove('d-none');
            profileLoggedIn.classList.add('d-none');
            resetNotLoggedIn.classList.remove('d-none');
            resetLoggedIn.classList.add('d-none');
        }
    }
    
    /**
     * 更新信任设备标签
     */
    async function updateTrustedDevicesTab() {
        const isLoggedIn = apiClient.isLoggedIn();
        
        if (isLoggedIn) {
            // 显示已登录状态
            trustedDevicesNotLoggedIn.classList.add('d-none');
            trustedDevicesLoggedIn.classList.remove('d-none');
            
            // 加载信任设备列表
            loadTrustedDevices();
        } else {
            // 显示未登录状态
            trustedDevicesNotLoggedIn.classList.remove('d-none');
            trustedDevicesLoggedIn.classList.add('d-none');
        }
    }
    
    /**
     * 显示通知
     * @param {string} title - 通知标题
     * @param {string} message - 通知消息
     */
    function showNotification(title, message) {
        toastTitle.textContent = title;
        toastMessage.textContent = message;
        toast.show();
    }
});
