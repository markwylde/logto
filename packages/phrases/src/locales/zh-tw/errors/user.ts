const user = {
  username_already_in_use: '該用戶名已被使用。',
  email_already_in_use: '該電子郵件地址已被使用。',
  phone_already_in_use: '該手機號碼已被使用。',
  invalid_email: '電子郵件地址不正確。',
  invalid_phone: '手機號碼不正確。',
  email_not_exist: '電子郵件地址尚未註冊。',
  phone_not_exist: '手機號碼尚未註冊。',
  identity_not_exist: '該社交帳號尚未註冊。',
  identity_already_in_use: '該社交帳號已被註冊。',
  social_account_exists_in_profile: '你已綁定當前社交帳號，無需重複操作。',
  cannot_delete_self: '無法刪除自己的帳戶。',
  sign_up_method_not_enabled: '註冊方式尚未啟用。',
  sign_in_method_not_enabled: '登錄方式尚未啟用。',
  same_password: '為確保帳戶安全，新密碼不能與舊密碼一致。',
  password_required_in_profile: '請設置登錄密碼。',
  new_password_required_in_profile: '請設置新密碼。',
  password_exists_in_profile: '當前用戶已設置密碼，無需重複操作。',
  username_required_in_profile: '請設置用戶名。',
  username_exists_in_profile: '當前用戶已設置用戶名，無需重複操作。',
  email_required_in_profile: '請綁定電子郵件地址',
  email_exists_in_profile: '當前用戶已綁定電子郵件，無需重複操作。',
  phone_required_in_profile: '請綁定手機號碼。',
  phone_exists_in_profile: '當前用戶已綁定手機號碼，無需重複操作。',
  email_or_phone_required_in_profile: '請綁定電子郵件地址或手機號碼。',
  suspended: '帳戶已被禁用。',
  user_not_exist: '未找到與 {{identifier}} 相關聯的用戶。',
  missing_profile: '請於登錄時提供必要的用戶補充信息。',
  role_exists: '角色 ID {{roleId}} 已添加到此用戶',
  invalid_role_type: '無效角色類型，無法將機器對機器角色分配給用戶。',
  missing_mfa: '在登錄前需要綁定額外的多因素驗證。',
  totp_already_in_use: 'TOTP 已經在使用中。',
  backup_code_already_in_use: '備份代碼已經在使用中。',
  password_algorithm_required: 'Password algorithm is required.',
  password_and_digest: 'You cannot set both plain text password and password digest.',
  personal_access_token_name_exists: '個人訪問令牌名稱已存在。',
  totp_secret_invalid: '提供的 TOTP 密鑰無效。',
  wrong_backup_code_format: '備份代碼格式無效。',
  username_required: '用戶名是一個必需的標識符，你不能將其設為 null。',
  email_or_phone_required: '電子郵件地址或手機號碼是一個必需的標識符，至少需要一個。',
  email_required: '電子郵件地址是一個必需的標識符，你不能將其設為 null。',
  phone_required: '手機號碼是一個必需的標識符，你不能將其設為 null。',
  enterprise_sso_identity_not_exists:
    '該用戶沒有連結到指定 SSO 連接器 ID 的企業身份：{{ ssoConnectorId }}。',
};

export default Object.freeze(user);
