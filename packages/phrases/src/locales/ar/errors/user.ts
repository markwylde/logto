const user = {
  username_already_in_use: 'اسم المستخدم هذا مستخدم بالفعل.',
  email_already_in_use: 'هذا البريد الإلكتروني مرتبط بحساب موجود بالفعل.',
  phone_already_in_use: 'هذا الرقم الهاتفي مرتبط بحساب موجود بالفعل.',
  invalid_email: 'عنوان البريد الإلكتروني غير صالح.',
  invalid_phone: 'رقم الهاتف غير صالح.',
  email_not_exist: 'عنوان البريد الإلكتروني غير مسجل حتى الآن.',
  phone_not_exist: 'رقم الهاتف غير مسجل حتى الآن.',
  identity_not_exist: 'الحساب الاجتماعي غير مسجل حتى الآن.',
  identity_already_in_use: 'تم ربط الحساب الاجتماعي بحساب موجود بالفعل.',
  social_account_exists_in_profile: 'لقد قمت بربط هذا الحساب الاجتماعي بالفعل.',
  cannot_delete_self: 'لا يمكنك حذف نفسك.',
  sign_up_method_not_enabled: 'طريقة التسجيل هذه غير ممكّنة.',
  sign_in_method_not_enabled: 'طريقة تسجيل الدخول هذه غير ممكّنة.',
  same_password: 'لا يمكن أن تكون كلمة المرور الجديدة هي نفس كلمة المرور القديمة.',
  password_required_in_profile: 'يجب عليك تعيين كلمة مرور قبل تسجيل الدخول.',
  new_password_required_in_profile: 'يجب عليك تعيين كلمة مرور جديدة.',
  password_exists_in_profile: 'كلمة المرور موجودة بالفعل في ملف التعريف الخاص بك.',
  username_required_in_profile: 'يجب عليك تعيين اسم مستخدم قبل تسجيل الدخول.',
  username_exists_in_profile: 'اسم المستخدم موجود بالفعل في ملف التعريف الخاص بك.',
  email_required_in_profile: 'يجب عليك إضافة عنوان بريد إلكتروني قبل تسجيل الدخول.',
  email_exists_in_profile: 'تم ربط ملف التعريف الخاص بك بالفعل بعنوان بريد إلكتروني.',
  phone_required_in_profile: 'يجب عليك إضافة رقم هاتف قبل تسجيل الدخول.',
  phone_exists_in_profile: 'تم ربط ملف التعريف الخاص بك بالفعل برقم هاتف.',
  email_or_phone_required_in_profile:
    'يجب عليك إضافة عنوان بريد إلكتروني أو رقم هاتف قبل تسجيل الدخول.',
  suspended: 'تم تعليق هذا الحساب.',
  user_not_exist: 'المستخدم بالمعرف {{ identifier }} غير موجود.',
  missing_profile: 'يجب عليك تقديم معلومات إضافية قبل تسجيل الدخول.',
  role_exists: 'تمت إضافة معرف الدور {{roleId}} بالفعل لهذا المستخدم.',
  invalid_role_type: 'نوع الدور غير صالح، لا يمكن تعيين دور آلة إلى المستخدم.',
  missing_mfa: 'يجب عليك ربط MFA الإضافي قبل تسجيل الدخول.',
  totp_already_in_use: 'تم استخدام TOTP بالفعل.',
  backup_code_already_in_use: 'تم استخدام رمز النسخ الاحتياطي بالفعل.',
  password_algorithm_required: 'مطلوب خوارزمية كلمة المرور.',
  password_and_digest: 'لا يمكنك تعيين كلمة مرور عادية ومعلومات تجزئة كلمة المرور معًا.',
  personal_access_token_name_exists: 'اسم رمز الوصول الشخصي موجود بالفعل.',
  /** UNTRANSLATED */
  totp_secret_invalid: 'Invalid TOTP secret supplied.',
  /** UNTRANSLATED */
  wrong_backup_code_format: 'Backup code format is invalid.',
  /** UNTRANSLATED */
  username_required: 'Username is a required identifier, you can not set it to null.',
  /** UNTRANSLATED */
  email_or_phone_required:
    'Email address or phone number is a required identifier, at least one is required.',
  /** UNTRANSLATED */
  email_required: 'Email address is a required identifier, you can not set it to null.',
  /** UNTRANSLATED */
  phone_required: 'Phone number is a required identifier, you can not set it to null.',
};

export default Object.freeze(user);
