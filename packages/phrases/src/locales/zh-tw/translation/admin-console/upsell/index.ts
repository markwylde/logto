import add_on from './add-on.js';
import featured_plan_content from './featured-plan-content.js';
import paywall from './paywall.js';

const upsell = {
  upgrade_plan: '升級計劃',
  compare_plans: '比較計劃',
  view_plans: '查看計劃',
  create_tenant: {
    title: '選擇您的租戶計劃',
    description:
      'Logto 提供創新且經濟實惠的定價計劃，旨在為不斷發展的公司提供競爭優勢。 <a>了解更多</a>',
    base_price: '基礎價格',
    monthly_price: '每月 {{value, number}}',
    view_all_features: '查看所有功能',
    select_plan: '選擇<name/>',
    free_tenants_limit: '最多{{count, number}}個免費租戶',
    free_tenants_limit_other: '最多{{count, number}}個免費租戶',
    most_popular: '最受歡迎',
    upgrade_success: '成功升級至<name/>',
  },
  mau_exceeded_modal: {
    title: 'MAU 超過限制，請升級您的計劃。',
    notification:
      '您當前的 MAU 已超過<planName/>的限制。請立即升級到高級計劃，以避免 Logto 服務的暫停。',
    update_plan: '更新計劃',
  },
  token_exceeded_modal: {
    title: '令牌使用超過限制，請升級您的計劃。',
    notification:
      '您的<planName/>令牌使用已超過限制。用戶將無法正常訪問 Logto 服務。請儘快升級您的計劃至高級，以避免任何不便。',
  },
  payment_overdue_modal: {
    title: '賬單逾期未付',
    notification:
      '糟糕！租戶<span>{{name}}</span>的賬單支付失敗。請儘快支付賬單，以避免 Logto 服務的中止。',
    unpaid_bills: '未付賬單',
    update_payment: '更新支付',
  },
  add_on_quota_item: {
    api_resource: 'API 資源',
    machine_to_machine: '機器對機器應用',
    tokens: '{{limit}}M 令牌',
    tenant_member: '租戶成員',
  },
  charge_notification_for_quota_limit:
    '您已超出{{item}}額度限制。Logto將為超出額度限制的使用添加費用。計費將從新的附加價格設計發布當天開始。 <a>了解更多</a>',
  paywall,
  featured_plan_content,
  add_on,
  convert_to_production_modal: {
    title: '你即將把開發租戶轉換為生產租戶',
    description: '準備好上線了嗎？將此開發租戶轉換為生產租戶以解鎖全部功能',
    benefits: {
      stable_environment: '對終端用戶：提供穩定的實際使用環境。',
      keep_pro_features: '保留專業版功能：你將訂閱專業版計劃。 <a>查看專業版功能。</a>',
      no_dev_restrictions: '沒有開發限制：移除實體和資源系統限制及登錄橫幅。',
    },
    cards: {
      dev_description: '測試用途',
      prod_description: '實際生產',
      convert_label: '轉換',
    },
    button: '轉換為生產租戶',
  },
};

export default Object.freeze(upsell);
