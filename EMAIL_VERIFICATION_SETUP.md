# Email Verification Setup Guide

## 1. 更新資料庫 Schema

執行以下命令來更新資料庫結構:

```bash
# 本地開發環境
npx wrangler d1 execute auth_system --file=./email-verification-schema.sql --local

# 生產環境
npx wrangler d1 execute auth_system --file=./email-verification-schema.sql --remote
```

## 2. 設定 Resend API

### 步驟 1: 註冊 Resend 帳號

1. 前往 [resend.com](https://resend.com) 註冊
2. 驗證你的域名 (或使用測試用的 `onboarding@resend.dev`)
3. 取得 API Key

### 步驟 2: 設定環境變數

```bash
# 設定 Resend API Key
npx wrangler secret put RESEND_API_KEY
# 輸入你的 Resend API Key (格式: re_xxxxxxxx)

# 設定寄件者信箱 (必須是已驗證的域名)
npx wrangler secret put FROM_EMAIL
# 輸入: your-email@yourdomain.com
# 或使用測試: onboarding@resend.dev
```

### 本地開發環境

創建 `.dev.vars` 檔案:

```env
RESEND_API_KEY=re_your_api_key_here
FROM_EMAIL=onboarding@resend.dev
```

## 3. 測試電子郵件功能

### 本地測試

```bash
npm run dev
```

1. 訪問 http://localhost:4321/register
2. 註冊新帳號
3. 檢查是否收到驗證郵件
4. 點擊郵件中的連結或輸入驗證碼

### 生產環境測試

```bash
npm run deploy
```

使用真實的電子郵件地址測試註冊流程。

## 4. Email Verification 流程

```
註冊 → 發送驗證郵件 → 用戶收到郵件 → 點擊連結/輸入驗證碼 → 驗證成功 → 登入
```

### 未完成註冊處理

系統會自動處理未完成的註冊:

1. **24 小時內**: 如果用戶嘗試重新註冊相同的 email/username,系統會:
   - 提示帳號已存在但未驗證
   - 提供「重新發送驗證郵件」按鈕
   - 限制每 2 分鐘只能發送一次

2. **24 小時後**: 自動刪除舊的未驗證帳號,允許重新註冊

3. **7 天後**: 定期清理腳本會自動刪除所有未驗證的帳號

### 重新發送驗證郵件

用戶可以在以下情況重新發送驗證郵件:
- 在註冊頁面看到「帳號已存在但未驗證」提示時
- 在驗證頁面點擊「Resend」連結
- 使用 API: `POST /api/auth/resend-verification`

### 安全特性

- ✅ 6位數隨機驗證碼
- ✅ 唯一驗證 token
- ✅ 15分鐘過期時間
- ✅ 防止重複驗證
- ✅ 重發郵件頻率限制(2分鐘)
- ✅ 自動清理過期帳號
- ✅ SQL injection 防護
- ✅ XSS 防護

## 5. 自訂郵件模板

編輯 `src/lib/email.ts` 中的 `generateVerificationEmailHTML` 函數來自訂郵件樣式:

```typescript
function generateVerificationEmailHTML(data: VerificationEmail): string {
  // 修改 HTML 模板
}
```

## 6. 監控和除錯

查看 Cloudflare Workers 日誌:

```bash
npx wrangler tail
```

檢查:
- 郵件發送狀態
- API 請求錯誤
- 資料庫查詢問題

## 7. 生產環境檢查清單

- [ ] 資料庫 schema 已更新
- [ ] 環境變數已設定
- [ ] SMTP 憑證已配置
- [ ] 測試註冊流程
- [ ] 測試驗證流程
- [ ] 測試重新發送功能
- [ ] 檢查郵件送達率
- [ ] 設定定期清理任務
- [ ] 監控錯誤日誌

## 8. 定期清理未驗證帳號

### 手動清理 (SQL)

```bash
npx wrangler d1 execute auth_system --file=./cleanup-unverified.sql --remote
```

### 自動清理 (API)

使用 Cloudflare Cron Triggers 或外部 cron job:

```bash
# 設定 admin token (可選)
npx wrangler secret put ADMIN_TOKEN

# 定期呼叫 API
curl -X POST https://your-domain.com/api/admin/cleanup-unverified \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

在 `wrangler.json` 中配置 Cron Trigger:

```json
{
  "triggers": {
    "crons": ["0 2 * * *"]
  }
}
```

## 常見問題

### Q: 如何取得 Resend API Key?
A: 前往 [resend.com](https://resend.com) 註冊並在 Dashboard 中生成 API Key

### Q: 可以使用免費方案嗎?
A: 可以! Resend 提供每月 3,000 封免費郵件額度,適合開發和小型專案

### Q: 必須驗證域名嗎?
A: 開發階段可使用 `onboarding@resend.dev`,生產環境建議驗證自己的域名

### Q: 郵件發送失敗但帳號已註冊?
A: 系統會在 24 小時後自動允許重新註冊,或使用「重新發送驗證郵件」功能

### Q: 可以重新發送驗證郵件嗎?
A: 可以,在驗證頁面點擊「Resend」或在註冊頁面看到提示時點擊重發按鈕

### Q: 重發郵件有頻率限制嗎?
A: 是的,每 2 分鐘只能發送一次,防止濫用

### Q: 驗證碼過期?
A: 預設 15 分鐘,可在 `send-verification.ts` 中調整

### Q: 郵件進入垃圾郵件?
A: 使用 Resend 並驗證自己的域名可大幅改善送達率

### Q: 未驗證的帳號會一直存在嗎?
A: 不會,24小時後可重新註冊,7天後會被自動清理
