# OAuth 整合指南

本系統支援 OAuth 2.0 單一登入 (SSO)，允許管理員配置多個 OAuth 提供商,讓使用者可以使用 Google、GitHub、Microsoft 等第三方帳號登入。

## 功能特色

- ✅ 管理員可動態新增/編輯/刪除 OAuth 提供商
- ✅ 支援 Google、GitHub、Microsoft 及自訂提供商
- ✅ CSRF 保護 (使用 state token)
- ✅ 自動帳號連結 (透過 email)
- ✅ 使用者可在 Dashboard 查看已連結帳號
- ✅ OAuth 登入與傳統密碼登入並存

## 資料庫架構

執行以下 SQL 來建立 OAuth 相關資料表:

```bash
wrangler d1 execute DB --file=./oauth-schema.sql
```

### 資料表說明

1. **oauth_providers** - OAuth 提供商配置
   - 儲存 client_id、client_secret、endpoints、scope 等
   - 管理員可啟用/停用提供商

2. **oauth_accounts** - 使用者的 OAuth 帳號連結
   - 儲存 access_token、refresh_token
   - 記錄 provider_email 與 provider_username

3. **oauth_states** - CSRF 保護的 state token
   - 10 分鐘過期
   - 驗證後自動刪除

4. **admin_users** - 管理員權限
   - 只有管理員可管理 OAuth 設定

## 管理員設定

### 1. 授予管理員權限

```sql
INSERT INTO admin_users (user_id, granted_by) 
VALUES (1, NULL); -- user_id 1 成為第一個管理員
```

### 2. 訪問 OAuth 管理頁面

登入後前往: `/admin/oauth`

### 3. 新增 OAuth 提供商

#### Google OAuth 設定

1. 前往 [Google Cloud Console](https://console.cloud.google.com/)
2. 建立專案並啟用 OAuth 2.0
3. 設定授權重新導向 URI:
   ```
   https://your-domain.com/api/oauth/google/callback
   ```
4. 取得 Client ID 和 Client Secret
5. 在管理頁面填入:
   - **Provider Name**: `google`
   - **Display Name**: `Google`
   - **Client ID**: `你的 Client ID`
   - **Client Secret**: `你的 Client Secret`
   - **Authorization URL**: `https://accounts.google.com/o/oauth2/v2/auth`
   - **Token URL**: `https://oauth2.googleapis.com/token`
   - **User Info URL**: `https://www.googleapis.com/oauth2/v2/userinfo`
   - **Scope**: `openid email profile`

#### GitHub OAuth 設定

1. 前往 [GitHub Developer Settings](https://github.com/settings/developers)
2. 建立新的 OAuth App
3. 設定 Authorization callback URL:
   ```
   https://your-domain.com/api/oauth/github/callback
   ```
4. 取得 Client ID 和 Client Secret
5. 在管理頁面填入:
   - **Provider Name**: `github`
   - **Display Name**: `GitHub`
   - **Client ID**: `你的 Client ID`
   - **Client Secret**: `你的 Client Secret`
   - **Authorization URL**: `https://github.com/login/oauth/authorize`
   - **Token URL**: `https://github.com/login/oauth/access_token`
   - **User Info URL**: `https://api.github.com/user`
   - **Scope**: `read:user user:email`

#### Microsoft OAuth 設定

1. 前往 [Azure Portal](https://portal.azure.com/)
2. 註冊應用程式
3. 設定重新導向 URI:
   ```
   https://your-domain.com/api/oauth/microsoft/callback
   ```
4. 取得 Application (client) ID 和 Client Secret
5. 在管理頁面填入:
   - **Provider Name**: `microsoft`
   - **Display Name**: `Microsoft`
   - **Client ID**: `你的 Application ID`
   - **Client Secret**: `你的 Client Secret`
   - **Authorization URL**: `https://login.microsoftonline.com/common/oauth2/v2.0/authorize`
   - **Token URL**: `https://login.microsoftonline.com/common/oauth2/v2.0/token`
   - **User Info URL**: `https://graph.microsoft.com/v1.0/me`
   - **Scope**: `openid email profile User.Read`

### 4. 啟用提供商

設定完成後,點擊「Enable」按鈕啟用提供商。

## 使用者登入流程

### OAuth 登入流程

1. 使用者訪問 `/login` 頁面
2. 點擊 OAuth 提供商按鈕 (例如「Google」)
3. 重新導向到 `/api/oauth/google/authorize`
4. 系統生成 state token 並儲存到資料庫
5. 重新導向到 Google 授權頁面
6. 使用者同意授權
7. Google 回呼到 `/api/oauth/google/callback?code=xxx&state=xxx`
8. 系統驗證 state token
9. 交換 code 取得 access_token
10. 使用 access_token 取得使用者資訊
11. 檢查是否有相同 email 的現有帳號:
    - **有**: 連結 OAuth 帳號到現有帳號
    - **無**: 建立新使用者並連結 OAuth 帳號
12. 建立 session 並重新導向到 dashboard

### 帳號連結邏輯

- 透過 `provider_user_id` 尋找現有的 OAuth 連結
- 如果沒有找到,透過 `email` 尋找現有使用者
- 如果找到現有使用者,將 OAuth 帳號連結到該使用者
- 如果是新使用者,自動建立帳號 (email_verified = 1)

### 安全性特性

1. **CSRF 保護**: 使用 state token 防止跨站請求偽造
2. **Token 過期**: State token 10 分鐘過期
3. **單次使用**: State token 驗證後立即刪除
4. **Email 驗證**: OAuth 登入的使用者自動標記為已驗證

## API 端點

### 發起 OAuth 授權

```
GET /api/oauth/{provider}/authorize
```

參數:
- `provider`: 提供商名稱 (例如 `google`, `github`, `microsoft`)

### OAuth 回呼

```
GET /api/oauth/{provider}/callback?code={code}&state={state}
```

參數:
- `code`: 授權碼
- `state`: CSRF 保護 token

## 程式碼結構

```
src/
├── lib/
│   └── oauth.ts                    # OAuth 核心邏輯
├── pages/
│   ├── admin/
│   │   └── oauth.astro             # OAuth 管理頁面
│   ├── api/
│   │   └── oauth/
│   │       └── [provider]/
│   │           ├── authorize.ts    # 發起授權
│   │           └── callback.ts     # 處理回呼
│   └── login.astro                 # 登入頁面 (顯示 OAuth 按鈕)
└── dashboard.astro                 # 顯示已連結帳號
```

## 開發測試

### 本地開發設定

1. 在 OAuth 提供商設定中新增本地回呼 URL:
   ```
   http://localhost:4321/api/oauth/google/callback
   ```

2. 啟動開發伺服器:
   ```bash
   npm run dev
   ```

3. 測試 OAuth 登入流程

### 生產部署

1. 確保所有 OAuth 提供商的回呼 URL 指向生產網域
2. 部署到 Cloudflare Pages:
   ```bash
   npm run build
   wrangler pages deploy dist
   ```

## 故障排除

### OAuth 登入失敗

1. **檢查 state token**: 確認沒有過期 (10 分鐘)
2. **檢查回呼 URL**: 確認與 OAuth 提供商設定一致
3. **檢查 scope**: 確認請求的 scope 正確
4. **查看錯誤訊息**: 檢查 `/login?error=xxx` 的錯誤參數

### 常見錯誤碼

- `invalid_state`: State token 無效或過期
- `provider_not_found`: OAuth 提供商未啟用
- `no_email`: OAuth 提供商未提供 email
- `oauth_failed`: OAuth 流程失敗 (查看伺服器日誌)

## 安全建議

1. **加密 Client Secret**: 在生產環境中應加密儲存
2. **定期輪換 Token**: 實作 refresh token 機制
3. **限制 Scope**: 只請求必要的權限
4. **監控登入活動**: 記錄所有 OAuth 登入事件
5. **HTTPS Only**: 僅在 HTTPS 環境下使用 OAuth

## 進階功能 (未來可擴充)

- [ ] 使用者可主動連結/解除連結 OAuth 帳號
- [ ] 支援多個 OAuth 帳號連結到同一使用者
- [ ] Refresh token 自動更新機制
- [ ] OAuth 登入活動日誌
- [ ] 管理員可查看 OAuth 使用統計
