# 🚀 部署指南

## 完整部署步驟

### 1. 安裝依賴

```bash
npm install
```

### 2. 建立 Cloudflare D1 資料庫

```bash
# 建立資料庫
npx wrangler d1 create auth_system
```

你會看到類似這樣的輸出：

```
✅ Successfully created DB 'auth_system'

[[d1_databases]]
binding = "DB"
database_name = "auth_system"
database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

**重要：複製 `database_id` 並更新 `wrangler.json` 中的 `database_id` 欄位！**

### 3. 初始化資料庫 Schema

```bash
# 套用 schema
npx wrangler d1 execute auth_system --file=./schema.sql
```

### 4. 本地測試

```bash
# 啟動開發伺服器
npm run dev
```

開啟瀏覽器訪問 `http://localhost:4321`

### 5. 測試功能

1. **註冊帳號**：訪問 `/register`
2. **登入**：訪問 `/login`
3. **啟用 MFA**：在 dashboard 中啟用 MFA
4. **測試安全性**：
   - XSS: 嘗試在表單中輸入 `<script>alert('XSS')</script>`
   - SQL Injection: 嘗試用 `admin' OR '1'='1` 登入

### 6. 部署到 Cloudflare（可選）

```bash
# 部署到生產環境
npm run deploy
```

## 📝 要交的檔案

1. **原始碼**（整個專案資料夾，含註解）
2. **PROJECT_REPORT.md** - 完整 3-5 頁報告
   - 包含架構圖
   - 安全機制說明
   - 測試結果
   - 學習心得

## ✅ 檢查清單

在提交前確認：

- [ ] 資料庫 schema 已建立
- [ ] 可以成功註冊帳號
- [ ] 可以成功登入
- [ ] MFA 功能正常運作
- [ ] XSS 測試通過（輸入被過濾）
- [ ] SQL Injection 測試通過（無法繞過認證）
- [ ] 密碼以雜湊值儲存（檢查資料庫）
- [ ] 報告已完成（3-5 頁）
- [ ] 程式碼含有適當註解

## 🐛 常見問題

### Q: wrangler 指令找不到？

```bash
npx wrangler --version
# 或全域安裝
npm install -g wrangler
```

### Q: D1 資料庫連線失敗？

確認 `wrangler.json` 中的 `database_id` 已正確設定。

### Q: 本地開發時無法存取 D1？

使用 `npm run dev`（不是 `astro dev`），這樣才會啟用 Cloudflare Workers 模擬環境。

### Q: TypeScript 錯誤？

執行 `npm run check` 檢查是否有錯誤。

## 📚 重要文件

- `PROJECT_REPORT.md` - 完整專案報告
- `SECURITY_SETUP.md` - 安全功能說明
- `schema.sql` - 資料庫結構
- `src/lib/*.ts` - 安全相關程式庫

