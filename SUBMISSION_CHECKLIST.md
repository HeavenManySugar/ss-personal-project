# ✅ 作業提交檢查清單

在提交作業之前，請確認以下所有項目都已完成：

## 📦 1. 必要檔案

- [ ] **原始碼**（完整專案資料夾）
- [ ] **PROJECT_REPORT.md**（3-5 頁完整報告）
- [ ] **schema.sql**（資料庫結構）
- [ ] **README.md** 或 **DEPLOYMENT_GUIDE.md**（安裝說明）

## 💻 2. 程式碼品質

- [ ] 所有程式碼都有**適當註解**
- [ ] 無明顯的編譯錯誤
- [ ] TypeScript 類型定義完整
- [ ] 程式碼結構清晰易懂

## 🔒 3. 安全功能實作

### 密碼安全
- [ ] **PBKDF2 雜湊**（100,000 次迭代）
- [ ] 每個使用者有**獨特的 salt**
- [ ] 資料庫中**不儲存明文密碼**
- [ ] 使用**常數時間比較**防止時序攻擊

### 多因素認證 (MFA)
- [ ] **TOTP 實作**（RFC 6238）
- [ ] **QR Code 產生**功能
- [ ] 與 **Google Authenticator 相容**
- [ ] 有**時鐘偏移容忍度**

### SQL Injection 防護
- [ ] **所有查詢都使用 Prepared Statements**
- [ ] 無字串拼接的 SQL 查詢
- [ ] 有輸入驗證
- [ ] TypeScript 類型安全

### XSS 防護
- [ ] **輸入清理**（移除 HTML 標籤）
- [ ] **輸出跳脫**（Astro 自動處理）
- [ ] **CSP 標頭**設定
- [ ] **HttpOnly cookies**（防止 JavaScript 存取）

### CSRF 防護
- [ ] 每個 session 有**唯一 CSRF token**
- [ ] 狀態變更操作都有**驗證 token**
- [ ] Cookie 有 **SameSite=Strict** 屬性

### Session 安全
- [ ] Cookie 有 **HttpOnly** flag
- [ ] Cookie 有 **Secure** flag
- [ ] Cookie 有 **SameSite=Strict** flag
- [ ] Session **24 小時後過期**
- [ ] 正確的**登出處理**

### 速率限制
- [ ] **5 次失敗後鎖定帳號**
- [ ] **15 分鐘冷卻期**
- [ ] 記錄**登入嘗試**
- [ ] 有**安全審計日誌**

## 🧪 4. 安全測試

### XSS 測試
- [ ] 測試輸入：`<script>alert('XSS')</script>`
- [ ] **結果：** 輸入被清理，沒有腳本執行
- [ ] 有截圖或測試記錄

### SQL Injection 測試
- [ ] 測試輸入：`admin' OR '1'='1`
- [ ] **結果：** 登入失敗，無法繞過認證
- [ ] 有截圖或測試記錄

### 密碼雜湊驗證
- [ ] 在資料庫中檢查密碼
- [ ] **結果：** 看到長雜湊字串，不是明文
- [ ] 執行：`npx wrangler d1 execute auth_system --command="SELECT username, password_hash, salt FROM users LIMIT 1"`

### MFA 功能測試
- [ ] 成功註冊帳號
- [ ] 啟用 MFA
- [ ] 掃描 QR code
- [ ] 登出後再登入
- [ ] **結果：** 需要輸入 MFA 代碼

### 帳號鎖定測試
- [ ] 連續 5 次輸入錯誤密碼
- [ ] **結果：** 「帳號已鎖定，請稍後再試」

## 📝 5. 報告內容（PROJECT_REPORT.md）

- [ ] **封面**（姓名、學號、課程、日期）
- [ ] **1. Introduction**（專案介紹、目標）
- [ ] **2. System Design**（系統架構圖、資料庫設計）
- [ ] **3. Security Implementation**（安全機制詳細說明）
  - [ ] Password hashing 說明 + 程式碼範例
  - [ ] MFA 實作說明
  - [ ] SQL Injection 防護說明
  - [ ] XSS 防護說明
  - [ ] Session 管理說明
- [ ] **4. Testing & Results**（測試結果 + 截圖）
  - [ ] XSS 測試結果
  - [ ] SQL Injection 測試結果
  - [ ] 密碼雜湊檢查結果
  - [ ] MFA 測試結果
- [ ] **5. Conclusion**（總結、成果）
- [ ] **6. Lessons Learned**（心得、學習收穫）
- [ ] **References**（參考資料）

## 📊 6. 報告格式

- [ ] 報告長度為 **3-5 頁**
- [ ] 有**架構圖**（系統設計）
- [ ] 有**程式碼範例**（重要功能）
- [ ] 有**測試截圖**（至少 2-3 張）
- [ ] 格式整齊、易讀

## 🎯 7. 功能完整性

### 基本功能
- [ ] **註冊頁面**正常運作
- [ ] **登入頁面**正常運作
- [ ] **Dashboard** 可正常顯示
- [ ] **登出功能**正常運作

### 進階功能
- [ ] **MFA 啟用/停用**功能正常
- [ ] **密碼強度檢查**（客戶端）
- [ ] **錯誤訊息適當**（不洩漏敏感資訊）
- [ ] **表單驗證**（客戶端 + 伺服器端）

## 🚀 8. 部署與執行

- [ ] 有清楚的**安裝說明**
- [ ] 有**部署步驟**說明
- [ ] 專案可以成功執行 `npm install`
- [ ] 專案可以成功執行 `npm run dev`
- [ ] 無明顯的執行錯誤

## 📚 9. 文件完整性

- [ ] **README.md** 或 **DEPLOYMENT_GUIDE.md** 說明如何安裝
- [ ] **PROJECT_REPORT.md** 完整報告
- [ ] **SECURITY_SETUP.md** 安全功能文件
- [ ] **schema.sql** 資料庫結構清楚
- [ ] 程式碼註解完整

## 🎓 10. 評分重點確認

根據作業要求，確認以下重點：

- [ ] ✅ **Secure coding practices** - 體現在程式碼中
- [ ] ✅ **Strong authentication** - PBKDF2 + MFA 實作
- [ ] ✅ **Prevent vulnerabilities** - SQL Injection、XSS 防護
- [ ] ✅ **Security testing** - 完整測試與結果

## 📤 提交前最後檢查

- [ ] 所有敏感資訊已移除（API keys、passwords）
- [ ] 壓縮檔包含所有必要檔案
- [ ] 檔案結構清楚
- [ ] 報告中填寫了姓名、學號
- [ ] 報告日期正確（Due: 12/03）

---

## ⚡ 快速測試指令

```bash
# 執行完整檢查
./test-setup.sh

# 檢查程式碼
npm run check

# 啟動開發伺服器
npm run dev

# 測試資料庫連線
npx wrangler d1 execute auth_system --command="SELECT * FROM users LIMIT 1"
```

---

## 🎉 全部完成！

當所有項目都打勾後，你就可以放心提交作業了！

**祝你拿高分！** 🏆
