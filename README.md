# AES-256 網頁加解密工具

這是 AES-256 加解密工具的純前端網頁版。它可以直接在本機瀏覽器開啟使用，不需要伺服器。

## 功能

- AES-256-CBC / AES-256-GCM 加密與解密
- PKCS7 padding
- 明文以 UTF-8 處理
- 密文以 Base64 輸出 / 輸入
- 支援貼上文字
- 支援上傳 `.txt`
- 支援下載 `.enc.txt` / `.dec.txt`
- 支援多組 Key / IV profiles
- Profiles 儲存在使用者本機瀏覽器 `localStorage`
- 支援匯入 / 匯出 profiles JSON
- AES 解密結果可做 JSON 美化，並保留原本欄位順序
- 內建小工具區，支援 UTF-8 / Base64 / Hex 即時互轉
- JSON Diff 比對工具，可先做 JSON 美化排序，再比對欄位差異與欄位值差異
- Log 整理 / 還原工具，可在本機整理 JSON、log 內嵌 JSON、Java / Spring log、escaped JSON、query string、key=value 與 headers
- Hash / HMAC 計算工具，支援 SHA-256、SHA-512、HMAC-SHA256、HMAC-SHA512
- 左側功能選單可切換 AES 加解密、文字編碼轉換、JSON Diff、Log 整理與 Hash / HMAC

## 使用方式

1. 打開 `index.html`。
2. 預設會進入「AES 加解密」功能。
3. 新增一組 Key / IV，或匯入 profiles JSON。
4. 選擇「加密」或「解密」。
5. 貼上文字或上傳 `.txt`。
6. 按下執行。
7. 複製結果或下載 TXT。

## 小工具

左側功能選單可切換到其他小工具：

共用的格式化、編碼、JSON 與複製輔助函式集中在 `shared-utils.js`，各工具主流程保留在 `app.js`。

### 文字編碼轉換

- 在 UTF-8、Base64 或 Hex 任一欄輸入內容，其他兩欄會即時更新
- Base64 欄支援一般 Base64，也可接受 URL-safe 字元 `-`、`_`
- Hex 欄可包含空白或換行，但有效 hex 字元數必須是偶數

### JSON Diff

- 左右貼入兩份 JSON 後按「比對」
- 預設啟用「JSON 美化排序」，object key 會穩定排序，array 會維持原順序
- 差異會分成「欄位差異」、「欄位值差異」與「型別差異」，摘要保留完整統計，列表可依分類篩看

### Log 整理 / 還原

- 可整理標準 JSON、log 內嵌 JSON、Java / Spring log、escaped JSON、JSON 字串內包 JSON、query string、key=value 與 HTTP headers
- 若一般 log 行尾或訊息中包含 JSON payload，會保留 log 文字並獨立格式化 JSON payload
- 若貼上多行 Java / Spring log，會拆出時間、等級、thread、logger、source 與 message，並用空行分隔每筆 entry；單筆 log 被換行拆開時也會先合併判斷
- Nested JSON 字串只會在看起來高度像 JSON 且 parse 成功時展開，最多展開 3 層
- 無法安全辨識的內容會保留原文，不會強行結構化或做根因分析

### Hash / HMAC

- 可計算 SHA-256、SHA-512、HMAC-SHA256、HMAC-SHA512
- 原文與 HMAC key 均以 UTF-8 處理
- 輸出 Hex 與 Base64，並可貼上預期值做一致性驗證

後續若要增加其他小工具，可以延伸同一個工具區，不需要改動 AES 加解密主流程。

## Key / IV 格式

CBC Key 支援：

- UTF-8 文字，編碼後必須剛好 `32 bytes`
- Base64，解碼後必須剛好 `32 bytes`

CBC IV 支援：

- UTF-8 文字，編碼後必須剛好 `16 bytes`
- Base64，解碼後必須剛好 `16 bytes`

GCM Key 支援：

- UTF-8 文字，編碼後必須剛好 `32 bytes`
- Base64，解碼後必須剛好 `32 bytes`
- Hex，必須剛好 `64` 個 hex 字元

GCM IV 支援：

- UTF-8 文字，編碼後必須剛好 `12 bytes`
- Base64，解碼後必須剛好 `12 bytes`
- Hex，必須剛好 `24` 個 hex 字元

## 本機保存說明

Profiles 只會存在使用者自己的瀏覽器：

```text
localStorage: aes_cbc_web_profiles_v1
```

這代表：

- 不會上傳到伺服器
- 不會寫入網頁原始碼
- 不會分享給其他使用者
- 換瀏覽器或清除瀏覽資料後，profiles 可能會消失

如果 Key / IV 很重要，建議定期使用「匯出 profiles JSON」備份，並妥善保管該 JSON 檔案。

## 安全提醒

`localStorage` 適合個人本機便利使用，但不是加密保險箱。如果電腦被他人使用、瀏覽器帳號被存取、瀏覽器擴充套件有風險，Key / IV 仍可能被讀取。

建議：

- 只在自己的電腦使用「儲存 profiles」
- 共用電腦使用完請按「清除本機保存」
- 不要把 profiles JSON 放在公開位置

## 流量統計

對外公開網站版本可使用 Google Analytics 4 (GA4) 記錄頁面瀏覽量，用於估算網站被查看的人次。

網站畫面上的「網站瀏覽次數」則使用 CounterAPI 公開計數器，會在公開 GitHub Pages 網址每次載入頁面時累加一次，方便直接在畫面上查看累積瀏覽次數。

目前只加入頁面瀏覽統計，不會主動把使用者輸入的明文、密文、Key、IV 或 profiles 內容送到分析服務。

## 相容性

本工具使用瀏覽器 Web Crypto API。建議使用新版 Chrome 或 Edge。

如果直接雙擊 `index.html` 後瀏覽器顯示 Web Crypto 不可用，可以改用本機 localhost 開啟，例如在此資料夾執行：

```powershell
python -m http.server 8080
```

然後打開：

```text
http://localhost:8080/
```
