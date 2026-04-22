# AES-CBC Web V1.0.0

這是 AES-CBC 加解密工具的純前端網頁版。它可以直接在本機瀏覽器開啟使用，不需要伺服器。

## 功能

- AES-256-CBC 加密 / 解密
- PKCS7 padding
- 明文以 UTF-8 處理
- 密文以 Base64 輸出 / 輸入
- 支援貼上文字
- 支援上傳 `.txt`
- 支援下載 `.enc.txt` / `.dec.txt`
- 支援多組 Key / IV profiles
- Profiles 儲存在使用者本機瀏覽器 `localStorage`
- 支援匯入 / 匯出 profiles JSON

## 使用方式

1. 打開 `index.html`。
2. 新增一組 Key / IV，或匯入 profiles JSON。
3. 選擇「加密」或「解密」。
4. 貼上文字或上傳 `.txt`。
5. 按下執行。
6. 複製結果或下載 TXT。

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
