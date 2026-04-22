(function () {
  "use strict";

  const STORAGE_KEY = "aes_cbc_web_profiles_v1";
  const APP_VERSION = "V1.0.1";
  const encoder = new TextEncoder();
  const decoder = new TextDecoder("utf-8", { fatal: false });
  const LARGE_TEXT_BYTES = 2 * 1024 * 1024;
  const VERY_LARGE_TEXT_BYTES = 10 * 1024 * 1024;

  const state = {
    mode: "E",
    cipherMode: "CBC",
    profiles: [],
    lastOutputName: ".enc.txt",
    lastOutputText: "",
    lastRawDecryptedText: "",
    lastGcmSources: null
  };

  const $ = (id) => document.getElementById(id);
  const els = {
    appVersion: $("appVersion"),
    cryptoNotice: $("cryptoNotice"),
    profileSelect: $("profileSelect"),
    profileName: $("profileName"),
    keyInput: $("keyInput"),
    ivInput: $("ivInput"),
    showSecrets: $("showSecrets"),
    newProfileBtn: $("newProfileBtn"),
    saveProfileBtn: $("saveProfileBtn"),
    deleteProfileBtn: $("deleteProfileBtn"),
    clearAllBtn: $("clearAllBtn"),
    importProfilesBtn: $("importProfilesBtn"),
    exportProfilesBtn: $("exportProfilesBtn"),
    profilesFile: $("profilesFile"),
    cbcMode: $("cbcMode"),
    gcmMode: $("gcmMode"),
    cipherTitle: $("cipherTitle"),
    cipherSubtitle: $("cipherSubtitle"),
    encryptMode: $("encryptMode"),
    decryptMode: $("decryptMode"),
    dropzone: $("dropzone"),
    textFile: $("textFile"),
    fileName: $("fileName"),
    inputLabel: $("inputLabel"),
    inputText: $("inputText"),
    inputStats: $("inputStats"),
    runBtn: $("runBtn"),
    clearInputBtn: $("clearInputBtn"),
    outputLabel: $("outputLabel"),
    outputText: $("outputText"),
    formatJsonOutput: $("formatJsonOutput"),
    copyBtn: $("copyBtn"),
    downloadBtn: $("downloadBtn"),
    clearOutputBtn: $("clearOutputBtn"),
    messageLog: $("messageLog")
  };

  function log(message, isError) {
    els.messageLog.textContent = message;
    els.messageLog.style.color = isError ? "#a83028" : "#69746e";
  }

  function formatBytes(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
  }

  function getTextByteLength(text) {
    return encoder.encode(text || "").length;
  }

  function updateInputStats() {
    const text = els.inputText.value || "";
    const bytes = getTextByteLength(text);
    els.inputStats.textContent = `${text.length.toLocaleString()} 字元 / 約 ${formatBytes(bytes)}`;
    els.inputStats.classList.toggle("warn", bytes >= LARGE_TEXT_BYTES);
  }

  function confirmLargeText(bytes, action) {
    if (bytes >= VERY_LARGE_TEXT_BYTES) {
      return confirm(`${action}內容約 ${formatBytes(bytes)}，瀏覽器可能明顯變慢甚至暫時無回應。確定要繼續？`);
    }
    if (bytes >= LARGE_TEXT_BYTES) {
      return confirm(`${action}內容約 ${formatBytes(bytes)}，處理與顯示可能需要一些時間。要繼續嗎？`);
    }
    return true;
  }

  async function loadTextFile(file) {
    if (!file) return;
    if (!confirmLargeText(file.size, "讀取的檔案")) return;
    els.inputText.value = await file.text();
    els.fileName.textContent = `${file.name} (${formatBytes(file.size)})`;
    updateInputStats();
    log(`已讀取檔案：${file.name}，大小 ${formatBytes(file.size)}。`);
  }

  function normalizeBase64(value) {
    return String(value || "").replace(/\s+/g, "");
  }

  function bytesToBase64(bytes) {
    let binary = "";
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(binary);
  }

  function base64ToBytes(value) {
    const normalized = normalizeBase64(value);
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized) || normalized.length % 4 !== 0) {
      throw new Error("不是有效的 Base64 格式。");
    }
    const binary = atob(normalized);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  function hexToBytes(value, expectedLength, label) {
    const normalized = String(value || "").replace(/\s+/g, "");
    if (!new RegExp(`^[0-9a-fA-F]{${expectedLength * 2}}$`).test(normalized)) {
      throw new Error(`${label} 格式錯誤：GCM ${label} 需為 ${expectedLength} bytes，也就是 ${expectedLength * 2} 個 hex 字元。`);
    }
    const bytes = new Uint8Array(expectedLength);
    for (let i = 0; i < expectedLength; i++) {
      bytes[i] = parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  function safeHexToBytes(value, expectedLength) {
    try { return hexToBytes(value, expectedLength, ""); } catch (_) { return null; }
  }

  function concatBytes(...parts) {
    const total = parts.reduce((sum, part) => sum + part.length, 0);
    const output = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) {
      output.set(part, offset);
      offset += part.length;
    }
    return output;
  }

  function safeBase64ToBytes(value) {
    try { return base64ToBytes(value); } catch (_) { return null; }
  }

  function getKeyCandidates(value) {
    const list = [];
    const raw = String(value || "");
    if (!raw.trim()) return list;
    const utf8 = encoder.encode(raw);
    if (utf8.length === 32) list.push({ bytes: utf8, source: "UTF-8", score: 100 });
    const b64 = safeBase64ToBytes(raw);
    if (b64 && b64.length === 32) list.push({ bytes: b64, source: "Base64", score: utf8.length === 32 ? 80 : 120 });
    return list;
  }

  function getByteCandidates(value, expectedLength, includeHex) {
    const list = [];
    const raw = String(value || "");
    if (!raw.trim()) return list;
    const utf8 = encoder.encode(raw);
    if (utf8.length === expectedLength) list.push({ bytes: utf8, source: "UTF-8", score: 100 });
    const b64 = safeBase64ToBytes(raw);
    if (b64 && b64.length === expectedLength) list.push({ bytes: b64, source: "Base64", score: utf8.length === expectedLength ? 80 : 120 });
    if (includeHex) {
      const hex = safeHexToBytes(raw, expectedLength);
      if (hex) list.push({ bytes: hex, source: "Hex", score: 90 });
    }
    return list;
  }

  function getIvCandidates(value) {
    return getByteCandidates(value, 16, false);
  }

  function getGcmKeyCandidates(value) {
    return getByteCandidates(value, 32, true);
  }

  function getGcmIvCandidates(value) {
    return getByteCandidates(value, 12, true);
  }

  async function importAesKey(keyBytes) {
    return crypto.subtle.importKey("raw", keyBytes, { name: "AES-CBC" }, false, ["encrypt", "decrypt"]);
  }

  async function importGcmKey(keyBytes) {
    return crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  }

  async function encryptText(plain, keyBytes, ivBytes) {
    if (!plain) throw new Error("明文為空：沒有可加密的資料。");
    const key = await importAesKey(keyBytes);
    const encrypted = await crypto.subtle.encrypt({ name: "AES-CBC", iv: ivBytes }, key, encoder.encode(plain));
    return bytesToBase64(new Uint8Array(encrypted));
  }

  async function decryptText(cipherBase64, keyBytes, ivBytes) {
    if (!String(cipherBase64 || "").trim()) throw new Error("密文為空：沒有可解密的資料。");
    const key = await importAesKey(keyBytes);
    const cipherBytes = base64ToBytes(cipherBase64);
    const decrypted = await crypto.subtle.decrypt({ name: "AES-CBC", iv: ivBytes }, key, cipherBytes);
    return decoder.decode(new Uint8Array(decrypted));
  }

  async function encryptGcmText(plain, keyBytes, ivBytes) {
    if (!plain) throw new Error("明文為空：沒有可加密的資料。");
    const key = await importGcmKey(keyBytes);
    const encryptedWithTag = new Uint8Array(await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: ivBytes, tagLength: 128 },
      key,
      encoder.encode(plain)
    ));
    return bytesToBase64(concatBytes(encryptedWithTag, ivBytes));
  }

  async function decryptGcmText(cipherBase64, keyBytes) {
    if (!String(cipherBase64 || "").trim()) throw new Error("密文為空：沒有可解密的資料。");
    const packed = base64ToBytes(cipherBase64);
    if (packed.length <= 28) {
      throw new Error("GCM 密文長度不足：需包含 ciphertext + 16 bytes tag + 12 bytes IV。");
    }
    const ivBytes = packed.slice(packed.length - 12);
    const encryptedWithTag = packed.slice(0, packed.length - 12);
    const key = await importGcmKey(keyBytes);
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: ivBytes, tagLength: 128 },
      key,
      encryptedWithTag
    );
    return decoder.decode(new Uint8Array(decrypted));
  }

  function scorePlainText(text) {
    let score = 0;
    if (/^\s*[{\[]/.test(text)) score += 50;
    if (/[\u4E00-\u9FFFA-Za-z0-9]/.test(text)) score += 20;
    const printable = (text.match(/[\x09\x0A\x0D\x20-\x7E\u4E00-\u9FFF]/g) || []).length;
    if (text.length > 0) score += Math.min(20, Math.floor(printable * 20 / text.length));
    return score;
  }

  function sortJsonValue(value) {
    if (Array.isArray(value)) return value.map(sortJsonValue);
    if (value && typeof value === "object") {
      return Object.keys(value).sort((a, b) => a.localeCompare(b, "zh-Hant")).reduce((sorted, key) => {
        sorted[key] = sortJsonValue(value[key]);
        return sorted;
      }, {});
    }
    return value;
  }

  function formatJsonIfEnabled(text) {
    if (!els.formatJsonOutput || !els.formatJsonOutput.checked) {
      return { text, formatted: false };
    }
    const trimmed = String(text || "").trim();
    if (!trimmed || !/^[{\[]/.test(trimmed)) {
      return { text, formatted: false };
    }
    try {
      const parsed = JSON.parse(trimmed);
      return { text: JSON.stringify(sortJsonValue(parsed), null, 2), formatted: true };
    } catch (_) {
      return { text, formatted: false };
    }
  }

  function stringifyGcmBody(value) {
    return JSON.stringify(value).replace(/":/g, '": ');
  }

  function tryParseJsonObject(text) {
    try {
      const parsed = JSON.parse(text);
      return parsed && typeof parsed === "object" ? parsed : null;
    } catch (_) {
      return null;
    }
  }

  function resolveGcmParams(requireIv) {
    const keyCandidates = getGcmKeyCandidates(els.keyInput.value);
    const ivCandidates = requireIv ? getGcmIvCandidates(els.ivInput.value) : [];
    if (!keyCandidates.length) throw new Error("Key 格式錯誤：GCM Key 需為 UTF-8 32 bytes、Base64 解碼後 32 bytes，或 64 個 hex 字元。");
    if (requireIv && !ivCandidates.length) throw new Error("IV 格式錯誤：GCM IV 需為 UTF-8 12 bytes、Base64 解碼後 12 bytes，或 24 個 hex 字元。");
    state.lastGcmSources = {
      key: keyCandidates[0].source,
      iv: requireIv ? ivCandidates[0].source : "密文內含"
    };
    return {
      key: keyCandidates[0],
      iv: requireIv ? ivCandidates[0] : null
    };
  }

  async function encryptGcmContent(content) {
    const { key, iv } = resolveGcmParams(true);
    const parsed = tryParseJsonObject(content);
    if (parsed && Object.prototype.hasOwnProperty.call(parsed, "Body")) {
      const bodyPlain = typeof parsed.Body === "string" ? parsed.Body : stringifyGcmBody(parsed.Body);
      parsed.Body = await encryptGcmText(bodyPlain, key.bytes, iv.bytes);
      return JSON.stringify(parsed, null, 2);
    }
    return encryptGcmText(content, key.bytes, iv.bytes);
  }

  async function decryptGcmContent(content) {
    const { key } = resolveGcmParams(false);
    const parsed = tryParseJsonObject(content);
    if (parsed && typeof parsed.Body === "string") {
      const bodyPlain = await decryptGcmText(parsed.Body, key.bytes);
      const bodyJson = tryParseJsonObject(bodyPlain);
      parsed.Body = bodyJson || bodyPlain;
      return JSON.stringify(parsed, null, 2);
    }
    return decryptGcmText(content, key.bytes);
  }

  function showOutput(output) {
    const outputBytes = getTextByteLength(output);
    state.lastOutputText = output;
    if (outputBytes >= LARGE_TEXT_BYTES && !confirm(`輸出結果約 ${formatBytes(outputBytes)}，完整顯示在文字框可能造成瀏覽器變慢。要完整顯示嗎？\n\n選「取消」仍可直接下載或複製完整結果。`)) {
      els.outputText.value = `結果已產生，但因為約 ${formatBytes(outputBytes)}，未完整顯示以避免畫面卡頓。請使用「下載結果 TXT」或「複製結果」。`;
    } else {
      els.outputText.value = output;
    }
    els.downloadBtn.disabled = false;
    return outputBytes;
  }

  function refreshJsonOutputFromRaw() {
    if (!state.lastRawDecryptedText) return;
    const jsonResult = formatJsonIfEnabled(state.lastRawDecryptedText);
    state.lastOutputName = jsonResult.formatted ? ".dec.pretty.json.txt" : ".dec.txt";
    const outputBytes = showOutput(jsonResult.text);
    const jsonNote = jsonResult.formatted ? "已套用 JSON 美化排序。" : "已顯示原始解密結果。";
    log(`${jsonNote}輸出約 ${formatBytes(outputBytes)}。`);
  }

  async function resolveKeyIvForMode(mode, content) {
    const keyCandidates = getKeyCandidates(els.keyInput.value);
    const ivCandidates = getIvCandidates(els.ivInput.value);
    if (!keyCandidates.length) throw new Error("Key 格式錯誤：AES-256 Key 需為 UTF-8 32 bytes，或 Base64 解碼後為 32 bytes。");
    if (!ivCandidates.length) throw new Error("IV 格式錯誤：需為 UTF-8 16 bytes，或 Base64 解碼後為 16 bytes。");

    let best = null;
    for (const key of keyCandidates) {
      for (const iv of ivCandidates) {
        const pair = { key, iv, score: key.score + iv.score, plain: null };
        if (mode === "D") {
          try {
            const plain = await decryptText(content, key.bytes, iv.bytes);
            pair.score += 1000 + scorePlainText(plain);
            pair.plain = plain;
          } catch (_) {
            pair.score -= 1000;
          }
        }
        if (!best || pair.score > best.score) best = pair;
      }
    }

    if (mode === "D" && (!best || best.plain === null)) {
      throw new Error("解密失敗：密文內容、Key 或 IV 不一致，請確認是否選到同一組設定。");
    }
    return best;
  }

  function loadProfiles() {
    try {
      const parsed = JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
      state.profiles = Array.isArray(parsed) ? parsed.filter(isProfileLike) : [];
    } catch (_) {
      state.profiles = [];
    }
  }

  function saveProfiles() {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state.profiles, null, 2));
  }

  function isProfileLike(item) {
    return item && typeof item === "object" && typeof item.name === "string" && typeof item.key === "string" && typeof item.iv === "string";
  }

  function extractProfiles(json) {
    const parsed = JSON.parse(json);
    const source = Array.isArray(parsed) ? parsed : parsed.profiles;
    if (!Array.isArray(source)) throw new Error("JSON 內找不到 profiles 陣列。");
    const profiles = source.filter(isProfileLike).map((p, index) => ({
      name: p.name.trim() || `匯入設定 ${index + 1}`,
      key: p.key,
      iv: p.iv
    }));
    if (!profiles.length) throw new Error("沒有可匯入的 Key/IV 設定。");
    return profiles;
  }

  function renderProfiles(selectedIndex) {
    els.profileSelect.innerHTML = "";
    if (!state.profiles.length) {
      const option = document.createElement("option");
      option.value = "";
      option.textContent = "尚未建立設定";
      els.profileSelect.appendChild(option);
      els.profileName.value = "";
      els.keyInput.value = "";
      els.ivInput.value = "";
      return;
    }

    state.profiles.forEach((profile, index) => {
      const option = document.createElement("option");
      option.value = String(index);
      option.textContent = profile.name;
      els.profileSelect.appendChild(option);
    });

    const index = Number.isInteger(selectedIndex) ? selectedIndex : 0;
    els.profileSelect.value = String(Math.max(0, Math.min(index, state.profiles.length - 1)));
    loadSelectedProfile();
  }

  function loadSelectedProfile() {
    const profile = state.profiles[Number(els.profileSelect.value)];
    if (!profile) return;
    els.profileName.value = profile.name;
    els.keyInput.value = profile.key;
    els.ivInput.value = profile.iv;
  }

  function isValidCbcProfile(profile) {
    return getKeyCandidates(profile.key).length && getIvCandidates(profile.iv).length;
  }

  function isValidGcmProfile(profile) {
    return getGcmKeyCandidates(profile.key).length && getGcmIvCandidates(profile.iv).length;
  }

  function validateProfileForSave(profile) {
    const cbcValid = isValidCbcProfile(profile);
    const gcmValid = isValidGcmProfile(profile);
    if (state.cipherMode === "GCM" && gcmValid) return;
    if (state.cipherMode === "CBC" && cbcValid) return;
    if (gcmValid) {
      setCipherMode("GCM");
      return;
    }
    if (cbcValid) {
      setCipherMode("CBC");
      return;
    }
    throw new Error("Key / IV 格式錯誤，尚未儲存。CBC IV 需 16 bytes；GCM IV 需 12 bytes。");
  }

  function saveCurrentProfile() {
    const profile = {
      name: els.profileName.value.trim() || "未命名設定",
      key: els.keyInput.value,
      iv: els.ivInput.value
    };

    validateProfileForSave(profile);

    const selectedValue = els.profileSelect.value;
    const selected = Number(selectedValue);
    if (selectedValue !== "" && Number.isInteger(selected) && selected >= 0 && selected < state.profiles.length) {
      state.profiles[selected] = profile;
      saveProfiles();
      renderProfiles(selected);
    } else {
      state.profiles.push(profile);
      saveProfiles();
      renderProfiles(state.profiles.length - 1);
    }
    log(`已儲存「${profile.name}」到本機瀏覽器。`);
  }

  function setMode(mode) {
    state.mode = mode;
    const isEncrypt = mode === "E";
    els.encryptMode.classList.toggle("active", isEncrypt);
    els.decryptMode.classList.toggle("active", !isEncrypt);
    els.inputLabel.textContent = isEncrypt ? "明文" : "密文 Base64";
    els.outputLabel.textContent = isEncrypt ? "加密結果 Base64" : "解密結果";
    els.runBtn.textContent = isEncrypt ? "執行加密" : "執行解密";
    state.lastOutputName = isEncrypt ? ".enc.txt" : ".dec.txt";
  }

  function setCipherMode(mode) {
    state.cipherMode = mode;
    const isGcm = mode === "GCM";
    els.cbcMode.classList.toggle("active", !isGcm);
    els.gcmMode.classList.toggle("active", isGcm);
    els.cipherTitle.textContent = isGcm ? "AES-256-GCM" : "AES-256-CBC";
    els.cipherSubtitle.textContent = isGcm ? "NoPadding / IV12 / Tag16 / Base64" : "PKCS7 / UTF-8 / Base64";
    els.keyInput.placeholder = isGcm
      ? "UTF-8 32 bytes、Base64 32 bytes，或 64 個 hex 字元"
      : "UTF-8 32 bytes 或 Base64 解碼後 32 bytes";
    els.ivInput.placeholder = isGcm
      ? "UTF-8 12 bytes、Base64 12 bytes，或 24 個 hex 字元"
      : "UTF-8 16 bytes 或 Base64 解碼後 16 bytes";
    log(isGcm
      ? "已切換到 GCM：Key/IV 可使用 UTF-8、Base64 或 hex；若輸入完整 JSON，會加解密 Body 欄位。"
      : "已切換到 CBC：沿用原本 Key/IV 與整段文字加解密流程。");
  }

  function downloadText(filename, text, withBom) {
    const parts = withBom ? [new Uint8Array([0xef, 0xbb, 0xbf]), text] : [text];
    const blob = new Blob(parts, { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  async function runCrypto() {
    try {
      const content = els.inputText.value;
      const inputBytes = getTextByteLength(content);
      if (!confirmLargeText(inputBytes, "即將處理的")) return;
      els.runBtn.disabled = true;
      els.runBtn.textContent = state.mode === "E" ? "加密中..." : "解密中...";
      const pair = state.cipherMode === "CBC" ? await resolveKeyIvForMode(state.mode, content) : null;
      let output;
      if (state.cipherMode === "GCM") {
        if (state.mode === "E") {
          state.lastRawDecryptedText = "";
          output = await encryptGcmContent(content);
          state.lastOutputName = ".gcm.enc.txt";
        } else {
          output = await decryptGcmContent(content);
          state.lastRawDecryptedText = output;
          const jsonResult = formatJsonIfEnabled(output);
          output = jsonResult.text;
          state.lastOutputName = jsonResult.formatted ? ".gcm.dec.pretty.json.txt" : ".gcm.dec.txt";
        }
      } else if (state.mode === "E") {
        state.lastRawDecryptedText = "";
        output = await encryptText(content, pair.key.bytes, pair.iv.bytes);
        state.lastOutputName = ".enc.txt";
      } else {
        state.lastRawDecryptedText = pair.plain;
        const jsonResult = formatJsonIfEnabled(pair.plain);
        output = jsonResult.text;
        state.lastOutputName = jsonResult.formatted ? ".dec.pretty.json.txt" : ".dec.txt";
      }
      const outputBytes = showOutput(output);
      const jsonNote = state.lastOutputName.includes("pretty.json") ? "已套用 JSON 美化排序。" : "";
      const sourceNote = state.cipherMode === "GCM"
        ? `GCM Key 來源：${state.lastGcmSources.key}，IV 來源：${state.lastGcmSources.iv}。`
        : `Key 來源：${pair.key.source}，IV 來源：${pair.iv.source}。`;
      log(`完成。${sourceNote}輸出約 ${formatBytes(outputBytes)}。${jsonNote}`);
    } catch (error) {
      log(error.message || String(error), true);
    } finally {
      els.runBtn.disabled = false;
      els.runBtn.textContent = state.mode === "E" ? "執行加密" : "執行解密";
    }
  }

  function bindEvents() {
    els.profileSelect.addEventListener("change", loadSelectedProfile);
    els.newProfileBtn.addEventListener("click", () => {
      els.profileSelect.value = "";
      els.profileName.value = "";
      els.keyInput.value = "";
      els.ivInput.value = "";
      log("已切換到建立新設定。填入名稱、Key、IV 後按「保存此設定到本機」。");
    });
    els.saveProfileBtn.addEventListener("click", () => {
      try { saveCurrentProfile(); } catch (error) { log(error.message, true); }
    });
    els.deleteProfileBtn.addEventListener("click", () => {
      const selectedValue = els.profileSelect.value;
      const selected = Number(selectedValue);
      if (selectedValue === "" || !Number.isInteger(selected) || selected < 0 || selected >= state.profiles.length) return;
      const removed = state.profiles.splice(selected, 1)[0];
      saveProfiles();
      renderProfiles(Math.max(0, selected - 1));
      log(`已刪除「${removed.name}」。`);
    });
    els.clearAllBtn.addEventListener("click", () => {
      if (!confirm("確定要清除這個瀏覽器保存的所有 Key/IV profiles？")) return;
      state.profiles = [];
      saveProfiles();
      renderProfiles();
      log("已清除本機瀏覽器保存的所有 profiles。");
    });
    els.showSecrets.addEventListener("change", () => {
      const type = els.showSecrets.checked ? "text" : "password";
      els.keyInput.type = type;
      els.ivInput.type = type;
    });
    els.importProfilesBtn.addEventListener("click", () => els.profilesFile.click());
    els.profilesFile.addEventListener("change", async () => {
      const file = els.profilesFile.files[0];
      if (!file) return;
      try {
        const imported = extractProfiles(await file.text());
        state.profiles = imported;
        saveProfiles();
        renderProfiles(0);
        log(`已匯入 ${imported.length} 組 profiles，並保存到本機瀏覽器。`);
      } catch (error) {
        log(error.message, true);
      } finally {
        els.profilesFile.value = "";
      }
    });
    els.exportProfilesBtn.addEventListener("click", () => {
      const payload = JSON.stringify({ version: `aes_256_web ${APP_VERSION}`, profiles: state.profiles }, null, 2);
      downloadText("aes_profiles.json", payload, false);
      log("已匯出 profiles JSON。請妥善保管，裡面包含 Key/IV。");
    });

    els.cbcMode.addEventListener("click", () => setCipherMode("CBC"));
    els.gcmMode.addEventListener("click", () => setCipherMode("GCM"));
    els.encryptMode.addEventListener("click", () => setMode("E"));
    els.decryptMode.addEventListener("click", () => setMode("D"));
    els.textFile.addEventListener("change", async () => {
      await loadTextFile(els.textFile.files[0]);
    });
    els.dropzone.addEventListener("dragover", (event) => {
      event.preventDefault();
      els.dropzone.classList.add("drag-over");
    });
    els.dropzone.addEventListener("dragleave", () => {
      els.dropzone.classList.remove("drag-over");
    });
    els.dropzone.addEventListener("drop", async (event) => {
      event.preventDefault();
      els.dropzone.classList.remove("drag-over");
      const file = event.dataTransfer.files[0];
      if (!file) return;
      await loadTextFile(file);
    });
    els.inputText.addEventListener("input", updateInputStats);
    els.formatJsonOutput.addEventListener("change", refreshJsonOutputFromRaw);
    els.runBtn.addEventListener("click", runCrypto);
    els.clearInputBtn.addEventListener("click", () => {
      els.inputText.value = "";
      els.textFile.value = "";
      els.fileName.textContent = "或把 TXT 拖曳到這裡";
      updateInputStats();
    });
    els.clearOutputBtn.addEventListener("click", () => {
      els.outputText.value = "";
      state.lastOutputText = "";
      state.lastRawDecryptedText = "";
      els.downloadBtn.disabled = true;
    });
    els.copyBtn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(state.lastOutputText || els.outputText.value);
        log("已複製結果到剪貼簿。");
      } catch (_) {
        if (state.lastOutputText && state.lastOutputText !== els.outputText.value) {
          els.outputText.value = state.lastOutputText;
        }
        els.outputText.select();
        document.execCommand("copy");
        log("已複製結果到剪貼簿。");
      }
    });
    els.downloadBtn.addEventListener("click", () => {
      downloadText(state.lastOutputName, state.lastOutputText || els.outputText.value, state.mode === "D");
      log(`已下載 ${state.lastOutputName}。`);
    });
  }

  function init() {
    els.appVersion.textContent = `Version ${APP_VERSION}`;
    if (!window.crypto || !crypto.subtle) {
      els.cryptoNotice.hidden = false;
      log("Web Crypto API 不可用，無法執行加解密。", true);
    }
    bindEvents();
    loadProfiles();
    renderProfiles();
    setMode("E");
    setCipherMode("CBC");
    updateInputStats();
  }

  init();
})();





