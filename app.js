(function () {
  "use strict";

  const STORAGE_KEY = "aes_cbc_web_profiles_v1";
  const APP_VERSION = document.querySelector('meta[name="app-version"]')?.content || "V1.7.0";
  const VISIT_COUNTER_ENDPOINT = "https://hitscounter.dev/api/hit?output=json&url=https%3A%2F%2Fyiminghu0125-svg.github.io%2Faes_cbc_web%2F&tz=Asia%2FTaipei";
  const encoder = new TextEncoder();
  const decoder = new TextDecoder("utf-8", { fatal: false });
  const fatalUtf8Decoder = new TextDecoder("utf-8", { fatal: true });
  const {
    LARGE_TEXT_BYTES,
    formatBytes,
    getTextByteLength,
    confirmLargeText,
    normalizeBase64,
    bytesToBase64,
    base64ToBytes,
    bytesToHex,
    normalizeJsonValue,
    parseJsonInput,
    prettyPrintJson,
    parseJsonSafely,
    tryUnescapeJson,
    expandNestedJson,
    parseQueryString,
    parseKeyValueText,
    parseHeaderBlock,
    detectStructuredFormat,
    copyTextToClipboard
  } = window.SharedUtils;

  const state = {
    mode: "E",
    cipherMode: "CBC",
    profiles: [],
    lastOutputName: ".enc.txt",
    lastOutputText: "",
    lastRawDecryptedText: "",
    lastGcmSources: null,
    converterSyncing: false,
    converterLastSource: "utf8",
    lastJsonDiffText: "",
    fullJsonDiffResults: [],
    selectedJsonDiffFilter: "all",
    jsonDiffHasCompared: false,
    lastLogRestoreText: "",
    lastHashText: "",
    hashLastOutput: "hex",
    hashInputFile: null
  };

  const $ = (id) => document.getElementById(id);
  const els = {
    appVersion: $("appVersion"),
    featureMenu: $("featureMenu"),
    visitCounter: $("visitCounter"),
    siteVisitCount: $("siteVisitCount"),
    aesFeatureBtn: $("aesFeatureBtn"),
    converterFeatureBtn: $("converterFeatureBtn"),
    jsonDiffFeatureBtn: $("jsonDiffFeatureBtn"),
    hashFeatureBtn: $("hashFeatureBtn"),
    aesView: $("aesView"),
    converterView: $("converterView"),
    jsonDiffView: $("jsonDiffView"),
    hashView: $("hashView"),
    cryptoNotice: $("cryptoNotice"),
    profileSelect: $("profileSelect"),
    profileName: $("profileName"),
    profileDetails: $("profileDetails"),
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
    dropzone: $("dropzone"),
    textFile: $("textFile"),
    fileName: $("fileName"),
    inputLabel: $("inputLabel"),
    inputText: $("inputText"),
    inputStats: $("inputStats"),
    encryptBtn: $("encryptBtn"),
    decryptBtn: $("decryptBtn"),
    clearInputBtn: $("clearInputBtn"),
    outputLabel: $("outputLabel"),
    outputText: $("outputText"),
    formatJsonOutput: $("formatJsonOutput"),
    copyBtn: $("copyBtn"),
    downloadBtn: $("downloadBtn"),
    clearOutputBtn: $("clearOutputBtn"),
    utf8Text: $("utf8Text"),
    base64Text: $("base64Text"),
    hexText: $("hexText"),
    utf8Stats: $("utf8Stats"),
    base64Stats: $("base64Stats"),
    hexStats: $("hexStats"),
    jsonDiffFormat: $("jsonDiffFormat"),
    runJsonDiffBtn: $("runJsonDiffBtn"),
    copyJsonDiffBtn: $("copyJsonDiffBtn"),
    clearJsonDiffBtn: $("clearJsonDiffBtn"),
    jsonDiffLeftInput: $("jsonDiffLeftInput"),
    jsonDiffRightInput: $("jsonDiffRightInput"),
    jsonDiffLeftStats: $("jsonDiffLeftStats"),
    jsonDiffRightStats: $("jsonDiffRightStats"),
    jsonDiffLeftOutput: $("jsonDiffLeftOutput"),
    jsonDiffRightOutput: $("jsonDiffRightOutput"),
    jsonDiffSummary: $("jsonDiffSummary"),
    jsonDiffFilter: $("jsonDiffFilter"),
    jsonDiffList: $("jsonDiffList"),
    logRestoreFeatureBtn: $("logRestoreFeatureBtn"),
    logRestoreView: $("logRestoreView"),
    logRestoreSortKeys: $("logRestoreSortKeys"),
    runLogRestoreBtn: $("runLogRestoreBtn"),
    copyLogRestoreBtn: $("copyLogRestoreBtn"),
    clearLogRestoreBtn: $("clearLogRestoreBtn"),
    logRestoreInput: $("logRestoreInput"),
    logRestoreInputStats: $("logRestoreInputStats"),
    logRestoreStatus: $("logRestoreStatus"),
    logRestoreOutput: $("logRestoreOutput"),
    logRestoreOriginal: $("logRestoreOriginal"),
    logRestoreDetailsBlock: $("logRestoreDetailsBlock"),
    logRestoreDetails: $("logRestoreDetails"),
    hashAlgorithm: $("hashAlgorithm"),
    hmacKeyField: $("hmacKeyField"),
    hmacKeyInput: $("hmacKeyInput"),
    hashDropzone: $("hashDropzone"),
    hashFile: $("hashFile"),
    hashFileName: $("hashFileName"),
    hashInputText: $("hashInputText"),
    hashInputStats: $("hashInputStats"),
    hashHexOutput: $("hashHexOutput"),
    hashBase64Output: $("hashBase64Output"),
    hashExpectedInput: $("hashExpectedInput"),
    hashVerifyFormat: $("hashVerifyFormat"),
    hashVerifyResult: $("hashVerifyResult"),
    runHashBtn: $("runHashBtn"),
    verifyHashBtn: $("verifyHashBtn"),
    copyHashBtn: $("copyHashBtn"),
    clearHashBtn: $("clearHashBtn"),
    copyConverterBtn: $("copyConverterBtn"),
    clearConverterBtn: $("clearConverterBtn"),
    messageLog: $("messageLog")
  };

  const MD5_SHIFT_AMOUNTS = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
  ];
  const MD5_CONSTANTS = Array.from(
    { length: 64 },
    (_, index) => Math.floor(Math.abs(Math.sin(index + 1)) * 0x100000000) >>> 0
  );

  function log(message, isError) {
    els.messageLog.textContent = message;
    els.messageLog.style.color = isError ? "#a83028" : "#69746e";
  }

  function setVisitCounterText(text) {
    if (!els.siteVisitCount) return;
    els.siteVisitCount.textContent = text;
  }

  function syncVisitCounterAnchor() {
    if (!els.visitCounter) return;
    const fallbackLeft = 12;
    if (!els.featureMenu) {
      els.visitCounter.style.setProperty("--visit-counter-left", `${fallbackLeft}px`);
      return;
    }

    const rect = els.featureMenu.getBoundingClientRect();
    const left = Math.max(fallbackLeft, Math.round(rect.left));
    els.visitCounter.style.setProperty("--visit-counter-left", `${left}px`);
  }

  function readFirstNumber(...values) {
    for (const value of values) {
      if (typeof value === "number" && Number.isFinite(value)) return value;
      if (typeof value === "string" && value.trim() !== "" && !Number.isNaN(Number(value))) {
        return Number(value);
      }
    }
    return null;
  }

  async function loadSiteVisitCount() {
    if (!els.visitCounter || !els.siteVisitCount) return;
    setVisitCounterText("讀取中");

    try {
      const response = await fetch(VISIT_COUNTER_ENDPOINT, {
        method: "GET",
        cache: "no-store"
      });
      if (!response.ok) {
        throw new Error(`Hits Counter HTTP ${response.status}`);
      }

      const data = await response.json();
      const total = readFirstNumber(
        data.total,
        data.total_hits,
        data.totalHits,
        data.value,
        data.count,
        data.hits
      );

      if (total === null) {
        throw new Error("Hits Counter JSON does not contain a total count.");
      }

      setVisitCounterText(`${total.toLocaleString()} 次`);
    } catch (error) {
      console.warn("Unable to load site visit count.", error);
      els.visitCounter.classList.add("is-error");
    }
  }

  function setActiveFeature(feature, silent) {
    const labels = {
      aes: "AES 加解密工具",
      converter: "文字編碼轉換工具",
      jsonDiff: "JSON Diff 比對工具",
      logRestore: "Log 整理 / 還原工具",
      hash: "Hash / HMAC 計算工具"
    };
    const views = {
      aes: els.aesView,
      converter: els.converterView,
      jsonDiff: els.jsonDiffView,
      logRestore: els.logRestoreView,
      hash: els.hashView
    };
    const buttons = {
      aes: els.aesFeatureBtn,
      converter: els.converterFeatureBtn,
      jsonDiff: els.jsonDiffFeatureBtn,
      logRestore: els.logRestoreFeatureBtn,
      hash: els.hashFeatureBtn
    };
    Object.keys(views).forEach((name) => {
      const active = name === feature;
      views[name].hidden = !active;
      views[name].classList.toggle("active", active);
      buttons[name].classList.toggle("active", active);
      buttons[name].toggleAttribute("aria-current", active);
    });
    if (!silent) {
      log(`已切換到${labels[feature] || labels.aes}。`);
    }
  }

  function updateInputStats() {
    const text = els.inputText.value || "";
    const bytes = getTextByteLength(text);
    els.inputStats.textContent = `${text.length.toLocaleString()} 字元 / 約 ${formatBytes(bytes)}`;
    els.inputStats.classList.toggle("warn", bytes >= LARGE_TEXT_BYTES);
  }

  function updateConverterStats() {
    const utf8 = els.utf8Text.value || "";
    const utf8Bytes = getTextByteLength(utf8);
    els.utf8Stats.textContent = `${utf8.length.toLocaleString()} 字元 / 約 ${formatBytes(utf8Bytes)}`;
    els.utf8Stats.classList.toggle("warn", utf8Bytes >= LARGE_TEXT_BYTES);
    els.base64Stats.textContent = `${(els.base64Text.value || "").length.toLocaleString()} 字元`;
    els.hexStats.textContent = `${(els.hexText.value || "").replace(/\s+/g, "").length.toLocaleString()} hex 字元`;
  }

  function updateJsonDiffStats() {
    const left = els.jsonDiffLeftInput.value || "";
    const right = els.jsonDiffRightInput.value || "";
    const leftBytes = getTextByteLength(left);
    const rightBytes = getTextByteLength(right);
    els.jsonDiffLeftStats.textContent = `${left.length.toLocaleString()} 字元 / 約 ${formatBytes(leftBytes)}`;
    els.jsonDiffRightStats.textContent = `${right.length.toLocaleString()} 字元 / 約 ${formatBytes(rightBytes)}`;
    els.jsonDiffLeftStats.classList.toggle("warn", leftBytes >= LARGE_TEXT_BYTES);
    els.jsonDiffRightStats.classList.toggle("warn", rightBytes >= LARGE_TEXT_BYTES);
  }

  function updateHashStats() {
    if (state.hashInputFile) {
      const bytes = state.hashInputFile.size;
      els.hashInputStats.textContent = `已選擇檔案：${state.hashInputFile.name} / ${formatBytes(bytes)}，計算時會優先使用檔案`;
      els.hashInputStats.classList.toggle("warn", bytes >= LARGE_TEXT_BYTES);
      return;
    }
    const text = els.hashInputText.value || "";
    const bytes = getTextByteLength(text);
    els.hashInputStats.textContent = `${text.length.toLocaleString()} 字元 / 約 ${formatBytes(bytes)}`;
    els.hashInputStats.classList.toggle("warn", bytes >= LARGE_TEXT_BYTES);
  }

  function clearHashInputFile() {
    state.hashInputFile = null;
    els.hashFile.value = "";
    els.hashFileName.textContent = "或把檔案拖曳到這裡";
    updateHashStats();
  }

  async function loadHashFile(file) {
    if (!file) return;
    state.hashInputFile = file;
    els.hashFileName.textContent = `${file.name} (${formatBytes(file.size)})`;
    updateHashStats();
    log(`已選擇 Hash 檔案：${file.name}，大小 ${formatBytes(file.size)}。`);
  }

  async function loadTextFile(file) {
    if (!file) return;
    if (!confirmLargeText(file.size, "讀取的檔案")) return;
    els.inputText.value = await file.text();
    els.fileName.textContent = `${file.name} (${formatBytes(file.size)})`;
    updateInputStats();
    log(`已讀取檔案：${file.name}，大小 ${formatBytes(file.size)}。`);
  }

  function converterBase64ToBytes(value) {
    let normalized = normalizeBase64(value).replace(/-/g, "+").replace(/_/g, "/");
    if (!normalized) return new Uint8Array();
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) {
      throw new Error("Base64 格式錯誤：只能包含 A-Z、a-z、0-9、+、/ 與結尾的 =。");
    }
    const remainder = normalized.length % 4;
    if (remainder === 1) throw new Error("Base64 長度錯誤：請確認是否少貼了字元。");
    if (remainder) normalized += "=".repeat(4 - remainder);
    const binary = atob(normalized);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  function converterHexToBytes(value) {
    const normalized = String(value || "").replace(/\s+/g, "");
    if (!normalized) return new Uint8Array();
    if (!/^[0-9a-fA-F]+$/.test(normalized)) {
      throw new Error("Hex 格式錯誤：只能包含 0-9、a-f、A-F。");
    }
    if (normalized.length % 2 !== 0) {
      throw new Error("Hex 長度必須是偶數，每 2 個 hex 字元代表 1 byte。");
    }
    const bytes = new Uint8Array(normalized.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  function bytesToUtf8(bytes) {
    if (!bytes.length) return "";
    try {
      return fatalUtf8Decoder.decode(bytes);
    } catch (_) {
      throw new Error("這組 bytes 不是有效的 UTF-8 文字，無法轉回 UTF-8 欄位。");
    }
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

  function getJsonType(value) {
    if (value === null) return "null";
    if (Array.isArray(value)) return "array";
    return typeof value;
  }

  function formatJsonPath(path) {
    if (!path.length) return "data";
    return path.reduce((output, segment) => {
      if (typeof segment === "number") return `${output}[${segment}]`;
      return `${output}.${segment}`;
    }, "data");
  }

  function stringifyDiffValue(value) {
    if (value === undefined) return "(不存在)";
    if (typeof value === "string") return JSON.stringify(value);
    return JSON.stringify(value, null, 2);
  }

  const DIFF_CATEGORY_LABELS = {
    field: "欄位差異",
    value: "欄位值差異",
    type: "型別差異"
  };

  const DIFF_TYPE_LABELS = {
    field_missing: "缺少欄位",
    field_extra: "新增欄位",
    value_changed: "值不同",
    type_changed: "型別不同"
  };

  function createDiffItem(type, path, leftValue, rightValue, leftType, rightType) {
    const category = type === "type_changed" ? "type" : type === "value_changed" ? "value" : "field";
    return {
      type,
      category,
      categoryLabel: DIFF_CATEGORY_LABELS[category],
      label: DIFF_TYPE_LABELS[type],
      path: formatJsonPath(path),
      leftValue,
      rightValue,
      leftType,
      rightType
    };
  }

  function isSamePrimitive(left, right) {
    return Object.is(left, right);
  }

  function deepDiffJson(left, right, path) {
    const diffs = [];
    const currentPath = path || [];
    const leftType = getJsonType(left);
    const rightType = getJsonType(right);

    if (leftType !== rightType) {
      diffs.push(createDiffItem("type_changed", currentPath, left, right, leftType, rightType));
      return diffs;
    }

    if (leftType === "object") {
      const leftKeys = Object.keys(left).sort((a, b) => a.localeCompare(b, "zh-Hant"));
      const rightKeys = Object.keys(right).sort((a, b) => a.localeCompare(b, "zh-Hant"));
      const rightKeySet = new Set(rightKeys);
      const leftKeySet = new Set(leftKeys);

      leftKeys.forEach((key) => {
        if (!rightKeySet.has(key)) {
          diffs.push(createDiffItem("field_missing", currentPath.concat(key), left[key], undefined, getJsonType(left[key]), "missing"));
        } else {
          diffs.push(...deepDiffJson(left[key], right[key], currentPath.concat(key)));
        }
      });

      rightKeys.forEach((key) => {
        if (!leftKeySet.has(key)) {
          diffs.push(createDiffItem("field_extra", currentPath.concat(key), undefined, right[key], "missing", getJsonType(right[key])));
        }
      });
      return diffs;
    }

    if (leftType === "array") {
      const maxLength = Math.max(left.length, right.length);
      for (let index = 0; index < maxLength; index++) {
        const existsLeft = index < left.length;
        const existsRight = index < right.length;
        if (!existsRight) {
          diffs.push(createDiffItem("field_missing", currentPath.concat(index), left[index], undefined, getJsonType(left[index]), "missing"));
        } else if (!existsLeft) {
          diffs.push(createDiffItem("field_extra", currentPath.concat(index), undefined, right[index], "missing", getJsonType(right[index])));
        } else {
          diffs.push(...deepDiffJson(left[index], right[index], currentPath.concat(index)));
        }
      }
      return diffs;
    }

    if (!isSamePrimitive(left, right)) {
      diffs.push(createDiffItem("value_changed", currentPath, left, right, leftType, rightType));
    }
    return diffs;
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
      return { text: JSON.stringify(parsed, null, 2), formatted: true };
    } catch (_) {
      return { text, formatted: false };
    }
  }

  function stringifyBody(value) {
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
      const bodyPlain = typeof parsed.Body === "string" ? parsed.Body : stringifyBody(parsed.Body);
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

  async function encryptCbcContent(content, pair) {
    const parsed = tryParseJsonObject(content);
    if (parsed && Object.prototype.hasOwnProperty.call(parsed, "Body")) {
      const bodyPlain = typeof parsed.Body === "string" ? parsed.Body : stringifyBody(parsed.Body);
      parsed.Body = await encryptText(bodyPlain, pair.key.bytes, pair.iv.bytes);
      return JSON.stringify(parsed, null, 2);
    }
    return encryptText(content, pair.key.bytes, pair.iv.bytes);
  }

  async function decryptCbcContent(content, pair) {
    const parsed = tryParseJsonObject(content);
    if (parsed && typeof parsed.Body === "string") {
      const bodyPlain = await decryptText(parsed.Body, pair.key.bytes, pair.iv.bytes);
      const bodyJson = tryParseJsonObject(bodyPlain);
      parsed.Body = bodyJson || bodyPlain;
      return JSON.stringify(parsed, null, 2);
    }
    return pair.plain;
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
    const jsonNote = jsonResult.formatted ? "已套用 JSON 美化。" : "已顯示原始解密結果。";
    log(`${jsonNote}輸出約 ${formatBytes(outputBytes)}。`);
  }

  function getConverterBytes(source) {
    if (source === "utf8") return encoder.encode(els.utf8Text.value || "");
    if (source === "base64") return converterBase64ToBytes(els.base64Text.value);
    return converterHexToBytes(els.hexText.value);
  }

  function syncConverterFrom(source) {
    if (state.converterSyncing) return;
    state.converterSyncing = true;
    state.converterLastSource = source;
    try {
      const bytes = getConverterBytes(source);
      if (source !== "utf8") els.utf8Text.value = bytesToUtf8(bytes);
      if (source !== "base64") els.base64Text.value = bytesToBase64(bytes);
      if (source !== "hex") els.hexText.value = bytesToHex(bytes);
      updateConverterStats();
      const label = source === "utf8" ? "UTF-8" : source === "base64" ? "Base64" : "Hex";
      log(`已從 ${label} 更新其他格式。`);
    } catch (error) {
      updateConverterStats();
      log(error.message || String(error), true);
    } finally {
      state.converterSyncing = false;
    }
  }

  function clearConverter() {
    els.utf8Text.value = "";
    els.base64Text.value = "";
    els.hexText.value = "";
    updateConverterStats();
    log("已清空文字編碼轉換工具。");
  }

  async function copyActiveConverterValue() {
    const sourceMap = {
      utf8: els.utf8Text,
      base64: els.base64Text,
      hex: els.hexText
    };
    const target = sourceMap[state.converterLastSource] || els.utf8Text;
    try {
      await navigator.clipboard.writeText(target.value);
    } catch (_) {
      target.focus();
      target.select();
      document.execCommand("copy");
    }
    log("已複製目前轉換欄位到剪貼簿。");
  }

  const LOG_FORMAT_LABELS = {
    json: "JSON",
    escaped_json: "Escaped JSON",
    nested_json_string: "Nested JSON string",
    log_embedded_json: "Log 內嵌 JSON",
    java_log: "Java / Spring Log",
    query_string: "Query String",
    key_value: "key=value 類型",
    headers: "HTTP Header block",
    plain_text: "原始文字"
  };

  function entriesToObject(entries) {
    return entries.reduce((output, entry) => {
      if (Object.prototype.hasOwnProperty.call(output, entry.key)) {
        output[entry.key] = Array.isArray(output[entry.key]) ? output[entry.key].concat(entry.value) : [output[entry.key], entry.value];
      } else {
        output[entry.key] = entry.value;
      }
      return output;
    }, {});
  }

  function formatKeyValueList(entries) {
    return entries.map((entry) => `${entry.key}: ${entry.value}`).join("\n");
  }

  function formatPlainText(input) {
    return String(input || "").replace(/\r\n/g, "\n").trim();
  }

  function parseJavaLogLines(input) {
    const rawLines = String(input || "").replace(/\r\n/g, "\n").split("\n").map((line) => line.trim()).filter(Boolean);
    if (!rawLines.length) return null;
    const entryStartPattern = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}\s+[A-Z]+\s+\[/;
    const lines = [];
    for (const line of rawLines) {
      if (entryStartPattern.test(line)) {
        lines.push(line);
      } else if (lines.length) {
        lines[lines.length - 1] = `${lines[lines.length - 1]} ${line}`;
      } else {
        return null;
      }
    }

    const pattern = /^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})\s+([A-Z]+)\s+\[([^\]]+)\]\s+(.+?)\s+\(([^)]+)\)\s+-\s*(.*)$/;
    const entries = [];
    for (const line of lines) {
      const match = line.match(pattern);
      if (!match) return null;
      entries.push({
        time: match[1],
        level: match[2],
        thread: match[3],
        logger: match[4],
        source: match[5],
        message: match[6]
      });
    }
    return entries;
  }

  function formatJavaLogEntries(entries) {
    return entries.map((entry, index) => [
      `Entry ${index + 1}`,
      `Time: ${entry.time}`,
      `Level: ${entry.level}`,
      `Thread: ${entry.thread}`,
      `Logger: ${entry.logger}`,
      `Source: ${entry.source}`,
      `Message: ${entry.message || "(空訊息)"}`
    ].join("\n")).join("\n\n");
  }

  function findEmbeddedJsonPayload(input) {
    const text = String(input || "");
    for (let start = 0; start < text.length; start++) {
      const opener = text[start];
      if (opener !== "{" && opener !== "[") continue;

      const closer = opener === "{" ? "}" : "]";
      const stack = [closer];
      let inString = false;
      let escaped = false;

      for (let index = start + 1; index < text.length; index++) {
        const char = text[index];
        if (inString) {
          if (escaped) {
            escaped = false;
          } else if (char === "\\") {
            escaped = true;
          } else if (char === "\"") {
            inString = false;
          }
          continue;
        }

        if (char === "\"") {
          inString = true;
          continue;
        }
        if (char === "{" || char === "[") {
          stack.push(char === "{" ? "}" : "]");
          continue;
        }
        if (char === "}" || char === "]") {
          if (char !== stack[stack.length - 1]) break;
          stack.pop();
          if (!stack.length) {
            const jsonText = text.slice(start, index + 1);
            const parsed = parseJsonSafely(jsonText);
            if (parsed.ok && parsed.value && typeof parsed.value === "object") {
              return {
                prefix: text.slice(0, start).trim(),
                jsonText,
                value: parsed.value,
                suffix: text.slice(index + 1).trim()
              };
            }
            break;
          }
        }
      }
    }
    return null;
  }

  function formatStructuredOutput(result, sortKeys) {
    if (["json", "escaped_json", "nested_json_string"].includes(result.format)) {
      return prettyPrintJson(result.value, sortKeys);
    }
    if (result.format === "log_embedded_json") {
      const lines = [];
      if (result.prefix) lines.push(`Log text\n${formatPlainText(result.prefix)}`);
      lines.push(`JSON payload\n${prettyPrintJson(result.value, sortKeys)}`);
      if (result.suffix) lines.push(`Trailing text\n${formatPlainText(result.suffix)}`);
      return lines.join("\n\n");
    }
    if (result.format === "java_log") {
      return formatJavaLogEntries(result.entries);
    }
    if (["query_string", "key_value", "headers"].includes(result.format)) {
      const objectView = entriesToObject(result.entries);
      const listView = formatKeyValueList(result.entries);
      const jsonView = JSON.stringify(sortKeys ? normalizeJsonValue(objectView) : objectView, null, 2);
      return `List view\n${listView}\n\nJSON view\n${jsonView}`;
    }
    return formatPlainText(result.original);
  }

  function restoreLogInput(input, sortKeys) {
    const original = String(input || "");
    const trimmed = original.trim();
    if (!trimmed) {
      return {
        ok: false,
        format: "plain_text",
        status: "請先貼上要整理的 log / body / 字串。",
        original,
        output: "",
        details: []
      };
    }

    const format = detectStructuredFormat(trimmed);
    const details = [];
    const result = { ok: true, format, original, details };

    if (format === "json" || format === "nested_json_string") {
      const parsed = parseJsonSafely(trimmed);
      result.value = expandNestedJson(parsed.value, 0, 3, "data", details);
      result.format = details.some((detail) => detail.status === "expanded") ? "nested_json_string" : "json";
      result.status = result.format === "nested_json_string" ? "已辨識為 Nested JSON string，並展開可解析的 JSON 字串欄位。" : "已辨識為 JSON。";
    } else if (format === "escaped_json") {
      const unescaped = tryUnescapeJson(trimmed);
      result.value = expandNestedJson(unescaped.value, 0, 3, "data", details);
      result.status = "已辨識為 Escaped JSON，已還原並格式化。";
      if (details.some((detail) => detail.status === "expanded")) result.status += " 內嵌 JSON 字串也已展開。";
    } else if (format === "query_string") {
      result.entries = parseQueryString(trimmed);
      result.status = "已辨識為 Query String，已 URL decode 並拆成 key-value。";
    } else if (format === "key_value") {
      result.entries = parseKeyValueText(trimmed);
      result.status = "已辨識為 key=value 類型，已拆成結構化列表。";
    } else if (format === "headers") {
      result.entries = parseHeaderBlock(trimmed);
      result.status = "已辨識為 Header block，已拆成結構化列表。";
    } else {
      const embedded = findEmbeddedJsonPayload(trimmed);
      if (embedded) {
        result.format = "log_embedded_json";
        result.prefix = embedded.prefix;
        result.suffix = embedded.suffix;
        result.value = expandNestedJson(embedded.value, 0, 3, "payload", details);
        result.status = "已辨識為 Log 內嵌 JSON，已保留 log 文字並格式化 JSON payload。";
        if (details.some((detail) => detail.status === "expanded")) result.status += " 內嵌 JSON 字串也已展開。";
      } else {
        const javaLogEntries = parseJavaLogLines(trimmed);
        if (javaLogEntries) {
          result.format = "java_log";
          result.entries = javaLogEntries;
          result.status = `已辨識為 Java / Spring Log，已整理 ${javaLogEntries.length} 筆 log entries。`;
        } else {
          result.status = "未辨識為可結構化格式，以下為原始內容。";
        }
      }
    }

    result.output = formatStructuredOutput(result, sortKeys);
    return result;
  }

  function updateLogRestoreStats() {
    const text = els.logRestoreInput.value || "";
    const bytes = getTextByteLength(text);
    els.logRestoreInputStats.textContent = `${text.length.toLocaleString()} 字元 / 約 ${formatBytes(bytes)}`;
    els.logRestoreInputStats.classList.toggle("warn", bytes >= LARGE_TEXT_BYTES);
  }

  function renderLogRestoreDetails(details) {
    els.logRestoreDetails.innerHTML = "";
    if (!details.length) {
      const item = document.createElement("div");
      item.className = "log-detail-item muted";
      item.textContent = "沒有偵測到內嵌 JSON 字串，資料沒有可展開的分層。";
      els.logRestoreDetails.appendChild(item);
      return;
    }
    details.forEach((detail) => {
      const item = document.createElement("div");
      item.className = "log-detail-item";
      const path = document.createElement("code");
      path.textContent = detail.path;
      const status = document.createElement("span");
      status.textContent = detail.status === "expanded"
        ? `第 ${detail.depth} 層：已展開 JSON`
        : `第 ${detail.depth} 層：展開失敗，保留原始字串`;
      item.appendChild(path);
      item.appendChild(status);
      els.logRestoreDetails.appendChild(item);
    });
  }

  function runLogRestore() {
    const input = els.logRestoreInput.value || "";
    const bytes = getTextByteLength(input);
    if (!confirmLargeText(bytes, "即將整理的")) return;

    const result = restoreLogInput(input, els.logRestoreSortKeys.checked);
    els.logRestoreStatus.classList.remove("match", "mismatch");
    els.logRestoreStatus.classList.add(result.ok ? "match" : "mismatch");
    els.logRestoreStatus.textContent = result.status;
    els.logRestoreOutput.value = result.output || "尚無結果。";
    els.logRestoreOriginal.value = result.original || "尚無原始內容。";
    renderLogRestoreDetails(result.details || []);
    state.lastLogRestoreText = result.output || "";
    log(result.ok ? `${result.status} 偵測類型：${LOG_FORMAT_LABELS[result.format]}。` : result.status, !result.ok);
  }

  function clearLogRestore() {
    els.logRestoreInput.value = "";
    els.logRestoreStatus.classList.remove("match", "mismatch");
    els.logRestoreStatus.textContent = "尚未整理。";
    els.logRestoreOutput.value = "尚無結果。";
    els.logRestoreOriginal.value = "尚無原始內容。";
    renderLogRestoreDetails([]);
    state.lastLogRestoreText = "";
    updateLogRestoreStats();
    log("已清空 Log 整理 / 還原工具。");
  }

  function summarizeDiffs(diffs) {
    return diffs.reduce((summary, diff) => {
      summary.total += 1;
      summary[diff.category] += 1;
      return summary;
    }, { total: 0, field: 0, value: 0, type: 0 });
  }

  function filterDiffs(diffs, selectedFilter) {
    if (selectedFilter === "all") return diffs;
    return diffs.filter((diff) => diff.category === selectedFilter);
  }

  function updateJsonDiffFilterButtons() {
    els.jsonDiffFilter.querySelectorAll("[data-diff-filter]").forEach((button) => {
      button.classList.toggle("active", button.dataset.diffFilter === state.selectedJsonDiffFilter);
    });
  }

  function renderJsonDiffSummary(diffs) {
    const summary = summarizeDiffs(diffs);
    els.jsonDiffSummary.classList.remove("match", "mismatch");
    if (!summary.total) {
      els.jsonDiffSummary.classList.add("match");
      els.jsonDiffSummary.textContent = "兩份 JSON 在排序正規化後內容一致";
      return;
    }

    els.jsonDiffSummary.classList.add("mismatch");
    els.jsonDiffSummary.innerHTML = "";
    [
      ["全部差異", summary.total],
      ["欄位差異", summary.field],
      ["欄位值差異", summary.value],
      ["型別差異", summary.type]
    ].forEach(([label, count]) => {
      const item = document.createElement("span");
      item.textContent = `${label}：共 ${count} 筆`;
      els.jsonDiffSummary.appendChild(item);
    });
  }

  function diffToPlainText(diffs) {
    const summary = summarizeDiffs(diffs);
    if (!diffs.length) return "兩份 JSON 在排序正規化後內容一致";
    return [
      `全部差異：共 ${summary.total} 筆`,
      `欄位差異：共 ${summary.field} 筆`,
      `欄位值差異：共 ${summary.value} 筆`,
      `型別差異：共 ${summary.type} 筆`,
      "",
      ...diffs.map((diff, index) => [
        `#${index + 1} ${diff.categoryLabel} / ${diff.label}`,
        `JSON Path: ${diff.path}`,
        `左側值: ${stringifyDiffValue(diff.leftValue)}`,
        `右側值: ${stringifyDiffValue(diff.rightValue)}`,
        `型別: ${diff.leftType} vs ${diff.rightType}`
      ].join("\n"))
    ].join("\n\n");
  }

  function renderJsonDiffList(diffs, fullDiffs) {
    els.jsonDiffList.innerHTML = "";
    if (!fullDiffs.length) return;
    if (!diffs.length) {
      const empty = document.createElement("p");
      empty.className = "diff-empty";
      empty.textContent = "目前篩選條件下沒有差異";
      els.jsonDiffList.appendChild(empty);
      return;
    }
    diffs.forEach((diff) => {
      const item = document.createElement("article");
      item.className = "diff-item";

      const meta = document.createElement("div");
      meta.className = "diff-item-meta";

      const badge = document.createElement("strong");
      badge.textContent = `${diff.categoryLabel} / ${diff.label}`;
      meta.appendChild(badge);

      const path = document.createElement("code");
      path.textContent = diff.path;
      meta.appendChild(path);

      const values = document.createElement("div");
      values.className = "diff-values";

      const left = document.createElement("pre");
      left.textContent = `左側值\n${stringifyDiffValue(diff.leftValue)}`;
      values.appendChild(left);

      const right = document.createElement("pre");
      right.textContent = `右側值\n${stringifyDiffValue(diff.rightValue)}`;
      values.appendChild(right);

      const types = document.createElement("small");
      types.className = "text-stats";
      types.textContent = `型別：${diff.leftType} vs ${diff.rightType}`;

      item.appendChild(meta);
      item.appendChild(values);
      item.appendChild(types);
      els.jsonDiffList.appendChild(item);
    });
  }

  function renderJsonDiffResults() {
    if (!state.jsonDiffHasCompared) {
      updateJsonDiffFilterButtons();
      return;
    }
    const visibleDiffs = filterDiffs(state.fullJsonDiffResults, state.selectedJsonDiffFilter);
    updateJsonDiffFilterButtons();
    renderJsonDiffSummary(state.fullJsonDiffResults);
    renderJsonDiffList(visibleDiffs, state.fullJsonDiffResults);
    state.lastJsonDiffText = diffToPlainText(state.fullJsonDiffResults);
  }

  function runJsonDiff() {
    const leftBytes = getTextByteLength(els.jsonDiffLeftInput.value);
    const rightBytes = getTextByteLength(els.jsonDiffRightInput.value);
    if (!confirmLargeText(leftBytes + rightBytes, "即將比對的")) return;

    els.jsonDiffLeftOutput.value = "";
    els.jsonDiffRightOutput.value = "";
    state.fullJsonDiffResults = [];
    state.selectedJsonDiffFilter = "all";
    state.jsonDiffHasCompared = false;
    els.jsonDiffSummary.textContent = "尚未比對。";
    els.jsonDiffSummary.classList.remove("match", "mismatch");
    els.jsonDiffList.innerHTML = "";
    state.lastJsonDiffText = "";
    updateJsonDiffFilterButtons();

    const errors = [];
    let leftParsed;
    let rightParsed;
    try {
      leftParsed = parseJsonInput(els.jsonDiffLeftInput.value, "左側");
    } catch (error) {
      errors.push(error.message);
    }
    try {
      rightParsed = parseJsonInput(els.jsonDiffRightInput.value, "右側");
    } catch (error) {
      errors.push(error.message);
    }
    if (errors.length) {
      state.fullJsonDiffResults = [];
      state.selectedJsonDiffFilter = "all";
      state.jsonDiffHasCompared = false;
      state.lastJsonDiffText = "";
      els.jsonDiffList.innerHTML = "";
      els.jsonDiffSummary.classList.remove("match", "mismatch");
      els.jsonDiffSummary.textContent = errors.join("\n");
      updateJsonDiffFilterButtons();
      log(errors.join("；"), true);
      return;
    }

    const sortKeys = els.jsonDiffFormat.checked;
    els.jsonDiffLeftOutput.value = prettyPrintJson(leftParsed, sortKeys);
    els.jsonDiffRightOutput.value = prettyPrintJson(rightParsed, sortKeys);
    const diffs = deepDiffJson(normalizeJsonValue(leftParsed), normalizeJsonValue(rightParsed));
    const summary = summarizeDiffs(diffs);

    state.fullJsonDiffResults = diffs;
    state.selectedJsonDiffFilter = "all";
    state.jsonDiffHasCompared = true;
    renderJsonDiffResults();
    if (!summary.total) {
      log("JSON Diff 完成：兩份 JSON 在排序正規化後內容一致。");
    } else {
      log(`JSON Diff 完成：全部差異 ${summary.total} 筆，欄位差異 ${summary.field} 筆，欄位值差異 ${summary.value} 筆，型別差異 ${summary.type} 筆。`);
    }
  }

  function clearJsonDiff() {
    els.jsonDiffLeftInput.value = "";
    els.jsonDiffRightInput.value = "";
    els.jsonDiffLeftOutput.value = "";
    els.jsonDiffRightOutput.value = "";
    state.fullJsonDiffResults = [];
    state.selectedJsonDiffFilter = "all";
    state.jsonDiffHasCompared = false;
    els.jsonDiffSummary.textContent = "尚未比對。";
    els.jsonDiffSummary.classList.remove("match", "mismatch");
    els.jsonDiffList.innerHTML = "";
    state.lastJsonDiffText = "";
    updateJsonDiffFilterButtons();
    updateJsonDiffStats();
    log("已清空 JSON Diff。");
  }

  function isHmacAlgorithm(algorithm) {
    return algorithm.startsWith("HMAC-");
  }

  function getHashName(algorithm) {
    if (algorithm === "HMAC-SHA256") return "SHA-256";
    if (algorithm === "HMAC-SHA512") return "SHA-512";
    return algorithm;
  }

  function leftRotate32(value, bits) {
    return ((value << bits) | (value >>> (32 - bits))) >>> 0;
  }

  function computeMd5(inputBytes) {
    const originalLength = inputBytes.length;
    const paddedLength = (((originalLength + 9) + 63) >> 6) << 6;
    const padded = new Uint8Array(paddedLength);
    padded.set(inputBytes);
    padded[originalLength] = 0x80;

    const bitLength = originalLength * 8;
    const view = new DataView(padded.buffer);
    view.setUint32(paddedLength - 8, bitLength >>> 0, true);
    view.setUint32(paddedLength - 4, Math.floor(bitLength / 0x100000000) >>> 0, true);

    let a0 = 0x67452301;
    let b0 = 0xefcdab89;
    let c0 = 0x98badcfe;
    let d0 = 0x10325476;

    for (let offset = 0; offset < paddedLength; offset += 64) {
      const words = new Uint32Array(16);
      for (let index = 0; index < 16; index++) {
        words[index] = view.getUint32(offset + index * 4, true);
      }

      let a = a0;
      let b = b0;
      let c = c0;
      let d = d0;

      for (let index = 0; index < 64; index++) {
        let f;
        let g;

        if (index < 16) {
          f = (b & c) | (~b & d);
          g = index;
        } else if (index < 32) {
          f = (d & b) | (~d & c);
          g = (5 * index + 1) % 16;
        } else if (index < 48) {
          f = b ^ c ^ d;
          g = (3 * index + 5) % 16;
        } else {
          f = c ^ (b | ~d);
          g = (7 * index) % 16;
        }

        const nextD = d;
        d = c;
        c = b;
        const sum = (a + f + MD5_CONSTANTS[index] + words[g]) >>> 0;
        b = (b + leftRotate32(sum, MD5_SHIFT_AMOUNTS[index])) >>> 0;
        a = nextD;
      }

      a0 = (a0 + a) >>> 0;
      b0 = (b0 + b) >>> 0;
      c0 = (c0 + c) >>> 0;
      d0 = (d0 + d) >>> 0;
    }

    const digest = new Uint8Array(16);
    const digestView = new DataView(digest.buffer);
    digestView.setUint32(0, a0, true);
    digestView.setUint32(4, b0, true);
    digestView.setUint32(8, c0, true);
    digestView.setUint32(12, d0, true);
    return digest;
  }

  async function getHashInputPayload() {
    if (state.hashInputFile) {
      if (!confirmLargeText(state.hashInputFile.size, "即將計算的檔案")) return null;
      const bytes = new Uint8Array(await state.hashInputFile.arrayBuffer());
      return {
        bytes,
        sourceLabel: `檔案：${state.hashInputFile.name}`
      };
    }

    const input = els.hashInputText.value;
    const inputBytes = getTextByteLength(input);
    if (!input) throw new Error("原文為空：沒有可計算的資料。");
    if (!confirmLargeText(inputBytes, "即將計算的")) return null;
    return {
      bytes: encoder.encode(input),
      sourceLabel: "文字"
    };
  }

  async function computeHashDigest(algorithm, inputBytes) {
    if (algorithm === "MD5") return computeMd5(inputBytes);

    if (isHmacAlgorithm(algorithm)) {
      const keyText = els.hmacKeyInput.value;
      if (!keyText) throw new Error("HMAC Key 為空：請輸入 Key 後再計算。");
      const key = await crypto.subtle.importKey(
        "raw",
        encoder.encode(keyText),
        { name: "HMAC", hash: getHashName(algorithm) },
        false,
        ["sign"]
      );
      return new Uint8Array(await crypto.subtle.sign("HMAC", key, inputBytes));
    }

    return new Uint8Array(await crypto.subtle.digest(algorithm, inputBytes));
  }

  async function computeHashResult() {
    const algorithm = els.hashAlgorithm.value;
    const payload = await getHashInputPayload();
    if (!payload) return null;
    const bytes = await computeHashDigest(algorithm, payload.bytes);
    return {
      algorithm,
      sourceLabel: payload.sourceLabel,
      hex: bytesToHex(bytes),
      base64: bytesToBase64(bytes)
    };
  }

  async function runHash() {
    try {
      const result = await computeHashResult();
      if (!result) return;
      els.hashHexOutput.value = result.hex;
      els.hashBase64Output.value = result.base64;
      state.lastHashText = `來源：${result.sourceLabel}\n演算法：${result.algorithm}\nHex：${result.hex}\nBase64：${result.base64}`;
      els.hashVerifyResult.textContent = "尚未驗證。";
      log(`${result.algorithm} 計算完成（${result.sourceLabel}）。`);
    } catch (error) {
      log(error.message || String(error), true);
    }
  }

  async function verifyHash() {
    try {
      if (!els.hashHexOutput.value || !els.hashBase64Output.value) {
        const result = await computeHashResult();
        if (!result) return;
        els.hashHexOutput.value = result.hex;
        els.hashBase64Output.value = result.base64;
        state.lastHashText = `來源：${result.sourceLabel}\n演算法：${result.algorithm}\nHex：${result.hex}\nBase64：${result.base64}`;
      }
      const format = els.hashVerifyFormat.value;
      const expected = String(els.hashExpectedInput.value || "").trim();
      if (!expected) throw new Error("預期簽章為空：請貼上要比對的 Hex 或 Base64。");
      const actual = format === "hex" ? els.hashHexOutput.value.trim().toLowerCase() : els.hashBase64Output.value.trim();
      const normalizedExpected = format === "hex" ? expected.replace(/\s+/g, "").toLowerCase() : normalizeBase64(expected);
      const matched = actual === normalizedExpected;
      els.hashVerifyResult.textContent = `${format === "hex" ? "用 Hex 驗證" : "用 Base64 驗證"}：${matched ? "一致" : "不一致"}`;
      els.hashVerifyResult.classList.toggle("match", matched);
      els.hashVerifyResult.classList.toggle("mismatch", !matched);
      log(`驗證結果：${matched ? "一致" : "不一致"}。`);
    } catch (error) {
      log(error.message || String(error), true);
    }
  }

  function updateHashMode() {
    const needsKey = isHmacAlgorithm(els.hashAlgorithm.value);
    els.hmacKeyField.hidden = !needsKey;
    els.hmacKeyField.style.display = needsKey ? "" : "none";
    els.hmacKeyField.setAttribute("aria-hidden", needsKey ? "false" : "true");
    els.hmacKeyInput.disabled = !needsKey;
    if (!needsKey) els.hmacKeyInput.value = "";
    els.hashVerifyResult.textContent = "尚未驗證。";
    els.hashVerifyResult.classList.remove("match", "mismatch");
  }

  function clearHash() {
    clearHashInputFile();
    els.hashInputText.value = "";
    els.hmacKeyInput.value = "";
    els.hashHexOutput.value = "";
    els.hashBase64Output.value = "";
    els.hashExpectedInput.value = "";
    els.hashVerifyResult.textContent = "尚未驗證。";
    els.hashVerifyResult.classList.remove("match", "mismatch");
    state.lastHashText = "";
    updateHashStats();
    log("已清空 Hash / HMAC。");
  }

  async function resolveKeyIvForMode(mode, content) {
    const keyCandidates = getKeyCandidates(els.keyInput.value);
    const ivCandidates = getIvCandidates(els.ivInput.value);
    if (!keyCandidates.length) throw new Error("Key 格式錯誤：AES-256 Key 需為 UTF-8 32 bytes，或 Base64 解碼後為 32 bytes。");
    if (!ivCandidates.length) throw new Error("IV 格式錯誤：需為 UTF-8 16 bytes，或 Base64 解碼後為 16 bytes。");
    const parsedContent = mode === "D" ? tryParseJsonObject(content) : null;
    const cipherContent = parsedContent && typeof parsedContent.Body === "string" ? parsedContent.Body : content;

    let best = null;
    for (const key of keyCandidates) {
      for (const iv of ivCandidates) {
        const pair = { key, iv, score: key.score + iv.score, plain: null };
        if (mode === "D") {
          try {
            const plain = await decryptText(cipherContent, key.bytes, iv.bytes);
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
      : "已切換到 CBC：若輸入完整 JSON，會加解密 Body 欄位。");
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

  async function runCrypto(mode) {
    try {
      state.mode = mode;
      const content = els.inputText.value;
      const inputBytes = getTextByteLength(content);
      if (!confirmLargeText(inputBytes, "即將處理的")) return;
      const activeButton = mode === "E" ? els.encryptBtn : els.decryptBtn;
      els.encryptBtn.disabled = true;
      els.decryptBtn.disabled = true;
      activeButton.textContent = mode === "E" ? "加密中..." : "解密中...";
      const pair = state.cipherMode === "CBC" ? await resolveKeyIvForMode(mode, content) : null;
      let output;
      if (state.cipherMode === "GCM") {
        if (mode === "E") {
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
      } else if (mode === "E") {
        state.lastRawDecryptedText = "";
        output = await encryptCbcContent(content, pair);
        state.lastOutputName = ".enc.txt";
      } else {
        output = await decryptCbcContent(content, pair);
        state.lastRawDecryptedText = output;
        const jsonResult = formatJsonIfEnabled(output);
        output = jsonResult.text;
        state.lastOutputName = jsonResult.formatted ? ".dec.pretty.json.txt" : ".dec.txt";
      }
      const outputBytes = showOutput(output);
      const jsonNote = state.lastOutputName.includes("pretty.json") ? "已套用 JSON 美化。" : "";
      const sourceNote = state.cipherMode === "GCM"
        ? `GCM Key 來源：${state.lastGcmSources.key}，IV 來源：${state.lastGcmSources.iv}。`
        : `Key 來源：${pair.key.source}，IV 來源：${pair.iv.source}。`;
      log(`完成。${sourceNote}輸出約 ${formatBytes(outputBytes)}。${jsonNote}`);
    } catch (error) {
      log(error.message || String(error), true);
    } finally {
      els.encryptBtn.disabled = false;
      els.decryptBtn.disabled = false;
      els.encryptBtn.textContent = "執行加密";
      els.decryptBtn.textContent = "執行解密";
    }
  }

  function bindEvents() {
    els.aesFeatureBtn.addEventListener("click", () => setActiveFeature("aes"));
    els.converterFeatureBtn.addEventListener("click", () => setActiveFeature("converter"));
    els.jsonDiffFeatureBtn.addEventListener("click", () => setActiveFeature("jsonDiff"));
    els.logRestoreFeatureBtn.addEventListener("click", () => setActiveFeature("logRestore"));
    els.hashFeatureBtn.addEventListener("click", () => setActiveFeature("hash"));
    els.profileSelect.addEventListener("change", loadSelectedProfile);
    els.newProfileBtn.addEventListener("click", () => {
      els.profileDetails.open = true;
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
      const current = state.profiles[selected];
      if (!confirm(`確定要刪除目前設定「${current.name}」？\n\n此操作會從本機瀏覽器移除這組 Key/IV。`)) return;
      const removed = state.profiles.splice(selected, 1)[0];
      saveProfiles();
      renderProfiles(Math.max(0, selected - 1));
      log(`已刪除「${removed.name}」。`);
    });
    els.clearAllBtn.addEventListener("click", () => {
      if (!confirm("確定要清除這個瀏覽器保存的所有 Key/IV profiles？\n\n此操作會移除全部本機設定。")) return;
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
    els.encryptBtn.addEventListener("click", () => runCrypto("E"));
    els.decryptBtn.addEventListener("click", () => runCrypto("D"));
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

    els.utf8Text.addEventListener("input", () => syncConverterFrom("utf8"));
    els.utf8Text.addEventListener("focus", () => { state.converterLastSource = "utf8"; });
    els.base64Text.addEventListener("input", () => syncConverterFrom("base64"));
    els.base64Text.addEventListener("focus", () => { state.converterLastSource = "base64"; });
    els.hexText.addEventListener("input", () => syncConverterFrom("hex"));
    els.hexText.addEventListener("focus", () => { state.converterLastSource = "hex"; });
    els.copyConverterBtn.addEventListener("click", copyActiveConverterValue);
    els.clearConverterBtn.addEventListener("click", clearConverter);

    els.jsonDiffLeftInput.addEventListener("input", updateJsonDiffStats);
    els.jsonDiffRightInput.addEventListener("input", updateJsonDiffStats);
    els.runJsonDiffBtn.addEventListener("click", runJsonDiff);
    els.clearJsonDiffBtn.addEventListener("click", clearJsonDiff);
    els.jsonDiffFilter.addEventListener("click", (event) => {
      const button = event.target.closest("[data-diff-filter]");
      if (!button) return;
      state.selectedJsonDiffFilter = button.dataset.diffFilter;
      renderJsonDiffResults();
    });
    els.copyJsonDiffBtn.addEventListener("click", async () => {
      if (!state.lastJsonDiffText) {
        log("尚無差異結果可複製。", true);
        return;
      }
      await copyTextToClipboard(state.lastJsonDiffText, els.jsonDiffLeftOutput);
      log("已複製完整差異結果到剪貼簿。");
    });

    els.logRestoreInput.addEventListener("input", updateLogRestoreStats);
    els.runLogRestoreBtn.addEventListener("click", runLogRestore);
    els.clearLogRestoreBtn.addEventListener("click", clearLogRestore);
    els.copyLogRestoreBtn.addEventListener("click", async () => {
      if (!state.lastLogRestoreText) {
        log("尚無 Log 整理結果可複製。", true);
        return;
      }
      await copyTextToClipboard(state.lastLogRestoreText, els.logRestoreOutput);
      log("已複製 Log 整理結果到剪貼簿。");
    });

    els.hashAlgorithm.addEventListener("change", updateHashMode);
    els.hashFile.addEventListener("change", async () => {
      await loadHashFile(els.hashFile.files[0]);
    });
    els.hashDropzone.addEventListener("dragover", (event) => {
      event.preventDefault();
      els.hashDropzone.classList.add("drag-over");
    });
    els.hashDropzone.addEventListener("dragleave", () => {
      els.hashDropzone.classList.remove("drag-over");
    });
    els.hashDropzone.addEventListener("drop", async (event) => {
      event.preventDefault();
      els.hashDropzone.classList.remove("drag-over");
      const file = event.dataTransfer.files[0];
      if (!file) return;
      await loadHashFile(file);
    });
    els.hashInputText.addEventListener("input", () => {
      if (state.hashInputFile && els.hashInputText.value) clearHashInputFile();
      updateHashStats();
    });
    els.runHashBtn.addEventListener("click", runHash);
    els.verifyHashBtn.addEventListener("click", verifyHash);
    els.clearHashBtn.addEventListener("click", clearHash);
    els.hashHexOutput.addEventListener("focus", () => { state.hashLastOutput = "hex"; });
    els.hashBase64Output.addEventListener("focus", () => { state.hashLastOutput = "base64"; });
    els.copyHashBtn.addEventListener("click", async () => {
      const target = state.hashLastOutput === "base64" ? els.hashBase64Output : els.hashHexOutput;
      if (!target.value) {
        log("尚無 Hash / HMAC 結果可複製。", true);
        return;
      }
      await copyTextToClipboard(target.value, target);
      log(`已複製 ${state.hashLastOutput === "base64" ? "Base64" : "Hex"} 結果到剪貼簿。`);
    });
  }

  function init() {
    document.querySelectorAll(".version-badge").forEach((badge) => {
      badge.textContent = `Version ${APP_VERSION}`;
    });
    if (!window.crypto || !crypto.subtle) {
      els.cryptoNotice.hidden = false;
      log("Web Crypto API 不可用，無法執行加解密。", true);
    }
    bindEvents();
    loadProfiles();
    renderProfiles();
    setCipherMode("CBC");
    setActiveFeature("aes", true);
    updateInputStats();
    updateConverterStats();
    updateJsonDiffStats();
    updateLogRestoreStats();
    updateHashStats();
    updateHashMode();
    syncVisitCounterAnchor();
    loadSiteVisitCount();
    window.addEventListener("resize", syncVisitCounterAnchor);
  }

  init();
})();
