(function () {
  "use strict";

  const utf8Text = document.getElementById("utf8Text");
  const base64Text = document.getElementById("base64Text");
  const hexText = document.getElementById("hexText");
  const utf8Stats = document.getElementById("utf8Stats");
  const base64Stats = document.getElementById("base64Stats");
  const hexStats = document.getElementById("hexStats");
  const clearConverterBtn = document.getElementById("clearConverterBtn");
  const messageLog = document.getElementById("messageLog");
  const utils = window.SharedUtils;

  if (!utf8Text || !base64Text || !hexText || !utf8Stats || !base64Stats || !hexStats || !utils) return;

  const encoder = new TextEncoder();
  const fatalUtf8Decoder = new TextDecoder("utf-8", { fatal: true });
  const DEFAULT_UTF8_PLACEHOLDER = "輸入一般文字";
  const INVALID_UTF8_PLACEHOLDER = "此內容不是有效的 UTF-8，無法顯示明碼";

  function setLog(message, isError) {
    if (!messageLog) return;
    messageLog.textContent = message;
    messageLog.style.color = isError ? "#a83028" : "#69746e";
  }

  function base64ToBytes(value) {
    let normalized = utils.normalizeBase64(value).replace(/-/g, "+").replace(/_/g, "/");
    if (!normalized) return new Uint8Array();
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) {
      throw new Error("Base64 格式錯誤：只能包含 A-Z、a-z、0-9、+、/ 與結尾的 =。");
    }
    const remainder = normalized.length % 4;
    if (remainder === 1) throw new Error("Base64 長度錯誤：請確認是否少貼了字元。");
    if (remainder) normalized += "=".repeat(4 - remainder);
    const binary = atob(normalized);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  function hexToBytes(value) {
    const normalized = String(value || "").replace(/\s+/g, "");
    if (!normalized) return new Uint8Array();
    if (!/^[0-9a-fA-F]+$/.test(normalized)) {
      throw new Error("Hex 格式錯誤：只能包含 0-9、a-f、A-F。");
    }
    if (normalized.length % 2 !== 0) {
      throw new Error("Hex 長度必須是偶數，每 2 個 hex 字元代表 1 byte。");
    }
    const bytes = new Uint8Array(normalized.length / 2);
    for (let i = 0; i < bytes.length; i += 1) {
      bytes[i] = parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  function resetUtf8Marker() {
    utf8Text.placeholder = DEFAULT_UTF8_PLACEHOLDER;
    utf8Stats.classList.remove("warn");
  }

  function renderUtf8(bytes) {
    try {
      const text = bytes.length ? fatalUtf8Decoder.decode(bytes) : "";
      utf8Text.value = text;
      resetUtf8Marker();
      const byteLength = encoder.encode(text).length;
      utf8Stats.textContent = `${text.length.toLocaleString()} 字元 / 約 ${utils.formatBytes(byteLength)}`;
      return true;
    } catch (_) {
      utf8Text.value = "";
      utf8Text.placeholder = INVALID_UTF8_PLACEHOLDER;
      utf8Stats.textContent = `無法轉換為 UTF-8 明碼 / ${utils.formatBytes(bytes.length)}`;
      utf8Stats.classList.add("warn");
      return false;
    }
  }

  function updateEncodedStats() {
    base64Stats.textContent = `${(base64Text.value || "").length.toLocaleString()} 字元`;
    hexStats.textContent = `${(hexText.value || "").replace(/\s+/g, "").length.toLocaleString()} hex 字元`;
  }

  function syncFrom(source) {
    try {
      if (source === "utf8") {
        const text = utf8Text.value || "";
        const bytes = encoder.encode(text);
        resetUtf8Marker();
        utf8Stats.textContent = `${text.length.toLocaleString()} 字元 / 約 ${utils.formatBytes(bytes.length)}`;
        base64Text.value = utils.bytesToBase64(bytes);
        hexText.value = utils.bytesToHex(bytes);
        updateEncodedStats();
        setLog("已從 UTF-8 更新其他格式。", false);
        return;
      }

      const bytes = source === "base64" ? base64ToBytes(base64Text.value) : hexToBytes(hexText.value);
      if (source === "base64") {
        hexText.value = utils.bytesToHex(bytes);
      } else {
        base64Text.value = utils.bytesToBase64(bytes);
      }
      updateEncodedStats();

      const utf8Valid = renderUtf8(bytes);
      const label = source === "base64" ? "Base64" : "Hex";
      const targetLabel = source === "base64" ? "Hex" : "Base64";
      setLog(
        utf8Valid
          ? `已從 ${label} 更新其他格式。`
          : `已從 ${label} 更新 ${targetLabel}；內容不是有效的 UTF-8，明碼欄位已標示。`,
        false
      );
    } catch (error) {
      updateEncodedStats();
      setLog(error.message || String(error), true);
    }
  }

  function bindOverride(element, source) {
    element.addEventListener("input", (event) => {
      event.stopImmediatePropagation();
      syncFrom(source);
    }, true);
  }

  bindOverride(utf8Text, "utf8");
  bindOverride(base64Text, "base64");
  bindOverride(hexText, "hex");

  clearConverterBtn?.addEventListener("click", () => {
    resetUtf8Marker();
    utf8Stats.textContent = "0 字元 / 約 0 B";
  });
})();
