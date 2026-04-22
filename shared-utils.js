(function () {
  "use strict";

  const textEncoder = new TextEncoder();
  const LARGE_TEXT_BYTES = 2 * 1024 * 1024;
  const VERY_LARGE_TEXT_BYTES = 10 * 1024 * 1024;

  function formatBytes(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
  }

  function getTextByteLength(text) {
    return textEncoder.encode(text || "").length;
  }

  function confirmLargeText(bytes, action) {
    if (bytes >= VERY_LARGE_TEXT_BYTES) {
      return confirm(`${action}\u5167\u5bb9\u7d04 ${formatBytes(bytes)}\uff0c\u700f\u89bd\u5668\u53ef\u80fd\u660e\u986f\u8b8a\u6162\u751a\u81f3\u66ab\u6642\u7121\u56de\u61c9\u3002\u78ba\u5b9a\u8981\u7e7c\u7e8c\uff1f`);
    }
    if (bytes >= LARGE_TEXT_BYTES) {
      return confirm(`${action}\u5167\u5bb9\u7d04 ${formatBytes(bytes)}\uff0c\u8655\u7406\u8207\u986f\u793a\u53ef\u80fd\u9700\u8981\u4e00\u4e9b\u6642\u9593\u3002\u8981\u7e7c\u7e8c\u55ce\uff1f`);
    }
    return true;
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
      throw new Error("\u4e0d\u662f\u6709\u6548\u7684 Base64 \u683c\u5f0f\u3002");
    }
    const binary = atob(normalized);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  function bytesToHex(bytes) {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  }

  function normalizeJsonValue(value) {
    if (Array.isArray(value)) return value.map(normalizeJsonValue);
    if (value && typeof value === "object") {
      return Object.keys(value).sort((a, b) => a.localeCompare(b, "zh-Hant")).reduce((sorted, key) => {
        sorted[key] = normalizeJsonValue(value[key]);
        return sorted;
      }, {});
    }
    return value;
  }

  function sortJsonValue(value) {
    return normalizeJsonValue(value);
  }

  function parseJsonInput(text, label) {
    const raw = String(text || "");
    if (!raw.trim()) throw new Error(`${label} JSON \u683c\u5f0f\u932f\u8aa4\uff1a\u5167\u5bb9\u70ba\u7a7a\u3002`);
    try {
      return JSON.parse(raw);
    } catch (error) {
      throw new Error(`${label} JSON \u683c\u5f0f\u932f\u8aa4\uff1a${error.message || String(error)}`);
    }
  }

  function prettyPrintJson(value, sortKeys) {
    return JSON.stringify(sortKeys ? normalizeJsonValue(value) : value, null, 2);
  }

  function parseJsonSafely(input) {
    try {
      return { ok: true, value: JSON.parse(input) };
    } catch (error) {
      return { ok: false, error };
    }
  }

  function looksLikeJsonText(text) {
    const trimmed = String(text || "").trim();
    return (trimmed.startsWith("{") && trimmed.endsWith("}")) || (trimmed.startsWith("[") && trimmed.endsWith("]"));
  }

  function looksLikeEscapedJsonText(text) {
    const trimmed = String(text || "").trim();
    return (trimmed.startsWith("{\\\"") && trimmed.endsWith("\\\"}")) || (trimmed.startsWith("[") && trimmed.endsWith("]"));
  }

  function tryUnescapeJson(input) {
    const trimmed = String(input || "").trim();
    const direct = parseJsonSafely(trimmed);
    if (direct.ok && typeof direct.value === "string" && looksLikeJsonText(direct.value)) {
      const nested = parseJsonSafely(direct.value);
      if (nested.ok) return { ok: true, text: direct.value, value: nested.value, source: "json_string_literal" };
    }

    const candidates = [
      trimmed.replace(/\\"/g, "\"").replace(/\\\\/g, "\\"),
      trimmed.replace(/\\n/g, "\n").replace(/\\r/g, "\r").replace(/\\t/g, "\t").replace(/\\"/g, "\"").replace(/\\\\/g, "\\")
    ];
    for (const candidate of candidates) {
      if (!looksLikeJsonText(candidate)) continue;
      const parsed = parseJsonSafely(candidate);
      if (parsed.ok) return { ok: true, text: candidate, value: parsed.value, source: "escaped_text" };
    }
    return { ok: false };
  }

  function expandNestedJson(value, depth, maxDepth, path, details) {
    const currentPath = path || "data";
    if (depth >= maxDepth) return value;

    if (typeof value === "string") {
      const trimmed = value.trim();
      if (!looksLikeJsonText(trimmed) && !looksLikeEscapedJsonText(trimmed)) return value;
      const parsed = parseJsonSafely(trimmed);
      const unescaped = parsed.ok ? null : tryUnescapeJson(trimmed);
      if (!parsed.ok && !unescaped.ok) {
        details.push({ path: currentPath, depth: depth + 1, status: "failed" });
        return value;
      }
      details.push({ path: currentPath, depth: depth + 1, status: "expanded" });
      return expandNestedJson(parsed.ok ? parsed.value : unescaped.value, depth + 1, maxDepth, currentPath, details);
    }

    if (Array.isArray(value)) {
      return value.map((item, index) => expandNestedJson(item, depth, maxDepth, `${currentPath}[${index}]`, details));
    }

    if (value && typeof value === "object") {
      return Object.keys(value).sort((a, b) => a.localeCompare(b, "zh-Hant")).reduce((output, key) => {
        output[key] = expandNestedJson(value[key], depth, maxDepth, `${currentPath}.${key}`, details);
        return output;
      }, {});
    }

    return value;
  }

  function parseQueryString(input) {
    const trimmed = String(input || "").trim().replace(/^\?/, "");
    if (!trimmed || !trimmed.includes("=") || !trimmed.includes("&") || /[\r\n]/.test(trimmed)) return null;
    const parts = trimmed.split("&");
    if (parts.some((part) => !part || !part.includes("="))) return null;
    const entries = [];
    try {
      const params = new URLSearchParams(trimmed);
      params.forEach((value, key) => entries.push({ key, value }));
    } catch (_) {
      return null;
    }
    return entries.length ? entries : null;
  }

  function parseKeyValueText(input) {
    const trimmed = String(input || "").trim();
    if (!trimmed || trimmed.includes("&")) return null;
    const segments = trimmed.split(/[,;\n]+/).map((part) => part.trim()).filter(Boolean);
    if (segments.length < 2) return null;
    const entries = [];
    for (const segment of segments) {
      const eqIndex = segment.indexOf("=");
      if (eqIndex <= 0 || eqIndex === segment.length - 1) return null;
      const key = segment.slice(0, eqIndex).trim();
      const value = segment.slice(eqIndex + 1).trim();
      if (!/^[A-Za-z0-9_.-]+$/.test(key)) return null;
      entries.push({ key, value });
    }
    return entries;
  }

  function parseHeaderBlock(input) {
    const lines = String(input || "").trim().split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    if (lines.length < 2) return null;
    const entries = [];
    for (const line of lines) {
      const colonIndex = line.indexOf(":");
      if (colonIndex <= 0 || colonIndex === line.length - 1) return null;
      const key = line.slice(0, colonIndex).trim();
      const value = line.slice(colonIndex + 1).trim();
      if (!/^[A-Za-z0-9-]+$/.test(key)) return null;
      entries.push({ key, value });
    }
    return entries;
  }

  function hasNestedJsonString(value) {
    if (typeof value === "string") {
      const trimmed = value.trim();
      return (looksLikeJsonText(trimmed) && parseJsonSafely(trimmed).ok) || (looksLikeEscapedJsonText(trimmed) && tryUnescapeJson(trimmed).ok);
    }
    if (Array.isArray(value)) return value.some(hasNestedJsonString);
    if (value && typeof value === "object") return Object.values(value).some(hasNestedJsonString);
    return false;
  }

  function detectStructuredFormat(input) {
    const trimmed = String(input || "").trim();
    if (!trimmed) return "plain_text";

    const json = parseJsonSafely(trimmed);
    if (json.ok && (Array.isArray(json.value) || (json.value && typeof json.value === "object"))) {
      return hasNestedJsonString(json.value) ? "nested_json_string" : "json";
    }

    const escaped = tryUnescapeJson(trimmed);
    if (escaped.ok) return "escaped_json";
    if (parseQueryString(trimmed)) return "query_string";
    if (parseKeyValueText(trimmed)) return "key_value";
    if (parseHeaderBlock(trimmed)) return "headers";
    return "plain_text";
  }

  async function copyTextToClipboard(text, fallbackElement) {
    try {
      await navigator.clipboard.writeText(text);
    } catch (_) {
      if (fallbackElement && typeof fallbackElement.select === "function") {
        fallbackElement.focus();
        fallbackElement.select();
      } else {
        const temp = document.createElement("textarea");
        temp.value = text;
        temp.setAttribute("readonly", "");
        temp.style.position = "fixed";
        temp.style.opacity = "0";
        document.body.appendChild(temp);
        temp.select();
        document.execCommand("copy");
        temp.remove();
        return;
      }
      document.execCommand("copy");
    }
  }

  window.SharedUtils = {
    LARGE_TEXT_BYTES,
    VERY_LARGE_TEXT_BYTES,
    formatBytes,
    getTextByteLength,
    confirmLargeText,
    normalizeBase64,
    bytesToBase64,
    base64ToBytes,
    bytesToHex,
    normalizeJsonValue,
    sortJsonValue,
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
  };
})();
