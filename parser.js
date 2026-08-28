/*
 * Loon resource parser.
 * Fetch the provider's Clash/URI representation directly, decode Base64 when
 * needed, convert only anytls:// entries, and leave every other line untouched
 * for Loon's normal parser.
 */

const SOURCE_SUFFIX = "?t=clash";

function sourceUrlFromResource(resource) {
  const link = resource && resource.link ? String(resource.link) : "";
  if (!link) return "";
  return link.replace(/[?#].*$/, "") + SOURCE_SUFFIX;
}

function safeDecodeURIComponent(value) {
  try { return decodeURIComponent(value); } catch (_) { return value; }
}

function decodeBase64Utf8(value) {
  const normalized = value.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized) || normalized.length % 4 === 1) return null;
  try {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let binary = "";
    let buffer = 0;
    let bits = 0;
    for (let i = 0; i < normalized.length; i += 1) {
      const char = normalized.charAt(i);
      if (char === "=") break;
      const value6 = alphabet.indexOf(char);
      if (value6 < 0) return null;
      buffer = (buffer << 6) | value6;
      bits += 6;
      if (bits >= 8) {
        bits -= 8;
        binary += String.fromCharCode((buffer >> bits) & 255);
      }
    }
    let escaped = "";
    for (let i = 0; i < binary.length; i += 1) {
      const hex = binary.charCodeAt(i).toString(16);
      escaped += `%${hex.length === 1 ? "0" : ""}${hex}`;
    }
    try { return decodeURIComponent(escaped); }
    catch (_) { return binary; }
  } catch (_) { return null; }
}

function looksLikeBase64(value) {
  const compact = value.replace(/\s+/g, "");
  if (!compact || compact.length < 16 || compact.length % 4 === 1) return false;
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(compact)) return false;
  const decoded = decodeBase64Utf8(compact);
  return Boolean(decoded && /(anytls|ss|ssr|vmess|vless|trojan|hysteria|tuic):\/\//i.test(decoded));
}

function maybeDecodeSubscription(content) {
  const raw = String(content || "");
  const trimmed = raw.trim();
  if (!looksLikeBase64(trimmed)) return raw;
  return decodeBase64Utf8(trimmed) || raw;
}

function escapeQuoted(value) {
  return String(value).replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

function parseQuery(query) {
  const result = {};
  query.split("&").forEach(pair => {
    if (!pair) return;
    const separator = pair.indexOf("=");
    const key = separator < 0 ? pair : pair.slice(0, separator);
    const value = separator < 0 ? "" : pair.slice(separator + 1);
    result[safeDecodeURIComponent(key.replace(/\+/g, " "))] = safeDecodeURIComponent(value.replace(/\+/g, " "));
  });
  return result;
}

function parseAnyTLS(uri) {
  const withoutScheme = uri.replace(/^anytls:\/\//i, "");
  const hashIndex = withoutScheme.indexOf("#");
  const name = hashIndex >= 0 ? safeDecodeURIComponent(withoutScheme.slice(hashIndex + 1)) || "AnyTLS" : "AnyTLS";
  const beforeHash = hashIndex >= 0 ? withoutScheme.slice(0, hashIndex) : withoutScheme;
  const queryIndex = beforeHash.indexOf("?");
  const authority = queryIndex >= 0 ? beforeHash.slice(0, queryIndex) : beforeHash;
  const query = queryIndex >= 0 ? parseQuery(beforeHash.slice(queryIndex + 1)) : {};
  const atIndex = authority.lastIndexOf("@");
  const credentials = atIndex >= 0 ? authority.slice(0, atIndex) : "";
  const hostPort = atIndex >= 0 ? authority.slice(atIndex + 1) : authority;
  const password = safeDecodeURIComponent(credentials);
  let server = hostPort;
  let port = "443";
  if (hostPort.charAt(0) === "[") {
    const closingBracket = hostPort.indexOf("]");
    if (closingBracket >= 0) {
      server = hostPort.slice(1, closingBracket);
      if (hostPort.charAt(closingBracket + 1) === ":") port = hostPort.slice(closingBracket + 2) || port;
    }
  } else {
    const colonIndex = hostPort.lastIndexOf(":");
    if (colonIndex > 0 && /^[0-9]+$/.test(hostPort.slice(colonIndex + 1))) {
      server = hostPort.slice(0, colonIndex);
      port = hostPort.slice(colonIndex + 1);
    }
  }
  const sni = query.sni || query.peer || "";
  const insecure = query.insecure === "1" || query.allowInsecure === "1";
  const udp = query.udp === undefined ? null : query.udp;
  if (!password || !server) throw new Error("missing AnyTLS password or server");

  let result = `${name.replace(/[\r\n]/g, " ")} = AnyTLS,${server},${port},"${escapeQuoted(password)}"`;
  if (sni) result += `,sni=${safeDecodeURIComponent(sni)}`;
  if (insecure) result += ",skip-cert-verify=true";
  if (udp !== null) result += `,udp=${udp !== "0" && udp !== "false" ? "true" : "false"}`;
  return result;
}

function transformLine(line) {
  const candidate = line.trim();
  if (!/^anytls:\/\//i.test(candidate)) return line;
  try { return parseAnyTLS(candidate); }
  catch (_) { return line; }
}

function transformSubscription(content) {
  return maybeDecodeSubscription(content).split(/\r?\n/).map(transformLine).join("\n");
}

if (typeof module !== "undefined") {
  module.exports = { SOURCE_SUFFIX, sourceUrlFromResource, decodeBase64Utf8, maybeDecodeSubscription, parseAnyTLS, transformSubscription };
}

if (typeof $done === "function" && typeof $httpClient !== "undefined") {
  const sourceUrl = sourceUrlFromResource(typeof $resource !== "undefined" ? $resource : null);
  if (!sourceUrl) {
    console.log("AnyTLS parser request skipped: Loon did not provide a resource URL");
    $done("");
  } else {
  $httpClient.get({
    url: sourceUrl,
    timeout: 30000,
    headers: { "User-Agent": "Loon" },
    "auto-redirect": true,
  }, (error, response, data) => {
    if (error || !response || response.status < 200 || response.status >= 400) {
      console.log(`AnyTLS parser request failed: ${error || `HTTP ${response && response.status}`}`);
      $done("");
      return;
    }
    try { $done(transformSubscription(data)); }
    catch (parseError) { console.log(`AnyTLS parser failed: ${parseError.message}`); $done(""); }
  });
  }
}
