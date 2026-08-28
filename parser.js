/*
 * Loon resource parser.
 * Loon supplies the downloaded resource as $resource.content. We decode a
 * Base64 subscription when needed, convert only anytls:// entries, and leave
 * every other line untouched for Loon's normal parser.
 */

function safeDecodeURIComponent(value) {
  try { return decodeURIComponent(value); } catch (_) { return value; }
}

function decodeBase64Utf8(value) {
  const normalized = value.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized) || normalized.length % 4 === 1) return null;
  try {
    const binary = atob(normalized + "=".repeat((4 - normalized.length % 4) % 4));
    let escaped = "";
    for (let i = 0; i < binary.length; i += 1) {
      escaped += `%${binary.charCodeAt(i).toString(16).padStart(2, "0")}`;
    }
    return decodeURIComponent(escaped);
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

function parseAnyTLS(uri) {
  const parsed = new URL(uri);
  const name = safeDecodeURIComponent((parsed.hash || "").slice(1)) || "AnyTLS";
  const password = safeDecodeURIComponent(parsed.username || "");
  const server = parsed.hostname;
  const port = parsed.port || "443";
  const sni = parsed.searchParams.get("sni") || parsed.searchParams.get("peer") || "";
  const insecure = parsed.searchParams.get("insecure") === "1" || parsed.searchParams.get("allowInsecure") === "1";
  const udp = parsed.searchParams.get("udp");
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
  module.exports = { decodeBase64Utf8, maybeDecodeSubscription, parseAnyTLS, transformSubscription };
}

if (typeof $resource !== "undefined" && typeof $done === "function") {
  try { $done({ content: transformSubscription($resource.content) }); }
  catch (error) { $done({ error: `AnyTLS parser failed: ${error.message}` }); }
}
