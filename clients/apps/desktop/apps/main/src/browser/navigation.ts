const SEARCH_ENGINE_BASE_URL = "https://www.google.com/search?q=";

const HAS_SCHEME_RE = /^[a-z][a-z0-9+.-]*:/i;
const IPV4_HOST_RE = /^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:\/.*)?$/;
const LOCALHOST_RE = /^localhost(?::\d+)?(?:\/.*)?$/i;
const DOMAIN_LIKE_RE = /^[\w.-]+\.[a-z]{2,}(?::\d+)?(?:\/.*)?$/i;

const BLOCKED_METADATA_HOSTS = new Set([
  "169.254.169.254",
  "169.254.170.2",
  "100.100.100.200",
  "fd00:ec2::254",
  "metadata.google.internal",
  "metadata.goog",
  "instance-data",
]);

function assertAllowedNavigationUrl(rawUrl: string): string {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch (err) {
    throw new Error("Invalid navigation URL.", { cause: err });
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("Only http:// and https:// URLs are allowed in the embedded browser.");
  }
  const host = parsed.hostname
    .toLowerCase()
    .replace(/^\[|\]$/g, "")
    .replace(/\.+$/, "");
  if (
    BLOCKED_METADATA_HOSTS.has(host) ||
    host.endsWith(".metadata.google.internal") ||
    host.startsWith("169.254.") ||
    host.includes("a9fe:") ||
    host.includes("6464:64c8")
  ) {
    throw new Error("Cloud metadata addresses are not allowed in the embedded browser.");
  }
  return parsed.toString();
}

export function normalizeNavigationTarget(target: string): string {
  const trimmed = target.trim();
  if (!trimmed) {
    throw new Error("Navigation target cannot be empty.");
  }

  if (HAS_SCHEME_RE.test(trimmed)) {
    return assertAllowedNavigationUrl(trimmed);
  }

  const looksLikeHost =
    LOCALHOST_RE.test(trimmed) || DOMAIN_LIKE_RE.test(trimmed) || IPV4_HOST_RE.test(trimmed);

  if (looksLikeHost && !/\s/.test(trimmed)) {
    const scheme =
      LOCALHOST_RE.test(trimmed) || IPV4_HOST_RE.test(trimmed) ? "http://" : "https://";
    return assertAllowedNavigationUrl(`${scheme}${trimmed}`);
  }

  return `${SEARCH_ENGINE_BASE_URL}${encodeURIComponent(trimmed)}`;
}
