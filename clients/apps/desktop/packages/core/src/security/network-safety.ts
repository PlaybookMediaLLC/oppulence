const CLOUD_METADATA_HOSTNAMES = new Set([
  "metadata.google.internal",
  "metadata.goog",
  "instance-data",
  "metadata",
]);

function parseIpv4Octets(ip: string): [number, number, number, number] | null {
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const octets = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])] as const;
  if (octets.some((n) => n < 0 || n > 255)) return null;
  return [octets[0], octets[1], octets[2], octets[3]];
}

function parseIpv6Hextets(rawIp: string): number[] | null {
  let ip = rawIp.toLowerCase().replace(/^\[|\]$/g, "");
  const zoneIdx = ip.indexOf("%");
  if (zoneIdx !== -1) ip = ip.slice(0, zoneIdx);
  if (!ip.includes(":")) return null;

  // Handle trailing embedded IPv4 dotted quad (e.g. ::ffff:169.254.169.254)
  const lastColon = ip.lastIndexOf(":");
  const tail = ip.slice(lastColon + 1);
  if (tail.includes(".")) {
    const octets = parseIpv4Octets(tail);
    if (!octets) return null;
    const hi = ((octets[0] << 8) | octets[1]).toString(16);
    const lo = ((octets[2] << 8) | octets[3]).toString(16);
    ip = `${ip.slice(0, lastColon + 1)}${hi}:${lo}`;
  }

  const halves = ip.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":").filter(Boolean) : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":").filter(Boolean) : [];
  const missing = halves.length === 2 ? 8 - (left.length + right.length) : 0;
  if (halves.length === 1 && left.length !== 8) return null;
  if (missing < 0) return null;

  const parts = [...left, ...Array<string>(missing).fill("0"), ...right];
  if (parts.length !== 8) return null;
  const hextets: number[] = [];
  for (const part of parts) {
    if (!/^[0-9a-f]{1,4}$/.test(part)) return null;
    hextets.push(parseInt(part, 16));
  }
  return hextets;
}

function extractEmbeddedIpv4FromIpv6(
  h: readonly number[],
): [number, number, number, number] | null {
  const fromLastTwo = (): [number, number, number, number] => [
    (h[6] >> 8) & 255,
    h[6] & 255,
    (h[7] >> 8) & 255,
    h[7] & 255,
  ];
  // IPv4-mapped ::ffff:0:0/96
  if (h[0] === 0 && h[1] === 0 && h[2] === 0 && h[3] === 0 && h[4] === 0 && h[5] === 0xffff) {
    return fromLastTwo();
  }
  // IPv4-translated ::ffff:0:0:0/96
  if (h[0] === 0 && h[1] === 0 && h[2] === 0 && h[3] === 0 && h[4] === 0xffff && h[5] === 0) {
    return fromLastTwo();
  }
  // IPv4-compatible ::/96 (excluding :: and ::1)
  if (
    h[0] === 0 &&
    h[1] === 0 &&
    h[2] === 0 &&
    h[3] === 0 &&
    h[4] === 0 &&
    h[5] === 0 &&
    (h[6] !== 0 || h[7] > 1)
  ) {
    return fromLastTwo();
  }
  // Well-known NAT64 64:ff9b::/96
  if (h[0] === 0x0064 && h[1] === 0xff9b && h[2] === 0 && h[3] === 0 && h[4] === 0 && h[5] === 0) {
    return fromLastTwo();
  }
  // Local-use NAT64 64:ff9b:1::/48
  if (h[0] === 0x0064 && h[1] === 0xff9b && h[2] === 0x0001) {
    return fromLastTwo();
  }
  // 6to4 2002::/16 (embedded IPv4 in hextets 1 and 2)
  if (h[0] === 0x2002) {
    return [(h[1] >> 8) & 255, h[1] & 255, (h[2] >> 8) & 255, h[2] & 255];
  }
  return null;
}

function isCloudMetadataIpv4(octets: readonly [number, number, number, number]): boolean {
  const [a, b, c, d] = octets;
  if (a === 169 && b === 254) return true;
  if (a === 100 && b === 100 && c === 100 && d === 200) return true;
  return false;
}

function isPrivateOrLocalIpv4(octets: readonly [number, number, number, number]): boolean {
  const [a, b] = octets;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  return false;
}

export function isCloudMetadataHostOrIp(rawHost: string): boolean {
  const host = rawHost
    .toLowerCase()
    .replace(/^\[|\]$/g, "")
    .replace(/\.+$/, "");
  if (!host) return false;
  if (CLOUD_METADATA_HOSTNAMES.has(host) || host.endsWith(".metadata.google.internal")) {
    return true;
  }
  const v4 = parseIpv4Octets(host);
  if (v4) {
    return isCloudMetadataIpv4(v4);
  }
  const h = parseIpv6Hextets(host);
  if (h) {
    // AWS EC2 IPv6 IMDS fd00:ec2::254
    if (
      h[0] === 0xfd00 &&
      h[1] === 0x0ec2 &&
      h[2] === 0 &&
      h[3] === 0 &&
      h[4] === 0 &&
      h[5] === 0 &&
      h[6] === 0 &&
      h[7] === 0x0254
    ) {
      return true;
    }
    const embedded = extractEmbeddedIpv4FromIpv6(h);
    if (embedded && isCloudMetadataIpv4(embedded)) {
      return true;
    }
  }
  return false;
}

export function isPrivateOrLocalIpAddress(rawIp: string): boolean {
  const ip = rawIp
    .toLowerCase()
    .replace(/^\[|\]$/g, "")
    .replace(/\.+$/, "");
  const v4 = parseIpv4Octets(ip);
  if (v4) {
    return isPrivateOrLocalIpv4(v4);
  }
  const h = parseIpv6Hextets(ip);
  if (h) {
    const isAllZeroPrefix =
      h[0] === 0 &&
      h[1] === 0 &&
      h[2] === 0 &&
      h[3] === 0 &&
      h[4] === 0 &&
      h[5] === 0 &&
      h[6] === 0;
    if (isAllZeroPrefix && (h[7] === 0 || h[7] === 1)) return true;
    if ((h[0] & 0xfe00) === 0xfc00 || (h[0] & 0xffc0) === 0xfe80) return true;
    if (h[0] === 0x0064 && h[1] === 0xff9b && h[2] === 0x0001) return true;
    const embedded = extractEmbeddedIpv4FromIpv6(h);
    if (embedded) return isPrivateOrLocalIpv4(embedded);
  }
  return false;
}
