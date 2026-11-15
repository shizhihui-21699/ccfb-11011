/**
 * Version comparison for OS build strings such as "15.2.0", "14.6",
 * "11.0.22631", or "6.8.0-45-generic". Only the leading dot-separated numeric
 * run is significant; pre-release suffixes are ignored on purpose so that an
 * unknown build cannot accidentally pass a minimum check.
 */
export function parseVersion(raw: string): number[] | null {
  const match = /^\s*v?(\d+(?:\.\d+)*)/i.exec(raw);
  if (!match) return null;
  const parts = match[1]!.split('.').map((part) => Number.parseInt(part, 10));
  if (parts.some((part) => !Number.isSafeInteger(part) || part < 0)) return null;
  return parts;
}

/**
 * Returns a negative number when `a < b`, zero when equal, positive when
 * `a > b`. Missing segments count as zero, so "14" == "14.0.0".
 * Unparseable input sorts before everything else.
 */
export function compareVersions(a: string, b: string): number {
  const left = parseVersion(a);
  const right = parseVersion(b);
  if (left === null && right === null) return 0;
  if (left === null) return -1;
  if (right === null) return 1;
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const delta = (left[index] ?? 0) - (right[index] ?? 0);
    if (delta !== 0) return delta;
  }
  return 0;
}

/** True when `actual` meets or exceeds `minimum`. Unparseable actual fails. */
export function meetsMinimumVersion(actual: string, minimum: string): boolean {
  if (parseVersion(actual) === null) return false;
  return compareVersions(actual, minimum) >= 0;
}

/** Normalizes an OS name to a coarse family used by policy matching. */
export function osFamily(osName: string): 'macos' | 'windows' | 'linux' | 'unknown' {
  const value = osName.toLowerCase();
  if (value.includes('mac') || value.includes('darwin') || value.includes('os x')) return 'macos';
  if (value.includes('windows') || value.startsWith('win')) return 'windows';
  if (value.includes('linux') || value.includes('ubuntu') || value.includes('debian')) return 'linux';
  return 'unknown';
}

export type OsFamily = 'macos' | 'windows' | 'linux';

/**
 * A minimum-version floor. A bare string applies to every OS family, but
 * OS version numbering is not comparable across families (macOS 15 vs Windows
 * 11.0.22631 vs Linux 6.8), so production floors should be a per-family map.
 * A map deliberately has no wildcard: a family that is absent has no floor,
 * and `resolveVersionFloor` reports that explicitly so callers can decide.
 */
export type VersionFloor = string | Partial<Record<OsFamily, string>>;

export function resolveVersionFloor(
  floor: VersionFloor | undefined,
  family: OsFamily,
): string | null {
  if (floor === undefined) return null;
  if (typeof floor === 'string') return floor;
  return floor[family] ?? null;
}

/**
 * Whether a floor applies to every family. Used for validation and for the
 * admin UI, which warns when a bare string is used for mixed OS fleets.
 */
export function floorIsFamilyScoped(floor: VersionFloor | undefined): boolean {
  return floor !== undefined && typeof floor === 'object';
}

