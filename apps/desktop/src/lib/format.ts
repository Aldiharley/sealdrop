// Small pure helpers: paths, dates, sizes, durations, short forms of keys and hashes.

export function baseName(p: string): string {
  const parts = p.split(/[\\/]/).filter(Boolean);
  return parts[parts.length - 1] ?? p;
}

/** Parent folder of a path (keeps the drive root usable). Empty string if there is none. */
export function parentDir(p: string): string {
  const trimmed = p.replace(/[\\/]+$/, "");
  const i = Math.max(trimmed.lastIndexOf("/"), trimmed.lastIndexOf("\\"));
  if (i < 0) return "";
  const dir = trimmed.slice(0, i);
  if (dir === "" ) return trimmed.slice(0, 1);
  if (/^[A-Za-z]:$/.test(dir)) return dir + trimmed[i];
  return dir;
}

function sepOf(p: string): string {
  return p.includes("\\") && !p.includes("/") ? "\\" : "/";
}

export function joinPath(dir: string, name: string): string {
  const s = sepOf(dir);
  return dir.endsWith("/") || dir.endsWith("\\") ? dir + name : dir + s + name;
}

/** True when `child` is `parent` itself or lives inside it (separator and case tolerant). */
export function isInside(child: string, parent: string): boolean {
  const norm = (x: string) => x.replace(/\\/g, "/").replace(/\/+$/, "").toLowerCase();
  const c = norm(child);
  const p = norm(parent);
  return c === p || c.startsWith(p + "/");
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let u = 0;
  while (v >= 1024 && u < units.length - 1) {
    v /= 1024;
    u++;
  }
  const s = v.toFixed(1).replace(/\.0$/, "");
  return `${s} ${units[u]}`;
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/** `13 Oct 09:12 UTC`, with the year when it is not the current one. Returns "" for bad input. */
export function formatDate(iso: string | null | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const p = (n: number) => String(n).padStart(2, "0");
  const year = d.getUTCFullYear() === new Date().getUTCFullYear() ? "" : ` ${d.getUTCFullYear()}`;
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]}${year} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())} UTC`;
}

export function shortHash(h: string): string {
  return h.length > 14 ? `${h.slice(0, 8)}…${h.slice(-4)}` : h;
}

export function shortSigner(k: string): string {
  return k.length > 16 ? `${k.slice(0, 10)}…${k.slice(-3)}` : k;
}

export type RecipientTone = "pink" | "blue" | "sage";

export function recipientTone(kind: string): RecipientTone {
  if (kind.startsWith("plugin:")) return "sage";
  if (kind.includes("pq") || kind.includes("hybrid")) return "blue";
  return "pink";
}

export function shortRecipient(raw: string, plugin: string | null): string {
  if (plugin) {
    const head = raw.slice(0, 5 + plugin.length);
    return `${plugin} · ${head}…${raw.slice(-2)}`;
  }
  return `${raw.slice(0, 8)}…${raw.slice(-4)}`;
}

export function plural(n: number, one: string, many = `${one}s`): string {
  return n === 1 ? one : many;
}

export type WindowUnit = "seconds" | "minutes" | "hours" | "days";
export const UNIT_SECS: Record<WindowUnit, number> = { seconds: 1, minutes: 60, hours: 3600, days: 86400 };
export const UNITS: WindowUnit[] = ["seconds", "minutes", "hours", "days"];

/** `10 minutes`, `1 hour`, `3 days` for a number of seconds (largest unit that divides evenly). */
export function windowText(secs: number): string {
  const order: [WindowUnit, string][] = [
    ["days", "day"],
    ["hours", "hour"],
    ["minutes", "minute"],
    ["seconds", "second"],
  ];
  for (const [u, one] of order) {
    const k = UNIT_SECS[u];
    if (secs % k === 0 && secs >= k) {
      const n = secs / k;
      return `${n} ${plural(n, one)}`;
    }
  }
  return `${secs} ${plural(secs, "second")}`;
}

/** Window from the form: whole number >= 1 times the unit, or null when invalid. */
export function parseWindow(n: string, unit: WindowUnit): number | null {
  if (!/^\d+$/.test(n.trim())) return null;
  const v = Number(n.trim());
  if (!Number.isSafeInteger(v) || v < 1) return null;
  return v * UNIT_SECS[unit];
}

/** Window text as the user typed it (`10 minutes`), used live while typing. */
export function windowFromForm(n: string, unit: WindowUnit): string {
  const secs = parseWindow(n, unit);
  if (secs === null) return "the window";
  const v = secs / UNIT_SECS[unit];
  const one = unit.slice(0, -1);
  return `${v} ${plural(v, one)}`;
}

/** Compact countdown text: `41 s`, `9 m 41 s`, `2 h 05 m`, `3 d 4 h`. */
export function compactDuration(total: number): string {
  const t = Math.max(0, Math.floor(total));
  const p2 = (n: number) => String(n).padStart(2, "0");
  const d = Math.floor(t / 86400);
  const h = Math.floor((t % 86400) / 3600);
  const m = Math.floor((t % 3600) / 60);
  const s = t % 60;
  if (d > 0) return `${d} d ${h} h`;
  if (h > 0) return `${h} h ${p2(m)} m`;
  if (m > 0) return `${m} m ${p2(s)} s`;
  return `${s} s`;
}

export function hostOf(url: string | null | undefined): string {
  if (!url) return "";
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

/** Letters, digits, - and _ only (the signer-name rule). */
export function validSignerName(n: string): boolean {
  return /^[A-Za-z0-9_-]+$/.test(n);
}

export function looksLikeSignerKey(k: string): boolean {
  return /^RWQ[A-Za-z0-9+/]{40,}={0,2}$/.test(k.trim());
}

/** True for YYYY-MM-DD that is a real calendar date. */
export function parseIsoDate(s: string): Date | null {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return null;
  const d = new Date(`${s}T00:00:00Z`);
  if (Number.isNaN(d.getTime()) || d.toISOString().slice(0, 10) !== s) return null;
  return d;
}

export function kindLabel(kind: string): string {
  if (kind === "x25519") return "x25519";
  if (kind === "hybrid-pq") return "post-quantum";
  if (kind.startsWith("plugin:")) return "plugin";
  if (kind === "scrypt") return "passphrase (scrypt)";
  if (kind === "argon2id") return "passphrase (Argon2id)";
  return kind;
}

/** `1 (x25519)` / `2 (x25519, plugin)`; adds "timed release" when the package has one. */
export function recipientsText(recipients: { kind: string }[] | null, timed: boolean): string {
  const list = recipients ?? [];
  const kinds = Array.from(new Set(list.map((r) => kindLabel(r.kind))));
  if (timed) kinds.push("timed release");
  return `${list.length} (${kinds.join(", ")})`;
}
