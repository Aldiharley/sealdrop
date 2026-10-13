// Mock backend for plain-browser development and README screenshots.
// Active only when window.__TAURI_INTERNALS__ is absent (see api.ts). Everything resolves after
// about 300 ms with plausible data. State (identity, trusted signers, settings) lives in memory.
//
// Query switches (mock mode only):
//   ?pkg=timed|pass|plain|untrusted|tampered   which package the "Choose package" buttons return
//   ?identity=none                             start without an identity

import type * as T from "./types";

const q = typeof window !== "undefined" ? new URLSearchParams(window.location.search) : new URLSearchParams();

const ALICE = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";
const BOB = "RWQa91Zc7pK2dQ8mWn4VtXrYj0uHsLbE3oFiCgA5Nx6yTzMq1RkPwDvS";
const CAROL = "RWQm3Ht8vWz0LxK5nBq2Ye7JdPcRu9AsFg4iTo1NhXb6ZkCyQlMrVwE2";
const SERVICE_KEY = "RWQs7eRvIcE3Kp0TnLq8YaWdB5ZhUxJm2GfOo9CtNr4VkDyXiSwQlHbM";
const SERVICE = "https://release.example.org";

const state = {
  identity: {
    exists: q.get("identity") !== "none",
    recipient: "age1qx7k4m9v2c8l5n3z6p0t7y4h2j8d5s9w3e6r1u4a7g0f2b8x5m3q9c6k4v7w2f3k2" as string | null,
    signer: ALICE as string | null,
    dir: "C:\\Users\\me\\.sealdrop",
  } as T.IdentityInfo,
  trusted: [
    { name: "alice", key: ALICE },
    { name: "bob", key: BOB },
  ] as T.Trusted[],
  settings: {
    release_service: SERVICE,
    release_token: "demo-deposit-token",
    scrypt_log_n: 18,
    armor: false,
    argon2id: false,
  } as T.Settings,
};

const delay = (ms = 300) => new Promise<void>((r) => setTimeout(r, ms));

// ---- progress events ----------------------------------------------------------------
const listeners = new Set<(p: T.ProgressEvent) => void>();
export function mockListen(cb: (p: T.ProgressEvent) => void): () => void {
  listeners.add(cb);
  return () => listeners.delete(cb);
}
function emit(kind: T.ProgressKind, detail = "") {
  listeners.forEach((l) => l({ kind, detail }));
}

// ---- dialogs -------------------------------------------------------------------------
let manifestPick = 0;
const MANIFESTS = ["report-q3", "payroll-oct", "site-plans"];

function pkgName(): string {
  switch (q.get("pkg")) {
    case "pass":
      return "payroll-pass.sealdrop.age";
    case "plain":
      return "q3-findings.sealdrop.age";
    case "untrusted":
      return "q3-findings-untrusted.sealdrop.age";
    case "tampered":
      return "q3-findings-tampered.sealdrop.age";
    default:
      return "q3-findings-timed.sealdrop.age";
  }
}

export function mockPick(kind: "file" | "package" | "manifest" | "receipt" | "folder" | "folder-in" | "folder-out"): string {
  const docs = "C:/Users/me/Documents";
  switch (kind) {
    case "file":
      return `${docs}/q3-findings.pdf`;
    case "package":
      return `${docs}/sealed/${pkgName()}`;
    case "manifest": {
      const n = MANIFESTS[manifestPick++ % MANIFESTS.length];
      return `${docs}/sealed/${n}.manifest.json`;
    }
    case "receipt":
      return `${docs}/sealed/report-q3.receipt.json`;
    case "folder-in":
      return `${docs}/report-q3`;
    case "folder-out":
    case "folder":
    default:
      return `${docs}/out`;
  }
}

// ---- helpers ---------------------------------------------------------------------------
function hash16(s: string): string {
  let h1 = 0xdeadbeef ^ s.length;
  let h2 = 0x41c6ce57;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 2654435761);
    h2 = Math.imul(h2 ^ c, 1597334677);
  }
  const a = (h1 >>> 0).toString(16).padStart(8, "0");
  const b = (h2 >>> 0).toString(16).padStart(8, "0");
  return a + b;
}

function lastSegment(p: string): string {
  const parts = p.split(/[\\/]/).filter(Boolean);
  return parts[parts.length - 1] ?? p;
}

function iso(offsetSecs: number): string {
  return new Date(Date.now() + offsetSecs * 1000).toISOString().replace(/\.\d+Z$/, "Z");
}

const WORDS = ["abacus", "cargo", "drift", "eagle", "fable", "galaxy"];
const SHA = "9c1f3a7b4d2e8f0a6b5c1d3e7f9a2b4c6d8e0f1a3b5c7d9e1f2a4b6c8d0e0a4f";

function isTimedPath(p: string) {
  return p.includes("timed");
}
function isPassPath(p: string) {
  return p.includes("pass");
}
function pkgSigner(p: string) {
  return p.includes("untrusted") ? CAROL : ALICE;
}

// ---- commands ---------------------------------------------------------------------------
export async function mock(cmd: string, args: Record<string, unknown> = {}): Promise<unknown> {
  await delay(300);
  switch (cmd) {
    case "get_identity":
      return { ...state.identity };

    case "generate_identity": {
      state.identity = {
        exists: true,
        recipient: "age1qx7k4m9v2c8l5n3z6p0t7y4h2j8d5s9w3e6r1u4a7g0f2b8x5m3q9c6k4v7w2f3k2",
        signer: ALICE,
        dir: state.identity.dir,
      };
      return { ...state.identity };
    }

    case "parse_recipient": {
      const s = String(args.s ?? "").trim();
      if (!/^age1[a-z0-9]{16,}$/.test(s)) throw `invalid recipient \`${s}\``;
      const fingerprint = hash16(s);
      if (s.startsWith("age1pq")) return { kind: "hybrid-pq", fingerprint, plugin: null, allowed: true };
      const m = /^age1([a-z]+)1/.exec(s);
      if (m && m[1] !== "qx" && m[1] !== "q" && m[1].length > 2) {
        const allowed = ["yubikey", "tpm", "se"].includes(m[1]);
        return { kind: `plugin:${m[1]}`, fingerprint, plugin: m[1], allowed };
      }
      return { kind: "x25519", fingerprint, plugin: null, allowed: true };
    }

    case "seal": {
      const req = args.req as T.SealArgs;
      if (!req.passphrase && req.recipients.length === 0) throw "policy refused: no recipients given";
      if (req.passphrase && req.recipients.length > 0)
        throw "policy refused: a passphrase cannot be combined with other recipients";
      if (req.expire_after_secs && !state.settings.release_service)
        throw "Set the release service URL in Settings first";
      emit("packing", req.input);
      await delay(350);
      emit("encrypted", "50331648");
      await delay(250);
      if (req.expire_after_secs) {
        emit("contacting", SERVICE);
        await delay(300);
      }
      emit("done");
      const stem = lastSegment(req.input).replace(/\.[^.]+$/, "") || "package";
      const dir = req.out_dir.replace(/[\\/]+$/, "");
      const out: T.SealOut = {
        package: `${dir}/${stem}.sealdrop.age`,
        manifest: `${dir}/${stem}.manifest.json`,
        package_id: "3f2a91c0-7d44-4b0e-9a1f-c5d2e8b71e04",
        ciphertext_sha256: SHA,
        files: 12,
        bytes: 50_646_835,
        passphrase: req.passphrase ? WORDS.join(" ") : null,
        entropy_bits: req.passphrase ? 77.5 : null,
        release: req.expire_after_secs ? { service: SERVICE, window_secs: req.expire_after_secs } : null,
      };
      return out;
    }

    case "probe": {
      const path = String(args.path ?? "");
      if (!path.endsWith(".sealdrop.age")) throw "not a sealdrop package";
      const out: T.ProbeOut = {
        needs_passphrase: isPassPath(path),
        timed_release: isTimedPath(path) ? { service: SERVICE, release_id: "rel_8c1d4f" } : null,
      };
      return out;
    }

    case "verify": {
      const path = String(args.path ?? "");
      const signerArg = (args.signer as string | null) ?? null;
      if (path.includes("tampered"))
        throw "verification failed: ciphertext hash does not match the signed manifest";
      if (path.includes("nosidecar")) throw `verification failed: manifest not found: ${path}`;
      const signer = pkgSigner(path);
      const base: T.VerifyOut = {
        ok: true,
        untrusted_signer: null,
        package_id: "3f2a91c0-7d44-4b0e-9a1f-c5d2e8b71e04",
        signer,
        trusted_as: null,
        created: "2026-10-13T09:00:00Z",
        classification: "confidential",
        expires: "2026-12-31",
        recipients: isPassPath(path)
          ? [{ kind: "scrypt", fingerprint: "" }]
          : [{ kind: "x25519", fingerprint: "a41c0e9b72d3f685" }],
        release: isTimedPath(path) ? { service: SERVICE, window_secs: 600 } : null,
        ciphertext_sha256: SHA,
      };
      if (signerArg) {
        if (signerArg !== signer) throw `verification failed: manifest signer ${signer} does not match --signer`;
        return base;
      }
      const t = state.trusted.find((x) => x.key === signer);
      if (!t) return { ...base, ok: false, untrusted_signer: signer, classification: null, expires: null };
      return { ...base, trusted_as: t.name };
    }

    case "open_package": {
      const req = args.req as T.OpenArgs;
      emit("verifying");
      if (isPassPath(req.package) && !req.passphrase) throw "this package needs a passphrase";
      await delay(250);
      if (isTimedPath(req.package)) {
        emit("contacting", SERVICE);
        await delay(350);
      }
      emit("extracting", req.package);
      await delay(350);
      emit("done");
      const timed = isTimedPath(req.package);
      const root = req.temp
        ? "C:/Users/me/AppData/Local/Temp/sealdrop-view-k3j9x2/0/report-q3"
        : `${(req.out_dir ?? "C:/Users/me/Documents").replace(/[\\/]+$/, "")}/report-q3`;
      const out: T.OpenOut = {
        root,
        files: 12,
        bytes: 50_646_835,
        signer: pkgSigner(req.package),
        trusted_as: req.skip_verify ? null : "alice",
        verified: !req.skip_verify,
        first_unlock: timed ? iso(-19) : null,
        expires_at: timed ? iso(581) : null,
        remaining_secs: timed ? 581 : null,
      };
      return out;
    }

    case "list_trusted":
      return state.trusted.map((t) => ({ ...t }));
    case "add_trusted": {
      const name = String(args.name ?? "");
      const key = String(args.key ?? "");
      if (!/^[A-Za-z0-9_-]+$/.test(name)) throw "trusted-signer names may use letters, digits, - and _ only";
      if (!/^RWQ[A-Za-z0-9+/]{40,}$/.test(key)) throw "invalid signer key";
      if (state.trusted.some((t) => t.name === name)) throw `a signer named \`${name}\` already exists`;
      state.trusted.push({ name, key });
      return null;
    }
    case "remove_trusted":
      state.trusted = state.trusted.filter((t) => t.name !== args.name);
      return null;

    case "get_settings":
      return { ...state.settings };
    case "set_settings": {
      const s = args.settings as T.Settings;
      const svc = s.release_service?.trim() || null;
      if (svc && !/^https:\/\/|^http:\/\/(localhost|127\.0\.0\.1|\[::1\])/.test(svc))
        throw "release service: invalid service URL: use https";
      state.settings = { ...s, release_service: svc, release_token: s.release_token?.trim() || null };
      return null;
    }

    case "receipt_fetch": {
      const path = String(args.manifestPath ?? "");
      let r: T.ReceiptOut = {
        release_id: "rel_8c1d4f",
        first_unlock: iso(-1130),
        expires_at: iso(250),
        remaining_secs: 250,
        unlock_count: 2,
        service_key: SERVICE_KEY,
        pinned: true,
        saved_to: path.replace(/\.manifest\.json$/, ".receipt.json"),
      };
      if (path.includes("payroll"))
        r = { ...r, release_id: "rel_41ab09", first_unlock: iso(-86400 * 3), expires_at: iso(-86400 * 3 + 600), remaining_secs: 0, unlock_count: 1 };
      if (path.includes("site"))
        r = { ...r, release_id: "rel_77d2e3", first_unlock: null, expires_at: null, remaining_secs: null, unlock_count: 0 };
      return r;
    }

    case "receipt_verify": {
      const key = (args.serviceKey as string | null) ?? null;
      if (key && key !== SERVICE_KEY) throw "verification failed: receipt signed by a different service key";
      const r: T.ReceiptOut = {
        release_id: "rel_8c1d4f",
        first_unlock: iso(-288),
        expires_at: iso(312),
        remaining_secs: 312,
        unlock_count: 2,
        service_key: SERVICE_KEY,
        pinned: !!key,
        saved_to: "",
      };
      return r;
    }

    default:
      throw `unknown command ${cmd}`;
  }
}

export const MOCK_SERVICE_KEY = SERVICE_KEY;
