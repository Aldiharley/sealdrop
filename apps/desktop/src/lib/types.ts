// TypeScript mirrors of the Tauri command structs (apps/desktop/src-tauri/src/commands.rs).
// Field names are snake_case exactly as serialized. Absent optionals arrive as `null`.

export interface IdentityInfo {
  exists: boolean;
  recipient: string | null;
  signer: string | null;
  dir: string;
  /** "x25519" or "pq"; null when there is no identity yet. */
  kind: "x25519" | "pq" | null;
}

export interface RecipientCheck {
  /** "x25519", "pq", "hybrid-pq" or "plugin:<name>" */
  kind: string;
  fingerprint: string;
  plugin: string | null;
  allowed: boolean;
}

export interface SealArgs {
  input: string;
  out_dir: string;
  recipients: string[];
  passphrase: boolean;
  /** "eff" | "bip39" */
  words: "eff" | "bip39";
  argon2id: boolean;
  /** "default" | "high" */
  kdf_profile: "default" | "high";
  armor: boolean;
  classification: string | null;
  expires: string | null;
  allow_unrecoverable: boolean;
  include_self: boolean;
  expire_after_secs: number | null;
}

export interface ReleaseOut {
  service: string;
  window_secs: number;
}

export interface SealOut {
  package: string;
  manifest: string;
  package_id: string;
  ciphertext_sha256: string;
  files: number;
  bytes: number;
  passphrase: string | null;
  entropy_bits: number | null;
  release: ReleaseOut | null;
  /** Why the sender's own identity was left out of the package, if it was. */
  self_omitted: string | null;
  /** True when every recipient of the package is a post-quantum kind. */
  post_quantum: boolean;
}

export interface ProbeOut {
  /** True for a passphrase stanza in the header, or a timed package whose manifest says
   *  the key inside is a passphrase. */
  needs_passphrase: boolean;
  /** recipients[0].kind from the manifest beside the package, read unverified: only a hint
   *  for showing the passphrase field ("scrypt" | "argon2id" | "x25519" | ...). */
  inner_kind: string | null;
  timed_release: { service: string; release_id: string } | null;
}

export interface RecipientOut {
  kind: string;
  fingerprint: string;
}

export interface VerifyOut {
  ok: boolean;
  untrusted_signer: string | null;
  package_id: string | null;
  signer: string | null;
  trusted_as: string | null;
  created: string | null;
  classification: string | null;
  expires: string | null;
  recipients: RecipientOut[] | null;
  release: ReleaseOut | null;
  ciphertext_sha256: string | null;
  /** Every signed recipient is post-quantum; null when the package was not verified. */
  post_quantum: boolean | null;
}

export interface OpenArgs {
  package: string;
  out_dir: string | null;
  temp: boolean;
  passphrase: string | null;
  signer: string | null;
  skip_verify: boolean;
  overwrite: boolean;
}

export interface OpenOut {
  root: string;
  files: number;
  bytes: number;
  signer: string | null;
  trusted_as: string | null;
  verified: boolean;
  first_unlock: string | null;
  expires_at: string | null;
  /** Service-clock sample taken when the response was produced. */
  remaining_secs: number | null;
  /** Every signed recipient is post-quantum; null when verification was skipped. */
  post_quantum: boolean | null;
}

export interface Trusted {
  name: string;
  key: string;
}

export interface Settings {
  release_service: string | null;
  /** Returned in clear by get_settings. Keep it in form state only. */
  release_token: string | null;
  /** 18 = Standard, 20 = High */
  scrypt_log_n: number;
  armor: boolean;
  argon2id: boolean;
}

export interface ReceiptOut {
  release_id: string;
  first_unlock: string | null;
  expires_at: string | null;
  remaining_secs: number | null;
  unlock_count: number;
  service_key: string;
  pinned: boolean;
  saved_to: string;
}

export type ProgressKind = "packing" | "encrypted" | "contacting" | "verifying" | "extracting" | "done";

export interface ProgressEvent {
  kind: ProgressKind;
  detail: string;
}

export type DragDropEvent =
  | { type: "enter"; paths: string[]; position: { x: number; y: number } }
  | { type: "over"; position: { x: number; y: number } }
  | { type: "drop"; paths: string[]; position: { x: number; y: number } }
  | { type: "leave" };

export type ScreenId = "seal" | "open" | "verify" | "keys" | "settings";

/** What a native file dialog should offer. */
export interface PickOptions {
  /** Used by the mock to invent a plausible path. */
  kind?: "file" | "package" | "manifest" | "receipt";
  /** Extensions without the dot, for the native dialog filter. */
  extensions?: string[];
  title?: string;
}
