// Maps the backend's error strings (core messages, see crates/sealdrop-core/src/error.rs) onto the
// copy in docs/design/brief.md. Anything unrecognised falls back to the generic pattern, which
// carries the reason through.

/** G1: any unclassified failure. */
export function g1(reason: string): string {
  return `Something went wrong: ${trimStop(reason)}. Nothing was changed.`;
}

function trimStop(s: string): string {
  return s.trim().replace(/[.\s]+$/, "");
}

export const G5 = "sealdrop can't read that. Check that it still exists and that you can open it.";
export const G6 = "sealdrop can't write to that folder. Choose another one.";
export const NOT_A_PACKAGE = "That doesn't look like a sealdrop package. Choose a file that ends in .sealdrop.age.";
export const SIDECAR_MISSING =
  "The manifest or signature file isn't next to the package. Keep the .sealdrop.age, .manifest.json and .minisig files together.";
export const VERIFY_FAILED = "This package failed verification. It may have been changed after it was sealed. Don't open it.";

const NOT_WRITABLE = /permission denied|access is denied|read-only|os error (5|13|30)\b/i;
const UNREACHABLE = /release service|connect|dns|timed out|timeout|network|error sending request|connection|io: |unexpected status|tls|certificate/i;

export type SealErrorField = "path" | "window" | "date" | undefined;

export function mapSealError(msg: string, pluginNames: string[] = []): { text: string; field: SealErrorField } {
  const m = msg;
  if (/hardware-only recipients need/i.test(m)) {
    return { text: "Hardware keys alone can't be recovered. Add a second recipient or accept the warning.", field: undefined };
  }
  if (/cannot be mixed with classical/i.test(m)) {
    return { text: "Post-quantum and classical recipients can't share one package. Remove one group, or seal twice.", field: undefined };
  }
  if (/policy refused:/i.test(m)) {
    const reason = m.replace(/^.*policy refused:\s*/i, "");
    return { text: `sealdrop refused to seal this: ${trimStop(reason)}.`, field: undefined };
  }
  const plug = /age-plugin-([a-z0-9_-]+)/i.exec(m);
  if (plug || (/plugin/i.test(m) && /not found|no such file|cannot find|os error 2\b|program not found/i.test(m))) {
    const name = plug?.[1] ?? pluginNames[0] ?? "plugin";
    return { text: `age-plugin-${name} wasn't found on this computer, so sealdrop can't use that key.`, field: undefined };
  }
  if (/deposit token in settings/i.test(m)) {
    return { text: "The release service needs a deposit token. Add it in Settings.", field: undefined };
  }
  if (/release service url in settings/i.test(m)) {
    return { text: "No release service is set up. Add one in Settings to use timed release.", field: undefined };
  }
  if (/invalid service url/i.test(m)) {
    return {
      text: "The release service address must start with https:// (http:// is allowed only for this computer).",
      field: undefined,
    };
  }
  if (/release service/i.test(m) && /401|403|token|unauthori[sz]ed|forbidden|rejected/i.test(m)) {
    return { text: "The release service refused the deposit token. Check it in Settings.", field: undefined };
  }
  if (/release service|deposit failed|receipt fetch failed/i.test(m) || (UNREACHABLE.test(m) && /http|status|connect|dns|tls/i.test(m))) {
    return {
      text: "The release service didn't respond, so nothing was sealed. Check the address in Settings and try again.",
      field: undefined,
    };
  }
  if (/\bempty\b|nothing to (seal|pack)|no files/i.test(m)) {
    return { text: "That folder is empty. There is nothing to seal.", field: "path" };
  }
  if (/at least 1 second|window must be/i.test(m)) {
    return { text: "Enter a whole number of at least 1.", field: "window" };
  }
  if (NOT_WRITABLE.test(m) && /write|create|out|folder|directory|i\/o/i.test(m)) {
    return { text: G6, field: undefined };
  }
  if (/cannot read/i.test(m)) {
    return { text: G5, field: "path" };
  }
  return { text: `Couldn't seal: ${trimStop(m)}. No package was kept.`, field: undefined };
}

export function mapOpenError(msg: string, host: string, usedPassphrase: boolean): string {
  const m = msg;
  if (/has expired|expired at the release service|\bexpired\b/i.test(m)) {
    return "This package has expired. The release service no longer holds the key, so it can't be opened.";
  }
  if (/does not match --signer/i.test(m)) {
    return "This package was signed by a different key than the one you entered.";
  }
  if (/manifest not found|signature not found/i.test(m)) return SIDECAR_MISSING;
  if (/verification failed|manifest signature invalid|trusted comment|ciphertext hash|ciphertext\.file/i.test(m)) return VERIFY_FAILED;
  if (/excessive work|work factor|too many (entries|bytes)|tar extension header|too large/i.test(m)) {
    return "This package asks for more time or memory than sealdrop allows. Nothing was opened.";
  }
  if (/forbidden entry type|bad path|extraction refused: (?!hash|file)/i.test(m) && !/hash mismatch|missing from archive|not listed/i.test(m)) {
    return "This package contains something sealdrop won't extract, such as a link or an unsafe path. Nothing was written.";
  }
  if (/hash mismatch|missing from archive|not listed in meta|extraction refused/i.test(m)) {
    return "The data failed its integrity check. Nothing was kept.";
  }
  if (/already exists/i.test(m)) {
    return "Some files already exist in that folder. Choose another folder, or turn on “Replace existing files” under More options.";
  }
  if (/no matching keys/i.test(m)) {
    return "Your key isn't one of this package's recipients. Ask the sender to seal it to your recipient string (Keys).";
  }
  if (/needs a passphrase|incorrect passphrase|wrong passphrase|bad passphrase|invalid mac|header mac|decryption failed/i.test(m)) {
    if (usedPassphrase) return "That passphrase didn't open the package. Check it and try again.";
    return "The data failed its integrity check. Nothing was kept.";
  }
  if (/unlock token rejected|release not found|bad key|invalid signing key/i.test(m)) {
    return "The release service refused this package. The sender may need to seal it again.";
  }
  if (NOT_WRITABLE.test(m)) return G6;
  if (UNREACHABLE.test(m)) {
    return `Couldn't reach ${host || "the release service"}. A timed package can't be opened offline.`;
  }
  return `Couldn't open the package: ${trimStop(m)}. Nothing was written.`;
}

export type VerifyFailure = {
  kind: "sidecar" | "signature" | "hash" | "signer-mismatch" | "other";
  text: string;
};

export function mapVerifyError(msg: string): VerifyFailure {
  if (/manifest not found|signature not found/i.test(msg)) return { kind: "sidecar", text: SIDECAR_MISSING };
  if (/does not match --signer/i.test(msg)) {
    return { kind: "signer-mismatch", text: "This package was signed by a different key than the one you entered." };
  }
  if (/ciphertext hash|ciphertext\.file/i.test(msg)) {
    return { kind: "hash", text: "The package doesn't match the hash in its manifest. It may have been changed or damaged." };
  }
  if (/signature|trusted comment|manifest error/i.test(msg)) {
    return { kind: "signature", text: "The manifest signature doesn't match. The record may have been altered." };
  }
  return { kind: "other", text: `Couldn't check the package: ${trimStop(msg)}.` };
}

/** Routes an add_trusted failure to the field it belongs to; anything else is a form-level error. */
export function mapTrustError(msg: string, name: string): { field: "name" | "key" | "form"; text: string } {
  if (/^(key store error: )?invalid trusted name/i.test(msg.trim())) {
    return { field: "name", text: "Use letters, digits, - and _ only." };
  }
  if (/already exists/i.test(msg)) return { field: "name", text: `A signer named “${name}” already exists.` };
  if (/base64|public key/i.test(msg)) return { field: "key", text: "That isn't a valid signer key." };
  return { field: "form", text: g1(msg) };
}

export function mapReceiptVerifyError(msg: string): string {
  if (/different service key/i.test(msg)) return "The receipt wasn't signed by the service key you entered.";
  if (/not a receipt|expected a file named|not valid|invalid.*(base64|key)|json/i.test(msg) && !/signature invalid/i.test(msg)) {
    return "That doesn't look like a sealdrop receipt.";
  }
  return "The receipt signature doesn't match. Don't rely on it.";
}

export function mapReceiptFetchError(msg: string): string {
  if (/release service url in settings|no release service|service is not set/i.test(msg)) {
    return "No release service is set up. Add one in Settings to check receipts.";
  }
  if (/different service key|receipt signature invalid|trusted comment|different release|different package/i.test(msg)) {
    return "This receipt doesn't match the service key saved when you sealed the package. Don't rely on it.";
  }
  if (/deposit token in settings/i.test(msg)) return "The release service needs a deposit token. Add it in Settings.";
  if (/manifest not found|signature not found/i.test(msg)) return SIDECAR_MISSING;
  if (/expected a file named|no timed release/i.test(msg)) return g1(msg);
  if (/release service|connect|dns|timed out|network|unexpected status|receipt fetch failed|io: /i.test(msg)) {
    return "Couldn't reach the release service. The row keeps its last result from this session.";
  }
  return g1(msg);
}
