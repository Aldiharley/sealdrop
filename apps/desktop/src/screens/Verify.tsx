import { useEffect, useState } from "react";
import { api, errText } from "../lib/api";
import { useApp } from "../lib/app";
import { baseName, formatDate, hostOf, looksLikeSignerKey, plural, recipientsText, shortHash, windowText } from "../lib/format";
import { NOT_A_PACKAGE, mapReceiptVerifyError, mapVerifyError } from "../lib/errors";
import type { VerifyFailure } from "../lib/errors";
import { mockQuery, useOnceWhen } from "../lib/hooks";
import type { ReceiptOut, VerifyOut } from "../lib/types";
import { Badge } from "../components/Chip";
import { CopyButton } from "../components/CopyButton";
import { DropZone } from "../components/DropZone";
import { Field } from "../components/Field";
import { KV, StatusRow } from "../components/Notice";
import { FirstRunBanner, PageHead } from "../components/PageHead";
import { Progress } from "../components/Progress";
import { LinkButton, SoftButton } from "../components/SoftButton";
import { Tile } from "../components/Tile";
import { TrustForm } from "../components/TrustForm";
import { Notice } from "../components/Notice";

type Outcome =
  | { kind: "ok"; v: VerifyOut }
  | { kind: "untrusted"; key: string }
  | { kind: "failed"; failure: VerifyFailure };

const TIMED_SENTENCE = "Expiry applies to the encrypted package only; nothing can recall a file after it has been decrypted.";

export default function Verify({ active }: { active: boolean }) {
  const { go, announce } = useApp();
  const [pkg, setPkg] = useState<{ path: string; name: string } | null>(null);
  const [pkgError, setPkgError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  const [altKey, setAltKey] = useState("");
  const [altError, setAltError] = useState<string | null>(null);
  const [trustedNote, setTrustedNote] = useState<string | null>(null);
  const [existing, setExisting] = useState<string[]>([]);

  // receipt
  const [rcpt, setRcpt] = useState<{ path: string; name: string } | null>(null);
  const [rcptKey, setRcptKey] = useState("");
  const [rcptBusy, setRcptBusy] = useState(false);
  const [rcptOut, setRcptOut] = useState<ReceiptOut | null>(null);
  const [rcptError, setRcptError] = useState<string | null>(null);

  async function run(path: string, signer?: string | null) {
    setChecking(true);
    setAltError(null);
    try {
      const v = await api.verify(path, signer);
      if (v.ok) {
        setOutcome({ kind: "ok", v });
        announce("Signature valid.");
      } else if (v.untrusted_signer) {
        setOutcome({ kind: "untrusted", key: v.untrusted_signer });
        announce("Signer not trusted.");
      } else {
        setOutcome({ kind: "failed", failure: { kind: "other", text: "Verification failed." } });
        announce("Verification failed.");
      }
    } catch (e) {
      const failure = mapVerifyError(errText(e));
      if (signer && failure.kind === "signer-mismatch") {
        setAltError(failure.text);
        // keep the previous outcome (untrusted) so the user can try another key
      } else {
        setOutcome({ kind: "failed", failure });
        announce("Verification failed.");
      }
    } finally {
      setChecking(false);
    }
  }

  async function choosePackage(path: string) {
    if (!path.toLowerCase().endsWith(".sealdrop.age")) {
      setPkgError(NOT_A_PACKAGE);
      return;
    }
    setPkgError(null);
    setPkg({ path, name: baseName(path) });
    setOutcome(null);
    setAltKey("");
    setTrustedNote(null);
    await run(path);
    api.listTrusted().then((t) => setExisting(t.map((x) => x.name))).catch(() => {});
  }

  async function pickPackage() {
    const p = await api.pickFile({ kind: "package", extensions: ["age"], title: "Choose a package" });
    if (p) await choosePackage(p);
  }

  async function checkReceipt(path: string, key: string) {
    setRcptBusy(true);
    setRcptError(null);
    try {
      const r = await api.receiptVerify(path, key.trim() || null);
      setRcptOut(r);
    } catch (e) {
      setRcptOut(null);
      setRcptError(mapReceiptVerifyError(errText(e)));
    } finally {
      setRcptBusy(false);
    }
  }

  async function pickReceipt() {
    const p = await api.pickFile({ kind: "receipt", extensions: ["json"], title: "Choose a receipt" });
    if (p) await chooseReceipt(p);
  }

  async function chooseReceipt(path: string) {
    setRcpt({ path, name: baseName(path) });
    await checkReceipt(path, rcptKey);
  }

  // Leaving the screen drops nothing secret (a signer key and hashes are public), but clear transient notes.
  useEffect(() => {
    if (!active) setTrustedNote(null);
  }, [active]);

  useOnceWhen(active && api.isMock && mockQuery().get("state") === "success", () => {
    void choosePackage("C:/Users/me/Documents/sealed/q3-findings.sealdrop.age");
    void chooseReceipt("C:/Users/me/Documents/sealed/report-q3.receipt.json");
  });

  const busy = checking;

  return (
    <>
      <PageHead title="Verify" subtitle="Check a package without opening it." />
      <span className="sr-only" aria-live="polite">
        {checking ? "Checking the signature and hash…" : ""}
      </span>
      <FirstRunBanner />
      <div className="cols-12">
        <div className="span-7 stack">
          <Tile title="Package">
            <DropZone
              label="Package to verify"
              headline="Drop a .sealdrop.age package here"
              helper="Keep the .manifest.json and .minisig files in the same folder."
              enabled={active && !busy}
              loaded={pkg ? { name: pkg.name, path: pkg.path } : null}
              error={pkgError}
              onPaths={(paths) => (paths.length === 1 ? void choosePackage(paths[0]) : setPkgError("Drop one file at a time."))}
              buttons={[{ label: "Choose package…", onClick: pickPackage }]}
            />
          </Tile>

          <Tile title="Result">
            <ResultBody pkg={pkg} checking={checking} outcome={outcome} />
          </Tile>
        </div>

        <div className="span-5 stack">
          <Tile title="Signer">
            <div className="stack">
              {outcome?.kind === "untrusted" ? (
                <>
                  <div>
                    <Badge tone="warn">Signer not trusted</Badge>
                  </div>
                  <Field label="Signer key" as="textarea" readOnly mono value={outcome.key} helper="Check this key with the sender by another route before you trust it." />
                  <TrustForm
                    buttonLabel="Trust this signer"
                    signerKey={outcome.key}
                    existing={existing}
                    onTrusted={(n) => {
                      setTrustedNote(`${n} is now trusted.`);
                      if (pkg) void run(pkg.path);
                    }}
                  />
                  <Field
                    label="Or check against a key you were given"
                    value={altKey}
                    onChange={(v) => {
                      setAltKey(v);
                      setAltError(null);
                    }}
                    placeholder="Paste a signer key (starts with RW)"
                    mono
                    error={altError}
                    onEnter={() => document.getElementById("verify-alt-check")?.click()}
                    action={
                      <SoftButton
                        id="verify-alt-check"
                        loading={checking}
                        busyLabel="Checking…"
                        onClick={() => {
                          if (!looksLikeSignerKey(altKey)) {
                            setAltError("That isn't a valid signer key.");
                            return;
                          }
                          if (pkg) void run(pkg.path, altKey.trim());
                        }}
                      >
                        Check
                      </SoftButton>
                    }
                  />
                </>
              ) : outcome?.kind === "ok" ? (
                <>
                  {outcome.v.trusted_as ? (
                    <div>
                      <div style={{ fontWeight: 700 }}>{outcome.v.trusted_as === "self" ? "You" : `${outcome.v.trusted_as} (trusted)`}</div>
                      {trustedNote ? <div style={{ marginTop: 4 }}>{trustedNote}</div> : null}
                    </div>
                  ) : (
                    <div style={{ fontWeight: 700 }}>Signed by the key you entered</div>
                  )}
                  <div className="mono">{outcome.v.signer}</div>
                  {outcome.v.trusted_as && outcome.v.trusted_as !== "self" ? (
                    <div>
                      <LinkButton onClick={() => go("keys")}>Manage in Keys</LinkButton>
                    </div>
                  ) : null}
                </>
              ) : (
                <p className="muted" style={{ margin: 0 }}>
                  {outcome?.kind === "failed" ? "No signer to trust: this package did not pass verification." : "The signer of the package you choose appears here."}
                </p>
              )}
            </div>
          </Tile>

          <Tile title="Check a receipt">
            <div className="stack">
              <DropZone
                small
                label="Receipt to check"
                headline="Drop a .receipt.json here"
                enabled={active && !rcptBusy}
                loaded={rcpt ? { name: rcpt.name, path: rcpt.path } : null}
                onPaths={(paths) => (paths.length === 1 ? void chooseReceipt(paths[0]) : setRcptError("Drop one file at a time."))}
                buttons={[{ label: "Choose receipt…", onClick: pickReceipt }]}
              />
              <Field
                label="Service key (optional)"
                value={rcptKey}
                onChange={(v) => setRcptKey(v)}
                onBlur={() => {
                  if (rcpt) void checkReceipt(rcpt.path, rcptKey);
                }}
                onEnter={() => {
                  if (rcpt) void checkReceipt(rcpt.path, rcptKey);
                }}
                placeholder="Paste the service key from the manifest"
                mono
                helper={rcptKey.trim() === "" ? "Enter the service key from the sealed manifest to pin it." : undefined}
              />
              {rcptBusy ? <Progress label="Checking the receipt" /> : null}
              {rcptError ? <Notice tone="err">{rcptError}</Notice> : null}
              {rcptOut && !rcptBusy ? <ReceiptResult r={rcptOut} /> : null}
            </div>
          </Tile>
        </div>
      </div>
    </>
  );
}

function ResultBody({ pkg, checking, outcome }: { pkg: { path: string; name: string } | null; checking: boolean; outcome: Outcome | null }) {
  if (!pkg) return <p style={{ margin: 0 }}>Choose a package to check it. Nothing is decrypted.</p>;
  if (checking) {
    return (
      <div className="stack">
        <Progress label="Checking the signature and hash" />
        <span>Checking the signature and hash…</span>
      </div>
    );
  }
  if (!outcome) return null;
  if (outcome.kind === "failed") {
    const f = outcome.failure;
    return (
      <div className="stack">
        <div>
          <Badge tone="err">Verification failed</Badge>
        </div>
        {f.kind === "hash" ? <StatusRow tone="ok">Manifest signature matches the signer key.</StatusRow> : null}
        <StatusRow tone="err">{f.text}</StatusRow>
      </div>
    );
  }
  if (outcome.kind === "untrusted") {
    return (
      <div className="stack">
        <div>
          <Badge tone="warn">Signer not trusted</Badge>
        </div>
        <StatusRow tone="warn">Signer is not in your trusted list.</StatusRow>
        <p style={{ margin: 0 }}>
          The signature and the package hash are checked once you trust this signer or check against its key.
        </p>
      </div>
    );
  }
  const v = outcome.v;
  const timed = v.release !== null;
  return (
    <div className="stack">
      <div>
        <Badge tone="ok">Signature valid</Badge>
      </div>
      <StatusRow tone="ok">Manifest signature matches the signer key.</StatusRow>
      <StatusRow tone="ok">Ciphertext hash matches the manifest.</StatusRow>
      {v.trusted_as === "self" ? (
        <StatusRow tone="ok">Signer is your own key.</StatusRow>
      ) : v.trusted_as ? (
        <StatusRow tone="ok">Signer is in your trusted list ({v.trusted_as}).</StatusRow>
      ) : null}
      <p style={{ margin: 0 }}>This confirms which key signed the package and that it hasn't changed. It doesn't show what is inside.</p>
      <div className="stack stack--sm">
        <KV k="Package id" mono>
          {v.package_id}
        </KV>
        <KV k="Sealed">{formatDate(v.created)}</KV>
        <KV k="Classification">{v.classification || "None"}</KV>
        {v.expires ? <KV k="Advisory date">{v.expires} (not enforced)</KV> : <KV k="Advisory date">None</KV>}
        <KV k="Recipients">{recipientsText(v.recipients, timed)}</KV>
        {v.ciphertext_sha256 ? (
          <KV k="SHA-256">
            <span className="cluster" style={{ gap: 12 }}>
              <span className="mono" title={v.ciphertext_sha256}>
                {shortHash(v.ciphertext_sha256)}
              </span>
              <CopyButton text={v.ciphertext_sha256} ariaLabel="Copy SHA-256" />
            </span>
          </KV>
        ) : null}
        {v.release ? (
          <KV k="Timed release">
            {windowText(v.release.window_secs)} after first open · {hostOf(v.release.service)}
          </KV>
        ) : null}
      </div>
      {v.release ? <p style={{ margin: 0 }}>{TIMED_SENTENCE}</p> : null}
    </div>
  );
}

function ReceiptResult({ r }: { r: ReceiptOut }) {
  const times = (
    <>
      opened {r.unlock_count} {plural(r.unlock_count, "time")}.
    </>
  );
  return (
    <div className="stack stack--sm" role="status">
      <div>{r.pinned ? <Badge tone="ok">Receipt verified</Badge> : <Badge tone="warn">Signature valid — service key not checked</Badge>}</div>
      <p style={{ margin: 0 }}>
        {r.first_unlock === null ? (
          "The package has not been opened yet."
        ) : (
          <>
            {r.pinned ? "Receipt verified. " : "Signature valid — service key not checked. "}First opened {formatDate(r.first_unlock)}, window ends{" "}
            {formatDate(r.expires_at)}, {times}
          </>
        )}
      </p>
    </div>
  );
}
