import { useEffect, useRef, useState } from "react";
import { api, errText } from "../lib/api";
import { useApp } from "../lib/app";
import { baseName, formatBytes, formatDate, hostOf, looksLikeSignerKey, parentDir, plural, recipientsText, shortSigner, windowText } from "../lib/format";
import { G5, NOT_A_PACKAGE, VERIFY_FAILED, mapOpenError, mapReceiptFetchError, mapVerifyError } from "../lib/errors";
import type { VerifyFailure } from "../lib/errors";
import { useDropTarget } from "../lib/dragdrop";
import { mockQuery, useIdleClear, useOnceWhen, useProgress } from "../lib/hooks";
import type { OpenOut, ProbeOut, VerifyOut } from "../lib/types";
import { Badge, Chip } from "../components/Chip";
import { Countdown } from "../components/Countdown";
import { CopyButton } from "../components/CopyButton";
import { DropZone } from "../components/DropZone";
import { Field } from "../components/Field";
import { GlyphChevron, GlyphOk, GlyphWarn } from "../components/icons";
import { KV, Notice, StatusRow } from "../components/Notice";
import { FirstRunBanner, PageHead } from "../components/PageHead";
import { Progress } from "../components/Progress";
import { LinkButton, SoftButton } from "../components/SoftButton";
import { Tile } from "../components/Tile";
import { Toggle } from "../components/Toggle";
import { TrustForm } from "../components/TrustForm";

type Outcome =
  | { kind: "ok"; v: VerifyOut }
  | { kind: "untrusted"; key: string }
  | { kind: "failed"; failure: VerifyFailure };

const TIMED_SENTENCE = "Expiry applies to the encrypted package only; nothing can recall a file after it has been decrypted.";
const WRONG_PASS = "That passphrase didn't open the package. Check it and try again.";

interface Opened {
  out: OpenOut;
  timed: boolean;
  temp: boolean;
  host: string;
  windowSecs: number | null;
  /** Bumped for each fresh service-clock sample (the countdown restarts from it). */
  sample: number;
}

export default function Open({ active }: { active: boolean }) {
  const { identity, go, announce } = useApp();

  const [pkg, setPkg] = useState<{ path: string; name: string } | null>(null);
  const [pkgError, setPkgError] = useState<string | null>(null);
  const [probe, setProbe] = useState<ProbeOut | null>(null);
  const [checking, setChecking] = useState(false);
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  const [expected, setExpected] = useState("");
  const [signerErr, setSignerErr] = useState<string | null>(null);
  /** The expected-signer value the current delivery record was verified with. */
  const checkedKey = useRef("");
  const [showTrust, setShowTrust] = useState(false);
  const [existing, setExisting] = useState<string[]>([]);
  const [moreOpen, setMoreOpen] = useState(false);
  const [overwrite, setOverwrite] = useState(false);
  const [skipVerify, setSkipVerify] = useState(false);

  const [passphrase, setPassphrase] = useState("");
  const [passKey, setPassKey] = useState(0);
  const [folder, setFolder] = useState<string | null>(null);

  const [working, setWorking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [opened, setOpened] = useState<Opened | null>(null);
  const [expired, setExpired] = useState(false);
  const [clockBusy, setClockBusy] = useState(false);
  const [clockError, setClockError] = useState<string | null>(null);

  // "Save to…" after a temporary open
  const [saveOpen, setSaveOpen] = useState(false);
  const [savePass, setSavePass] = useState("");
  const [saveBusy, setSaveBusy] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  const phase = useProgress(working || saveBusy);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const tileRef = useRef<HTMLDivElement>(null);
  const reqSeq = useRef(0);

  const timed = probe?.timed_release != null;
  const needsPass = probe?.needs_passphrase ?? false;
  const hostName = hostOf(probe?.timed_release?.service) || (outcome?.kind === "ok" ? hostOf(outcome.v.release?.service) : "");

  function clearSecrets() {
    setPassphrase("");
    setSavePass("");
  }

  // Leaving the screen clears typed secrets.
  useEffect(() => {
    if (!active) clearSecrets();
  }, [active]);
  useIdleClear(passphrase !== "" || savePass !== "", clearSecrets);

  async function verifyNow(path: string, signer: string | null, seq: number) {
    try {
      const v = await api.verify(path, signer);
      if (seq !== reqSeq.current) return;
      setSignerErr(null);
      checkedKey.current = signer ?? "";
      if (v.ok) setOutcome({ kind: "ok", v });
      else if (v.untrusted_signer) setOutcome({ kind: "untrusted", key: v.untrusted_signer });
      else setOutcome({ kind: "failed", failure: { kind: "other", text: VERIFY_FAILED } });
    } catch (e) {
      if (seq !== reqSeq.current) return;
      const failure = mapVerifyError(errText(e));
      if (signer && failure.kind === "signer-mismatch") {
        // A mistyped expected key is a problem with that field, not with the package: keep the
        // previous delivery record (and the Trust form if the signer is still unknown).
        setSignerErr(failure.text);
      } else {
        setOutcome({ kind: "failed", failure });
      }
    }
  }

  async function choosePackage(path: string) {
    if (!path.toLowerCase().endsWith(".sealdrop.age")) {
      setPkgError(NOT_A_PACKAGE);
      return;
    }
    const seq = ++reqSeq.current;
    setPkgError(null);
    setPkg({ path, name: baseName(path) });
    setProbe(null);
    setOutcome(null);
    setExpected("");
    setSignerErr(null);
    checkedKey.current = "";
    setShowTrust(false);
    setMoreOpen(false);
    setOverwrite(false);
    setSkipVerify(false);
    clearSecrets();
    setFolder(null);
    setError(null);
    setOpened(null);
    setExpired(false);
    setSaveOpen(false);
    setChecking(true);
    api.listTrusted().then((t) => setExisting(t.map((x) => x.name))).catch(() => {});
    let p: ProbeOut | null = null;
    try {
      p = await api.probe(path);
      if (seq !== reqSeq.current) return;
      setProbe(p);
    } catch (e) {
      if (seq !== reqSeq.current) return;
      const m = errText(e);
      setPkg(null);
      setPkgError(/cannot read|os error|no such file|not found|denied/i.test(m) ? G5 : NOT_A_PACKAGE);
      setChecking(false);
      return;
    }
    await verifyNow(path, null, seq);
    if (seq === reqSeq.current) setChecking(false);
    return p;
  }

  async function pickPackage() {
    const p = await api.pickFile({ kind: "package", extensions: ["age"], title: "Choose a package" });
    if (p) await choosePackage(p);
  }

  async function recheck() {
    if (!pkg) return;
    const key = expected.trim();
    if (key !== "" && !looksLikeSignerKey(key)) {
      setSignerErr("That isn't a valid signer key.");
      return;
    }
    const seq = ++reqSeq.current;
    setChecking(true);
    setError(null);
    await verifyNow(pkg.path, key || null, seq);
    if (seq === reqSeq.current) setChecking(false);
  }

  async function pickFolder() {
    const f = await api.pickFolder("Choose a folder to restore into", "output");
    if (f) setFolder(f);
  }

  // ----- gating -----
  const keyPkgNoIdentity = probe !== null && !needsPass && identity !== null && !identity.exists;
  let reason: string | null = null;
  if (!pkg || probe === null) reason = checking && pkg ? `Checking ${pkg.name}…` : "Choose a package first.";
  else if (checking) reason = `Checking ${pkg.name}…`;
  else if (keyPkgNoIdentity) reason = "Create your identity in Keys first.";
  else if (needsPass && passphrase === "") reason = "Enter the passphrase.";
  else if (!skipVerify && signerErr) reason = signerErr;
  else if (!skipVerify && outcome?.kind === "untrusted") reason = "Trust the signer or enter their key first.";
  else if (!skipVerify && outcome?.kind === "failed") {
    reason = outcome.failure.kind === "signature" || outcome.failure.kind === "hash" ? VERIFY_FAILED : outcome.failure.text;
  }

  async function perform(a: {
    path: string;
    timed: boolean;
    host: string;
    windowSecs: number | null;
    passphrase: string | null;
    folder: string | null;
    signer: string | null;
    skip: boolean;
    overwrite: boolean;
    needsPass: boolean;
  }) {
    setWorking(true);
    setError(null);
    const useTemp = a.timed && a.folder === null;
    try {
      const out = await api.openPackage({
        package: a.path,
        out_dir: useTemp ? null : (a.folder ?? parentDir(a.path)),
        temp: useTemp,
        passphrase: a.needsPass ? a.passphrase : null,
        signer: a.signer,
        skip_verify: a.skip,
        overwrite: a.overwrite,
      });
      clearSecrets();
      setOpened({ out, timed: a.timed, temp: useTemp, host: a.host, windowSecs: a.windowSecs, sample: 1 });
      setExpired(out.remaining_secs !== null && out.remaining_secs <= 0 && a.timed);
      announce(`Opened. ${out.files} ${plural(out.files, "file")} restored.`);
      window.setTimeout(() => headingRef.current?.focus(), 60);
    } catch (e) {
      const text = mapOpenError(errText(e), a.host, a.needsPass);
      setError(text);
      if (text === WRONG_PASS) setPassKey((k) => k + 1); // masks the field again, keeps its text
    } finally {
      setWorking(false);
    }
  }

  function onOpenClick() {
    if (reason || !pkg || working) return;
    void perform({
      path: pkg.path,
      timed,
      host: hostName,
      windowSecs: outcome?.kind === "ok" ? (outcome.v.release?.window_secs ?? null) : null,
      passphrase: needsPass ? passphrase : null,
      folder,
      signer: expected.trim() || null,
      skip: skipVerify,
      overwrite,
      needsPass,
    });
  }

  async function saveTo() {
    if (!pkg || !opened) return;
    if (needsPass && !saveOpen) {
      setSaveOpen(true);
      return;
    }
    if (needsPass && savePass === "") {
      setSaveError("Enter the passphrase.");
      return;
    }
    const f = await api.pickFolder("Save the restored files to", "output");
    if (!f) return;
    setSaveBusy(true);
    setSaveError(null);
    try {
      const out = await api.openPackage({
        package: pkg.path,
        out_dir: f,
        temp: false,
        passphrase: needsPass ? savePass : null,
        signer: expected.trim() || null,
        skip_verify: skipVerify,
        overwrite,
      });
      setSavePass("");
      setSaveOpen(false);
      setOpened({ ...opened, out, temp: false, sample: opened.sample + 1 });
      announce(`Saved to ${baseName(f)}.`);
    } catch (e) {
      setSaveError(mapOpenError(errText(e), opened.host, needsPass));
    } finally {
      setSaveBusy(false);
    }
  }

  /**
   * Fresh service-clock sample after the countdown went stale (sleep/wake). Uses receipt_fetch on the
   * package's manifest, which also writes <name>.receipt.json next to the manifest.
   */
  async function checkAgain() {
    if (!pkg || !opened) return;
    setClockBusy(true);
    setClockError(null);
    try {
      const manifest = pkg.path.replace(/\.sealdrop\.age$/i, ".manifest.json");
      const r = await api.receiptFetch(manifest);
      setOpened((o) =>
        o
          ? {
              ...o,
              out: { ...o.out, remaining_secs: r.remaining_secs, first_unlock: r.first_unlock ?? o.out.first_unlock, expires_at: r.expires_at ?? o.out.expires_at },
              sample: o.sample + 1,
            }
          : o,
      );
      setExpired(r.remaining_secs !== null && r.remaining_secs <= 0);
    } catch (e) {
      setClockError(mapReceiptFetchError(errText(e)));
    } finally {
      setClockBusy(false);
    }
  }

  function reset() {
    setClockError(null);
    reqSeq.current++;
    setPkg(null);
    setPkgError(null);
    setProbe(null);
    setOutcome(null);
    setExpected("");
    setSignerErr(null);
    checkedKey.current = "";
    setShowTrust(false);
    setOpened(null);
    setExpired(false);
    setError(null);
    setFolder(null);
    setSaveOpen(false);
    setSaveError(null);
    setSkipVerify(false);
    setOverwrite(false);
    setMoreOpen(false);
    clearSecrets();
  }

  const dropped = useDropTarget(
    tileRef,
    (paths) => (paths.length === 1 ? void choosePackage(paths[0]) : setPkgError("Drop one file at a time.")),
    active && !working && !opened && pkg !== null,
  );

  // Mock deep link: ?screen=open&state=success runs a whole open.
  useOnceWhen(active && api.isMock && mockQuery().get("state") === "success", () => {
    void (async () => {
      const path = "C:/Users/me/Documents/sealed/q3-findings-timed.sealdrop.age";
      await choosePackage(path);
      await perform({
        path,
        timed: true,
        host: "release.example.org",
        windowSecs: 600,
        passphrase: null,
        folder: null,
        signer: null,
        skip: false,
        overwrite: false,
        needsPass: false,
      });
    })();
  });

  // ----- phase text -----
  const phaseText =
    phase?.kind === "contacting"
      ? `Contacting ${hostOf(phase.detail) || hostName || "the release service"}…`
      : phase?.kind === "extracting"
        ? "Decrypting and restoring…"
        : phase?.kind === "verifying"
          ? "Verifying…"
          : "";
  const buttonBusy = phase?.kind === "contacting" ? `Contacting ${hostOf(phase.detail) || hostName}…` : "Opening…";

  const destValue = timed ? (folder ?? "Temporary folder") : (folder ?? (pkg ? parentDir(pkg.path) : ""));

  // Always rendered while this layout is shown, so the first announcement is not skipped.
  const liveRegion = (
    <span className="sr-only" aria-live="polite">
      {working || saveBusy ? phaseText : checking && pkg ? `Checking ${pkg.name}…` : ""}
    </span>
  );

  // ============ success layout ============
  if (opened) {
    const o = opened.out;
    const rootDir = o.root;
    return (
      <>
        <PageHead title="Open" subtitle="Check, unlock and restore a package." />
        {liveRegion}
        <FirstRunBanner />
        <div className="cols-12">
          <div className="span-7 stack">
            <Tile title="Opened">
              <div className="stack">
                <div className="row" style={{ alignItems: "flex-start" }}>
                  <GlyphOk />
                  <h3 ref={headingRef} tabIndex={-1} className="lead">
                    Opened.
                  </h3>
                </div>
                <div>
                  {o.files} {plural(o.files, "file")} restored to <span className="mono">{rootDir}</span>.
                </div>
                {o.verified ? (
                  <StatusRow tone="ok">Contents match the signed record.</StatusRow>
                ) : (
                  <div>
                    <Badge tone="warn">Signature NOT verified — you chose to skip verification.</Badge>
                  </div>
                )}
                <div className="cluster" style={{ gap: 12 }}>
                  <CopyButton text={rootDir} label="Copy folder path" />
                  {opened.temp ? (
                    <SoftButton size="sm" loading={saveBusy} busyLabel="Saving…" onClick={saveTo}>
                      Save to…
                    </SoftButton>
                  ) : null}
                  <SoftButton size="sm" onClick={reset}>
                    Open another package
                  </SoftButton>
                </div>
                {opened.temp && opened.timed ? <div className="field__helper">Saving to a folder unlocks the package a second time, inside the window.</div> : null}
                {opened.temp ? (
                  <p className="field__helper" style={{ margin: 0 }}>
                    Saved to a temporary folder. It is removed when you close sealdrop (best effort; copies you made elsewhere are not touched).
                  </p>
                ) : null}
                {saveOpen && opened.temp ? (
                  <div className="stack">
                    <Field
                      key={`sp-${passKey}`}
                      label="Passphrase"
                      type="password"
                      value={savePass}
                      onChange={(v) => {
                        setSavePass(v);
                        setSaveError(null);
                      }}
                      placeholder="Type or paste the passphrase"
                      helper="Kept only until the package is opened."
                      disabled={saveBusy}
                      onEnter={saveTo}
                    />
                    <div>
                      <SoftButton variant="primary" loading={saveBusy} busyLabel="Saving…" onClick={saveTo}>
                        Choose folder and save
                      </SoftButton>
                    </div>
                  </div>
                ) : null}
                {saveBusy && phaseText ? <span>{phaseText}</span> : null}
                {saveError ? <Notice tone="err">{saveError}</Notice> : null}
              </div>
            </Tile>
            <Tile title="Files">
              <div>
                {o.files} {plural(o.files, "file")} · {formatBytes(o.bytes)}
              </div>
              {o.trusted_as || o.signer ? (
                <div className="field__helper" style={{ marginTop: 8 }}>
                  {o.verified ? <>Signed by {o.trusted_as === "self" ? "you" : o.trusted_as ? `${o.trusted_as} (trusted)` : "the key you entered"}.</> : null}
                </div>
              ) : null}
            </Tile>
          </div>
          {opened.timed ? (
            <div className="span-5 stack">
              <Tile title="Timed package">
                <div className="stack">
                  {o.remaining_secs !== null ? (
                    <div>
                      <Countdown
                        remainingSecs={o.remaining_secs}
                        windowSecs={opened.windowSecs}
                        sampleKey={opened.sample}
                        announce
                        onExpire={() => setExpired(true)}
                        onCheckAgain={() => void checkAgain()}
                        checkingAgain={clockBusy}
                      />
                    </div>
                  ) : null}
                  {clockError ? <Notice tone="err">{clockError}</Notice> : null}
                  {o.first_unlock ? <div>First opened {formatDate(o.first_unlock)} (service clock)</div> : null}
                  <p style={{ margin: 0 }}>{TIMED_SENTENCE}</p>
                  <p style={{ margin: 0 }}>Files you have already restored are not removed when the timer ends.</p>
                  {expired ? <p style={{ margin: 0, fontWeight: 700 }}>The window has ended. The package can't be opened again.</p> : null}
                </div>
              </Tile>
            </div>
          ) : null}
        </div>
      </>
    );
  }

  // ============ idle / loaded layout ============
  if (!pkg) {
    return (
      <>
        <PageHead title="Open" subtitle="Check, unlock and restore a package." />
        {liveRegion}
        <FirstRunBanner />
        <div className="cols-12">
          <div className="span-7">
            <Tile title="Package">
              <DropZone
                label="Package to open"
                headline="Drop a .sealdrop.age package here"
                helper="Keep the .manifest.json and .minisig files in the same folder."
                enabled={active}
                error={pkgError}
                onPaths={(paths) => (paths.length === 1 ? void choosePackage(paths[0]) : setPkgError("Drop one file at a time."))}
                buttons={[{ label: "Choose package…", onClick: pickPackage }]}
              />
            </Tile>
          </div>
        </div>
      </>
    );
  }

  const v = outcome?.kind === "ok" ? outcome.v : null;
  const kinds = v?.recipients ?? [];
  const passKind = kinds.find((r) => r.kind === "argon2id" || r.kind === "scrypt")?.kind;
  const opensWith = needsPass
    ? passKind === "argon2id"
      ? "a passphrase (Argon2id)"
      : "a passphrase"
    : timed
      ? "your identity key, after the release service allows it (timed)"
      : "your identity key";
  const busyWork = working;

  return (
    <>
      <PageHead title="Open" subtitle="Check, unlock and restore a package." />
      {liveRegion}
      <FirstRunBanner />
      <div className="cols-12">
        <div className="span-7 stack">
          <div ref={tileRef} data-drop-over={dropped ? "true" : undefined}>
            <Tile title="Package">
              <div className="stack">
                <div>
                  <div style={{ fontWeight: 700, overflowWrap: "anywhere" }}>{pkg.name}</div>
                  <div className="muted">{v?.created ? `sealed ${formatDate(v.created)}` : checking ? `Checking ${pkg.name}…` : ""}</div>
                </div>
                <div className="cluster">
                  {v?.classification ? <Chip tone="cream">{v.classification}</Chip> : null}
                  {timed ? <Chip tone="blue">Timed release</Chip> : null}
                  {needsPass ? <Chip tone="sage">{passKind === "argon2id" ? "Passphrase (Argon2id)" : "Passphrase"}</Chip> : null}
                </div>
                <div>
                  <LinkButton onClick={pickPackage}>Choose another package…</LinkButton>
                </div>
                <div className="field__helper">{dropped ? "Release to add" : "Or drop a .sealdrop.age file anywhere on this tile."}</div>
                {pkgError ? <div className="field__error" role="alert">{pkgError}</div> : null}
              </div>
            </Tile>
          </div>

          <Tile title="Delivery record">
            <div className="stack">
              {checking ? (
                <div className="stack stack--sm">
                  <Progress label="Checking the package" />
                  <span>Checking {pkg.name}…</span>
                </div>
              ) : null}
              {!checking && outcome?.kind === "ok" ? (
                <>
                  <StatusRow tone="ok">
                    {v!.trusted_as === "self" ? (
                      <>Signature valid. Signed by you.</>
                    ) : v!.trusted_as ? (
                      <>Signature valid. Signed by {v!.trusted_as} (trusted).</>
                    ) : (
                      <>Signature valid. Signed by the key you entered.</>
                    )}
                  </StatusRow>
                  <StatusRow tone="ok">Package matches its signed hash.</StatusRow>
                  {v!.expires ? <StatusRow tone="warn">Advisory date {v!.expires}. No software enforces it.</StatusRow> : null}
                </>
              ) : null}
              {!checking && outcome?.kind === "untrusted" ? (
                <>
                  <StatusRow tone="warn">
                    Signer not trusted: {shortSigner(outcome.key)}. Check it with the sender, then trust it to continue.
                  </StatusRow>
                  {!showTrust ? (
                    <div>
                      <SoftButton onClick={() => setShowTrust(true)}>Trust this signer…</SoftButton>
                    </div>
                  ) : (
                    <TrustForm
                      buttonLabel="Trust this signer"
                      signerKey={outcome.key}
                      existing={existing}
                      onTrusted={() => {
                        setShowTrust(false);
                        void recheck();
                      }}
                    />
                  )}
                </>
              ) : null}
              {!checking && outcome?.kind === "failed" ? (
                <StatusRow tone="err">
                  {outcome.failure.kind === "signature" || outcome.failure.kind === "hash" ? VERIFY_FAILED : outcome.failure.text}
                </StatusRow>
              ) : null}

              {v ? (
                <div className="stack stack--sm">
                  <KV k="Package id" mono>
                    {v.package_id}
                  </KV>
                  <KV k="Sealed">{formatDate(v.created)}</KV>
                  <KV k="Recipients">{recipientsText(v.recipients, v.release !== null)}</KV>
                  <KV k="Opens with">{opensWith}</KV>
                </div>
              ) : (
                <div className="stack stack--sm">
                  <KV k="Opens with">{opensWith}</KV>
                </div>
              )}

              <Field
                label="Expected signer (optional)"
                value={expected}
                onChange={(val) => {
                  setExpected(val);
                  setSignerErr(null);
                }}
                error={signerErr}
                onBlur={() => {
                  if (expected.trim() !== checkedKey.current) void recheck();
                }}
                onEnter={() => void recheck()}
                placeholder="Paste a signer key (starts with RWQ)"
                helper="Only needed for a signer you haven't trusted."
                mono
                disabled={busyWork}
                action={
                  <SoftButton size="sm" unavailable={busyWork || checking} onClick={() => void recheck()}>
                    Check
                  </SoftButton>
                }
              />

              <div>
                <button
                  type="button"
                  className="link-btn"
                  aria-expanded={moreOpen}
                  aria-controls="open-more"
                  onClick={() => setMoreOpen((m) => !m)}
                  style={{ display: "inline-flex", alignItems: "center", gap: 8 }}
                >
                  <GlyphChevron open={moreOpen} />
                  More options
                </button>
              </div>
              {moreOpen ? (
                <div id="open-more" className="stack">
                  <Toggle
                    checked={overwrite}
                    onChange={setOverwrite}
                    unavailable={busyWork}
                    label="Replace existing files"
                    helper="Overwrites files with the same names in the folder you choose."
                  />
                  <div className="notice" style={{ alignItems: "flex-start" }}>
                    <GlyphWarn />
                    <div style={{ flex: 1 }}>
                      <Toggle
                        checked={skipVerify}
                        onChange={setSkipVerify}
                        unavailable={busyWork}
                        label="Skip verification"
                        helper={
                          <span style={{ color: "var(--ink)" }}>
                            Not recommended. Decryption still checks the data, but the signer and the delivery record won't be checked.
                          </span>
                        }
                      />
                    </div>
                  </div>
                </div>
              ) : null}
            </div>
          </Tile>
        </div>

        <div className="span-5 stack">
          {timed ? (
            <Tile title="Timed package">
              <div className="stack">
                <p style={{ margin: 0 }}>
                  This package expires {v?.release ? windowText(v.release.window_secs) : "a set time"} after first open (service clock). The window starts
                  the first time anyone opens it.
                </p>
                <p style={{ margin: 0 }}>{TIMED_SENTENCE}</p>
                <p style={{ margin: 0 }}>Opening it contacts {hostOf(probe?.timed_release?.service) || "the release service"}.</p>
              </div>
            </Tile>
          ) : null}

          <Tile title="Unlock">
            {probe === null ? (
              <span className="muted">Checking…</span>
            ) : needsPass ? (
              <Field
                key={`p-${passKey}`}
                label="Passphrase"
                type="password"
                value={passphrase}
                onChange={(val) => {
                  setPassphrase(val);
                  if (error === WRONG_PASS) setError(null);
                }}
                placeholder="Type or paste the passphrase"
                helper="Kept only until the package is opened."
                invalid={error === WRONG_PASS}
                disabled={busyWork}
                onEnter={onOpenClick}
              />
            ) : keyPkgNoIdentity ? (
              <div className="stack">
                <p style={{ margin: 0 }}>This package needs your identity key, and you haven't created one yet. Create one in Keys.</p>
                <div>
                  <SoftButton onClick={() => go("keys", { focusCreate: true })}>Go to Keys</SoftButton>
                </div>
              </div>
            ) : (
              <p style={{ margin: 0 }}>Opens with your identity key. No passphrase needed.</p>
            )}
          </Tile>

          <Tile title="Restore into">
            <div className="stack">
              <Field
                label="Folder"
                value={destValue}
                readOnly
                mono
                helper={timed ? (folder ? undefined : "Removed when you close sealdrop (best effort; copies you made elsewhere are not touched).") : "Next to the package."}
                action={
                  <SoftButton size="sm" unavailable={busyWork} onClick={pickFolder}>
                    {timed ? "Save to…" : "Choose…"}
                  </SoftButton>
                }
              />
              {timed && folder ? (
                <div>
                  <LinkButton onClick={() => setFolder(null)}>Use the temporary folder</LinkButton>
                </div>
              ) : null}
              {working ? (
                <div className="stack stack--sm">
                  <Progress label="Opening" />
                  <span>{phaseText}</span>
                </div>
              ) : null}
              {error ? <Notice tone="err">{error}</Notice> : null}
              <SoftButton
                variant="primary"
                block
                loading={working}
                busyLabel={buttonBusy}
                unavailable={!!reason}
                aria-describedby={reason ? "open-reason" : undefined}
                onClick={onOpenClick}
              >
                {timed ? "Open and start the clock" : "Open"}
              </SoftButton>
              {reason ? (
                <div id="open-reason" className="field__helper">
                  {reason}
                </div>
              ) : null}
            </div>
          </Tile>
        </div>
      </div>
    </>
  );
}
