import { useEffect, useId, useRef, useState } from "react";
import { api, errText } from "../lib/api";
import { useApp } from "../lib/app";
import {
  UNITS,
  baseName,
  formatBytes,
  hostOf,
  isInside,
  parentDir,
  parseIsoDate,
  parseWindow,
  plural,
  recipientTone,
  shortHash,
  shortRecipient,
  windowFromForm,
  windowText,
} from "../lib/format";
import type { WindowUnit } from "../lib/format";
import { mapSealError } from "../lib/errors";
import { mockQuery, useIdleClear, useOnceWhen, useProgress } from "../lib/hooks";
import type { RecipientCheck, SealArgs, SealOut } from "../lib/types";
import { Chip } from "../components/Chip";
import { CopyButton } from "../components/CopyButton";
import { DropZone } from "../components/DropZone";
import { Field } from "../components/Field";
import { GlyphChevron, GlyphOk } from "../components/icons";
import { KV, Notice } from "../components/Notice";
import { FirstRunBanner, PageHead } from "../components/PageHead";
import { Progress } from "../components/Progress";
import { Qr } from "../components/Qr";
import { Seg } from "../components/Seg";
import { LinkButton, SoftButton } from "../components/SoftButton";
import { Tile } from "../components/Tile";
import { Toggle } from "../components/Toggle";

type Mode = "recipients" | "passphrase";
interface Rec {
  raw: string;
  check: RecipientCheck;
}
interface Item {
  path: string;
  name: string;
  kind?: "file" | "folder";
}
interface Sealed {
  out: SealOut;
  mode: Mode;
  includeSelf: boolean;
  argon2id: boolean;
  windowSecs: number | null;
  host: string;
  folder: string;
}

const TIMED_SENTENCE = (w: string) => `The recipient can open this only within ${w} after they first open it. This does not protect the contents once decrypted.`;

export default function Seal({ active }: { active: boolean }) {
  const { identity, settings, refreshSettings, go, announce } = useApp();

  const [item, setItem] = useState<Item | null>(null);
  const [itemError, setItemError] = useState<string | null>(null);
  const [mode, setMode] = useState<Mode>("recipients");

  // recipients
  const [recText, setRecText] = useState("");
  const [recs, setRecs] = useState<Rec[]>([]);
  const [recError, setRecError] = useState<string | null>(null);
  const [includeSelf, setIncludeSelf] = useState(true);
  const [allowUnrec, setAllowUnrec] = useState(false);

  // passphrase
  const [words, setWords] = useState<"eff" | "bip39">("eff");
  const [strength, setStrength] = useState<"default" | "high">("default");

  // timed release
  const [timed, setTimed] = useState(false);
  const [winN, setWinN] = useState("10");
  const [unit, setUnit] = useState<WindowUnit>("minutes");
  const [winTouched, setWinTouched] = useState(false);

  // details / output
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [classification, setClassification] = useState("");
  const [advisory, setAdvisory] = useState("");
  const [dateTouched, setDateTouched] = useState(false);
  const [armor, setArmor] = useState(false);
  const [outDir, setOutDir] = useState<string | null>(null);

  // outcome
  const [working, setWorking] = useState(false);
  const [error, setError] = useState<{ text: string; field?: "path" | "window" | "date" } | null>(null);
  const [sealed, setSealed] = useState<Sealed | null>(null);
  // The generated passphrase lives here only; cleared on Hide, on leaving the screen, on idle and on reset.
  const [pass, setPass] = useState<string | null>(null);
  const [passGone, setPassGone] = useState(false);

  const strengthTouched = useRef(false);
  const armorTouched = useRef(false);
  const recInput = useRef<HTMLInputElement & HTMLTextAreaElement & HTMLSelectElement>(null);
  const sealedHeading = useRef<HTMLHeadingElement>(null);
  const passHeading = useRef<HTMLHeadingElement>(null);
  const removeFocus = useRef<number | null>(null);
  const winId = useId();

  const phase = useProgress(working);

  // Initialise toggles from Settings, and re-sync on return unless the user changed them here.
  useEffect(() => {
    if (!active) return;
    let live = true;
    refreshSettings().then((s) => {
      if (!live || !s) return;
      if (!armorTouched.current) setArmor(s.armor);
      if (!strengthTouched.current) setStrength(s.scrypt_log_n === 20 ? "high" : "default");
    });
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active]);

  // Leaving the screen clears the passphrase from memory.
  function hidePassphrase() {
    setPass(null);
    setPassGone(true);
  }
  useEffect(() => {
    if (!active && pass !== null) hidePassphrase();
  }, [active, pass]);
  useIdleClear(pass !== null, hidePassphrase);

  const service = settings?.release_service ?? null;
  const hasToken = settings?.has_token ?? false;
  const timedAvailable = !!service;
  useEffect(() => {
    if (settings && !settings.release_service && timed) setTimed(false);
  }, [settings, timed]);

  const effSelf = mode === "recipients" && includeSelf && !timed;
  const hwOnly = mode === "recipients" && recs.length > 0 && recs.every((r) => r.check.kind.startsWith("plugin:")) && !effSelf;
  const winSecs = parseWindow(winN, unit);
  const winError = timed && winTouched && winSecs === null ? "Enter a whole number of at least 1." : null;

  let dateError: string | null = null;
  if (advisory.trim() !== "") {
    const d = parseIsoDate(advisory.trim());
    if (!d) dateError = "Use the format YYYY-MM-DD.";
    else if (d.getTime() <= Date.now()) dateError = "Choose a date in the future.";
  }
  const dateShown = dateTouched ? dateError : null;

  const effDir = outDir ?? (item ? parentDir(item.path) : "");
  const insideError = item && effDir && isInside(effDir, item.path) ? "The save folder can't be inside the folder you are sealing." : null;

  // First unmet requirement, shown under the button and linked with aria-describedby.
  let reason: string | null = null;
  if (!item) reason = "Choose something to send.";
  else if (mode === "recipients" && recs.length === 0) reason = "Add a recipient or choose a passphrase.";
  else if (identity && !identity.exists) reason = "Create your identity in Keys first.";
  else if (timed && !service) reason = "Set up the release service in Settings first.";
  else if (timed && !hasToken) reason = "The release service needs a deposit token. Add it in Settings.";
  else if (hwOnly && !allowUnrec) reason = "Accept the unrecoverable-package warning or add a second recipient.";
  else if (timed && winSecs === null) reason = "Enter a whole number of at least 1.";
  else if (dateError) reason = dateError;
  else if (insideError) reason = insideError;

  // ---------- items ----------
  async function chooseFile() {
    const p = await api.pickFile({ kind: "file", title: "Choose a file to send" });
    if (p) setPicked({ path: p, name: baseName(p), kind: "file" });
  }
  async function chooseFolder() {
    const p = await api.pickFolder("Choose a folder to send", "input");
    if (p) setPicked({ path: p, name: baseName(p), kind: "folder" });
  }
  function setPicked(i: Item) {
    setItem(i);
    setItemError(null);
    setError(null);
    setOutDir(null);
  }
  function onDropped(paths: string[]) {
    if (paths.length !== 1) {
      setItemError("Seal one item at a time. Put several files in a folder first.");
      return;
    }
    setPicked({ path: paths[0], name: baseName(paths[0]) });
  }

  // ---------- recipients ----------
  async function addRecipients() {
    const tokens = recText.split(/\s+/).filter(Boolean);
    if (tokens.length === 0) return;
    let added = 0;
    let list = recs;
    for (let i = 0; i < tokens.length; i++) {
      const raw = tokens[i];
      if (list.some((r) => r.raw === raw)) {
        setRecError("That recipient is already in the list.");
        setRecText(tokens.slice(i).join("\n"));
        break;
      }
      try {
        const check = await api.parseRecipient(raw);
        if (!check.allowed) {
          setRecError(`Plugin ${check.plugin ?? check.kind.replace(/^plugin:/, "")} is not on the allow-list`);
          setRecText(tokens.slice(i).join("\n"));
          break;
        }
        list = [...list, { raw, check }];
        added++;
        setRecError(null);
        if (i === tokens.length - 1) setRecText("");
      } catch {
        setRecError("Not a recipient string");
        setRecText(tokens.slice(i).join("\n"));
        break;
      }
    }
    if (added > 0) {
      setRecs(list);
      announce("Recipient added.");
    }
    recInput.current?.focus();
  }

  function removeRecipient(i: number) {
    setRecs((r) => r.filter((_, k) => k !== i));
    removeFocus.current = i;
    announce("Recipient removed.");
  }
  useEffect(() => {
    if (removeFocus.current === null) return;
    const idx = removeFocus.current;
    removeFocus.current = null;
    const btns = document.querySelectorAll<HTMLElement>("[data-rm-recipient]");
    (btns[idx] ?? btns[btns.length - 1] ?? recInput.current)?.focus();
  }, [recs]);

  // ---------- seal ----------
  function buildArgs(): SealArgs | null {
    if (!item) return null;
    return {
      input: item.path,
      out_dir: effDir,
      recipients: mode === "recipients" ? recs.map((r) => r.raw) : [],
      passphrase: mode === "passphrase",
      words,
      argon2id: mode === "passphrase" && !!settings?.argon2id,
      kdf_profile: strength,
      armor,
      classification: classification.trim() || null,
      expires: advisory.trim() || null,
      allow_unrecoverable: hwOnly && allowUnrec,
      include_self: effSelf,
      expire_after_secs: timed ? winSecs : null,
    };
  }

  async function run(args: SealArgs, snap: { mode: Mode; includeSelf: boolean; host: string }) {
    setWorking(true);
    setError(null);
    try {
      const out = await api.seal(args);
      const words2 = out.passphrase;
      setPass(words2);
      setPassGone(false);
      setSealed({
        out: { ...out, passphrase: null },
        mode: snap.mode,
        includeSelf: snap.includeSelf,
        argon2id: args.argon2id,
        windowSecs: out.release?.window_secs ?? null,
        host: out.release ? hostOf(out.release.service) : snap.host,
        folder: parentDir(out.package),
      });
      announce(words2 ? "Sealed. Passphrase shown. It is shown once." : "Sealed.");
      window.setTimeout(() => (words2 ? passHeading.current : sealedHeading.current)?.focus(), 60);
    } catch (e) {
      const m = mapSealError(errText(e), recs.map((r) => r.check.plugin).filter((x): x is string => !!x));
      setError(m.field ? { text: m.text, field: m.field } : { text: m.text });
      if (m.field === "path") setItemError(null);
    } finally {
      setWorking(false);
    }
  }

  function onSeal() {
    if (working || reason) return;
    const args = buildArgs();
    if (!args) return;
    void run(args, { mode, includeSelf: effSelf, host: hostOf(service) });
  }

  function reset() {
    setItem(null);
    setItemError(null);
    setMode("recipients");
    setRecText("");
    setRecs([]);
    setRecError(null);
    setIncludeSelf(true);
    setAllowUnrec(false);
    setWords("eff");
    setTimed(false);
    setWinN("10");
    setUnit("minutes");
    setWinTouched(false);
    setDetailsOpen(false);
    setClassification("");
    setAdvisory("");
    setDateTouched(false);
    setOutDir(null);
    setError(null);
    setSealed(null);
    setPass(null);
    setPassGone(false);
    armorTouched.current = false;
    strengthTouched.current = false;
    void refreshSettings().then((s) => {
      if (!s) return;
      setArmor(s.armor);
      setStrength(s.scrypt_log_n === 20 ? "high" : "default");
    });
  }

  // Mock deep link: ?screen=seal&state=success seals a folder with a passphrase and timed release.
  useOnceWhen(active && api.isMock && mockQuery().get("state") === "success", () => {
    const path = "C:/Users/me/Documents/report-q3";
    setItem({ path, name: "report-q3", kind: "folder" });
    setMode("passphrase");
    setTimed(true);
    void run(
      {
        input: path,
        out_dir: "C:/Users/me/Documents",
        recipients: [],
        passphrase: true,
        words: "eff",
        argon2id: false,
        kdf_profile: "default",
        armor: false,
        classification: null,
        expires: null,
        allow_unrecoverable: false,
        include_self: false,
        expire_after_secs: 600,
      },
      { mode: "passphrase", includeSelf: false, host: "release.example.org" },
    );
  });

  async function chooseOutDir() {
    const f = await api.pickFolder("Choose where to save the package", "output");
    if (f) {
      setOutDir(f);
      setError(null);
    }
  }

  const phaseText =
    phase?.kind === "packing"
      ? "Packing and encrypting…"
      : phase?.kind === "encrypted"
        ? "Signing and writing the delivery record…"
        : phase?.kind === "contacting"
          ? "Placing the key with the release service…"
          : "";

  // ============ success layout ============
  if (sealed) {
    const o = sealed.out;
    const pkgName = baseName(o.package);
    const manName = baseName(o.manifest);
    const w = sealed.windowSecs ? windowText(sealed.windowSecs) : "";
    const words2 = pass ? pass.split(/\s+/) : [];
    return (
      <>
        <PageHead title="Seal" subtitle="Lock a file or folder, sign it, and get a delivery record." />
        <FirstRunBanner />
        <div className="cols-12">
          <div className="span-7 stack">
            <Tile title="Sealed">
              <div className="stack">
                <div className="row" style={{ alignItems: "flex-start" }}>
                  <GlyphOk />
                  <h3 ref={sealedHeading} tabIndex={-1} className="lead">
                    Sealed.
                  </h3>
                </div>
                <div>
                  3 files written to <span className="mono">{sealed.folder}</span>.
                </div>
                <div className="stack stack--sm">
                  <KV k="Package">
                    <span className="cluster" style={{ gap: 12 }}>
                      <span className="mono">{pkgName}</span>
                      <CopyButton text={o.package} ariaLabel="Copy package path" />
                    </span>
                  </KV>
                  <KV k="Manifest" mono>
                    {manName}
                  </KV>
                  <KV k="Signature" mono>
                    {manName}.minisig
                  </KV>
                  <KV k="Package id" mono>
                    {o.package_id}
                  </KV>
                  <KV k="SHA-256">
                    <span className="cluster" style={{ gap: 12 }}>
                      <span className="mono" title={o.ciphertext_sha256}>
                        {shortHash(o.ciphertext_sha256)}
                      </span>
                      <CopyButton text={o.ciphertext_sha256} ariaLabel="Copy SHA-256" />
                    </span>
                  </KV>
                  <KV k="Size">
                    {formatBytes(o.bytes)}, {o.files} {plural(o.files, "file")}
                  </KV>
                </div>
                <div className="cluster" style={{ gap: 12 }}>
                  <CopyButton text={sealed.folder} label="Copy folder path" />
                  <SoftButton size="sm" onClick={reset}>
                    Seal another
                  </SoftButton>
                </div>
                <p className="field__helper" style={{ margin: 0 }}>
                  The package, manifest and signature must stay together.
                </p>
              </div>
            </Tile>

            {sealed.mode === "passphrase" ? (
              pass !== null ? (
                <Tile title="Passphrase, shown once" headingRef={passHeading} headingFocusable>
                  <div className="stack">
                    <div style={{ display: "flex", gap: 20, alignItems: "flex-start", flexWrap: "wrap" }}>
                      <div className="neu-inset passphrase" role="group" aria-label="Passphrase" style={{ flex: "1 1 260px", width: "auto" }}>
                        {words2.map((wd, i) => (
                          <span key={i}>
                            <span>{wd}</span>
                            {i < words2.length - 1 ? (
                              <>
                                {" "}
                                <span className="passphrase__sep" aria-hidden="true">
                                  {" · "}
                                </span>
                              </>
                            ) : null}
                          </span>
                        ))}
                      </div>
                      <div className="stack stack--sm" style={{ alignItems: "center" }}>
                        <Qr text={pass} />
                        <span className="field__helper">Scan to read the passphrase.</span>
                      </div>
                    </div>
                    {o.entropy_bits !== null ? <div className="num">{o.entropy_bits.toFixed(1)} bits — send it on a different channel</div> : null}
                    <div className="cluster" style={{ gap: 12 }}>
                      <CopyButton text={pass} secret />
                      <SoftButton size="sm" onClick={hidePassphrase}>
                        Hide
                      </SoftButton>
                    </div>
                    <p className="field__helper" style={{ margin: 0 }}>
                      Shown once and not saved anywhere. Anyone with this passphrase and the package can open it.
                    </p>
                    <p className="field__helper" style={{ margin: 0 }}>
                      Clears when you leave this screen.
                    </p>
                  </div>
                </Tile>
              ) : (
                <Tile title="Passphrase, shown once" headingRef={passHeading} headingFocusable>
                  <p style={{ margin: 0 }}>Passphrase hidden. It can't be shown again. If you haven't shared it, seal the file again.</p>
                </Tile>
              )
            ) : null}
          </div>

          <div className="span-5 stack">
            <Tile title="Sending it">
              {sealed.mode === "passphrase" ? (
                <ol style={{ margin: 0, paddingLeft: 20, display: "grid", gap: 8 }}>
                  <li>Send all three files to your recipient.</li>
                  <li>Give them the passphrase another way, such as a phone call. Don't put both in one message.</li>
                  <li>They open the package in sealdrop (Open).</li>
                </ol>
              ) : (
                <ol style={{ margin: 0, paddingLeft: 20, display: "grid", gap: 8 }}>
                  <li>Send all three files to your recipients.</li>
                  <li>
                    They open the package in sealdrop (Open). Stock age tools can decrypt it too, but they won't check the signed record.
                  </li>
                </ol>
              )}
              {sealed.argon2id ? <p style={{ margin: "12px 0 0" }}>Packages made with Argon2id open only in sealdrop.</p> : null}
              {o.release ? <p style={{ margin: "12px 0 0" }}>Packages with timed release open only in sealdrop.</p> : null}
            </Tile>
            {o.release ? (
              <Tile title="Timed release">
                <div className="stack">
                  <div style={{ fontWeight: 700 }}>Timed release: {w} after first open.</div>
                  <p style={{ margin: 0 }}>{TIMED_SENTENCE(w)}</p>
                  <p style={{ margin: 0 }}>Key placed with {sealed.host}. After it is first opened, check the receipt in Keys with this manifest.</p>
                </div>
              </Tile>
            ) : null}
          </div>
        </div>
      </>
    );
  }

  // ============ form layout ============
  const busy = working;
  const recCount =
    recs.length === 0
      ? "No recipients yet. Add at least one, or choose a passphrase."
      : `${recs.length} ${plural(recs.length, "recipient")}${effSelf ? ", plus you" : ""}.`;
  const timedWindowText = windowFromForm(winN, unit);

  return (
    <>
      <PageHead title="Seal" subtitle="Lock a file or folder, sign it, and get a delivery record." />
      <FirstRunBanner />
      <div className="cols-12">
        <div className="span-7 stack">
          <Tile title="What to send">
            <DropZone
              label="What to send"
              headline="Drop a file or folder here"
              enabled={active && !busy}
              loaded={item}
              error={itemError ?? (error?.field === "path" ? error.text : null)}
              onPaths={onDropped}
              onClear={() => {
                setItem(null);
                setItemError(null);
                setOutDir(null);
              }}
              buttons={[
                { label: "Choose file…", onClick: chooseFile },
                { label: "Choose folder…", onClick: chooseFolder },
              ]}
            />
          </Tile>

          <Tile title="Who can open it">
            <div className="stack">
              <Seg
                label="Delivery method"
                value={mode}
                disabled={busy}
                onChange={(v) => setMode(v)}
                options={[
                  { value: "recipients", label: "To recipients" },
                  { value: "passphrase", label: "With a passphrase" },
                ]}
              />
              {mode === "recipients" ? (
                <>
                  <Field
                    label="Recipients"
                    value={recText}
                    onChange={(v) => {
                      setRecText(v);
                      setRecError(null);
                    }}
                    inputRef={recInput}
                    placeholder="Paste a recipient (age1…, age1pq… or a plugin key)"
                    helper="Each recipient opens the package with their own key."
                    error={recError}
                    disabled={busy}
                    mono
                    onEnter={() => void addRecipients()}
                    action={
                      <SoftButton unavailable={busy} onClick={() => void addRecipients()}>
                        Add
                      </SoftButton>
                    }
                  />
                  {recs.length > 0 ? (
                    <div className="chip-list">
                      {recs.map((r, i) => {
                        const short = shortRecipient(r.raw, r.check.plugin);
                        return (
                          <Chip
                            key={r.raw}
                            tone={recipientTone(r.check.kind)}
                            title={r.raw}
                            removeLabel={`Remove recipient ${short}`}
                            removeDisabled={busy}
                            onRemove={() => removeRecipient(i)}
                          >
                            <span className="mono" style={{ fontSize: 13 }}>
                              {short}
                            </span>
                          </Chip>
                        );
                      })}
                    </div>
                  ) : null}
                  <div className="field__helper" aria-live="polite">
                    {recCount}
                  </div>
                  <Toggle
                    checked={effSelf}
                    unavailable={busy || timed}
                    onChange={setIncludeSelf}
                    label="Also encrypt to me"
                    helper={timed ? "Not added to a timed release package, because it would bypass the release service." : "Keeps a copy you can reopen with your own key."}
                  />
                  {hwOnly ? (
                    <>
                      <Notice tone="warn">Hardware keys can't be backed up. If the key is lost or broken, this package can never be opened.</Notice>
                      <Toggle
                        checked={allowUnrec}
                        unavailable={busy}
                        onChange={setAllowUnrec}
                        label="I accept this package may become unrecoverable"
                        helper="Or add a second recipient that you can recover."
                      />
                    </>
                  ) : null}
                </>
              ) : (
                <>
                  <p style={{ margin: 0 }}>
                    sealdrop generates a passphrase and shows it once. A passphrase package has one lock, so recipients are not used.
                    {recs.length > 0 ? " Your recipient list is kept and comes back if you switch to recipients." : ""}
                  </p>
                  <div className="field">
                    <span className="label">Word list</span>
                    <Seg
                      label="Word list"
                      value={words}
                      disabled={busy}
                      onChange={setWords}
                      describedBy="seal-words-help"
                      options={[
                        { value: "eff", label: "EFF large list" },
                        { value: "bip39", label: "BIP-39" },
                      ]}
                    />
                    <div id="seal-words-help" className="field__helper">
                      EFF: at least 6 words, 12.9 bits each. BIP-39: at least 10 words, 11 bits each.
                    </div>
                  </div>
                  <div className="field">
                    <span className="label">Key strength</span>
                    <Seg
                      label="Key strength"
                      value={strength}
                      disabled={busy}
                      onChange={(v) => {
                        strengthTouched.current = true;
                        setStrength(v);
                      }}
                      describedBy="seal-strength-help"
                      options={[
                        { value: "default", label: "Standard" },
                        { value: "high", label: "High (slower)" },
                      ]}
                    />
                    <div id="seal-strength-help" className="field__helper">
                      {settings?.argon2id
                        ? "High needs about 2 GiB of free memory to open. (Standard uses the compat profile, 256 MiB.)"
                        : "High takes noticeably longer when sealing and when opening."}
                    </div>
                  </div>
                  {settings?.argon2id ? (
                    <div className="cluster" style={{ gap: 12 }}>
                      <Chip tone="cream">Argon2id (non-standard)</Chip>
                      <span className="field__helper">
                        Stock age tools can't open this package. Change this in Settings. <LinkButton onClick={() => go("settings")}>Settings</LinkButton>
                      </span>
                    </div>
                  ) : null}
                </>
              )}
            </div>
          </Tile>
        </div>

        <div className="span-5 stack">
          <Tile title="Timed release">
            <div className="stack">
              <Toggle
                checked={timed}
                unavailable={busy || !timedAvailable}
                onChange={setTimed}
                label="Timed release"
              />
              {!timedAvailable ? (
                <>
                  <Notice tone="warn">No release service is set up. Add one in Settings to use timed release.</Notice>
                  <div>
                    <SoftButton size="sm" onClick={() => go("settings")}>
                      Open Settings
                    </SoftButton>
                  </div>
                </>
              ) : !timed ? (
                <p style={{ margin: 0 }}>Off. The package can be opened at any time.</p>
              ) : (
                <>
                  <div className="field">
                    <label className="label" htmlFor={winId}>
                      Window
                    </label>
                    <div className="field__row">
                      <input
                        id={winId}
                        className="neu-inset"
                        type="number"
                        min={1}
                        inputMode="numeric"
                        autoComplete="off"
                        placeholder="10"
                        value={winN}
                        disabled={busy}
                        aria-invalid={winError || error?.field === "window" ? true : undefined}
                        aria-describedby={`${winId}-h${winError ? ` ${winId}-e` : ""}`}
                        onChange={(e) => setWinN(e.target.value)}
                        onBlur={() => setWinTouched(true)}
                      />
                      <select
                        className="neu-inset field__unit"
                        aria-label="Window unit"
                        value={unit}
                        disabled={busy}
                        onChange={(e) => setUnit(e.target.value as WindowUnit)}
                      >
                        {UNITS.map((u) => (
                          <option key={u} value={u}>
                            {u}
                          </option>
                        ))}
                      </select>
                    </div>
                    <div id={`${winId}-h`} className="field__helper">
                      The window starts when the recipient first opens the package.
                    </div>
                    {winError ? (
                      <div id={`${winId}-e`} className="field__error">
                        {winError}
                      </div>
                    ) : null}
                  </div>
                  <p role="status" style={{ margin: 0 }}>
                    {TIMED_SENTENCE(timedWindowText)}
                  </p>
                  <div className="cluster" style={{ gap: 8 }}>
                    <span>Release service: {hostOf(service)}</span>
                    <LinkButton onClick={() => go("settings")}>Change in Settings</LinkButton>
                  </div>
                  {!hasToken ? <Notice tone="warn">The release service needs a deposit token. Add it in Settings.</Notice> : null}
                </>
              )}
            </div>
          </Tile>

          <Tile>
            <button
              type="button"
              className="link-btn"
              aria-expanded={detailsOpen}
              aria-controls="seal-details"
              onClick={() => setDetailsOpen((d) => !d)}
              style={{ display: "flex", alignItems: "center", gap: 8, width: "100%", justifyContent: "space-between", textDecoration: "none", textAlign: "left" }}
            >
              <span>
                <span style={{ fontSize: 17 }}>Details (optional)</span>
                <span className="field__helper" style={{ display: "block", fontWeight: 400 }}>
                  Classification, advisory date, armor
                </span>
              </span>
              <GlyphChevron open={detailsOpen} />
            </button>
            {detailsOpen ? (
              <div id="seal-details" className="stack" style={{ marginTop: 16 }}>
                <Field
                  label="Classification"
                  value={classification}
                  onChange={setClassification}
                  placeholder="e.g. confidential"
                  helper="A free-text label saved in the signed record."
                  disabled={busy}
                />
                <Field
                  label="Advisory expiry date"
                  value={advisory}
                  onChange={(v) => setAdvisory(v)}
                  onBlur={() => setDateTouched(true)}
                  placeholder="YYYY-MM-DD"
                  helper="Advisory only. No software enforces this date."
                  error={dateShown}
                  disabled={busy}
                />
                <Toggle
                  checked={armor}
                  unavailable={busy}
                  onChange={(v) => {
                    armorTouched.current = true;
                    setArmor(v);
                  }}
                  label="ASCII armor"
                  helper="Writes text you can paste into a message. The file is larger."
                />
              </div>
            ) : null}
          </Tile>

          <Tile title="Save to">
            <div className="stack">
              <Field
                label="Folder"
                hideLabel
                value={effDir}
                readOnly
                mono
                placeholder="Choose something to send first"
                error={insideError}
                helper={`${outDir ? "" : "Next to the source. "}sealdrop writes three files here: the package, its manifest and its signature.`}
                action={
                  <SoftButton unavailable={busy} onClick={chooseOutDir}>
                    Choose…
                  </SoftButton>
                }
              />
              {working ? (
                <div className="stack stack--sm">
                  <Progress label="Sealing" />
                  <span aria-live="polite">{phaseText}</span>
                </div>
              ) : null}
              {error ? (
                <>
                  <Notice tone="err">{error.text}</Notice>
                  <div>
                    <SoftButton size="sm" onClick={onSeal} unavailable={!!reason}>
                      Try again
                    </SoftButton>
                  </div>
                </>
              ) : null}
              <SoftButton
                variant="primary"
                block
                loading={working}
                busyLabel="Sealing…"
                unavailable={!!reason}
                aria-describedby="seal-status"
                onClick={onSeal}
              >
                Seal
              </SoftButton>
              <div id="seal-status" className="field__helper">
                {reason ?? "Ready when you are."}
              </div>
            </div>
          </Tile>
        </div>
      </div>
    </>
  );
}
