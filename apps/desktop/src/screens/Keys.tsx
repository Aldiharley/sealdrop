import { useCallback, useEffect, useRef, useState } from "react";
import { api, errText } from "../lib/api";
import { useApp } from "../lib/app";
import { formatDate, plural, shortSigner } from "../lib/format";
import { g1, mapReceiptFetchError } from "../lib/errors";
import { baseName } from "../lib/format";
import { mockQuery, useOnceWhen } from "../lib/hooks";
import type { ReceiptOut, Trusted } from "../lib/types";
import { Badge } from "../components/Chip";
import { Countdown } from "../components/Countdown";
import { CopyButton } from "../components/CopyButton";
import { AlertDialog } from "../components/Dialog";
import { Field } from "../components/Field";
import { PageHead } from "../components/PageHead";
import { Progress } from "../components/Progress";
import { LinkButton, SoftButton } from "../components/SoftButton";
import { Tile } from "../components/Tile";
import { TrustForm } from "../components/TrustForm";
import { Notice } from "../components/Notice";
import { Toggle } from "../components/Toggle";

const PQ_HELPER =
  "Protects against a future quantum computer reading packages recorded today. Senders need sealdrop 0.3 or age 1.3 or newer, and your recipient string becomes about 2 000 characters long.";

/** Off by default; the helper text is linked to the switch with aria-describedby. */
function PqSwitch({ checked, onChange, disabled }: { checked: boolean; onChange: (v: boolean) => void; disabled?: boolean }) {
  return <Toggle checked={checked} onChange={onChange} unavailable={disabled} label="Post-quantum identity" helper={PQ_HELPER} />;
}

interface ReceiptRow {
  path: string;
  name: string;
  receipt: ReceiptOut | null;
  error: string | null;
  checking: boolean;
  /** Bumped on every fresh service-clock sample so the countdown restarts from it. */
  sample: number;
}

function stemOf(path: string): string {
  return baseName(path).replace(/\.manifest\.json$/i, "");
}

export default function Keys({ active }: { active: boolean }) {
  const { identity, setIdentity, announce, focusCreateTick, screen } = useApp();
  const [creating, setCreating] = useState(false);
  const [pq, setPq] = useState(false);
  const [idError, setIdError] = useState<string | null>(null);
  const [replaceOpen, setReplaceOpen] = useState(false);
  const [confirmText, setConfirmText] = useState("");
  const [replaceError, setReplaceError] = useState<string | null>(null);
  const [trusted, setTrusted] = useState<Trusted[] | null>(null);
  const [removing, setRemoving] = useState<string | null>(null);
  const [trustedMsg, setTrustedMsg] = useState<string | null>(null);
  const [trustedError, setTrustedError] = useState<string | null>(null);
  const [rows, setRows] = useState<ReceiptRow[]>([]);
  const [receiptError, setReceiptError] = useState<string | null>(null);

  const [createdMsg, setCreatedMsg] = useState<string | null>(null);
  const idHeading = useRef<HTMLHeadingElement>(null);
  const createRef = useRef<HTMLButtonElement>(null);
  const replaceBtn = useRef<HTMLButtonElement>(null);
  const keepBtn = useRef<HTMLButtonElement>(null);

  const loadTrusted = useCallback(async () => {
    try {
      setTrusted(await api.listTrusted());
      setTrustedError(null);
    } catch (e) {
      setTrustedError(g1(errText(e)));
    }
  }, []);

  useEffect(() => {
    if (active) void loadTrusted();
  }, [active, loadTrusted]);

  // "Go to Keys" from the first-run banner lands on the Create button.
  useEffect(() => {
    if (focusCreateTick > 0 && screen === "keys") {
      const t = window.setTimeout(() => createRef.current?.focus(), 30);
      return () => window.clearTimeout(t);
    }
  }, [focusCreateTick, screen]);

  async function create(force: boolean) {
    setCreating(true);
    setIdError(null);
    setReplaceError(null);
    try {
      const info = await api.generateIdentity(force, pq);
      setIdentity(info);
      announce("Identity created.");
      setCreatedMsg("Identity created.");
      setReplaceOpen(false);
      setConfirmText("");
      // The Create button is gone now; land on the new identity instead of losing focus.
      window.setTimeout(() => idHeading.current?.focus(), 80);
    } catch (e) {
      const text = `Couldn't create the keys: ${errText(e).replace(/[.\s]+$/, "")}. Your existing identity was not changed.`;
      if (force) setReplaceError(text);
      else setIdError(text);
    } finally {
      setCreating(false);
    }
  }

  async function addReceipt(path: string) {
    const row: ReceiptRow = { path, name: stemOf(path), receipt: null, error: null, checking: true, sample: 0 };
    setRows((rs) => [row, ...rs.filter((r) => r.path !== path)]);
    await refreshRow(path, true);
  }

  async function refreshRow(path: string, first = false) {
    setRows((rs) => rs.map((r) => (r.path === path ? { ...r, checking: true, error: first ? null : r.error } : r)));
    try {
      const receipt = await api.receiptFetch(path);
      setRows((rs) => rs.map((r) => (r.path === path ? { ...r, receipt, error: null, checking: false, sample: r.sample + 1 } : r)));
      announce("Receipt updated.");
    } catch (e) {
      const error = mapReceiptFetchError(errText(e));
      setRows((rs) => rs.map((r) => (r.path === path ? { ...r, error, checking: false } : r)));
    }
  }

  async function chooseManifest() {
    setReceiptError(null);
    const p = await api.pickFile({ kind: "manifest", extensions: ["json"], title: "Choose a manifest" });
    if (!p) return;
    if (!/\.manifest\.json$/i.test(p)) {
      setReceiptError("Choose a file named <name>.manifest.json.");
      return;
    }
    await addReceipt(p);
  }

  // Mock deep link: ?screen=keys&state=success shows three receipts.
  useOnceWhen(active && api.isMock && mockQuery().get("state") === "success", () => {
    void (async () => {
      for (const n of ["site-plans", "payroll-oct", "report-q3"]) await addReceipt(`C:/Users/me/Documents/sealed/${n}.manifest.json`);
    })();
  });

  const hasId = identity?.exists;

  return (
    <>
      <PageHead title="Keys" subtitle="Your identity, trusted signers and receipts." />
      <div className="cols-12">
        <div className="span-7 stack">
          <Tile title="Your identity" headingRef={idHeading} headingFocusable>
            {identity === null ? null : !hasId ? (
              <div className="stack">
                <p style={{ margin: 0 }}>
                  You don't have an identity yet. An identity is a key pair for opening packages sent to you, plus a signing key that proves packages came from you.
                  It stays on this computer.
                </p>
                {idError ? <Notice tone="err">{idError}</Notice> : null}
                <PqSwitch checked={pq} onChange={setPq} disabled={creating} />
                {creating ? <Progress label="Creating your keys" /> : null}
                <div>
                  <SoftButton ref={createRef} variant="primary" loading={creating} busyLabel="Creating your keys…" onClick={() => create(false)}>
                    Create identity
                  </SoftButton>
                </div>
              </div>
            ) : (
              <div className="stack">
                {createdMsg ? <div role="status">{createdMsg}</div> : null}
                <Field
                  label={
                    <span className="cluster">
                      <span>Recipient</span>{" "}
                      {identity.kind ? <Badge tone="info">{identity.kind === "pq" ? "post-quantum" : "x25519"}</Badge> : null}
                    </span>
                  }
                  as="textarea"
                  readOnly
                  mono
                  value={identity.recipient ?? ""}
                  helper="Give this to people who send to you."
                />
                <div>
                  <CopyButton text={identity.recipient ?? ""} label="Copy recipient" />
                </div>
                <Field
                  label="Signer key"
                  as="textarea"
                  readOnly
                  mono
                  value={identity.signer ?? ""}
                  helper="People add this to their trusted signers so they can check what you send."
                />
                <div className="cluster" style={{ justifyContent: "space-between" }}>
                  <CopyButton text={identity.signer ?? ""} label="Copy signer key" />
                  <SoftButton
                    ref={replaceBtn}
                    variant="pink"
                    onClick={() => {
                      setConfirmText("");
                      setReplaceError(null);
                      setPq(false);
                      setReplaceOpen(true);
                    }}
                  >
                    Replace identity…
                  </SoftButton>
                </div>
                <p className="field__helper" style={{ margin: 0 }}>
                  Stored in <span className="mono">{identity.dir}</span>. The private keys never leave this computer.
                </p>
              </div>
            )}
          </Tile>

          <Tile title="Trusted signers">
            <div className="stack">
              {trustedError ? <Notice tone="err">{trustedError}</Notice> : null}
              {trusted && trusted.length === 0 ? (
                <p style={{ margin: 0 }}>
                  No trusted signers yet. Packages from a signer you haven't trusted need their key each time you open or verify them.
                </p>
              ) : null}
              {trusted && trusted.length > 0 ? (
                <ul className="list">
                  {trusted.map((t) => (
                    <li key={t.name} className="list__row" style={{ flexWrap: "wrap" }}>
                      <div className="list__row-main">
                        <span style={{ fontWeight: 700 }}>{t.name}</span> <span className="muted">·</span>{" "}
                        <span className="mono" title={t.key}>
                          {shortSigner(t.key)}
                        </span>
                      </div>
                      {removing === t.name ? (
                        <div className="cluster" style={{ flexBasis: "100%", gap: 12 }}>
                          <span>Remove {t.name}? Packages signed by this key will need the key entered again.</span>
                          <SoftButton
                            size="sm"
                            variant="pink"
                            onClick={async () => {
                              try {
                                await api.removeTrusted(t.name);
                                setRemoving(null);
                                announce(`${t.name} removed.`);
                                await loadTrusted();
                              } catch (e) {
                                setTrustedError(g1(errText(e)));
                              }
                            }}
                          >
                            Remove
                          </SoftButton>
                          <SoftButton size="sm" onClick={() => setRemoving(null)}>
                            Keep
                          </SoftButton>
                        </div>
                      ) : (
                        <LinkButton aria-label={`Remove ${t.name}`} onClick={() => setRemoving(t.name)}>
                          Remove
                        </LinkButton>
                      )}
                    </li>
                  ))}
                </ul>
              ) : null}
              <div className="stack stack--sm">
                <div className="label">Add a signer</div>
                <TrustForm
                  inline
                  buttonLabel="Trust signer"
                  existing={(trusted ?? []).map((t) => t.name)}
                  onTrusted={(n) => {
                    setTrustedMsg(`${n} is now trusted.`);
                    void loadTrusted();
                  }}
                />
                {trustedMsg ? <span>{trustedMsg}</span> : null}
              </div>
            </div>
          </Tile>
        </div>

        <div className="span-5 stack">
          <Tile title="Receipts">
            <div className="stack">
              <p style={{ margin: 0 }}>Pick the manifest of a package you sealed.</p>
              <div>
                <SoftButton onClick={chooseManifest}>Choose manifest…</SoftButton>
              </div>
              {receiptError ? <div className="field__error" role="alert">{receiptError}</div> : null}
              {rows.length === 0 ? (
                <p className="field__helper" style={{ margin: 0 }}>
                  No receipts checked yet. Choose the manifest of a timed package you sealed to see when it was opened.
                </p>
              ) : (
                <ul className="list">
                  {rows.map((r) => (
                    <li key={r.path} className="list__row" style={{ alignItems: "flex-start" }}>
                      <ReceiptItem row={r} onCheck={() => refreshRow(r.path)} />
                    </li>
                  ))}
                </ul>
              )}
              <p className="field__helper" style={{ margin: 0 }}>
                Receipts are checked against the service key recorded in the signed manifest of the package you sealed.
              </p>
              <p className="field__helper" style={{ margin: 0 }}>
                Receipts are signed by the release service, and the service clock decides the times shown here.
              </p>
              <p className="field__helper" style={{ margin: 0 }}>
                Receipts you check here are not saved. They are gone when you close sealdrop.
              </p>
            </div>
          </Tile>
        </div>
      </div>

      {replaceOpen ? (
        <AlertDialog
          title="Replace your identity?"
          body="This creates new keys and deletes the old ones. Packages sealed to your old recipient string can no longer be opened, and people who trust your old signer key will need your new one."
          initialFocus={keepBtn}
          returnFocus={replaceBtn}
          onClose={() => setReplaceOpen(false)}
        >
          <div className="stack">
            <PqSwitch checked={pq} onChange={setPq} disabled={creating} />
            <Field label="Type REPLACE to confirm" value={confirmText} onChange={setConfirmText} placeholder="REPLACE" disabled={creating} />
            {replaceError ? <Notice tone="err">{replaceError}</Notice> : null}
            <div className="cluster" style={{ justifyContent: "flex-end", gap: 12 }}>
              <SoftButton ref={keepBtn} variant="primary" onClick={() => setReplaceOpen(false)}>
                Keep my identity
              </SoftButton>
              <SoftButton
                variant="pink"
                loading={creating}
                busyLabel="Creating your keys…"
                unavailable={confirmText !== "REPLACE"}
                onClick={() => create(true)}
              >
                Replace identity
              </SoftButton>
            </div>
          </div>
        </AlertDialog>
      ) : null}
    </>
  );
}

function ReceiptItem({ row, onCheck }: { row: ReceiptRow; onCheck: () => void }) {
  const r = row.receipt;
  const opened = r?.first_unlock ?? null;
  const expired = r !== null && r.remaining_secs !== null && r.remaining_secs <= 0 && opened !== null;
  return (
    <div className="list__row-main stack stack--sm">
      <div style={{ fontWeight: 700, overflowWrap: "anywhere" }}>{row.name}</div>
      {r ? (
        <>
          {opened === null ? (
            <div>
              <Countdown remainingSecs={null} waiting sampleKey={row.sample} />
            </div>
          ) : expired ? (
            <div>Opened {formatDate(opened)}, expired</div>
          ) : (
            <>
              <div>
                <span className="badge badge--info">Opened {formatDate(opened)}</span>
              </div>
              {r.remaining_secs !== null ? (
                <div>
                  <Countdown remainingSecs={r.remaining_secs} sampleKey={row.sample} onCheckAgain={onCheck} checkingAgain={row.checking} />
                </div>
              ) : null}
            </>
          )}
          {opened !== null ? (
            <div>
              Opened {r.unlock_count} {plural(r.unlock_count, "time")}
            </div>
          ) : null}
          <div>
            <Badge tone="ok">Receipt verified</Badge>
          </div>
        </>
      ) : null}
      {row.error ? <Notice tone="err">{row.error}</Notice> : null}
      <div className="cluster" style={{ gap: 12 }}>
        <SoftButton size="sm" loading={row.checking} busyLabel="Checking…" onClick={onCheck}>
          Check now
        </SoftButton>
      </div>
    </div>
  );
}
