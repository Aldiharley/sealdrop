import { useState } from "react";
import { api, errText } from "../lib/api";
import { useApp } from "../lib/app";
import { looksLikeSignerKey, validSignerName } from "../lib/format";
import { mapTrustError } from "../lib/errors";
import { Field } from "./Field";
import { SoftButton } from "./SoftButton";

interface TrustFormProps {
  /** Key to trust. When omitted the form shows its own key field (Keys screen). */
  signerKey?: string;
  buttonLabel: string;
  /** Names already in the trusted list, for the duplicate check. */
  existing?: string[];
  onTrusted: (name: string) => void;
  /** Show the Name helper ("Letters, digits, - and _ only.") */
  nameHelper?: boolean;
  /** Layout the two fields side by side (Keys). */
  inline?: boolean;
  idPrefix?: string;
}

/** Name (and optional key) fields with a Trust button; calls add_trusted and reports the outcome. */
export function TrustForm({ signerKey, buttonLabel, existing = [], onTrusted, nameHelper = true, inline }: TrustFormProps) {
  const { announce } = useApp();
  const [name, setName] = useState("");
  const [key, setKey] = useState("");
  const [nameErr, setNameErr] = useState<string | null>(null);
  const [keyErr, setKeyErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    if (busy) return;
    const n = name.trim();
    const k = (signerKey ?? key).trim();
    let bad = false;
    if (!validSignerName(n)) {
      setNameErr("Use letters, digits, - and _ only.");
      bad = true;
    } else if (existing.includes(n)) {
      setNameErr(`A signer named “${n}” already exists.`);
      bad = true;
    } else setNameErr(null);
    if (!signerKey && !looksLikeSignerKey(k)) {
      setKeyErr("That isn't a valid signer key.");
      bad = true;
    } else setKeyErr(null);
    if (bad) return;
    setBusy(true);
    try {
      await api.addTrusted(n, k);
      setName("");
      setKey("");
      announce(`${n} is now trusted.`);
      onTrusted(n);
    } catch (e) {
      const msg = mapTrustError(errText(e), n);
      if (/key/.test(msg)) setKeyErr(msg);
      else setNameErr(msg);
    } finally {
      setBusy(false);
    }
  }

  const nameField = (
    <Field
      label="Name"
      value={name}
      onChange={(v) => {
        setName(v);
        setNameErr(null);
      }}
      placeholder={inline ? "Name, e.g. alice" : "e.g. alice"}
      helper={nameHelper ? "Letters, digits, - and _ only." : undefined}
      error={nameErr}
      disabled={busy}
      onEnter={signerKey ? submit : undefined}
    />
  );
  const keyField = !signerKey ? (
    <Field
      label="Signer key"
      value={key}
      onChange={(v) => {
        setKey(v);
        setKeyErr(null);
      }}
      placeholder="Signer key (starts with RWQ)"
      error={keyErr}
      disabled={busy}
      mono
      onEnter={submit}
    />
  ) : null;
  return (
    <div className="stack">
      {inline ? (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1.6fr", gap: 12, alignItems: "start" }}>
          {nameField}
          {keyField}
        </div>
      ) : (
        <>
          {nameField}
          {keyField}
        </>
      )}
      <div>
        <SoftButton loading={busy} busyLabel="Trusting…" onClick={submit}>
          {buttonLabel}
        </SoftButton>
      </div>
    </div>
  );
}
