import { useCallback, useEffect, useRef, useState } from "react";
import { api, errText } from "../lib/api";
import { useApp } from "../lib/app";
import { hostOf } from "../lib/format";
import type { Settings as SettingsT } from "../lib/types";
import { Chip } from "../components/Chip";
import { Field } from "../components/Field";
import { FirstRunBanner, PageHead } from "../components/PageHead";
import { Pill } from "../components/Pill";
import { Seg } from "../components/Seg";
import { LinkButton, SoftButton } from "../components/SoftButton";
import { Tile } from "../components/Tile";
import { Toggle } from "../components/Toggle";

const INK = { color: "var(--ink)" } as const;

function validateAddress(a: string): string | null {
  const t = a.trim();
  if (!t) return null;
  const bad = "That address isn't valid. Use https://host, or http://localhost.";
  if (!/^https?:\/\//i.test(t)) return bad;
  try {
    const u = new URL(t);
    if (u.protocol === "http:" && !["localhost", "127.0.0.1", "[::1]"].includes(u.hostname)) {
      return "Use https:// for a service on another computer.";
    }
  } catch {
    return bad;
  }
  return null;
}

export default function Settings({ active }: { active: boolean }) {
  const { identity, refreshSettings, announce } = useApp();
  // The deposit token lives only in this form state; it is dropped when the screen is left.
  const [saved, setSaved] = useState<SettingsT | null>(null);
  const [service, setService] = useState("");
  const [token, setToken] = useState("");
  const [addrError, setAddrError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [note, setNote] = useState<{ where: "service" | "argon" | "strength" | "armor"; text: string } | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [epoch, setEpoch] = useState(0);
  const noteTimer = useRef<number | undefined>(undefined);

  const flash = useCallback(
    (where: "service" | "argon" | "strength" | "armor", text: string) => {
      setNote({ where, text });
      announce(text);
      window.clearTimeout(noteTimer.current);
      noteTimer.current = window.setTimeout(() => setNote(null), 4000);
    },
    [announce],
  );

  useEffect(() => {
    if (!active) {
      // Leaving the screen: drop the token and the Show state.
      setSaved(null);
      setService("");
      setToken("");
      setAddrError(null);
      setNote(null);
      return;
    }
    let live = true;
    setEpoch((n) => n + 1);
    api
      .getSettings()
      .then((s) => {
        if (!live) return;
        setSaved(s);
        setService(s.release_service ?? "");
        setToken(s.release_token ?? "");
        setLoadError(null);
      })
      .catch((e) => live && setLoadError(errText(e)));
    return () => {
      live = false;
    };
  }, [active]);

  useEffect(() => () => window.clearTimeout(noteTimer.current), []);

  const dirty = saved !== null && (service.trim() !== (saved.release_service ?? "") || token.trim() !== (saved.release_token ?? ""));

  /** Persist a full Settings object (the command replaces all five fields). */
  async function persist(next: SettingsT, where: "service" | "argon" | "strength" | "armor") {
    try {
      await api.setSettings(next);
      const fresh = await api.getSettings();
      setSaved(fresh);
      setService(fresh.release_service ?? "");
      setToken(fresh.release_token ?? "");
      await refreshSettings();
      flash(where, "Saved.");
      return true;
    } catch (e) {
      const msg = errText(e);
      if (where === "service") setAddrError(msg);
      else setLoadError(msg);
      return false;
    }
  }

  async function onSave() {
    if (!saved || !dirty || saving) return;
    const t = token.trim();
    const a = service.trim();
    const err = validateAddress(a) ?? (t && !a ? "Enter the address before the token." : null);
    if (err) {
      setAddrError(err);
      return;
    }
    setAddrError(null);
    setSaving(true);
    await persist({ ...saved, release_service: a || null, release_token: t || null }, "service");
    setSaving(false);
  }

  async function onClear() {
    if (!saved) return;
    setAddrError(null);
    setSaving(true);
    await persist({ ...saved, release_service: null, release_token: null }, "service");
    setSaving(false);
  }

  const host = hostOf(saved?.release_service);
  const disabledReason = !dirty ? "Change the address or token to save." : undefined;

  return (
    <>
      <PageHead title="Settings" subtitle="Release service, passphrase options and output." />
      <FirstRunBanner />
      {loadError ? (
        <div className="notice notice--err" role="alert" style={{ marginBottom: 16 }}>
          <span>Something went wrong: {loadError}. Nothing was changed.</span>
        </div>
      ) : null}
      <div className="cols-12">
        <div className="span-7 stack">
          <Tile title="Release service">
            <div className="stack" key={epoch}>
              <p style={{ margin: 0 }}>Used when you seal a timed package or check a receipt.</p>
              <Field
                label="Release service address"
                value={service}
                onChange={(v) => {
                  setService(v);
                  setAddrError(null);
                }}
                onBlur={() => setAddrError(validateAddress(service))}
                placeholder="https://release.example.org"
                helper="Must start with https://. http:// works only for this computer (localhost)."
                error={addrError}
                disabled={saving || !saved}
              />
              <Field
                label="Deposit token"
                type="password"
                value={token}
                onChange={setToken}
                placeholder="Paste the token your operator gave you"
                helper="Saved in sealdrop's settings on this computer. When you seal, sealdrop signs the manifest and then deposits the key with the service you configured. When you open a timed package or check a receipt, sealdrop verifies the manifest signature first and sends the deposit token only to the service named in that signed manifest."
                disabled={saving || !saved}
              />
              <div className="cluster" style={{ gap: 16 }}>
                <SoftButton
                  variant="primary"
                  loading={saving}
                  busyLabel="Saving…"
                  unavailable={!dirty}
                  aria-describedby={disabledReason ? "settings-save-reason" : undefined}
                  onClick={onSave}
                >
                  Save
                </SoftButton>
                {note?.where === "service" ? <span>{note.text}</span> : null}
                <LinkButton onClick={onClear}>Clear service settings</LinkButton>
              </div>
              {disabledReason ? (
                <span id="settings-save-reason" className="sr-only">
                  {disabledReason}
                </span>
              ) : null}
            </div>
          </Tile>

          <Tile title="Passphrases">
            <div className="stack">
              <Toggle
                checked={!!saved?.argon2id}
                unavailable={!saved}
                onChange={(v) => saved && persist({ ...saved, argon2id: v }, "argon")}
                label={
                  <span className="cluster">
                    <span>Use Argon2id for passphrases</span>
                    <Chip tone="cream">Non-standard</Chip>
                  </span>
                }
                helper={
                  <span style={INK}>
                    Adds little over scrypt and breaks interoperability with stock age tools. Off by default.
                    {saved?.argon2id ? " Packages made this way open only in sealdrop." : ""}
                  </span>
                }
              />
              {note?.where === "argon" ? <span>{note.text}</span> : null}
              <div className="field">
                <span className="label" id="settings-strength-label">
                  Default key strength
                </span>
                <div className="cluster" style={{ gap: 16 }}>
                  <Seg
                    label="Default key strength"
                    value={saved?.scrypt_log_n === 20 ? "high" : "default"}
                    disabled={!saved}
                    onChange={(v) => saved && persist({ ...saved, scrypt_log_n: v === "high" ? 20 : 18 }, "strength")}
                    options={[
                      { value: "default", label: "Standard" },
                      { value: "high", label: "High (slower)" },
                    ]}
                    describedBy="settings-strength-help"
                  />
                  {note?.where === "strength" ? <span>{note.text}</span> : null}
                </div>
                <div id="settings-strength-help" className="field__helper">
                  Standard is scrypt 2^18 (Argon2id: 256 MiB). High is scrypt 2^20 (Argon2id: 2 GiB).
                </div>
              </div>
            </div>
          </Tile>
        </div>

        <div className="span-5 stack">
          <Tile title="Output">
            <Toggle
              checked={!!saved?.armor}
              unavailable={!saved}
              onChange={(v) => saved && persist({ ...saved, armor: v }, "armor")}
              label="ASCII armor"
              helper="Writes text instead of binary. The file is larger."
            />
            {note?.where === "armor" ? <div style={{ marginTop: 8 }}>{note.text}</div> : null}
          </Tile>

          <Tile title="Network">
            <div className="stack">
              <p style={{ margin: 0 }}>
                sealdrop makes network requests only to: the release service you configure here (when you seal a timed package or check a receipt) and the
                release service named inside a timed package you open (shown to you before the call).
              </p>
              <div>
                <Pill dot={host ? "ok" : "off"}>{host ? `Release service: ${host}` : "Release service: not set"}</Pill>
              </div>
            </div>
          </Tile>

          <Tile title="About">
            <div className="stack stack--sm">
              <div style={{ fontWeight: 700 }}>sealdrop 0.2.0</div>
              <p style={{ margin: 0 }}>
                Packages made for recipients or with a standard passphrase open in stock age tools. Argon2id and timed release packages need sealdrop.
              </p>
              <p style={{ margin: 0 }}>
                Keys are stored in <span className="mono">{identity?.dir ?? "…"}</span>.
              </p>
            </div>
          </Tile>
        </div>
      </div>
    </>
  );
}
