import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "./lib/api";
import { AppContext } from "./lib/app";
import type { AppCtx, GoOptions, PublicSettings } from "./lib/app";
import { mockQuery } from "./lib/hooks";
import type { IdentityInfo, ScreenId } from "./lib/types";
import { Nav } from "./components/Nav";
import Keys from "./screens/Keys";
import Open from "./screens/Open";
import Seal from "./screens/Seal";
import Settings from "./screens/Settings";
import Verify from "./screens/Verify";

const SCREENS: ScreenId[] = ["seal", "open", "verify", "keys", "settings"];

function initialScreen(): ScreenId {
  // Deep links (?screen=open) are for mock mode only, used for screenshots.
  const s = mockQuery().get("screen");
  return SCREENS.includes(s as ScreenId) ? (s as ScreenId) : "seal";
}

export default function App() {
  const [screen, setScreen] = useState<ScreenId>(initialScreen);
  const [identity, setIdentity] = useState<IdentityInfo | null>(null);
  const [settings, setSettings] = useState<PublicSettings | null>(null);
  const [live, setLive] = useState("");
  const [focusCreateTick, setFocusCreateTick] = useState(0);
  const flip = useRef(false);
  const first = useRef(true);

  const announce = useCallback((msg: string) => {
    // Alternate a trailing zero-width space so repeating the same message is announced again.
    flip.current = !flip.current;
    setLive(msg + (flip.current ? "​" : ""));
  }, []);

  const refreshSettings = useCallback(async (): Promise<PublicSettings | null> => {
    try {
      const s = await api.getSettings();
      // The deposit token stays in the Settings form only; other screens see whether one exists.
      const pub: PublicSettings = {
        release_service: s.release_service,
        has_token: !!s.release_token,
        scrypt_log_n: s.scrypt_log_n,
        armor: s.armor,
        argon2id: s.argon2id,
      };
      setSettings(pub);
      return pub;
    } catch {
      return null;
    }
  }, []);

  const go = useCallback((s: ScreenId, opts?: GoOptions) => {
    setScreen(s);
    if (opts?.focusCreate) setFocusCreateTick((n) => n + 1);
  }, []);

  useEffect(() => {
    api
      .getIdentity()
      .then(setIdentity)
      .catch(() => setIdentity({ exists: false, recipient: null, signer: null, dir: "", kind: null }));
    void refreshSettings();
  }, [refreshSettings]);

  // Move focus to the page title when the screen changes (not on first paint).
  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    const t = window.setTimeout(() => {
      document.querySelector<HTMLElement>(".page:not([hidden]) h1")?.focus();
    }, 0);
    return () => window.clearTimeout(t);
  }, [screen]);

  // Optional shortcuts: Ctrl/Cmd + 1 to 5.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!(e.ctrlKey || e.metaKey) || e.altKey || e.shiftKey) return;
      const i = Number(e.key) - 1;
      if (Number.isInteger(i) && i >= 0 && i < SCREENS.length) {
        e.preventDefault();
        setScreen(SCREENS[i]);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const ctx = useMemo<AppCtx>(
    () => ({ identity, setIdentity, settings, refreshSettings, screen, go, announce, focusCreateTick }),
    [identity, settings, refreshSettings, screen, go, announce, focusCreateTick],
  );

  return (
    <AppContext.Provider value={ctx}>
      <div className="app aa" lang="en">
        <Nav current={screen} onSelect={(s) => go(s)} />
        <main className="main">
          <Page id="seal" screen={screen}>
            <Seal active={screen === "seal"} />
          </Page>
          <Page id="open" screen={screen}>
            <Open active={screen === "open"} />
          </Page>
          <Page id="verify" screen={screen}>
            <Verify active={screen === "verify"} />
          </Page>
          <Page id="keys" screen={screen}>
            <Keys active={screen === "keys"} />
          </Page>
          <Page id="settings" screen={screen}>
            <Settings active={screen === "settings"} />
          </Page>
        </main>
        <div className="sr-only" role="status" aria-live="polite">
          {live}
        </div>
      </div>
    </AppContext.Provider>
  );
}

/** Every screen stays mounted (so non-secret state survives switching); only the current one is shown. */
function Page({ id, screen, children }: { id: ScreenId; screen: ScreenId; children: React.ReactNode }) {
  return (
    <div className="page" hidden={screen !== id} data-screen={id}>
      {children}
    </div>
  );
}
