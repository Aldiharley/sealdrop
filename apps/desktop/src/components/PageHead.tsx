import { useApp } from "../lib/app";
import { SoftButton } from "./SoftButton";
import { Pill } from "./Pill";
import { GlyphWarn } from "./icons";

/** Title, one-line subtitle and the identity status pill shared by all screens. */
export function PageHead({ title, subtitle }: { title: string; subtitle: string }) {
  const { identity } = useApp();
  return (
    <header className="page-head">
      <div>
        <h1 className="h1 no-ring" tabIndex={-1}>{title}</h1>
        <div className="muted" style={{ marginTop: 4 }}>
          {subtitle}
        </div>
      </div>
      {identity ? <Pill dot={identity.exists ? "ok" : "off"}>{identity.exists ? "Identity ready" : "No identity"}</Pill> : null}
    </header>
  );
}

/** Cream first-run banner; shown on every screen except Keys while there is no identity. */
export function FirstRunBanner() {
  const { identity, go, screen } = useApp();
  if (!identity || identity.exists || screen === "keys") return null;
  return (
    <div className="banner" role="region" aria-label="First run">
      <GlyphWarn />
      <span className="banner__text">No identity yet — create one in Keys.</span>
      <SoftButton onClick={() => go("keys", { focusCreate: true })}>Go to Keys</SoftButton>
    </div>
  );
}
