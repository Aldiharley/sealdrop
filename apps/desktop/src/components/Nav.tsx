import type { ReactNode } from "react";
import type { ScreenId } from "../lib/types";
import { VERSION } from "../lib/version";
import { Brand, NavKeys, NavOpen, NavSeal, NavSettings, NavVerify } from "./icons";

const TOP: { id: ScreenId; label: string; icon: ReactNode }[] = [
  { id: "seal", label: "Seal", icon: <NavSeal /> },
  { id: "open", label: "Open", icon: <NavOpen /> },
  { id: "verify", label: "Verify", icon: <NavVerify /> },
  { id: "keys", label: "Keys", icon: <NavKeys /> },
];
const BOTTOM = { id: "settings" as ScreenId, label: "Settings", icon: <NavSettings /> };

/** Five icon pills; the current one is inset and carries aria-current="page". */
export function Nav({ current, onSelect }: { current: ScreenId; onSelect: (s: ScreenId) => void }) {
  const item = (it: { id: ScreenId; label: string; icon: ReactNode }) => (
    <div key={it.id} className="neu-nav__item-wrap">
      <button
        type="button"
        className="neu-nav__item"
        aria-label={it.label}
        aria-current={current === it.id ? "page" : undefined}
        onClick={() => onSelect(it.id)}
      >
        {it.icon}
      </button>
      <span className="nav-label" aria-hidden="true">
        {it.label}
      </span>
    </div>
  );
  return (
    <nav className="neu-nav" aria-label="Main">
      <div className="neu-nav__logo" aria-hidden="true">
        <Brand />
      </div>
      {TOP.map(item)}
      <div className="neu-nav__spacer" />
      {item(BOTTOM)}
      <div className="muted" style={{ fontSize: 12, marginTop: 4 }} aria-hidden="true">
        sealdrop {VERSION}
      </div>
    </nav>
  );
}
