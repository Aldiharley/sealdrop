import type { ReactNode } from "react";

/** Raised, non-interactive pill. `dot` adds a status dot ("ok" sage, "off" pink). */
export function Pill({ dot, children }: { dot?: "ok" | "off"; children: ReactNode }) {
  return (
    <span className="neu-pill">
      {dot ? <span className={dot === "off" ? "dot dot--off" : "dot"} aria-hidden="true" /> : null}
      <span>{children}</span>
    </span>
  );
}
