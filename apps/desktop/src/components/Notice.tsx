import type { ReactNode } from "react";
import { GlyphErr, GlyphOk, GlyphWarn } from "./icons";

interface NoticeProps {
  tone: "warn" | "err" | "ok";
  children: ReactNode;
  /** Errors use role="alert" once, when they appear. */
  role?: "alert" | "status";
  id?: string;
}

export function Notice({ tone, children, role, id }: NoticeProps) {
  return (
    <div
      id={id}
      className={`notice${tone === "err" ? " notice--err" : tone === "ok" ? " notice--ok" : ""}`}
      role={role ?? (tone === "err" ? "alert" : undefined)}
    >
      {tone === "err" ? <GlyphErr /> : tone === "ok" ? <GlyphOk /> : <GlyphWarn />}
      <div>{children}</div>
    </div>
  );
}

/** Glyph plus text row for results (never colour alone). */
export function StatusRow({ tone, children }: { tone: "ok" | "warn" | "err"; children: ReactNode }) {
  return (
    <div className="row" style={{ alignItems: "flex-start", gap: 10 }}>
      <span style={{ flex: "none", marginTop: 1 }}>{tone === "ok" ? <GlyphOk /> : tone === "warn" ? <GlyphWarn /> : <GlyphErr />}</span>
      <span>{children}</span>
    </div>
  );
}

/** Label / value row inside a result tile. */
export function KV({ k, children, mono }: { k: string; children: ReactNode; mono?: boolean }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "128px 1fr", gap: 12, alignItems: "baseline" }}>
      <span className="muted" style={{ fontSize: 14 }}>
        {k}
      </span>
      <span className={mono ? "mono" : undefined} style={{ minWidth: 0 }}>
        {children}
      </span>
    </div>
  );
}
