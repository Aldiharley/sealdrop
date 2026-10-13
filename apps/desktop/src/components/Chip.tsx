import type { ReactNode } from "react";
import { GlyphErr, GlyphOk, GlyphWarn, GlyphCross } from "./icons";

export type ChipTone = "pink" | "blue" | "sage" | "cream" | "word";

interface ChipProps {
  tone?: ChipTone;
  children: ReactNode;
  /** Makes the chip removable; `removeLabel` is the accessible name of the x button. */
  onRemove?: () => void;
  removeLabel?: string;
  removeDisabled?: boolean;
  title?: string;
}

export function Chip({ tone = "pink", children, onRemove, removeLabel, removeDisabled, title }: ChipProps) {
  return (
    <span className={`neu-chip neu-chip--${tone}`} title={title}>
      <span>{children}</span>
      {onRemove ? (
        <button
          type="button"
          className="neu-chip__x"
          aria-label={removeLabel ?? "Remove"}
          aria-disabled={removeDisabled || undefined}
          onClick={() => {
            if (!removeDisabled) onRemove();
          }}
        >
          <GlyphCross />
        </button>
      ) : null}
    </span>
  );
}

export type BadgeTone = "ok" | "warn" | "err" | "info";

/** Status badge: always glyph plus a word, never colour alone. */
export function Badge({ tone, children }: { tone: BadgeTone; children: ReactNode }) {
  return (
    <span className={`badge badge--${tone}`}>
      {tone === "ok" ? <GlyphOk size={16} /> : tone === "warn" ? <GlyphWarn size={16} /> : tone === "err" ? <GlyphErr size={16} /> : null}
      <span>{children}</span>
    </span>
  );
}
