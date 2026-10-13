import { useRef } from "react";
import type { ReactNode } from "react";
import { api } from "../lib/api";
import { useDropTarget } from "../lib/dragdrop";
import { GlyphFile, GlyphFolder } from "./icons";
import { LinkButton, SoftButton } from "./SoftButton";

export interface ChooseButton {
  label: string;
  onClick: () => void;
}

export interface LoadedItem {
  name: string;
  path: string;
  kind?: "file" | "folder";
}

interface DropZoneProps {
  /** Accessible name of the group. */
  label: string;
  headline: string;
  /** Small text under the buttons. */
  helper?: ReactNode;
  small?: boolean;
  /** False while the owning screen is hidden or an operation is running. */
  enabled: boolean;
  onPaths: (paths: string[]) => void;
  /** Keyboard alternative: always visible, opens the native dialog. */
  buttons: ChooseButton[];
  loaded?: LoadedItem | null;
  onClear?: () => void;
  error?: string | null;
  describedBy?: string;
}

/**
 * Inset drop target. Not a tab stop: the Choose buttons inside it are the keyboard alternative.
 * In mock mode (plain browser) clicking the empty area acts like the first Choose button.
 */
export function DropZone({ label, headline, helper, small, enabled, onPaths, buttons, loaded, onClear, error, describedBy }: DropZoneProps) {
  const ref = useRef<HTMLDivElement>(null);
  const over = useDropTarget(ref, onPaths, enabled);
  const errId = error ? `${label.replace(/\W+/g, "-")}-err` : undefined;
  return (
    <div>
      <div
        ref={ref}
        className={`neu-drop${small ? " neu-drop--sm" : ""}`}
        role="group"
        aria-label={label}
        aria-describedby={[describedBy, errId].filter(Boolean).join(" ") || undefined}
        data-active={over ? "true" : undefined}
        onClick={(e) => {
          if (api.isMock && enabled && buttons[0] && !(e.target as HTMLElement).closest("button")) buttons[0].onClick();
        }}
      >
        <div className="drop__inner">
          {loaded ? (
            <>
              {loaded.kind === "folder" ? <GlyphFolder size={48} /> : <GlyphFile size={48} />}
              <div style={{ fontWeight: 700, overflowWrap: "anywhere" }}>{loaded.name}</div>
              <div className="mono muted">{loaded.path}</div>
            </>
          ) : (
            <>
              {small ? null : <GlyphFolder size={48} />}
              <div style={{ fontWeight: 700 }}>{over ? "Release to add" : headline}</div>
              <div className="muted">or</div>
            </>
          )}
          <div className="cluster" style={{ justifyContent: "center" }}>
            {buttons.map((b) => (
              <SoftButton key={b.label} size="sm" unavailable={!enabled} onClick={b.onClick}>
                {b.label}
              </SoftButton>
            ))}
            {loaded && onClear ? <LinkButton onClick={onClear}>Clear</LinkButton> : null}
          </div>
          {helper ? <div className="field__helper">{helper}</div> : null}
        </div>
      </div>
      {error ? (
        <div id={errId} className="field__error" role="alert" style={{ marginTop: 8 }}>
          {error}
        </div>
      ) : null}
    </div>
  );
}
