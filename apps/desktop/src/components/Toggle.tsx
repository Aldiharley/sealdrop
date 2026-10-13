import { useId } from "react";
import type { ReactNode } from "react";

interface ToggleProps {
  checked: boolean;
  onChange: (next: boolean) => void;
  label: ReactNode;
  /** Helper text under the label; linked with aria-describedby. */
  helper?: ReactNode;
  /** Unavailable: aria-disabled, ignores activation, reason belongs in `helper`. */
  unavailable?: boolean;
  /** Text shown for the state; defaults to On / Off. */
  stateText?: [string, string];
  /** Extra class for the row (e.g. a warning tint). */
  className?: string;
}

/** role="switch" row; the whole row is the 44 px target and shows On / Off as text. */
export function Toggle({ checked, onChange, label, helper, unavailable, stateText = ["On", "Off"], className }: ToggleProps) {
  const id = useId();
  const labelId = `${id}-l`;
  const helperId = `${id}-h`;
  const toggle = () => {
    if (!unavailable) onChange(!checked);
  };
  return (
    <div className={`toggle-row${className ? ` ${className}` : ""}`} style={{ alignItems: helper ? "flex-start" : "center" }}>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        aria-labelledby={labelId}
        aria-describedby={helper ? helperId : undefined}
        aria-disabled={unavailable || undefined}
        className="neu-toggle"
        style={{ flex: "none", marginTop: helper ? 7 : 0 }}
        onClick={toggle}
      />
      <div className="toggle-row__text">
        <span id={labelId} onClick={toggle} style={{ cursor: unavailable ? "not-allowed" : "pointer", display: "inline-block", paddingTop: helper ? 6 : 0 }}>
          {label}
        </span>
        {helper ? (
          <div id={helperId} className="field__helper" style={{ marginTop: 2 }}>
            {helper}
          </div>
        ) : null}
      </div>
      <span className="toggle-row__state" aria-hidden="true" style={{ marginTop: helper ? 8 : 0, opacity: unavailable ? 0.5 : 1 }}>
        {checked ? stateText[0] : stateText[1]}
      </span>
    </div>
  );
}
