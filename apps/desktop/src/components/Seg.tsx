import { useRef } from "react";
import type { KeyboardEvent } from "react";

interface SegOption<V extends string> {
  value: V;
  label: string;
  unavailable?: boolean;
}

interface SegProps<V extends string> {
  label: string;
  value: V;
  options: SegOption<V>[];
  onChange: (v: V) => void;
  /** Working: every option becomes aria-disabled. */
  disabled?: boolean;
  describedBy?: string;
}

/** Segmented radiogroup: one tab stop, arrow keys move and select. */
export function Seg<V extends string>({ label, value, options, onChange, disabled, describedBy }: SegProps<V>) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const move = (from: number, dir: 1 | -1) => {
    const n = options.length;
    for (let step = 1; step <= n; step++) {
      const i = (((from + dir * step) % n) + n) % n;
      const o = options[i];
      if (!o.unavailable) {
        onChange(o.value);
        refs.current[i]?.focus();
        return;
      }
    }
  };
  const onKey = (e: KeyboardEvent, i: number) => {
    if (disabled) return;
    if (e.key === "ArrowRight" || e.key === "ArrowDown") {
      e.preventDefault();
      move(i, 1);
    } else if (e.key === "ArrowLeft" || e.key === "ArrowUp") {
      e.preventDefault();
      move(i, -1);
    }
  };
  return (
    <div className="seg" role="radiogroup" aria-label={label} aria-describedby={describedBy}>
      {options.map((o, i) => {
        const checked = o.value === value;
        const off = !!(disabled || o.unavailable);
        return (
          <button
            key={o.value}
            ref={(el) => {
              refs.current[i] = el;
            }}
            type="button"
            role="radio"
            aria-checked={checked}
            aria-disabled={off || undefined}
            tabIndex={checked ? 0 : -1}
            className="seg__item"
            onKeyDown={(e) => onKey(e, i)}
            onClick={() => {
              if (!off) onChange(o.value);
            }}
          >
            {o.label}
          </button>
        );
      })}
    </div>
  );
}
