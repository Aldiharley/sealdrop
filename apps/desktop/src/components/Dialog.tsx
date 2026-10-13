import { useEffect, useId, useRef } from "react";
import type { ReactNode, RefObject } from "react";

interface DialogProps {
  title: string;
  body: ReactNode;
  /** Esc and the safe button call this. */
  onClose: () => void;
  /** Element that receives focus when the dialog opens (the safe, default action). */
  initialFocus: RefObject<HTMLElement | null>;
  /** Where focus returns when the dialog closes. */
  returnFocus: RefObject<HTMLElement | null>;
  children: ReactNode;
}

const FOCUSABLE = 'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/** Destructive-action dialog: role="alertdialog", focus trap, Esc closes, focus returns to the opener. */
export function AlertDialog({ title, body, onClose, initialFocus, returnFocus, children }: DialogProps) {
  const id = useId();
  const box = useRef<HTMLDivElement>(null);
  const closeRef = useRef(onClose);
  closeRef.current = onClose;

  useEffect(() => {
    const back = returnFocus.current;
    initialFocus.current?.focus();
    return () => {
      back?.focus();
    };
  }, [initialFocus, returnFocus]);

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") {
      e.stopPropagation();
      closeRef.current();
      return;
    }
    if (e.key !== "Tab" || !box.current) return;
    const items = Array.from(box.current.querySelectorAll<HTMLElement>(FOCUSABLE)).filter((el) => el.getAttribute("aria-hidden") !== "true");
    if (items.length === 0) return;
    const first = items[0];
    const last = items[items.length - 1];
    const cur = document.activeElement;
    if (e.shiftKey && cur === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && cur === last) {
      e.preventDefault();
      first.focus();
    } else if (!box.current.contains(cur)) {
      e.preventDefault();
      first.focus();
    }
  };

  return (
    <div className="scrim" onKeyDown={onKeyDown}>
      <div ref={box} className="neu-tile dialog" role="alertdialog" aria-modal="true" aria-labelledby={`${id}-t`} aria-describedby={`${id}-b`}>
        <h2 id={`${id}-t`} className="h2" style={{ marginBottom: 12 }}>
          {title}
        </h2>
        <p id={`${id}-b`} style={{ margin: "0 0 16px" }}>
          {body}
        </p>
        {children}
      </div>
    </div>
  );
}
