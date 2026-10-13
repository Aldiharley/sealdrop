import { useEffect, useRef, useState } from "react";
import { useApp } from "../lib/app";
import { writeClipboard } from "../lib/hooks";
import { SoftButton } from "./SoftButton";

interface CopyButtonProps {
  text: string;
  label?: string;
  /** Accessible name when several Copy buttons share a label. */
  ariaLabel?: string;
  /** Secret (passphrase): the confirmation also asks the user to clear the clipboard. */
  secret?: boolean;
}

/** Small Copy button with the inline "Copied." confirmation (also sent to the live region). */
export function CopyButton({ text, label = "Copy", ariaLabel, secret }: CopyButtonProps) {
  const { announce } = useApp();
  const [done, setDone] = useState(false);
  const timer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(timer.current), []);
  const msg = secret ? "Copied. Clear your clipboard once you have shared it." : "Copied.";
  return (
    <span className="cluster" style={{ gap: 10 }}>
      <SoftButton
        size="sm"
        aria-label={ariaLabel}
        onClick={async () => {
          if (await writeClipboard(text)) {
            setDone(true);
            announce("Copied.");
            window.clearTimeout(timer.current);
            timer.current = window.setTimeout(() => setDone(false), secret ? 8000 : 3000);
          }
        }}
      >
        {label}
      </SoftButton>
      {done ? <span className="field__helper">{msg}</span> : null}
    </span>
  );
}
