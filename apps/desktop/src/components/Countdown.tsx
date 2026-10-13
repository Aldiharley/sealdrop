import { useEffect, useRef, useState } from "react";
import { compactDuration } from "../lib/format";

interface CountdownProps {
  /**
   * Service-clock sample: seconds left at the moment the response arrived (open_package or
   * receipt_fetch `remaining_secs`). null with `waiting` means "not opened yet".
   */
  remainingSecs: number | null;
  /** Window length in seconds, when known (low state at 25% of it; threshold announcements). */
  windowSecs?: number | null;
  /** Changes whenever a new sample is taken, so the monotonic timer restarts from it. */
  sampleKey: string | number;
  /** Not opened yet (cream slab). */
  waiting?: boolean;
  /** Announce thresholds in a polite live region (off in lists, where it would be noisy). */
  announce?: boolean;
  /** Called once per sample when the display reaches zero after counting down from a positive sample. */
  onExpire?: () => void;
}

const THRESHOLDS: { at: number; text: string }[] = [
  { at: 600, text: "10 minutes left" },
  { at: 60, text: "1 minute left" },
  { at: 30, text: "30 seconds left" },
];

interface Sample {
  key: string | number;
  rem: number | null;
  /** performance.now() when this sample was first rendered: a monotonic reference, not the wall clock. */
  t0: number;
  announced: Set<number>;
  expired: boolean;
}

/**
 * Display-only countdown. The value is the service's `remaining_secs` sample advanced by a
 * monotonic timer (performance.now), never `expires_at` minus the wall clock. It only counts
 * down and then reads "expired"; enforcement is the release service.
 */
export function Countdown({ remainingSecs, windowSecs, sampleKey, waiting, announce, onExpire }: CountdownProps) {
  const [, setTick] = useState(0);
  const [msg, setMsg] = useState("");
  const sample = useRef<Sample | null>(null);

  // A new sample restarts the monotonic reference and marks the thresholds already behind it.
  if (!sample.current || sample.current.key !== sampleKey || sample.current.rem !== remainingSecs) {
    sample.current = {
      key: sampleKey,
      rem: remainingSecs,
      t0: performance.now(),
      announced: new Set(
        THRESHOLDS.filter((t) => remainingSecs === null || t.at >= remainingSecs || (windowSecs != null && t.at >= windowSecs)).map((t) => t.at),
      ),
      expired: false,
    };
    if (remainingSecs === 0) sample.current.announced.add(0);
  }
  const s = sample.current;

  useEffect(() => {
    const id = window.setInterval(() => setTick((n) => n + 1), 1000);
    return () => window.clearInterval(id);
  }, []);

  const left = remainingSecs === null ? null : Math.max(0, Math.ceil(remainingSecs - (performance.now() - s.t0) / 1000));

  const expireRef = useRef(onExpire);
  expireRef.current = onExpire;
  useEffect(() => {
    if (left === null) return;
    if (announce) {
      for (const t of THRESHOLDS) {
        if (left <= t.at && !s.announced.has(t.at)) {
          s.announced.add(t.at);
          setMsg(t.text);
          break;
        }
      }
      if (left === 0 && !s.announced.has(0)) {
        s.announced.add(0);
        setMsg("The window has ended.");
      }
    }
    if (left === 0 && (remainingSecs ?? 0) > 0 && !s.expired) {
      s.expired = true;
      expireRef.current?.();
    }
  }, [left, announce, s, remainingSecs]);

  let state: "low" | "expired" | "waiting" | undefined;
  let label = "expires in";
  let text = "";
  if (waiting || left === null) {
    state = "waiting";
    label = "Waiting:";
    text = "not opened yet";
  } else if (left === 0) {
    state = "expired";
    label = "";
    text = "expired";
  } else {
    text = compactDuration(left);
    const lowAt = windowSecs ? Math.max(60, windowSecs * 0.25) : 60;
    if (left < 60 || left <= lowAt) state = "low";
  }
  return (
    <>
      <div className="countdown" role="timer" aria-label="Time left" data-state={state}>
        {label ? <span className="label">{label}</span> : null}
        <span className="countdown__time">{text}</span>
      </div>
      {announce ? (
        <span className="sr-only" aria-live="polite">
          {msg}
        </span>
      ) : null}
    </>
  );
}
