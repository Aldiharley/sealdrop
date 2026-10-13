import { useEffect, useRef, useState } from "react";
import { api, isTauri } from "./api";
import type { ProgressEvent } from "./types";

/** Query switches for mock mode only (deep links used for screenshots). Empty in the real app. */
export function mockQuery(): URLSearchParams {
  return !isTauri && typeof window !== "undefined" ? new URLSearchParams(window.location.search) : new URLSearchParams();
}

/** Clears a secret after `ms` without any pointer or key activity (default 5 minutes). */
export function useIdleClear(present: boolean, clear: () => void, ms = 5 * 60 * 1000) {
  const clearRef = useRef(clear);
  clearRef.current = clear;
  useEffect(() => {
    if (!present) return;
    let timer = window.setTimeout(() => clearRef.current(), ms);
    const bump = () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(() => clearRef.current(), ms);
    };
    const events = ["keydown", "pointerdown", "pointermove"] as const;
    events.forEach((e) => window.addEventListener(e, bump, { passive: true }));
    return () => {
      window.clearTimeout(timer);
      events.forEach((e) => window.removeEventListener(e, bump));
    };
  }, [present, ms]);
}

/**
 * Latest `progress` event while `active`; null otherwise. The listener is attached for the whole
 * life of the component so no early event is missed when an operation starts.
 */
export function useProgress(active: boolean): ProgressEvent | null {
  const [p, setP] = useState<ProgressEvent | null>(null);
  const activeRef = useRef(active);
  activeRef.current = active;
  useEffect(() => {
    let off: (() => void) | undefined;
    let cancelled = false;
    api
      .onProgress((e) => {
        if (activeRef.current) setP(e);
      })
      .then((u) => {
        if (cancelled) u();
        else off = u;
      });
    return () => {
      cancelled = true;
      off?.();
    };
  }, []);
  useEffect(() => {
    if (!active) setP(null);
  }, [active]);
  return p;
}

/** Runs `fn` once, the first time `cond` becomes true. */
export function useOnceWhen(cond: boolean, fn: () => void) {
  const done = useRef(false);
  const fnRef = useRef(fn);
  fnRef.current = fn;
  useEffect(() => {
    if (cond && !done.current) {
      done.current = true;
      fnRef.current();
    }
  }, [cond]);
}

/** Clipboard write with a fallback for webviews without the async clipboard API. */
export async function writeClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand("copy");
      document.body.removeChild(ta);
      return ok;
    } catch {
      return false;
    }
  }
}
