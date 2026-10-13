import { useEffect, useRef, useState } from "react";
import type { RefObject } from "react";
import { api } from "./api";
import type { DragDropEvent } from "./types";

// One window-level drag-and-drop subscription shared by every drop target. Tauri reports the
// pointer in physical pixels, so each event is hit-tested against the visible target rectangles.
// A target on a hidden screen has an empty rectangle and never matches.

interface Target {
  el: () => HTMLElement | null;
  onPaths: (paths: string[]) => void;
  setOver: (over: boolean) => void;
}

const targets = new Set<Target>();
let started: Promise<() => void> | null = null;

function hit(t: Target, pos: { x: number; y: number }): boolean {
  const el = t.el();
  if (!el || el.offsetParent === null) return false;
  const r = el.getBoundingClientRect();
  if (r.width === 0 || r.height === 0) return false;
  const dpr = window.devicePixelRatio || 1;
  const x = pos.x / dpr;
  const y = pos.y / dpr;
  return x >= r.left && x <= r.right && y >= r.top && y <= r.bottom;
}

function handle(e: DragDropEvent) {
  if (e.type === "leave") {
    targets.forEach((t) => t.setOver(false));
    return;
  }
  // Prefer the smallest matching rectangle so a zone inside a tile wins over the tile.
  let best: Target | null = null;
  let bestArea = Infinity;
  for (const t of targets) {
    if (!hit(t, e.position)) continue;
    const r = t.el()!.getBoundingClientRect();
    const area = r.width * r.height;
    if (area < bestArea) {
      best = t;
      bestArea = area;
    }
  }
  for (const t of targets) t.setOver(e.type !== "drop" && t === best);
  if (e.type === "drop" && best) best.onPaths(e.paths);
}

function ensureStarted() {
  if (!started) started = api.onDragDrop(handle);
}

/**
 * Registers `ref` as a drop target. `enabled` should be false while the owner is busy or its
 * screen is hidden. Returns whether a drag is currently over the element.
 */
export function useDropTarget(
  ref: RefObject<HTMLElement | null>,
  onPaths: (paths: string[]) => void,
  enabled: boolean,
): boolean {
  const [over, setOver] = useState(false);
  const cb = useRef(onPaths);
  cb.current = onPaths;

  useEffect(() => {
    if (!enabled) {
      setOver(false);
      return;
    }
    ensureStarted();
    const t: Target = { el: () => ref.current, onPaths: (p) => cb.current(p), setOver };
    targets.add(t);
    return () => {
      targets.delete(t);
    };
  }, [ref, enabled]);

  return over;
}
