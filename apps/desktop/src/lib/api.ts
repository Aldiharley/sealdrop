import type * as T from "./types";

/** True when running inside the Tauri shell; false in a plain browser (mock mode). */
export const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

async function call<R>(cmd: string, args?: Record<string, unknown>): Promise<R> {
  if (!isTauri) {
    const { mock } = await import("./mock");
    return mock(cmd, args) as Promise<R>;
  }
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<R>(cmd, args);
}

/** Commands reject with a plain string; normalise anything else. */
export function errText(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  try {
    return JSON.stringify(e);
  } catch {
    return String(e);
  }
}

/** Raw drag-and-drop events from the window (paths are absolute). */
async function onDragDrop(cb: (e: T.DragDropEvent) => void): Promise<() => void> {
  if (!isTauri) return () => {};
  const { getCurrentWebview } = await import("@tauri-apps/api/webview");
  return getCurrentWebview().onDragDropEvent((e) => {
    const p = e.payload;
    if (p.type === "leave") cb({ type: "leave" });
    else if (p.type === "over") cb({ type: "over", position: { x: p.position.x, y: p.position.y } });
    else if (p.type === "enter") cb({ type: "enter", paths: p.paths, position: { x: p.position.x, y: p.position.y } });
    else if (p.type === "drop") cb({ type: "drop", paths: p.paths, position: { x: p.position.x, y: p.position.y } });
  });
}

export const api = {
  isMock: !isTauri,
  getIdentity: () => call<T.IdentityInfo>("get_identity"),
  generateIdentity: (force: boolean, pq = false) => call<T.IdentityInfo>("generate_identity", { force, pq }),
  parseRecipient: (s: string) => call<T.RecipientCheck>("parse_recipient", { s }),
  seal: (req: T.SealArgs) => call<T.SealOut>("seal", { req }),
  probe: (path: string) => call<T.ProbeOut>("probe", { path }),
  verify: (path: string, signer?: string | null) =>
    call<T.VerifyOut>("verify", { path, signer: signer ? signer : null }),
  openPackage: (req: T.OpenArgs) => call<T.OpenOut>("open_package", { req }),
  listTrusted: () => call<T.Trusted[]>("list_trusted"),
  addTrusted: (name: string, key: string) => call<void>("add_trusted", { name, key }),
  removeTrusted: (name: string) => call<void>("remove_trusted", { name }),
  getSettings: () => call<T.Settings>("get_settings"),
  setSettings: (settings: T.Settings) => call<void>("set_settings", { settings }),
  receiptFetch: (manifestPath: string) => call<T.ReceiptOut>("receipt_fetch", { manifestPath }),
  receiptVerify: (receiptPath: string, serviceKey?: string | null) =>
    call<T.ReceiptOut>("receipt_verify", { receiptPath, serviceKey: serviceKey ? serviceKey : null }),

  /** Native file dialog. Returns an absolute path, or null when cancelled. */
  pickFile: async (opts: T.PickOptions = {}): Promise<string | null> => {
    if (!isTauri) {
      const { mockPick } = await import("./mock");
      return mockPick(opts.kind ?? "file");
    }
    const { open } = await import("@tauri-apps/plugin-dialog");
    const r = await open({
      multiple: false,
      directory: false,
      title: opts.title,
      filters: opts.extensions ? [{ name: "Files", extensions: opts.extensions }] : undefined,
    });
    return typeof r === "string" ? r : null;
  },
  /** Native folder dialog. Returns an absolute path, or null when cancelled. */
  pickFolder: async (title?: string, hint: "input" | "output" = "output"): Promise<string | null> => {
    if (!isTauri) {
      const { mockPick } = await import("./mock");
      return mockPick(hint === "input" ? "folder-in" : "folder-out");
    }
    const { open } = await import("@tauri-apps/plugin-dialog");
    const r = await open({ multiple: false, directory: true, title });
    return typeof r === "string" ? r : null;
  },

  /** `progress { kind, detail }` events. Returns an unlisten function. */
  onProgress: async (cb: (p: T.ProgressEvent) => void): Promise<() => void> => {
    if (!isTauri) {
      const { mockListen } = await import("./mock");
      return mockListen(cb);
    }
    const { listen } = await import("@tauri-apps/api/event");
    return listen<T.ProgressEvent>("progress", (e) => cb(e.payload));
  },
  onDragDrop,
  /** Convenience: dropped paths only. */
  onDrop: (cb: (paths: string[]) => void): Promise<() => void> =>
    onDragDrop((e) => {
      if (e.type === "drop") cb(e.paths);
    }),
};
