import { createContext, useContext } from "react";
import type { IdentityInfo, ScreenId } from "./types";

/** Settings as other screens may see them. The deposit token never leaves the Settings form. */
export interface PublicSettings {
  release_service: string | null;
  has_token: boolean;
  scrypt_log_n: number;
  armor: boolean;
  argon2id: boolean;
}

export interface GoOptions {
  /** Keys: move focus to "Create identity" after switching. */
  focusCreate?: boolean;
}

export interface AppCtx {
  /** null while the first get_identity is in flight. */
  identity: IdentityInfo | null;
  setIdentity: (i: IdentityInfo) => void;
  settings: PublicSettings | null;
  refreshSettings: () => Promise<PublicSettings | null>;
  /** Screen currently shown. */
  screen: ScreenId;
  go: (s: ScreenId, opts?: GoOptions) => void;
  /** Short outcome for the polite live region ("Copied."). Never pass secrets. */
  announce: (msg: string) => void;
  /** Incremented each time Keys should focus its Create button. */
  focusCreateTick: number;
}

export const AppContext = createContext<AppCtx | null>(null);

export function useApp(): AppCtx {
  const c = useContext(AppContext);
  if (!c) throw new Error("AppContext missing");
  return c;
}
