// Inline two-tone SVG glyphs (dusty pink #E8A9AD + periwinkle #8FA4C9, details cut out in #EEEBE6).
// All decorative: aria-hidden, always next to a text label or an aria-label on the button.

const PINK = "#E8A9AD";
const BLUE = "#8FA4C9";
const BG = "#EEEBE6";
const INK = "#3B3B40";

interface GlyphProps {
  size?: number;
  className?: string;
}

function svg(size: number, viewBox: string, className?: string) {
  return { viewBox, width: size, height: size, "aria-hidden": true as const, className, focusable: false as const };
}

export function NavSeal({ size = 32 }: GlyphProps) {
  return (
    <svg {...svg(size, "0 0 32 32")}>
      <rect x="4" y="8" width="24" height="17" rx="6" fill={BLUE} />
      <path d="M7 12.5 16 19l9-6.5" fill="none" stroke={BG} strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx="22.5" cy="22" r="6" fill={PINK} />
    </svg>
  );
}

export function NavOpen({ size = 32 }: GlyphProps) {
  return (
    <svg {...svg(size, "0 0 32 32")}>
      <rect x="4" y="16" width="24" height="12" rx="5" fill={BLUE} />
      <rect x="9" y="4" width="14" height="15" rx="4" fill={PINK} />
      <path d="M16 8v6m-3-2.5 3 3 3-3" fill="none" stroke={BG} strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function NavVerify({ size = 32 }: GlyphProps) {
  return (
    <svg {...svg(size, "0 0 32 32")}>
      <path
        d="M16 4.5 25.5 8v7.5c0 6-4.2 10.2-9.5 12-5.3-1.8-9.5-6-9.5-12V8z"
        fill={BLUE}
        stroke={BLUE}
        strokeWidth="3"
        strokeLinejoin="round"
      />
      <circle cx="16" cy="16" r="6.5" fill={PINK} />
      <path d="m13 16.2 2.2 2.2 4-4.4" fill="none" stroke={BG} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function NavKeys({ size = 32 }: GlyphProps) {
  return (
    <svg {...svg(size, "0 0 32 32")}>
      <circle cx="11" cy="16" r="7.5" fill={PINK} />
      <circle cx="11" cy="16" r="2.8" fill={BG} />
      <rect x="16" y="13.8" width="13" height="4.6" rx="2.3" fill={BLUE} />
      <rect x="23" y="18" width="3.4" height="5.2" rx="1.5" fill={BLUE} />
    </svg>
  );
}

export function NavSettings({ size = 32 }: GlyphProps) {
  return (
    <svg {...svg(size, "0 0 32 32")}>
      <rect x="4" y="6" width="24" height="4.4" rx="2.2" fill={BLUE} />
      <rect x="4" y="13.8" width="24" height="4.4" rx="2.2" fill={BLUE} />
      <rect x="4" y="21.6" width="24" height="4.4" rx="2.2" fill={BLUE} />
      <circle cx="11" cy="8.2" r="4.6" fill={PINK} />
      <circle cx="21" cy="16" r="4.6" fill={PINK} />
      <circle cx="13" cy="23.8" r="4.6" fill={PINK} />
    </svg>
  );
}

/** Brand mark: pink disc with a blue droplet cut-out. Not a button. */
export function Brand({ size = 44 }: GlyphProps) {
  return (
    <svg {...svg(size, "0 0 32 32")}>
      <circle cx="16" cy="16" r="14" fill={PINK} />
      <path d="M16 7.5c3.2 4 5.2 6.6 5.2 9.2a5.2 5.2 0 0 1-10.4 0c0-2.6 2-5.2 5.2-9.2z" fill={BLUE} />
    </svg>
  );
}

export function GlyphOk({ size = 20 }: GlyphProps) {
  return (
    <svg {...svg(size, "0 0 24 24")}>
      <circle cx="12" cy="12" r="11" fill="#A8C9B8" />
      <path d="m7 12.5 3.2 3.2L17 9" fill="none" stroke={INK} strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function GlyphWarn({ size = 20 }: GlyphProps) {
  return (
    <svg {...svg(size, "0 0 24 24")}>
      <circle cx="12" cy="12" r="11" fill="#F3E7D3" stroke={INK} strokeWidth="1.5" />
      <path d="M12 7v6.5M12 17v.2" fill="none" stroke={INK} strokeWidth="2.4" strokeLinecap="round" />
    </svg>
  );
}

export function GlyphErr({ size = 20 }: GlyphProps) {
  return (
    <svg {...svg(size, "0 0 24 24")}>
      <circle cx="12" cy="12" r="11" fill={PINK} />
      <path d="m8.5 8.5 7 7m0-7-7 7" fill="none" stroke={INK} strokeWidth="2.4" strokeLinecap="round" />
    </svg>
  );
}

export function GlyphFolder({ size = 20 }: GlyphProps) {
  return (
    <svg {...svg(size, "0 0 32 32")}>
      <rect x="3" y="7" width="12" height="8" rx="3" fill={PINK} />
      <rect x="3" y="11" width="26" height="16" rx="5" fill={BLUE} />
    </svg>
  );
}

export function GlyphFile({ size = 20 }: GlyphProps) {
  return (
    <svg {...svg(size, "0 0 32 32")}>
      <rect x="6" y="3" width="20" height="26" rx="5" fill={PINK} />
      <path d="M18 3h2a6 6 0 0 1 6 6v0a3 3 0 0 1-3 3h-2a3 3 0 0 1-3-3z" fill={BLUE} />
    </svg>
  );
}

export function GlyphCopy({ size = 20 }: GlyphProps) {
  return (
    <svg {...svg(size, "0 0 24 24")}>
      <rect x="8" y="8" width="13" height="13" rx="4" fill={BLUE} />
      <rect x="3" y="3" width="13" height="13" rx="4" fill={PINK} />
    </svg>
  );
}

export function GlyphLock({ size = 20 }: GlyphProps) {
  return (
    <svg {...svg(size, "0 0 24 24")}>
      <path d="M8 11V8a4 4 0 0 1 8 0v3" fill="none" stroke={PINK} strokeWidth="3" strokeLinecap="round" />
      <rect x="4" y="10" width="16" height="12" rx="4" fill={BLUE} />
    </svg>
  );
}

export function GlyphClock({ size = 20 }: GlyphProps) {
  return (
    <svg {...svg(size, "0 0 24 24")}>
      <circle cx="12" cy="12" r="9" fill="none" stroke={BLUE} strokeWidth="3" />
      <path d="M12 7v5l3 2" fill="none" stroke={PINK} strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function GlyphChevron({ size = 12, open = false }: GlyphProps & { open?: boolean }) {
  return (
    <svg {...svg(size, "0 0 12 12")} style={{ transform: open ? "rotate(90deg)" : undefined }}>
      <path d="m4 2 4 4-4 4" fill="none" stroke={BLUE} strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function GlyphCross({ size = 12 }: GlyphProps) {
  return (
    <svg {...svg(size, "0 0 12 12")}>
      <path d="m3 3 6 6m0-6-6 6" fill="none" stroke={INK} strokeWidth="2" strokeLinecap="round" />
    </svg>
  );
}
