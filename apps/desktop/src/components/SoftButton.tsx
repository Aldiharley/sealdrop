import type { ButtonHTMLAttributes, MouseEvent, ReactNode, Ref } from "react";

interface SoftButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, "disabled" | "onClick"> {
  variant?: "default" | "primary" | "pink";
  size?: "sm";
  block?: boolean;
  /** Operation in progress: aria-disabled, shows `busyLabel` (default "…"). */
  loading?: boolean;
  busyLabel?: string;
  /** Cannot be used right now. Stays focusable; give the reason via aria-describedby. */
  unavailable?: boolean;
  onClick?: (e: MouseEvent<HTMLButtonElement>) => void;
  ref?: Ref<HTMLButtonElement>;
  children: ReactNode;
}

/**
 * Raised pill button. Unavailable controls use aria-disabled (never native `disabled`) so they
 * stay in the tab order and their reason text can be read; the click is ignored.
 */
export function SoftButton({
  variant = "default",
  size,
  block,
  loading,
  busyLabel = "…",
  unavailable,
  onClick,
  className,
  children,
  type = "button",
  ...rest
}: SoftButtonProps) {
  const off = !!(loading || unavailable);
  const cls = [
    "neu-btn",
    variant !== "default" ? `neu-btn--${variant}` : "",
    size === "sm" ? "neu-btn--sm" : "",
    block ? "neu-btn--block" : "",
    className ?? "",
  ]
    .filter(Boolean)
    .join(" ");
  return (
    <button
      {...rest}
      type={type}
      className={cls}
      aria-disabled={off || undefined}
      onClick={(e) => {
        if (off) {
          e.preventDefault();
          return;
        }
        onClick?.(e);
      }}
    >
      {loading ? busyLabel : children}
    </button>
  );
}

interface LinkButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, "onClick"> {
  onClick?: () => void;
  children: ReactNode;
}

/** Underlined text button (Show, Hide, Remove, Clear, disclosures). */
export function LinkButton({ onClick, className, children, type = "button", ...rest }: LinkButtonProps) {
  return (
    <button {...rest} type={type} className={`link-btn${className ? ` ${className}` : ""}`} onClick={() => onClick?.()}>
      {children}
    </button>
  );
}
