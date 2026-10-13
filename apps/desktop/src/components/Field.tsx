import { useId, useState } from "react";
import type { CSSProperties, KeyboardEvent, ReactNode, Ref } from "react";
import { LinkButton } from "./SoftButton";

type AnyControl = HTMLInputElement & HTMLTextAreaElement & HTMLSelectElement;

interface FieldProps {
  label: ReactNode;
  value: string;
  onChange?: (v: string) => void;
  helper?: ReactNode;
  error?: ReactNode;
  as?: "input" | "textarea" | "select";
  type?: "text" | "password" | "number";
  placeholder?: string;
  disabled?: boolean;
  readOnly?: boolean;
  mono?: boolean;
  rows?: number;
  options?: { value: string; label: string }[];
  onBlur?: () => void;
  onEnter?: () => void;
  inputRef?: Ref<AnyControl>;
  /** Placed beside the control (a Copy, Add or Choose button). */
  action?: ReactNode;
  /** Visually hide the label but keep it for assistive tech. */
  hideLabel?: boolean;
  min?: number;
  inputMode?: "numeric" | "text";
  className?: string;
  /** Extra id to include in aria-describedby (e.g. a notice). */
  describedBy?: string;
  controlStyle?: CSSProperties;
  /** Mark invalid without a message (the message lives elsewhere). */
  invalid?: boolean;
}

/**
 * Label above an inset control, with helper and error linked by aria-describedby. Password
 * fields get a Show / Hide link button with aria-pressed. Errors set aria-invalid.
 */
export function Field({
  label,
  value,
  onChange,
  helper,
  error,
  as = "input",
  type = "text",
  placeholder,
  disabled,
  readOnly,
  mono,
  rows,
  options,
  onBlur,
  onEnter,
  inputRef,
  action,
  hideLabel,
  min,
  inputMode,
  className,
  describedBy,
  controlStyle,
  invalid: forceInvalid,
}: FieldProps) {
  const id = useId();
  const helperId = `${id}-h`;
  const errorId = `${id}-e`;
  const [shown, setShown] = useState(false);
  const isPassword = type === "password";
  const desc = [helper ? helperId : "", error ? errorId : "", describedBy ?? ""].filter(Boolean).join(" ") || undefined;
  const cls = `neu-inset${mono ? " mono" : ""}${as === "select" ? " field__unit" : ""}`;
  const invalid = error || forceInvalid ? (true as const) : undefined;
  const handleKey = (e: KeyboardEvent) => {
    if (e.key === "Enter" && onEnter) {
      e.preventDefault();
      onEnter();
    }
  };
  let control: ReactNode;
  if (as === "select") {
    control = (
      <select
        id={id}
        className={cls}
        aria-invalid={invalid}
        aria-describedby={desc}
        disabled={disabled}
        style={controlStyle}
        ref={inputRef as Ref<HTMLSelectElement>}
        value={value}
        onChange={(e) => onChange?.(e.target.value)}
        onBlur={onBlur}
      >
        {options?.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    );
  } else if (as === "textarea") {
    control = (
      <textarea
        id={id}
        className={cls}
        aria-invalid={invalid}
        aria-describedby={desc}
        disabled={disabled}
        style={controlStyle}
        ref={inputRef as Ref<HTMLTextAreaElement>}
        rows={rows ?? 2}
        value={value}
        readOnly={readOnly}
        spellCheck={false}
        placeholder={placeholder}
        onChange={(e) => onChange?.(e.target.value)}
        onBlur={onBlur}
      />
    );
  } else {
    control = (
      <input
        id={id}
        className={cls}
        aria-invalid={invalid}
        aria-describedby={desc}
        disabled={disabled}
        style={controlStyle}
        ref={inputRef as Ref<HTMLInputElement>}
        type={isPassword && shown ? "text" : type}
        value={value}
        readOnly={readOnly}
        placeholder={placeholder}
        autoComplete="off"
        spellCheck={false}
        min={min}
        inputMode={inputMode}
        onChange={(e) => onChange?.(e.target.value)}
        onBlur={onBlur}
        onKeyDown={handleKey}
      />
    );
  }
  return (
    <div className={`field${className ? ` ${className}` : ""}`}>
      <label className={hideLabel ? "sr-only" : "label"} htmlFor={id}>
        {label}
      </label>
      {isPassword || action ? (
        <div className="field__row">
          {control}
          {isPassword ? (
            <LinkButton aria-pressed={shown} onClick={() => setShown((v) => !v)}>
              {shown ? "Hide" : "Show"}
            </LinkButton>
          ) : null}
          {action}
        </div>
      ) : (
        control
      )}
      {helper ? (
        <div id={helperId} className="field__helper">
          {helper}
        </div>
      ) : null}
      {error ? (
        <div id={errorId} className="field__error">
          {error}
        </div>
      ) : null}
    </div>
  );
}
