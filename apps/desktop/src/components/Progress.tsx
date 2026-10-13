/** Pill progress track. Without `value` it is indeterminate; the phase text beside it names the activity. */
export function Progress({ label, value }: { label: string; value?: number }) {
  if (value === undefined) {
    return (
      <div className="progress" role="progressbar" aria-label={label} data-indeterminate="true">
        <div className="progress__bar" />
      </div>
    );
  }
  const v = Math.max(0, Math.min(100, Math.round(value)));
  return (
    <div
      className="progress"
      role="progressbar"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={v}
      style={{ ["--p" as string]: `${v}%` }}
    >
      <div className="progress__bar" />
    </div>
  );
}
