import { useId } from "react";
import type { ReactNode, Ref } from "react";

interface TileProps {
  title?: ReactNode;
  /** Ref to the heading, for moving focus to it (e.g. "Sealed."). */
  headingRef?: Ref<HTMLHeadingElement>;
  /** Make the heading programmatically focusable (tabIndex -1). */
  headingFocusable?: boolean;
  /** Heading rendered in a lead (success headline) style instead of the small label style. */
  headingClass?: string;
  className?: string;
  children?: ReactNode;
  role?: string;
  "aria-label"?: string;
}

/** A calm raised container. The title is an h2 styled as a label; the section is labelled by it. */
export function Tile({ title, headingRef, headingFocusable, headingClass = "label", className, children, ...rest }: TileProps) {
  const id = useId();
  return (
    <section className={`neu-tile${className ? ` ${className}` : ""}`} aria-labelledby={title ? id : undefined} {...rest}>
      {title ? (
        <h2 id={id} ref={headingRef} className={headingClass} tabIndex={headingFocusable ? -1 : undefined} style={{ margin: "0 0 12px" }}>
          {title}
        </h2>
      ) : null}
      {children}
    </section>
  );
}
