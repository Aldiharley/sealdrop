import { useEffect, useRef } from "react";
import QRCode from "qrcode";

/** QR rendered client-side into a canvas (dark modules on white, 4-module quiet zone). Decorative. */
export function Qr({ text }: { text: string }) {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const c = ref.current;
    if (!c) return;
    QRCode.toCanvas(c, text, {
      width: 336,
      margin: 4,
      errorCorrectionLevel: "M",
      color: { dark: "#000000", light: "#ffffff" },
    })
      .then(() => {
        // The library sizes the canvas in CSS pixels too; keep it at 168 (the bitmap is 2x for sharpness).
        c.style.width = "168px";
        c.style.height = "168px";
      })
      .catch(() => {});
    return () => {
      c.getContext("2d")?.clearRect(0, 0, c.width, c.height);
    };
  }, [text]);
  return (
    <div className="qr" aria-hidden="true">
      <canvas ref={ref} />
    </div>
  );
}
