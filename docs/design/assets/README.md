# Generated assets

Both images were generated on 13 October 2026 with the Higgsfield CLI
(`higgsfield generate create nano_banana_pro`), using `docs/design/screenshots/seal.png`
as the style reference so they match the app's pastel neumorphic design.

| File | Job | Parameters |
|---|---|---|
| `banner.png` (3168×1344) | `aaa9eda1-6fa2-4aba-a2ff-2f9a56f1521c` | aspect 21:9, resolution 2k |
| `icon.png` (1024×1024) | `4e0a2a9f-c5a7-4c35-a2fd-b5d0e2ac903f` | aspect 1:1, resolution 1k |

The Tauri icon set under `apps/desktop/src-tauri/icons/` is derived from `icon.png`
with `cd apps/desktop && npx tauri icon ../../docs/design/assets/icon.png` (the Android
and iOS folders it also writes are not used by the desktop app and are not kept). The
earlier pre-generation stand-in, `icon-placeholder.png`, has been removed.

`icon-app.png` is `icon.png` cropped to the wax seal (bbox 234–790 px, 22 % margin) so the
seal fills the canvas: the uncropped tile shrank to a pink dot at 32 px. The Tauri icon set
is generated from `icon-app.png`.
