# Security Notes

This client applies best-effort protections that depend on the OS and desktop environment.

## Clipboard
- Secure mode enforces a clipboard size limit (configurable via `clipboard_max_bytes`).
- Data that exceeds the limit (or file/image data) is cleared and triggers automatic re-encryption.
- The OS clipboard cannot be fully blocked; other processes may still access it.

## Screenshots
- Windows: uses `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)`.
- macOS: not implemented in this reference build.
- Linux (X11): not supported by the OS; Wayland provides better isolation.

## Memory
- Decrypted files are stored only in RAM via `SecureBuffer`.
- Pages are locked where possible and cleared on release.
- Core-dump exclusion is attempted on Linux.

## Temp files
- Optional temp-file mode writes decrypted data to a temporary path for external tools.
- Temp files are removed on terminate/reencrypt in this reference build.
- Location is OS-dependent (`/dev/shm` preferred on Linux).

## Network
- The client only connects to the configured server.
- OS-level firewall restrictions are not enforced by this app.
