# Cipheator

Secure client-server file encryption system (C++17). This repository contains:

- `client/` Qt-based GUI client (optional CLI client placeholder)
- `server/` TLS server that performs crypto and key storage
- `admin/` Qt-based admin console for alerts/logs
- `common/` shared libraries (protocol, crypto helpers, secure memory)

## Dependencies

- CMake 3.20+
- C++17 compiler
- OpenSSL 1.1.1+ (TLS + AES-GCM/ChaCha20-Poly1305 + SHA-2/SHA-3 + PBKDF2)
- Qt 6 (Widgets) for GUI client
- Qt 6 (Widgets) for admin console

## Build

```bash
cmake -S . -B build \
  -DBUILD_CLIENT=ON \
  -DBUILD_SERVER=ON \
  -DBUILD_GUI=ON \
  -DBUILD_ADMIN=ON
cmake --build build
```

If Qt 6 is not available, set `-DBUILD_GUI=OFF` and implement the CLI client (stub included).

## Server setup

1. Create TLS cert and key:

```bash
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes
```

2. Place cert/key paths in `config/server.conf`.
3. Initialize a user:

```bash
./cipheator-server --init-user admin StrongPassword123
```

## Run

```bash
./cipheator-server
./cipheator-client
./cipheator-admin
```

## Client metadata

Encrypted files use a single-file container format with an embedded header that stores
metadata (cipher, hash, key storage, IV/tag, file_id, hash_value). Legacy `.cph/.key`
sidecars are still accepted for backward compatibility.

## Supported crypto profiles

Encryption (client UI):
- AES-256-GCM, AES-192-GCM, AES-128-GCM
- ChaCha20-Poly1305
- AES-256-CTR, AES-256-CFB, AES-256-OFB, AES-256-CBC
- DES-CBC, DES-ECB (legacy/demo)
- KUZNECHIK, MAGMA (GOST via external CLI binaries)

Hashing:
- SHA-256, SHA-512
- SHA3-256, SHA3-512
- BLAKE2b-512
- STREEBOG-256 (if OpenSSL GOST digest is available)

For GOST ciphers the UI provides conditional mode selection for demo scenarios.
The actual encryption mode is defined by your external GOST binary implementation.

## Admin console

Set `admin_token` in `config/server.conf` and add devices in the admin console.
The admin API runs on `admin_host/admin_port` using TLS and requires the token.
Devices are stored in `config/admin_devices.conf`.
Admin client TLS settings are in `config/admin.conf`.

Alerts include:
- suspicious login time
- 3+ failed logins in a time window
- bulk file operations in a short window

Thresholds are configurable in `config/server.conf`.

## Integrity checks

When a `file_id` is present, the server verifies integrity on decrypt by recomputing
the stored hash. If the hash doesn't match, the server returns an error and logs
an `integrity_failed` alert.

## Anomaly lockouts (optional)

You can configure temporary lockouts for suspicious time, failed logins, or bulk operations
via the `anomaly_*_lock_sec` settings in `config/server.conf`. Set to `0` to disable
blocking (alerts only).

## Temp file mode (optional)

The client can write decrypted data into a temporary file (auto-cleaned on terminate)
to allow external apps (e.g., DB tools) to access data. Enable `decrypt_to_temp=true`
in `config/client.conf` or use the UI toggle.

## GOST CLI integration

The server expects GOST CLI tools:
- `enc_magma` and `dec_magma`
- `enc_kuznechik` and `dec_kuznechik` (optional)

Set their paths in `config/server.conf`. The adapter currently assumes:
- Encryption writes `<input>.enc` and `<input>.key`
- Decryption reads encrypted file and key file

Adjust the config or adapter if your tools use different filenames.

## Streebog hashing

Streebog hashing is attempted via OpenSSL digests (`streebog256` or `md_gost12_256`).
If your OpenSSL build does not include GOST engines, Streebog will fail until you add
an engine/provider that implements GOST 34.11-2012.

## Security notes

This is a reference implementation. Some platform security controls (clipboard, screenshots, firewall) are best-effort and OS-limited.
See `client/SECURITY_NOTES.md` for limitations.
