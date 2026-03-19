# Windows installer (client only)

## Prerequisites
- CMake 3.20+
- Visual Studio 2022 Build Tools (C++ workload)
- Qt 6 (Widgets) with `windeployqt` in PATH
- OpenSSL (DLLs available on PATH or discoverable by CMake)
- NSIS (for `.exe` installer)

## Build and package
```powershell
cmake -S . -B build-win -G "Visual Studio 17 2022" -A x64 \
  -DBUILD_CLIENT=ON -DBUILD_GUI=ON -DBUILD_SERVER=OFF -DBUILD_ADMIN=OFF

cmake --build build-win --config Release

cpack --config build-win/CPackConfig.cmake -C Release
```

The NSIS installer will appear inside `build-win`.

## Notes
- The installer bundles `config/client.conf` and `config/server.crt` (if present in the repo).
- Replace `config/server.crt` with your CA certificate or adjust `config/client.conf` after install.
