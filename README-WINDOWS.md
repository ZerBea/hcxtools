# hcxtools — native Windows build

This fork adds an **optional native Windows (x64) build** of the core *offline*
[hcxtools](https://github.com/ZerBea/hcxtools) utilities, produced with
[MSYS2](https://www.msys2.org/) / mingw-w64.

> Upstream marks Windows as unsupported. This is a **community/optional** build
> for users who need to convert and inspect captures on Windows without WSL.
> hcxtools is © ZeroBeat and MIT licensed; that license is retained here.

## What builds

| Tool | Purpose |
|------|---------|
| `hcxpcapngtool` | convert `pcapng` / `pcap` / `cap` → hashcat/JtR hash formats (mode 22000) |
| `hcxpmktool` | PMK / PMKID calculation and verification |
| `hcxpsktool` | generate PSK candidates |
| `hcxwltool` | wordlist filtering (digits-only, length, case) |
| `hcxeiutool` | ESSID / identity helpers |
| `hcxhash2cap` | convert a hash line back to `cap` |

The network- and potfile-oriented tools (`hcxhashtool`, `hcxpottool`,
`whoismac`, `wlancap2wpasec`) are intentionally **not** part of this build —
they depend on `pwd.h` / `pthread` / `libcurl` and add a large DLL tree for
little benefit on Windows.

## How the port works

The upstream C sources are **not modified**. Windows support is provided by:

1. `windows/win_shim.h` — a force-included header supplying BSD `strsep()`,
   which the mingw C runtime lacks. Guarded by `#ifdef _WIN32`.
2. Linking `-lws2_32` — Windows provides `ntohs` / `ntohl` in the sockets
   library rather than libc.

That's the whole port: one tiny compat header + one link flag, applied only on
Windows via build flags.

## Build locally (MSYS2)

```bash
# in an MSYS2 MINGW64 shell, from the repo root
pacman -S --needed --noconfirm \
  make mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl \
  mingw-w64-x86_64-zlib mingw-w64-x86_64-pkgconf

make hcxpcapngtool hcxpmktool hcxpsktool hcxwltool hcxeiutool hcxhash2cap \
  CPPFLAGS="-include windows/win_shim.h" \
  LDFLAGS="-lws2_32"
```

The resulting `.exe` files need `libcrypto-3-x64.dll` and `zlib1.dll`
(from `/mingw64/bin`) next to them, or on `PATH`.

## Build in CI (recommended)

`.github/workflows/windows.yml` builds everything on `windows-latest`, bundles
the required DLLs + a `SHA256SUMS.txt`, and:

- **Actions → Windows build → Run workflow** → download the zipped binaries as an artifact, or
- push a tag like `v7.1.2-win1` → a **GitHub Release** is created automatically with the zip and checksums.

## License

hcxtools is distributed under the MIT license, © 2000–2026 ZeroBeat. See
`license.txt`. For authorized security auditing and educational use only.

Windows build support (the compat shim, the CI workflow, and this document)
© 2026 Ahmad Al-Ahmad (github.com/Obsidian-Strike), under the same MIT terms.
