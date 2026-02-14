# p2p-chat (Linux, C++20, Boost.Asio)

Two small terminal programs:

- `rendezvous_server`: presence/discovery server (never relays chat content)
- `p2p_chat_gui`: Qt6 desktop chat client (friends list + chat pane)

## Build (Ubuntu/Debian)

Suggested packages:

```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libboost-system-dev libssl-dev
```

Notes:
- JSON uses a vendored `nlohmann/json.hpp` in `third_party/nlohmann/json.hpp` (no system package required).

Build:

```bash
make -j
```

`-march=native`:
- Enabled by default for local `make` builds.
- Auto-disabled on GitHub Actions (`GITHUB_ACTIONS=true`).
- Override with `make NATIVE_ARCH=0 -j` (disable) or `make NATIVE_ARCH=1 -j` (enable).

Qt GUI build (Qt6 Widgets):

```bash
sudo apt-get install -y qt6-base-dev qt6-base-dev-tools qt6-multimedia-dev libopus-dev
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/p2p_chat_gui
```

CMake also enables `-march=native` by default for local non-CI, non-cross builds.
Override with `-DP2PCHAT_ENABLE_MARCH_NATIVE=OFF`.

## Cross-compile to Windows (from Linux)

Most reliable: build on Windows (or CI Windows runner). Cross-compiling from Linux works best with **MXE** (MinGW + Qt).

High-level MXE steps:

1) Build MXE toolchain + deps (Qt6, OpenSSL, Boost).
2) Configure this project with MXE’s `mxe-conf.cmake`.
3) Build `p2p_chat_gui.exe` (and optionally `rendezvous_server.exe`).
4) Bundle Qt DLLs via `windeployqt` (from the same Qt toolchain).

Example (MXE, 64-bit, shared):

```bash
git clone https://github.com/mxe/mxe.git ~/mxe
cd ~/mxe
make MXE_TARGETS='x86_64-w64-mingw32.shared' qt6-qtbase openssl boost

cd /path/to/p2p-chat
cmake -S . -B build-win \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_TOOLCHAIN_FILE=~/mxe/usr/x86_64-w64-mingw32.shared/share/cmake/mxe-conf.cmake
cmake --build build-win -j
```

After build, run MXE’s `windeployqt` on `p2p_chat_gui.exe` to collect required Qt DLLs into a distributable folder (zip that folder to send to friends).

## Build on Windows (MSYS2)

This is often simpler than cross-compiling:

1) Install MSYS2, open **MSYS2 MinGW x64** shell
2) Install deps:

```bash
pacman -Syu
pacman -S --needed \
  mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake mingw-w64-x86_64-ninja \
  mingw-w64-x86_64-qt6-base mingw-w64-x86_64-qt6-multimedia mingw-w64-x86_64-opus \
  mingw-w64-x86_64-boost mingw-w64-x86_64-openssl \
  mingw-w64-x86_64-pkgconf
```

3) Build + bundle:

```bash
cmake -S . -B build-win -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-win
mkdir dist
cp build-win/p2p_chat_gui.exe dist/
windeployqt --release --no-translations dist/p2p_chat_gui.exe
```

## Run

Server (public VPS):

```bash
./rendezvous_server 0.0.0.0 5555
```

Clients:

```bash
./build/p2p_chat_gui
# or force runtime debug logs
P2PCHAT_DEBUG=1 ./build/p2p_chat_gui
# or
./build/p2p_chat_gui --debug
```

Profiles:
- On startup, the GUI shows a profile picker (qTox-style): select existing profile or create a new one.
- New profiles can be created with optional password protection (encrypts `identity.pem` at rest).
- Legacy single-profile data in `~/.config/p2p-chat` is auto-migrated to `~/.config/p2p-chat/profiles/<name>/`.
- Headless migration only:

```bash
QT_QPA_PLATFORM=offscreen ./build/p2p_chat_gui --migrate-profiles
```

CLI profile selection:

```bash
./build/p2p_chat --profile default
./build/p2p_chat --profile secure --profile-password 'your-password'
```

Both GUI and CLI read profile data from the same profile directory and therefore share the same ID/key for that profile.

Voice calls:
- Requires Qt6 Multimedia + Opus.
- Use the top-right `Call` button in a chat; configure devices/bitrate via `Options -> Audio Settings...`.

IDs and names:
- Each user has a cryptographic shareable ID (`Your ID:`) derived from their Ed25519 public key.
- Each profile stores its identity key as `identity.pem` in its own profile directory.
- Your name is only shared with peers after they accept your friend request and you establish a direct P2P connection.

Encryption:
- P2P traffic is end-to-end encrypted and authenticated (X25519 + HKDF-SHA256 + ChaCha20-Poly1305), with peer authentication via Ed25519 signatures (your ID).
- The rendezvous server channel is not encrypted (it never relays chat content, only discovery + requests).

Discovery / UDP:
- Clients publish their current UDP endpoint to rendezvous and connect peer-to-peer via UDP hole punching.
- Rendezvous stores observed address + UDP mapping only; it does not maintain a TCP reachability flag.
