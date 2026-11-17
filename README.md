# kubevpn

A single local SOCKS5/HTTP port that routes each request to the tunnel you choose by domain suffix.

It is a small desktop front-end (Rust + egui) around battle-tested proxy engines: it keeps several
tunnel profiles alive, exposes one mixed proxy port, and decides per connection which profile to use.

```
client (browser, kubectl, curl)
        |
        v
  127.0.0.1:3080   <- one mixed port: SOCKS5 or HTTP, auto-detected
        |
        +-- *.internal.example.com  --> profile A (AmneziaWG via awg-wireproxy)
        +-- *.corp.example.net      --> profile B (Xray)
        +-- everything else         --> direct (or a profile you pick)
```

## Features

- One listening port that speaks both SOCKS5 and HTTP (detected from the first byte).
- Routing by domain suffix, configurable in the UI; the default route is configurable too.
- Profiles can be imported from the clipboard, from a file, by drag and drop, or from a
  subscription URL (the app asks for the `v2rayNG` user agent, which most panels answer with JSON).
- Three engines, each running as a managed sidecar process:
  - AmneziaWG through [awg-wireproxy](https://github.com/bropines/awg-wireproxy)
  - Xray-compatible JSON (including REALITY and `finalmask` if your build supports it)
  - sing-box JSON
- Live reconfiguration: adding, enabling or removing a profile takes effect without a restart.
- The listening address is editable in the window: changing it restarts only the listener, tunnels keep
  running. It can also be overridden at launch with `--listen`.
- Tray icon with a menu (show window / start / stop / quit). Closing the window hides it to the tray
  instead of quitting; disable that with `minimize_to_tray: false`.
- `launch at login` checkbox (HKCU Run key on Windows, LaunchAgent on macOS, autostart entry on Linux).
- Everything slow runs in the background: engine downloads and sidecar starts never block the UI.
- Per-profile status in the list, a `restart` button, and automatic restart 5 seconds after a sidecar
  exits unexpectedly.
- Duplicate configs are skipped on import, so re-importing a subscription does not multiply profiles.
- A warning appears when a route (or the default route) points at a profile that is not running.
- Routes pointing at a stopped profile are skipped, so traffic falls back to direct instead of
  hitting a dead port.
- Per-request log in the window and in `%TEMP%\kubevpn-app.log`; each sidecar writes its own log
  to `%TEMP%\kubevpn-profiles\<id>.log`.

## Platform support

The application itself is cross-platform: the UI is egui/eframe, HTTP is done with `ureq`, and stale
sidecar cleanup uses `sysinfo`. Platform-specific behaviour (hiding the console of child processes) is
isolated behind a small `#[cfg(windows)]` helper.

| platform | status |
|---|---|
| Windows 10/11 | primary target, tested |
| Linux (X11 / Wayland) | builds in CI, needs a GPU/GL stack for the window |
| macOS | builds in CI |

Engine binaries are separate executables, so on each platform you need builds of the engines you
actually use: `wireproxy` (`wireproxy.exe` on Windows), `xray`, `sing-box`. Paths are configured in
the app and are not built into it.

## Installing the engines

The app can fetch them itself from GitHub releases: each engine row in the settings has an
`install` button. It asks the GitHub API for the latest release, picks the asset that matches your OS
and architecture, downloads it, verifies the SHA-256 when the release publishes `checksums.txt`
(awg-wireproxy does) and unpacks it into:

- Windows: `%LOCALAPPDATA%\kubevpn\engines\<engine>`
- Linux/macOS: `$XDG_DATA_HOME/kubevpn/engines/<engine>` (or `~/.local/share/...`)

The resolved path is written back into `config.json`. For headless setup, launch with
`KUBEVPN_INSTALL_ENGINES=awg,xray,singbox` and the app installs the listed engines on startup.

| engine | source |
|---|---|
| awg-wireproxy | `bropines/awg-wireproxy` |
| xray | `XTLS/Xray-core` |
| sing-box | `SagerNet/sing-box` |

Engines are third-party software with their own licenses; the app only downloads them.

## Requirements

- Rust toolchain.
- On Linux, the usual egui/winit development packages:
  `libgtk-3-dev libxkbcommon-dev libwayland-dev libx11-dev libxi-dev libgl1-mesa-dev`.
- The engine binaries listed above.

## Build

```bash
cargo build --release
```

On Windows either the MSVC toolchain (Visual Studio Build Tools) or the GNU one
(`rustup default stable-x86_64-pc-windows-gnu` plus a MinGW distribution) works.

The binary lands in `target/release/kubevpn.exe` (or `target/<triple>/release/`).
Put `config.json` next to the binary, or run it from the directory that contains the config.

## Command line

```text
kubevpn.exe [--listen <addr>]
```

`--listen` accepts `host:port` or a bare port number. It overrides the value from `config.json` for
this run only; use the `Apply` button in the window to persist a new address.

Environment variables, useful for scripted setup:

| variable | effect |
|---|---|
| `KUBEVPN_IMPORT_URL` | import a subscription on startup |
| `KUBEVPN_INSTALL_ENGINES` | comma-separated engines to install on startup (`awg,xray,singbox`) |
| `KUBEVPN_AUTOSTART` | `1`/`0` — enable or disable launch at login, then exit the setting |

## Tray

The window can be closed to the tray; the tunnels keep running. The tray menu has *Show window*,
*Start tunnels*, *Stop tunnels* and *Quit*. A double click on the icon shows the window.

On Windows the window is minimized and its taskbar button is removed (`WS_EX_TOOLWINDOW`) rather than
hidden with `ShowWindow(SW_HIDE)`. A truly hidden window stops receiving redraws, the egui update loop
stops, and the tray menu would never be processed again. Minimizing keeps the loop alive.

A diagnostic switch `KUBEVPN_TEST_TRAY=1` hides the window after 6 seconds and shows it again after
12, which is handy when checking this behaviour without clicking the tray.

## Configuration

`config.json` is written by the app. Copy `config.example.json` and fill in your own values.

| field | meaning |
|---|---|
| `listen` | address of the mixed port, for example `127.0.0.1:3080`; editable in the window |
| `autostart` | start the tunnels and the listener immediately on launch |
| `binaries.awg` / `binaries.xray` / `binaries.singbox` | paths to engine executables |
| `profiles[]` | `id`, `name`, `kind` (`awg` / `xray` / `singbox`), `text` (the raw config), `port` (local SOCKS port the engine listens on), `enabled` |
| `rules[]` | `suffix` + `profile` id |
| `default_profile` | profile id for everything that matches no rule, `null` means direct |

The app rewrites the engine config before starting it: for AWG it appends a `[Socks5]` section, for
Xray and sing-box it replaces `inbounds` with a single local SOCKS inbound on `profile.port`.
Everything else in your config is preserved.

## Import

- **Clipboard / file / drag and drop** accept a single config, an array of configs, or an INI file.
- **URL** accepts a subscription link. The request is made with `curl` and the `v2rayNG` user agent;
  when the panel answers with a JSON array, each element becomes a separate profile named after its
  `remarks` field.
- Headless import: set `KUBEVPN_IMPORT_URL` before launching to import a subscription on startup.

## Security

- `config.json` contains private keys and UUIDs. It is listed in `.gitignore` and must never be
  committed. Engine configs generated at runtime are written to `%TEMP%\kubevpn-profiles`, so treat
  that directory as sensitive too.
- The mixed port binds to `127.0.0.1` by default and has no authentication; do not expose it to a
  network.

## Limitations

- Protocols are implemented by the engines, not by this app. A config that needs a feature missing
  from your engine build will fail; the error is shown in the log and in `%TEMP%\kubevpn-app.log`.
- Configs from a sing-box *fork* (for example ones using `finalmask`) do not run on vanilla sing-box.
- SOCKS4 is not supported, because it resolves DNS on the client; use SOCKS5 or HTTP.
- A hard kill of the app can leave sidecars running until the next launch, which cleans them up.

## License

MIT, see [LICENSE](LICENSE).
