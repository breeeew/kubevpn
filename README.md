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
- Routes pointing at a stopped profile are skipped, so traffic falls back to direct instead of
  hitting a dead port.
- Per-request log in the window and in `%TEMP%\kubevpn-app.log`; each sidecar writes its own log
  to `%TEMP%\kubevpn-profiles\<id>.log`.

## Requirements

- Windows 10/11. The code uses Windows-specific process flags; other platforms are not supported yet.
- The engine binaries are **not bundled**. Point the app at the ones you have:
  `wireproxy.exe`, `xray.exe`, `sing-box.exe`.
- Rust toolchain to build.

## Build

```powershell
rustup default stable-x86_64-pc-windows-gnu   # or the MSVC toolchain with Visual Studio Build Tools
cargo build --release
```

The binary lands in `target/release/kubevpn.exe` (or `target/<triple>/release/`).
Put `config.json` next to the binary, or run it from the directory that contains the config.

## Configuration

`config.json` is written by the app. Copy `config.example.json` and fill in your own values.

| field | meaning |
|---|---|
| `listen` | address of the mixed port, for example `127.0.0.1:3080` |
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
