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
- Routing by domain suffix, IP or CIDR (10.0.0.0/8, 2001:db8::/32), configurable in the UI;
  the longest suffix / longest prefix wins regardless of rule order. The default route is
  configurable too.
- Profiles can be imported from the clipboard, from a file, by drag and drop, or from a
  subscription URL (the app asks for the `v2rayNG` user agent, which most panels answer with JSON).
  Share-URI subscriptions are understood too: plain or base64-encoded lists of
  vless://, vmess://, trojan:// and ss:// links are converted to Xray configs.
- Three engines, each running as a managed sidecar process:
  - AmneziaWG through [awg-wireproxy](https://github.com/bropines/awg-wireproxy)
  - Xray-compatible JSON (including REALITY and `finalmask` if your build supports it)
  - sing-box JSON
- Live reconfiguration: adding, enabling or removing a profile takes effect without a restart.
- The mixed port speaks SOCKS5 (CONNECT and UDP ASSOCIATE) and HTTP (CONNECT plus absolute
  requests with keep-alive), so applications that need UDP — voice chat, games, QUIC — can be
  pointed at it too. SOCKS4 is deliberately not supported (it resolves DNS on the client).
- The listening address is editable in the window: changing it restarts only the listener, tunnels keep
  running. It can also be overridden at launch with `--listen`.
- Tray icon with a menu (show window / start / stop / quit). Closing the window hides it to the tray
  instead of quitting; disable that with `minimize_to_tray: false`. The icon reflects the state:
  gray stopped, green running, red when a route target is down or a probe fails; the tooltip shows
  live counters.
- `launch at login` checkbox (HKCU Run key on Windows, LaunchAgent on macOS, autostart entry on Linux).
- Everything slow runs in the background: engine downloads, sidecar starts and health probes never
  block the UI, and every background result wakes the UI loop directly (no busy repaint timer).
- Per-profile status in the list, `restart`, `test` and `log` buttons, and automatic restart with
  exponential backoff (5s → 10s → … → 5 min) after a sidecar exits unexpectedly; after 8 consecutive
  failures the profile is marked as a crash loop instead of spinning forever.
- Active health probes: every 30s each running profile is probed through its own SOCKS port
  (xray/sing-box end-to-end against a public host, awg by handshake; configurable per profile via
  `probe`). Latency is shown per profile, and 3 consecutive failures restart the sidecar.
- Per-profile traffic counters (connections, bytes up/down) next to each tunnel.
- Duplicate configs are skipped on import, so re-importing a subscription does not multiply profiles.
- Subscriptions are first-class: a URL becomes one entry that owns its profiles, with a `refresh`
  button. Refreshing reconciles the list — configs that appeared are added, changed ones are updated in
  place, and profiles that vanished from the server are removed together with the rules pointing at them.
  Matching goes by the `remarks` name first, then by identical config text, then by position.
  Subscriptions also auto-refresh every 24h by default (`subscription_refresh_hours`, 0 disables)
  and on startup when stale.
- A warning appears when a route (or the default route) points at a profile that is not running.
- Choose what happens in that case: fall back to a direct connection (default) or refuse the
  connection. The checkbox `block traffic when the target profile is down` switches to fail closed,
  which also covers the first seconds after start-up while profiles are still coming up.
- Routes pointing at a stopped profile are skipped, so traffic falls back to direct instead of
  hitting a dead port.
- Optional credentials on the mixed port (SOCKS5 user/pass + HTTP Basic proxy auth); a warning is
  shown when the listener binds a non-loopback address.
- Single instance: a second launch detects the running one and exits instead of fighting over
  sidecars and ports.
- On Windows sidecars live in a job object with kill-on-close: if kubevpn crashes or is killed,
  the OS terminates its sidecars automatically. Stale-sidecar cleanup additionally verifies the
  process start time, so a recycled PID can never kill an unrelated process.
- config.json is saved atomically (temp file + rename) with a .bak generation; a corrupt file is
  preserved as .corrupt and the backup is restored instead of silently starting from scratch.
- Per-request log in the window and in `%TEMP%\kubevpn-app.log` (rotated at 5 MiB, one previous
  generation kept); each sidecar writes its own log to `%TEMP%\kubevpn-profiles\<id>.log`, viewable
  in the app with the `log` button. Request logging can be switched off (`log_requests`).

## Platform support

The application itself is cross-platform: the UI is egui/eframe, HTTP is done with `ureq`, and stale
sidecar cleanup uses `sysinfo`. Platform-specific behaviour (hiding the console of child processes,
the job object, single-instance guard) is isolated behind small `#[cfg(windows)]` helpers.

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
and architecture, downloads it, verifies the SHA-256 against whatever the release publishes
(`checksums.txt`, `sha256sum.txt` or a per-asset `.dgst`; a missing checksum is a visible warning)
and unpacks it into a per-version folder, so a running binary is never overwritten and previous
versions remain for rollback:

- Windows: `%LOCALAPPDATA%\kubevpn\engines\<engine>\<version>`
- Linux/macOS: `$XDG_DATA_HOME/kubevpn/engines/<engine>/<version>` (or `~/.local/share/...`)

If a binary is already configured, `install` asks for a second click before replacing it: the
download is the vanilla release, and a custom build (for example one with `finalmask`) would stop
being used.

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
  `libgtk-3-dev libxkbcommon-dev libwayland-dev libx11-dev libxi-dev libgl1-mesa-dev`,
  plus `libxdo-dev` for the clipboard (`arboard`).
- The engine binaries listed above.

## Build

```bash
cargo build --release
```

On Windows either the MSVC toolchain (Visual Studio Build Tools) or the GNU one
(`rustup default stable-x86_64-pc-windows-gnu` plus a MinGW distribution) works.

The binary lands in `target/release/kubevpn.exe` (or `target/<triple>/release/`).
Put `config.json` next to the binary, or run it from the directory that contains the config.
Without a portable config the per-user directory is used: `%APPDATA%\kubevpn` on Windows,
`~/Library/Application Support/kubevpn` on macOS, `$XDG_CONFIG_HOME/kubevpn` (or `~/.config/kubevpn`)
on Linux.

## CI

The workflow runs on a self-hosted Linux runner with the labels `self-hosted`, `linux`, `x64`:

- `fmt + clippy` — `cargo fmt --all --check` and `cargo clippy --all-targets -- -D warnings`;
- `tests` — `cargo test --locked` (unit tests plus end-to-end proxy tests on ephemeral ports);
- `build` — release build, the binary is uploaded as an artifact;
- `release` — on a `v*` tag, packs the artifact and publishes a GitHub Release.

The runner machine needs the Linux dependencies listed above. GitHub-hosted runners are not used:
the account that owns this repository has a billing lock, so `windows-latest` and `macos-latest`
jobs were dropped. When billing is resolved, they can be added back by extending the `runs-on`
of each job into a matrix.

Registering a runner (once):

```bash
mkdir -p /opt/actions-runner && cd /opt/actions-runner
curl -fsSL -o runner.tar.gz https://github.com/actions/runner/releases/download/v<version>/actions-runner-linux-x64-<version>.tar.gz
tar xzf runner.tar.gz
./config.sh --url https://github.com/<owner>/<repo> --token <registration-token> \
  --name <name> --labels self-hosted,linux,x64 --unattended --replace
```

Then run `./run.sh` as a systemd service, or `./svc.sh install && ./svc.sh start`.

## Local checks

The same three checks run by CI can be executed locally:

```bash
./scripts/check.sh        # Linux and macOS
```

```powershell
./scripts/check.ps1       # Windows
```

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
| `KUBEVPN_AUTOSTART` | `1`/`0` — enable or disable launch at login on startup |

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
| `profiles[]` | `id`, `name`, `kind` (`awg` / `xray` / `singbox`), `text` (the raw config), `port` (local SOCKS port the engine listens on), `enabled`, `probe` |
| `profiles[].probe` | health-probe target `host:port`; omit for the kind default (xray/sing-box probe a public host end-to-end, awg handshakes only), `""` for handshake-only |
| `rules[]` | `suffix` (domain, IP or CIDR) + `profile` id; longest match wins |
| `default_profile` | profile id for everything that matches no rule, `null` means direct |
| `subscriptions` | remote lists: `id`, `name`, `url`, the `profiles` they own, `last_refresh` |
| `fail_closed` | `false` (default): a rule whose target profile is down falls back to direct; `true`: such traffic is refused |
| `minimize_to_tray` | closing the window keeps the app running in the tray |
| `auth` | optional `{ "user": ..., "pass": ... }` required on the mixed port (SOCKS5 user/pass + HTTP Basic); `null` keeps it open |
| `log_requests` | log every proxied request (default `true`) |
| `subscription_refresh_hours` | auto-refresh interval, default 24, `0` disables |

The app rewrites the engine config before starting it: for AWG it appends a `[Socks5]` section, for
Xray and sing-box it replaces `inbounds` with a single local SOCKS inbound on `profile.port`.
Everything else in your config is preserved.

## Import

- **Clipboard / file / drag and drop** accept a single config, an array of configs, or an INI file.
- **URL** accepts a subscription link. The request is made with `ureq` and the `v2rayNG` user agent;
  when the panel answers with a JSON array, each element becomes a separate profile named after its
  `remarks` field. Plain or base64-encoded URI lists (vless/vmess/trojan/ss) work as well.
- Headless import: set `KUBEVPN_IMPORT_URL` before launching to import a subscription on startup.

## Security

- `config.json` contains private keys and UUIDs. It is listed in `.gitignore` and must never be
  committed. Engine configs generated at runtime are written to `%TEMP%\kubevpn-profiles` and are
  deleted on stop/exit (logs are kept); treat that directory as sensitive while the app runs.
- The mixed port binds to `127.0.0.1` by default and has no authentication unless `auth` is set;
  do not expose it to a network without credentials.

## Limitations

- Protocols are implemented by the engines, not by this app. A config that needs a feature missing
  from your engine build will fail; the error is shown in the log and in `%TEMP%\kubevpn-app.log`.
- Configs from a sing-box *fork* (for example ones using `finalmask`) do not run on vanilla sing-box.
- SOCKS4 is not supported, because it resolves DNS on the client; use SOCKS5 or HTTP.
- On Windows a hard kill of the app terminates its sidecars via the job object. On other platforms
  a hard kill can leave sidecars running until the next launch, which cleans them up.
- Absolute-form HTTP requests with a body use a single-shot connection (Connection: close);
  bodyless requests support keep-alive and origin-connection reuse.

## License

MIT, see [LICENSE](LICENSE).
