# Automation & Protection Toolkit

A personal Windows automation + security toolkit built on **AutoHotkey v2** for a developer's daily workflow (tests, git, clipboard, windows, browsers) and a defense-in-depth security suite (audits, remediation, tamper-evident logging, USB/network/hosts/clipboard/logon watchers, backups, panic key).

It **complements, never replaces** Windows Defender / EDR. No telemetry, no auto-updates, no hidden persistence beyond the documented Task Scheduler entries.

---

## Status

| Area | Status |
|---|---|
| Core library (`Lib\Core.ahk` + Toast/JSON/Crypto/UIA/CDP) | ✅ shipped, test-validated (26/26 smoke tests) |
| `Scripts\Launcher.ahk` (tray host) | ✅ shipped, selftest clean |
| `Tests\Test-Core.ahk` | ✅ shipped, green |
| Productivity tools (DevHotkeys, TextExpander, ClipboardManager, WindowManager, GitWorkflow, BrowserAutomation, FocusMode, CommandPalette, HealthHUD, DevEnvDoctor) | 🚧 in progress |
| Security suite (SecurityCheck, Remediate, PersistenceMonitor, USBGuard, NetworkWatch, HostsGuard, ClipboardGuard, SecretsScanner, LogonWatch, PrivacyMonitor, BackupGuardian, PanicKey) | 🚧 in progress |
| Installer + Task Scheduler (`Install\Install.ps1`, logon + weekly XMLs) | 🚧 in progress |

The hotkey table below lists the full planned surface; keys marked 🚧 activate once their tool ships.

---

## Prerequisites

- **AutoHotkey v2** installed at `C:\Program Files\AutoHotkey\v2\AutoHotkey64.exe` (verify: `& 'C:\Program Files\AutoHotkey\v2\AutoHotkey64.exe' /?`).
- Windows 10/11 (PowerShell 5.1 is used as the engine for system queries, crypto and CDP — no extra modules).
- Admin rights only where a tool says so (SecurityCheck/Remediate/HostsGuard/LogonWatch run elevated).

---

## Quick start — using it right now

1. **Run the smoke test** (validates the foundation):
   ```powershell
   & 'C:\Program Files\AutoHotkey\v2\AutoHotkey64.exe' 'E:\Projects\automation_scripts\Tests\Test-Core.ahk'
   ```
   Expect `RESULT: 26 passed, 0 failed`.

2. **Start the Launcher** (tray icon with every tool):
   ```powershell
   & 'C:\Program Files\AutoHotkey\v2\AutoHotkey64.exe' 'E:\Projects\automation_scripts\Scripts\Launcher.ahk'
   ```
   - `--safe-mode` → security tools only.
   - Left-click the tray icon: start/stop each tool (checkboxes persist in `Config\settings.ini`), open Logs, open this README, run the elevated Security Check, Panic, Exit All.
   - **Kill-switch (every tool): `Esc` + `Pause`** — exits the script immediately; `Esc` itself keeps working.

3. **Tools you run once** (not via Launcher):
   ```powershell
   # Weekly posture audit (elevated) → Logs\SecurityReport.html + .json
   Start-Process -Verb RunAs 'C:\Program Files\AutoHotkey\v2\AutoHotkey64.exe' -ArgumentList 'E:\Projects\automation_scripts\Security\SecurityCheck.ahk','--standalone'
   ```

4. **Start at logon** (once `Install\` ships, or manually): create a Task Scheduler task
   *Run only when user is logged on, 30-second delay, restart on failure*, Action:
   `C:\Program Files\AutoHotkey\v2\AutoHotkey64.exe` with argument
   `E:\Projects\automation_scripts\Scripts\Launcher.ahk`, Start-in `E:\Projects\automation_scripts`.
   (`Install\Install.ps1` will do this + the weekly audit task automatically.)

---

## Hotkey reference

Scope `A` = global; `VS Code` = only when a VS Code window is active; `Term` = terminal/IDE windows.

| Tool | Hotkey | Action | Scope | Config key (`[hotkeys]`) |
|---|---|---|---|---|
| Launcher | tray menu | start/stop tools, logs, panic | tray | — |
| every tool | `Esc`+`Pause` | kill-switch (clean exit + log line) | A | — |
| DevHotkeys 🚧 | `Win+Alt+T` | run tests for the current project (npm/pnpm/yarn, dotnet, pytest, cargo, go, forge/hardhat) | VS Code | `run_tests` |
| DevHotkeys 🚧 | `Win+Alt+B` | open project in Git GUI / terminal | VS Code | `git_gui` |
| DevHotkeys 🚧 | `Win+Alt+C` | copy current file path (+`Shift` relative, +`Ctrl` path:line) | VS Code | `copy_path` |
| DevHotkeys 🚧 | `Win+Alt+K` | kill the process on a port (confirm first) | A | `kill_port` |
| DevHotkeys 🚧 | `Win+Alt+P` | print PID/cmdline of the process on a port | A | `print_port` |
| DevHotkeys 🚧 | `Win+Alt+E` | open the project's `.env.example` (never `.env`) | VS Code | `open_env_example` |
| ClipboardManager 🚧 | `Win+Shift+C` | clipboard history menu (select / pin) | A | `clip_menu` |
| ClipboardManager 🚧 | `Win+Shift+V` | cycle-paste through history | A | `clip_cycle` |
| ClipboardManager 🚧 | `Win+Shift+X` | clear all history | A | `clip_clear` |
| WindowManager 🚧 | `Win+Numpad0` / `Win+Numpad1` | restore / save window layout | A | — |
| WindowManager 🚧 | `Win+Alt+←→↑↓` | half/quarter snapping | A | — |
| WindowManager 🚧 | `Win+Alt+M` | move window to next monitor | A | — |
| GitWorkflow 🚧 | (menu) | smart commit, branch switcher, cleanup, rebase pull | Term/IDE | — |
| BrowserAutomation 🚧 | `Win+Alt+J` / `F` / `S` | Jira/PR from branch · form fill · table→TSV | browser | `browser_jira/fill/scrape` |
| FocusMode 🚧 | `Win+Alt+F12` | toggle Do-Not-Disturb + block distractions | A | `focus_mode` |
| CommandPalette 🚧 | `Ctrl+Alt+Space` | fuzzy launcher (tools, actions, snippets) | A | `palette` |
| HealthHUD 🚧 | `Win+Alt+H` | CPU/RAM/disk/net/VPN overlay | A | `health_hud` |
| DevEnvDoctor 🚧 | `Win+Alt+D` | toolchain + dependency-vulnerability report | A | `dev_doctor` |
| SecretsScanner 🚧 | `Win+Alt+9` | scan configured roots for hardcoded secrets | A | `secrets_scan` |
| PrivacyMonitor 🚧 | `Win+Alt+Q` | mute/unmute system microphone | A | `privacy_mute` |
| PanicKey 🚧 | `Ctrl+Alt+Shift+Pause` | lock, mute mic, purge clipboard, cut network | A | `panic` |

**Hotkey conflicts already resolved for you:** clipboard menu avoids `Win+V` (Windows history); Git GUI uses `Win+Alt+B` (Game Bar uses `Win+Alt+G`/`Win+Alt+R` on some builds). Edit any binding in `Config\settings.ini` → `[hotkeys]`, then restart the tool or the Launcher.

---

## Snippets (TextExpander 🚧)

Type these in any app (Space/Enter/Tab triggers): `;gitpush` · `;pr` · `;shrug` · `;date` · `;iso` · `;uuid` · `;commit` · `;ty`. Add your own in `Config\snippets.ini` (no code changes):

```ini
[mine]
trigger=;sig
expansion=Best regards,\n{username}
mode=clipboard
```

Placeholders: `{date} {time} {iso} {branch} {clipboard} {cursor} {uuid} {username}`.

---

## Config

| File | What it controls |
|---|---|
| `Config\settings.ini` | hotkeys, tool enable flags, clipboard/backup/panic options, ntfy alerts |
| `Config\snippets.ini` | text-expansion triggers |
| `Config\windowlayout.ini` | window layouts (IDE left / browser monitor 2 / terminal quarter) |
| `Config\ignorelist.ini` | clipboard-excluded apps, trusted USB serials, browser allow-list |
| `Config\formfill.json` | browser form-fill definitions (secret fields use `cred:<target>`) |

**Secrets never live in config.** Store them in Windows Credential Manager, e.g.:
```powershell
cmdkey /generic:AHK-ntfy /user:token /pass:<your-ntfy-token>
```
(Enable push alerts with `[alerts] ntfy_enabled=1` + `ntfy_url`.)

---

## Data, logs, audit trail

- `Logs\` — per-tool rotating logs (2 MB × 5). `Logs\SecurityReport.html/.json` from audits.
- `Data\` — encrypted clipboard history (DPAPI, CurrentUser scope), baselines, remediation backups. **Never commit this folder** (gitignored).
- Security events go to a **tamper-evident chain** (`Logs\audit-*.log`): each line is SHA-256-linked to the previous. `VerifyLogChain()` detects edits — the test suite proves it catches a tampered line.

## Security model

- **Least privilege**: only SecurityCheck/Remediate/HostsGuard/LogonWatch ask for admin, and they say why.
- **No network calls** except what you configure (ntfy push, localhost CDP, your Jira/GitHub).
- **Destructive actions always confirm** and are recorded in the audit chain.
- **Limits** (per tool): pattern-based SecretsScanner can miss obfuscated secrets; ClipboardGuard's hijack window is heuristic (~3 s); LogonWatch is event-log based (log clearing is itself alerted); BackupGuardian is only as safe as your offline copy — if the backup disk is always connected, rotate one offline.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Hotkey does nothing | Another app took it (Game Bar, PowerToys). Check `Settings > Apps > Installed apps` and remap in `[hotkeys]`. |
| Hotkeys ignored in an elevated window | Your tool is not elevated and UAC blocks it. Run that tool elevated (Task Scheduler elevated variant). |
| Defender/AV flags the scripts | AHK scripts are a common false positive. Add `E:\Projects\automation_scripts` to Defender exclusions, or run the `.ahk` files directly (no compiled exe). |
| PowerShell errors | The toolkit uses `-ExecutionPolicy Bypass` for its own process-scope calls only; your machine policy is untouched. |
| No tray icon | The tool was started with `--child` (Launcher child). Use the Launcher's tray menu, or start the tool standalone. |
| Dialogs pop on script start | `#Warn All, StdOut` is set — warnings print to stdout, never dialog. If you see an AHK error dialog, read it and file it; it's a load-time error. |
| Chrome debug port refused | BrowserAutomation needs Chrome/Edge started with `--remote-debugging-port=9222` + a **dedicated** `--user-data-dir` (never your main profile; port stays on 127.0.0.1). See the tool's setup dialog. |

## Development

- Run the suite: `AutoHotkey64.exe Tests\Test-Core.ahk` (exit 0 = green).
- Every script carries the standard header, kill-switch, `SafeWrap`ped hotkeys, and `--selftest`.
- **v2 gotchas this codebase follows** (bought with debugging hours): no single-quoted strings; literal quotes via `` `" ``; comparisons always `==`; `#Warn All, StdOut`; `-File` (not `-Command`) for PowerShell; 1-based string indexes; libraries included after the functions they depend on.

## How to extend

1. Add a file `Scripts\MyTool.ahk` with the standard header (see any tool), `InstallKillSwitch("...")`, and `if ArgHas("--selftest") { Log("selftest OK", "TEST"); ExitApp(0) }`.
2. Register it in `Lib\Core.ahk` → `Tools.Register({name: "MyTool", script: "Scripts\MyTool.ahk", category: "Productivity", desc: "...", hotkeys: [...], enabled: true, admin: false})`.
3. Bind hotkeys with `BindHotkey(Cfg.Read("hotkeys", "my_key", "Win+Alt+Z"), MyAction, "MyTool action")`.
4. Add config keys to `Config\settings.ini` and read via `Cfg.Read/Bool/Int`.
5. Add a `--selftest` path and a smoke case in `Tests\`.

Security checks plug into the same pattern: one function per check returning `{id, title, status, severity, evidence, remediation_id, safe_to_autofix}` → `SecurityReport.json` → `Remediate.ahk`.

## Update / uninstall

- Update: `git pull` in `E:\Projects\automation_scripts`, then re-run `Install\Install.ps1`.
- Uninstall: `Install\Uninstall.ps1` removes the scheduled tasks and ACLs; delete the folder to remove everything (your `Data\` and `Logs\` are local-only).
