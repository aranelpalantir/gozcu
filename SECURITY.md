# Security policy / Güvenlik politikası

## Reporting a vulnerability / Açık bildirme

Please **do not open a public issue** for security problems. Use GitHub's private reporting instead:
**Security tab → "Report a vulnerability"** on this repository. Include steps to reproduce and the Windows/Python version.
I'll acknowledge reports as time allows; this is a hobby project maintained on a best-effort basis.

Güvenlik sorunları için herkese açık issue açmayın; bu deponun **Security sekmesinden → "Report a vulnerability"** ile özel bildirim yapın.

## Supported versions

Only the latest commit on `main` / the latest release.

## Threat model (what the tool does and does not defend)

- The web UI listens on `127.0.0.1` only, validates the `Host` header and requires a per-run random token for every state-changing request. It is **not** meant to be exposed to a network or reverse-proxied.
- Anything running as your user can reach `127.0.0.1`; the tool does not protect itself against malware already running on the same machine.
- Actions that change the system (firewall rules, process termination, scheduled task) require the dashboard to be started as administrator.
- Telegram bot tokens are encrypted with Windows DPAPI (current Windows account only) and are never sent back to the browser.

## Dual-use note

Gözcü is a defensive/monitoring tool for your **own** computer. Do not use it on systems you do not own or administer.
