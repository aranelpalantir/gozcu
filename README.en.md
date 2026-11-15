# Gözcü — Windows network & system monitor

![Gözcü](gozcu.svg)

[Türkçe](README.md) · **English**

Gözcü ("watchman" in Turkish; formerly *SysDash*) is a local Windows dashboard that shows what is happening on your machine at a glance:
processes, network connections, per-process traffic, DNS queries and the Windows Firewall. It runs a small web server on `127.0.0.1` only and,
by default, sends nothing off your computer. The one exception is **Telegram notifications**, which you opt into and which go only to your own bot.
Country/ASN lookups use an offline database, so lookups never leave your machine.

> **Status: beta (v0.1.x).** Some admin-only features (country blocking, start-at-boot, firewall restore) have had limited testing.
> The user interface is in **Turkish**. See [SECURITY.md](SECURITY.md) to report bugs or vulnerabilities.

> **Warning:** the dashboard can add/remove firewall rules, cut your internet access and terminate processes. Use it only on your own machine and
> only if you understand what each action does. A firewall backup is taken automatically before risky actions. Provided as is, without warranty (MIT).

## Features

- **Processes:** CPU/memory/IO, digital signature status, parent chain, command line, SHA-256, a 0–100 risk score, and rules for suspicious command lines
  (encoded PowerShell, download-and-run, LOLBin abuse, Office → shell chains).
- **Network:** all TCP/UDP connections, listening ports with a risk database, per-process and per-connection traffic via Windows **ETW** (no driver needed),
  DNS queries per process, country/ASN of remote addresses, daily traffic history.
- **Alerts:** new/unusual destinations, high sustained upload, first-time internet access by a program, new countries, beaconing, DGA/DNS-tunnelling patterns,
  suspicious remote ports, unsigned programs going online. Optional desktop and Telegram notifications.
- **Firewall tools:** rule health analysis (over-broad allows, risky listening ports, dead/duplicate/conflicting rules), one-click disable or restrict a rule's
  remote addresses, backup/restore (`netsh advfirewall export/import`), change monitoring, block a program / IP / country, and a one-click "cut internet" switch with an auto-restore timer.
- **Alert management:** per-alert *Mute* (per process + type, reversible, also silences Telegram), a persistent **alert history** (`alerts.jsonl`), and **timed program blocks** (15 min / 1 h / 4 h / permanent, auto-removed).
- **Other:** startup items and services, disk usage and large-file finder, security checklist, light/dark theme, command palette (`Ctrl+K`).

## Requirements & running

- Windows 10/11, 64-bit Python 3.10+, and `psutil` (`start.bat` installs it if missing).
- `start.bat` runs it as a normal user; `start-admin.bat` runs it elevated (**recommended** — ETW, firewall and start-at-boot need administrator rights).
- Open `http://127.0.0.1:8799` (the next free port is used if 8799 is busy; override with the `SYSDASH_PORT` environment variable).
- Optional: put the free [DB-IP Lite](https://db-ip.com/db/lite.php) country/ASN files in `geodata/` (see [geodata/README.md](geodata/README.md)); without them everything works except the country/organization columns.

## Prebuilt .exe (no Python needed)

Download `Gozcu.exe` from [Releases](https://github.com/aranelpalantir/gozcu/releases) and double-click it; the dashboard opens in your browser (no console window).

- **Admin mode:** ETW network monitoring, firewall tools and start-at-boot need administrator rights — right-click → *Run as administrator*, or use the in-app *restart as administrator* button.
- **Your data** (settings, backups, history) lives in `%LOCALAPPDATA%\Gozcu`. Put the optional `geodata` folder there or next to `Gozcu.exe`.
- **SmartScreen / antivirus:** the exe is **not code-signed**, so Windows SmartScreen may warn (*More info → Run anyway*) and some antivirus products may flag PyInstaller-packed tools that touch the firewall/network. Compare against `Gozcu.exe.sha256`, or inspect the code and build it yourself with `build.ps1` (64-bit Python; output `dist\Gozcu.exe`). Release files are built from this repository by GitHub Actions.

## Privacy & local files

Local data files (`telegram.json` — Telegram token encrypted with Windows DPAPI, `nettraffic.json`, `baseline.json`, `fw_snapshot.json`, `backups/`) stay on your machine
and are excluded from the repository by `.gitignore`. Firewall rule names keep the legacy `SysDash` prefix so that existing rules are not orphaned after the rename.

## License

MIT. IP data: [IP Geolocation by DB-IP](https://db-ip.com), CC BY 4.0.
