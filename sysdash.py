#!/usr/bin/env python3
"""
Gözcü (eski adı SysDash) - Windows ağ ve sistem izleme paneli.

Calistirma:  python sysdash.py            (tarayicida http://127.0.0.1:8799 acilir)
Yonetici:    start-admin.bat              (firewall logu, kural ekleme, tum surec bilgileri)
Gereksinim:  python -m pip install psutil
"""
import os
import sys
import json
import time
import queue
import heapq
import ctypes
import base64
import socket
import secrets
import hashlib
import platform
import tempfile
import threading
import ipaddress
import subprocess
import traceback
import webbrowser
import winreg
from collections import deque, Counter
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

try:
    import psutil
except ImportError:
    print("psutil gerekli. Kurmak için:  python -m pip install psutil")
    sys.exit(1)

FROZEN = bool(getattr(sys, "frozen", False))          # PyInstaller ile paketlenmiş .exe mi?
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RES_DIR = getattr(sys, "_MEIPASS", SCRIPT_DIR)        # index.html, ikon (pakete gömülü, salt okunur)
if FROZEN:   # veri dosyaları (ayarlar, yedekler, geçmiş) kalıcı ve yazılabilir bir klasörde durur
    APP_DIR = os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"), "Gozcu")
    os.makedirs(APP_DIR, exist_ok=True)
else:
    APP_DIR = SCRIPT_DIR


def self_command(extra=""):
    """Gözcü'yü yeniden başlatmak için (yürütülebilir, argümanlar, çalışma klasörü)."""
    if FROZEN:
        return sys.executable, extra.strip(), APP_DIR
    return sys.executable, f'"{os.path.abspath(__file__)}" {extra}'.strip(), APP_DIR
PORT = int(os.environ.get("SYSDASH_PORT", "8799"))
INTERVAL = 2.0
TOKEN = secrets.token_hex(16)
NCPU = psutil.cpu_count() or 1
CREATE_NO_WINDOW = 0x08000000
STARTED = time.time()


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


ADMIN = is_admin()

# --------------------------------------------------------------------------
# Port / risk bilgisi
# --------------------------------------------------------------------------
RISKY_PORTS = {
    21: ("FTP", "high", "Şifresiz dosya transferi; anonim erişim ve brute-force hedefi"),
    22: ("SSH", "medium", "Uzaktan erişim; brute-force hedefi"),
    23: ("Telnet", "high", "Şifresiz uzaktan erişim; botnetlerin ana hedefi"),
    25: ("SMTP", "medium", "Açık relay / spam kötüye kullanımı"),
    53: ("DNS", "medium", "DNS amplification saldırıları"),
    69: ("TFTP", "high", "Kimlik doğrulamasız dosya transferi"),
    80: ("HTTP", "low", "Web sunucusu (sifresiz)"),
    111: ("RPCbind", "medium", "RPC servis keşfi"),
    135: ("MS-RPC", "high", "DCOM/RPC sömürüleri (Blaster vb.), yanal hareket"),
    137: ("NetBIOS-NS", "high", "NBNS zehirleme, bilgi sızıntısı"),
    138: ("NetBIOS-DGM", "high", "NetBIOS datagram; bilgi sızıntısı"),
    139: ("NetBIOS-SSN", "high", "NetBIOS üzerinden SMB; yanal hareket"),
    161: ("SNMP", "medium", "Varsayılan community string'ler"),
    389: ("LDAP", "medium", "Dizin bilgisi sızıntısı"),
    443: ("HTTPS", "low", "Sifreli web sunucusu"),
    445: ("SMB", "high", "EternalBlue/WannaCry, SMBGhost; fidye yazılımı yayilimi"),
    1433: ("MSSQL", "high", "Veritabanı brute-force"),
    1434: ("MSSQL Browser", "medium", "SQL sunucu keşfi"),
    1723: ("PPTP", "medium", "Zayıf VPN protokolü"),
    1900: ("SSDP/UPnP", "medium", "UPnP sömürüleri, amplification"),
    2375: ("Docker API", "high", "Kimlik doğrulamasız Docker API = sistemin ele geçirilmesi"),
    3306: ("MySQL", "high", "Veritabanı brute-force"),
    3389: ("RDP", "high", "BlueKeep, brute-force; fidye yazılımlarının 1 numarali giriş kapısı"),
    4444: ("Metasploit", "high", "Metasploit varsayılan dinleyicisi / arka kapı"),
    5000: ("UPnP/Dev", "low", "Geliştirme sunucuları / UPnP"),
    5355: ("LLMNR", "medium", "LLMNR zehirleme (Responder ile parola hash'i çalma)"),
    5432: ("PostgreSQL", "high", "Veritabanı brute-force"),
    5800: ("VNC-HTTP", "high", "VNC web arayuzu"),
    5900: ("VNC", "high", "Zayıf parola, kimlik dogrulama atlatma"),
    5938: ("TeamViewer", "medium", "Uzaktan erişim aracı"),
    5985: ("WinRM", "high", "Uzaktan PowerShell; yanal hareket"),
    5986: ("WinRM-HTTPS", "high", "Uzaktan PowerShell; yanal hareket"),
    6379: ("Redis", "high", "Kimlik doğrulamasız Redis"),
    6667: ("IRC", "high", "Botnet komuta-kontrol kanalı"),
    7070: ("AnyDesk", "medium", "Uzaktan erişim aracı"),
    8080: ("HTTP-Alt", "low", "Proxy / geliştirme sunucusu"),
    9200: ("Elasticsearch", "high", "Kimlik doğrulamasız veri erisimi"),
    11211: ("Memcached", "high", "Amplification saldırıları"),
    12345: ("NetBus", "high", "Klasik arka kapı portu"),
    1337: ("Backdoor", "high", "Arka kapilarin sik kullandigi port"),
    27017: ("MongoDB", "high", "Kimlik doğrulamasız veritabani"),
    31337: ("Back Orifice", "high", "Klasik arka kapı portu"),
}

SUS_REMOTE_PORTS = {
    4444: "Metasploit", 6666: "IRC/C2", 6667: "IRC/C2", 6668: "IRC/C2", 6669: "IRC/C2",
    1337: "Arka kapı", 31337: "Back Orifice", 12345: "NetBus", 9001: "Tor", 9030: "Tor",
    9050: "Tor SOCKS", 9150: "Tor Browser", 23: "Telnet", 445: "SMB (internete)",
    3389: "RDP (internete)", 5900: "VNC (internete)", 135: "RPC (internete)",
}

SYSTEM_NAMES = {
    "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe",
    "wininit.exe", "spoolsv.exe", "taskhostw.exe", "dwm.exe", "conhost.exe", "rundll32.exe",
    "lsm.exe", "explorer.exe", "dllhost.exe", "sihost.exe",
}
WINDIR = os.environ.get("SystemRoot", r"C:\Windows").lower()
SUSPICIOUS_DIRS = ["\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\users\\public\\",
                   "\\$recycle.bin\\", "\\programdata\\temp", "\\downloads\\"]


# --------------------------------------------------------------------------
# Davranış kuralları (komut satırı / üst-alt işlem) ve bilinen işlem sözlüğü
# --------------------------------------------------------------------------
import re
CMD_RULES = [
    ("high", r"(powershell|pwsh)(\.exe)?\"?\s.*\s-(e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}",
     "PowerShell kodlanmış (base64) komut çalıştırıyor"),
    ("high", r"(downloadstring|downloadfile|invoke-webrequest|iwr\s|invoke-restmethod|net\.webclient).*(\biex\b|invoke-expression)"
             r"|(\biex\b|invoke-expression).*(downloadstring|net\.webclient|\biwr\s)",
     "PowerShell internetten indirdiği kodu doğrudan çalıştırıyor"),
    ("warn", r"(powershell|pwsh).*-w(indowstyle)?\s+hidden", "PowerShell gizli pencerede çalışıyor"),
    ("high", r"certutil.*-(urlcache|verifyctl).*https?:|certutil.*-decode", "certutil ile dosya indiriyor/çözüyor (LOLBin kötüye kullanımı)"),
    ("warn", r"bitsadmin.*/transfer", "bitsadmin ile arka planda dosya indiriyor"),
    ("high", r"mshta(\.exe)?\"?\s+(https?:|vbscript:|javascript:)", "mshta uzak/betik içerik çalıştırıyor"),
    ("high", r"regsvr32.*(/i:https?|scrobj\.dll)", "regsvr32 ile uzak betik çalıştırıyor (Squiblydoo tekniği)"),
    ("high", r"rundll32.*(javascript:|mshtml,)", "rundll32 ile betik çalıştırıyor"),
    ("warn", r"wmic.*process\s+call\s+create", "WMI ile yeni işlem başlatıyor"),
    ("high", r"vssadmin.*delete\s+shadows|wmic.*shadowcopy\s+delete|bcdedit.*recoveryenabled\s+no",
     "Yedekleri/kurtarmayı siliyor (fidye yazılımı davranışı)"),
    ("high", r"wevtutil.*\scl\s", "Windows olay günlüklerini siliyor"),
    ("warn", r"\bnet1?(\.exe)?\s+user\s+\S+\s+\S+\s+/add", "Yeni kullanıcı hesabı ekliyor"),
]
CMD_RULES_C = [(lvl, re.compile(rx, re.I), desc) for lvl, rx, desc in CMD_RULES]
OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe",
                  "acrord32.exe", "foxitreader.exe"}
SHELL_CHILDREN = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                  "regsvr32.exe", "rundll32.exe", "certutil.exe", "bitsadmin.exe"}

KNOWN_PROCS = {
    "system": "Windows çekirdeği. Sürücüler ve çekirdek iş parçacıkları burada çalışır.",
    "registry": "Windows kayıt defteri verisini bellekte tutan çekirdek süreci.",
    "memory compression": "Windows'un belleği sıkıştırarak yer açmasını sağlayan normal sistem süreci.",
    "system idle process": "Boştaki işlemci zamanını gösterir; gerçek bir program değildir.",
    "smss.exe": "Oturum Yöneticisi: Windows açılırken oturumları başlatır.",
    "csrss.exe": "Windows istemci/sunucu çalışma zamanı. Kritik; sonlandırılırsa sistem çöker.",
    "wininit.exe": "Windows başlatma süreci; services.exe ve lsass.exe'yi başlatır.",
    "winlogon.exe": "Oturum açma/kapama ve kilit ekranını yönetir.",
    "services.exe": "Windows servislerini başlatan Servis Denetim Yöneticisi.",
    "lsass.exe": "Yerel güvenlik yetkilisi: parolaları ve oturum kimliklerini doğrular. Hedef alan taklitçilere dikkat (yol: System32 olmalı).",
    "svchost.exe": "Birçok Windows servisini barındıran ortak süreç. Çok sayıda kopyası olması normaldir; yol System32 olmalı.",
    "dwm.exe": "Masaüstü Pencere Yöneticisi: pencerelerin ve efektlerin çizimi.",
    "explorer.exe": "Windows Gezgini: masaüstü, görev çubuğu ve Başlat menüsü.",
    "taskhostw.exe": "Windows görev ana bilgisayarı; arka plan görevlerini barındırır.",
    "sihost.exe": "Shell altyapısı (bildirimler, görev görünümü).",
    "ctfmon.exe": "Klavye düzeni ve metin girişi hizmeti.",
    "conhost.exe": "Konsol penceresi ana bilgisayarı; cmd/PowerShell pencerelerine eşlik eder.",
    "fontdrvhost.exe": "Yazı tipi sürücüsü ana bilgisayarı.",
    "runtimebroker.exe": "Mağaza uygulamalarının izinlerini denetler.",
    "searchindexer.exe": "Windows arama dizinleyicisi; dosyaları dizine alır.",
    "searchhost.exe": "Windows Arama arayüzü.",
    "audiodg.exe": "Windows ses aygıtı grafik yalıtımı; ses işleme.",
    "spoolsv.exe": "Yazdırma biriktiricisi. Yazıcı kullanmıyorsanız servisini kapatabilirsiniz.",
    "dllhost.exe": "COM yüzeyi ana bilgisayarı (örn. küçük resim üretimi).",
    "wmiprvse.exe": "WMI sağlayıcı ana bilgisayarı; izleme/yönetim araçları sorgu yaptığında çalışır.",
    "msmpeng.exe": "Microsoft Defender virüsten koruma motoru. Taramalarda CPU kullanması normaldir.",
    "nissrv.exe": "Microsoft Defender ağ denetimi.",
    "securityhealthsystray.exe": "Windows Güvenliği bildirim alanı simgesi.",
    "applicationframehost.exe": "Evrensel (UWP) uygulamaların pencere çerçevesi.",
    "startmenuexperiencehost.exe": "Başlat menüsü arayüzü.",
    "shellexperiencehost.exe": "Görev çubuğu/takvim/saat açılır pencereleri.",
    "textinputhost.exe": "Dokunmatik klavye ve emoji paneli.",
    "backgroundtaskhost.exe": "Mağaza uygulamalarının arka plan görevleri.",
    "msiexec.exe": "Windows Installer: program kurulum/kaldırma.",
    "trustedinstaller.exe": "Windows Modules Installer: sistem güncellemelerini uygular.",
    "tiworker.exe": "Windows güncelleme çalışanı; güncelleme sırasında yoğun çalışabilir.",
    "wudfhost.exe": "Kullanıcı modu sürücü çerçevesi.",
    "chrome.exe": "Google Chrome tarayıcısı. Her sekme/eklenti ayrı süreçtir, çok sayıda olması normaldir.",
    "msedge.exe": "Microsoft Edge tarayıcısı (Chromium). Çok süreçli çalışır.",
    "firefox.exe": "Mozilla Firefox tarayıcısı.",
    "code.exe": "Visual Studio Code düzenleyicisi (Electron, çok süreçli).",
    "node.exe": "Node.js çalışma zamanı: JavaScript programları/geliştirme sunucuları.",
    "python.exe": "Python yorumlayıcısı; çalışan bir betiği yürütüyor. Komut satırından hangi betik olduğuna bakın.",
    "pythonw.exe": "Pencere açmadan çalışan Python yorumlayıcısı.",
    "powershell.exe": "Windows PowerShell komut kabuğu. Komut satırında -enc / indirme gibi ifadeler varsa dikkat.",
    "pwsh.exe": "PowerShell 7+ komut kabuğu.",
    "cmd.exe": "Windows komut istemcisi.",
    "wscript.exe": "Windows Script Host (.vbs/.js dosyaları). Beklenmedik ise inceleyin; zararlılarca sık kullanılır.",
    "cscript.exe": "Konsol tabanlı Windows Script Host; zararlılarca sık kullanılır.",
    "mshta.exe": "HTML Uygulama Ana Bilgisayarı. Nadiren meşrudur; zararlılarca sık kötüye kullanılır.",
    "regsvr32.exe": "DLL kaydetme aracı; uzak betik çalıştırmak için kötüye kullanılabilir.",
    "rundll32.exe": "DLL işlevi çalıştırıcı; zararlılarca sık kullanılır, komut satırına bakın.",
    "certutil.exe": "Sertifika aracı; dosya indirmek için kötüye kullanılabilir.",
    "taskmgr.exe": "Görev Yöneticisi.",
    "notepad.exe": "Not Defteri.",
    "onedrive.exe": "Microsoft OneDrive bulut eşitleme istemcisi.",
    "dropbox.exe": "Dropbox eşitleme istemcisi.",
    "googledrivefs.exe": "Google Drive masaüstü eşitleme istemcisi.",
    "teams.exe": "Microsoft Teams.", "ms-teams.exe": "Microsoft Teams.",
    "slack.exe": "Slack mesajlaşma uygulaması.", "discord.exe": "Discord sohbet uygulaması.",
    "spotify.exe": "Spotify müzik uygulaması.", "steam.exe": "Steam oyun istemcisi.",
    "teamviewer.exe": "TeamViewer uzak erişim aracı. Kendiniz kurmadıysanız şüphelidir.",
    "teamviewer_service.exe": "TeamViewer uzak erişim servisi. Kendiniz kurmadıysanız şüphelidir.",
    "anydesk.exe": "AnyDesk uzak erişim aracı. Kendiniz kurmadıysanız şüphelidir.",
    "docker desktop.exe": "Docker Desktop arayüzü.", "com.docker.backend.exe": "Docker Desktop arka plan servisi.",
    "vmmem": "WSL2/Hyper-V sanal makinesinin ayırdığı bellek.", "wslhost.exe": "WSL (Linux alt sistemi) ana bilgisayarı.",
    "wsl.exe": "Windows Subsystem for Linux başlatıcısı.", "git.exe": "Git sürüm denetimi.",
    "claude.exe": "Claude masaüstü/komut satırı uygulaması.", "codex.exe": "OpenAI Codex komut satırı aracı.",
    "tailscaled.exe": "Tailscale VPN servisi.", "tailscale-ipn.exe": "Tailscale VPN arayüzü.",
}


_B64ENC = re.compile(r"-(?:e|ec|enc|encodedcommand)\s+([A-Za-z0-9+/=]{20,})", re.I)


def own_powershell(name, cmd, ppid):
    """Gözcü'nün kendi (ya da başka bir Gözcü örneğinin) run_ps çağrısı mı? Yanlış alarm vermesin.
    Hem komutun bilinen başlangıcı hem de üst işlemin sysdash.py çalıştırması gerekir (taklit edilemesin)."""
    if not name.lower().startswith("powershell") or not cmd:
        return False
    m = _B64ENC.search(cmd)
    if not m:
        return False
    try:
        raw = m.group(1)
        txt = base64.b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-16-le", "replace")
    except Exception:
        return False
    if not txt.startswith("[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"):
        return False
    try:
        par = psutil.Process(ppid)
        return "sysdash.py" in " ".join(par.cmdline()).lower() or (FROZEN and par.name().lower() == "gozcu.exe")
    except Exception:
        return False


def cmd_scan(pid, created, name, cmd, ppid, snap):
    """Yeni görülen işlemin komut satırını ve üst işlemini şüpheli kalıplara karşı denetler."""
    if ppid == os.getpid() or not name:
        return
    if own_powershell(name, cmd, ppid):
        return
    reasons = []
    if cmd:
        for lvl, rx, desc in CMD_RULES_C:
            if rx.search(cmd):
                reasons.append((lvl, desc))
    par = snap.get(ppid)
    if par and par[1].lower() in OFFICE_PARENTS and name.lower() in SHELL_CHILDREN:
        reasons.append(("high", f"{par[1]} bir komut kabuğu/betik başlattı ({name}); makro veya zararlı belge belirtisi olabilir"))
    if not reasons:
        return
    MON.cmd_flags[(pid, created)] = reasons
    if len(MON.cmd_flags) > 3000:
        MON.cmd_flags.clear()
        MON.cmd_flags[(pid, created)] = reasons
    parname = par[1] if par else ""
    for lvl, desc in reasons:
        MON.add_alert(("cmd", desc, (cmd or name)[:100]), lvl,
                      f'{desc}: {name} (PID {pid}, üst işlem: {parname or "bilinmiyor"})' + (f' — {cmd[:150]}' if cmd else ""),
                      pid=pid, name=name, parent=parname)


def fmt_bytes(n):
    n = float(n)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024


def ip_class(ip):
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return "unknown"
    if getattr(a, "ipv4_mapped", None):
        a = a.ipv4_mapped
    if a.is_unspecified:
        return "any"
    if a.is_loopback:
        return "loopback"
    if a.is_multicast:
        return "multicast"
    if a.is_link_local:
        return "linklocal"
    if a.is_private:
        return "private"
    return "public"


def path_flags(exe, name):
    flags = []
    if not exe:
        return flags
    low = exe.lower()
    for d in SUSPICIOUS_DIRS:
        if d in low:
            flags.append("susp_path")
            break
    n = (name or "").lower()
    if n in SYSTEM_NAMES and not low.startswith(WINDIR):
        flags.append("masquerade")
    return flags


# --------------------------------------------------------------------------
# PowerShell yardimcilari
# --------------------------------------------------------------------------
def run_ps(script, timeout=90, env_extra=None):
    full = ("[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
            "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Continue';" + script)
    enc = base64.b64encode(full.encode("utf-16-le")).decode()
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    r = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-EncodedCommand", enc],
        capture_output=True, timeout=timeout, creationflags=CREATE_NO_WINDOW, env=env)
    return (r.returncode, r.stdout.decode("utf-8", "replace").lstrip("\ufeff"),
            r.stderr.decode("utf-8", "replace"))


def ps_json(script, timeout=90, env_extra=None):
    code, out, err = run_ps(script, timeout, env_extra)
    out = out.strip()
    if not out:
        if err.strip() and code != 0:
            raise RuntimeError(clean_ps_err(err))
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        raise RuntimeError(clean_ps_err(err) or out[:300])
    if isinstance(data, dict):
        data = [data]
    return data


def clean_ps_err(err):
    lines = [l.strip() for l in err.splitlines() if l.strip()]
    if not lines:
        return ""
    if lines[0].startswith("#< CLIXML"):
        return "PowerShell hatasi"
    return lines[0][:300]


class Cached:
    def __init__(self, fn, ttl):
        self.fn, self.ttl = fn, ttl
        self.t, self.v, self.err = 0, None, None
        self.lock = threading.Lock()

    def get(self, force=False):
        with self.lock:
            if force or self.v is None or time.time() - self.t > self.ttl:
                try:
                    self.v = self.fn()
                    self.err = None
                except Exception as e:  # noqa
                    self.err = str(e)
                    if self.v is None:
                        self.v = []
                self.t = time.time()
            return self.v, self.err


# --------------------------------------------------------------------------
# Ters DNS ve imza kontrolu (arka planda)
# --------------------------------------------------------------------------
RDNS = {}
_rdns_q = queue.Queue()


def _rdns_worker():
    while True:
        ip = _rdns_q.get()
        try:
            host = socket.gethostbyaddr(ip)[0]
        except Exception:
            host = ""
        RDNS[ip] = host


def rdns(ip):
    if ip in RDNS:
        return RDNS[ip]
    RDNS[ip] = None
    _rdns_q.put(ip)
    return None


SIG = {}           # exe yolu (lower) -> {"s": durum, "n": imzalayan}
_sig_pending = set()
_sig_lock = threading.Lock()


def sig_request(path):
    if not path:
        return
    k = path.lower()
    with _sig_lock:
        if k not in SIG and k not in _sig_pending:
            _sig_pending.add(path)


def _sig_worker():
    while True:
        time.sleep(3)
        with _sig_lock:
            batch = list(_sig_pending)[:60]
        if not batch:
            continue
        tmp = os.path.join(tempfile.gettempdir(), f"sysdash_sig_{os.getpid()}.json")
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(batch, f)
            res = ps_json(
                "$paths = @(Get-Content -Raw -Encoding UTF8 $env:SYSDASH_ARG | ConvertFrom-Json);"
                " $out = foreach($x in $paths){ $x = [string]$x;"
                " $s = Get-AuthenticodeSignature -LiteralPath $x -ErrorAction SilentlyContinue;"
                " [pscustomobject]@{p=$x; s=\"$($s.Status)\";"
                " n=$(if($s -and $s.SignerCertificate){[string]$s.SignerCertificate.Subject}else{''})} };"
                " $out | ConvertTo-Json -Compress", timeout=180, env_extra={"SYSDASH_ARG": tmp})
            got = set()
            for r in res:
                p = r.get("p") or ""
                signer = r.get("n") or ""
                cn = signer
                if "CN=" in signer:
                    cn = signer.split("CN=", 1)[1].split(",")[0].strip('"')
                SIG[p.lower()] = {"s": r.get("s") or "Unknown", "n": cn}
                got.add(p)
            with _sig_lock:
                for p in batch:
                    if p not in got:
                        SIG[p.lower()] = {"s": "Unknown", "n": ""}
                    _sig_pending.discard(p)
        except Exception:
            traceback.print_exc()
            with _sig_lock:
                for p in batch:
                    SIG[p.lower()] = {"s": "Unknown", "n": ""}
                    _sig_pending.discard(p)
        finally:
            try:
                os.remove(tmp)
            except OSError:
                pass


def sig_of(path):
    if not path:
        return None
    return SIG.get(path.lower())


# --------------------------------------------------------------------------
# Tum surecleri tek bir sistem cagrisiyla oku (psutil'in surec basina
# cagrilarindan ~100 kat hizli). Sadece 64-bit Python.
# --------------------------------------------------------------------------
import struct
_NT_OK = struct.calcsize("P") == 8
if _NT_OK:
    _ntdll = ctypes.WinDLL("ntdll")
    _ntdll.NtQuerySystemInformation.restype = ctypes.c_long
    _ntdll.NtQuerySystemInformation.argtypes = [ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong,
                                                ctypes.POINTER(ctypes.c_ulong)]
_nt_size = 1 << 20


def nt_processes():
    """pid -> (ppid, ad, threads, create_unix, cpu_100ns, rss, private, handles, io_bytes)"""
    global _nt_size
    while True:
        buf = ctypes.create_string_buffer(_nt_size)
        ret = ctypes.c_ulong(0)
        st = _ntdll.NtQuerySystemInformation(5, buf, _nt_size, ctypes.byref(ret)) & 0xFFFFFFFF
        if st == 0xC0000004:
            _nt_size = max(_nt_size * 2, ret.value + 65536)
            continue
        if st != 0:
            raise OSError(f"NtQuerySystemInformation 0x{st:08X}")
        break
    base = ctypes.addressof(buf)
    raw = buf.raw[:ret.value or _nt_size]
    out = {}
    off = 0
    while True:
        nxt, nthr = struct.unpack_from("<II", raw, off)
        ct, ut, kt = struct.unpack_from("<qqq", raw, off + 32)
        nlen, _, nbuf = struct.unpack_from("<HH4xQ", raw, off + 56)
        pid, ppid = struct.unpack_from("<QQ", raw, off + 80)
        handles = struct.unpack_from("<I", raw, off + 96)[0]
        ws = struct.unpack_from("<Q", raw, off + 144)[0]
        priv = struct.unpack_from("<Q", raw, off + 200)[0]
        rt, wt = struct.unpack_from("<qq", raw, off + 232)
        if pid:
            if nbuf and 0 <= nbuf - base < len(raw):
                name = raw[nbuf - base: nbuf - base + nlen].decode("utf-16-le", "replace")
            else:
                name = "System" if pid == 4 else ""
            created = ct / 1e7 - 11644473600 if ct else psutil.boot_time()
            out[pid] = (ppid, name, nthr, created, ut + kt, ws, priv, handles, rt + wt)
        if not nxt:
            break
        off += nxt
    return out


# --------------------------------------------------------------------------
# Canli izleme (monitor) - her INTERVAL saniyede bir ornek alir
# --------------------------------------------------------------------------
class Monitor(threading.Thread):
    HIST = 180

    def __init__(self):
        super().__init__(daemon=True)
        self.lock = threading.Lock()
        H = self.HIST
        self.hist = {k: deque(maxlen=H) for k in ("t", "cpu", "mem", "down", "up", "dread", "dwrite")}
        self.snapshot = {"procs": {}, "conns": [], "nics": {}, "percpu": []}
        self.events = deque(maxlen=4000)
        self.alerts = deque(maxlen=500)
        self.event_id = 0
        self.alert_keys = set()
        self.prev_net = None
        self.prev_nics = None
        self.prev_disk = None
        self.prev_t = None
        self.prev_io = {}
        self.prev_cpu = {}
        self.static = {}
        self.prev_pids = None
        self.prev_conn_keys = None
        self.prev_listen = None
        self.fwlog = deque(maxlen=3000)
        self.fwlog_id = 0
        self.fwlog_pos = None
        self.fwlog_fields = None
        self.fwlog_status = "henüz okunmadı"
        self.fwlog_path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                                       "System32", "LogFiles", "Firewall", "pfirewall.log")
        self.stats = Counter()
        self.ready = False
        self.alert_cool = {}
        self.high_since = {}
        self.last_disk_chk = 0
        self.last_leak_sample = 0
        self.mem_hist = {}
        self.cmd_flags = {}
        self.beacon = {}

    def track_beacon(self, r, now):
        """Aynı işlemin aynı internet adresine düzenli aralıklarla yeniden bağlanması (beacon) tespiti."""
        if len(self.beacon) > 3000:
            self.beacon.clear()
        key = (r["name"].lower(), r["rip"])
        h = self.beacon.setdefault(key, deque(maxlen=24))
        h.append(now)
        if len(h) < 8:
            return
        ts = list(h)
        iv = [b - a for a, b in zip(ts, ts[1:])]
        mean = sum(iv) / len(iv)
        if 15 <= mean <= 1800:
            sd = (sum((x - mean) ** 2 for x in iv) / len(iv)) ** 0.5
            if sd <= max(0.15 * mean, 3.0):
                self.add_alert(("beacon", key), "warn",
                               f'{r["name"]} her ~{mean:.0f} sn\'de bir {r["rip"]}:{r["rport"]} adresine yeniden bağlanıyor. '
                               f'Bu düzenlilik zararlı yazılımların komuta-kontrol (beacon) davranışına benzer; '
                               f'ama normal bir senkronizasyon/telemetri de olabilir',
                               pid=r["pid"], name=r["name"], rip=r["rip"])

    # ---- olaylar
    def add_event(self, kind, level, msg, **data):
        self.event_id += 1
        ev = {"id": self.event_id, "t": time.time(), "kind": kind, "level": level, "msg": msg}
        ev.update(data)
        self.events.append(ev)
        self.stats[kind] += 1
        if kind == "alert":
            persist_alert(ev)
            if NOTIFY is not None:
                try:
                    NOTIFY.push(ev)
                except Exception:
                    pass
        return ev

    @staticmethod
    def _cat(key):
        return key[0] if isinstance(key, tuple) and key and isinstance(key[0], str) else ""

    def add_alert(self, key, level, msg, **data):
        cat = self._cat(key)
        if cat and is_suppressed(cat, data.get("name"), data.get("parent", "")):
            return
        if key in self.alert_keys:
            return
        self.alert_keys.add(key)
        ev = self.add_event("alert", level, msg, cat=cat, **data)
        self.alerts.append(ev)

    def add_alert_cool(self, key, cooldown, level, msg, **data):
        """Tekrarlayabilen uyarı: aynı anahtar için `cooldown` saniye içinde bir kez."""
        cat = self._cat(key)
        if cat and is_suppressed(cat, data.get("name"), data.get("parent", "")):
            return
        now = time.time()
        if now - self.alert_cool.get(key, 0) < cooldown:
            return
        self.alert_cool[key] = now
        ev = self.add_event("alert", level, msg, cat=cat, **data)
        self.alerts.append(ev)

    def watch_resources(self, now, cpu, vm, procs):
        """Kalıcı yüksek CPU/bellek, dolan disk ve olası bellek sızıntısı uyarıları."""
        for name, val, thr, label in (("cpu", cpu, 90, "CPU"), ("mem", vm.percent, 92, "Bellek")):
            if val >= thr:
                self.high_since.setdefault(name, now)
                if now - self.high_since[name] >= 30 and procs:
                    top = max(procs.values(), key=lambda p: p["cpu"] if name == "cpu" else p["mem"])
                    extra = f'{top["cpu"]:.0f}% CPU' if name == "cpu" else fmt_bytes(top["mem"])
                    self.add_alert_cool(("hi", name), 900, "warn",
                                        f'{label} 30 saniyedir %{val:.0f} üzerinde. En çok kullanan: {top["name"]} ({extra})',
                                        pid=top["pid"], name=top["name"])
            else:
                self.high_since.pop(name, None)

        if now - self.last_disk_chk > 60:
            self.last_disk_chk = now
            try:
                for p in psutil.disk_partitions(all=False):
                    if "cdrom" in p.opts or not p.fstype:
                        continue
                    try:
                        u = psutil.disk_usage(p.mountpoint)
                    except OSError:
                        continue
                    if u.percent >= 95:
                        self.add_alert_cool(("disk", p.mountpoint), 6 * 3600, "warn",
                                            f"Disk neredeyse dolu: {p.mountpoint} %{u.percent:.0f} dolu ({fmt_bytes(u.free)} boş)")
            except Exception:
                pass

        if now - self.last_leak_sample >= 30:
            self.last_leak_sample = now
            live = set()
            for pid, pr in procs.items():
                if pr["mem"] < 150 * 1024 * 1024:
                    continue
                key = (pid, round(pr["created"], 1))
                live.add(key)
                h = self.mem_hist.setdefault(key, deque(maxlen=20))
                h.append(pr["mem"])
                if len(h) >= 12:
                    seq = list(h)
                    first, last = seq[0], seq[-1]
                    rising = sum(1 for a, b in zip(seq, seq[1:]) if b >= a * 0.995)
                    if last - first >= 150 * 1024 * 1024 and last >= first * 1.3 and rising >= len(seq) - 2:
                        self.add_alert_cool(("leak", pr["name"].lower()), 3600, "warn",
                                            f'Olası bellek sızıntısı: {pr["name"]} (PID {pid}) son {len(seq) * 30 // 60} dk içinde '
                                            f'{fmt_bytes(first)} → {fmt_bytes(last)} büyüdü',
                                            pid=pid, name=pr["name"])
            for k in list(self.mem_hist):
                if k not in live:
                    del self.mem_hist[k]

    def run(self):
        while True:
            t0 = time.time()
            try:
                self.tick()
            except Exception:
                traceback.print_exc()
            try:
                self.tail_fwlog()
            except Exception:
                traceback.print_exc()
            self.ready = True
            time.sleep(max(0.2, INTERVAL - (time.time() - t0)))

    def tick(self):
        now = time.time()
        dt = (now - self.prev_t) if self.prev_t else INTERVAL
        cpu = psutil.cpu_percent(None)
        percpu = psutil.cpu_percent(None, percpu=True)
        vm = psutil.virtual_memory()
        net = psutil.net_io_counters()
        nics = psutil.net_io_counters(pernic=True)
        try:
            disk = psutil.disk_io_counters()
        except Exception:
            disk = None

        down = up = dr = dw = 0.0
        if self.prev_net:
            down = max(0, net.bytes_recv - self.prev_net.bytes_recv) / dt
            up = max(0, net.bytes_sent - self.prev_net.bytes_sent) / dt
        if disk and self.prev_disk:
            dr = max(0, disk.read_bytes - self.prev_disk.read_bytes) / dt
            dw = max(0, disk.write_bytes - self.prev_disk.write_bytes) / dt
        nic_rates = {}
        for name, c in nics.items():
            p = (self.prev_nics or {}).get(name)
            nic_rates[name] = {
                "down": max(0, c.bytes_recv - p.bytes_recv) / dt if p else 0,
                "up": max(0, c.bytes_sent - p.bytes_sent) / dt if p else 0,
                "recv": c.bytes_recv, "sent": c.bytes_sent,
                "errin": c.errin, "errout": c.errout, "dropin": c.dropin, "dropout": c.dropout,
            }
        self.prev_net, self.prev_nics, self.prev_disk, self.prev_t = net, nics, disk, now

        # ---- surecler
        procs = self.collect_procs_nt(dt) if _NT_OK else self.collect_procs_psutil(dt)
        self.tick_rest(now, dt, cpu, percpu, vm, net, down, up, dr, dw, nic_rates, procs)

    def collect_procs_nt(self, dt):
        snap = nt_processes()
        procs = {}
        new_cpu = {}
        new_io = {}
        cache = self.static
        for pid, (ppid, name, nthr, created, cpu_t, ws, priv, handles, io) in snap.items():
            key = (pid, round(created, 1))
            st = cache.get(key)
            if st is None:
                exe, user, cmd = "", "", ""
                try:
                    p = psutil.Process(pid)
                    try:
                        exe = p.exe()
                    except Exception:
                        pass
                    try:
                        user = (p.username() or "").split("\\")[-1]
                    except Exception:
                        pass
                    try:
                        cmd = " ".join(p.cmdline())
                    except Exception:
                        pass
                except Exception:
                    pass
                st = cache[key] = {"exe": exe, "user": user, "flags": path_flags(exe, name)}
                sig_request(exe)
                try:
                    cmd_scan(pid, key[1], name, cmd, ppid, snap)
                except Exception:
                    traceback.print_exc()
            c = 0.0
            if key in self.prev_cpu:
                c = max(0.0, (cpu_t - self.prev_cpu[key]) / (dt * 1e7) / NCPU * 100)
            io_rate = max(0, io - self.prev_io[key]) / dt if key in self.prev_io else 0.0
            new_cpu[key] = cpu_t
            new_io[key] = io
            procs[pid] = {
                "pid": pid, "ppid": ppid, "name": name or "?", "user": st["user"], "exe": st["exe"],
                "created": created, "mem": ws, "private": priv, "threads": nthr, "handles": handles,
                "status": "", "cpu": round(min(c, 100.0), 1), "io": io_rate, "flags": st["flags"],
            }
        self.prev_cpu, self.prev_io = new_cpu, new_io
        if len(cache) > 5000:
            live = set(new_cpu)
            self.static = {k: v for k, v in cache.items() if k in live}
        return procs

    def collect_procs_psutil(self, dt):
        procs = {}
        new_io = {}
        for p in psutil.process_iter(["pid", "ppid", "name", "username", "exe", "create_time",
                                      "memory_info", "num_threads", "status"], ad_value=None):
            i = p.info
            pid = i["pid"]
            try:
                c = p.cpu_percent(None) / NCPU
            except Exception:
                c = 0.0
            io_rate = 0.0
            try:
                io = p.io_counters()
                tot = io.read_bytes + io.write_bytes
                key = (pid, i["create_time"])
                new_io[key] = tot
                if key in self.prev_io:
                    io_rate = max(0, tot - self.prev_io[key]) / dt
            except Exception:
                pass
            mi = i["memory_info"]
            exe = i["exe"] or ""
            procs[pid] = {
                "pid": pid, "ppid": i["ppid"], "name": i["name"] or "?",
                "user": (i["username"] or "").split("\\")[-1], "exe": exe,
                "created": i["create_time"], "mem": mi.rss if mi else 0,
                "threads": i["num_threads"] or 0, "status": i["status"] or "",
                "cpu": round(c, 1), "io": io_rate, "flags": path_flags(exe, i["name"]),
            }
            sig_request(exe)
        self.prev_io = new_io
        return procs

    def tick_rest(self, now, dt, cpu, percpu, vm, net, down, up, dr, dw, nic_rates, procs):
        # ---- baglantilar
        try:
            raw = psutil.net_connections("inet")
        except Exception:
            raw = []
        listen_set = set()
        for c in raw:
            if c.status == psutil.CONN_LISTEN:
                listen_set.add((c.pid, c.laddr.port))
        conns = []
        conn_keys = {}
        listen_keys = {}
        for c in raw:
            proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
            lip, lport = (c.laddr.ip, c.laddr.port) if c.laddr else ("", 0)
            rip, rport = (c.raddr.ip, c.raddr.port) if c.raddr else ("", 0)
            pr = procs.get(c.pid) or {}
            status = c.status if proto == "TCP" else ("BOUND" if not rip else "UDP")
            direction = ""
            if proto == "TCP" and status == psutil.CONN_LISTEN:
                direction = "listen"
            elif proto == "UDP" and not rip:
                direction = "listen"
            elif rip:
                direction = "in" if (c.pid, lport) in listen_set else "out"
            rclass = ip_class(rip) if rip else ""
            flags = []
            if rip and rclass == "public":
                if direction == "out" and rport in SUS_REMOTE_PORTS:
                    flags.append("sus_rport")
                if direction == "in":
                    flags.append("inbound_public")
            if (direction == "listen" and lport in RISKY_PORTS and ip_class(lip) in ("any", "private", "public", "linklocal")
                    and port_needs_attention(proto, lport, pr.get("exe", ""), pr.get("name", "System" if c.pid in (0, 4) else "?"))):
                flags.append("risky_listen")
            host = rdns(rip) if rip and rclass in ("public", "private") else None
            row = {
                "proto": proto, "lip": lip, "lport": lport, "rip": rip, "rport": rport,
                "status": status, "pid": c.pid, "name": pr.get("name", "System" if c.pid in (0, 4) else "?"),
                "exe": pr.get("exe", ""), "dir": direction, "rclass": rclass, "host": host,
                "flags": flags, "pflags": pr.get("flags", []),
            }
            conns.append(row)
            if direction == "listen":
                if proto == "TCP" or (lport < 49152 and ip_class(lip) != "loopback"):
                    listen_keys[(proto, lip, lport, c.pid)] = row
            elif proto == "TCP" and rip and status in ("ESTABLISHED", "SYN_SENT", "SYN_RECV"):
                conn_keys[(lip, lport, rip, rport, c.pid)] = row

        # surec basina baglanti sayisi
        cc = Counter(r["pid"] for r in conns if r["dir"] in ("in", "out"))
        lp = {}
        for r in conns:
            if r["dir"] == "listen":
                lp.setdefault(r["pid"], set()).add(f'{r["proto"][0]}{r["lport"]}')
        for pid, pr in procs.items():
            pr["conns"] = cc.get(pid, 0)
            pr["listen"] = sorted(lp.get(pid, []))

        # ---- olay uretimi (ilk turdan sonra)
        if self.prev_pids is not None:
            for pid in procs.keys() - self.prev_pids.keys():
                pr = procs[pid]
                self.add_event("proc_start", "info", f'İşlem başladı: {pr["name"]} (PID {pid})',
                               pid=pid, name=pr["name"], exe=pr["exe"])
            for pid in self.prev_pids.keys() - procs.keys():
                pr = self.prev_pids[pid]
                self.add_event("proc_end", "info", f'İşlem sonlandı: {pr["name"]} (PID {pid})',
                               pid=pid, name=pr["name"], exe=pr["exe"])
            for k in conn_keys.keys() - self.prev_conn_keys.keys():
                r = conn_keys[k]
                if r["dir"] == "out" and r["rclass"] == "public":
                    self.track_beacon(r, now)
                arrow = "<-" if r["dir"] == "in" else "->"
                lvl = "warn" if r["flags"] else "info"
                self.add_event("conn_" + r["dir"], lvl,
                               f'{r["name"]} {arrow} {r["rip"]}:{r["rport"]}' + (f' ({r["host"]})' if r["host"] else ""),
                               pid=r["pid"], name=r["name"], rip=r["rip"], rport=r["rport"],
                               lport=r["lport"], rclass=r["rclass"])
            for k in self.prev_conn_keys.keys() - conn_keys.keys():
                r = self.prev_conn_keys[k]
                self.stats["conn_closed"] += 1
            for k in listen_keys.keys() - self.prev_listen.keys():
                r = listen_keys[k]
                exposed = ip_class(r["lip"]) != "loopback"
                lvl = "high" if (exposed and r["lport"] in RISKY_PORTS and RISKY_PORTS[r["lport"]][1] == "high") else ("warn" if exposed else "info")
                self.add_event("listen", lvl,
                               f'Yeni dinleyen port: {r["proto"]} {r["lip"]}:{r["lport"]} - {r["name"]}',
                               pid=r["pid"], name=r["name"], lport=r["lport"])
                if exposed and r["proto"] == "TCP":
                    self.add_alert(("listen", r["lport"], r["name"]), lvl,
                                   f'{r["name"]} dış ağa açık yeni bir port dinlemeye başladı: TCP {r["lport"]}',
                                   pid=r["pid"], name=r["name"])
            for k in self.prev_listen.keys() - listen_keys.keys():
                r = self.prev_listen[k]
                self.add_event("unlisten", "info", f'Port kapandı: {r["proto"]} {r["lip"]}:{r["lport"]} - {r["name"]}',
                               pid=r["pid"], name=r["name"], lport=r["lport"])

        # ---- uyarilar (surekli kontroller)
        for r in conn_keys.values():
            if "sus_rport" in r["flags"]:
                self.add_alert(("susr", r["pid"], r["rip"], r["rport"]), "high",
                               f'{r["name"]} şüpheli bir uzak porta bağlandı: {r["rip"]}:{r["rport"]} ({SUS_REMOTE_PORTS.get(r["rport"])})',
                               pid=r["pid"], name=r["name"], rip=r["rip"])
            if "inbound_public" in r["flags"]:
                self.add_alert(("inpub", r["pid"], r["rip"], r["lport"]), "warn",
                               f'İnternetten gelen bağlantı: {r["rip"]} -> {r["name"]} yerel port {r["lport"]}',
                               pid=r["pid"], name=r["name"], rip=r["rip"])
            if r["rclass"] == "public" and r["exe"]:
                if "susp_path" in r["pflags"]:
                    self.add_alert(("spath", r["exe"].lower()), "warn",
                                   f'Geçici/şüpheli klasördeki program internete bağlanıyor: {r["exe"]}',
                                   pid=r["pid"], name=r["name"])
                s = sig_of(r["exe"])
                if s and s["s"] in ("NotSigned", "HashMismatch", "NotTrusted"):
                    self.add_alert(("unsigned", r["exe"].lower()), "warn" if s["s"] == "NotSigned" else "high",
                                   f'İmzasız program internete bağlanıyor ({s["s"]}): {r["exe"]}',
                                   pid=r["pid"], name=r["name"])
        for pr in procs.values():
            if "masquerade" in pr["flags"]:
                self.add_alert(("masq", pr["exe"].lower()), "high",
                               f'Sistem işlemi taklidi olabilir: {pr["name"]} beklenmeyen konumda çalışıyor -> {pr["exe"]}',
                               pid=pr["pid"], name=pr["name"])

        try:
            self.watch_resources(now, cpu, vm, procs)
        except Exception:
            traceback.print_exc()

        self.prev_pids = procs
        self.prev_conn_keys = conn_keys
        self.prev_listen = listen_keys

        with self.lock:
            h = self.hist
            h["t"].append(now)
            h["cpu"].append(round(cpu, 1))
            h["mem"].append(round(vm.percent, 1))
            h["down"].append(round(down))
            h["up"].append(round(up))
            h["dread"].append(round(dr))
            h["dwrite"].append(round(dw))
            self.snapshot = {"procs": procs, "conns": conns, "nics": nic_rates, "percpu": percpu,
                             "cpu": cpu, "vm": vm._asdict(), "down": down, "up": up,
                             "dread": dr, "dwrite": dw, "t": now,
                             "net_total": {"recv": net.bytes_recv, "sent": net.bytes_sent}}

    # ---- Windows Guvenlik Duvarı log dosyasi
    def tail_fwlog(self):
        path = self.fwlog_path
        try:
            size = os.path.getsize(path)
        except FileNotFoundError:
            self.fwlog_status = "log dosyası yok (loglama kapalı olabilir)"
            return
        except PermissionError:
            self.fwlog_status = "erişim reddedildi (yönetici olarak çalıştırın)"
            return
        except OSError as e:
            self.fwlog_status = f"okunamadı: {e}"
            return
        try:
            if self.fwlog_pos is None or size < self.fwlog_pos:
                start = max(0, size - 256 * 1024)
            else:
                start = self.fwlog_pos
            if start == size:
                self.fwlog_status = "ok"
                return
            with open(path, "rb") as f:
                f.seek(start)
                data = f.read(4 * 1024 * 1024)
            self.fwlog_pos = start + len(data)
        except PermissionError:
            self.fwlog_status = "erişim reddedildi (yönetici olarak çalıştırın)"
            return
        self.fwlog_status = "ok"
        text = data.decode("utf-8", "replace")
        if start > 0 and self.fwlog_fields is None:
            try:
                with open(path, "rb") as f:
                    head = f.read(1024).decode("utf-8", "replace")
                for line in head.splitlines():
                    if line.startswith("#Fields:"):
                        self.fwlog_fields = line[8:].split()
            except OSError:
                pass
        lines = text.splitlines()
        if start > 0 and self.fwlog_pos - len(data) == start and self.fwlog_id == 0:
            lines = lines[1:]  # ilk kismi satiri at
        for line in lines:
            if not line.strip():
                continue
            if line.startswith("#"):
                if line.startswith("#Fields:"):
                    self.fwlog_fields = line[8:].split()
                continue
            parts = line.split()
            fields = self.fwlog_fields or ["date", "time", "action", "protocol", "src-ip", "dst-ip",
                                           "src-port", "dst-port", "size", "tcpflags", "tcpsyn",
                                           "tcpack", "tcpwin", "icmptype", "icmpcode", "info", "path", "pid"]
            rec = dict(zip(fields, parts))
            self.fwlog_id += 1
            out = {"id": self.fwlog_id, "date": rec.get("date"), "time": rec.get("time"),
                   "action": rec.get("action"), "proto": rec.get("protocol"),
                   "src": rec.get("src-ip"), "dst": rec.get("dst-ip"),
                   "sport": rec.get("src-port"), "dport": rec.get("dst-port"),
                   "size": rec.get("size"), "path": rec.get("path"), "pid": rec.get("pid")}
            pid = out["pid"]
            if pid and pid.isdigit():
                pr = self.snapshot["procs"].get(int(pid))
                out["name"] = pr["name"] if pr else ""
            self.fwlog.append(out)


NOTIFY = None


# ---- Susturulan uyarilar ("cat|islem adi") ve kalici uyari gecmisi
SUP_FILE = os.path.join(APP_DIR, "suppress.json")
SUPPRESS = {}
ALERT_LOG = os.path.join(APP_DIR, "alerts.jsonl")
_alog_lock = threading.Lock()


def _sup_key(cat, name, parent=""):
    return f"{cat}|{(name or '').lower()}" + (f"|{parent.lower()}" if parent else "")


def is_suppressed(cat, name, parent=""):
    """Kural 'cat|ad' tum uyarilari, 'cat|ad|ust' yalnizca o ust islem tarafindan baslatilanlari susturur."""
    if not name:
        return False
    return _sup_key(cat, name) in SUPPRESS or (bool(parent) and _sup_key(cat, name, parent) in SUPPRESS)


def _sup_save():
    try:
        with open(SUP_FILE, "w", encoding="utf-8") as f:
            json.dump(list(SUPPRESS.values()), f, ensure_ascii=False)
    except OSError:
        pass


def _sup_load():
    try:
        with open(SUP_FILE, "r", encoding="utf-8") as f:
            for r in json.load(f):
                SUPPRESS[_sup_key(r["cat"], r["name"], r.get("parent", ""))] = r
    except (OSError, ValueError, KeyError):
        pass


def persist_alert(ev):
    try:
        row = {k: ev.get(k) for k in ("t", "level", "msg", "name", "cat", "pid", "parent")}
        with _alog_lock, open(ALERT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    except OSError:
        pass


def trim_alert_log(max_bytes=2 * 1024 * 1024, keep=3000):
    try:
        if os.path.getsize(ALERT_LOG) <= max_bytes:
            return
        with open(ALERT_LOG, "r", encoding="utf-8") as f:
            lines = f.readlines()[-keep:]
        with open(ALERT_LOG, "w", encoding="utf-8") as f:
            f.writelines(lines)
    except OSError:
        pass


MON = Monitor()

try:
    from etwnet import NetTrace
    NETTRACE = NetTrace()
except Exception:  # noqa
    traceback.print_exc()
    NETTRACE = None
NETWATCH = None

try:
    from notify import Notifier
    NOTIFY = Notifier(os.path.join(APP_DIR, "telegram.json"), socket.gethostname())
except Exception:  # noqa
    traceback.print_exc()
    NOTIFY = None

try:
    from geoip import GeoIP
    _geo_dirs = [os.path.join(APP_DIR, "geodata")]
    if FROZEN:   # .exe: veritabanı exe'nin yanındaki geodata klasöründe de aranır
        _geo_dirs.append(os.path.join(os.path.dirname(sys.executable), "geodata"))
    GEO = GeoIP(_geo_dirs)
except Exception:  # noqa
    traceback.print_exc()
    GEO = None


def geo_fields(row, ip):
    """Satira ulke kodu / kurulus / ASN alanlarini ekler (yalnizca genel IP'ler)."""
    g = GEO.lookup(ip) if GEO and ip else None
    row["cc"] = (g or {}).get("cc", "")
    row["org"] = (g or {}).get("org", "")
    row["asn"] = (g or {}).get("asn", 0)


# --------------------------------------------------------------------------
# Statik / yavas degisen veriler
# --------------------------------------------------------------------------
def fw_profiles():
    return ps_json(
        "Get-NetFirewallProfile | ForEach-Object { [pscustomobject]@{"
        " name=\"$($_.Name)\"; enabled=\"$($_.Enabled)\"; inAct=\"$($_.DefaultInboundAction)\";"
        " outAct=\"$($_.DefaultOutboundAction)\"; logAllowed=\"$($_.LogAllowed)\";"
        " logBlocked=\"$($_.LogBlocked)\"; logFile=\"$($_.LogFileName)\"; logMax=\"$($_.LogMaxSizeKilobytes)\";"
        " notify=\"$($_.NotifyOnListen)\"} } | ConvertTo-Json -Compress", timeout=60)


def fw_active_profile():
    try:
        res = ps_json("Get-NetConnectionProfile | ForEach-Object { [pscustomobject]@{"
                      " alias=$_.InterfaceAlias; name=$_.Name; cat=\"$($_.NetworkCategory)\";"
                      " v4=\"$($_.IPv4Connectivity)\" } } | ConvertTo-Json -Compress", timeout=30)
        return res
    except Exception:
        return []


def fw_rules():
    rules = ps_json(
        "$p = New-Object -ComObject HNetCfg.FwPolicy2; $p.Rules | ForEach-Object {"
        " [pscustomobject]@{ n=$_.Name; app=$_.ApplicationName; svc=$_.ServiceName; pr=$_.Protocol;"
        " lp=$_.LocalPorts; rp=$_.RemotePorts; la=$_.LocalAddresses; ra=$_.RemoteAddresses;"
        " d=$_.Direction; a=$_.Action; e=$_.Enabled; pf=$_.Profiles; g=$_.Grouping } }"
        " | ConvertTo-Json -Compress", timeout=120)
    protos = {6: "TCP", 17: "UDP", 1: "ICMPv4", 58: "ICMPv6", 256: "Tümü", 2: "IGMP", 47: "GRE", 41: "IPv6"}
    out = []
    for r in rules:
        pf = r.get("pf") or 0
        profs = []
        if pf == 2147483647 or pf == 7:
            profs = ["Tümü"]
        else:
            if pf & 1:
                profs.append("Etki alanı")
            if pf & 2:
                profs.append("Özel")
            if pf & 4:
                profs.append("Genel")
        g = r.get("g") or ""
        name = r.get("n") or ""
        if name.startswith("@{"):  # cozulmemis Microsoft Store uygulamasi kaynak adi
            name = name[2:].split("?")[0].rstrip("}").split("_")[0] + " (Store uygulaması)"
        if g.startswith("@{"):
            g = g[2:].split("?")[0].rstrip("}").split("_")[0]
        out.append({
            "name": name, "app": r.get("app") or "", "svc": r.get("svc") or "",
            "proto": protos.get(r.get("pr"), str(r.get("pr"))),
            "lport": r.get("lp") or "*", "rport": r.get("rp") or "*",
            "laddr": r.get("la") or "*", "raddr": r.get("ra") or "*",
            "dir": "in" if r.get("d") == 1 else "out",
            "action": "allow" if r.get("a") == 1 else "block",
            "enabled": bool(r.get("e")), "profiles": ", ".join(profs),
            "group": "" if g.startswith("@") else g,
            "sysdash": g == "SysDash",
        })
    return out


def startup_items():
    items = []
    keys = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM Run (32-bit)"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Winlogon"),
    ]
    approved = {}
    for hive, key in [(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"),
                      (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"),
                      (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32"),
                      (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder"),
                      (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder")]:
        try:
            with winreg.OpenKey(hive, key) as k:
                i = 0
                while True:
                    try:
                        n, v, _ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    if isinstance(v, bytes) and v:
                        approved[n.lower()] = (v[0] % 2 == 0)
                    i += 1
        except OSError:
            pass
    for hive, key, label in keys:
        try:
            with winreg.OpenKey(hive, key) as k:
                i = 0
                while True:
                    try:
                        n, v, _ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    i += 1
                    if label == "Winlogon":
                        if n.lower() not in ("shell", "userinit"):
                            continue
                        normal = {"shell": "explorer.exe", "userinit": "c:\\windows\\system32\\userinit.exe,"}
                        if str(v).strip().lower() in (normal[n.lower()], normal[n.lower()].rstrip(",")):
                            continue
                    items.append({"source": label, "name": n, "cmd": str(v),
                                  "enabled": approved.get(n.lower(), True)})
        except OSError:
            pass
    folders = [
        (os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"), "Başlangıç klasörü (kullanıcı)"),
        (os.path.join(os.environ.get("PROGRAMDATA", ""), r"Microsoft\Windows\Start Menu\Programs\StartUp"), "Başlangıç klasörü (tum kullanıcılar)"),
    ]
    for d, label in folders:
        try:
            for e in os.scandir(d):
                if e.name.lower() == "desktop.ini":
                    continue
                items.append({"source": label, "name": e.name, "cmd": e.path,
                              "enabled": approved.get(e.name.lower(), True)})
        except OSError:
            pass
    return items


def sched_tasks():
    return ps_json(
        "Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object {"
        " [pscustomobject]@{ name=$_.TaskName; path=$_.TaskPath; state=\"$($_.State)\"; author=$_.Author;"
        " ms=($_.TaskPath -like '\\Microsoft\\*');"
        " run=(($_.Actions | ForEach-Object { (\"$($_.Execute) $($_.Arguments)\").Trim() }) -join ' | ');"
        " trig=(($_.Triggers | ForEach-Object { $_.CimClass.CimClassName -replace 'MSFT_Task','' -replace 'Trigger','' }) -join ', ') } }"
        " | ConvertTo-Json -Compress", timeout=120)


# Windows'un calismasi icin kritik servisler: Gozcu bunlari durdurmaz / devre disi birakmaz
PROTECTED_SVC = {
    "rpcss", "dcomlaunch", "rpceptmapper", "lsm", "samss", "eventlog", "plugplay", "power", "profsvc", "schedule", "winmgmt",
    "cryptsvc", "dhcp", "dnscache", "bfe", "mpssvc", "windefend", "wscsvc", "trustedinstaller", "lanmanworkstation", "nsi",
    "netprofm", "nlasvc", "gpsvc", "sens", "systemeventsbroker", "timebrokersvc", "usermanager", "brokerinfrastructure",
    "coremessagingregistrar", "staterepository", "tiledatamodelsvc", "keyiso", "lsass", "wininit", "csrss", "smss",
}
SVC_LOG_FILE = os.path.join(APP_DIR, "svc_changes.json")
SVC_CHANGES = {}   # servis adi (lower) -> son Gozcu degisikligi
SVC_MODES = {"automatic": "auto", "delayed": "delayed-auto", "manual": "demand", "disabled": "disabled"}
SVC_MODE_TR = {"automatic": "Otomatik", "delayed": "Otomatik (gecikmeli)", "manual": "El ile", "disabled": "Devre dışı"}


def _svc_delayed(name):
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\" + name) as k:
            return winreg.QueryValueEx(k, "DelayedAutostart")[0] == 1
    except OSError:
        return False


def _svc_log_load():
    try:
        with open(SVC_LOG_FILE, "r", encoding="utf-8") as f:
            for r in json.load(f):
                SVC_CHANGES[r["name"].lower()] = r
    except (OSError, ValueError, KeyError):
        pass


def _svc_log_add(name, display, what, prev, new):
    SVC_CHANGES[name.lower()] = {"name": name, "display": display, "what": what, "prev": prev, "new": new, "t": time.time()}
    try:
        with open(SVC_LOG_FILE, "w", encoding="utf-8") as f:
            json.dump(list(SVC_CHANGES.values()), f, ensure_ascii=False)
    except OSError:
        pass


def services():
    out = []
    for s in psutil.win_service_iter():
        try:
            d = s.as_dict()
        except Exception:
            continue
        bp = d.get("binpath") or ""
        low = bp.lower().strip('"')
        start = d.get("start_type")
        out.append({
            "name": d.get("name"), "display": d.get("display_name"), "status": d.get("status"),
            "start": start, "delayed": start == "automatic" and _svc_delayed(d.get("name") or ""),
            "pid": d.get("pid"), "user": d.get("username") or "",
            "bin": bp, "ms": low.startswith(WINDIR) or "\\windows\\" in low[:40],
            "desc": (d.get("description") or "")[:300],
            "critical": (d.get("name") or "").lower() in PROTECTED_SVC,
            "gz": SVC_CHANGES.get((d.get("name") or "").lower()),
        })
    return out


def _svc_err(msg):
    """Windows'un (İngilizce/Türkçe karışık) servis hata iletisini anlaşılır Türkçe'ye çevirir."""
    m = (msg or "").strip().splitlines()
    m = m[0].strip() if m else ""
    low = m.lower()
    if "denied" in low or "reddedildi" in low or "cannot open" in low or "açılamıyor" in low:
        return "Erişim reddedildi: Gözcü'yü yönetici olarak çalıştırın."
    if "dependent" in low or "bağımlı" in low:
        return "Başka servisler buna bağlı; önce onlar durdurulmalı."
    if "timeout" in low or "zaman aşımı" in low or "did not respond" in low:
        return "Servis zamanında yanıt vermedi (zaman aşımı)."
    if "disabled" in low or "devre dışı" in low:
        return "Servis devre dışı: önce başlangıç türünü değiştirin."
    return m[:200]


def _svc_find(name):
    for r in (CACHE["services"].v or []):
        if r["name"] == name:
            return r
    return None


def post_service_action(b):
    need_admin()
    name, action = str(b.get("name", "")), str(b.get("action", ""))
    svc = _svc_find(name)
    if not svc:
        return {"ok": False, "error": "Servis bulunamadı (listeyi yenileyin)"}
    if action not in ("start", "stop", "restart"):
        return {"ok": False, "error": "Geçersiz eylem"}
    if action in ("stop", "restart") and name.lower() in PROTECTED_SVC:
        return {"ok": False, "error": "Bu servis Windows'un çalışması için kritik; Gözcü durdurmaz. Gerekirse Windows 'Hizmetler' (services.msc) kullanın."}
    cmd = {"start": "Start-Service", "stop": "Stop-Service", "restart": "Restart-Service"}[action]
    try:
        code, _, err = run_ps(
            "try { Add-Type -AssemblyName System.ServiceProcess -ErrorAction Stop; "
            "$svc = [System.ServiceProcess.ServiceController]::new($env:GOZCU_SVC); "
            f"{cmd} -InputObject $svc -ErrorAction Stop }} "
            "catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }",
            timeout=120, env_extra={"GOZCU_SVC": name})
    except subprocess.TimeoutExpired:
        CACHE["services"].get(True)
        return {"ok": False, "error": "İşlem zaman aşımına uğradı. Son durumu görmek için listeyi yenileyin."}
    if code != 0:
        return {"ok": False, "error": _svc_err(err) or "Eylem başarısız oldu"}
    tr = {"start": "başlatıldı", "stop": "durduruldu", "restart": "yeniden başlatıldı"}[action]
    MON.add_event("action", "warn", f"Servis {tr}: {svc['display']} ({name})")
    CACHE["services"].get(True)
    return {"ok": True}


def post_service_startup(b):
    need_admin()
    name, mode = str(b.get("name", "")), str(b.get("mode", ""))
    svc = _svc_find(name)
    if not svc:
        return {"ok": False, "error": "Servis bulunamadı (listeyi yenileyin)"}
    if mode not in SVC_MODES:
        return {"ok": False, "error": "Geçersiz başlangıç türü"}
    if name.lower() in PROTECTED_SVC and mode in ("manual", "disabled"):
        return {"ok": False, "error": "Bu servis Windows'un çalışması için kritik; Gözcü başlangıç türünü 'El ile' ya da 'Devre dışı' yapmaz."}
    prev = "delayed" if (svc["start"] == "automatic" and svc.get("delayed")) else svc["start"]
    r = subprocess.run(["sc.exe", "config", name, "start=", SVC_MODES[mode]], capture_output=True, creationflags=CREATE_NO_WINDOW, timeout=60)
    if r.returncode != 0:
        txt = (r.stdout + r.stderr).decode("oem", "replace").strip().splitlines()
        return {"ok": False, "error": _svc_err(txt[-1] if txt else "") or "Başlangıç türü değiştirilemedi"}
    _svc_log_add(name, svc["display"], "startup", prev, mode)
    MON.add_event("action", "warn", f"Servis başlangıç türü değişti: {svc['display']} ({name}): "
                                    f"{SVC_MODE_TR.get(prev, prev)} → {SVC_MODE_TR[mode]}")
    CACHE["services"].get(True)
    return {"ok": True, "prev": prev}


def neighbors():
    return ps_json(
        "Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Unreachable' -and $_.LinkLayerAddress -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' -and $_.LinkLayerAddress -ne 'FF-FF-FF-FF-FF-FF' } |"
        " ForEach-Object { [pscustomobject]@{ ip=$_.IPAddress; mac=$_.LinkLayerAddress; state=\"$($_.State)\"; nic=$_.InterfaceAlias } }"
        " | ConvertTo-Json -Compress", timeout=30)


def dns_servers():
    return ps_json(
        "Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } |"
        " ForEach-Object { [pscustomobject]@{ nic=$_.InterfaceAlias; servers=($_.ServerAddresses -join ', ') } }"
        " | ConvertTo-Json -Compress", timeout=30)


def reg_get(hive, key, name, default=None):
    try:
        with winreg.OpenKey(hive, key) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return default


def security_checks():
    checks = []

    def add(cid, title, status, detail, fix=""):
        checks.append({"id": cid, "title": title, "status": status, "detail": detail, "fix": fix})

    add("admin", "Panel yetki seviyesi", "ok" if ADMIN else "info",
        "Yönetici olarak çalışıyor - tum veriler görünür." if ADMIN else
        "Standart kullanıcı. Firewall logu, bazı işlemlerin dosya yolları ve kural ekleme için yönetici gerekir.")

    profs, err = CACHE["fw_profiles"].get()
    if profs:
        off = [p["name"] for p in profs if p.get("enabled") != "True"]
        add("fw", "Windows Güvenlik Duvarı", "bad" if off else "ok",
            ("Kapalı profiller: " + ", ".join(off)) if off else "Tüm profillerde açık.",
            "Ayarlar > Gizlilik ve güvenlik > Windows Güvenliği > Güvenlik duvarı")
        inallow = [p["name"] for p in profs if p.get("inAct") == "Allow"]
        if inallow:
            add("fwin", "Varsayılan gelen trafik", "bad", "Gelen trafiği varsayılan olarak İZİN veren profiller: " + ", ".join(inallow))
        logging = any(p.get("logBlocked") == "True" or p.get("logAllowed") == "True" for p in profs)
        add("fwlog", "Güvenlik duvarı loglama", "ok" if logging else "warn",
            "Loglama açık." if logging else "Loglama kapalı - engellenen/izin verilen paketler kaydedilmiyor.",
            "Güvenlik Duvarı sekmesinden açabilirsiniz (yönetici).")
    elif err:
        add("fw", "Windows Güvenlik Duvarı", "info", "Okunamadı: " + err)

    # Windows Guvenlik Merkezi'ne kayitli antivirüsler (productState: bit 12 = acik, bit 4 = tanimlar eski)
    avs = []
    try:
        for a in ps_json("Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop |"
                         " ForEach-Object { [pscustomobject]@{ n=$_.displayName; s=[int]$_.productState } } | ConvertTo-Json -Compress",
                         timeout=30):
            s = int(a.get("s") or 0)
            avs.append({"n": a.get("n") or "?", "on": bool(s & 0x1000), "old": bool(s & 0x10)})
    except Exception:
        pass
    active = [a for a in avs if a["on"]]
    if avs:
        add("av", "Antivirüs koruması", "ok" if active else "bad",
            ("Etkin: " + ", ".join(dict.fromkeys(a["n"] + (" (tanımlar ESKİ)" if a["old"] else "") for a in active))) if active
            else "Kayıtlı antivirüslerin hiçbiri etkin değil: " + ", ".join(a["n"] for a in avs),
            "Windows Güvenliği > Virüs ve tehdit koruması")
    try:
        mp = ps_json("$s=Get-MpComputerStatus -ErrorAction Stop; [pscustomobject]@{ av=$s.AntivirusEnabled; rt=$s.RealTimeProtectionEnabled;"
                     " mode=\"$($s.AMRunningMode)\"; age=$s.AntivirusSignatureAge; tamper=$s.IsTamperProtected; qs=$s.QuickScanAge;"
                     " ver=$s.AntivirusSignatureVersion } | ConvertTo-Json -Compress", timeout=30)
        if mp:
            m = mp[0]
            others = list(dict.fromkeys(a["n"] for a in active if "defender" not in a["n"].lower()))
            if m.get("av") and m.get("rt"):
                add("defender", "Microsoft Defender", "ok",
                    f'Açık, gerçek zamanlı koruma açık, kurcalama koruması {"açık" if m.get("tamper") else "kapalı"}.')
                age = m.get("age")
                if age is not None and age < 10000:
                    add("defsig", "Defender virüs tanımları", "ok" if age <= 3 else "warn",
                        f'Tanımlar {age} gün önce güncellendi (sürüm {m.get("ver")}).')
            elif others:
                add("defender", "Microsoft Defender", "info",
                    f'Pasif ({m.get("mode") or "kapalı"}) - koruma {", ".join(others)} tarafından sağlanıyor. Bu normaldir.')
            else:
                add("defender", "Microsoft Defender", "bad",
                    f'Gerçek zamanlı koruma KAPALI ve başka etkin antivirüs bulunamadı (mod: {m.get("mode") or "?"}).',
                    "Windows Güvenliği > Virüs ve tehdit koruması")
    except Exception as e:
        if not avs:
            add("defender", "Microsoft Defender", "info", "Durum okunamadı: " + str(e)[:120])

    rdp = reg_get(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections", 1)
    nla = reg_get(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication", 1)
    if rdp == 0:
        add("rdp", "Uzak Masaüstü (RDP)", "warn" if nla else "bad",
            "RDP AÇIK" + (" (NLA açık)" if nla else " ve NLA KAPALI - brute-force ve BlueKeep riskine açık") + ". Kullanmıyorsanız kapatın.",
            "Ayarlar > Sistem > Uzak Masaüstü")
    else:
        add("rdp", "Uzak Masaüstü (RDP)", "ok", "Kapalı.")

    lua = reg_get(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", 1)
    cpb = reg_get(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin", 5)
    add("uac", "Kullanıcı Hesabı Denetimi (UAC)", "ok" if lua and cpb != 0 else "bad",
        "Açık." if lua and cpb != 0 else "UAC kapalı ya da sormadan yükseltiyor - zararlı yazılım sessizce yönetici olabilir.")

    smb1 = reg_get(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1", None)
    smb1drv = reg_get(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start", 4)
    if smb1 == 1 or (smb1drv is not None and smb1drv != 4):
        add("smb1", "SMBv1 protokolü", "bad", "SMBv1 etkin görünüyor - EternalBlue/WannaCry açığı. Devre dışı bırakın.")
    else:
        add("smb1", "SMBv1 protokolü", "ok", "Devre dışı.")

    pe = reg_get(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", "ProxyEnable", 0)
    psrv = reg_get(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", "ProxyServer", "")
    pac = reg_get(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", "AutoConfigURL", "")
    if pe or pac:
        add("proxy", "Proxy ayarı", "warn", f"Sistem proxy'si tanımlı: {psrv or ''} {pac or ''} - siz ayarlamadıysanız trafik izleniyor olabilir.")
    else:
        add("proxy", "Proxy ayarı", "ok", "Proxy tanımlı değil.")

    hosts = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), r"System32\drivers\etc\hosts")
    try:
        with open(hosts, encoding="utf-8-sig", errors="replace") as f:
            entries = [l.split("#")[0].strip() for l in f]
        entries = [" ".join(e.split()) for e in entries if e]
        benign = ("docker.internal", "kubernetes.docker.internal", "localhost", "wsl.localhost")
        unknown = [e for e in entries if not any(b in e.lower() for b in benign)]
        if unknown:
            add("hosts", "hosts dosyası", "warn",
                "Bilinmeyen yönlendirmeler: " + " | ".join(unknown[:15]) + (" ..." if len(unknown) > 15 else "") +
                ". Bazı zararlılar güvenlik sitelerini engellemek veya sahte sitelere yönlendirmek için bu dosyayı değiştirir.")
        else:
            add("hosts", "hosts dosyası", "ok",
                ("Sadece bilinen kayıtlar (Docker/localhost): " + str(len(entries))) if entries else "Özel yönlendirme yok.")
    except OSError as e:
        add("hosts", "hosts dosyası", "info", f"Okunamadı: {e}")

    try:
        shares = ps_json("Get-CimInstance Win32_Share | ForEach-Object { [pscustomobject]@{n=$_.Name; p=$_.Path; t=$_.Type} } | ConvertTo-Json -Compress", timeout=30)
        user_shares = [s for s in shares if not str(s.get("n", "")).endswith("$")]
        add("shares", "Ağ paylaşımları", "warn" if user_shares else "ok",
            ("Paylaşılan klasörler: " + ", ".join(f'{s["n"]} ({s.get("p")})' for s in user_shares)) if user_shares
            else f'Sadece yönetimsel paylaşımlar ({", ".join(s["n"] for s in shares)}).')
    except Exception as e:
        add("shares", "Ağ paylaşımları", "info", "Okunamadı: " + str(e)[:100])

    try:
        users = ps_json("Get-LocalUser | ForEach-Object { [pscustomobject]@{n=$_.Name; e=$_.Enabled; pw=$_.PasswordRequired;"
                        " ll=$(if($_.LastLogon){$_.LastLogon.ToString('yyyy-MM-dd HH:mm')}else{''})} } | ConvertTo-Json -Compress", timeout=30)
        enabled = [u for u in users if u.get("e")]
        guest = [u for u in enabled if u["n"].lower() in ("guest", "konuk")]
        add("users", "Yerel kullanıcı hesapları", "bad" if guest else "ok",
            f"{len(enabled)} etkin hesap: " + ", ".join(f'{u["n"]}' + (f' (son giriş {u["ll"]})' if u.get("ll") else "") for u in enabled) +
            (" | KONUK hesabı etkin!" if guest else "") + ". Tanımadığınız bir hesap varsa inceleyin.")
    except Exception as e:
        add("users", "Yerel kullanıcı hesapları", "info", "Okunamadı: " + str(e)[:100])

    ports = api_ports({})["ports"]
    hi = sorted({(p["lport"], p["svc_name"], p["name"]) for p in ports if p["risk"] == "high"})
    med = sorted({(p["lport"], p["svc_name"], p["name"]) for p in ports if p["risk"] == "medium" and p["svc_name"]})
    if hi:
        add("ports", "Dış ağa açık riskli portlar", "bad",
            "Güvenlik duvarında İZİNLİ ve yüksek riskli: " + ", ".join(f"{p} {s} ({n})" for p, s, n in hi) +
            (f". Ayrıca {len(med)} orta riskli port var." if med else "") + " Kullanmıyorsanız servisi kapatın veya portu engelleyin.",
            "Açık Portlar sekmesi > 'Gelenleri engelle'")
    elif med:
        add("ports", "Dış ağa açık riskli portlar", "warn",
            "Orta riskli (çoğu güvenlik duvarınca engelli): " + ", ".join(sorted({f"{p} {s}" for p, s, n in med})))
    else:
        add("ports", "Dış ağa açık riskli portlar", "ok", "Güvenlik duvarından geçebilen riskli bir port yok.")

    al = list(MON.alerts)
    hi = [a for a in al if a["level"] == "high"]
    add("alerts", "Canlı izleme uyarıları", "bad" if hi else ("warn" if al else "ok"),
        f"{len(al)} uyarı ({len(hi)} yüksek). Detaylar Canlı Akış sekmesinde." if al else "Şu ana kadar uyarı yok.")

    try:
        boot = psutil.boot_time()
        days = (time.time() - boot) / 86400
        add("uptime", "Çalışma süresi", "warn" if days > 14 else "ok",
            f"{days:.1f} gündür yeniden başlatılmadı." + (" Bekleyen güncellemeler için yeniden başlatın." if days > 14 else ""))
    except Exception:
        pass
    return checks


CACHE = {
    "fw_profiles": Cached(fw_profiles, 20),
    "fw_rules": Cached(fw_rules, 60),
    "net_profiles": Cached(fw_active_profile, 30),
    "startup": Cached(startup_items, 30),
    "tasks": Cached(sched_tasks, 120),
    "services": Cached(services, 30),
    "neighbors": Cached(neighbors, 20),
    "dns": Cached(dns_servers, 60),
    "security": Cached(security_checks, 30),
}


# --------------------------------------------------------------------------
# Buyuk dosya tarayici
# --------------------------------------------------------------------------
class Scanner:
    def __init__(self):
        self.lock = threading.Lock()
        self.cancel = False
        self.state = {"running": False, "root": "", "files": 0, "dirs": 0, "bytes": 0, "errors": 0,
                      "current": "", "started": 0, "ended": 0, "top": [], "children": [], "exts": []}

    def start(self, root, min_mb, limit=300):
        with self.lock:
            if self.state["running"]:
                return False, "Zaten bir tarama çalışıyor"
            if not os.path.isdir(root):
                return False, "Klasör bulunamadı"
            self.cancel = False
            self.state = {"running": True, "root": root, "files": 0, "dirs": 0, "bytes": 0, "errors": 0,
                          "current": root, "started": time.time(), "ended": 0, "top": [], "children": [], "exts": [],
                          "min_mb": min_mb}
        threading.Thread(target=self._run, args=(root, int(min_mb * 1024 * 1024), limit), daemon=True).start()
        return True, ""

    def _run(self, root, min_bytes, limit):
        heap = []
        children = Counter()
        exts = Counter()
        st = self.state
        stack = [(root, None)]
        last = 0
        while stack and not self.cancel:
            d, top = stack.pop()
            st["dirs"] += 1
            try:
                it = os.scandir(d)
            except OSError:
                st["errors"] += 1
                continue
            with it:
                for e in it:
                    try:
                        if e.is_symlink() or (hasattr(e, "is_junction") and e.is_junction()):
                            continue
                        if e.is_dir(follow_symlinks=False):
                            stack.append((e.path, top or e.name))
                        elif e.is_file(follow_symlinks=False):
                            s = e.stat(follow_symlinks=False)
                            sz = s.st_size
                            st["files"] += 1
                            st["bytes"] += sz
                            children[top or "(kök dizindeki dosyalar)"] += sz
                            ext = os.path.splitext(e.name)[1].lower() or "(uzantısız)"
                            exts[ext] += sz
                            if sz >= min_bytes:
                                item = (sz, e.path, s.st_mtime)
                                if len(heap) < limit:
                                    heapq.heappush(heap, item)
                                elif sz > heap[0][0]:
                                    heapq.heapreplace(heap, item)
                    except OSError:
                        st["errors"] += 1
            now = time.time()
            if now - last > 0.5:
                last = now
                self._publish(heap, children, exts, d)
        self._publish(heap, children, exts, "")
        st["running"] = False
        st["ended"] = time.time()
        st["cancelled"] = self.cancel

    def _publish(self, heap, children, exts, cur):
        st = self.state
        st["current"] = cur
        st["top"] = [{"size": s, "path": p, "mtime": m} for s, p, m in sorted(heap, reverse=True)]
        st["children"] = [{"name": k, "size": v} for k, v in children.most_common(40)]
        st["exts"] = [{"ext": k, "size": v} for k, v in exts.most_common(20)]


SCANNER = Scanner()


# --------------------------------------------------------------------------
# API
# --------------------------------------------------------------------------
def conn_info(conns):
    """pid -> {pub: internete bağlı sayısı, sus: şüpheli uzak port sayısı, exp: riskli dış açık port}"""
    ci = {}
    for c in conns:
        d = ci.setdefault(c["pid"], {"pub": 0, "sus": 0, "exp": 0})
        if c["dir"] in ("in", "out") and c["rclass"] == "public":
            d["pub"] += 1
        if "sus_rport" in c["flags"]:
            d["sus"] += 1
        if "risky_listen" in c["flags"]:
            d["exp"] += 1
    return ci


def risk_of(p, ci):
    """Bir işlem için 0-100 risk skoru ve gerekçeleri (sezgisel; kesin hüküm değildir)."""
    score, why = 0, []
    fl = p.get("flags", [])
    s = sig_of(p.get("exe"))
    st = s["s"] if s else ""
    signer = (s or {}).get("n", "").lower()
    if "masquerade" in fl:
        score += 60
        why.append("Sistem işlemi adını taşıyor ama beklenen konumda değil")
    if "susp_path" in fl:
        score += 25
        why.append("Geçici/indirilenler/herkese açık bir klasörden çalışıyor")
    if st in ("HashMismatch", "NotTrusted"):
        score += 40
        why.append("Dijital imzası geçersiz veya güvenilmeyen")
    elif st == "NotSigned" and p.get("exe"):
        score += 15
        why.append("Dijital imzası yok")
    if ci.get("sus"):
        score += 35
        why.append("Şüpheli bir uzak porta bağlı (C2/Tor/arka kapı portları)")
    if ci.get("pub") and st in ("NotSigned", "HashMismatch", "NotTrusted"):
        score += 10
        why.append("İmzasız olduğu halde internete bağlı")
    if ci.get("exp"):
        score += 10
        why.append("Dış ağa açık riskli bir port dinliyor")
    for lvl, desc in MON.cmd_flags.get((p["pid"], round(p.get("created", 0), 1)), []):
        score += 40 if lvl == "high" else 20
        why.append(desc)
    if score and time.time() - p.get("created", 0) < 600:
        score += 5
        why.append("Son 10 dakika içinde başlatıldı")
    if score and "microsoft" in signer and "masquerade" not in fl and "susp_path" not in fl:
        score = max(0, score - 15)
    return min(100, score), why


def build_insights(vm, cpu, groups, procs, disks, counts, riskmap, boot):
    out = []
    add = lambda lvl, t, go="": out.append({"l": lvl, "t": t, "go": go})
    gtxt = lambda g: f'{g["name"]} ({g["n"]} işlem)' if g["n"] > 1 else g["name"]
    hi = sorted(((pid, r) for pid, r in riskmap.items() if r[0] >= 50), key=lambda x: -x[1][0])
    if hi:
        names = ", ".join(dict.fromkeys(procs[pid]["name"] for pid, _ in hi[:4] if pid in procs))
        add("bad", f"{len(hi)} işlem yüksek risk skorlu: {names}. Ayrıntı için İşlemler sekmesinde Risk sütununa bakın.", "procs")
    if counts["alerts_high"]:
        add("bad", f'{counts["alerts_high"]} yüksek öncelikli uyarı var. Canlı Akış sekmesinde inceleyin.', "feed")
    if cpu >= 70:
        g = max(groups, key=lambda g: g["cpu"])
        add("warn", f'İşlemci %{cpu:.0f} yoğun. En çok kullanan: {gtxt(g)} ~%{g["cpu"]:.0f}. Gerekirse önceliğini düşürün veya kapatın.', "procs")
    if vm["percent"] >= 80:
        g = max(groups, key=lambda g: g["mem"])
        add("warn", f'Bellek %{vm["percent"]:.0f} dolu. En çok bellek kullanan: {gtxt(g)} — {fmt_bytes(g["mem"])}.', "procs")
    elif groups:
        g = max(groups, key=lambda g: g["mem"])
        if g["mem"] > 1 << 30:
            add("info", f'En çok bellek kullanan uygulama: {gtxt(g)} — {fmt_bytes(g["mem"])}.', "procs")
    for d in disks:
        if d["pct"] >= 90:
            add("warn", f'{d["mount"]} diski %{d["pct"]:.0f} dolu ({fmt_bytes(d["free"])} boş). Disk sekmesindeki temizlik önerilerine bakın.', "disk")
    if counts["risky"]:
        add("warn", f'{counts["risky"]} riskli port dış ağa açık. Açık Portlar sekmesinde "Gelenleri engelle" ile kapatabilirsiniz.', "ports")
    unsigned_net = [p["name"] for p in procs.values() if p.get("conns") and (sig_of(p["exe"]) or {}).get("s") == "NotSigned"]
    if unsigned_net:
        add("warn", f'İmzasız {len(set(unsigned_net))} program ağ kullanıyor: {", ".join(list(dict.fromkeys(unsigned_net))[:4])}.', "procs")
    days = (time.time() - boot) / 86400
    if days > 14:
        add("info", f"Bilgisayar {days:.0f} gündür yeniden başlatılmadı; bekleyen güncellemeler olabilir.", "sec")
    if not [i for i in out if i["l"] in ("bad", "warn")]:
        out.insert(0, {"l": "ok", "t": "Belirgin bir sorun görünmüyor: kaynak kullanımı normal, riskli/şüpheli davranış tespit edilmedi.", "go": ""})
    return out


def api_overview(q):
    s = MON.snapshot
    with MON.lock:
        hist = {k: list(v) for k, v in MON.hist.items()}
    procs = list(s["procs"].values())
    conns = s["conns"]
    disks = []
    for p in psutil.disk_partitions(all=False):
        if "cdrom" in p.opts or not p.fstype:
            continue
        try:
            u = psutil.disk_usage(p.mountpoint)
            disks.append({"mount": p.mountpoint, "fs": p.fstype, "total": u.total, "used": u.used,
                          "free": u.free, "pct": u.percent})
        except OSError:
            pass
    try:
        bat = psutil.sensors_battery()
        bat = {"pct": bat.percent, "plugged": bat.power_plugged} if bat else None
    except Exception:
        bat = None
    sw = psutil.swap_memory()
    try:
        freq = psutil.cpu_freq()
        freq = freq.current if freq else None
    except Exception:
        freq = None
    est = [c for c in conns if c["dir"] in ("in", "out") and c["status"] == "ESTABLISHED"]
    listen = [c for c in conns if c["dir"] == "listen"]
    al = list(MON.alerts)
    groups = {}
    for p in procs:
        g = groups.setdefault(p["name"].lower(), {"name": p["name"], "n": 0, "cpu": 0.0, "mem": 0})
        g["n"] += 1
        g["cpu"] += p["cpu"]
        g["mem"] += p["mem"]
    groups = list(groups.values())
    ci = conn_info(conns)
    riskmap = {p["pid"]: risk_of(p, ci.get(p["pid"], {})) for p in procs}
    counts = {"procs": len(procs), "threads": sum(p["threads"] for p in procs),
              "est": len(est), "listen_tcp": len({(c["lip"], c["lport"]) for c in listen if c["proto"] == "TCP"}),
              "listen_udp": len({(c["lip"], c["lport"]) for c in listen if c["proto"] == "UDP"}),
              "remote_hosts": len({c["rip"] for c in est if c["rclass"] == "public"}),
              "risky": len({(r["proto"], r["lport"]) for r in compute_ports(CACHE["fw_rules"].v or [])
                            if r["reach"] == "open" and r["risk"] in ("high", "medium") and not r["trusted"]}),
              "alerts": len(al), "alerts_high": sum(1 for a in al if a["level"] == "high"),
              "unsigned": len({p["exe"].lower() for p in procs if p["exe"] and (sig_of(p["exe"]) or {}).get("s") == "NotSigned"})}
    vmd = s.get("vm", {})
    insights = build_insights(vmd, s.get("cpu", 0), groups, {p["pid"]: p for p in procs}, disks, counts, riskmap,
                              psutil.boot_time()) if vmd else []
    return {
        "groups": sorted(groups, key=lambda g: g["mem"], reverse=True)[:8], "insights": insights,
        "host": socket.gethostname(), "user": os.environ.get("USERNAME", ""),
        "os": f"{platform.system()} {platform.release()} ({platform.version()})",
        "cpu_name": platform.processor(), "ncpu": NCPU, "ncpu_phys": psutil.cpu_count(logical=False),
        "boot": psutil.boot_time(), "admin": ADMIN, "now": time.time(), "freq": freq,
        "netcut": NETCUT["on"], "netcut_until": NETCUT["until"],
        "cpu": s.get("cpu", 0), "percpu": s.get("percpu", []), "vm": s.get("vm", {}),
        "swap": {"total": sw.total, "used": sw.used, "pct": sw.percent},
        "down": s.get("down", 0), "up": s.get("up", 0), "dread": s.get("dread", 0), "dwrite": s.get("dwrite", 0),
        "net_total": s.get("net_total", {}),
        "hist": hist, "disks": disks, "battery": bat,
        "counts": counts, "risky_procs": sum(1 for r in riskmap.values() if r[0] >= 50),
        "top_cpu": sorted(procs, key=lambda p: p["cpu"], reverse=True)[:8],
        "top_mem": sorted(procs, key=lambda p: p["mem"], reverse=True)[:8],
        "top_io": sorted(procs, key=lambda p: p["io"], reverse=True)[:8],
        "alerts": al[-12:][::-1],
        "stats": dict(MON.stats),
        "ready": MON.ready,
    }


def api_processes(q):
    out = []
    ci = conn_info(MON.snapshot["conns"])
    for p in MON.snapshot["procs"].values():
        r = dict(p)
        s = sig_of(p["exe"])
        r["sig"] = s["s"] if s else ("" if not p["exe"] else "?")
        r["signer"] = s["n"] if s else ""
        r["risk"], why = risk_of(p, ci.get(p["pid"], {}))
        r["why"] = "; ".join(why)
        out.append(r)
    return {"procs": out, "admin": ADMIN}


def sha256_file(path, limit=512 * 1024 * 1024):
    try:
        if os.path.getsize(path) > limit:
            return "(dosya çok büyük)"
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError as e:
        return f"(okunamadı: {e.strerror})"


def ended_info(pid):
    """Artik calismayan islem: olay kayitlarindan bilinen ad/yolu dondurur."""
    name = exe = ""
    for e in reversed(MON.events):
        if e.get("pid") == pid and e.get("name"):
            name = name or e["name"]
            exe = exe or e.get("exe", "")
            if name and exe:
                break
    return {"ended": True, "pid": pid, "name": name or "?", "exe": exe}


def api_process(q):
    pid = int(q.get("pid", ["0"])[0])
    t = float(q["t"][0]) if "t" in q else None
    try:
        p = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return ended_info(pid)
    try:
        if t and p.create_time() > t + 2:   # PID baska bir islem tarafindan yeniden kullanilmis
            return ended_info(pid)
    except psutil.Error:
        pass
    snap = MON.snapshot["procs"].get(pid, {})
    d = {"pid": pid, **snap}

    def safe(fn, default=None):
        try:
            return fn()
        except Exception:
            return default
    d["cmdline"] = safe(lambda: " ".join(p.cmdline()), "")
    d["cwd"] = safe(p.cwd, "")
    d["exe"] = safe(p.exe, snap.get("exe", ""))
    d["username"] = safe(p.username, "")
    d["nice"] = safe(p.nice, "")
    d["prio"] = PRIO_NAME_BY_VALUE.get(int(d["nice"]), "") if d["nice"] != "" else ""
    d["status"] = safe(p.status, "")
    d["protected"] = d.get("name", "").lower() in PROTECTED
    d["handles"] = safe(p.num_handles, "")
    mi = safe(p.memory_full_info) or safe(p.memory_info)
    d["meminfo"] = mi._asdict() if mi else {}
    d["open_files"] = safe(lambda: [f.path for f in p.open_files()][:200], None)
    d["modules_count"] = safe(lambda: len(p.memory_maps()), None)
    chain = []
    cur = safe(p.parent)
    while cur and len(chain) < 10:
        chain.append({"pid": cur.pid, "name": safe(cur.name, "?"), "exe": safe(cur.exe, "")})
        cur = safe(cur.parent)
    d["parents"] = chain
    d["children"] = [{"pid": c.pid, "name": safe(c.name, "?")} for c in safe(lambda: p.children(), [])]
    d["connections"] = [c for c in MON.snapshot["conns"] if c["pid"] == pid]
    s = sig_of(d["exe"])
    if d["exe"] and not s:
        try:
            r = ps_json("$s=Get-AuthenticodeSignature -LiteralPath $env:SYSDASH_ARG; [pscustomobject]@{s=\"$($s.Status)\";"
                        " n=$(if($s.SignerCertificate){$s.SignerCertificate.Subject}else{''})} | ConvertTo-Json -Compress",
                        timeout=30, env_extra={"SYSDASH_ARG": d["exe"]})
            if r:
                n = r[0].get("n") or ""
                s = {"s": r[0].get("s"), "n": n.split("CN=", 1)[1].split(",")[0].strip('"') if "CN=" in n else n}
                SIG[d["exe"].lower()] = s
        except Exception:
            pass
    d["sig"] = s
    d["sha256"] = sha256_file(d["exe"]) if d["exe"] else ""
    d["svc"] = [x["name"] for x in (CACHE["services"].v or []) if x.get("pid") == pid]
    d["risk"], d["risk_why"] = risk_of({**snap, "pid": pid, "exe": d["exe"]}, conn_info(d["connections"]).get(pid, {})) if snap else (0, [])
    nm = (d.get("name") or "").lower()
    d["about"] = KNOWN_PROCS.get(nm, "")
    if d["about"] and "masquerade" in snap.get("flags", []):
        d["about"] += " UYARI: Bu işlem bu adı taşıyor ama beklenen konumda çalışmıyor; taklit olabilir."
    return d


def api_connections(q):
    rows = MON.snapshot["conns"]
    for r in rows:
        if r["rip"] and r["host"] is None:
            r["host"] = RDNS.get(r["rip"])
        s = sig_of(r["exe"])
        r["sig"] = s["s"] if s else ""
        if r["rclass"] == "public":
            geo_fields(r, r["rip"])
    return {"conns": rows, "geo": bool(GEO and GEO.ready)}


TRUSTPORTS_FILE = os.path.join(APP_DIR, "trusted_ports.json")
TRUSTPORTS = {}   # "proto|port|islem adi" -> {"proto","port","name","t","why"}


def _tp_key(proto, port, name):
    return f"{str(proto).upper()}|{int(port)}|{(name or '').lower()}"


def _tp_load():
    try:
        with open(TRUSTPORTS_FILE, "r", encoding="utf-8") as f:
            for r in json.load(f):
                TRUSTPORTS[_tp_key(r["proto"], r["port"], r["name"])] = r
    except (OSError, ValueError, KeyError):
        pass


def _tp_save():
    try:
        with open(TRUSTPORTS_FILE, "w", encoding="utf-8") as f:
            json.dump(list(TRUSTPORTS.values()), f, ensure_ascii=False)
    except OSError:
        pass


def api_trustports(q):
    return {"rules": sorted(TRUSTPORTS.values(), key=lambda r: (r["proto"], r["port"]))}


def post_trustport_add(b):
    try:
        proto, port, name = str(b.get("proto", "")).upper(), int(b.get("port", 0)), str(b.get("name", "")).strip()
    except (TypeError, ValueError):
        return {"ok": False, "error": "Geçersiz port"}
    if proto not in ("TCP", "UDP") or not (0 < port < 65536) or not name:
        return {"ok": False, "error": "Geçersiz port bilgisi"}
    TRUSTPORTS[_tp_key(proto, port, name)] = {"proto": proto, "port": port, "name": name, "t": time.time(),
                                               "why": str(b.get("why", ""))[:200]}
    _tp_save()
    MON.add_event("action", "info", f"Port güvenilir olarak işaretlendi: {proto} {port} · {name}")
    return {"ok": True}


def post_trustport_remove(b):
    key = str(b.get("key", ""))
    r = TRUSTPORTS.pop(key, None)
    if r is None:
        return {"ok": False, "error": "Kayıt bulunamadı"}
    _tp_save()
    MON.add_event("action", "info", f"Port güveni kaldırıldı: {r['proto']} {r['port']} · {r['name']}")
    return {"ok": True}


# ---- Gozcu uzerinden yapilan kural degisikliklerinin kaydi (kural adi, yon) -> son degisiklik
FWCHG_FILE = os.path.join(APP_DIR, "fw_changes.json")
GOZCU_CHANGES = {}


def _fwchg_load():
    try:
        with open(FWCHG_FILE, "r", encoding="utf-8") as f:
            for r in json.load(f):
                GOZCU_CHANGES[(r["name"].lower(), r["dir"])] = r
    except (OSError, ValueError, KeyError):
        pass


def _fwchg_add(name, direction, action, remote=""):
    direction = "in" if direction == "in" else "out"
    GOZCU_CHANGES[(str(name).lower(), direction)] = {"name": str(name), "dir": direction, "action": action,
                                                     "remote": remote, "t": time.time()}
    try:
        with open(FWCHG_FILE, "w", encoding="utf-8") as f:
            json.dump(list(GOZCU_CHANGES.values()), f, ensure_ascii=False)
    except OSError:
        pass


def _port_match(spec, port):
    if spec in ("*", "", None):
        return True
    for part in str(spec).split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            if lo.isdigit() and hi.isdigit() and int(lo) <= port <= int(hi):
                return True
        elif part.isdigit() and int(part) == port:
            return True
    return False


_CGNAT = ipaddress.ip_network("100.64.0.0/10")     # Tailscale / CGNAT
_TS6 = ipaddress.ip_network("fd7a:115c:a1e0::/48")  # Tailscale IPv6
_TRUSTED_NETS = [_CGNAT, _TS6]
_PRIV_NETS = [ipaddress.ip_network(x) for x in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "127.0.0.0/8",
                                                 "224.0.0.0/4", "fc00::/7", "fe80::/10", "ff00::/8", "::1/128")]


def _inside(lo, hi, nets):
    return any(lo.version == n.version and lo in n and hi in n for n in nets)
_LAN_WORDS = {"localsubnet", "localsubnet6", "intranet", "defaultgateway", "dhcp", "dns", "wins"}
_SCOPE_RANK = {"limited": 1, "lan": 2, "internet": 3}


def _raddr_scope(raddr):
    """Kuralin uzak adres kapsami: internet (herkes) > lan (yerel ag adresleri) > limited (belirli adresler, ör. Tailscale)."""
    toks = [t.strip() for t in str(raddr or "").split(",") if t.strip()]
    if not toks:
        return "internet"
    best = "limited"
    for t in toks:
        tl = t.lower()
        if tl in ("*", "any", "internet"):
            sc = "internet"
        elif tl in _LAN_WORDS:
            sc = "lan"
        else:
            sc = "limited"
            try:
                if "-" in t and "/" not in t:
                    x, y = t.split("-", 1)
                    lo, hi = ipaddress.ip_address(x.strip()), ipaddress.ip_address(y.strip())
                else:
                    net = ipaddress.ip_network(t, strict=False)
                    lo, hi = net.network_address, net.broadcast_address
                if _inside(lo, hi, _TRUSTED_NETS):
                    sc = "limited"            # Tailscale (IPv4 CGNAT / IPv6 ULA): belirli, guvenilir esler
                elif _inside(lo, hi, _PRIV_NETS):
                    sc = "lan"                # yalnizca ozel/yerel ag adresleri
                elif int(hi) - int(lo) > 2 ** 24:   # cok genis aralik = pratikte internet (0.0.0.0/0 gibi)
                    sc = "internet"
            except ValueError:
                pass
        if _SCOPE_RANK[sc] > _SCOPE_RANK[best]:
            best = sc
    return best


_FWV = {"fw": None, "n": -1, "allow": [], "block": [], "memo": {}}


def fw_classify(fw, proto, port, exe):
    """Gelen trafik icin guvenlik duvari durumu: (blocked|restricted|allowed|default, kural adlari).
    Ayni kural listesi icin sonuclar onbellege alinir (listener sayisi cok)."""
    if _FWV["fw"] is not fw or _FWV["n"] != len(fw):
        _FWV.update(fw=fw, n=len(fw), memo={},
                    allow=[r for r in fw if r["dir"] == "in" and r["action"] == "allow" and r["enabled"]],
                    block=[r for r in fw if r["dir"] == "in" and r["action"] == "block" and r["enabled"]])
    exe_l = (exe or "").lower()
    mk = (proto, port, exe_l)
    hit = _FWV["memo"].get(mk)
    if hit is not None:
        return hit

    def match(r):
        if r["proto"] not in (proto, "Tümü"):
            return False
        app = (r["app"] or "").lower()
        if app and app != exe_l:
            return False
        if not app and not r["svc"] and r["lport"] in ("*", "") and r["proto"] == "Tümü":
            return False  # cok genel kurallari sayma
        if r["svc"] and r["lport"] in ("*", ""):
            return False  # servise ozel 'her port' kurali: ayni svchost'taki baska servisin portuna uygulanamaz
        return _port_match(r["lport"], port)
    blk = [r["name"] for r in _FWV["block"] if match(r)]
    ar = [r for r in _FWV["allow"] if match(r)]
    if blk:
        res = ("blocked", blk[:3])
    elif ar:
        # en genis kuralin kapsami belirler: internet (herkes) > yerel ag > belirli adresler (ör. Tailscale)
        top = max((_raddr_scope(r["raddr"]) for r in ar), key=_SCOPE_RANK.get)
        if top == "internet":
            res = ("allowed", [r["name"] for r in ar[:3]])
        elif top == "lan":
            res = ("lan", [f'{r["name"]} → {r["raddr"][:60]}' for r in ar[:3]])
        else:
            res = ("restricted", [f'{r["name"]} → {r["raddr"][:60]}' for r in ar[:3]])
    else:
        res = ("default", [])
    _FWV["memo"][mk] = res
    return res


def port_needs_attention(proto, port, exe, name):
    """Riskli bir portta dinleyen soket gercekten dikkat gerektiriyor mu? (dışarıdan erişilebilir, yüksek/orta risk, güvenilir değil)"""
    info = RISKY_PORTS.get(port)
    if not info or info[1] not in ("high", "medium"):
        return False
    if _tp_key(proto, port, name) in TRUSTPORTS:
        return False
    fw = CACHE["fw_rules"].v
    if not fw:
        return True    # kurallar okunamadi: bilinmiyor -> temkinli davran
    return fw_classify(fw, proto, port, exe)[0] == "allowed"


def compute_ports(fw):
    """Dinleyen soketler + risk + güvenlik duvarı durumu (uzak adres sınırı dahil)."""
    rows = []
    seen = set()

    for c in MON.snapshot["conns"]:
        if c["dir"] != "listen":
            continue
        key = (c["proto"], c["lip"], c["lport"], c["pid"])
        if key in seen:
            continue
        seen.add(key)
        info = RISKY_PORTS.get(c["lport"])
        scope = ip_class(c["lip"])
        exposed = scope != "loopback"
        if not exposed:
            fws, fwr = "local", []
        elif not fw:
            fws, fwr = "unknown", []      # kurallar okunamadi: durumu bilmiyoruz, riski dusurme
        else:
            fws, fwr = fw_classify(fw, c["proto"], c["lport"], c["exe"])
        gz = None
        for rn in fwr:
            gz = GOZCU_CHANGES.get((rn.split(" → ")[0].lower(), "in"))
            if gz:
                break
        # reach: portun DISARIDAN gercekten erisilebilir olup olmadigi (dinlemek tek basina risk degildir)
        #   open = herkes (izin kurali var / kurallar okunamadi), limited = belirli adreslerle sinirli,
        #   blocked = guvenlik duvari gelen baglantiyi reddediyor, local = yalniz bu bilgisayar
        reach = "local" if not exposed else {"allowed": "open", "unknown": "open", "lan": "lan", "restricted": "limited",
                                             "blocked": "blocked", "default": "blocked"}[fws]
        risk = "none"
        if exposed:
            risk = info[1] if info else "low"
            if reach == "blocked":
                risk = "none"
            elif reach == "limited":
                risk = "low" if risk in ("high", "medium") else risk
            elif reach == "lan":
                risk = {"high": "medium", "medium": "low"}.get(risk, risk)
        s = sig_of(c["exe"])
        rows.append({**c, "svc_name": info[0] if info else "", "risk": risk, "why": info[2] if info else "",
                     "scope": scope, "exposed": exposed, "fw": fws, "reach": reach, "fw_rules": fwr, "gz": gz,
                     "trusted": _tp_key(c["proto"], c["lport"], c["name"]) in TRUSTPORTS,
                     "sig": s["s"] if s else "",
                     "clients": sum(1 for x in MON.snapshot["conns"] if x["dir"] == "in" and x["lport"] == c["lport"] and x["pid"] == c["pid"])})
    return rows


def api_ports(q):
    fw, _ = CACHE["fw_rules"].get()
    return {"ports": compute_ports(fw or []), "fw_loaded": bool(fw)}


def api_events(q):
    since = int(q.get("since", ["0"])[0])
    evs = [e for e in MON.events if e["id"] > since]
    return {"events": evs[-1500:], "last": MON.event_id, "stats": dict(MON.stats)}


def api_firewall(q):
    force = q.get("force", ["0"])[0] == "1"
    profs, perr = CACHE["fw_profiles"].get(force)
    rules, rerr = CACHE["fw_rules"].get(force)
    netp, _ = CACHE["net_profiles"].get(force)
    rules = [{**r, "gz": GOZCU_CHANGES.get((r["name"].lower(), r["dir"]))} for r in (rules or [])]
    return {"profiles": profs, "rules": rules, "net_profiles": netp, "err": perr or rerr,
            "admin": ADMIN, "log_status": MON.fwlog_status, "log_path": MON.fwlog_path}


def api_fwlog(q):
    since = int(q.get("since", ["0"])[0])
    rows = [r for r in MON.fwlog if r["id"] > since]
    return {"rows": rows[-2000:], "last": MON.fwlog_id, "status": MON.fwlog_status}


def api_etw(q):
    if NETTRACE is None:
        return {"status": "etwnet modülü yüklenemedi", "rows": [], "procs": [], "flows": [], "last": 0}
    since = int(q.get("since", ["0"])[0])
    rows, procs, flows, last, total = NETTRACE.snapshot(since)
    snap = MON.snapshot.get("procs", {})

    def nm(pid):
        pr = snap.get(pid)
        return pr["name"] if pr else ("System" if pid in (0, 4) else "?")

    for r in rows:
        r["name"] = nm(r["pid"])
        r["rclass"] = ip_class(r["rip"])
        r["host"] = NETTRACE.host_of(r["rip"]) or RDNS.get(r["rip"])
        if r["rclass"] == "public":
            geo_fields(r, r["rip"])
    blocked = {(r.get("app") or "").lower() for r in (CACHE["fw_rules"].v or [])
               if r.get("sysdash") and r.get("action") == "block" and r.get("app")}
    plist = []
    for pid, v in procs.items():
        exe = (snap.get(pid) or {}).get("exe", "")
        plist.append({"pid": pid, "name": nm(pid), "tx": v[0], "rx": v[1], "txr": v[2], "rxr": v[3],
                      "exe": exe, "blk": bool(exe) and exe.lower() in blocked, "until": TIMED.get(exe.lower(), 0) if exe else 0})
    flows.sort(key=lambda kv: kv[1][5], reverse=True)
    flist = []
    for (pid, proto, rip, rport, lport), v in flows[:600]:
        rc = ip_class(rip)
        fr = {}
        if rc == "public":
            geo_fields(fr, rip)
        flist.append({**fr, "pid": pid, "name": nm(pid), "proto": proto, "rip": rip, "rport": rport, "lport": lport,
                      "tx": v[0], "rx": v[1], "txn": v[2], "rxn": v[3], "first": v[4], "last": v[5],
                      "rclass": rc, "host": NETTRACE.host_of(rip) or (rdns(rip) if rc in ("public", "private") else None)})
    bcc = sorted({r["name"][len(CC_PREFIX):len(CC_PREFIX) + 2] for r in (CACHE["fw_rules"].v or [])
                  if r.get("sysdash") and r.get("name", "").startswith(CC_PREFIX)})
    return {"status": NETTRACE.status, "rows": rows, "procs": plist, "flows": flist, "last": last, "blocked_cc": bcc,
            "total": {"tx": total[0], "rx": total[1]}, "since": NETTRACE.t_start}


def api_etwdns(q):
    if NETTRACE is None or NETTRACE.status != "ok":
        return {"status": NETTRACE.status if NETTRACE else "etwnet yüklenemedi", "rows": [], "last": 0}
    since = int(q.get("since", ["0"])[0])
    rows, last = NETTRACE.dns_since(since)
    snap = MON.snapshot.get("procs", {})
    for r in rows:
        pr = snap.get(r["pid"])
        r["pname"] = pr["name"] if pr else ("System" if r["pid"] in (0, 4) else "?")
        r["self"] = r["pid"] == os.getpid()
    return {"status": NETTRACE.dns_status, "rows": rows, "last": last}


def api_etwproc(q):
    pid = int(q.get("pid", ["0"])[0])
    if NETTRACE is None or NETTRACE.status != "ok":
        return {"tx": [], "rx": [], "status": NETTRACE.status if NETTRACE else "yok"}
    r = NETTRACE.rate_hist(pid)
    r["status"] = "ok"
    return r


def api_etwhist(q):
    if NETWATCH is None:
        return {"status": NETTRACE.status if NETTRACE else "etwnet yüklenemedi", "days": [], "procs": []}
    days = max(1, min(60, int(q.get("days", ["7"])[0])))
    r = NETWATCH.history(days)
    r["status"] = "ok"
    return r


def api_notify(q):
    return NOTIFY.status() if NOTIFY else {"configured": False, "enabled": False, "error": "notify modülü yüklenemedi"}


def post_notify_save(b):
    if not NOTIFY:
        return {"ok": False, "error": "notify modülü yüklenemedi"}
    level = b.get("min")
    if level == "off":
        NOTIFY.disable()
        return {"ok": True, **NOTIFY.status()}
    ok, e = NOTIFY.configure(token=b.get("token"), chat=b.get("chat"), min_level=level, enabled=True)
    return {"ok": ok, "error": e, **NOTIFY.status()}


def post_notify_test(b):
    if not NOTIFY:
        return {"ok": False, "error": "notify modülü yüklenemedi"}
    ok, e = NOTIFY.test()
    return {"ok": ok, "error": e}


TASK_NAME = "Gozcu"


def autostart_status():
    code, out, err = run_ps("@(Get-ScheduledTask -TaskName $env:GOZCU_T -ErrorAction SilentlyContinue).Count",
                            timeout=30, env_extra={"GOZCU_T": TASK_NAME})
    return code == 0 and out.strip().isdigit() and int(out.strip()) > 0


def api_autostart(q):
    return {"on": autostart_status(), "admin": ADMIN}


def post_autostart(b):
    need_admin()
    if not b.get("enable"):
        code, out, err = run_ps("Unregister-ScheduledTask -TaskName $env:GOZCU_T -Confirm:$false -ErrorAction Stop",
                                timeout=60, env_extra={"GOZCU_T": TASK_NAME})
        if code != 0:
            return {"ok": False, "error": clean_ps_err(err) or "Görev silinemedi"}
        MON.add_event("action", "info", "Açılışta otomatik başlatma kapatıldı")
        return {"ok": True, "on": False}
    exe, args, wdir = self_command("--no-browser")
    pw = os.path.join(os.path.dirname(exe), "pythonw.exe")
    if not FROZEN and os.path.isfile(pw):
        exe = pw
    code, out, err = run_ps(
        "$u = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name;"
        " $a = New-ScheduledTaskAction -Execute $env:GOZCU_EXE -Argument $env:GOZCU_ARGS -WorkingDirectory $env:GOZCU_DIR;"
        " $t = New-ScheduledTaskTrigger -AtLogOn -User $u; $t.Delay = 'PT20S';"
        " $p = New-ScheduledTaskPrincipal -UserId $u -LogonType Interactive -RunLevel Highest;"
        " $s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries"
        " -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable;"
        " Register-ScheduledTask -TaskName $env:GOZCU_T -Action $a -Trigger $t -Principal $p -Settings $s"
        " -Description 'Gözcü: ağ ve sistem izleme paneli' -Force | Out-Null",
        timeout=60, env_extra={"GOZCU_T": TASK_NAME, "GOZCU_EXE": exe, "GOZCU_DIR": wdir,
                               "GOZCU_ARGS": args})
    if code != 0:
        return {"ok": False, "error": clean_ps_err(err) or "Görev oluşturulamadı"}
    MON.add_event("action", "info", "Açılışta otomatik başlatma açıldı (oturum açılınca, yönetici yetkisiyle)")
    return {"ok": True, "on": True}


def post_quit(b):
    for fn in (lambda: NETWATCH and NETWATCH.save(), lambda: NETTRACE and NETTRACE.stop()):
        try:
            fn()
        except Exception:
            pass
    threading.Timer(0.5, lambda: os._exit(0)).start()
    return {"ok": True}


def find_running():
    """Ayni makinede zaten calisan bir Gozcu varsa portunu dondurur (cift ETW oturumu cakismasin)."""
    import urllib.request
    for p in range(PORT, PORT + 20):
        with socket.socket() as sk:          # once port acik mi (hizli), sonra Gozcu mu (yavas olabilir)
            sk.settimeout(0.3)
            if sk.connect_ex(("127.0.0.1", p)) != 0:
                continue
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{p}/api/ping", timeout=6) as r:
                if json.loads(r.read().decode()).get("app") == "gozcu":
                    return p
        except Exception:
            continue
    return None


def api_suppress(q):
    return {"rules": sorted(SUPPRESS.values(), key=lambda r: -r.get("t", 0))}


def post_suppress_add(b):
    cat, name = str(b.get("cat", "")).strip(), str(b.get("name", "")).strip()
    parent = str(b.get("parent", "")).strip()
    if not cat or not name:
        return {"ok": False, "error": "Bu uyarı türü susturulamaz (işlem adı yok)"}
    key = _sup_key(cat, name, parent)
    SUPPRESS[key] = {"cat": cat, "name": name, "parent": parent, "key": key, "t": time.time(),
                     "example": str(b.get("example", ""))[:200]}
    _sup_save()
    low, plow = name.lower(), parent.lower()
    MON.alerts = deque((a for a in MON.alerts
                        if not (a.get("cat") == cat and (a.get("name") or "").lower() == low
                                and (not plow or (a.get("parent") or "").lower() == plow))), maxlen=500)
    MON.add_event("action", "info", f"Uyarı susturuldu: {name} · {cat}" + (f" (üst işlem: {parent})" if parent else ""))
    return {"ok": True}


def post_suppress_remove(b):
    key = str(b.get("key", "")).lower()
    r = SUPPRESS.pop(key, None)
    if r is None:
        return {"ok": False, "error": "Kayıt bulunamadı"}
    _sup_save()
    MON.add_event("action", "info", f"Uyarı susturması kaldırıldı: {r['name']} · {r['cat']}")
    return {"ok": True}


def api_alerthistory(q):
    days = max(1, min(365, int(q.get("days", ["30"])[0])))
    lo = time.time() - days * 86400
    rows = []
    try:
        with open(ALERT_LOG, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                if r.get("t", 0) >= lo:
                    rows.append(r)
    except OSError:
        pass
    return {"rows": rows[-3000:][::-1], "days": days}


# ---- Sureli program engelleme
TIMED_FILE = os.path.join(APP_DIR, "timed_blocks.json")
TIMED = {}   # exe yolu (kucuk harf) -> bitis zamani


def _timed_save():
    try:
        with open(TIMED_FILE, "w", encoding="utf-8") as f:
            json.dump(TIMED, f)
    except OSError:
        pass


def _timed_load():
    try:
        with open(TIMED_FILE, "r", encoding="utf-8") as f:
            TIMED.update({k: float(v) for k, v in json.load(f).items()})
    except (OSError, ValueError):
        pass


def timed_loop():
    """Suresi dolan program engellerini kaldirir (yonetici gerekir; degilse sonraki denemede)."""
    while True:
        time.sleep(20)
        now = time.time()
        for exe, until in list(TIMED.items()):
            if now < until:
                continue
            try:
                r = post_unblock_program({"value": exe})
            except PermissionError:
                continue
            except Exception:
                traceback.print_exc()
                continue
            if r.get("ok"):
                MON.add_event("action", "info", f"Süreli engel doldu, kaldırıldı: {exe}")


def api_startup(q):
    force = q.get("force", ["0"])[0] == "1"
    part = q.get("part", [""])[0]
    if part:
        if part not in ("startup", "tasks", "services"):
            return {"error": "Geçersiz başlangıç sekmesi"}
        rows, err = CACHE[part].get(force)
        return {"rows": rows, "err": err}
    st, e1 = CACHE["startup"].get(force)
    tk, e2 = CACHE["tasks"].get(force)
    sv, e3 = CACHE["services"].get(force)
    return {"startup": st, "tasks": tk, "services": sv, "err": e1 or e2 or e3}


def api_network(q):
    force = q.get("force", ["0"])[0] == "1"
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    rates = MON.snapshot.get("nics", {})
    nics = []
    for name, al in addrs.items():
        st = stats.get(name)
        r = rates.get(name, {})
        nics.append({
            "name": name, "up": bool(st and st.isup), "speed": st.speed if st else 0, "mtu": st.mtu if st else 0,
            "addrs": [{"fam": "IPv4" if a.family == socket.AF_INET else ("IPv6" if a.family == socket.AF_INET6 else "MAC"),
                       "addr": a.address, "mask": a.netmask} for a in al],
            **r,
        })
    nb, e1 = CACHE["neighbors"].get(force)
    dn, e2 = CACHE["dns"].get(force)
    netp, _ = CACHE["net_profiles"].get(force)
    conns = MON.snapshot["conns"]
    remote = Counter()
    rproc = {}
    pairs = Counter()
    for c in conns:
        if c["dir"] in ("in", "out") and c["rclass"] == "public":
            remote[c["rip"]] += 1
            rproc.setdefault(c["rip"], set()).add(c["name"])
            pairs[(c["rip"], c["name"])] += 1
    def _ipinfo(ip):
        g = (GEO.lookup(ip) if GEO and ip_class(ip) == "public" else None) or {}
        host = (NETTRACE.host_of(ip) if NETTRACE else None) or RDNS.get(ip) or ""
        return host, g.get("cc", ""), g.get("org", "")
    top_remote = [{"ip": ip, "n": n, "host": _ipinfo(ip)[0], "cc": _ipinfo(ip)[1], "org": _ipinfo(ip)[2], "procs": sorted(rproc[ip])}
                  for ip, n in remote.most_common(25)]
    byproc = Counter(c["name"] for c in conns if c["dir"] in ("in", "out"))
    def _edge(ip, n, v):
        host, cc, org = _ipinfo(ip)
        return {"ip": ip, "name": n, "n": v, "host": host, "cc": cc, "org": org}
    edges = [_edge(ip, n, v) for (ip, n), v in pairs.most_common(400)]
    return {"nics": nics, "neighbors": nb, "dns": dn, "profiles": netp, "err": e1 or e2,
            "top_remote": top_remote, "by_proc": byproc.most_common(20), "edges": edges}


def api_security(q):
    force = q.get("force", ["0"])[0] == "1"
    checks, err = CACHE["security"].get(force)
    return {"checks": checks, "err": err}


def api_scan_status(q):
    st = dict(SCANNER.state)
    return st


def api_drives(q):
    out = [{"path": p.mountpoint} for p in psutil.disk_partitions(all=False) if p.fstype]
    home = os.path.expanduser("~")
    out.insert(0, {"path": home})
    for sub in ("Downloads", "Desktop", "Documents", "Videos", "AppData"):
        pth = os.path.join(home, sub)
        if os.path.isdir(pth):
            out.append({"path": pth})
    return {"drives": out}


# ---- POST islemleri
def need_admin():
    if not ADMIN:
        raise PermissionError("Bu eylem için paneli yönetici olarak çalıştırın (sol alttaki 'Yönetici olarak yeniden başlat').")


PROTECTED = {"csrss.exe", "lsass.exe", "winlogon.exe", "services.exe", "smss.exe", "wininit.exe",
             "dwm.exe", "system", "registry", "memory compression", "system idle process", "fontdrvhost.exe"}
PRIO_LEVELS = {"idle": "IDLE_PRIORITY_CLASS", "below": "BELOW_NORMAL_PRIORITY_CLASS",
               "normal": "NORMAL_PRIORITY_CLASS", "above": "ABOVE_NORMAL_PRIORITY_CLASS",
               "high": "HIGH_PRIORITY_CLASS"}
PRIO_NAME_BY_VALUE = {int(getattr(psutil, v)): k for k, v in PRIO_LEVELS.items() if hasattr(psutil, v)}


def post_suspend(b):
    pid = int(b.get("pid", 0))
    resume = bool(b.get("resume"))
    if pid in (0, 4) or pid == os.getpid():
        return {"ok": False, "error": "Bu işlem askıya alınamaz"}
    try:
        p = psutil.Process(pid)
        name = p.name()
        if name.lower() in PROTECTED and not resume:
            return {"ok": False, "error": f"{name} kritik bir sistem işlemi; askıya almak Windows'u kilitler."}
        p.resume() if resume else p.suspend()
        MON.add_event("action", "warn", f"İşlem {'devam ettirildi' if resume else 'askıya alındı'}: {name} (PID {pid})",
                      pid=pid, name=name)
        return {"ok": True}
    except psutil.AccessDenied:
        return {"ok": False, "error": "Erişim reddedildi (yönetici gerekli olabilir)"}
    except psutil.NoSuchProcess:
        return {"ok": False, "error": "İşlem zaten yok"}


def post_priority(b):
    pid = int(b.get("pid", 0))
    level = PRIO_LEVELS.get(str(b.get("level", "")))
    if not level or not hasattr(psutil, level):
        return {"ok": False, "error": "Geçersiz öncelik"}
    try:
        p = psutil.Process(pid)
        p.nice(getattr(psutil, level))
        MON.add_event("action", "info", f"Öncelik değiştirildi: {p.name()} (PID {pid}) -> {b.get('level')}", pid=pid, name=p.name())
        return {"ok": True}
    except psutil.AccessDenied:
        return {"ok": False, "error": "Erişim reddedildi (yönetici gerekli olabilir)"}
    except psutil.NoSuchProcess:
        return {"ok": False, "error": "İşlem bulunamadı"}


def post_kill(b):
    pid = int(b.get("pid", 0))
    if pid in (0, 4) or pid == os.getpid():
        return {"ok": False, "error": "Bu işlem sonlandırılamaz"}
    try:
        p = psutil.Process(pid)
        name = p.name()
        if name.lower() in PROTECTED:
            return {"ok": False, "error": f"{name} kritik bir sistem işlemi; sonlandırmak Windows'u çökertir."}
        p.terminate()
        try:
            p.wait(3)
        except psutil.TimeoutExpired:
            p.kill()
        MON.add_event("action", "warn", f"İşlem kullanıcı tarafından sonlandırıldı: {name} (PID {pid})", pid=pid, name=name)
        return {"ok": True}
    except psutil.AccessDenied:
        return {"ok": False, "error": "Erişim reddedildi (yönetici gerekli olabilir)"}
    except psutil.NoSuchProcess:
        return {"ok": False, "error": "İşlem zaten yok"}


def post_block(b):
    need_admin()
    auto_backup("engel")
    kind = b.get("kind")
    val = str(b.get("value", "")).strip()
    direction = "Outbound" if b.get("dir", "out") == "out" else "Inbound"
    dirs = ["Outbound", "Inbound"] if b.get("dir") == "both" else [direction]
    if kind == "ip":
        try:
            ipaddress.ip_network(val, strict=False)
        except ValueError:
            return {"ok": False, "error": "Geçersiz IP / CIDR"}
        param = "-RemoteAddress $env:SYSDASH_ARG"
    elif kind == "program":
        if not os.path.isfile(val):
            return {"ok": False, "error": "Program dosyası bulunamadı"}
        param = "-Program $env:SYSDASH_ARG"
    elif kind == "port":
        if not val.isdigit() or not (0 < int(val) < 65536):
            return {"ok": False, "error": "Geçersiz port"}
        proto = "UDP" if b.get("proto") == "UDP" else "TCP"
        param = f"-Protocol {proto} -LocalPort $env:SYSDASH_ARG"
    else:
        return {"ok": False, "error": "Bilinmeyen tür"}
    for d in dirs:
        name = f"SysDash Engel - {kind} {val} ({'giden' if d == 'Outbound' else 'gelen'})"
        code, out, err = run_ps(
            f"New-NetFirewallRule -DisplayName $env:SYSDASH_NAME -Group 'SysDash' -Direction {d} -Action Block {param} -Profile Any | Out-Null",
            timeout=60, env_extra={"SYSDASH_ARG": val, "SYSDASH_NAME": name})
        if code != 0:
            return {"ok": False, "error": clean_ps_err(err) or "Kural eklenemedi"}
        MON.add_event("action", "warn", f"Güvenlik duvarı kuralı eklendi: {name}")
    if kind == "program":
        minutes = max(0, min(7 * 24 * 60, int(b.get("minutes", 0) or 0)))
        if minutes:
            TIMED[val.lower()] = time.time() + minutes * 60
            MON.add_event("action", "info", f"Program {minutes} dk süreyle engellendi: {val}")
        else:
            TIMED.pop(val.lower(), None)
        _timed_save()
    CACHE["fw_rules"].get(True)
    return {"ok": True}


KILL_PREFIX = "SysDash İnternet Kesici"
NETCUT = {"on": False, "until": 0}
_netcut_timer = None


def non_private_cidrs():
    """Yerel/ozel/loopback/multicast disindaki tum adresler (internet) CIDR listesi olarak."""
    def minus(nets, excl):
        for e in excl:
            e = ipaddress.ip_network(e)
            out = []
            for n in nets:
                if n.version != e.version:
                    out.append(n)
                elif e.subnet_of(n):
                    out.extend(n.address_exclude(e))
                elif n.subnet_of(e):
                    continue
                else:
                    out.append(n)
            nets = out
        return nets
    v4 = minus([ipaddress.ip_network("0.0.0.0/0")],
               ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4"])
    v6 = minus([ipaddress.ip_network("::/0")], ["::1/128", "fe80::/10", "fc00::/7", "ff00::/8"])
    return [str(n) for n in sorted(v4 + v6, key=lambda n: (n.version, n.network_address))]


def netcut_status():
    try:
        code, out, err = run_ps("@(Get-NetFirewallRule -DisplayName ($env:SYSDASH_ARG + '*') -ErrorAction SilentlyContinue).Count",
                                timeout=30, env_extra={"SYSDASH_ARG": KILL_PREFIX})
        NETCUT["on"] = code == 0 and out.strip().isdigit() and int(out.strip()) > 0
    except Exception:
        pass
    if not NETCUT["on"]:
        NETCUT["until"] = 0


def _netcut_loop():
    while True:
        netcut_status()
        time.sleep(30)


def _netcut_remove():
    code, out, err = run_ps("Get-NetFirewallRule -DisplayName ($env:SYSDASH_ARG + '*') -ErrorAction SilentlyContinue"
                            " | Remove-NetFirewallRule", timeout=60, env_extra={"SYSDASH_ARG": KILL_PREFIX})
    return code == 0, clean_ps_err(err)


def post_netcut(b):
    global _netcut_timer
    need_admin()
    if _netcut_timer:
        _netcut_timer.cancel()
        _netcut_timer = None
    if not b.get("enable"):
        ok, e = _netcut_remove()
        if not ok:
            return {"ok": False, "error": e or "Kural silinemedi"}
        NETCUT.update(on=False, until=0)
        MON.add_event("action", "info", "İnternet erişimi yeniden açıldı")
        return {"ok": True}
    minutes = max(0, min(1440, int(b.get("minutes", 0) or 0)))
    auto_backup("kes")
    _netcut_remove()
    addrs = ",".join(non_private_cidrs())
    for d, lbl in (("Outbound", "giden"), ("Inbound", "gelen")):
        code, out, err = run_ps(
            f"New-NetFirewallRule -DisplayName $env:SYSDASH_NAME -Group 'SysDash' -Direction {d} -Action Block "
            f"-RemoteAddress ($env:SYSDASH_ARG -split ',') -Profile Any | Out-Null",
            timeout=60, env_extra={"SYSDASH_ARG": addrs, "SYSDASH_NAME": f"{KILL_PREFIX} ({lbl})"})
        if code != 0:
            _netcut_remove()
            return {"ok": False, "error": clean_ps_err(err) or "Kural eklenemedi"}
    NETCUT.update(on=True, until=time.time() + minutes * 60 if minutes else 0)
    MON.add_event("action", "warn", "İnternet erişimi kesildi" + (f" ({minutes} dk sonra otomatik açılacak)" if minutes else ""))
    if minutes:
        def restore():
            _netcut_remove()
            NETCUT.update(on=False, until=0)
            MON.add_event("action", "info", "İnternet erişimi süre dolduğu için yeniden açıldı")
        _netcut_timer = threading.Timer(minutes * 60, restore)
        _netcut_timer.daemon = True
        _netcut_timer.start()
    CACHE["fw_rules"].get(True)
    return {"ok": True}


CC_PREFIX = "SysDash Ülke Engeli - "


def post_blockcountry(b):
    need_admin()
    cc = str(b.get("cc", "")).upper()
    if len(cc) != 2 or not cc.isalpha():
        return {"ok": False, "error": "Geçersiz ülke kodu"}
    if not GEO or not GEO.ready:
        return {"ok": False, "error": "IP veritabanı henüz yüklenmedi"}
    ranges = GEO.ranges(cc)
    if not ranges:
        return {"ok": False, "error": f"{cc} için adres aralığı bulunamadı"}
    if len(ranges) > 20000:
        return {"ok": False, "error": f"{cc} çok fazla adres aralığı içeriyor ({len(ranges)}); güvenlik duvarı kuralı için fazla büyük"}
    auto_backup("ulke")
    chunks, cur, n = [], [], 0
    for r in ranges:
        if n + len(r) + 1 > 20000:
            chunks.append(",".join(cur))
            cur, n = [], 0
        cur.append(r)
        n += len(r) + 1
    if cur:
        chunks.append(",".join(cur))
    tmp = os.path.join(tempfile.gettempdir(), f"sysdash_cc_{os.getpid()}.json")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(chunks, f)
    try:
        code, out, err = run_ps(
            "Get-NetFirewallRule -DisplayName ($env:SYSDASH_PFX + $env:SYSDASH_CC + ' (*') -ErrorAction SilentlyContinue | Remove-NetFirewallRule;"
            " $chunks = @(Get-Content -Raw -Encoding UTF8 $env:SYSDASH_ARG | ConvertFrom-Json); $n = $chunks.Count; $i = 0;"
            " foreach ($c in $chunks) { $i++; foreach ($d in 'Outbound','Inbound') {"
            " New-NetFirewallRule -DisplayName ($env:SYSDASH_PFX + $env:SYSDASH_CC + \" ($i/$n) \" + $d) -Group 'SysDash'"
            " -Direction $d -Action Block -RemoteAddress ($c -split ',') -Profile Any | Out-Null } }",
            timeout=300, env_extra={"SYSDASH_ARG": tmp, "SYSDASH_CC": cc, "SYSDASH_PFX": CC_PREFIX})
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass
    if code != 0:
        return {"ok": False, "error": clean_ps_err(err) or "Kural eklenemedi"}
    MON.add_event("action", "warn", f"Ülke engellendi: {cc} ({len(ranges)} adres aralığı)")
    CACHE["fw_rules"].get(True)
    return {"ok": True, "ranges": len(ranges)}


def post_unblockcountry(b):
    need_admin()
    cc = str(b.get("cc", "")).upper()
    if len(cc) != 2 or not cc.isalpha():
        return {"ok": False, "error": "Geçersiz ülke kodu"}
    code, out, err = run_ps(
        "Get-NetFirewallRule -DisplayName ($env:SYSDASH_PFX + $env:SYSDASH_CC + ' (*') -ErrorAction SilentlyContinue | Remove-NetFirewallRule",
        timeout=120, env_extra={"SYSDASH_CC": cc, "SYSDASH_PFX": CC_PREFIX})
    if code != 0:
        return {"ok": False, "error": clean_ps_err(err)}
    MON.add_event("action", "info", f"Ülke engeli kaldırıldı: {cc}")
    CACHE["fw_rules"].get(True)
    return {"ok": True}


def api_timeline(q):
    pid = int(q.get("pid", ["0"])[0])
    now = time.time()
    if "t" in q:
        t = float(q["t"][0])
        lo, hi = t - 900, t + 900
    else:
        lo, hi = now - 1800, now
    items = []
    for e in list(MON.events):
        if e.get("pid") == pid and lo <= e["t"] <= hi:
            items.append({"t": e["t"], "k": e["kind"], "lvl": e["level"], "msg": e["msg"]})
    if NETTRACE is not None and NETTRACE.status == "ok":
        for r in NETTRACE.dns_for(pid, lo, hi):
            if r["kind"] == "yanıt":
                res = (r["results"] or "").replace("::ffff:", "")[:80]
                items.append({"t": r["t"], "k": "dns", "lvl": "info",
                              "msg": f'DNS: {r["name"]} ({r["qtype"]})' + (f" → {res}" if res else "")})
        buckets = {}
        for r in NETTRACE.rows_for(pid, lo, hi):
            k = (int(r["t"] // 10), r["dir"], r["proto"], r["rip"], r["rport"])
            e = buckets.setdefault(k, [r["t"], 0, 0])
            e[1] += r["size"]
            e[2] += 1
        for (_, d, proto, rip, rport), (t0, size, cnt) in buckets.items():
            g = GEO.lookup(rip) if GEO and ip_class(rip) == "public" else None
            host = NETTRACE.host_of(rip) or RDNS.get(rip) or ""
            tail = " · ".join(x for x in (host, (g or {}).get("cc", ""), (g or {}).get("org", "")) if x)
            items.append({"t": t0, "k": "net_" + d, "lvl": "info",
                          "msg": f'{"Giden" if d == "out" else "Gelen"} {proto} {rip}:{rport} — {fmt_bytes(size)}'
                                 + (f" ({tail})" if tail else "")})
    items.sort(key=lambda x: x["t"])
    return {"items": items[-400:], "lo": lo, "hi": hi}


def post_unblock_program(b):
    need_admin()
    val = str(b.get("value", "")).strip()
    names = [f"SysDash Engel - program {val} (giden)", f"SysDash Engel - program {val} (gelen)"]
    code, out, err = run_ps(
        "Get-NetFirewallRule -Group 'SysDash' | Where-Object { ($env:SYSDASH_ARG -split '\\|') -contains $_.DisplayName }"
        " | Remove-NetFirewallRule", timeout=60, env_extra={"SYSDASH_ARG": "|".join(names)})
    if code != 0:
        return {"ok": False, "error": clean_ps_err(err)}
    TIMED.pop(val.lower(), None)
    _timed_save()
    MON.add_event("action", "info", f"Program engeli kaldırıldı: {val}")
    CACHE["fw_rules"].get(True)
    return {"ok": True}


BACKUP_DIR = os.path.join(APP_DIR, "backups")
_BK_RE = re.compile(r"^fw-(\d{8})-(\d{6})-([a-z0-9-]{1,30})\.wfw$")
BK_REASONS = {"elle": "Elle alındı", "ilk": "İlk yedek", "ulke": "Ülke engeli öncesi", "kes": "İnternet kesme öncesi",
              "engel": "Engelleme öncesi", "geri-yukleme-oncesi": "Geri yükleme öncesi", "kural": "Kural değişikliği öncesi"}
BK_KEEP = 40
_last_auto_bk = [0.0]


def _netsh(*args):
    r = subprocess.run(["netsh", "advfirewall", *args], capture_output=True, creationflags=CREATE_NO_WINDOW, timeout=120)
    txt = (r.stdout + r.stderr).decode("oem", "replace").strip()
    return r.returncode == 0, txt


def fw_backup(reason="elle"):
    """Tum guvenlik duvari ilkesini (kurallar + profiller) .wfw dosyasina aktarir. -> (ok, ad_veya_hata)"""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    name = f"fw-{time.strftime('%Y%m%d-%H%M%S')}-{reason}.wfw"
    ok, txt = _netsh("export", os.path.join(BACKUP_DIR, name))
    if not ok or not os.path.isfile(os.path.join(BACKUP_DIR, name)):
        return False, txt or "Yedek alınamadı"
    files = sorted(f for f in os.listdir(BACKUP_DIR) if _BK_RE.match(f))
    for old in files[:-BK_KEEP]:
        try:
            os.remove(os.path.join(BACKUP_DIR, old))
        except OSError:
            pass
    return True, name


def auto_backup(reason):
    """Riskli bir degisiklikten once (en fazla 10 dakikada bir) sessizce yedek al."""
    if not ADMIN or time.time() - _last_auto_bk[0] < 600:
        return
    _last_auto_bk[0] = time.time()
    try:
        ok, n = fw_backup(reason)
        MON.add_event("fwchange", "info" if ok else "warn",
                      f"Güvenlik duvarı yedeği alındı ({BK_REASONS.get(reason, reason)}): {n}" if ok else f"Otomatik yedek alınamadı: {n}")
    except Exception:
        traceback.print_exc()


def api_fwbackups(q):
    out = []
    if os.path.isdir(BACKUP_DIR):
        for f in sorted(os.listdir(BACKUP_DIR), reverse=True):
            m = _BK_RE.match(f)
            if not m:
                continue
            fp = os.path.join(BACKUP_DIR, f)
            out.append({"name": f, "t": os.path.getmtime(fp), "size": os.path.getsize(fp),
                        "reason": BK_REASONS.get(m.group(3), m.group(3))})
    return {"backups": out, "admin": ADMIN, "dir": BACKUP_DIR}


def post_fwbackup(b):
    need_admin()
    ok, n = fw_backup("elle")
    if not ok:
        return {"ok": False, "error": n}
    MON.add_event("fwchange", "info", f"Güvenlik duvarı yedeği alındı: {n}")
    return {"ok": True, "name": n}


def _bk_path(name):
    name = str(name or "")
    if not _BK_RE.match(name):
        return None
    fp = os.path.join(BACKUP_DIR, name)
    return fp if os.path.isfile(fp) else None


def post_fwrestore(b):
    need_admin()
    fp = _bk_path(b.get("name"))
    if not fp:
        return {"ok": False, "error": "Yedek dosyası bulunamadı"}
    ok, n = fw_backup("geri-yukleme-oncesi")
    if not ok:
        return {"ok": False, "error": "Geri yüklemeden önce mevcut durum yedeklenemedi: " + n}
    ok, txt = _netsh("import", fp)
    if not ok:
        return {"ok": False, "error": txt or "Geri yükleme başarısız"}
    MON.add_event("fwchange", "warn", f"Güvenlik duvarı yedekten geri yüklendi: {os.path.basename(fp)}")
    FWWATCH["skip"] = True  # geri yukleme degisikligi uyari uretmesin
    netcut_status()
    for k in ("fw_profiles", "fw_rules"):
        CACHE[k].get(True)
    return {"ok": True}


def _rule_ps(b, action_ps, env_extra=None):
    """Ad + yone gore kurallari bulup action_ps ile degistirir. -> (ok, hata)"""
    name = str(b.get("name", ""))
    d = "Inbound" if b.get("dir") == "in" else "Outbound"
    if not name:
        return False, "Kural adı eksik"
    code, out, err = run_ps(
        "$d = $env:SYSDASH_DIR; $r = @(Get-NetFirewallRule | Where-Object { $_.DisplayName -eq $env:SYSDASH_ARG -and [string]$_.Direction -eq $d });"
        " if ($r.Count -eq 0) { Write-Error 'Kural bulunamadı'; exit 3 }; $r | " + action_ps,
        timeout=90, env_extra={"SYSDASH_ARG": name, "SYSDASH_DIR": d, **(env_extra or {})})
    if code == 3:
        return False, "Kural bulunamadı (adı farklı olabilir; listeyi yenileyin)"
    if code != 0:
        return False, clean_ps_err(err) or "İşlem başarısız"
    return True, ""


def post_fwrule_toggle(b):
    need_admin()
    en = bool(b.get("enable"))
    auto_backup("kural")
    ok, e = _rule_ps(b, "Enable-NetFirewallRule" if en else "Disable-NetFirewallRule")
    if not ok:
        return {"ok": False, "error": e}
    FWWATCH["skip"] = True
    _fwchg_add(b.get("name"), b.get("dir"), "enable" if en else "disable")
    MON.add_event("fwchange", "warn", f'Güvenlik duvarı kuralı {"etkinleştirildi" if en else "devre dışı bırakıldı"}: {b.get("name")}')
    CACHE["fw_rules"].get(True)
    return {"ok": True}


def post_fwrule_scope(b):
    """Gelen kuralin uzak adresini verilen aralıklarla sinirlar (ornegin Tailscale 100.64.0.0/10)."""
    need_admin()
    parts = [x.strip() for x in str(b.get("remote", "")).split(",") if x.strip()]
    if not parts:
        return {"ok": False, "error": "En az bir adres/aralık girin"}
    for x in parts:
        try:
            ipaddress.ip_network(x, strict=False)
        except ValueError:
            return {"ok": False, "error": f"Geçersiz adres/aralık: {x}"}
    auto_backup("kural")
    ok, e = _rule_ps(b, "Set-NetFirewallRule -RemoteAddress ($env:SYSDASH_REMOTE -split ',')",
                     {"SYSDASH_REMOTE": ",".join(parts)})
    if not ok:
        return {"ok": False, "error": e}
    FWWATCH["skip"] = True
    _fwchg_add(b.get("name"), b.get("dir"), "scope", ",".join(parts))
    MON.add_event("fwchange", "warn", f'Kuralın uzak adresi sınırlandı: {b.get("name")} → {", ".join(parts)}')
    CACHE["fw_rules"].get(True)
    return {"ok": True}


def post_fwbackup_delete(b):
    fp = _bk_path(b.get("name"))
    if not fp:
        return {"ok": False, "error": "Yedek dosyası bulunamadı"}
    os.remove(fp)
    return {"ok": True}


# ---- Kural sagligi
def _ports_of(spec):
    single, ranges = set(), []
    for part in str(spec or "").split(","):
        part = part.strip()
        if part.isdigit():
            single.add(int(part))
        elif re.fullmatch(r"\d+-\d+", part):
            a, c = part.split("-")
            ranges.append((int(a), int(c)))
    return single, ranges


def _has_port(spec, port):
    single, ranges = _ports_of(spec)
    return port in single or any(a <= port <= c for a, c in ranges)


EXPOSE_PORTS = {21: "FTP", 23: "Telnet", 135: "MS-RPC", 139: "NetBIOS", 445: "SMB", 1433: "MSSQL", 2375: "Docker API",
                3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 5986: "WinRM-HTTPS",
                6379: "Redis", 27017: "MongoDB"}


def fw_health(rules, profs, netcut_on=False, listening=()):
    out = []

    def add(level, title, detail, items=None, refs=None, scope=False):
        """refs: items ile ayni sirada [{"n": kural adi, "d": "in"/"out"}]; scope: 'uzak adresi sinirla' sunulsun mu."""
        items = items or []
        out.append({"level": level, "title": title, "detail": detail, "items": items[:30], "n": len(items),
                    "refs": (refs or [])[:30], "scope": scope})

    def ref(r):
        return {"n": r["name"], "d": r["dir"]}

    pn = {"Domain": "Etki alanı", "Private": "Özel", "Public": "Genel"}
    for p in profs or []:
        nm = pn.get(p.get("name"), p.get("name"))
        if p.get("enabled") != "True":
            add("bad", f"{nm} profilinde güvenlik duvarı KAPALI",
                "Bu profildeki ağlara bağlanınca hiçbir kural uygulanmaz. Öneri: Windows Güvenliği → Güvenlik duvarı bölümünden açın.")
        if p.get("inAct") == "Allow":
            add("bad", f"{nm} profilinde varsayılan gelen eylem 'İzin ver'",
                "Kuralı olmayan her gelen bağlantı kabul edilir. Öneri: varsayılan gelen eylemi 'Engelle' olmalı.")
    if profs and not any(p.get("logBlocked") == "True" or p.get("logAllowed") == "True" for p in profs):
        add("info", "Güvenlik duvarı loglaması kapalı",
            "Engellenen bağlantılar kaydedilmiyor; olay incelemesi zorlaşır. Öneri: yukarıdaki banner'dan loglamayı açın.")
    if netcut_on:
        add("warn", "İnternet kesici kuralı etkin",
            "'SysDash İnternet Kesici' (Gözcü) kuralları hâlâ duruyor; tüm internet erişimi engelli. Öneri: üst çubuktan geri açın.")

    act = [r for r in rules or [] if r.get("enabled")]
    inallow = [r for r in act if r["dir"] == "in" and r["action"] == "allow"]

    # Mağaza/paketli uygulama kuralları program yolu yerine paket kimliğine bağlıdır (COM'dan okunamaz): yanlış alarm olmasın
    broad = [r for r in inallow if not r["app"] and not r["svc"] and r["lport"] in ("*", "")
             and r["raddr"] in ("*", "") and r["proto"] in ("Tümü", "TCP", "UDP")
             and not r["name"].endswith("(Store uygulaması)") and r.get("group") != r["name"]]
    if broad:
        add("warn", f"Program/port kısıtı görünmeyen gelen izin kuralları ({len(broad)})",
            "Bu kurallarda program, port ve uzak adres kısıtı okunamıyor; makineyi her yerden erişilebilir kılıyor olabilir. "
            "Not: arayüz (ör. VPN) ya da paket bazlı kurallar yanlış alarm olabilir; Mağaza uygulamaları dahil edilmedi. "
            "Öneri: tanımadığınız kuralları devre dışı bırakın.", [r["name"] for r in broad], [ref(r) for r in broad])

    sus = [r for r in inallow if r["app"] and any(d in os.path.expandvars(r["app"]).lower() for d in SUSPICIOUS_DIRS)]
    if sus:
        add("warn", f"Geçici/şüpheli klasördeki programlara gelen izin ({len(sus)})",
            "Temp, Downloads, Public gibi klasörlerdeki programlara kalıcı izin verilmesi zararlı yazılım belirtisi olabilir. "
            "Çoğu zaman bir kurulum/demo programının bıraktığı kuraldır. "
            "Öneri: programı tanımıyor ya da artık kullanmıyorsanız kuralı devre dışı bırakın.",
            [f'{r["name"]} → {r["app"]}' for r in sus], [ref(r) for r in sus])

    live, core, dormant = [], [], []   # (metin, kural)
    for r in inallow:
        if r["raddr"] in ("*", "") and r["lport"] not in ("*", "") and r["proto"] in ("TCP", "UDP", "Tümü"):
            for port, nm in EXPOSE_PORTS.items():
                if _has_port(r["lport"], port):
                    item = (f'{r["name"]} → {nm} ({port}) · {r["profiles"]}', r)
                    if port not in listening:
                        dormant.append(item)
                    elif port in (135, 139, 445):
                        core.append(item)   # Windows'ta zaten hep dinler; yalnızca Genel ağlarda anlamlı
                    else:
                        live.append(item)
                    break
    if live:
        add("bad", f"Riskli port her adresten erişime açık VE şu an dinleniyor ({len(live)})",
            "Bu portlarda gerçekten bir servis dinliyor ve güvenlik duvarı her adresten erişime izin veriyor "
            "(Genel/kafe ağlarında da). Öneri: servisi kullanmıyorsanız kapatın; kullanıyorsanız kuralın uzak adresini "
            "yalnızca güvendiğiniz IP'lerle sınırlayın (ör. Tailscale kullanıyorsanız yalnızca Tailscale aralığına).",
            [i for i, _ in live], [ref(r) for _, r in live], scope=True)
    if core:
        add("warn", f"Windows'un yerleşik RPC/SMB portları her adresten açık ({len(core)})",
            "135/139/445 Windows'ta her zaman dinler; kural 'Genel' profili de kapsıyorsa kafe/otel gibi ağlarda bu portlar "
            "dışarıdan erişilebilir olur. Öneri: kullanmıyorsanız (Hyper-V uzak yönetimi, dosya paylaşımı) kuralları devre dışı bırakın.",
            [i for i, _ in core], [ref(r) for _, r in core], scope=True)
    if dormant:
        add("info", f"Riskli portlara açık ama şu an dinleyen servis yok ({len(dormant)})",
            "RDP, SMB, VNC gibi hizmetler için izin kuralı var; ilgili servis kapalı olduğundan şu an risk yok, "
            "ama servis açılırsa hemen erişilebilir olur. Öneri: kullanmıyorsanız kuralları devre dışı bırakın.",
            [i for i, _ in dormant], [ref(r) for _, r in dormant], scope=True)

    dead = []
    for r in act:
        a = r["app"]
        if r["action"] == "allow" and a and not a.startswith("@") and "{" not in a and "*" not in a:
            if not os.path.exists(os.path.expandvars(a)):
                dead.append(r)
    if dead:
        add("info", f"Programı artık olmayan izin kuralları ({len(dead)})",
            "Silinmiş/kaldırılmış programlara ait kurallar boşuna kalabilir; aynı yola sonradan konan bir dosya izin alır. "
            "Öneri: kullanmadığınız programların kurallarını devre dışı bırakın.",
            [f'{r["name"]} → {r["app"]}' for r in dead], [ref(r) for r in dead])

    def k6(r):
        return (r["dir"], r["app"].lower(), r["svc"].lower(), r["proto"], r["lport"], r["rport"], r["raddr"])
    allow, block = {}, {}
    for r in act:
        if not (r["app"] or r["svc"] or r["lport"] not in ("*", "")):
            continue
        (allow if r["action"] == "allow" else block).setdefault(k6(r), []).append(r["name"])
    conf = [f'İzin: {allow[k][0]} ⟷ Engel: {block[k][0]}' for k in allow.keys() & block.keys()]
    if conf:
        add("warn", f"İzin ve engel kuralları çakışıyor ({len(conf)})",
            "Windows'ta engel kuralı izin kuralına baskındır; bu yüzden izin kuralı sessizce etkisiz kalıyor. "
            "Öneri: hangisini istediğinize karar verip diğerini silin.", conf)

    dup = {}
    for r in act:
        dup.setdefault(k6(r) + (r["action"], r["profiles"]), []).append(r["name"])
    dups = [f'{v[0]} (×{len(v)})' for v in dup.values() if len(v) > 1]
    if dups:
        add("info", f"Birebir aynı kurallar ({len(dups)} grup)",
            "Aynı program/port/profil için yinelenen kurallar listeyi karıştırır. Öneri: fazlalıkları silin.", dups)

    order = {"bad": 0, "warn": 1, "info": 2}
    out.sort(key=lambda f: order[f["level"]])
    return out


def api_fwhealth(q):
    force = q.get("force", ["0"])[0] == "1"
    rules, e1 = CACHE["fw_rules"].get(force)
    profs, e2 = CACHE["fw_profiles"].get(force)
    listening = {c["lport"] for c in MON.snapshot.get("conns", []) if c["dir"] == "listen" and ip_class(c["lip"]) != "loopback"}
    f = fw_health(rules or [], profs or [], NETCUT["on"], listening)
    return {"findings": f, "rules": len(rules or []), "err": e1 or e2,
            "counts": {k: sum(1 for x in f if x["level"] == k) for k in ("bad", "warn", "info")}}


# ---- Degisiklik izleme
FW_SNAP_FILE = os.path.join(APP_DIR, "fw_snapshot.json")
FW_WATCH_SECS = 90
FWWATCH = {"skip": False}


def _rkey(r):
    return "|".join(str(r.get(k, "")) for k in ("name", "dir", "action", "app", "svc", "proto", "lport",
                                               "rport", "laddr", "raddr", "profiles", "enabled"))


def fw_diff(prev, rules, profs, closed=False):
    """prev: {"profiles": {ad: [enabled,in,out]}, "rules": {anahtar: {ad, dir, action, ...}}}.
    -> (uyarilar[(anahtar, seviye, mesaj)], olaylar[(seviye, mesaj)])"""
    alerts, events = [], []
    pre = "Panel kapalıyken: " if closed else ""
    pn = {"Domain": "Etki alanı", "Private": "Özel", "Public": "Genel"}
    cur_prof = {p["name"]: [p.get("enabled"), p.get("inAct"), p.get("outAct")] for p in profs}
    for name, v in cur_prof.items():
        o = prev.get("profiles", {}).get(name)
        if not o or o == v:
            continue
        nm = pn.get(name, name)
        if o[0] == "True" and v[0] != "True":
            alerts.append((("fwprof", name, "off", v[0]), "high", f"{pre}{nm} profilinde güvenlik duvarı KAPATILDI"))
        elif o[0] != "True" and v[0] == "True":
            events.append(("info", f"{pre}{nm} profilinde güvenlik duvarı açıldı"))
        if o[1] != v[1]:
            if v[1] == "Allow":
                alerts.append((("fwprof", name, "in", v[1]), "high",
                               f"{pre}{nm} profilinde varsayılan gelen eylem değişti: {o[1]} → {v[1]}"))
            else:
                events.append(("info", f"{pre}{nm} varsayılan gelen eylem: {o[1]} → {v[1]}"))
        if o[2] != v[2]:
            events.append(("info", f"{pre}{nm} profilinde varsayılan giden eylem değişti: {o[2]} → {v[2]}"))

    old = prev.get("rules", {})
    cur = {_rkey(r): r for r in rules if not r.get("sysdash")}
    added = [k for k in cur if k not in old]
    removed = [k for k in old if k not in cur]
    old_names = {(v["name"], v["dir"]) for v in old.values()}
    cur_names = {(v["name"], v["dir"]) for v in cur.values()}
    shown = 0
    for k in added:
        r = cur[k]
        if not (r["enabled"] and r["dir"] == "in" and r["action"] == "allow"):
            continue
        changed = (r["name"], r["dir"]) in old_names
        broad = (not r["app"] and not r["svc"] and r["lport"] in ("*", "") and r["raddr"] in ("*", "")
                 and not r["name"].endswith("(Store uygulaması)") and r.get("group") != r["name"])
        sus = bool(r["app"]) and any(d in os.path.expandvars(r["app"]).lower() for d in SUSPICIOUS_DIRS)
        lvl = "high" if (broad or sus) else "warn"
        if lvl == "warn" and (len(added) > 15 or shown >= 8):
            continue  # toplu degisiklik (ornegin Windows guncellemesi): tek tek uyari yerine ozet
        shown += 1
        what = "değiştirildi" if changed else "eklendi"
        alerts.append((("fwrule", k), lvl,
                       f'{pre}Gelen izin kuralı {what}: "{r["name"]}" ({r["proto"]} {r["lport"]}) {r["app"] or r["svc"] or "tüm programlar"}'
                       + (" — çok geniş kural" if broad else " — şüpheli klasördeki program" if sus else "")))
    n_new = len({cur[k]["name"] for k in added if (cur[k]["name"], cur[k]["dir"]) not in old_names})
    n_gone = len({old[k]["name"] for k in removed if (old[k]["name"], old[k]["dir"]) not in cur_names})
    if n_new or n_gone:
        events.append(("info", f"{pre}Güvenlik duvarı kuralları değişti: {n_new} eklendi, {n_gone} silindi"))
    for k in removed:
        o = old[k]
        if o["action"] == "block" and o["enabled"] and (o["name"], o["dir"]) not in cur_names:
            alerts.append((("fwrm", k), "warn",
                           f'{pre}Engelleme kuralı silindi: "{o["name"]}" ({o["proto"]} {o["lport"]}) {o["app"] or ""}'.rstrip()))
    return alerts, events


def _fw_snapshot(rules, profs):
    return {"profiles": {p["name"]: [p.get("enabled"), p.get("inAct"), p.get("outAct")] for p in profs},
            "rules": {_rkey(r): {k: r.get(k, "") for k in ("name", "dir", "action", "app", "svc", "proto", "lport", "enabled")}
                      for r in rules if not r.get("sysdash")}}


def fw_watch_loop():
    prev = None
    closed = False
    try:
        with open(FW_SNAP_FILE, "r", encoding="utf-8") as f:
            prev = json.load(f)
        closed = True
    except (OSError, ValueError):
        pass
    while True:
        try:
            profs, _ = CACHE["fw_profiles"].get(True)
            rules, _ = CACHE["fw_rules"].get(True)
            if rules and profs:
                snap = _fw_snapshot(rules, profs)
                if FWWATCH["skip"]:
                    FWWATCH["skip"] = False
                elif prev is not None:
                    alerts, events = fw_diff(prev, rules, profs, closed)
                    for key, lvl, msg in alerts:
                        MON.add_alert(key, lvl, msg)
                    for lvl, msg in events:
                        MON.add_event("fwchange", lvl, msg)
                closed = False
                prev = snap
                try:
                    with open(FW_SNAP_FILE, "w", encoding="utf-8") as f:
                        json.dump(snap, f)
                except OSError:
                    pass
        except Exception:
            traceback.print_exc()
        time.sleep(FW_WATCH_SECS)


def post_fw_remove(b):
    need_admin()
    name = str(b.get("name", ""))
    code, out, err = run_ps(
        "Get-NetFirewallRule -Group 'SysDash' | Where-Object { $_.DisplayName -eq $env:SYSDASH_ARG } | Remove-NetFirewallRule",
        timeout=60, env_extra={"SYSDASH_ARG": name})
    if code != 0:
        return {"ok": False, "error": clean_ps_err(err)}
    MON.add_event("action", "info", f"Güvenlik duvarı kuralı silindi: {name}")
    CACHE["fw_rules"].get(True)
    return {"ok": True}


def post_fw_logging(b):
    need_admin()
    en = "True" if b.get("enable") else "False"
    code, out, err = run_ps(
        f"Set-NetFirewallProfile -All -LogBlocked {en} -LogAllowed {en} -LogMaxSizeKilobytes 32767", timeout=60)
    if code != 0:
        return {"ok": False, "error": clean_ps_err(err)}
    MON.fwlog_pos = None
    CACHE["fw_profiles"].get(True)
    MON.add_event("action", "info", f"Güvenlik duvarı loglaması {'açıldı' if b.get('enable') else 'kapatıldı'}")
    return {"ok": True}


def _approved_key(source):
    """Başlangıç öğesinin Windows'un 'StartupApproved' kaydı: (hive, alt anahtar) ya da None."""
    base = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved"
    if source == "HKCU Run":
        return winreg.HKEY_CURRENT_USER, base + r"\Run"
    if source == "HKLM Run":
        return winreg.HKEY_LOCAL_MACHINE, base + r"\Run"
    if source == "HKLM Run (32-bit)":
        return winreg.HKEY_LOCAL_MACHINE, base + r"\Run32"
    if source.startswith("Başlangıç klasörü"):
        hive = winreg.HKEY_CURRENT_USER if "(kullanıcı)" in source else winreg.HKEY_LOCAL_MACHINE
        return hive, base + r"\StartupFolder"
    return None


def post_startup_toggle(b):
    name, source, enable = str(b.get("name", "")), str(b.get("source", "")), bool(b.get("enable"))
    st, _ = CACHE["startup"].get(True)
    if not any(i["name"] == name and i["source"] == source for i in (st or [])):
        return {"ok": False, "error": "Başlangıç öğesi bulunamadı (listeyi yenileyin)"}
    loc = _approved_key(source)
    if not loc:
        return {"ok": False, "error": "Bu kaynak türü buradan değiştirilemez"}
    hive, sub = loc
    if hive == winreg.HKEY_LOCAL_MACHINE:
        need_admin()
    if enable:
        data = b"\x02" + b"\x00" * 11
    else:
        ft = int((time.time() + 11644473600) * 10_000_000)
        data = b"\x03\x00\x00\x00" + struct.pack("<Q", ft)
    try:
        with winreg.CreateKeyEx(hive, sub, 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, name, 0, winreg.REG_BINARY, data)
    except OSError as e:
        return {"ok": False, "error": f"Kayıt defterine yazılamadı: {e}"}
    CACHE["startup"].get(True)
    MON.add_event("action", "info", f"Başlangıç öğesi {'etkinleştirildi' if enable else 'devre dışı bırakıldı'}: {name}")
    return {"ok": True}


def post_reveal(b):
    path = str(b.get("path", ""))
    if not os.path.exists(path):
        return {"ok": False, "error": "Yol bulunamadı"}
    subprocess.Popen(["explorer.exe", "/select,", os.path.normpath(path)])
    return {"ok": True}


def post_scan(b):
    ok, err = SCANNER.start(str(b.get("path", "")), float(b.get("min_mb", 100)))
    return {"ok": ok, "error": err}


def post_scan_cancel(b):
    SCANNER.cancel = True
    return {"ok": True}


def post_elevate(b):
    if ADMIN:
        return {"ok": True, "msg": "Zaten yönetici"}
    exe, params, wdir = self_command(f"--no-browser --wait-port --port {PORT}")
    r = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, wdir, 1)
    if r <= 32:
        return {"ok": False, "error": "Yükseltme iptal edildi"}
    threading.Timer(1.0, lambda: os._exit(0)).start()
    return {"ok": True}


def post_clear_alerts(b):
    MON.alerts.clear()
    return {"ok": True}


def api_alerts(q):
    """Aktif (henüz temizlenmemiş) uyarılar, en yeni üstte: menüdeki Canlı Akış rozetinin sayısı."""
    return {"alerts": [dict(a) for a in list(MON.alerts)[::-1][:100]]}


def post_alert_dismiss(b):
    aid = int(b.get("id", 0) or 0)
    MON.alerts = deque((a for a in MON.alerts if a["id"] != aid), maxlen=500)
    return {"ok": True}


# ---- Değişiklik tespiti: "referans" anı ile şimdiki durumu karşılaştır
BASELINE_FILE = os.path.join(APP_DIR, "baseline.json")
BASE_LABELS = {"startup": "Başlangıç öğesi", "tasks": "Zamanlanmış görev", "services": "Servis",
               "ports": "Dinleyen port", "devices": "Ağ cihazı", "rules": "Gelen izin kuralı"}


def baseline_snapshot():
    snap = {k: {} for k in BASE_LABELS}
    snap["t"] = time.time()
    st, _ = CACHE["startup"].get(True)
    for i in st or []:
        snap["startup"][f'{i["source"]} | {i["name"]}'] = i["cmd"] + ("" if i["enabled"] else "  [devre dışı]")
    tk, _ = CACHE["tasks"].get(True)
    for t in tk or []:
        if not t.get("ms"):
            snap["tasks"][f'{t.get("path", "")}{t.get("name", "")}'] = t.get("run", "")
    sv, _ = CACHE["services"].get(True)
    for s in sv or []:
        snap["services"][s["name"]] = f'{s["bin"]} ({s["start"]})'
    for c in MON.snapshot["conns"]:
        if c["dir"] == "listen" and ip_class(c["lip"]) != "loopback" and (c["proto"] == "TCP" or c["lport"] < 49152):
            snap["ports"][f'{c["proto"]} {c["lport"]} · {c["name"]}'] = c["exe"]
    nb, _ = CACHE["neighbors"].get(True)
    for n in nb or []:
        snap["devices"][(n.get("mac") or "").upper()] = n.get("ip", "")
    rules, _ = CACHE["fw_rules"].get(True)
    for r in rules or []:
        if r["enabled"] and r["dir"] == "in" and r["action"] == "allow" and not r["sysdash"]:
            snap["rules"][f'{r["name"]} | {r["proto"]} {r["lport"]} | {r["app"]}'] = r["raddr"]
    return snap


def api_baseline(q):
    try:
        with open(BASELINE_FILE, encoding="utf-8") as f:
            base = json.load(f)
    except (OSError, ValueError):
        return {"exists": False}
    cur = baseline_snapshot()
    diff = []
    for cat, label in BASE_LABELS.items():
        b, c = base.get(cat, {}), cur[cat]
        for k in sorted(c.keys() - b.keys()):
            diff.append({"cat": label, "kind": "added", "item": k, "detail": c[k]})
        for k in sorted(b.keys() - c.keys()):
            diff.append({"cat": label, "kind": "removed", "item": k, "detail": b[k]})
        for k in sorted(c.keys() & b.keys()):
            if b[k] != c[k]:
                diff.append({"cat": label, "kind": "changed", "item": k, "detail": f"{b[k]}  →  {c[k]}"})
    return {"exists": True, "saved": base.get("t", 0), "diff": diff,
            "sizes": {BASE_LABELS[k]: len(cur[k]) for k in BASE_LABELS}}


def post_baseline_save(b):
    snap = baseline_snapshot()
    with open(BASELINE_FILE, "w", encoding="utf-8") as f:
        json.dump(snap, f, ensure_ascii=False)
    MON.add_event("action", "info", "Değişiklik tespiti için referans noktası kaydedildi")
    return {"ok": True}


# ---- Güvenli temizlik önerileri (yalnızca sabit, bilinen önbellek/geçici klasörler)
def cleanup_targets():
    la = os.environ.get("LOCALAPPDATA", "")
    win = os.environ.get("SystemRoot", r"C:\Windows")
    t = [
        ("temp", "Kullanıcı geçici dosyaları", tempfile.gettempdir()),
        ("wintemp", "Windows geçici dosyaları", os.path.join(win, "Temp")),
        ("inet", "Windows internet önbelleği", os.path.join(la, r"Microsoft\Windows\INetCache")),
        ("chrome", "Chrome önbelleği", os.path.join(la, r"Google\Chrome\User Data\Default\Cache")),
        ("edge", "Edge önbelleği", os.path.join(la, r"Microsoft\Edge\User Data\Default\Cache")),
        ("crash", "Çökme dökümleri", os.path.join(la, "CrashDumps")),
        ("wu", "Windows Update indirmeleri", os.path.join(win, r"SoftwareDistribution\Download")),
        ("npm", "npm önbelleği", os.path.join(la, "npm-cache")),
        ("pip", "pip önbelleği", os.path.join(la, r"pip\Cache")),
    ]
    return [(i, n, p) for i, n, p in t if p and os.path.isdir(p)]


def _dir_size(path, deadline):
    total = files = 0
    stale = 0
    cutoff = time.time() - 86400
    approx = False
    stack = [path]
    while stack:
        if time.time() > deadline:
            approx = True
            break
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    try:
                        if e.is_symlink():
                            continue
                        if e.is_dir(follow_symlinks=False):
                            stack.append(e.path)
                        else:
                            st = e.stat(follow_symlinks=False)
                            total += st.st_size
                            files += 1
                            if st.st_mtime < cutoff:
                                stale += st.st_size
                    except OSError:
                        pass
        except OSError:
            pass
    return total, stale, files, approx


def cleanup_scan():
    out = []
    for cid, name, path in cleanup_targets():
        size, stale, files, approx = _dir_size(path, time.time() + 6)
        out.append({"id": cid, "name": name, "path": path, "size": size, "stale": stale, "files": files,
                    "approx": approx, "admin_only": cid in ("wintemp", "wu") and not ADMIN})
    return out


CACHE["cleanup"] = Cached(cleanup_scan, 120)


def api_cleanup(q):
    rows, err = CACHE["cleanup"].get(q.get("force", ["0"])[0] == "1")
    return {"items": rows, "err": err}


def clean_dir(path, max_seconds=60):
    """1 günden eski dosyaları siler (kullanımda olanlar atlanır). (serbest kalan bayt, silinen dosya, atlanan) döner."""
    cutoff = time.time() - 86400
    deadline = time.time() + max_seconds
    freed = removed = skipped = 0
    dirs = []
    for root, ds, fs in os.walk(path, topdown=True, followlinks=False):
        if time.time() > deadline:
            break
        dirs.append(root)
        for f in fs:
            fp = os.path.join(root, f)
            try:
                if os.path.islink(fp):
                    continue
                st = os.stat(fp)
                if st.st_mtime >= cutoff:
                    continue
                os.remove(fp)
                freed += st.st_size
                removed += 1
            except OSError:
                skipped += 1
    for d in sorted(dirs, key=len, reverse=True):
        if d != path:
            try:
                os.rmdir(d)  # yalnızca boşsa silinir
            except OSError:
                pass
    return freed, removed, skipped


def post_cleanup(b):
    cid = str(b.get("id", ""))
    target = next(((n, p) for i, n, p in cleanup_targets() if i == cid), None)
    if not target:
        return {"ok": False, "error": "Bilinmeyen temizlik hedefi"}
    name, path = target
    freed, removed, skipped = clean_dir(path)
    CACHE["cleanup"].get(True)
    MON.add_event("action", "info", f"Temizlik: {name} — {fmt_bytes(freed)} boşaltıldı ({removed} dosya, {skipped} atlandı)")
    return {"ok": True, "freed": freed, "removed": removed, "skipped": skipped}


# ---- Yerel ağda yeni cihaz izleyici
def _lan_watch():
    t0 = time.time()
    known = None
    while True:
        try:
            nb, err = CACHE["neighbors"].get(True)
            cur = {}
            for n in nb or []:
                mac = (n.get("mac") or "").upper()
                ip = n.get("ip") or ""
                if not mac or ip.startswith(("224.", "239.")) or ip.endswith(".255"):
                    continue
                cur[mac] = ip
            if known is None:
                if nb or not err:
                    known = set(cur)
            elif time.time() - t0 < 180:
                known.update(cur)  # ARP önbelleği ısınana kadar sessiz referans
            else:
                for mac, ip in cur.items():
                    if mac not in known:
                        known.add(mac)
                        rnd = int(mac.replace("-", "")[:2], 16) & 2
                        MON.add_alert(("lan", mac), "warn",
                                      f"Yerel ağda yeni cihaz göründü: {ip} ({mac})" +
                                      (" - rastgele (özel) MAC adresi kullanıyor" if rnd else ""))
        except Exception:
            traceback.print_exc()
        time.sleep(30)


GET_ROUTES = {
    "/api/overview": api_overview, "/api/processes": api_processes, "/api/process": api_process,
    "/api/connections": api_connections, "/api/ports": api_ports, "/api/events": api_events,
    "/api/firewall": api_firewall, "/api/fwlog": api_fwlog, "/api/etw": api_etw, "/api/etwhist": api_etwhist, "/api/etwproc": api_etwproc, "/api/etwdns": api_etwdns, "/api/timeline": api_timeline, "/api/fwhealth": api_fwhealth, "/api/notify": api_notify, "/api/fwbackups": api_fwbackups,"/api/startup": api_startup,
    "/api/network": api_network, "/api/security": api_security, "/api/scan": api_scan_status,
    "/api/drives": api_drives, "/api/token": lambda q: {"token": TOKEN}, "/api/ping": lambda q: {"app": "gozcu"}, "/api/suppress": api_suppress, "/api/trustports": api_trustports, "/api/alerts": api_alerts, "/api/alerthistory": api_alerthistory, "/api/autostart": api_autostart, "/api/baseline": api_baseline,
    "/api/cleanup": api_cleanup,
}
POST_ROUTES = {
    "/api/kill": post_kill, "/api/block": post_block, "/api/fw/remove": post_fw_remove, "/api/netcut": post_netcut, "/api/unblock": post_unblock_program, "/api/blockcountry": post_blockcountry, "/api/fwbackup": post_fwbackup, "/api/fwrestore": post_fwrestore, "/api/fwbackup/delete": post_fwbackup_delete, "/api/notify/save": post_notify_save, "/api/service/action": post_service_action, "/api/service/startup": post_service_startup, "/api/autostart": post_autostart, "/api/suppress/add": post_suppress_add, "/api/trustports/add": post_trustport_add, "/api/trustports/remove": post_trustport_remove, "/api/alerts/dismiss": post_alert_dismiss, "/api/suppress/remove": post_suppress_remove, "/api/quit": post_quit, "/api/notify/test": post_notify_test, "/api/fwrule/toggle": post_fwrule_toggle, "/api/fwrule/scope": post_fwrule_scope, "/api/unblockcountry": post_unblockcountry,
    "/api/fw/logging": post_fw_logging, "/api/startup/toggle": post_startup_toggle, "/api/reveal": post_reveal, "/api/scan": post_scan,
    "/api/scan/cancel": post_scan_cancel, "/api/elevate": post_elevate, "/api/alerts/clear": post_clear_alerts,
    "/api/suspend": post_suspend, "/api/priority": post_priority, "/api/baseline/save": post_baseline_save,
    "/api/cleanup": post_cleanup,
}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def host_ok(self):
        return self.headers.get("Host", "") in (f"127.0.0.1:{PORT}", f"localhost:{PORT}")

    def send(self, code, body, ctype="application/json; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, obj, code=200):
        self.send(code, json.dumps(obj, default=str, ensure_ascii=False).encode("utf-8"))

    def do_GET(self):
        if not self.host_ok():
            return self.send(403, b"forbidden", "text/plain")
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            with open(os.path.join(RES_DIR, "index.html"), "rb") as f:
                html = f.read().replace(b"__SYSDASH_TOKEN__", TOKEN.encode())
            return self.send(200, html, "text/html; charset=utf-8")
        if u.path == "/favicon.ico":
            try:
                with open(os.path.join(RES_DIR, "gozcu.ico"), "rb") as f:
                    return self.send(200, f.read(), "image/x-icon")
            except OSError:
                return self.send(404, b"not found", "text/plain")
        fn = GET_ROUTES.get(u.path)
        if not fn:
            return self.send(404, b"not found", "text/plain")
        try:
            self.send_json(fn(parse_qs(u.query)))
        except Exception as e:
            traceback.print_exc()
            self.send_json({"error": str(e)}, 500)

    def do_POST(self):
        # govdeyi her durumda oku; okunmazsa keep-alive baglantidaki sonraki istek bozulur
        n = min(int(self.headers.get("Content-Length", 0) or 0), 1024 * 1024)
        raw = self.rfile.read(n) if n else b""
        if not self.host_ok() or self.headers.get("X-Token") != TOKEN:
            return self.send(403, b"forbidden", "text/plain")
        u = urlparse(self.path)
        fn = POST_ROUTES.get(u.path)
        if not fn:
            return self.send(404, b"not found", "text/plain")
        try:
            body = json.loads(raw or b"{}")
            self.send_json(fn(body))
        except PermissionError as e:
            self.send_json({"ok": False, "error": str(e)})
        except Exception as e:
            traceback.print_exc()
            self.send_json({"ok": False, "error": str(e)}, 500)


class Server(ThreadingHTTPServer):
    allow_reuse_address = False
    daemon_threads = True

    def handle_error(self, request, client_address):
        if isinstance(sys.exc_info()[1], (ConnectionAbortedError, ConnectionResetError, BrokenPipeError)):
            return  # tarayici sekmesi kapandi / yenilendi
        super().handle_error(request, client_address)

    def server_bind(self):
        # Windows: baska bir programin ayni portu paylasmasini engelle
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def port_free(port):
    """0.0.0.0 veya 127.0.0.1 uzerinde baska bir dinleyici var mi?"""
    for c in psutil.net_connections("tcp"):
        if c.status == psutil.CONN_LISTEN and c.laddr and c.laddr.port == port:
            return False
    return True


def main():
    global PORT
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    no_browser = "--no-browser" in sys.argv
    wait = "--wait-port" in sys.argv
    if not wait and "--port" not in sys.argv:
        other = find_running()
        if other:
            url = f"http://127.0.0.1:{other}"
            print(f"Gözcü zaten çalışıyor: {url}")
            if not no_browser:
                webbrowser.open(url)
            return
    if "--port" in sys.argv:
        PORT = int(sys.argv[sys.argv.index("--port") + 1])
        candidates = [PORT]
    else:
        candidates = list(range(PORT, PORT + 20))
    srv = None
    deadline = time.time() + (20 if wait else 0)
    while srv is None:
        for p in candidates:
            if not wait and not port_free(p):
                continue
            try:
                srv = Server(("127.0.0.1", p), Handler)
                PORT = p
                break
            except OSError:
                continue
        if srv is None:
            if time.time() > deadline:
                print(f"Boş port bulunamadı ({candidates[0]}-{candidates[-1]}).")
                return
            time.sleep(0.5)
    for _ in range(6):
        threading.Thread(target=_rdns_worker, daemon=True).start()
    threading.Thread(target=_sig_worker, daemon=True).start()
    threading.Thread(target=_netcut_loop, daemon=True).start()
    if GEO is not None:
        GEO.start()
    _sup_load()
    _svc_log_load()
    _fwchg_load()
    _tp_load()
    _timed_load()
    trim_alert_log()
    threading.Thread(target=timed_loop, daemon=True).start()
    threading.Thread(target=fw_watch_loop, daemon=True).start()
    if NOTIFY is not None and not os.environ.get("GOZCU_NO_NOTIFY"):   # test kopyaları gerçek bota yazmasın
        NOTIFY.start()
    if ADMIN and not (os.path.isdir(BACKUP_DIR) and any(_BK_RE.match(f) for f in os.listdir(BACKUP_DIR))):
        threading.Thread(target=lambda: fw_backup("ilk"), daemon=True).start()
    threading.Thread(target=_lan_watch, daemon=True).start()
    MON.start()
    if NETTRACE is not None:
        try:
            NETTRACE.start()
            if NETTRACE.status == "ok":
                from etwnet import NetWatch
                global NETWATCH
                NETWATCH = NetWatch(NETTRACE, os.path.join(APP_DIR, "nettraffic.json"),
                                    lambda pid: (MON.snapshot.get("procs", {}).get(pid) or {}).get("name", ""),
                                    MON.add_alert, MON.add_alert_cool)
                NETWATCH.exe_of = lambda pid: (MON.snapshot.get("procs", {}).get(pid) or {}).get("exe", "")
                NETWATCH.sig_of = lambda exe: sig_of(exe)
                NETWATCH.geo_cc = lambda ip: ((GEO.lookup(ip) or {}).get("cc", "") if GEO else "")
                NETWATCH.start()
        except Exception:
            traceback.print_exc()
            NETTRACE.status = "başlatılamadı"
    # yavas verileri arka planda isit
    threading.Thread(target=lambda: [CACHE[k].get() for k in ("fw_profiles", "services", "fw_rules")], daemon=True).start()
    url = f"http://127.0.0.1:{PORT}"
    print("=" * 60)
    print(f"  Gözcü çalışıyor: {url}")
    print(f"  Yetki: {'YÖNETİCİ' if ADMIN else 'standart kullanıcı'}")
    print("  Kapatmak için bu pencerede Ctrl+C")
    print("=" * 60)
    if not no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
