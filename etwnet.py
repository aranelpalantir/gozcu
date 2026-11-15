"""
SysDash - ETW tabanli ag izleyici (surucu gerektirmez, yonetici yetkisi ister).

Microsoft-Windows-Kernel-Network saglayicisini dinler: her TCP/UDP veri gonderme/alma
olayi icin islem (PID), yon, uzak/yerel adres:port ve bayt sayisi gelir.
Icerik (payload) okunmaz, sadece meta veri.
"""
import atexit
import math
import ctypes
import ipaddress
import json
import os
import socket
import traceback
import struct
import threading
import time
import uuid
from collections import deque
from ctypes import (POINTER, Structure, byref, c_byte, c_int64, c_long, c_uint64, c_ubyte, c_ulong,
                    c_ushort, c_void_p, c_wchar, c_wchar_p, sizeof)

import psutil
import re
import subprocess

SESSION_PREFIX = "GozcuNet-"      # her Gozcu ornegi kendi oturumunu kullanir (birbirini kapatmasin)
LEGACY_SESSION = "SysDashNet"     # eski surumun ortak oturum adi
PROVIDER = uuid.UUID("7DD42A49-5329-4832-8DFD-43D979153A88")  # Microsoft-Windows-Kernel-Network

# olay kimlikleri: id -> (protokol, yon, ipv6)
EVENTS = {
    10: ("TCP", "out", False), 11: ("TCP", "in", False),
    26: ("TCP", "out", True), 27: ("TCP", "in", True),
    42: ("UDP", "out", False), 43: ("UDP", "in", False),
    58: ("UDP", "out", True), 59: ("UDP", "in", True),
}

REAL_TIME = 0x100
PROCESS_TRACE_MODE_REAL_TIME = 0x100
PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000
INVALID_HANDLE = 0xFFFFFFFFFFFFFFFF


class GUID(Structure):
    _fields_ = [("Data1", c_ulong), ("Data2", c_ushort), ("Data3", c_ushort), ("Data4", c_ubyte * 8)]


class WNODE_HEADER(Structure):
    _fields_ = [("BufferSize", c_ulong), ("ProviderId", c_ulong), ("HistoricalContext", c_uint64),
                ("TimeStamp", c_int64), ("Guid", GUID), ("ClientContext", c_ulong), ("Flags", c_ulong)]


class TRACE_PROPS(Structure):
    _fields_ = [("Wnode", WNODE_HEADER), ("BufferSize", c_ulong), ("MinimumBuffers", c_ulong),
                ("MaximumBuffers", c_ulong), ("MaximumFileSize", c_ulong), ("LogFileMode", c_ulong),
                ("FlushTimer", c_ulong), ("EnableFlags", c_ulong), ("AgeLimit", c_long),
                ("NumberOfBuffers", c_ulong), ("FreeBuffers", c_ulong), ("EventsLost", c_ulong),
                ("BuffersWritten", c_ulong), ("LogBuffersLost", c_ulong), ("RealTimeBuffersLost", c_ulong),
                ("LoggerThreadId", c_void_p), ("LogFileNameOffset", c_ulong), ("LoggerNameOffset", c_ulong)]


class PROPS_BUF(Structure):
    _fields_ = [("p", TRACE_PROPS), ("name", c_wchar * 64), ("file", c_wchar * 8)]


class EVENT_RECORD(Structure):
    _fields_ = [("Size", c_ushort), ("HeaderType", c_ushort), ("Flags", c_ushort), ("EventProperty", c_ushort),
                ("ThreadId", c_ulong), ("ProcessId", c_ulong), ("TimeStamp", c_int64), ("ProviderId", GUID),
                ("Id", c_ushort), ("Version", c_ubyte), ("Channel", c_ubyte), ("Level", c_ubyte),
                ("Opcode", c_ubyte), ("Task", c_ushort), ("Keyword", c_uint64),
                ("KernelTime", c_ulong), ("UserTime", c_ulong), ("ActivityId", GUID),
                ("ProcessorNumber", c_ubyte), ("Alignment", c_ubyte), ("LoggerId", c_ushort),
                ("ExtendedDataCount", c_ushort), ("UserDataLength", c_ushort),
                ("ExtendedData", c_void_p), ("UserData", c_void_p), ("UserContext", c_void_p)]


CALLBACK = ctypes.WINFUNCTYPE(None, POINTER(EVENT_RECORD))


class LOGFILE(Structure):
    _fields_ = [("LogFileName", c_wchar_p), ("LoggerName", c_wchar_p), ("CurrentTime", c_int64),
                ("BuffersRead", c_ulong), ("ProcessTraceMode", c_ulong),
                ("CurrentEvent", c_byte * 88), ("LogfileHeader", c_byte * 280),
                ("BufferCallback", c_void_p), ("BufferSize", c_ulong), ("Filled", c_ulong),
                ("EventsLost", c_ulong), ("EventRecordCallback", CALLBACK),
                ("IsKernelTrace", c_ulong), ("Context", c_void_p)]


_adv = ctypes.WinDLL("advapi32", use_last_error=True)
_adv.StartTraceW.argtypes = [POINTER(c_uint64), c_wchar_p, c_void_p]
_adv.StartTraceW.restype = c_ulong
_adv.ControlTraceW.argtypes = [c_uint64, c_wchar_p, c_void_p, c_ulong]
_adv.ControlTraceW.restype = c_ulong
_adv.EnableTraceEx2.argtypes = [c_uint64, POINTER(GUID), c_ulong, c_ubyte, c_uint64, c_uint64, c_ulong, c_void_p]
_adv.EnableTraceEx2.restype = c_ulong
_adv.OpenTraceW.argtypes = [POINTER(LOGFILE)]
_adv.OpenTraceW.restype = c_uint64
_adv.ProcessTrace.argtypes = [POINTER(c_uint64), c_ulong, c_void_p, c_void_p]
_adv.ProcessTrace.restype = c_ulong
_adv.CloseTrace.argtypes = [c_uint64]
_adv.CloseTrace.restype = c_ulong


DNS_PROVIDER = uuid.UUID("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D")  # Microsoft-Windows-DNS-Client
DNS_EVENTS = {3006, 3008}  # sorgu basladi / sorgu tamamlandi
QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS"}


def _ustr(d, off):
    """off konumundan itibaren sifirla biten UTF-16LE dizgi: (metin, sonraki konum)."""
    end = off
    n = len(d)
    while end + 1 < n and not (d[end] == 0 and d[end + 1] == 0):
        end += 2
    return d[off:end].decode("utf-16-le", "replace"), end + 2


_PUB = {}


def is_public(ip):
    v = _PUB.get(ip)
    if v is None:
        try:
            a = ipaddress.ip_address(ip.split("%")[0])
            if getattr(a, "ipv4_mapped", None):
                a = a.ipv4_mapped
            v = not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast
                     or a.is_unspecified or a.is_reserved)
        except ValueError:
            v = False
        if len(_PUB) > 20000:
            _PUB.clear()
        _PUB[ip] = v
    return v


def _new_props():
    b = PROPS_BUF()
    b.p.Wnode.BufferSize = sizeof(PROPS_BUF)
    b.p.Wnode.Flags = 0x20000  # WNODE_FLAG_TRACED_GUID
    b.p.Wnode.ClientContext = 1  # QPC
    b.p.LogFileMode = REAL_TIME
    b.p.LoggerNameOffset = sizeof(TRACE_PROPS)
    return b


def _stop_session(name):
    b = _new_props()
    return _adv.ControlTraceW(0, name, byref(b), 1)  # EVENT_TRACE_CONTROL_STOP


def cleanup_stale():
    """Cokmus/kapanmis Gozcu orneklerinden kalan ETW oturumlarini kapatir (oturum sayisi sinirli: 64)."""
    try:
        out = subprocess.run(["logman", "query", "-ets"], capture_output=True, timeout=20,
                             creationflags=0x08000000).stdout.decode("oem", "replace")
    except Exception:
        return
    me = os.getpid()
    for line in out.splitlines():
        parts = line.split()
        name = parts[0] if parts else ""
        m = re.fullmatch(re.escape(SESSION_PREFIX) + r"(\d+)", name)
        if m and int(m.group(1)) != me and not psutil.pid_exists(int(m.group(1))):
            _stop_session(name)
        elif name == LEGACY_SESSION:     # eski surumun ortak oturumu: sahipsiz kalir, yeni surumde kullanilmaz
            _stop_session(name)


class NetTrace:
    MAX_ROWS = 20000

    def __init__(self):
        self.status = "başlatılmadı"
        self.lock = threading.Lock()
        self.rows = deque(maxlen=self.MAX_ROWS)
        self.row_id = 0
        self.procs = {}   # pid -> [tx, rx, txrate, rxrate, ptx, prx, last_t]
        self.flows = {}   # (pid, proto, rip, rport, lport) -> [tx, rx, txn, rxn, first, last]
        self.locals = set()
        self.locals_t = 0
        self.total = [0, 0]
        self.rhist = {}   # pid -> deque[(giden/sn, gelen/sn)], 2 sn aralikli
        self.dns = deque(maxlen=5000)
        self.dns_id = 0
        self.dns_status = "başlatılmadı"
        self.ipname = {}  # IP -> son DNS yanitindaki alan adi
        self.t_start = time.time()
        self._cb = CALLBACK(self._on_event)
        self._handle = None
        self._trace = None
        self.session = f"{SESSION_PREFIX}{os.getpid()}"
        self._stopping = False
        self.restarts = 0

    # ------------------------------------------------------------------ baslat
    def start(self):
        if self._trace is not None:
            return
        self._refresh_locals()
        cleanup_stale()
        if not self._open():
            return
        atexit.register(self.stop)
        threading.Thread(target=self._consume, daemon=True).start()
        threading.Thread(target=self._rates, daemon=True).start()

    def _open(self):
        """ETW oturumunu acar, saglayicilari etkinlestirir, izi acar. -> basari"""
        _stop_session(self.session)   # ayni ornege ait artik oturum varsa kapat (baska orneklere dokunma)
        b = _new_props()
        h = c_uint64(0)
        err = _adv.StartTraceW(byref(h), self.session, byref(b))
        if err == 5:
            self.status = "erişim reddedildi (yönetici olarak çalıştırın)"
            return False
        if err != 0:
            self.status = f"oturum başlatılamadı (hata {err})"
            return False
        self._handle = h
        g = GUID.from_buffer_copy(PROVIDER.bytes_le)
        err = _adv.EnableTraceEx2(h.value, byref(g), 1, 5, 0xFFFFFFFFFFFFFFFF, 0, 0, None)
        if err != 0:
            self.status = ("erişim reddedildi (yönetici olarak çalıştırın)" if err == 5
                           else f"sağlayıcı açılamadı (hata {err})")
            _stop_session(self.session)
            return False
        # DNS sorgulari (basarisiz olursa sadece DNS sekmesi bos kalir)
        g2 = GUID.from_buffer_copy(DNS_PROVIDER.bytes_le)
        self.dns_status = "ok" if _adv.EnableTraceEx2(h.value, byref(g2), 1, 5, 0xFFFFFFFFFFFFFFFF, 0, 0, None) == 0 \
            else "DNS sağlayıcısı açılamadı"
        lf = LOGFILE()
        lf.LoggerName = self.session
        lf.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD
        lf.EventRecordCallback = self._cb
        self._lf = lf
        th = _adv.OpenTraceW(byref(lf))
        if th == INVALID_HANDLE:
            self.status = f"iz açılamadı (hata {ctypes.get_last_error()})"
            _stop_session(self.session)
            return False
        self._trace = c_uint64(th)
        self.status = "ok"
        return True

    def stop(self):
        self._stopping = True
        try:
            _stop_session(self.session)
        except Exception:
            pass

    def _consume(self):
        """Olaylari isler. Oturum disaridan kapatilirsa (ornegin baska bir program) kendiliginden yeniden kurar."""
        fails = 0
        while not self._stopping:
            if self._trace is None:
                time.sleep(min(2 * (fails + 1), 20))
                if self._stopping:
                    break
                if self._open():
                    fails = 0
                    self.restarts += 1
                else:
                    fails += 1
                continue
            err = _adv.ProcessTrace(byref(self._trace), 1, None, None)
            if self._stopping:
                break
            try:
                _adv.CloseTrace(self._trace.value)
            except Exception:
                pass
            self._trace = None
            _stop_session(self.session)
            self.status = f"izleme durdu (kod {err}); yeniden başlatılıyor"

    # ------------------------------------------------------------------ olaylar
    def _refresh_locals(self):
        s = set()
        try:
            for addrs in psutil.net_if_addrs().values():
                for a in addrs:
                    if a.family in (socket.AF_INET, socket.AF_INET6):
                        s.add(a.address.split("%")[0].lower())
        except Exception:
            pass
        s.update({"127.0.0.1", "::1"})
        self.locals = s
        self.locals_t = time.time()

    def _on_dns(self, rec):
        d = ctypes.string_at(rec.UserData, rec.UserDataLength)
        name, off = _ustr(d, 0)
        if not name:
            return
        qtype = struct.unpack_from("<I", d, off)[0] if off + 4 <= len(d) else 0
        status, results = None, ""
        if rec.Id == 3008:
            if off + 16 <= len(d):
                status = struct.unpack_from("<I", d, off + 12)[0]
                results, _ = _ustr(d, off + 16)
        row = {"t": time.time(), "pid": rec.ProcessId, "name": name.rstrip("."), "qtype": QTYPES.get(qtype, str(qtype)),
               "kind": "yanıt" if rec.Id == 3008 else "sorgu", "status": status, "results": results}
        ips = []
        for tok in results.replace(" ", "").split(";"):
            tok = tok.replace("::ffff:", "")
            if tok and (tok[0].isdigit() or ":" in tok):
                try:
                    ipaddress.ip_address(tok)
                    ips.append(tok)
                except ValueError:
                    pass
        with self.lock:
            self.dns_id += 1
            row["id"] = self.dns_id
            self.dns.append(row)
            if ips and len(self.ipname) < 50000:
                for ip in ips:
                    self.ipname[ip] = row["name"]

    def _on_event(self, rec_p):
        try:
            rec = rec_p.contents
            if rec.Id in DNS_EVENTS and rec.ProviderId.Data1 == 0x1C95126E:
                self._on_dns(rec)
                return
            info = EVENTS.get(rec.Id)
            if not info or rec.UserDataLength < 20:
                return
            proto, direction, v6 = info
            d = ctypes.string_at(rec.UserData, rec.UserDataLength)
            if v6:
                pid, size, da, sa, dp, sp = struct.unpack_from("<II16s16sHH", d)
                dip = socket.inet_ntop(socket.AF_INET6, da)
                sip = socket.inet_ntop(socket.AF_INET6, sa)
            else:
                pid, size, da, sa, dp, sp = struct.unpack_from("<II4s4sHH", d)
                dip = socket.inet_ntoa(da)
                sip = socket.inet_ntoa(sa)
            if not size:
                return
            dp = socket.ntohs(dp)
            sp = socket.ntohs(sp)
            now = time.time()
            if now - self.locals_t > 30:
                self._refresh_locals()
            loc = self.locals
            s_local, d_local = sip.lower() in loc, dip.lower() in loc
            if d_local and not s_local:
                lip, lport, rip, rport = dip, dp, sip, sp
            else:
                lip, lport, rip, rport = sip, sp, dip, dp
            with self.lock:
                self.row_id += 1
                self.rows.append({"id": self.row_id, "t": now, "pid": pid, "proto": proto, "dir": direction,
                                  "lip": lip, "lport": lport, "rip": rip, "rport": rport, "size": size})
                p = self.procs.get(pid)
                if p is None:
                    # [tx, rx, txrate, rxrate, ptx, prx, t, pubtx, pubtx_prev, pubtxrate, nl_tx, nl_rx]
                    p = self.procs[pid] = [0, 0, 0.0, 0.0, 0, 0, now, 0, 0, 0.0, 0, 0]
                nl = not (rip.startswith("127.") or rip == "::1")
                if nl:
                    p[10 if direction == "out" else 11] += size
                if direction == "out" and is_public(rip):
                    p[7] += size
                k = (pid, proto, rip, rport, lport if proto == "TCP" else 0)
                f = self.flows.get(k)
                if f is None:
                    if len(self.flows) > 6000:
                        old = sorted(self.flows.items(), key=lambda kv: kv[1][5])[:1500]
                        for ok, _ in old:
                            del self.flows[ok]
                    f = self.flows[k] = [0, 0, 0, 0, now, now]
                f[5] = now
                if direction == "out":
                    p[0] += size
                    f[0] += size
                    f[2] += 1
                    self.total[0] += size
                else:
                    p[1] += size
                    f[1] += size
                    f[3] += 1
                    self.total[1] += size
        except Exception:
            pass

    def _rates(self):
        prev = time.time()
        while True:
            time.sleep(2.0)
            now = time.time()
            dt = max(0.1, now - prev)
            prev = now
            with self.lock:
                for p in self.procs.values():
                    p[2] = (p[0] - p[4]) / dt
                    p[3] = (p[1] - p[5]) / dt
                    p[4], p[5] = p[0], p[1]
                    p[9] = (p[7] - p[8]) / dt
                    p[8] = p[7]
                for pid, p in self.procs.items():
                    h = self.rhist.get(pid)
                    if h is None:
                        if not (p[2] or p[3]):
                            continue
                        h = self.rhist[pid] = deque(maxlen=150)
                    h.append((round(p[2]), round(p[3])))

    # ------------------------------------------------------------------ okuma
    def dns_since(self, since):
        with self.lock:
            return [dict(r) for r in self.dns if r["id"] > since][-1500:], self.dns_id

    def rows_for(self, pid, lo, hi):
        with self.lock:
            return [dict(r) for r in self.rows if r["pid"] == pid and lo <= r["t"] <= hi]

    def dns_for(self, pid, lo, hi):
        with self.lock:
            return [dict(r) for r in self.dns if r["pid"] == pid and lo <= r["t"] <= hi]

    def host_of(self, ip):
        return self.ipname.get(ip)

    def rate_hist(self, pid):
        with self.lock:
            h = list(self.rhist.get(pid, ()))
        return {"tx": [a for a, _ in h], "rx": [b for _, b in h]}

    def stats(self):
        with self.lock:
            return ({pid: list(v) for pid, v in self.procs.items()},
                    [(k, list(v)) for k, v in self.flows.items()])

    def snapshot(self, since):
        with self.lock:
            rows = [r for r in self.rows if r["id"] > since][-1500:]
            procs = {pid: list(v) for pid, v in self.procs.items()}
            flows = [(k, list(v)) for k, v in self.flows.items()]
            last = self.row_id
            total = list(self.total)
        return rows, procs, flows, last, total


# ----------------------------------------------------------------------------
# Esik uyarilari, yeni hedef tespiti ve trafik gecmisi
# ----------------------------------------------------------------------------
RATE_THR = 2 * 1024 * 1024        # internete surekli yukleme hizi (bayt/sn)
RATE_SECS = 10                    # ... en az bu kadar sure surerse uyar
TOTAL_THR = 500 * 1024 * 1024     # bir islemin internete toplam yuklemesi
NEW_DEST_MIN = 5 * 1024 * 1024    # yeni hedefe bu kadar yukleme olursa uyar
MIN_KNOWN_DESTS = 10              # islemin gecmisi bu kadar hedef icermiyorsa "ogrenme" sayilir
NEW_PROG_LEARN = 600              # ilk calistirmadan sonra bu kadar sn "ogrenme" (yeni program uyarisi yok)
NEW_CC_MIN = 50 * 1024            # yeni ulkeye bu kadar veri aktarilirsa uyar
MIN_KNOWN_CC = 3                  # islemin gecmisi bu kadar ulke icermiyorsa "ogrenme" sayilir
BROWSERS = {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe"}
KEEP_DAYS = 60
MAX_DESTS = 400


def _entropy(s):
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in (s.count(ch) for ch in set(s)))


DNS_NX_THR = 25        # 60 sn icinde bir islemin basarisiz (NXDOMAIN) sorgu sayisi
DNS_DGA_THR = 5        # ... bunlardan rastgele gorunenlerin sayisi
DNS_TXT_THR = 20       # 60 sn icinde TXT sorgusu sayisi (DNS tunelleme belirtisi)
DNS_LONG_LABEL = 40    # bu uzunlukta bir etiket (alan adi parcasi) tunelleme belirtisi


def _fmt(n):
    n = float(n)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024


class NetWatch(threading.Thread):
    def __init__(self, trace, path, name_of, alert, alert_cool):
        super().__init__(daemon=True)
        self.trace, self.path = trace, path
        self.name_of, self.alert, self.alert_cool = name_of, alert, alert_cool
        self.hist = {}            # tarih -> {islem adi: [giden, gelen]}
        self.dests = {}           # islem adi (lower) -> diskteki bilinen genel IP'ler
        self.session_dests = {}   # bu oturumda gorulenler (kayit sirasinda eklenir)
        self.flushed = {}         # pid -> (tx, rx) gecmise islenen
        self.names = {}           # pid -> son bilinen ad
        self.hi = {}              # pid -> ardisik yuksek hiz sayisi
        self.lock = threading.Lock()
        self.t0 = time.time()
        self.dns_last = 0
        self.dns_nx, self.dns_dga, self.dns_txt = {}, {}, {}
        self.ccs = {}             # islem adi (lower) -> diskteki bilinen ulkeler
        self.session_ccs = {}
        self.exes = set()         # bilinen program anahtarlari (ad|imzalayan veya yol)
        self.first_run = None
        self.exe_of = lambda pid: ""
        self.sig_of = lambda exe: None
        self.geo_cc = lambda ip: ""

    # -- disk
    def load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                d = json.load(f)
            self.hist = d.get("hist", {})
            self.dests = {k: set(v) for k, v in d.get("dests", {}).items()}
            self.ccs = {k: set(v) for k, v in d.get("ccs", {}).items()}
            self.exes = set(d.get("exes", []))
            self.first_run = d.get("first_run")
        except (OSError, ValueError):
            pass
        if not self.first_run:
            self.first_run = time.time()

    def save(self):
        with self.lock:
            self.flush()
            for name, ips in self.session_dests.items():
                cur = self.dests.setdefault(name, set())
                for ip in ips:
                    if len(cur) < MAX_DESTS:
                        cur.add(ip)
            for name, ccs in self.session_ccs.items():
                self.ccs.setdefault(name, set()).update(ccs)
            cutoff = time.strftime("%Y-%m-%d", time.localtime(time.time() - KEEP_DAYS * 86400))
            for day in [d for d in self.hist if d < cutoff]:
                del self.hist[day]
            data = {"hist": self.hist, "dests": {k: sorted(v) for k, v in self.dests.items()},
                    "ccs": {k: sorted(v) for k, v in self.ccs.items()}, "exes": sorted(self.exes),
                    "first_run": self.first_run}
        tmp = self.path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f)
            os.replace(tmp, self.path)
        except OSError:
            pass

    # -- gecmis
    def flush(self):
        """Son kayittan beri olan trafigi bugunun toplamina ekler (kilit disarida tutulmali)."""
        procs, _ = self.trace.stats()
        day = self.hist.setdefault(time.strftime("%Y-%m-%d"), {})
        for pid, v in procs.items():
            name = self.names.get(pid) or self.name_of(pid) or "?"
            ftx, frx = self.flushed.get(pid, (0, 0))
            dtx = v[10] - ftx if v[10] >= ftx else v[10]
            drx = v[11] - frx if v[11] >= frx else v[11]
            self.flushed[pid] = (v[10], v[11])
            if dtx or drx:
                e = day.setdefault(name, [0, 0])
                e[0] += dtx
                e[1] += drx

    def history(self, days):
        with self.lock:
            self.flush()
            today = time.time()
            keys = [time.strftime("%Y-%m-%d", time.localtime(today - i * 86400)) for i in range(days)]
            per_day, per_proc = [], {}
            for k in keys:
                day = self.hist.get(k, {})
                tx = sum(v[0] for v in day.values())
                rx = sum(v[1] for v in day.values())
                per_day.append({"date": k, "tx": tx, "rx": rx})
                for name, v in day.items():
                    e = per_proc.setdefault(name, [0, 0])
                    e[0] += v[0]
                    e[1] += v[1]
        procs = [{"name": n, "tx": v[0], "rx": v[1]} for n, v in per_proc.items()]
        return {"days": per_day, "procs": procs}

    # -- calisma
    def run(self):
        self.load()
        atexit.register(self.save)
        last_save = time.time()
        while True:
            time.sleep(2.0)
            try:
                self.tick()
            except Exception:
                traceback.print_exc()
            if time.time() - last_save >= 60:
                self.save()
                last_save = time.time()

    @staticmethod
    def _push(store, key, now, window=60):
        dq = store.setdefault(key, deque())
        dq.append(now)
        while dq and now - dq[0] > window:
            dq.popleft()
        return len(dq)

    def _dns_scan(self):
        rows, last = self.trace.dns_since(self.dns_last)
        self.dns_last = last
        now = time.time()
        me = os.getpid()
        for r in rows:
            if r["pid"] == me or r["kind"] != "yanıt":
                continue
            pid = r["pid"]
            pname = self.names.get(pid) or self.name_of(pid) or "?"
            low = pname.lower()
            name = r["name"].lower()
            labels = name.split(".")
            if len(labels) >= 2 and max(len(x) for x in labels) >= DNS_LONG_LABEL and low not in BROWSERS:
                self.alert_cool(("dnslong", low), 1800, "warn",
                                f"{pname} (PID {pid}) çok uzun bir alan adı sorguladı: {name[:80]}… "
                                f"DNS tünelleme (veri sızdırma) belirtisi olabilir", pid=pid, name=pname)
            if r["qtype"] == "TXT" and low not in BROWSERS:
                if self._push(self.dns_txt, low, now) >= DNS_TXT_THR:
                    self.alert_cool(("dnstxt", low), 1800, "warn",
                                    f"{pname} (PID {pid}) bir dakikada {DNS_TXT_THR}+ TXT sorgusu yaptı. "
                                    f"Bu yoğunluk DNS tünelleme/komuta-kontrol davranışına benzer", pid=pid, name=pname)
            if (r["status"] == 9003 and r["qtype"] != "PTR" and len(labels) >= 2
                    and not name.endswith((".local", ".arpa", ".internal"))):
                n = self._push(self.dns_nx, low, now)
                if n >= DNS_NX_THR:
                    self.alert_cool(("dnsnx", low), 1800, "warn",
                                    f"{pname} (PID {pid}) bir dakikada {n} olmayan alan adını sorguladı (NXDOMAIN)",
                                    pid=pid, name=pname)
                sld = labels[-2]
                if len(sld) >= 10 and _entropy(sld) >= 3.2:
                    if self._push(self.dns_dga, low, now) >= DNS_DGA_THR:
                        self.alert_cool(("dnsdga", low), 1800, "high",
                                        f"{pname} (PID {pid}) rastgele görünen birçok alan adını çözmeye çalışıyor "
                                        f"(örn. {name[:60]}). Bu, zararlı yazılımların alan adı üretme (DGA) davranışına benzer",
                                        pid=pid, name=pname)

    def _novelty(self, flows):
        learning = time.time() - self.first_run < NEW_PROG_LEARN
        for (pid, proto, rip, rport, lport), f in flows:
            if f[0] + f[1] <= 0 or not is_public(rip):
                continue
            name = self.names.get(pid) or "?"
            low = name.lower()
            if low == "?":
                continue
            exe = self.exe_of(pid)
            if exe:
                sg = self.sig_of(exe)
                if sg is not None:
                    signed = sg.get("s") == "Valid" and sg.get("n")
                    key = low + "|" + (sg["n"].lower() if signed else exe.lower())
                    if key not in self.exes:
                        self.exes.add(key)
                        if not learning:
                            bad = sg.get("s") in ("NotSigned", "HashMismatch", "NotTrusted")
                            self.alert(("newprog", key), "high" if bad else "warn",
                                       f"İlk kez internete çıkan program: {name} (PID {pid}) → {rip}:{rport}. "
                                       f"Yol: {exe}. İmza: {sg.get('s')}" + (f" ({sg['n']})" if sg.get("n") else ""),
                                       pid=pid, name=name, rip=rip)
            if f[0] + f[1] >= NEW_CC_MIN and low not in BROWSERS:
                cc = self.geo_cc(rip)
                if cc:
                    self.session_ccs.setdefault(low, set()).add(cc)
                    known = self.ccs.get(low)
                    if known is not None and len(known) >= MIN_KNOWN_CC and cc not in known:
                        self.alert(("newcc", low, cc), "warn",
                                   f"{name} (PID {pid}) daha önce hiç bağlanmadığı bir ülkeye bağlandı: {cc} ({rip}:{rport})",
                                   pid=pid, name=name, rip=rip)

    def tick(self):
        if self.trace.status != "ok":
            return
        try:
            self._dns_scan()
        except Exception:
            traceback.print_exc()
        procs, flows = self.trace.stats()
        for pid in procs:
            n = self.name_of(pid)
            if n:
                self.names[pid] = n
        for pid, v in procs.items():
            name = self.names.get(pid) or "?"
            low = name.lower()
            if v[9] >= RATE_THR:
                self.hi[pid] = self.hi.get(pid, 0) + 1
                if self.hi[pid] * 2 >= RATE_SECS:
                    self.alert_cool(("netrate", low), 900, "warn",
                                    f"{name} (PID {pid}) internete {_fmt(v[9])}/sn hızla yükleme yapıyor "
                                    f"(≥{RATE_SECS} sn). Bulut eşitleme/yedekleme olabilir; değilse veri sızıntısı belirtisi",
                                    pid=pid, name=name)
            else:
                self.hi.pop(pid, None)
            if v[7] >= TOTAL_THR:
                self.alert_cool(("nettotal", low), 6 * 3600, "warn",
                                f"{name} (PID {pid}) panel açıldığından beri internete toplam {_fmt(v[7])} yükledi",
                                pid=pid, name=name)
        try:
            self._novelty(flows)
        except Exception:
            traceback.print_exc()
        # yeni (daha once gorulmemis) genel hedefe buyuk yukleme
        agg = {}
        for (pid, proto, rip, rport, lport), f in flows:
            if f[0] <= 0 or not is_public(rip):
                continue
            name = self.names.get(pid) or "?"
            k = (name.lower(), rip)
            e = agg.setdefault(k, [0, name, pid, rport])
            e[0] += f[0]
        for (low, rip), (tx, name, pid, rport) in agg.items():
            self.session_dests.setdefault(low, set()).add(rip)
            known = self.dests.get(low)
            if (known is not None and len(known) >= MIN_KNOWN_DESTS and rip not in known
                    and tx >= NEW_DEST_MIN and low not in BROWSERS and low != "?"):
                self.alert(("newdest", low, rip), "warn",
                           f"{name} (PID {pid}) daha önce bağlanmadığı {rip}:{rport} adresine {_fmt(tx)} veri yükledi",
                           pid=pid, name=name, rip=rip)
