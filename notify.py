"""
Gözcü - Telegram bildirimleri (istege bagli).

Bot belirteci (token) Windows DPAPI ile sifrelenip telegram.json'a yazilir: yalnizca bu Windows
kullanici hesabi cozebilir. Mesajlar yalnizca kullanicinin kendi botuna / sohbetine gider.
"""
import base64
import ctypes
import json
import os
import queue
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from ctypes import wintypes as wt

API = "https://api.telegram.org/bot{token}/{method}"
ENTROPY = b"SysDash-telegram-v1"
RATE_MAX, RATE_WINDOW = 10, 600      # 10 dakikada en fazla 10 mesaj
LEVELS = {"high": ("high",), "warn": ("high", "warn")}
ICON = {"high": "🔴", "warn": "🟠", "info": "🔵"}


class _BLOB(ctypes.Structure):
    _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi(data, protect):
    crypt = ctypes.windll.crypt32
    fn = crypt.CryptProtectData if protect else crypt.CryptUnprotectData
    fn.argtypes = [ctypes.POINTER(_BLOB), ctypes.c_void_p, ctypes.POINTER(_BLOB), ctypes.c_void_p,
                   ctypes.c_void_p, wt.DWORD, ctypes.POINTER(_BLOB)]
    fn.restype = wt.BOOL
    buf = ctypes.create_string_buffer(data, len(data))
    ebuf = ctypes.create_string_buffer(ENTROPY, len(ENTROPY))
    inb = _BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    ent = _BLOB(len(ENTROPY), ctypes.cast(ebuf, ctypes.POINTER(ctypes.c_char)))
    out = _BLOB()
    ok = fn(ctypes.byref(inb), None, ctypes.byref(ent), None, None, 0, ctypes.byref(out))
    if not ok:
        raise OSError("DPAPI hatası")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)


class Notifier(threading.Thread):
    def __init__(self, path, host):
        super().__init__(daemon=True)
        self.path, self.host = path, host
        self.token, self.chat = "", ""
        self.min, self.enabled = "high", False
        self.bot = ""
        self.q = queue.Queue(maxsize=200)
        self.sent_times = deque()
        self.suppressed = 0
        self.last_ok, self.last_err, self.sent = 0.0, "", 0
        self.lock = threading.Lock()
        self.load()

    # ---- ayarlar
    def load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                d = json.load(f)
            if d.get("token"):
                self.token = _dpapi(base64.b64decode(d["token"]), False).decode("utf-8")
            self.chat = str(d.get("chat", ""))
            self.min = d.get("min", "high") if d.get("min") in LEVELS else "high"
            self.enabled = bool(d.get("enabled")) and bool(self.token and self.chat)
            self.bot = d.get("bot", "")
        except (OSError, ValueError):
            pass
        except Exception:
            traceback.print_exc()
            self.last_err = "Kayıtlı ayarlar çözülemedi (başka bir Windows hesabı?)"

    def _save(self):
        d = {"chat": self.chat, "min": self.min, "enabled": self.enabled, "bot": self.bot}
        if self.token:
            d["token"] = base64.b64encode(_dpapi(self.token.encode("utf-8"), True)).decode()
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(d, f)
        os.replace(tmp, self.path)

    def status(self):
        return {"configured": bool(self.token and self.chat), "has_token": bool(self.token), "chat": self.chat,
                "enabled": self.enabled, "min": self.min, "bot": self.bot, "last_ok": self.last_ok,
                "last_err": self.last_err, "sent": self.sent}

    # ---- Telegram API
    def _call(self, token, method, params=None, timeout=15):
        data = urllib.parse.urlencode(params or {}).encode()
        req = urllib.request.Request(API.format(token=token, method=method), data=data,
                                     headers={"User-Agent": "Gozcu"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            try:
                body = json.loads(e.read().decode("utf-8"))
                raise RuntimeError(body.get("description") or f"HTTP {e.code}")
            except ValueError:
                raise RuntimeError(f"HTTP {e.code}")
        except urllib.error.URLError as e:
            raise RuntimeError(f"Bağlantı kurulamadı: {e.reason}")

    def configure(self, token=None, chat=None, min_level=None, enabled=None):
        """-> (ok, hata). Belirteç verilirse dogrulanir; sohbet kimligi bos ise getUpdates ile bulunur."""
        with self.lock:
            tok = (token or "").strip() or self.token
            if not tok:
                return False, "Bot belirteci (token) gerekli"
            if token and token.strip():
                try:
                    me = self._call(tok, "getMe")
                except RuntimeError as e:
                    return False, f"Token doğrulanamadı: {e}"
                self.bot = (me.get("result") or {}).get("username", "")
            ch = str(chat or "").strip() or self.chat
            if not ch:
                try:
                    ups = self._call(tok, "getUpdates", {"limit": 20}).get("result", [])
                except RuntimeError as e:
                    return False, f"Sohbet kimliği aranamadı: {e}"
                for u in reversed(ups):
                    m = u.get("message") or u.get("channel_post") or u.get("my_chat_member") or {}
                    c = (m.get("chat") or {}).get("id")
                    if c:
                        ch = str(c)
                        break
                if not ch:
                    return False, (f"Sohbet bulunamadı. Önce Telegram'da @{self.bot or 'botunuza'} bir mesaj (örn. /start) "
                                   f"yazın, sonra tekrar deneyin ya da Chat ID'yi elle girin.")
            self.token, self.chat = tok, ch
            if min_level in LEVELS:
                self.min = min_level
            if enabled is not None:
                self.enabled = bool(enabled)
            try:
                self._save()
            except Exception as e:
                return False, f"Ayarlar kaydedilemedi: {e}"
            return True, ""

    def disable(self):
        self.enabled = False
        try:
            self._save()
        except Exception:
            pass

    def _send(self, text):
        self._call(self.token, "sendMessage", {"chat_id": self.chat, "text": text[:3500],
                                               "disable_web_page_preview": "true"})

    def test(self):
        if not (self.token and self.chat):
            return False, "Önce ayarları kaydedin"
        try:
            self._send(f"✅ Gözcü test mesajı\nBilgisayar: {self.host}\nBildirimler çalışıyor.")
            self.last_ok, self.last_err = time.time(), ""
            return True, ""
        except Exception as e:
            self.last_err = str(e)
            return False, str(e)

    # ---- uyari kuyrugu
    def push(self, ev):
        if not self.enabled or ev.get("level") not in LEVELS.get(self.min, ()):
            return
        try:
            self.q.put_nowait(ev)
        except queue.Full:
            pass

    def run(self):
        while True:
            ev = self.q.get()
            try:
                if not self.enabled:
                    continue
                now = time.time()
                while self.sent_times and now - self.sent_times[0] > RATE_WINDOW:
                    self.sent_times.popleft()
                if len(self.sent_times) >= RATE_MAX:
                    self.suppressed += 1
                    continue
                head = f"{ICON.get(ev.get('level'), '')} Gözcü · {self.host}"
                note = f"\n(Son {RATE_WINDOW // 60} dk içinde {self.suppressed} uyarı daha bastırıldı; ayrıntı için Gözcü paneline bakın)" if self.suppressed else ""
                text = f"{head}\n{ev.get('msg', '')}\n{time.strftime('%H:%M:%S', time.localtime(ev.get('t', now)))}{note}"
                try:
                    self._send(text)
                    self.sent_times.append(time.time())
                    self.sent += 1
                    self.suppressed = 0
                    self.last_ok, self.last_err = time.time(), ""
                except Exception as e:
                    self.last_err = str(e)
                    if not ev.get("_retry"):
                        ev["_retry"] = True
                        time.sleep(5)
                        try:
                            self.q.put_nowait(ev)
                        except queue.Full:
                            pass
                time.sleep(1.2)
            except Exception:
                traceback.print_exc()
