"""
SysDash - cevrimdisi IP -> ulke / ASN eslestirme.

Veri: DB-IP "IP to Country Lite" ve "IP to ASN Lite" (CC BY 4.0, https://db-ip.com).
Dosyalar geodata/ klasorunde durur: dbip-country-lite-YYYY-MM.csv.gz, dbip-asn-lite-YYYY-MM.csv.gz
"""
import csv
import glob
import gzip
import ipaddress
import os
import threading
import traceback
from array import array
from bisect import bisect_right


class _Table:
    """Siralanmis, ust uste binmeyen araliklar. IPv4: 32 bit, IPv6: ilk 64 bit."""

    def __init__(self):
        self.s4, self.e4, self.v4 = array("I"), array("I"), array("I")
        self.s6, self.e6, self.v6 = array("Q"), array("Q"), array("I")

    def add(self, a, b, v):
        try:
            if ":" in a:
                self.s6.append(int(ipaddress.IPv6Address(a)) >> 64)
                self.e6.append(int(ipaddress.IPv6Address(b)) >> 64)
                self.v6.append(v)
            else:
                self.s4.append(int(ipaddress.IPv4Address(a)))
                self.e4.append(int(ipaddress.IPv4Address(b)))
                self.v4.append(v)
        except ValueError:
            pass

    def find(self, ip):
        if ip.version == 6:
            x = int(ip) >> 64
            s, e, v = self.s6, self.e6, self.v6
        else:
            x = int(ip)
            s, e, v = self.s4, self.e4, self.v4
        i = bisect_right(s, x) - 1
        if i >= 0 and x <= e[i]:
            return v[i]
        return None


def _latest(pattern):
    files = sorted(glob.glob(pattern))
    return files[-1] if files else None


class GeoIP:
    def __init__(self, folder):
        self.folder = folder
        self.ready = False
        self.status = "yüklenmedi"
        self.cc = {}        # ulke kodu <-> sayi
        self.cc_list = [""]
        self.orgs = [""]    # kuruluş adları
        self.org_idx = {}
        self.country = _Table()
        self.asn = _Table()
        self.asn_of = array("I")   # asn tablosunda deger = org indeksi
        self.asn_num = array("I")
        self.source = ""

    def start(self):
        threading.Thread(target=self._load, daemon=True).start()

    def _load(self):
        try:
            cf = _latest(os.path.join(self.folder, "dbip-country-lite-*.csv.gz"))
            af = _latest(os.path.join(self.folder, "dbip-asn-lite-*.csv.gz"))
            if not cf and not af:
                self.status = "veritabanı dosyası yok (geodata klasörü)"
                return
            if cf:
                with gzip.open(cf, "rt", encoding="utf-8", newline="") as f:
                    for row in csv.reader(f):
                        if len(row) < 3:
                            continue
                        code = row[2]
                        i = self.cc.get(code)
                        if i is None:
                            i = self.cc[code] = len(self.cc_list)
                            self.cc_list.append(code)
                        self.country.add(row[0], row[1], i)
            if af:
                with gzip.open(af, "rt", encoding="utf-8", newline="") as f:
                    for row in csv.reader(f):
                        if len(row) < 4 or not row[2].isdigit():
                            continue
                        org = row[3]
                        j = self.org_idx.get(org)
                        if j is None:
                            j = self.org_idx[org] = len(self.orgs)
                            self.orgs.append(org)
                        self.asn.add(row[0], row[1], len(self.asn_num))
                        self.asn_num.append(int(row[2]))
                        self.asn_of.append(j)
            self.source = ", ".join(os.path.basename(x) for x in (cf, af) if x)
            self.ready = True
            self.status = "ok"
        except Exception:
            traceback.print_exc()
            self.status = "yüklenemedi"

    def ranges(self, cc):
        """Ulkenin birlesik adres araliklari: ["a.b.c.d-e.f.g.h", ...] (IPv4 + IPv6 /64 sinirli)."""
        ci = self.cc.get(cc)
        if not ci or not self.ready:
            return []
        out = []
        t = self.country
        cur = None
        for s, e, v in zip(t.s4, t.e4, t.v4):
            if v != ci:
                continue
            if cur and s <= cur[1] + 1:
                cur[1] = max(cur[1], e)
            else:
                if cur:
                    out.append(cur)
                cur = [s, e]
        if cur:
            out.append(cur)
        res = [f"{ipaddress.IPv4Address(a)}-{ipaddress.IPv4Address(b)}" for a, b in out]
        cur = None
        out6 = []
        for s, e, v in zip(t.s6, t.e6, t.v6):
            if v != ci:
                continue
            if cur and s <= cur[1] + 1:
                cur[1] = max(cur[1], e)
            else:
                if cur:
                    out6.append(cur)
                cur = [s, e]
        if cur:
            out6.append(cur)
        for a, b in out6:
            res.append(f"{ipaddress.IPv6Address(a << 64)}-{ipaddress.IPv6Address((b << 64) | ((1 << 64) - 1))}")
        return res

    def lookup(self, ip):
        """-> {"cc": "DE", "asn": 13335, "org": "Cloudflare, Inc."} ya da None"""
        if not self.ready:
            return None
        try:
            a = ipaddress.ip_address(ip.split("%")[0])
        except ValueError:
            return None
        if getattr(a, "ipv4_mapped", None):
            a = a.ipv4_mapped
        if a.is_private or a.is_loopback or a.is_link_local or a.is_multicast:
            return None
        out = {}
        ci = self.country.find(a)
        if ci:
            code = self.cc_list[ci]
            if code and code != "ZZ":
                out["cc"] = code
        ai = self.asn.find(a)
        if ai is not None:
            out["asn"] = self.asn_num[ai]
            out["org"] = self.orgs[self.asn_of[ai]]
        return out or None
