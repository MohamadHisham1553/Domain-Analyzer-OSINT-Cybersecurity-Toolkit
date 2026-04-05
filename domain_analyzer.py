#!/usr/bin/env python3
"""
Domain Analyzer - OSINT & Cybersecurity Analysis Tool
A multi-layer domain analysis tool with a modern dark GUI.
Includes API Keys management tab for VirusTotal, Shodan, AbuseIPDB.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import socket
import ssl
import json
import logging
import datetime
import time
import re
import requests
from typing import Optional

# DNS / WHOIS / OpenSSL
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import OpenSSL.crypto
    OPENSSL_AVAILABLE = True
except ImportError:
    OPENSSL_AVAILABLE = False

# ──────────────────────────────────────────────
# COLOUR PALETTE  (cyberpunk / terminal dark)
# ──────────────────────────────────────────────
BG        = "#0d0f14"
BG2       = "#13161e"
BG3       = "#1a1e2a"
PANEL     = "#111420"
BORDER    = "#1e2540"
ACCENT    = "#00d4ff"
ACCENT2   = "#7c3aed"
GREEN     = "#00ff9d"
RED       = "#ff3366"
YELLOW    = "#ffd700"
ORANGE    = "#ff6b35"
TEXT      = "#c8d6e5"
TEXT_DIM  = "#4a5568"
TEXT_BRIGHT = "#ffffff"

FONT_MONO  = ("Courier New", 10)
FONT_LABEL = ("Courier New", 9, "bold")
FONT_TITLE = ("Courier New", 14, "bold")
FONT_HEAD  = ("Courier New", 11, "bold")
FONT_SMALL = ("Courier New", 8)

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 8080, 8443]

# ──────────────────────────────────────────────
# GLOBAL API KEY STORE  (populated by GUI tab)
# ──────────────────────────────────────────────
API_KEYS = {
    "virustotal": "",
    "shodan":     "",
    "abuseipdb":  "",
}

# ──────────────────────────────────────────────
# LOGGING SETUP
# ──────────────────────────────────────────────
logger = logging.getLogger("DomainAnalyzer")
logger.setLevel(logging.DEBUG)


class TextHandler(logging.Handler):
    """Redirect log records to a Tkinter Text widget."""
    def __init__(self, widget: tk.Text):
        super().__init__()
        self.widget = widget

    def emit(self, record):
        msg = self.format(record)
        level = record.levelname
        tag = {"DEBUG": "dim", "INFO": "info", "WARNING": "warn",
               "ERROR": "err", "CRITICAL": "crit"}.get(level, "info")
        def _append():
            self.widget.configure(state="normal")
            self.widget.insert("end", f"[{level:8s}] {msg}\n", tag)
            self.widget.see("end")
            self.widget.configure(state="disabled")
        self.widget.after(0, _append)


# ──────────────────────────────────────────────
# ANALYSIS FUNCTIONS
# ──────────────────────────────────────────────

def do_whois(domain: str) -> dict:
    result = {}
    if not WHOIS_AVAILABLE:
        result["error"] = "python-whois not installed"
        return result
    try:
        w = whois.whois(domain)
        result["registrar"]    = str(w.registrar or "N/A")
        result["organization"] = str(w.org or "N/A")
        result["name_servers"] = (", ".join(w.name_servers)
                                  if isinstance(w.name_servers, list)
                                  else str(w.name_servers or "N/A"))
        result["status"]       = str(w.status[0] if isinstance(w.status, list) else w.status or "N/A")

        def fmt_date(d):
            if isinstance(d, list): d = d[0]
            return str(d)[:19] if d else "N/A"

        result["creation_date"]   = fmt_date(w.creation_date)
        result["expiration_date"] = fmt_date(w.expiration_date)
        result["updated_date"]    = fmt_date(w.updated_date)

        exp = w.expiration_date
        if isinstance(exp, list): exp = exp[0]
        if exp and isinstance(exp, datetime.datetime):
            days_left = (exp - datetime.datetime.utcnow()).days
            result["days_until_expiry"] = days_left
            result["_expired"]          = days_left < 0
            result["_expiring_soon"]    = 0 <= days_left <= 30
    except Exception as e:
        result["error"] = str(e)
    return result


def do_dns(domain: str) -> dict:
    result = {}
    if not DNS_AVAILABLE:
        result["error"] = "dnspython not installed"
        return result
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"):
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=6)
            if rtype == "MX":
                result[rtype] = [f"{r.preference} {r.exchange}" for r in answers]
            elif rtype == "TXT":
                result[rtype] = [b"".join(r.strings).decode(errors="replace") for r in answers]
            else:
                result[rtype] = [str(r) for r in answers]
        except Exception:
            result[rtype] = []
    return result


def do_ip_info(domain: str) -> dict:
    result = {}
    try:
        ip = socket.gethostbyname(domain)
        result["ip"] = ip

        try:
            rev = socket.gethostbyaddr(ip)
            result["reverse_dns"] = rev[0]
        except Exception:
            result["reverse_dns"] = "N/A"

        # GeoIP via ip-api.com (free, no key needed)
        try:
            r = requests.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as",
                timeout=6)
            if r.ok:
                geo = r.json()
                if geo.get("status") == "success":
                    result["country"] = geo.get("country", "N/A")
                    result["region"]  = geo.get("regionName", "N/A")
                    result["city"]    = geo.get("city", "N/A")
                    result["isp"]     = geo.get("isp", "N/A")
                    result["org"]     = geo.get("org", "N/A")
                    result["asn"]     = geo.get("as", "N/A")
        except Exception as e:
            result["geo_error"] = str(e)

        # AbuseIPDB (requires API key)
        abuseipdb_key = API_KEYS.get("abuseipdb", "").strip()
        if abuseipdb_key:
            try:
                r2 = requests.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": abuseipdb_key, "Accept": "application/json"},
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    timeout=8)
                if r2.ok:
                    d2 = r2.json().get("data", {})
                    result["abuse_confidence"] = d2.get("abuseConfidenceScore", "N/A")
                    result["abuse_reports"]    = d2.get("totalReports", "N/A")
                    result["abuse_last_seen"]  = d2.get("lastReportedAt", "N/A") or "Never"
                    result["abuse_country"]    = d2.get("countryCode", "N/A")
                    result["_abuse_flagged"]   = d2.get("abuseConfidenceScore", 0) > 25
                else:
                    result["abuseipdb_error"] = f"HTTP {r2.status_code}"
            except Exception as e:
                result["abuseipdb_error"] = str(e)
        else:
            result["abuseipdb_note"] = "No API key — add one in the API KEYS tab"

        # Shodan (requires API key)
        shodan_key = API_KEYS.get("shodan", "").strip()
        if shodan_key:
            try:
                r3 = requests.get(
                    f"https://api.shodan.io/shodan/host/{ip}",
                    params={"key": shodan_key},
                    timeout=8)
                if r3.ok:
                    sd = r3.json()
                    result["shodan_ports"] = sd.get("ports", [])
                    result["shodan_os"]    = sd.get("os") or "N/A"
                    result["shodan_org"]   = sd.get("org") or "N/A"
                    result["shodan_vulns"] = list(sd.get("vulns", {}).keys())
                    result["shodan_tags"]  = sd.get("tags", [])
                else:
                    result["shodan_error"] = f"HTTP {r3.status_code}: {r3.text[:120]}"
            except Exception as e:
                result["shodan_error"] = str(e)
        else:
            result["shodan_note"] = "No API key — add one in the API KEYS tab"

    except Exception as e:
        result["error"] = str(e)
    return result


def do_ssl(domain: str) -> dict:
    result = {}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
                socket.create_connection((domain, 443), timeout=8),
                server_hostname=domain) as s:
            cert = s.getpeercert()

        def parse_rdn(rdn_seq):
            out = {}
            for rdn in rdn_seq:
                for k, v in rdn:
                    out[k] = v
            return out

        subject = parse_rdn(cert.get("subject", ()))
        issuer  = parse_rdn(cert.get("issuer", ()))
        result["subject_cn"] = subject.get("commonName", "N/A")
        result["issuer_cn"]  = issuer.get("commonName", "N/A")
        result["issuer_org"] = issuer.get("organizationName", "N/A")
        result["not_before"] = cert.get("notBefore", "N/A")
        result["not_after"]  = cert.get("notAfter", "N/A")
        result["serial"]     = str(cert.get("serialNumber", "N/A"))
        result["version"]    = str(cert.get("version", "N/A"))
        result["san"]        = [v for _, v in cert.get("subjectAltName", [])]

        fmt = "%b %d %H:%M:%S %Y %Z"
        try:
            not_after  = datetime.datetime.strptime(result["not_after"],  fmt)
            not_before = datetime.datetime.strptime(result["not_before"], fmt)
            now = datetime.datetime.utcnow()
            result["_expired"]       = now > not_after
            result["_not_yet_valid"] = now < not_before
            result["days_left"]      = (not_after - now).days
        except Exception:
            pass

    except ssl.SSLCertVerificationError as e:
        result["error"]        = f"SSL Verification Error: {e}"
        result["_ssl_invalid"] = True
    except Exception as e:
        result["error"] = str(e)
    return result


def do_ports(domain: str, ports: list) -> dict:
    result = {"open": [], "closed": [], "filtered": []}
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        result["error"] = "Could not resolve domain"
        return result

    port_results = {}
    lock = threading.Lock()

    def worker(p):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            code = s.connect_ex((ip, p))
            s.close()
            with lock:
                port_results[p] = (code == 0)
        except Exception:
            with lock:
                port_results[p] = False

    threads = [threading.Thread(target=worker, args=(p,), daemon=True) for p in ports]
    for t in threads: t.start()
    for t in threads: t.join(timeout=3)

    for port in sorted(ports):
        if port_results.get(port):
            result["open"].append(port)
        else:
            result["closed"].append(port)
    return result


def do_http_headers(domain: str) -> dict:
    result = {}
    for scheme in ("https", "http"):
        try:
            r = requests.get(f"{scheme}://{domain}", timeout=8, allow_redirects=True,
                             headers={"User-Agent": "DomainAnalyzer/1.0"})
            result["status_code"]    = r.status_code
            result["final_url"]      = r.url
            result["headers"]        = dict(r.headers)
            result["redirect_chain"] = [resp.url for resp in r.history]
            h = {k.lower(): v for k, v in r.headers.items()}
            result["security_headers"] = {
                "HSTS":            h.get("strict-transport-security", "MISSING"),
                "X-Frame-Options": h.get("x-frame-options", "MISSING"),
                "CSP":             h.get("content-security-policy", "MISSING"),
                "X-Content-Type":  h.get("x-content-type-options", "MISSING"),
                "Referrer-Policy": h.get("referrer-policy", "MISSING"),
            }
            break
        except Exception as e:
            result[f"{scheme}_error"] = str(e)
    return result


def do_reputation(domain: str) -> dict:
    """
    Reputation check:
      - VirusTotal v3 API  (API key from API KEYS tab)
      - URLhaus abuse.ch   (free, no key needed)
    """
    result = {}
    vt_key = API_KEYS.get("virustotal", "").strip()

    # ── VirusTotal ──────────────────────────────
    if vt_key:
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": vt_key},
                timeout=10)
            if r.status_code == 200:
                data  = r.json()
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                result["vt_malicious"]    = stats.get("malicious", 0)
                result["vt_suspicious"]   = stats.get("suspicious", 0)
                result["vt_harmless"]     = stats.get("harmless", 0)
                result["vt_undetected"]   = stats.get("undetected", 0)
                result["vt_reputation"]   = attrs.get("reputation", "N/A")
                result["vt_categories"]   = attrs.get("categories", {})
                result["vt_last_analysis"]= attrs.get("last_analysis_date", "N/A")
                result["_vt_ok"]          = True
            elif r.status_code == 401:
                result["vt_note"] = "Invalid API key — check the API KEYS tab"
            elif r.status_code == 404:
                result["vt_note"] = "Domain not found in VirusTotal database"
            else:
                result["vt_note"] = f"VirusTotal returned HTTP {r.status_code}"
        except Exception as e:
            result["vt_note"] = f"VirusTotal error: {e}"
    else:
        result["vt_note"] = "No VirusTotal API key — add one in the API KEYS tab"

    # ── URLhaus ─────────────────────────────────
    try:
        r2 = requests.post("https://urlhaus-api.abuse.ch/v1/host/",
                           data={"host": domain}, timeout=8)
        if r2.ok:
            d2 = r2.json()
            result["urlhaus_status"]         = d2.get("query_status", "N/A")
            urls                             = d2.get("urls", [])
            result["urlhaus_malicious_urls"] = len(urls)
            if urls:
                result["_urlhaus_flagged"] = True
                result["urlhaus_samples"]  = [
                    {"url": u.get("url"), "threat": u.get("threat")}
                    for u in urls[:5]
                ]
    except Exception as e:
        result["urlhaus_note"] = f"URLhaus unavailable: {e}"

    return result


# ──────────────────────────────────────────────
# GUI APPLICATION
# ──────────────────────────────────────────────

class DomainAnalyzerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("DOMAIN ANALYZER  //  OSINT & SECURITY TOOLKIT")
        self.root.configure(bg=BG)
        self.root.geometry("1320x880")
        self.root.minsize(1100, 700)

        self.domain_var   = tk.StringVar()
        self.status_var   = tk.StringVar(value="Ready.")
        self.progress_var = tk.DoubleVar(value=0)
        self._analysis_data = {}
        self._running = False

        # API key StringVars (bound to Entry widgets in the tab)
        self._vt_key_var     = tk.StringVar()
        self._shodan_key_var = tk.StringVar()
        self._abuse_key_var  = tk.StringVar()

        self._setup_styles()
        self._build_ui()
        self._setup_logger()

    # ── Styles ──────────────────────────────────
    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook",      background=BG, borderwidth=0)
        style.configure("TNotebook.Tab",
                        background=BG3, foreground=TEXT_DIM,
                        padding=[14, 6], font=FONT_LABEL, borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", BG2)],
                  foreground=[("selected", ACCENT)])
        style.configure("Horizontal.TProgressbar",
                        troughcolor=BG3, background=ACCENT,
                        bordercolor=BORDER, lightcolor=ACCENT, darkcolor=ACCENT2)

    # ── Build UI ─────────────────────────────────
    def _build_ui(self):
        self._build_header()
        self._build_input_bar()
        self._build_progress()
        self._build_main_area()
        self._build_status_bar()

    def _build_header(self):
        hdr = tk.Frame(self.root, bg=BG)
        hdr.pack(fill="x")
        tk.Frame(hdr, height=3, bg=ACCENT).pack(fill="x")
        inner = tk.Frame(hdr, bg=BG, padx=20, pady=10)
        inner.pack(fill="x")
        tk.Label(inner, text="◈  DOMAIN ANALYZER", font=FONT_TITLE,
                 bg=BG, fg=ACCENT).pack(side="left")
        tk.Label(inner, text="OSINT · CYBERSECURITY · INTELLIGENCE",
                 font=FONT_SMALL, bg=BG, fg=TEXT_DIM).pack(side="left", padx=16)
        ts = datetime.datetime.utcnow().strftime("UTC %Y-%m-%d")
        tk.Label(inner, text=ts, font=("Courier New", 9),
                 bg=BG, fg=TEXT_DIM).pack(side="right")

    def _build_input_bar(self):
        bar = tk.Frame(self.root, bg=BG2, padx=20, pady=10)
        bar.pack(fill="x")

        tk.Label(bar, text="TARGET DOMAIN ›", font=FONT_LABEL,
                 bg=BG2, fg=ACCENT).pack(side="left")

        entry = tk.Entry(bar, textvariable=self.domain_var,
                         font=("Courier New", 13, "bold"),
                         bg=BG3, fg=GREEN, insertbackground=ACCENT,
                         relief="flat", bd=6, width=36)
        entry.pack(side="left", padx=(10, 16), ipady=4)
        entry.bind("<Return>", lambda _: self._start_analysis())

        self.analyze_btn = tk.Button(bar, text="▶  ANALYZE",
                                     font=FONT_LABEL, bg=ACCENT, fg=BG,
                                     activebackground=GREEN, activeforeground=BG,
                                     relief="flat", padx=18, pady=6,
                                     cursor="hand2", command=self._start_analysis)
        self.analyze_btn.pack(side="left")

        tk.Button(bar, text="⟳  CLEAR", font=FONT_LABEL,
                  bg=BG3, fg=TEXT_DIM, activebackground=BORDER,
                  relief="flat", padx=12, pady=6,
                  cursor="hand2", command=self._clear_all).pack(side="left", padx=6)

        tk.Button(bar, text="⬇  TXT", font=FONT_LABEL,
                  bg=BG3, fg=TEXT_DIM, activebackground=BORDER,
                  relief="flat", padx=10, pady=6, cursor="hand2",
                  command=lambda: self._export("txt")).pack(side="right", padx=4)
        tk.Button(bar, text="⬇  JSON", font=FONT_LABEL,
                  bg=BG3, fg=TEXT_DIM, activebackground=BORDER,
                  relief="flat", padx=10, pady=6, cursor="hand2",
                  command=lambda: self._export("json")).pack(side="right", padx=4)

    def _build_progress(self):
        pf = tk.Frame(self.root, bg=BG, padx=20)
        pf.pack(fill="x")
        self.progressbar = ttk.Progressbar(pf, variable=self.progress_var,
                                           style="Horizontal.TProgressbar",
                                           maximum=100, length=1)
        self.progressbar.pack(fill="x", pady=4)

    def _build_main_area(self):
        paned = tk.PanedWindow(self.root, orient="horizontal",
                               bg=BG, sashwidth=4, sashrelief="flat", sashpad=0)
        paned.pack(fill="both", expand=True, padx=10, pady=6)

        # ── Left: result tabs ────────────────────
        left = tk.Frame(paned, bg=BG)
        paned.add(left, minsize=680)

        self.notebook = ttk.Notebook(left)
        self.notebook.pack(fill="both", expand=True)

        result_tabs = [
            ("WHOIS",      "whois_box"),
            ("DNS",        "dns_box"),
            ("IP / GEO",   "ip_box"),
            ("SSL / TLS",  "ssl_box"),
            ("PORTS",      "port_box"),
            ("HTTP HDR",   "http_box"),
            ("REPUTATION", "rep_box"),
        ]
        for label, attr in result_tabs:
            frame = tk.Frame(self.notebook, bg=BG2)
            self.notebook.add(frame, text=f"  {label}  ")
            box = scrolledtext.ScrolledText(frame, font=FONT_MONO,
                                             bg=BG2, fg=TEXT,
                                             insertbackground=ACCENT,
                                             relief="flat", padx=10, pady=8,
                                             state="disabled", wrap="word",
                                             selectbackground=ACCENT2)
            box.pack(fill="both", expand=True)
            self._tag_setup(box)
            setattr(self, attr, box)

        # ── API KEYS tab ─────────────────────────
        self._build_api_keys_tab()

        # ── Right: log panel ─────────────────────
        right = tk.Frame(paned, bg=BG)
        paned.add(right, minsize=280)

        tk.Label(right, text="◈ ACTIVITY LOG", font=FONT_LABEL,
                 bg=BG, fg=ACCENT2, pady=6).pack(fill="x", padx=8)
        self.log_box = scrolledtext.ScrolledText(right, font=("Courier New", 9),
                                                  bg=PANEL, fg=TEXT_DIM,
                                                  insertbackground=ACCENT,
                                                  relief="flat", padx=8, pady=6,
                                                  state="disabled", wrap="word")
        self.log_box.pack(fill="both", expand=True, padx=6, pady=(0, 6))
        self._log_tag_setup(self.log_box)

    # ─────────────────────────────────────────────
    # API KEYS TAB
    # ─────────────────────────────────────────────
    def _build_api_keys_tab(self):
        outer = tk.Frame(self.notebook, bg=BG2)
        self.notebook.add(outer, text="  ⚿ API KEYS  ")

        # Scrollable inner frame
        canvas = tk.Canvas(outer, bg=BG2, highlightthickness=0)
        vsb    = tk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        inner = tk.Frame(canvas, bg=BG2)
        win   = canvas.create_window((0, 0), window=inner, anchor="nw")

        def _on_resize(e):
            canvas.itemconfig(win, width=e.width)
        canvas.bind("<Configure>", _on_resize)
        inner.bind("<Configure>",
                   lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

        # ── Page header ──────────────────────────
        tk.Label(inner, text="\n  ⚿  API KEY CONFIGURATION",
                 font=FONT_HEAD, bg=BG2, fg=ACCENT).pack(anchor="w", padx=24)
        tk.Label(inner,
                 text=("  Enter your API keys below and click  ✔ SAVE KEYS FOR SESSION.\n"
                       "  Keys are stored in memory only — never written to disk.\n"),
                 font=FONT_SMALL, bg=BG2, fg=TEXT_DIM, justify="left").pack(anchor="w", padx=24)
        tk.Frame(inner, height=1, bg=BORDER).pack(fill="x", padx=24, pady=(0, 8))

        # ── Reusable block builder ────────────────
        def api_block(title, var, link_url, link_label, description, free=False):
            card = tk.Frame(inner, bg=BG3, pady=14, padx=20)
            card.pack(fill="x", padx=24, pady=6)

            # Title + badge
            top = tk.Frame(card, bg=BG3)
            top.pack(fill="x")
            tk.Label(top, text=title, font=FONT_HEAD, bg=BG3, fg=ACCENT2).pack(side="left")
            badge_col = GREEN if free else YELLOW
            badge_txt = "FREE TIER" if free else "PAID / FREE TIER"
            tk.Label(top, text=f"  [ {badge_txt} ]",
                     font=FONT_SMALL, bg=BG3, fg=badge_col).pack(side="left", padx=6)

            # Description
            tk.Label(card, text=description, font=FONT_SMALL,
                     bg=BG3, fg=TEXT_DIM, justify="left",
                     wraplength=620, anchor="w").pack(anchor="w", pady=(4, 10))

            # Entry + buttons row
            row = tk.Frame(card, bg=BG3)
            row.pack(fill="x")

            tk.Label(row, text="API KEY ›", font=FONT_LABEL,
                     bg=BG3, fg=TEXT_DIM, width=10, anchor="w").pack(side="left")

            ent = tk.Entry(row, textvariable=var, font=FONT_MONO, show="•",
                           bg=BG, fg=GREEN, insertbackground=ACCENT,
                           relief="flat", bd=4, width=52)
            ent.pack(side="left", padx=(6, 8), ipady=3)

            show_lbl = tk.StringVar(value="◎ SHOW")

            def toggle(e=ent, sl=show_lbl):
                if e.cget("show") == "•":
                    e.configure(show="")
                    sl.set("◉ HIDE")
                else:
                    e.configure(show="•")
                    sl.set("◎ SHOW")

            tk.Button(row, textvariable=show_lbl, font=FONT_SMALL,
                      bg=BG3, fg=TEXT_DIM, activebackground=BORDER,
                      relief="flat", padx=7, pady=2, cursor="hand2",
                      command=toggle).pack(side="left")

            tk.Button(row, text="✕ CLEAR", font=FONT_SMALL,
                      bg=BG3, fg=RED, activebackground=BORDER,
                      relief="flat", padx=7, pady=2, cursor="hand2",
                      command=lambda v=var: v.set("")).pack(side="left", padx=6)

            # Signup link
            lnk_row = tk.Frame(card, bg=BG3)
            lnk_row.pack(anchor="w", pady=(8, 0))
            tk.Label(lnk_row, text="Get your free key →",
                     font=FONT_SMALL, bg=BG3, fg=TEXT_DIM).pack(side="left")
            lnk = tk.Label(lnk_row, text=link_label, font=FONT_SMALL,
                           bg=BG3, fg=ACCENT, cursor="hand2")
            lnk.pack(side="left", padx=4)
            lnk.bind("<Button-1>", lambda e, u=link_url: self._open_url(u))

        # ── VirusTotal ───────────────────────────
        api_block(
            "VIRUSTOTAL",
            self._vt_key_var,
            "https://www.virustotal.com/gui/join-us",
            "virustotal.com/gui/join-us",
            ("Used in the REPUTATION tab.\n"
             "Scans the domain against 90+ antivirus engines and threat intelligence feeds.\n"
             "Free tier: 4 lookups / min · 500 / day · No credit card required."),
            free=True,
        )

        # ── Shodan ───────────────────────────────
        api_block(
            "SHODAN",
            self._shodan_key_var,
            "https://account.shodan.io/register",
            "account.shodan.io/register",
            ("Used in the IP / GEO tab.\n"
             "Returns open ports, OS fingerprint, banners, known CVEs, and threat tags\n"
             "for the resolved IP address.  Free account includes limited host queries."),
            free=False,
        )

        # ── AbuseIPDB ────────────────────────────
        api_block(
            "ABUSEIPDB",
            self._abuse_key_var,
            "https://www.abuseipdb.com/register",
            "abuseipdb.com/register",
            ("Used in the IP / GEO tab.\n"
             "Shows the abuse confidence score, total community reports, and last-seen date\n"
             "for the resolved IP address.  Free tier: 1,000 checks / day · No credit card."),
            free=True,
        )

        # ── Save button + status ─────────────────
        tk.Frame(inner, height=1, bg=BORDER).pack(fill="x", padx=24, pady=(12, 6))

        btn_row = tk.Frame(inner, bg=BG2)
        btn_row.pack(padx=24, pady=4, anchor="w")

        self._key_status_var = tk.StringVar(value="")

        tk.Button(btn_row, text="✔  SAVE KEYS FOR SESSION",
                  font=FONT_LABEL, bg=GREEN, fg=BG,
                  activebackground=ACCENT, activeforeground=BG,
                  relief="flat", padx=18, pady=7, cursor="hand2",
                  command=self._save_api_keys).pack(side="left")

        tk.Label(btn_row, textvariable=self._key_status_var,
                 font=FONT_SMALL, bg=BG2, fg=GREEN).pack(side="left", padx=16)

        # ── Info / help box ──────────────────────
        info_text = (
            "\n  HOW IT WORKS\n"
            "  ─────────────────────────────────────────────────────────────\n"
            "  1.  Paste your API key(s) into the fields above.\n"
            "  2.  Click  ✔ SAVE KEYS FOR SESSION  to activate them.\n"
            "  3.  Run an analysis — enriched data from each keyed service\n"
            "      will appear automatically in the relevant result tab.\n\n"
            "  Keys are held in memory for this session only.  They are\n"
            "  never written to disk and are lost when you close the app.\n\n"
            "  ─────────────────────────────────────────────────────────────\n"
            "  WHAT WORKS WITHOUT ANY KEYS\n"
            "  • WHOIS lookup                 ✓ always free\n"
            "  • DNS records (A/MX/NS/TXT…)   ✓ always free\n"
            "  • SSL / TLS certificate        ✓ always free\n"
            "  • Port scanner (17 ports)      ✓ always free\n"
            "  • HTTP headers + security audit✓ always free\n"
            "  • GeoIP  (ip-api.com)          ✓ always free, no key\n"
            "  • URLhaus malware feed         ✓ always free, no key\n"
            "  • VirusTotal engine scan       ✗ API key required\n"
            "  • Shodan host intelligence     ✗ API key required\n"
            "  • AbuseIPDB confidence score   ✗ API key required\n"
        )
        info_box = tk.Text(inner, font=FONT_SMALL, bg=PANEL, fg=TEXT_DIM,
                           relief="flat", padx=16, pady=10,
                           height=18, state="normal", wrap="none")
        info_box.insert("end", info_text)
        info_box.configure(state="disabled")
        info_box.pack(fill="x", padx=24, pady=(4, 24))

    def _save_api_keys(self):
        API_KEYS["virustotal"] = self._vt_key_var.get().strip()
        API_KEYS["shodan"]     = self._shodan_key_var.get().strip()
        API_KEYS["abuseipdb"]  = self._abuse_key_var.get().strip()
        active = [n.upper() for n, v in API_KEYS.items() if v]
        if active:
            self._key_status_var.set(f"✔  Active: {', '.join(active)}")
            logger.info(f"API keys saved — active: {', '.join(active)}")
        else:
            self._key_status_var.set("⚠  No keys saved (all fields empty)")
            logger.warning("No API keys provided.")

    def _open_url(self, url: str):
        import webbrowser
        webbrowser.open(url)

    def _build_status_bar(self):
        sb = tk.Frame(self.root, bg=BG3, pady=4)
        sb.pack(fill="x", side="bottom")
        tk.Frame(sb, height=1, bg=BORDER).pack(fill="x")
        tk.Label(sb, textvariable=self.status_var, font=("Courier New", 9),
                 bg=BG3, fg=TEXT_DIM, padx=14).pack(side="left")

    # ── Tag setup ────────────────────────────────
    def _tag_setup(self, box):
        box.tag_configure("header",      foreground=ACCENT,   font=("Courier New", 10, "bold"))
        box.tag_configure("label",       foreground=TEXT_DIM)
        box.tag_configure("value",       foreground=TEXT)
        box.tag_configure("good",        foreground=GREEN)
        box.tag_configure("warn",        foreground=YELLOW)
        box.tag_configure("bad",         foreground=RED,      font=("Courier New", 10, "bold"))
        box.tag_configure("orange",      foreground=ORANGE)
        box.tag_configure("dim",         foreground=TEXT_DIM)
        box.tag_configure("accent",      foreground=ACCENT2)
        box.tag_configure("port_open",   foreground=RED,      font=("Courier New", 10, "bold"))
        box.tag_configure("port_closed", foreground=TEXT_DIM)

    def _log_tag_setup(self, box):
        box.tag_configure("dim",  foreground=TEXT_DIM)
        box.tag_configure("info", foreground=TEXT)
        box.tag_configure("warn", foreground=YELLOW)
        box.tag_configure("err",  foreground=RED)
        box.tag_configure("crit", foreground=RED, font=("Courier New", 9, "bold"))

    def _setup_logger(self):
        handler = TextHandler(self.log_box)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)

    # ── Write helpers ────────────────────────────
    def _write(self, box, text: str, tag: str = "value"):
        box.configure(state="normal")
        box.insert("end", text, tag)
        box.configure(state="disabled")

    def _clear_box(self, box):
        box.configure(state="normal")
        box.delete("1.0", "end")
        box.configure(state="disabled")

    def _section(self, box, title: str):
        self._write(box, f"\n◈ {title}\n", "header")
        self._write(box, "─" * 60 + "\n", "dim")

    def _kv(self, box, key: str, value: str, vtag: str = "value"):
        self._write(box, f"  {key:<26}", "label")
        self._write(box, f"{value}\n", vtag)

    # ── Analysis orchestrator ────────────────────
    def _start_analysis(self):
        if self._running:
            return
        domain = self.domain_var.get().strip().lower()
        domain = re.sub(r"^https?://", "", domain).rstrip("/").split("/")[0]
        if not domain:
            messagebox.showwarning("Input Required", "Please enter a domain name.")
            return
        self.domain_var.set(domain)
        self._running = True
        self.analyze_btn.configure(state="disabled", text="⏳ ANALYZING…")
        self._clear_all_boxes()
        self._analysis_data = {}
        self.progress_var.set(0)
        logger.info(f"Starting analysis for: {domain}")
        t = threading.Thread(target=self._run_analysis, args=(domain,), daemon=True)
        t.start()

    def _clear_all_boxes(self):
        for attr in ("whois_box", "dns_box", "ip_box", "ssl_box",
                     "port_box", "http_box", "rep_box"):
            self._clear_box(getattr(self, attr))

    def _set_status(self, msg):
        self.root.after(0, lambda: self.status_var.set(msg))

    def _set_progress(self, val):
        self.root.after(0, lambda: self.progress_var.set(val))

    def _run_analysis(self, domain):
        steps = [
            ("WHOIS Lookup",     self._do_whois,  domain),
            ("DNS Records",      self._do_dns,    domain),
            ("IP / GeoIP",       self._do_ip,     domain),
            ("SSL Certificate",  self._do_ssl,    domain),
            ("Port Scan",        self._do_ports,  domain),
            ("HTTP Headers",     self._do_http,   domain),
            ("Reputation Check", self._do_rep,    domain),
        ]
        total = len(steps)
        for i, (name, fn, arg) in enumerate(steps):
            self._set_status(f"Running: {name}…")
            logger.info(f"[{i+1}/{total}] {name}")
            try:
                fn(arg)
            except Exception as e:
                logger.error(f"{name} failed: {e}")
            self._set_progress((i + 1) / total * 100)

        self._set_status(
            f"Analysis complete for {domain}  ·  "
            f"{datetime.datetime.utcnow().strftime('%H:%M:%S UTC')}")
        logger.info("Analysis complete.")
        self.root.after(0, self._finish_analysis)

    def _finish_analysis(self):
        self._running = False
        self.analyze_btn.configure(state="normal", text="▶  ANALYZE")

    # ── WHOIS ────────────────────────────────────
    def _do_whois(self, domain):
        data = do_whois(domain)
        self._analysis_data["whois"] = data
        box = self.whois_box
        def render():
            self._section(box, "WHOIS REGISTRATION DATA")
            if "error" in data:
                self._write(box, f"  Error: {data['error']}\n", "bad"); return
            self._kv(box, "Registrar",    data.get("registrar",    "N/A"))
            self._kv(box, "Organization", data.get("organization", "N/A"))
            self._kv(box, "Name Servers", data.get("name_servers", "N/A"))
            self._kv(box, "Status",       data.get("status",       "N/A"))
            self._kv(box, "Created",      data.get("creation_date","N/A"))
            exp_val = data.get("expiration_date", "N/A")
            days    = data.get("days_until_expiry")
            if data.get("_expired"):
                tag = "bad";  note = "  ⚠ EXPIRED"
            elif data.get("_expiring_soon"):
                tag = "warn"; note = f"  ⚠ EXPIRING IN {days} DAYS"
            else:
                tag = "good"; note = f"  ✓ {days} days remaining" if days is not None else ""
            self._kv(box, "Expires", exp_val + note, tag)
            self._kv(box, "Updated", data.get("updated_date", "N/A"))
        self.root.after(0, render)

    # ── DNS ──────────────────────────────────────
    def _do_dns(self, domain):
        data = do_dns(domain)
        self._analysis_data["dns"] = data
        box = self.dns_box
        def render():
            self._section(box, "DNS RECORDS")
            for rtype, records in data.items():
                if rtype == "error":
                    self._write(box, f"  Error: {records}\n", "bad"); continue
                self._write(box, f"\n  ▸ {rtype} RECORDS\n", "accent")
                if not records:
                    self._write(box, "    (none)\n", "dim")
                else:
                    for rec in records:
                        self._write(box, f"    {rec}\n", "value")
        self.root.after(0, render)

    # ── IP / GEO ─────────────────────────────────
    def _do_ip(self, domain):
        data = do_ip_info(domain)
        self._analysis_data["ip"] = data
        box = self.ip_box
        def render():
            self._section(box, "IP INFORMATION")
            if "error" in data:
                self._write(box, f"  Error: {data['error']}\n", "bad"); return
            self._kv(box, "Resolved IP",  data.get("ip",          "N/A"), "good")
            self._kv(box, "Reverse DNS",  data.get("reverse_dns", "N/A"))

            self._section(box, "GEO-IP INTELLIGENCE  (ip-api.com · no key needed)")
            self._kv(box, "Country", data.get("country", "N/A"))
            self._kv(box, "Region",  data.get("region",  "N/A"))
            self._kv(box, "City",    data.get("city",    "N/A"))
            self._kv(box, "ISP",     data.get("isp",     "N/A"))
            self._kv(box, "Org",     data.get("org",     "N/A"))
            self._kv(box, "ASN",     data.get("asn",     "N/A"))
            if "geo_error" in data:
                self._kv(box, "GeoIP Error", data["geo_error"], "warn")

            # AbuseIPDB section
            self._section(box, "ABUSEIPDB REPUTATION  (API key required)")
            if "abuseipdb_note" in data:
                self._write(box, f"  ℹ  {data['abuseipdb_note']}\n", "dim")
            elif "abuseipdb_error" in data:
                self._write(box, f"  Error: {data['abuseipdb_error']}\n", "bad")
            else:
                score = data.get("abuse_confidence", "N/A")
                stag  = "bad" if data.get("_abuse_flagged") else "good"
                self._kv(box, "Confidence Score", f"{score}%", stag)
                self._kv(box, "Total Reports",    str(data.get("abuse_reports",  "N/A")))
                self._kv(box, "Last Reported",    str(data.get("abuse_last_seen","N/A")))
                self._kv(box, "Country Code",     data.get("abuse_country",  "N/A"))

            # Shodan section
            self._section(box, "SHODAN HOST INTELLIGENCE  (API key required)")
            if "shodan_note" in data:
                self._write(box, f"  ℹ  {data['shodan_note']}\n", "dim")
            elif "shodan_error" in data:
                self._write(box, f"  Error: {data['shodan_error']}\n", "bad")
            else:
                ports = data.get("shodan_ports", [])
                self._kv(box, "Open Ports",
                         ", ".join(map(str, ports)) if ports else "None",
                         "warn" if ports else "good")
                self._kv(box, "OS",  data.get("shodan_os",  "N/A"))
                self._kv(box, "Org", data.get("shodan_org", "N/A"))
                vulns = data.get("shodan_vulns", [])
                self._kv(box, "CVEs Found",
                         ", ".join(vulns) if vulns else "None",
                         "bad" if vulns else "good")
                tags = data.get("shodan_tags", [])
                self._kv(box, "Tags", ", ".join(tags) if tags else "None")
        self.root.after(0, render)

    # ── SSL ──────────────────────────────────────
    def _do_ssl(self, domain):
        data = do_ssl(domain)
        self._analysis_data["ssl"] = data
        box = self.ssl_box
        def render():
            self._section(box, "SSL / TLS CERTIFICATE")
            if "error" in data:
                self._write(box, f"  Error: {data['error']}\n", "bad"); return
            self._kv(box, "Subject (CN)",  data.get("subject_cn", "N/A"))
            self._kv(box, "Issuer (CN)",   data.get("issuer_cn",  "N/A"))
            self._kv(box, "Issuer (Org)",  data.get("issuer_org", "N/A"))
            self._kv(box, "Valid From",    data.get("not_before", "N/A"))
            exp  = data.get("not_after",  "N/A")
            days = data.get("days_left")
            if data.get("_expired"):
                tag = "bad";  note = "  ⚠ CERTIFICATE EXPIRED"
            elif days is not None and days <= 14:
                tag = "warn"; note = f"  ⚠ EXPIRES IN {days} DAYS"
            else:
                tag = "good"; note = f"  ✓ {days} days remaining" if days is not None else ""
            self._kv(box, "Valid Until",   exp + note, tag)
            self._kv(box, "Serial Number", data.get("serial",  "N/A"))
            self._kv(box, "Version",       data.get("version", "N/A"))
            san = data.get("san", [])
            self._section(box, f"SUBJECT ALT NAMES  ({len(san)} entries)")
            for name in san[:20]:
                self._write(box, f"    {name}\n", "value")
            if len(san) > 20:
                self._write(box, f"    … and {len(san)-20} more\n", "dim")
        self.root.after(0, render)

    # ── PORTS ────────────────────────────────────
    def _do_ports(self, domain):
        data = do_ports(domain, COMMON_PORTS)
        self._analysis_data["ports"] = data
        box = self.port_box
        PORT_NAMES = {
            21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
            80:"HTTP", 110:"POP3", 143:"IMAP", 443:"HTTPS",
            465:"SMTPS", 587:"Submission", 993:"IMAPS", 995:"POP3S",
            3306:"MySQL", 3389:"RDP", 8080:"HTTP-Alt", 8443:"HTTPS-Alt",
        }
        def render():
            self._section(box, "PORT SCAN RESULTS")
            if "error" in data:
                self._write(box, f"  Error: {data['error']}\n", "bad"); return
            open_ports = data.get("open", [])
            self._write(box,
                f"\n  ◆ Open Ports: {len(open_ports)}/{len(COMMON_PORTS)}\n\n",
                "warn" if open_ports else "good")
            self._write(box, f"  {'PORT':<8}{'SERVICE':<16}{'STATE'}\n", "label")
            self._write(box, "  " + "─" * 36 + "\n", "dim")
            for port in sorted(COMMON_PORTS):
                svc = PORT_NAMES.get(port, "unknown")
                if port in open_ports:
                    self._write(box, f"  {port:<8}{svc:<16}", "label")
                    self._write(box, "OPEN  ◀\n", "port_open")
                else:
                    self._write(box, f"  {port:<8}{svc:<16}closed\n", "port_closed")
        self.root.after(0, render)

    # ── HTTP HEADERS ─────────────────────────────
    def _do_http(self, domain):
        data = do_http_headers(domain)
        self._analysis_data["http"] = data
        box = self.http_box
        def render():
            self._section(box, "HTTP RESPONSE")
            sc = data.get("status_code", "N/A")
            self._kv(box, "Status Code", str(sc),
                     "good" if isinstance(sc, int) and sc < 400 else "bad")
            self._kv(box, "Final URL",   data.get("final_url", "N/A"))
            chain = data.get("redirect_chain", [])
            if chain:
                self._kv(box, "Redirect Chain", " → ".join(chain), "warn")
            self._section(box, "SECURITY HEADERS AUDIT")
            for header, value in data.get("security_headers", {}).items():
                if value == "MISSING":
                    self._kv(box, header, "✗ MISSING", "bad")
                else:
                    short = value[:70] + "…" if len(value) > 70 else value
                    self._kv(box, header, f"✓ {short}", "good")
            self._section(box, "ALL RESPONSE HEADERS")
            for k, v in data.get("headers", {}).items():
                self._kv(box, k, v)
        self.root.after(0, render)

    # ── REPUTATION ───────────────────────────────
    def _do_rep(self, domain):
        data = do_reputation(domain)
        self._analysis_data["reputation"] = data
        box = self.rep_box
        def render():
            self._section(box, "REPUTATION INTELLIGENCE")

            self._write(box, "\n  ◆ VIRUSTOTAL  (API key required)\n", "accent")
            if "vt_note" in data:
                icon = "ℹ" if "key" in data["vt_note"].lower() else "⚠"
                self._write(box, f"    {icon}  {data['vt_note']}\n", "warn")
            else:
                mal = data.get("vt_malicious", 0)
                sus = data.get("vt_suspicious", 0)
                self._kv(box, "Malicious Detections", str(mal), "bad"  if mal > 0 else "good")
                self._kv(box, "Suspicious",           str(sus), "warn" if sus > 0 else "good")
                self._kv(box, "Harmless",             str(data.get("vt_harmless",  0)), "good")
                self._kv(box, "Undetected",           str(data.get("vt_undetected",0)))
                self._kv(box, "Reputation Score",     str(data.get("vt_reputation","N/A")))
                cats = data.get("vt_categories", {})
                if cats:
                    self._kv(box, "Categories", ", ".join(cats.values()))

            self._write(box, "\n  ◆ URLHAUS  (abuse.ch · no key needed)\n", "accent")
            if "urlhaus_note" in data:
                self._write(box, f"    ⚠  {data['urlhaus_note']}\n", "warn")
            else:
                status = data.get("urlhaus_status", "N/A")
                count  = data.get("urlhaus_malicious_urls", 0)
                self._kv(box, "Status",         status,    "bad"  if data.get("_urlhaus_flagged") else "good")
                self._kv(box, "Malicious URLs", str(count),"bad"  if count > 0 else "good")
                for s in data.get("urlhaus_samples", []):
                    self._write(box, f"    [{s['threat']}] {s['url']}\n", "bad")
        self.root.after(0, render)

    # ── Clear ────────────────────────────────────
    def _clear_all(self):
        self._clear_all_boxes()
        self._analysis_data = {}
        self.progress_var.set(0)
        self.status_var.set("Ready.")
        self._clear_box(self.log_box)

    # ── Export ───────────────────────────────────
    def _export(self, fmt: str):
        if not self._analysis_data:
            messagebox.showinfo("No Data", "Run an analysis first.")
            return
        domain = self.domain_var.get().strip() or "domain"
        ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        fname = f"domain_analyzer_{domain}_{ts}.{fmt}"
        path = filedialog.asksaveasfilename(defaultextension=f".{fmt}",
                                             initialfile=fname,
                                             filetypes=[(fmt.upper(), f"*.{fmt}")])
        if not path:
            return
        try:
            if fmt == "json":
                with open(path, "w") as f:
                    json.dump(self._analysis_data, f, indent=2, default=str)
            else:
                with open(path, "w") as f:
                    f.write("DOMAIN ANALYZER REPORT\n")
                    f.write(f"Target : {domain}\n")
                    f.write(f"Date   : {datetime.datetime.utcnow().isoformat()} UTC\n")
                    f.write("=" * 60 + "\n\n")
                    for section, sdata in self._analysis_data.items():
                        f.write(f"\n[{section.upper()}]\n")
                        f.write(json.dumps(sdata, indent=2, default=str) + "\n")
            messagebox.showinfo("Exported", f"Saved to:\n{path}")
            logger.info(f"Exported {fmt.upper()} to {path}")
        except Exception as e:
            messagebox.showerror("Export Failed", str(e))


# ──────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────

def main():
    root = tk.Tk()
    root.option_add("*tearOff", False)
    try:
        root.tk.call("wm", "iconphoto", root._w)
    except Exception:
        pass
    app = DomainAnalyzerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
