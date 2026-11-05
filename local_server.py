"""Loopback-only Egress launcher and user-initiated IPSuper lookup."""
import ipaddress
import json
import os
import threading
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
LOCAL = "http://127.0.0.1:4187"
ORIGINS = {LOCAL, "http://localhost:4187", "https://blackslience-reaper.github.io"}
LOCKS = {name: threading.Lock() for name in ("ipsuper", "ipinfo")}
CACHES = {name: {} for name in LOCKS}


def lookup(ip, provider):
    from playwright.sync_api import sync_playwright
    with sync_playwright() as api:
        options = {"headless": True}
        if not Path(api.chromium.executable_path).exists():
            options["channel"] = "chrome"
        browser = api.chromium.launch(**options)
        try:
            page = browser.new_page(locale="zh-CN")
            if provider == "ipinfo":
                response = page.goto("https://ipinfo.io/" + ip, wait_until="domcontentloaded", timeout=30000)
                if not response or response.status != 200 or urlsplit(page.url).hostname != "ipinfo.io":
                    raise ValueError("IPinfo detail unavailable")
                page.get_by_text("Summary", exact=True).first.wait_for(state="attached", timeout=10000)
                raw = page.locator("body").inner_text().split("Table of Contents")[0]
                return {"ip": ip, "text": raw[:120000], "time": int(time.time()*1000)}
            page.goto("https://ipsuper.com/?ip=" + ip, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_function("""ip => {
              const inputMatches = [...document.querySelectorAll('input')].some(el => el.value.trim() === ip);
              const targetShown = inputMatches || [...document.querySelectorAll('a[href]')].some(a => a.textContent.trim() === ip && new URL(a.href, location.href).searchParams.get('ip') === ip);
              const grid = document.querySelector('.attributes-grid');
              return targetShown && new URL(location.href).searchParams.get('ip') === ip && grid?.innerText.includes('公司类型')
                && ([...grid.querySelectorAll('.grid-cell')].some(c => /家宽|机房|商业|移动|教育|政府/.test(c.innerText)) || document.querySelector('.risk-scores .right-label[title]'))
                ;
            }""", arg=ip, timeout=60000)
            return page.locator(".attributes-grid").filter(has_text="公司类型").first.evaluate("""grid => {
              const headers = [...grid.querySelectorAll(':scope > .grid-header')].slice(1).map(n=>n.innerText.trim());
              const rows = {};
              for(const label of grid.querySelectorAll(':scope > .grid-label')) {
                const values = [];
                let cell = label.nextElementSibling;
                while(cell?.classList.contains('grid-cell')) { values.push(cell.innerText.trim()); cell=cell.nextElementSibling; }
                if(values.length===headers.length) rows[label.innerText.trim()]=values;
              }
              const riskPercent = {};
              for (const row of document.querySelectorAll('.risk-scores .info-row')) {
                const name = row.querySelector('.info-label')?.textContent.trim();
                const title = row.querySelector('.right-label')?.title || '';
                const match = /^风险\s*\(([0-9.]+)%\)$/.exec(title);
                if (name && match && Number(match[1]) <= 100) riskPercent[name] = Number(match[1]);
              }
              return {headers,rows,riskPercent,ip:new URL(location.href).searchParams.get('ip'),time:Date.now()};
            }""")
        except Exception:
            if page:
                print(provider, page.title(), "grids", page.locator(".attributes-grid").count(),
                      "risk_rows", page.locator(".risk-scores .info-row").count(), flush=True)
                if provider == "ipsuper" and page.locator(".attributes-grid").count():
                    print("type grid:", page.locator(".attributes-grid").first.inner_text()[:350], flush=True)
            raise
        finally:
            browser.close()


class Handler(SimpleHTTPRequestHandler):
    def reply(self, code, data):
        self.send_response(code)
        origin = self.headers.get("Origin")
        if origin in ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Access-Control-Allow-Private-Network", "true")
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_OPTIONS(self):
        self.reply(200 if self.headers.get("Origin") in ORIGINS else 403, {})

    def do_POST(self):
        if (self.path not in {"/lookup/ipsuper","/lookup/ipinfo"} or self.headers.get("Origin") not in ORIGINS
            or self.headers.get("Host") not in {"127.0.0.1:4188","localhost:4188"}
            or self.headers.get_content_type() != "application/json"):
            return self.reply(403, {})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 256: raise ValueError()
            ip = ipaddress.ip_address(json.loads(self.rfile.read(length))["ip"])
            if not ip.is_global or ip.is_multicast or "%" in str(ip): raise ValueError()
        except (TypeError, ValueError, KeyError):
            return self.reply(400, {})
        ip = str(ip)
        provider = self.path.rsplit("/",1)[1]
        lock = LOCKS[provider]
        cache = CACHES[provider]
        if not lock.acquire(timeout=2):
            return self.reply(429, {"error":"上一轮网页查询仍在运行"})
        try:
            result = cache.get(ip)
            if not result or time.time()*1000-result["time"] > 600000:
                result = lookup(ip, provider)
                if result["ip"] != ip: raise ValueError()
                if len(cache) >= 128: cache.pop(next(iter(cache)))
                cache[ip] = result
            self.reply(200,result)
        except Exception as exc:
            print(provider, type(exc).__name__, flush=True)
            self.reply(502, {"error":provider + " 网页未返回可读取的报告"})
        finally:
            lock.release()

    def do_GET(self):
        path = urlsplit(self.path).path
        allowed = {"/","/index.html","/config.js","/styles.css","/favicon.svg"}
        if path not in allowed and path not in {"/src/"+p.name for p in (ROOT/"src").glob("*.js")}:
            return self.send_error(404)
        super().do_GET()

    do_HEAD = do_GET


if __name__ == "__main__":
    os.chdir(ROOT)
    helper = ThreadingHTTPServer(("127.0.0.1",4188), Handler)
    try:
        site = ThreadingHTTPServer(("127.0.0.1",4187), Handler)
    except OSError:
        site = None
    if site:
        threading.Thread(target=site.serve_forever, daemon=True).start()
    helper.serve_forever()
