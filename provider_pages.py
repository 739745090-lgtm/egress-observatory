"""Bounded, fixed-site browser fallbacks for unavailable provider records."""
import asyncio
import time
from pathlib import Path
from urllib.parse import urlsplit

SITES = {
    "iphub": "https://iphub.info/",
    "ipqs": "https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{ip}",
    "ipdata": "https://ipdata.co/{ip}",
    "ipregistry": "https://ipregistry.co/{ip}",
    "dbip": "https://db-ip.com/{ip}",
    "scamalytics": "https://scamalytics.com/ip/{ip}",
    "ipapiis": "https://ipapi.is/?q={ip}",
    "ipquery": "https://api.ipquery.io/{ip}?format=json",
    "blackbox": "https://blackbox.ipinfo.app/api/v3beta/{ip}",
}


def lookup_sources(ip):
    return asyncio.run(_lookup(ip))


async def _lookup(ip):
    from playwright.async_api import async_playwright
    extractor = (Path(__file__).parent / "src" / "page-extract.js").read_text(encoding="utf-8").replace("export function", "function")
    evaluate = "({provider,ip}) => {" + extractor + "; return extractProviderPage(provider,ip); }"
    async with async_playwright() as api:
        options = {"headless": True}
        if not Path(api.chromium.executable_path).exists():
            options["channel"] = "chrome"
        browser = await api.chromium.launch(**options)
        context = await browser.new_context(locale="en-US", viewport={"width": 1440, "height": 1000})
        slots = asyncio.Semaphore(3)

        async def read(provider, url):
            async with slots:
                page = await context.new_page()
                observed = None
                try:
                    response = await page.goto(url.format(ip=ip), wait_until="domcontentloaded", timeout=16000)
                    if urlsplit(page.url).hostname != urlsplit(url).hostname:
                        raise ValueError("网页跳转到其他站点，未读取字段")
                    if not response or response.status >= 400:
                        raise ValueError("网页访问受限" if response and response.status in (401, 403) else "网页返回 HTTP " + str(response.status if response else "无响应"))
                    if provider == "iphub":
                        await page.get_by_role("textbox", name="IP address or domain name").fill(ip, timeout=4000)
                        await page.get_by_role("button", name="Lookup", exact=True).click(timeout=4000)
                        await page.wait_for_function("ip => document.querySelector('[data-copy-field=ip]')?.textContent.trim() === ip", arg=ip, timeout=12000)
                    elif provider == "ipapiis":
                        await page.get_by_role("searchbox", name="Search by IP address or ASN").fill(ip, timeout=4000)
                        await page.get_by_role("button", name="Run IP lookup", exact=True).click(timeout=4000)
                    # Give client-rendered JSON a bounded chance to replace placeholders.
                    end = time.monotonic() + 8
                    while True:
                        try:
                            observed = await page.evaluate(evaluate, {"provider": provider, "ip": ip})
                            break
                        except Exception as exc:
                            if time.monotonic() >= end:
                                message = str(exc).split("Error: ")[-1].split("\n")[0]
                                raise ValueError(message if message.startswith("网页") else "网页字段暂不可读取") from None
                            await asyncio.sleep(0.8)
                    return provider, {"status": "ok", "data": observed["data"], "site": url.format(ip=ip), "time": int(time.time()*1000)}
                except Exception as exc:
                    message = str(exc) if isinstance(exc, ValueError) else "网页加载或查询超时"
                    return provider, {"status": "error", "error": message[:100], "site": url.format(ip=ip), "time": int(time.time()*1000)}
                finally:
                    await page.close()
        try:
            results = await asyncio.gather(*(read(name, url) for name, url in SITES.items()))
            return {"ip": ip, "time": int(time.time()*1000), "sources": dict(results)}
        finally:
            await context.close()
            await browser.close()
