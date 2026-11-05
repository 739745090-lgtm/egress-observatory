"""Public, fixed-target lookup API used by the GitHub Pages frontend."""
import ipaddress
import os
import json
import urllib.request
import urllib.parse
import threading
import time
from collections import OrderedDict, deque

from flask import Flask, jsonify, request
from local_server import lookup

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 256
ORIGINS = {"https://blackslience-reaper.github.io", "http://127.0.0.1:4187", "http://localhost:4187"}
CACHE = OrderedDict()
CACHE_LOCK = threading.Lock()
BROWSER = threading.Lock()
CONTACT_API = threading.Lock()
CONTACT_CALLS = deque()


@app.after_request
def cors(response):
    origin = request.headers.get("Origin")
    if origin in ORIGINS:
        response.headers.update({"Access-Control-Allow-Origin": origin,
                                 "Access-Control-Allow-Methods": "POST, OPTIONS",
                                 "Access-Control-Allow-Headers": "Content-Type",
                                 "Access-Control-Expose-Headers": "Retry-After",
                                 "Access-Control-Max-Age": "600", "Vary": "Origin"})
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/health")
def health():
    return {"status": "ok", "providers": ["ipinfo", "ipsuper"]}


@app.route("/lookup/<provider>", methods=["POST", "OPTIONS"])
def report(provider):
    if provider not in {"ipinfo", "ipsuper", "getipintel"}:
        return {"error": "未知来源"}, 404
    if request.headers.get("Origin") not in ORIGINS:
        return {"error": "来源未获允许"}, 403
    if request.method == "OPTIONS":
        return "", 204
    payload = request.get_json(silent=True)
    try:
        value = payload["ip"]
        if not isinstance(value, str) or "%" in value: raise ValueError()
        addr = ipaddress.ip_address(value)
        if not addr.is_global or addr.is_multicast: raise ValueError()
    except (KeyError, ValueError, TypeError):
        return {"error": "需要有效的公网 IP"}, 400
    ip = str(addr)
    key = (provider, ip)
    # Cached reports must remain available while Chromium is busy with another IP.
    with CACHE_LOCK:
        cached = CACHE.get(key)
        if cached and cached[0] > time.monotonic():
            return jsonify(cached[1])
    gate = CONTACT_API if provider == 'getipintel' else BROWSER
    if not gate.acquire(timeout=35):
        return {"error": "查询服务繁忙，请稍后重试"}, 429, {"Retry-After": "5"}
    try:
        with CACHE_LOCK:
            cached = CACHE.get(key)
            if cached and cached[0] > time.monotonic():
                return jsonify(cached[1])
        if provider == 'getipintel':
            contact = os.environ.get('GETIPINTEL_CONTACT')
            if not contact: return {'error':'联系邮箱未配置'}, 503
            now = time.monotonic()
            while CONTACT_CALLS and CONTACT_CALLS[0] <= now-86400: CONTACT_CALLS.popleft()
            if len(CONTACT_CALLS) >= 500 or sum(t > now-60 for t in CONTACT_CALLS) >= 15:
                return {'error':'GetIPIntel 免费查询额度已用完'}, 429
            CONTACT_CALLS.append(now)
            params = urllib.parse.urlencode({'ip':ip,'contact':contact,'format':'json','flags':'m'})
            req = urllib.request.Request('https://check.getipintel.net/check.php?'+params,headers={'User-Agent':'Egress-Observatory/1.0 (+https://github.com/BlackSlience-Reaper/egress-observatory)'})
            with urllib.request.urlopen(req,timeout=12) as response:
                upstream = json.load(response)
            if upstream.get('status') != 'success' or ipaddress.ip_address(upstream.get('queryIP','')) != addr:
                return {'error':'GetIPIntel 上游拒绝查询：'+str(upstream.get('result','无结果'))[:10]}, 502
            prob = float(upstream['result'])
            if not 0 <= prob <= 1: raise ValueError()
            result = {'ip':ip,'probability':prob,'risk':round(prob*100)}
        else:
            result = lookup(ip, provider)
        if ipaddress.ip_address(result["ip"]) != addr: raise ValueError()
        with CACHE_LOCK:
            CACHE[key] = (time.monotonic() + 600, result)
            CACHE.move_to_end(key)
            if len(CACHE) > 256: CACHE.popitem(last=False)
        return jsonify(result)
    except Exception as exc:
        app.logger.warning("%s lookup failed: %s", provider, type(exc).__name__)
        return {"error": provider + " 网页查询失败"}, 502
    finally:
        gate.release()
