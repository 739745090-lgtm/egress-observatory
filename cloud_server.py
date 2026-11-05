"""Public, fixed-target lookup API used by the GitHub Pages frontend."""
import ipaddress
import threading
import time
from collections import OrderedDict

from flask import Flask, jsonify, request
from local_server import lookup

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 256
ORIGIN = "https://blackslience-reaper.github.io"
CACHE = OrderedDict()
BROWSER = threading.Lock()


@app.after_request
def cors(response):
    if request.headers.get("Origin") == ORIGIN:
        response.headers.update({"Access-Control-Allow-Origin": ORIGIN,
                                 "Access-Control-Allow-Methods": "POST, OPTIONS",
                                 "Access-Control-Allow-Headers": "Content-Type", "Vary": "Origin"})
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/health")
def health():
    return {"status": "ok", "providers": ["ipinfo", "ipsuper"]}


@app.route("/lookup/<provider>", methods=["POST", "OPTIONS"])
def report(provider):
    if provider not in {"ipinfo", "ipsuper"}:
        return {"error": "未知来源"}, 404
    if request.headers.get("Origin") != ORIGIN:
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
    if not BROWSER.acquire(timeout=50):
        return {"error": "查询服务繁忙，请稍后重试"}, 429
    try:
        cached = CACHE.get(key)
        if cached and cached[0] > time.monotonic():
            return jsonify(cached[1])
        result = lookup(ip, provider)
        if ipaddress.ip_address(result["ip"]) != addr: raise ValueError()
        CACHE[key] = (time.monotonic() + 600, result)
        CACHE.move_to_end(key)
        if len(CACHE) > 256: CACHE.popitem(last=False)
        return jsonify(result)
    except Exception as exc:
        app.logger.warning("%s lookup failed: %s", provider, type(exc).__name__)
        return {"error": provider + " 网页查询失败"}, 502
    finally:
        BROWSER.release()
