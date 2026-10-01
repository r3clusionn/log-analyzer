"""Writes a synthetic nginx-style access log for benchmarking.

    python scripts/gen_log.py out.log 10000000

Deterministic (seeded). Traffic is steady with a daily curve, a few bursts, a slow route, an
error route and an occasional out-of-order line, so every code path in logscan gets exercised.
"""
import random
import sys

def main():
    out, n = sys.argv[1], int(sys.argv[2])
    rnd = random.Random(7)
    routes = [("GET", "/api/items/%d", 0.030), ("GET", "/api/users/%d/profile", 0.045),
              ("POST", "/api/orders", 0.120), ("GET", "/static/app.js", 0.004),
              ("GET", "/healthz", 0.001), ("GET", "/search", 0.200)]
    agents = ['"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"', '"curl/8.4.0"', '"Go-http-client/2.0"']
    months = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()
    t = 1_696_946_136  # 2023-10-10 13:55:36 UTC
    rows = []
    with open(out, "w", newline="\n") as f:
        for i in range(n):
            # About 1000 requests per simulated second on average, with bursts.
            if i % 1000 == 0:
                t += 1
            burst = (i // 2_000_000) % 3 == 1 and (i % 5000) < 50
            method, path, base = rnd.choice(routes)
            if "%d" in path:
                path = path % rnd.randint(1, 50000)
            status = 200
            r = rnd.random()
            if r < 0.02:
                status = 404
            elif r < 0.025 or (path == "/search" and r < 0.03):
                status = 500
            elif r < 0.05:
                status = 304
            lat = base * rnd.lognormvariate(0, 0.6) * (30 if burst else 1)
            ts = t - (7 if i % 50_000 == 49_999 else 0)
            tm = __import__("time").gmtime(ts)
            stamp = "%02d/%s/%d:%02d:%02d:%02d +0000" % (tm.tm_mday, months[tm.tm_mon - 1], tm.tm_year, tm.tm_hour, tm.tm_min, tm.tm_sec)
            f.write('203.0.113.%d - - [%s] "%s %s HTTP/1.1" %d %d "-" %s %.3f\n' % (
                rnd.randint(1, 254), stamp, method, path, status, rnd.randint(200, 90000), rnd.choice(agents), lat))

main()
