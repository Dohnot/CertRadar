#!/usr/bin/env python3
"""CertRadar MVP: local read-only certificate inventory and explicit TLS checks.
No third-party Python dependencies. Python 3.10+.
"""
import argparse
import datetime as dt
import ipaddress
import json
import concurrent.futures
import os
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get('CERTRADAR_DATA_DIR', ROOT / 'data'))
DATA_DIR.mkdir(parents=True, exist_ok=True)
INVENTORY = DATA_DIR / 'inventory.json'
CACHE = DATA_DIR / 'ct_cache.json'
LOCK = threading.Lock()
DOMAIN_RE = re.compile(r'^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$', re.I)
HOST_RE = DOMAIN_RE
DEMO = [
    {'id': 'demo-1', 'common_name': 'portal.example.org', 'names': ['portal.example.org'], 'issuer': 'Example CA', 'not_before': '2026-07-01T00:00:00', 'not_after': '2026-11-09T00:00:00', 'source': 'Demo'},
    {'id': 'demo-2', 'common_name': 'api.example.org', 'names': ['api.example.org'], 'issuer': 'Example CA', 'not_before': '2026-08-01T00:00:00', 'not_after': '2027-01-05T00:00:00', 'source': 'Demo'},
    {'id': 'demo-3', 'common_name': '*.example.org', 'names': ['*.example.org'], 'issuer': 'Another Example CA', 'not_before': '2026-01-01T00:00:00', 'not_after': '2026-10-12T00:00:00', 'source': 'Demo'},
]

def read_json(path, default):
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return default

def save_json(path, data):
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
    temp.replace(path)

def normalize_ct(row):
    names = sorted({s.strip().lower() for s in str(row.get('name_value') or '').splitlines() if s.strip()})
    return {'id': str(row.get('id') or ''), 'common_name': str(row.get('common_name') or ''), 'names': names, 'issuer': str(row.get('issuer_name') or ''), 'not_before': str(row.get('not_before') or ''), 'not_after': str(row.get('not_after') or ''), 'source': 'crt.sh'}

def normalize_domain(value):
    """Accept bare hosts and web URLs; reject ports, credentials and path-only inputs."""
    value = value.strip().lower()
    if not value:
        raise ValueError('Bitte Domain oder URL eingeben.')
    if '://' not in value:
        value = 'https://' + value
    url = urllib.parse.urlsplit(value)
    if url.scheme not in ('http', 'https') or url.username or url.password:
        raise ValueError('Nur HTTP(S)-URLs ohne Zugangsdaten verwenden.')
    try:
        if url.port is not None and not 1 <= url.port <= 65535:
            raise ValueError('Ungültiger Port.')
    except ValueError:
        raise ValueError('Ungültiger Port in der URL.')
    host = (url.hostname or '').rstrip('.')
    if not DOMAIN_RE.fullmatch(host):
        raise ValueError('Bitte eine gültige Domain eingeben (z. B. theater-in-essen.de).')
    return host


def fetch_ct_query(query):
    url = 'https://crt.sh/?' + urllib.parse.urlencode({'q': query, 'output': 'json'})
    req = urllib.request.Request(url, headers={'User-Agent': 'CertRadar-MVP/0.2 (educational, low frequency)', 'Accept': 'application/json'})
    with urllib.request.urlopen(req, timeout=25) as response:
        raw = response.read(12_000_001)
    if len(raw) > 12_000_000:
        raise ValueError('Antwort von crt.sh zu groß (über 12 MB).')
    if not raw.strip():
        return []
    rows = json.loads(raw)
    if not isinstance(rows, list):
        raise ValueError('Unerwartete Antwort von crt.sh')
    return rows


def search_ct(domain):
    key = domain.lower()
    with LOCK:
        cache = read_json(CACHE, {})
    cached = cache.get(key)
    if cached and cached.get('version') == 2 and time.time() - cached.get('saved', 0) < 3600:
        return cached['rows'], True
    # Query the apex and all subdomains separately: %.example.org does not
    # reliably return certificates covering example.org only.
    queries = [domain, '%.' + domain]
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(fetch_ct_query, q) for q in queries]
        results = []
        errors = []
        for query, future in zip(queries, futures):
            try:
                results.extend(future.result())
            except Exception as exc:
                errors.append(query + ': ' + str(exc))
    if errors:
        raise ValueError('crt.sh-Teilabfrage fehlgeschlagen: ' + '; '.join(errors))
    unique = {}
    for r in results:
        record = normalize_ct(r)
        if record['id']:
            unique[record['id']] = record
    result = sorted(unique.values(), key=lambda x: x['not_after'], reverse=True)[:5000]
    with LOCK:
        cache = read_json(CACHE, {})
        cache[key] = {'version': 2, 'saved': time.time(), 'rows': result}
        save_json(CACHE, cache)
    return result, False

def check_endpoint(host, port):
    # Explicit targets only. Public IPs by default; do not probe private or local networks.
    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    ip_strings = sorted({entry[4][0] for entry in addresses})
    if not ip_strings or any(not ipaddress.ip_address(ip).is_global for ip in ip_strings):
        raise ValueError('Ziel löst auf eine private/reservierte IP auf. Nur öffentliche Ziele sind im MVP zugelassen.')
    ctx = ssl.create_default_context()
    # TLS validation is deliberately enabled: expired / invalid certs are reported as errors.
    with socket.create_connection((ip_strings[0], port), timeout=6) as sock:
        sock.settimeout(6)
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
            cipher = tls.cipher()
            expiry = cert.get('notAfter')
            issuer = ', '.join('='.join(part) for rdn in cert.get('issuer', ()) for part in rdn)
            subject = ', '.join('='.join(part) for rdn in cert.get('subject', ()) for part in rdn)
            return {'host': host, 'port': port, 'valid': True, 'subject': subject, 'issuer': issuer, 'not_after': dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(expiry), dt.timezone.utc).isoformat() if expiry else None, 'tls_version': tls.version(), 'cipher': cipher[0] if cipher else None, 'checked_at': dt.datetime.now(dt.timezone.utc).isoformat()}

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print('%s - %s' % (self.address_string(), fmt % args))

    def send_json(self, payload, status=200):
        body = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path)
        if path.path == '/':
            content = (ROOT / 'index.html').read_bytes()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'")
            self.send_header('Content-Length', str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        elif path.path == '/app.js' or path.path == '/style.css':
            content = (ROOT / path.path[1:]).read_bytes()
            self.send_response(200)
            self.send_header('Content-Type', 'text/javascript; charset=utf-8' if path.path.endswith('.js') else 'text/css; charset=utf-8')
            self.send_header('Content-Length', str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        elif path.path == '/api/inventory':
            self.send_json(read_json(INVENTORY, []))
        elif path.path == '/api/demo':
            self.send_json({'domain': 'example.org', 'rows': DEMO, 'cached': False, 'demo': True})
        elif path.path == '/api/ct':
            raw_domain = urllib.parse.parse_qs(path.query).get('domain', [''])[0]
            try:
                domain = normalize_domain(raw_domain)
            except ValueError as exc:
                return self.send_json({'error': str(exc)}, 400)
            try:
                rows, cached = search_ct(domain)
                self.send_json({'domain': domain, 'rows': rows, 'cached': cached, 'demo': False, 'truncated': len(rows) == 5000})
            except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
                self.send_json({'error': 'crt.sh konnte nicht abgefragt werden: ' + str(exc)}, 502)
            except Exception:
                self.send_json({'error': 'Unerwarteter Fehler bei der crt.sh-Abfrage.'}, 502)
        else:
            self.send_json({'error': 'Nicht gefunden'}, 404)

    def do_POST(self):
        size = int(self.headers.get('Content-Length', '0'))
        if size < 1 or size > 50000:
            return self.send_json({'error': 'Ungültige Anfragegröße'}, 400)
        try:
            payload = json.loads(self.rfile.read(size))
        except ValueError:
            return self.send_json({'error': 'Ungültiges JSON'}, 400)
        if self.path == '/api/inventory':
            host = str(payload.get('host', '')).lower().strip()
            port = payload.get('port', 443)
            owner = str(payload.get('owner', '')).strip()[:100]
            if not HOST_RE.fullmatch(host) or type(port) is not int or not 1 <= port <= 65535:
                return self.send_json({'error': 'Gültigen Hostnamen und Port angeben.'}, 400)
            with LOCK:
                inventory = read_json(INVENTORY, [])
                if len(inventory) >= 500:
                    return self.send_json({'error': 'Maximal 500 Endpunkte im MVP.'}, 400)
                if any(e['host'] == host and e['port'] == port for e in inventory):
                    return self.send_json({'error': 'Endpunkt bereits vorhanden.'}, 409)
                item = {'host': host, 'port': port, 'owner': owner, 'added_at': dt.datetime.now(dt.timezone.utc).isoformat()}
                inventory.append(item)
                save_json(INVENTORY, inventory)
            return self.send_json(item, 201)
        elif self.path == '/api/check':
            host = str(payload.get('host', '')).lower().strip()
            port = payload.get('port', 443)
            if type(port) is not int or not HOST_RE.fullmatch(host) or not 1 <= port <= 65535:
                return self.send_json({'error': 'Ungültiger Host oder Port'}, 400)
            inventory = read_json(INVENTORY, [])
            if not any(item['host'] == host and item['port'] == port for item in inventory):
                return self.send_json({'error': 'Ziel ist nicht im Inventar registriert.'}, 403)
            try:
                return self.send_json(check_endpoint(host, port))
            except (OSError, ssl.SSLError, ValueError) as exc:
                return self.send_json({'host': host, 'port': port, 'valid': False, 'error': str(exc), 'checked_at': dt.datetime.now(dt.timezone.utc).isoformat()})
        elif self.path == '/api/delete':
            host = str(payload.get('host', '')).lower().strip()
            port = payload.get('port')
            with LOCK:
                inventory = read_json(INVENTORY, [])
                remainder = [x for x in inventory if not (x['host'] == host and x['port'] == port)]
                save_json(INVENTORY, remainder)
            return self.send_json({'deleted': len(inventory) - len(remainder)})
        self.send_json({'error': 'Nicht gefunden'}, 404)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='CertRadar local MVP')
    parser.add_argument('--port', type=int, default=8765)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error('Port muss zwischen 1 und 65535 liegen')
    server = ThreadingHTTPServer(('127.0.0.1', args.port), Handler)
    print(f'CertRadar läuft auf http://127.0.0.1:{args.port} (Strg+C zum Beenden)')
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()
