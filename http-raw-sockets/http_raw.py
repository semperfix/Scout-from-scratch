#!/usr/bin/env python3
"""A complete HTTP/1.1 client on raw sockets -- stdlib only.

  * URL parsing (http/https, default ports, userinfo rejected)
  * request building, status-line + header parsing
  * body framing: Content-Length, chunked (extensions + trailers via a
    small state machine), close-delimited
  * redirects: 301/302/303/307/308 with relative-Location resolution,
    method rewriting per spec/browser convention
  * keep-alive connection reuse (HTTP/1.1 persistent by default)
  * forward proxy: absolute-URI for http, CONNECT tunnel + TLS for https
  * https via stdlib ssl (certificate verification on)

Response.headers maps lowercase name -> list of values; resp.header(name)
returns the first value. Trailers from chunked responses land in
resp.trailers (same shape).
"""
import socket
import ssl
from urllib.parse import urlsplit, urljoin

USER_AGENT = "scout-skills-http-raw/1.0"
REDIRECT_CODES = {301, 302, 303, 307, 308}


class HttpError(Exception):
    pass


# ---------------------------------------------------------------------------
# buffered socket reader
# ---------------------------------------------------------------------------

class _Reader:
    def __init__(self, sock):
        self.sock = sock
        self.buf = bytearray()

    def _fill(self, n=1):
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("connection closed mid-response")
            self.buf += chunk

    def readline(self, limit=65536):
        while True:
            i = self.buf.find(b"\n")
            if i >= 0:
                line = bytes(self.buf[:i + 1])
                del self.buf[:i + 1]
                return line
            if len(self.buf) > limit:
                raise HttpError("header line too long")
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("connection closed mid-headers")
            self.buf += chunk

    def read(self, n):
        self._fill(n)
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    def read_to_close(self):
        out = bytearray(self.buf)
        self.buf.clear()
        while True:
            chunk = self.sock.recv(65536)
            if not chunk:
                return bytes(out)
            out += chunk


# ---------------------------------------------------------------------------
# response
# ---------------------------------------------------------------------------

class Response:
    def __init__(self):
        self.url = ""
        self.status = 0
        self.reason = ""
        self.headers = {}      # lower name -> [values]
        self.trailers = {}     # lower name -> [values] (chunked only)
        self.body = b""
        self.redirects = []    # urls followed

    def header(self, name, default=None):
        vals = self.headers.get(name.lower())
        return vals[0] if vals else default


def _parse_headers(reader):
    headers = {}
    while True:
        line = reader.readline().rstrip(b"\r\n")
        if not line:
            return headers
        if line[:1] in b" \t":
            # continuation line (obs-fold): append to previous value
            if not headers:
                raise HttpError("continuation with no header")
            last = list(headers)[-1]
            headers[last][-1] += " " + line.strip().decode("latin-1")
            continue
        name, _, value = line.partition(b":")
        if not _:
            raise HttpError(f"malformed header line: {line!r}")
        key = name.strip().decode("latin-1").lower()
        headers.setdefault(key, []).append(value.strip().decode("latin-1"))


def _read_chunked(reader):
    """Chunked transfer decoder: extensions ignored, trailers collected."""
    body = bytearray()
    trailers = {}
    while True:
        line = reader.readline().decode("latin-1").strip()
        size_str = line.split(";", 1)[0].strip()   # drop chunk extensions
        try:
            size = int(size_str, 16)
        except ValueError:
            raise HttpError(f"bad chunk size: {line!r}")
        if size == 0:
            trailers = _parse_headers(reader)       # trailers, then done
            break
        body += reader.read(size)
        crlf = reader.read(2)
        if crlf != b"\r\n":
            raise HttpError("chunk not followed by CRLF")
    return bytes(body), trailers


def _read_response(reader, method):
    resp = Response()
    status_line = reader.readline().decode("latin-1").rstrip("\r\n")
    try:
        version, status, reason = status_line.split(" ", 2)
    except ValueError:
        version, status, reason = status_line.split(" ", 1) + [""]
    if not version.startswith("HTTP/"):
        raise HttpError(f"bad status line: {status_line!r}")
    resp.status, resp.reason = int(status), reason
    resp.headers = _parse_headers(reader)

    no_body = (method == "HEAD" or resp.status in (204, 304)
               or 100 <= resp.status < 200)
    if no_body:
        return resp
    te = resp.header("transfer-encoding", "")
    if "chunked" in te.lower():
        resp.body, resp.trailers = _read_chunked(reader)
    elif resp.header("content-length") is not None:
        try:
            n = int(resp.header("content-length"))
        except ValueError:
            raise HttpError("bad Content-Length")
        resp.body = reader.read(n)
    else:
        resp.body = reader.read_to_close()          # close-delimited
    return resp


# ---------------------------------------------------------------------------
# client / session
# ---------------------------------------------------------------------------

def _parse_url(url):
    p = urlsplit(url)
    if p.scheme not in ("http", "https"):
        raise HttpError(f"unsupported scheme: {p.scheme!r}")
    if p.username or p.password:
        raise HttpError("userinfo in URL is not supported")
    if not p.hostname:
        raise HttpError("URL has no host")
    port = p.port or (443 if p.scheme == "https" else 80)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    return p.scheme, p.hostname, port, path


class Session:
    """Keep-alive HTTP/1.1 session with redirect + proxy support."""

    def __init__(self, proxy=None, timeout=10, max_redirects=5,
                 user_agent=USER_AGENT):
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.user_agent = user_agent
        self.proxy = _parse_url(proxy) if proxy else None
        if self.proxy and self.proxy[0] not in ("http",):
            raise HttpError("only http:// proxies are supported")
        self._conns = {}   # (scheme, host, port) -> (sock, reader)
        self._ctx = None

    # -- connection management ------------------------------------------
    def _tls_context(self):
        if self._ctx is None:
            self._ctx = ssl.create_default_context()
        return self._ctx

    def _connect(self, scheme, host, port):
        if self.proxy and scheme == "http":
            return socket.create_connection((self.proxy[1], self.proxy[2]),
                                            timeout=self.timeout), False
        sock = socket.create_connection((host, port), timeout=self.timeout)
        if self.proxy and scheme == "https":
            self._tunnel(sock, host, port)
        if scheme == "https":
            sock = self._tls_context().wrap_socket(sock, server_hostname=host)
        return sock, scheme == "https"

    def _tunnel(self, sock, host, port):
        req = (f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
               f"User-Agent: {self.user_agent}\r\n\r\n").encode()
        sock.sendall(req)
        r = _Reader(sock)
        line = r.readline().decode("latin-1").rstrip("\r\n")
        parts = line.split(" ", 2)
        if len(parts) < 2 or parts[1] != "200":
            raise HttpError(f"proxy CONNECT failed: {line}")
        _parse_headers(r)  # consume rest of CONNECT response

    def _get_conn(self, scheme, host, port):
        key = (scheme, host, port,
               (self.proxy[1], self.proxy[2]) if self.proxy else None)
        if key in self._conns:
            return self._conns[key]
        sock, _tls = self._connect(scheme, host, port)
        conn = (sock, _Reader(sock))
        self._conns[key] = conn
        return conn

    def _drop_conn(self, scheme, host, port):
        key = (scheme, host, port,
               (self.proxy[1], self.proxy[2]) if self.proxy else None)
        conn = self._conns.pop(key, None)
        if conn:
            try:
                conn[0].close()
            except OSError:
                pass

    def close(self):
        for (sock, _) in self._conns.values():
            try:
                sock.close()
            except OSError:
                pass
        self._conns.clear()

    # -- requests --------------------------------------------------------
    def request(self, method, url, headers=None, body=b""):
        scheme, host, port, path = _parse_url(url)
        headers = {k.lower(): v for k, v in (headers or {}).items()}
        redirects = []
        current_url = url
        cur_method, cur_body = method.upper(), body

        for _ in range(self.max_redirects + 1):
            scheme, host, port, path = _parse_url(current_url)
            # request target: absolute URI through a forward proxy (plain http)
            if self.proxy and scheme == "http":
                target = (f"{scheme}://{host}:{port}{path}" if port != 80
                          else f"{scheme}://{host}{path}")
            else:
                target = path
            host_hdr = host if port in (80, 443) else f"{host}:{port}"

            lines = [f"{cur_method} {target} HTTP/1.1",
                     f"Host: {host_hdr}",
                     f"User-Agent: {self.user_agent}",
                     "Connection: keep-alive",
                     "Accept-Encoding: identity"]
            for k, v in headers.items():
                if k not in ("host", "connection", "content-length"):
                    lines.append(f"{k}: {v}")
            if cur_body:
                lines.append(f"Content-Length: {len(cur_body)}")
            raw = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + cur_body

            sock, reader = self._get_conn(scheme, host, port)
            try:
                sock.sendall(raw)
                resp = _read_response(reader, cur_method)
            except (ConnectionError, OSError):
                self._drop_conn(scheme, host, port)   # stale pooled conn: retry once
                sock, reader = self._get_conn(scheme, host, port)
                sock.sendall(raw)
                resp = _read_response(reader, cur_method)
            resp.url = current_url
            resp.redirects = list(redirects)

            conn_hdr = (resp.header("connection") or "").lower()
            if conn_hdr == "close" or resp.headers.get("proxy-connection") == ["close"]:
                self._drop_conn(scheme, host, port)

            if resp.status in REDIRECT_CODES and resp.header("location"):
                redirects.append(current_url)
                nxt = urljoin(current_url, resp.header("location"))
                # method rewriting
                if resp.status == 303 and cur_method != "HEAD":
                    cur_method, cur_body = "GET", b""
                elif resp.status in (301, 302) and cur_method == "POST":
                    cur_method, cur_body = "GET", b""
                # 307/308: keep method+body
                current_url = nxt
                continue
            return resp
        raise HttpError(f"too many redirects (>{self.max_redirects})")

    def get(self, url, headers=None):
        return self.request("GET", url, headers)

    def head(self, url, headers=None):
        return self.request("HEAD", url, headers)

    def post(self, url, body=b"", headers=None):
        return self.request("POST", url, headers, body)


def fetch(url, **kwargs):
    """One-shot GET with a throwaway session."""
    s = Session(**kwargs)
    try:
        return s.request("GET", url)
    finally:
        s.close()
