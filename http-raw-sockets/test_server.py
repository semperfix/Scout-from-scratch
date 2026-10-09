#!/usr/bin/env python3
"""Raw-socket HTTP/1.1 test server for the http-raw-sockets skill.

Serves tricky-but-legal responses no canned framework will give you:
  /redirect  -> 302 with a *relative* Location: /chunked
  /chunked   -> Transfer-Encoding: chunked, chunk extensions, trailers
  /length    -> plain Content-Length body
  /close     -> close-delimited body (Connection: close, no length headers)
  /echo      -> 200 with the request line + headers echoed in the body
  /redir307  -> 307 to /echo-method (tests method preservation)

Keeps connections alive across requests (counts them) so keep-alive reuse
can be verified. Stdlib only. Run: python3 test_server.py [port]
"""
import socket
import threading

CHUNKED_BODY = b"Hello, " + b"chunked " * 3 + b"world!"
EXPECTED = {
    "/length": b"L" * 100,
    "/chunked": CHUNKED_BODY,
    "/close": b"close-delimited body, no length header",
}

connections = 0
requests_served = 0
_lock = threading.Lock()


def _read_request(rfile):
    line = rfile.readline().decode("latin-1")
    if not line:
        return None, None, {}, b""
    method, target, _ver = line.rstrip("\r\n").split(" ", 2)
    headers = {}
    while True:
        h = rfile.readline().decode("latin-1")
        if h in ("\r\n", "\n", ""):
            break
        k, _, v = h.partition(":")
        headers[k.strip().lower()] = v.strip()
    # absolute-URI form (proxied requests): reduce to origin-form path
    if "://" in target:
        target = "/" + target.split("://", 1)[1].split("/", 1)[1] \
            if "/" in target.split("://", 1)[1] else "/"
    n = int(headers.get("content-length", 0))
    body = rfile.read(n) if n else b""
    return method, target, headers, body


def _respond(wfile, status, headers, body=b""):
    wfile.write(f"HTTP/1.1 {status}\r\n".encode())
    for k, v in headers.items():
        wfile.write(f"{k}: {v}\r\n".encode())
    wfile.write(b"\r\n")
    wfile.write(body)
    wfile.flush()


def _handle(conn):
    global connections, requests_served
    with _lock:
        connections += 1
    rfile = conn.makefile("rb")
    wfile = conn.makefile("wb")
    try:
        while True:
            req = _read_request(rfile)
            if req[0] is None:
                break
            method, target, headers, body = req
            with _lock:
                requests_served += 1
            path = target.split("?", 1)[0]
            keep = headers.get("connection", "").lower() != "close"

            if path == "/redirect":
                _respond(wfile, "302 Found",
                         {"Location": "/chunked", "Content-Length": "0",
                          "Connection": "keep-alive" if keep else "close"})
            elif path == "/redir307":
                _respond(wfile, "307 Temporary Redirect",
                         {"Location": "/echo-method", "Content-Length": "0",
                          "Connection": "keep-alive" if keep else "close"})
            elif path == "/chunked":
                wfile.write(b"HTTP/1.1 200 OK\r\n")
                wfile.write(b"Transfer-Encoding: chunked\r\n")
                wfile.write(b"Connection: keep-alive\r\n\r\n")
                # chunks WITH extensions, then trailers
                wfile.write(b"7;ext=one\r\nHello, \r\n")
                wfile.write(b"18;foo=bar;baz\r\n" + b"chunked " * 3 + b"\r\n")
                wfile.write(b"6\r\nworld!\r\n")
                wfile.write(b"0\r\n")
                wfile.write(b"X-Checksum: deadbeef\r\n")
                wfile.write(b"X-Chunks: 3\r\n\r\n")
                wfile.flush()
            elif path == "/length":
                _respond(wfile, "200 OK",
                         {"Content-Length": str(len(EXPECTED["/length"])),
                          "Connection": "keep-alive" if keep else "close"},
                         EXPECTED["/length"])
            elif path == "/close":
                wfile.write(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
                wfile.write(EXPECTED["/close"])
                wfile.flush()
                break  # server closes
            elif path == "/echo":
                echo = (f"{method} {target}\n"
                        + "".join(f"{k}: {v}\n" for k, v in headers.items())
                        ).encode()
                _respond(wfile, "200 OK",
                         {"Content-Length": str(len(echo)),
                          "Connection": "keep-alive" if keep else "close"},
                         echo)
            elif path == "/echo-method":
                _respond(wfile, "200 OK",
                         {"Content-Length": str(len(method) + len(body) + 1),
                          "Connection": "keep-alive" if keep else "close"},
                         method.encode() + b" " + body)
            else:
                _respond(wfile, "404 Not Found",
                         {"Content-Length": "9",
                          "Connection": "keep-alive" if keep else "close"},
                         b"not found")
            if not keep:
                break
    except (ConnectionError, BrokenPipeError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def serve(port, stop_event):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)
    srv.settimeout(0.3)
    while not stop_event.is_set():
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        threading.Thread(target=_handle, args=(conn,), daemon=True).start()
    srv.close()


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18333
    stop = threading.Event()
    print(f"test server on 127.0.0.1:{port} (Ctrl-C to stop)")
    try:
        serve(port, stop)
    except KeyboardInterrupt:
        pass
