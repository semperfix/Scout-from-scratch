"""Nostr client over the hand-rolled WebSocket: publish + subscribe."""

import json
import time

from ws import client_connect, parse_ws_url
from event import verify_event


class NostrClient:
    def __init__(self, url: str, timeout: int = 15):
        host, port, path, use_tls = parse_ws_url(url)
        self.conn = client_connect(host, port, path, use_tls, timeout)
        self.url = url

    def publish(self, ev: dict, timeout: int = 10) -> tuple:
        """Returns (accepted: bool, message: str) from the relay's OK."""
        self.conn.send_text(json.dumps(["EVENT", ev]))
        deadline = time.time() + timeout
        while time.time() < deadline:
            msg = json.loads(self.conn.recv_text())
            if msg[0] == "OK" and msg[1] == ev["id"]:
                return bool(msg[2]), msg[3] if len(msg) > 3 else ""
            # tolerate NOTICE chatter while waiting
        raise TimeoutError("no OK from relay")

    def query(self, *filters, timeout: int = 15, verify=True) -> list:
        """REQ + collect until EOSE. Verifies every event by default."""
        sub_id = f"q{int(time.time()*1000)%100000}"
        self.conn.send_text(json.dumps(["REQ", sub_id, *filters]))
        out, deadline = [], time.time() + timeout
        while time.time() < deadline:
            msg = json.loads(self.conn.recv_text())
            if msg[0] == "EVENT" and msg[1] == sub_id:
                ev = msg[2]
                if verify:
                    ok, reason = verify_event(ev)
                    if not ok:
                        raise ValueError(f"relay sent bad event: {reason}")
                out.append(ev)
            elif msg[0] == "EOSE" and msg[1] == sub_id:
                break
            elif msg[0] == "NOTICE":
                pass
        else:
            raise TimeoutError("no EOSE from relay")
        self.conn.send_text(json.dumps(["CLOSE", sub_id]))
        return out

    def close(self):
        self.conn.close()
