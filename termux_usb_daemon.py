import argparse
import json
import os
import socket
import struct
import sys
from typing import Optional
 
 
def _read_usb_fd() -> int:
    v = os.environ.get("TERMUX_USB_FD") or os.environ.get("RTWMON_TERMUX_USB_FD")
    if v is None:
        raise RuntimeError("missing TERMUX_USB_FD")
    s = str(v).strip()
    if not s.isdigit():
        raise RuntimeError("invalid TERMUX_USB_FD")
    return int(s, 10)
 
 
def _send_json_with_fd(conn: socket.socket, obj: dict, fd: int) -> None:
    data = (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")
    anc = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("i", int(fd)))]
    conn.sendmsg([data], anc)
 
 
def _send_json(conn: socket.socket, obj: dict) -> None:
    data = (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")
    conn.sendall(data)
 
 
def _handle(conn: socket.socket, *, usb_fd: int) -> bool:
    buf = b""
    while b"\n" not in buf:
        chunk = conn.recv(65536)
        if not chunk:
            return True
        buf += chunk
        if len(buf) > 1024 * 1024:
            _send_json(conn, {"ok": False, "error": "request too large"})
            return True
    line = buf.split(b"\n", 1)[0]
    try:
        req = json.loads(line.decode("utf-8", errors="replace"))
    except Exception:
        _send_json(conn, {"ok": False, "error": "bad json"})
        return True
    if not isinstance(req, dict):
        _send_json(conn, {"ok": False, "error": "bad request"})
        return True
    method = str(req.get("method", "") or "")
    if method == "ping":
        _send_json(conn, {"ok": True, "result": {"pong": True}})
        return True
    if method == "get_fd":
        _send_json_with_fd(conn, {"ok": True, "result": {"fd": True}}, int(usb_fd))
        return True
    if method == "close":
        _send_json(conn, {"ok": True, "result": {"closing": True}})
        return False
    _send_json(conn, {"ok": False, "error": "unknown method"})
    return True
 
 
def _serve(*, sock_path: str, usb_fd: int) -> int:
    try:
        os.umask(0o077)
    except Exception:
        pass
    try:
        if sock_path and os.path.exists(sock_path):
            os.unlink(sock_path)
    except Exception:
        pass
 
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock_path)
    try:
        os.chmod(sock_path, 0o600)
    except Exception:
        pass
    srv.listen(8)
    while True:
        conn, _addr = srv.accept()
        try:
            cont = _handle(conn, usb_fd=int(usb_fd))
        finally:
            try:
                conn.close()
            except Exception:
                pass
        if not cont:
            break
    try:
        srv.close()
    except Exception:
        pass
    try:
        if sock_path and os.path.exists(sock_path):
            os.unlink(sock_path)
    except Exception:
        pass
    return 0
 
 
def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="termux_usb_daemon")
    ap.add_argument("--sock", default="")
    args = ap.parse_args(argv)
 
    sock_path = str(getattr(args, "sock", "") or "").strip()
    if not sock_path:
        sock_path = "/data/data/com.termux/files/usr/tmp/rtwmon-usb.sock"
    usb_fd = _read_usb_fd()
    return _serve(sock_path=sock_path, usb_fd=int(usb_fd))
 
 
if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
