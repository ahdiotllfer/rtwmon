import argparse
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time
import signal
from typing import Optional, Sequence
 
 
def _read_usb_fd() -> int:
    v = os.environ.get("TERMUX_USB_FD") or os.environ.get("RTWMON_TERMUX_USB_FD")
    if v is None:
        raise RuntimeError("missing TERMUX_USB_FD")
    s = str(v).strip()
    if not s.isdigit():
        raise RuntimeError("invalid TERMUX_USB_FD")
    return int(s, 10)
 
 
def _libusb_error_name(lib: object, code: int) -> str:
    try:
        f = getattr(lib, "libusb_error_name", None)
        if f is None:
            return str(int(code))
        import ctypes

        f.argtypes = [ctypes.c_int]
        f.restype = ctypes.c_char_p
        s = f(int(code))
        if isinstance(s, (bytes, bytearray)):
            return s.decode("utf-8", errors="replace")
        if s is None:
            return str(int(code))
        return str(s)
    except Exception:
        return str(int(code))


def _validate_usb_fd(usb_fd: int) -> Optional[str]:
    try:
        import ctypes
        import usb.backend.libusb1 as libusb1
    except Exception:
        return None

    def _find_libusb1(name):
        p = os.environ.get("LIBUSB_PATH")
        if p:
            return str(p)
        termux = "/data/data/com.termux/files/usr/lib/libusb-1.0.so"
        if os.path.isfile(termux):
            return termux
        if name:
            return name
        return None

    backend = libusb1.get_backend(find_library=_find_libusb1)
    if backend is None:
        return "libusb backend not available"
    lib = backend.lib

    wrap = getattr(lib, "libusb_wrap_sys_device", None)
    if wrap is None:
        return "libusb_wrap_sys_device not available"
    wrap.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    wrap.restype = ctypes.c_int

    handle = ctypes.c_void_p()
    r = int(wrap(backend.ctx, ctypes.c_void_p(int(usb_fd)), ctypes.byref(handle)))
    if r != 0 or not handle:
        return f"libusb_wrap_sys_device failed: {_libusb_error_name(lib, r)}"
    return None

 
def _send_frame(conn: socket.socket, *, kind: bytes, payload: bytes) -> None:
    conn.sendall(kind + struct.pack("!I", int(len(payload))) + payload)


def _send_json(conn: socket.socket, obj: dict) -> None:
    _send_frame(conn, kind=b"J", payload=(json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8"))


def _read_json_line(conn: socket.socket) -> dict:
    buf = b""
    while b"\n" not in buf:
        chunk = conn.recv(65536)
        if not chunk:
            return {}
        buf += chunk
        if len(buf) > 1024 * 1024:
            return {}
    line = buf.split(b"\n", 1)[0]
    try:
        v = json.loads(line.decode("utf-8", errors="replace"))
    except Exception:
        return {}
    return v if isinstance(v, dict) else {}


def _replace_usb_fd(argv: Sequence[str], usb_fd: int) -> list[str]:
    fd_s = str(int(usb_fd))
    out: list[str] = []
    for x in argv:
        out.append(fd_s if x == "{USB_FD}" else str(x))
    return out


def _stream_pipe(pipe, conn: socket.socket, kind: bytes, send_lock: threading.Lock) -> None:
    try:
        while True:
            chunk = pipe.read(4096)
            if not chunk:
                return
            if not isinstance(chunk, (bytes, bytearray)):
                chunk = str(chunk).encode("utf-8", errors="replace")
            with send_lock:
                _send_frame(conn, kind=kind, payload=bytes(chunk))
    except Exception:
        return
 
 
def _handle(conn: socket.socket, *, usb_fd: int) -> bool:
    req = _read_json_line(conn)
    method = str(req.get("method", "") or "")
    if method == "ping":
        _send_json(conn, {"ok": True, "result": {"pong": True}})
        return True
    if method == "close":
        _send_json(conn, {"ok": True, "result": {"closing": True}})
        return False
    if method != "run":
        _send_json(conn, {"ok": False, "error": "unknown method"})
        return True

    err = _validate_usb_fd(int(usb_fd))
    if err:
        _send_json(conn, {"ok": False, "error": err})
        return False

    cmd = req.get("cmd", None)
    if not isinstance(cmd, list) or not cmd or not all(isinstance(x, str) for x in cmd):
        _send_json(conn, {"ok": False, "error": "invalid cmd"})
        return True

    argv = _replace_usb_fd(cmd, int(usb_fd))
    env = dict(os.environ)
    env["RTWMON_TERMUX_USB_FD"] = str(int(usb_fd))
    try:
        os.set_inheritable(int(usb_fd), True)
    except Exception:
        pass

    send_lock = threading.Lock()
    stop_event = threading.Event()
    try:
        p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, pass_fds=(int(usb_fd),))
    except Exception as e:
        _send_json(conn, {"ok": False, "error": str(e)})
        return True

    _send_json(conn, {"ok": True, "result": {"pid": int(getattr(p, "pid", -1) or -1)}})

    def _stream(pipe, kind: bytes) -> None:
        try:
            while True:
                if stop_event.is_set():
                    return
                chunk = pipe.read(4096)
                if not chunk:
                    return
                if not isinstance(chunk, (bytes, bytearray)):
                    chunk = str(chunk).encode("utf-8", errors="replace")
                with send_lock:
                    _send_frame(conn, kind=kind, payload=bytes(chunk))
        except Exception:
            stop_event.set()
            return

    t_out = threading.Thread(target=_stream, args=(p.stdout, b"O"), daemon=True)
    t_err = threading.Thread(target=_stream, args=(p.stderr, b"E"), daemon=True)
    t_out.start()
    t_err.start()
    rc: Optional[int] = None
    while True:
        polled = p.poll()
        if polled is not None:
            rc = int(polled)
            break
        if stop_event.is_set():
            try:
                p.send_signal(signal.SIGINT)
            except Exception:
                pass
            t_deadline = time.monotonic() + 0.8
            while time.monotonic() < t_deadline:
                polled2 = p.poll()
                if polled2 is not None:
                    rc = int(polled2)
                    break
                time.sleep(0.05)
            if rc is None:
                try:
                    p.terminate()
                except Exception:
                    pass
                t_deadline2 = time.monotonic() + 0.8
                while time.monotonic() < t_deadline2:
                    polled3 = p.poll()
                    if polled3 is not None:
                        rc = int(polled3)
                        break
                    time.sleep(0.05)
            if rc is None:
                try:
                    p.kill()
                except Exception:
                    pass
                rc = int(p.wait())
            break
        time.sleep(0.05)
    try:
        if p.stdout:
            p.stdout.close()
    except Exception:
        pass
    try:
        if p.stderr:
            p.stderr.close()
    except Exception:
        pass
    t_out.join(timeout=1.0)
    t_err.join(timeout=1.0)
    with send_lock:
        try:
            _send_frame(conn, kind=b"X", payload=struct.pack("!i", int(rc if rc is not None else 1)))
        except Exception:
            pass
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
