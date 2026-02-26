import argparse
import base64
import json
import os
import re
import socket
import socketserver
import sys
from dataclasses import dataclass
from typing import Any, Optional


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=False)


def _read_int_env(name: str) -> Optional[int]:
    v = os.environ.get(name)
    if v is None:
        return None
    s = str(v).strip()
    if not s or re.fullmatch(r"[0-9]+", s) is None:
        return None
    return int(s, 10)


def _libusb_error_name(lib: Any, code: int) -> str:
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


def _open_device_from_usb_fd(usb_fd: int):
    import ctypes
    import usb.backend.libusb1 as libusb1
    import usb.core

    backend = libusb1.get_backend()
    lib = backend.lib

    wrap = getattr(lib, "libusb_wrap_sys_device", None)
    if wrap is None:
        raise RuntimeError("libusb_wrap_sys_device not available (need libusb >= 1.0.23)")
    wrap.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    wrap.restype = ctypes.c_int

    handle = ctypes.c_void_p()
    r = int(wrap(backend.ctx, ctypes.c_void_p(int(usb_fd)), ctypes.byref(handle)))
    if r != 0:
        raise RuntimeError(f"libusb_wrap_sys_device failed: {_libusb_error_name(lib, r)}")
    if not handle:
        raise RuntimeError("libusb_wrap_sys_device returned NULL handle")

    get_dev = getattr(lib, "libusb_get_device", None)
    if get_dev is None:
        raise RuntimeError("libusb_get_device not available")
    get_dev.argtypes = [ctypes.c_void_p]
    get_dev.restype = ctypes.c_void_p
    dev_ptr = ctypes.c_void_p(get_dev(handle))
    if not dev_ptr:
        raise RuntimeError("libusb_get_device returned NULL device")

    dev_id = libusb1._Device(dev_ptr)
    dev = usb.core.Device(dev_id, backend)

    class _WrappedHandle:
        def __init__(self, *, handle, devid):
            self.handle = handle
            self.devid = devid

    dev._ctx.handle = _WrappedHandle(handle=handle, devid=dev_id.devid)
    return dev


@dataclass
class UsbProxyState:
    dev: Any
    token: str


def _json_obj(line: bytes) -> dict[str, Any]:
    s = line.decode("utf-8", errors="replace").strip()
    if not s:
        return {}
    v = json.loads(s)
    if not isinstance(v, dict):
        raise ValueError("request must be a JSON object")
    return v


def _json_line(obj: dict[str, Any]) -> bytes:
    return (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")


class _Handler(socketserver.StreamRequestHandler):
    state: UsbProxyState

    def handle(self) -> None:
        while True:
            line = self.rfile.readline()
            if not line:
                return
            try:
                req = _json_obj(line)
                rid = req.get("id", None)
                token = str(req.get("token", "") or "")
                if self.state.token and token != self.state.token:
                    self.wfile.write(_json_line({"id": rid, "ok": False, "error": "bad token"}))
                    self.wfile.flush()
                    continue

                method = str(req.get("method", "") or "")
                params = req.get("params", {})
                if not isinstance(params, dict):
                    raise ValueError("params must be an object")

                result = self._dispatch(method, params)
                self.wfile.write(_json_line({"id": rid, "ok": True, "result": result}))
                self.wfile.flush()
            except Exception as e:
                try:
                    rid = None
                    try:
                        rid = req.get("id", None) if isinstance(req, dict) else None
                    except Exception:
                        rid = None
                    self.wfile.write(_json_line({"id": rid, "ok": False, "error": str(e)}))
                    self.wfile.flush()
                except Exception:
                    return

    def _dispatch(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        dev = self.state.dev
        import usb.util

        if method == "ping":
            return {"pong": True}

        if method == "device_info":
            return {
                "idVendor": int(getattr(dev, "idVendor", 0) or 0),
                "idProduct": int(getattr(dev, "idProduct", 0) or 0),
                "bus": int(getattr(dev, "bus", -1) or -1),
                "address": int(getattr(dev, "address", -1) or -1),
            }

        if method == "set_configuration":
            cfg = int(params.get("configuration", 1))
            dev.set_configuration(cfg)
            return {"configuration": cfg}

        if method == "get_active_configuration":
            cfg = dev.get_active_configuration()
            return {"bConfigurationValue": int(getattr(cfg, "bConfigurationValue", 0) or 0)}

        if method == "claim_interface":
            interface = int(params["interface"])
            usb.util.claim_interface(dev, interface)
            return {"interface": interface}

        if method == "release_interface":
            interface = int(params["interface"])
            usb.util.release_interface(dev, interface)
            return {"interface": interface}

        if method == "set_interface_altsetting":
            interface = int(params["interface"])
            alt = int(params.get("alternate_setting", 0))
            dev.set_interface_altsetting(interface=interface, alternate_setting=alt)
            return {"interface": interface, "alternate_setting": alt}

        if method == "ctrl_transfer":
            bm = int(params["bmRequestType"])
            br = int(params["bRequest"])
            wv = int(params.get("wValue", 0))
            wi = int(params.get("wIndex", 0))
            timeout = params.get("timeout", None)
            if timeout is not None:
                timeout = int(timeout)
            if "data_b64" in params:
                data = _b64d(str(params["data_b64"]))
                r = dev.ctrl_transfer(bm, br, wValue=wv, wIndex=wi, data_or_wLength=data, timeout=timeout)
                return {"written": int(r)}
            length = int(params.get("length", 0))
            r = dev.ctrl_transfer(bm, br, wValue=wv, wIndex=wi, data_or_wLength=length, timeout=timeout)
            rb = bytes(r) if not isinstance(r, (bytes, bytearray)) else bytes(r)
            return {"data_b64": _b64e(rb)}

        if method == "bulk_write":
            ep = int(params["endpoint"])
            data = _b64d(str(params["data_b64"]))
            timeout = params.get("timeout", None)
            if timeout is not None:
                timeout = int(timeout)
            r = dev.write(ep, data, timeout=timeout)
            return {"written": int(r)}

        if method == "bulk_read":
            ep = int(params["endpoint"])
            size = int(params["size"])
            timeout = params.get("timeout", None)
            if timeout is not None:
                timeout = int(timeout)
            r = dev.read(ep, size, timeout=timeout)
            rb = bytes(r) if not isinstance(r, (bytes, bytearray)) else bytes(r)
            return {"data_b64": _b64e(rb)}

        if method == "close":
            try:
                usb.util.dispose_resources(dev)
            except Exception:
                pass
            return {"closed": True}

        raise ValueError(f"unknown method: {method}")


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass, state: UsbProxyState):
        super().__init__(server_address, RequestHandlerClass)
        self.state = state


def _serve(*, host: str, port: int, usb_fd: int, token: str, expect_vid: int, expect_pid: int) -> int:
    dev = _open_device_from_usb_fd(int(usb_fd))
    if expect_vid >= 0 and int(getattr(dev, "idVendor", 0) or 0) != int(expect_vid):
        raise RuntimeError("VID mismatch")
    if expect_pid >= 0 and int(getattr(dev, "idProduct", 0) or 0) != int(expect_pid):
        raise RuntimeError("PID mismatch")

    state = UsbProxyState(dev=dev, token=token)

    class Handler(_Handler):
        state = state

    with _Server((host, int(port)), Handler, state=state) as srv:
        srv.serve_forever(poll_interval=0.2)
    return 0


def _call(*, host: str, port: int, token: str, method: str, params_json: str) -> int:
    try:
        params = json.loads(params_json) if params_json else {}
    except Exception:
        params = {}
    if not isinstance(params, dict):
        params = {}
    req = {"id": 1, "token": token, "method": method, "params": params}
    data = _json_line(req)

    with socket.create_connection((host, int(port)), timeout=5.0) as s:
        s.sendall(data)
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        line = buf.split(b"\n", 1)[0] + b"\n"
        resp = _json_obj(line)
        sys.stdout.write(json.dumps(resp, indent=2, ensure_ascii=False) + "\n")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="usb_fd_proxy")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_serve = sub.add_parser("serve")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8765)
    p_serve.add_argument("--usb-fd", type=int, default=-1)
    p_serve.add_argument("--token", default="")
    p_serve.add_argument("--expect-vid", type=lambda s: int(s, 0), default=-1)
    p_serve.add_argument("--expect-pid", type=lambda s: int(s, 0), default=-1)

    p_call = sub.add_parser("call")
    p_call.add_argument("--host", default="127.0.0.1")
    p_call.add_argument("--port", type=int, default=8765)
    p_call.add_argument("--token", default="")
    p_call.add_argument("--method", required=True)
    p_call.add_argument("--params", default="{}")

    args, extra = ap.parse_known_args(argv)
    if args.cmd == "serve":
        usb_fd = int(getattr(args, "usb_fd", -1))
        if usb_fd < 0:
            env_fd = _read_int_env("TERMUX_USB_FD") or _read_int_env("RTWMON_TERMUX_USB_FD")
            if env_fd is not None:
                usb_fd = int(env_fd)
        if usb_fd < 0 and extra and len(extra) == 1 and re.fullmatch(r"[0-9]+", str(extra[0]).strip() or "") is not None:
            usb_fd = int(str(extra[0]).strip(), 10)
        if usb_fd < 0:
            raise SystemExit("missing usb fd (use --usb-fd or TERMUX_USB_FD)")
        return _serve(
            host=str(args.host),
            port=int(args.port),
            usb_fd=int(usb_fd),
            token=str(args.token or ""),
            expect_vid=int(getattr(args, "expect_vid", -1)),
            expect_pid=int(getattr(args, "expect_pid", -1)),
        )
    return _call(
        host=str(args.host),
        port=int(args.port),
        token=str(args.token or ""),
        method=str(args.method),
        params_json=str(args.params or "{}"),
    )


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

