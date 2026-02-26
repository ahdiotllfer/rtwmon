import json
import os
import re
import sys
from typing import Any, Optional, Tuple


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


def _detect_vid_pid_from_usb_fd(usb_fd: int) -> Tuple[int, int]:
    import ctypes
    import usb.backend.libusb1 as libusb1

    backend = libusb1.get_backend()
    lib = backend.lib

    wrap = getattr(lib, "libusb_wrap_sys_device", None)
    if wrap is None:
        raise RuntimeError("libusb_wrap_sys_device not available")
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

    get_desc = getattr(lib, "libusb_get_device_descriptor", None)
    if get_desc is None:
        raise RuntimeError("libusb_get_device_descriptor not available")

    class _DevDesc(ctypes.Structure):
        _fields_ = [
            ("bLength", ctypes.c_uint8),
            ("bDescriptorType", ctypes.c_uint8),
            ("bcdUSB", ctypes.c_uint16),
            ("bDeviceClass", ctypes.c_uint8),
            ("bDeviceSubClass", ctypes.c_uint8),
            ("bDeviceProtocol", ctypes.c_uint8),
            ("bMaxPacketSize0", ctypes.c_uint8),
            ("idVendor", ctypes.c_uint16),
            ("idProduct", ctypes.c_uint16),
            ("bcdDevice", ctypes.c_uint16),
            ("iManufacturer", ctypes.c_uint8),
            ("iProduct", ctypes.c_uint8),
            ("iSerialNumber", ctypes.c_uint8),
            ("bNumConfigurations", ctypes.c_uint8),
        ]

    desc = _DevDesc()
    get_desc.argtypes = [ctypes.c_void_p, ctypes.POINTER(_DevDesc)]
    get_desc.restype = ctypes.c_int
    r2 = int(get_desc(dev_ptr, ctypes.byref(desc)))
    if r2 != 0:
        raise RuntimeError(f"libusb_get_device_descriptor failed: {_libusb_error_name(lib, r2)}")

    return int(desc.idVendor), int(desc.idProduct)


def _read_usb_fd() -> int:
    v = os.environ.get("TERMUX_USB_FD") or os.environ.get("RTWMON_TERMUX_USB_FD")
    if v is None:
        raise RuntimeError("missing TERMUX_USB_FD")
    s = str(v).strip()
    if re.fullmatch(r"[0-9]+", s) is None:
        raise RuntimeError("invalid TERMUX_USB_FD")
    return int(s, 10)


def _read_cmd() -> list[str]:
    spec = os.environ.get("RTWMON_EXEC_JSON", "")
    if not spec:
        raise RuntimeError("missing RTWMON_EXEC_JSON")
    v = json.loads(spec)
    if not isinstance(v, list) or not v or not all(isinstance(x, str) for x in v):
        raise RuntimeError("invalid RTWMON_EXEC_JSON")
    return [str(x) for x in v]


def main() -> int:
    usb_fd = _read_usb_fd()
    mode = str(os.environ.get("RTWMON_MODE", "") or "")

    if mode == "vidpid":
        v, p = _detect_vid_pid_from_usb_fd(int(usb_fd))
        sys.stdout.write(f"{v:04x}:{p:04x}\n")
        sys.stdout.flush()
        return 0

    cmd = _read_cmd()
    fd_s = str(int(usb_fd))
    cmd = [fd_s if x == "{USB_FD}" else x for x in cmd]
    env = dict(os.environ)
    env["RTWMON_TERMUX_USB_FD"] = fd_s
    os.execvpe(cmd[0], cmd, env)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

