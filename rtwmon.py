import argparse
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional, Sequence, Tuple


SUPPORTED = {
    "8188eu": {
        "ids": {(0x2357, 0x010C)},
        "bin": "rtl8188eu_libusb",
        "py": "rtl8188eu_pyusb.py",
    },
    "8821au": {
        "ids": {(0x2357, 0x0120)},
        "py": "rtl8821au_pyusb.py",
    },
    "8822bu": {
        "ids": {(0x0BDA, 0xB812)},
        "py": "rtl8822bu_pyusb.py",
    },
}


def _libusb_error_name(lib, code: int) -> str:
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


def _pick_driver(vid: int, pid: int) -> Optional[str]:
    for name, info in SUPPORTED.items():
        if (int(vid), int(pid)) in set(info["ids"]):
            return name
    return None


def _autodetect_driver(
    *, vid: Optional[int], pid: Optional[int], usb_fd: Optional[int], bus: Optional[int], address: Optional[int]
) -> Tuple[str, Optional[Tuple[int, int]]]:
    if usb_fd is not None and int(usb_fd) >= 0:
        v, p = _detect_vid_pid_from_usb_fd(int(usb_fd))
        drv = _pick_driver(v, p)
        if drv is None:
            raise RuntimeError(f"Unsupported USB device via fd: {v:04x}:{p:04x}")
        return drv, (v, p)

    if vid is not None and pid is not None:
        drv = _pick_driver(int(vid), int(pid))
        if drv is not None:
            return drv, (int(vid), int(pid))

    try:
        import usb.core
    except Exception:
        usb = None
    else:
        usb = usb.core

    if usb is not None:
        want = set()
        for info in SUPPORTED.values():
            want |= set(info["ids"])
        matches = []
        found = list(usb.find(find_all=True) or [])
        for d in found:
            dv = int(getattr(d, "idVendor", 0) or 0)
            dp = int(getattr(d, "idProduct", 0) or 0)
            if (dv, dp) not in want:
                continue
            if bus is not None and int(bus) >= 0 and int(getattr(d, "bus", -1) or -1) != int(bus):
                continue
            if address is not None and int(address) >= 0 and int(getattr(d, "address", -1) or -1) != int(address):
                continue
            drv = _pick_driver(dv, dp)
            if drv is None:
                continue
            matches.append((drv, dv, dp, int(getattr(d, "bus", -1) or -1), int(getattr(d, "address", -1) or -1)))

        uniq = {(drv, dv, dp, b, a) for (drv, dv, dp, b, a) in matches}
        if len(uniq) == 1:
            drv, dv, dp, _b, _a = next(iter(uniq))
            return drv, (dv, dp)
        if len(uniq) > 1:
            rows = sorted(uniq, key=lambda x: (x[0], x[1], x[2], x[3], x[4]))
            parts = []
            for drv, dv, dp, b, a in rows:
                extra = []
                if b >= 0:
                    extra.append(f"bus={b}")
                if a >= 0:
                    extra.append(f"address={a}")
                extra_s = f" ({', '.join(extra)})" if extra else ""
                parts.append(f"{drv}:{dv:04x}:{dp:04x}{extra_s}")
            raise RuntimeError(
                "Multiple supported adapters detected: "
                + ", ".join(parts)
                + ". Use --driver or --vid/--pid/--bus/--address to choose."
            )

    try:
        out = subprocess.check_output(["lsusb"], stderr=subprocess.DEVNULL, text=True)
    except Exception:
        out = ""
    m = re.findall(r"ID\s+([0-9a-fA-F]{4}):([0-9a-fA-F]{4})", out)
    for vs, ps in m:
        dv, dp = int(vs, 16), int(ps, 16)
        drv = _pick_driver(dv, dp)
        if drv is not None:
            return drv, (dv, dp)

    raise RuntimeError("No supported Realtek USB adapter found (use --driver or --vid/--pid/--usb-fd)")


def _script_path(name: str) -> str:
    p = (Path(__file__).resolve().parent / str(name)).resolve()
    return str(p)


def _exec_backend(prog: str, argv: Sequence[str]) -> int:
    if str(prog).endswith(".py"):
        py = os.environ.get("PYTHON", "python3")
        cmd = [py, prog, *argv]
    else:
        cmd = [prog, *argv]
    r = subprocess.run(cmd).returncode
    return int(r)


def main(argv: Sequence[str]) -> int:
    argv = list(argv)
    ap = argparse.ArgumentParser(prog="rtwmon")
    ap.add_argument("--driver", choices=tuple(SUPPORTED.keys()) + ("auto",), default="auto")
    ap.add_argument("--vid", type=lambda s: int(s, 0), default=None)
    ap.add_argument("--pid", type=lambda s: int(s, 0), default=None)
    ap.add_argument("--usb-fd", type=int, default=-1)
    ap.add_argument("--bus", type=int, default=-1)
    ap.add_argument("--address", type=int, default=-1)
    ap.add_argument("--interface", type=int, default=0)
    ap.add_argument("--configuration", type=int, default=1)
    ap.add_argument("--tables-from", type=str, default="")
    ap.add_argument("--debug", action="store_true")

    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("info")

    p_scan = sub.add_parser("scan")
    p_scan.add_argument("--channels", default="1-11")
    p_scan.add_argument("--bw", type=int, choices=(20, 40, 80), default=20)
    p_scan.add_argument("--dwell-ms", type=int, default=1000)
    p_scan.add_argument("--timeout-ms", type=int, default=1200)
    p_scan.add_argument("--read-size", type=int, default=32768)
    p_scan.add_argument("--size", type=int, default=32768, dest="read_size")
    p_scan.add_argument("--target-ssid", default="")
    p_scan.add_argument("--station-scan-ms", type=int, default=5000)
    p_scan.add_argument("--scan-include-bad-fcs", action="store_true")
    p_scan.add_argument("--pcap", default="")
    p_scan.add_argument("--pcap-include-bad-fcs", action="store_true")
    p_scan.add_argument("--pcap-with-fcs", action="store_true")
    p_scan.add_argument("--igi", type=int, default=-1)

    p_rx = sub.add_parser("rx")
    p_rx.add_argument("--channel", type=int, default=1)
    p_rx.add_argument("--bw", type=int, choices=(20, 40, 80), default=20)
    p_rx.add_argument("--timeout-ms", type=int, default=1000)
    p_rx.add_argument("--read-size", type=int, default=32768)
    p_rx.add_argument("--size", type=int, default=32768, dest="read_size")
    p_rx.add_argument("--pcap", default="")
    p_rx.add_argument("--pcap-include-bad-fcs", action="store_true")
    p_rx.add_argument("--pcap-with-fcs", action="store_true")
    p_rx.add_argument("--igi", type=int, default=-1)

    p_deauth = sub.add_parser("deauth")
    p_deauth.add_argument("--channel", type=int, default=1)
    p_deauth.add_argument("--bw", type=int, choices=(20, 40, 80), default=20)
    p_deauth.add_argument("--target-mac", required=True)
    p_deauth.add_argument("--bssid", required=True)
    p_deauth.add_argument("--source-mac", default=None)
    p_deauth.add_argument("--reason", type=int, default=7)
    p_deauth.add_argument("--count", type=int, default=1)
    p_deauth.add_argument("--delay-ms", type=int, default=100)

    p_burst = sub.add_parser("deauth-burst")
    p_burst.add_argument("--channel", type=int, default=1)
    p_burst.add_argument("--bw", type=int, choices=(20, 40, 80), default=20)
    p_burst.add_argument("--target-mac", required=True)
    p_burst.add_argument("--bssid", required=True)
    p_burst.add_argument("--source-mac", default=None)
    p_burst.add_argument("--reason", type=int, default=7)
    p_burst.add_argument("--pcap", required=True)
    p_burst.add_argument("--pcap-include-bad-fcs", action="store_true")
    p_burst.add_argument("--pcap-with-fcs", action="store_true")
    p_burst.add_argument("--burst-size", type=int, default=20)
    p_burst.add_argument("--burst-interval-ms", type=int, default=2000)
    p_burst.add_argument("--burst-duration-s", type=float, default=0.0)
    p_burst.add_argument("--burst-read-timeout-ms", type=int, default=50)
    p_burst.add_argument("--read-size", type=int, default=32768)
    p_burst.add_argument("--size", type=int, default=32768, dest="read_size")

    args, extra = ap.parse_known_args(argv)
    if extra and len(extra) == 1 and extra[0] == argv[-1] and re.fullmatch(r"[0-9]+", extra[0]) is not None and int(getattr(args, "usb_fd", -1)) < 0:
        usb_fd_auto = int(extra[0], 10)
        args, extra = ap.parse_known_args(argv[:-1])
        args.usb_fd = usb_fd_auto

    usb_fd = int(getattr(args, "usb_fd", -1))
    want_vid = getattr(args, "vid", None)
    want_pid = getattr(args, "pid", None)

    if str(getattr(args, "driver", "auto")) != "auto":
        driver = str(args.driver)
        detected = None
    else:
        bus = int(getattr(args, "bus", -1))
        addr = int(getattr(args, "address", -1))
        driver, detected = _autodetect_driver(
            vid=(int(want_vid) if want_vid is not None else None),
            pid=(int(want_pid) if want_pid is not None else None),
            usb_fd=(usb_fd if usb_fd >= 0 else None),
            bus=(bus if bus >= 0 else None),
            address=(addr if addr >= 0 else None),
        )

    if args.cmd == "info":
        if detected is None:
            if usb_fd >= 0:
                v, p = _detect_vid_pid_from_usb_fd(usb_fd)
                detected = (v, p)
            elif want_vid is not None and want_pid is not None:
                detected = (int(want_vid), int(want_pid))
        det_s = f"{detected[0]:04x}:{detected[1]:04x}" if detected is not None else "unknown"
        sys.stdout.write(f"driver={driver} usb={det_s}\n")
        return 0

    use_8188eu_bin = False
    if driver == "8188eu":
        bin_path = Path(_script_path(SUPPORTED["8188eu"]["bin"]))
        if bin_path.is_file() and os.access(str(bin_path), os.X_OK) and args.cmd in ("scan", "rx", "deauth-burst"):
            use_8188eu_bin = True
            prog_abs = str(bin_path)
        else:
            prog_abs = _script_path(SUPPORTED["8188eu"]["py"])
    else:
        prog_abs = _script_path(SUPPORTED[driver]["py"])

    fwd: list[str] = []
    if bool(getattr(args, "debug", False)):
        fwd.append("--debug")
    if want_vid is not None:
        fwd += ["--vid", hex(int(want_vid))]
    if want_pid is not None:
        fwd += ["--pid", hex(int(want_pid))]
    if usb_fd >= 0:
        fwd += ["--usb-fd", str(int(usb_fd))]
    if driver == "8188eu" and not use_8188eu_bin:
        tables_from = str(getattr(args, "tables_from", "") or "").strip()
        if not tables_from:
            tables_from = str((Path(__file__).resolve().parent / "firmware" / "rtl8xxxu_8188e.c").resolve())
        fwd += ["--tables-from", tables_from]

    if driver in ("8821au", "8822bu"):
        bus = int(getattr(args, "bus", -1))
        addr = int(getattr(args, "address", -1))
        fwd += ["--interface", str(int(getattr(args, "interface", 0)))]
        fwd += ["--configuration", str(int(getattr(args, "configuration", 1)))]
        if driver == "8822bu" and bus >= 0:
            fwd += ["--bus", str(bus)]
        if driver == "8822bu" and addr >= 0:
            fwd += ["--address", str(addr)]
    elif driver == "8188eu" and use_8188eu_bin:
        bus = int(getattr(args, "bus", -1))
        addr = int(getattr(args, "address", -1))
        if bus >= 0:
            fwd += ["--bus", str(bus)]
        if addr >= 0:
            fwd += ["--address", str(addr)]

    cmd_argv: list[str] = []
    if args.cmd == "scan":
        if use_8188eu_bin:
            cmd_argv += [
                "--scan",
                "--scan-channels",
                str(getattr(args, "channels", "")),
                "--bw",
                str(int(getattr(args, "bw", 20))),
                "--dwell-ms",
                str(int(getattr(args, "dwell_ms", 1000))),
                "--timeout-ms",
                str(int(getattr(args, "timeout_ms", 1200))),
                "--read-size",
                str(int(getattr(args, "read_size", 32768))),
                "--target-ssid",
                str(getattr(args, "target_ssid", "")),
                "--station-scan-time",
                str(int(getattr(args, "station_scan_ms", 5000))),
            ]
        else:
            size_flag = "--size" if driver == "8821au" else "--read-size"
            cmd_argv += [
                "scan",
                "--channels",
                str(getattr(args, "channels", "")),
                "--bw",
                str(int(getattr(args, "bw", 20))),
                "--dwell-ms",
                str(int(getattr(args, "dwell_ms", 1000))),
                "--timeout-ms",
                str(int(getattr(args, "timeout_ms", 1200))),
                size_flag,
                str(int(getattr(args, "read_size", 32768))),
                "--target-ssid",
                str(getattr(args, "target_ssid", "")),
                "--station-scan-ms",
                str(int(getattr(args, "station_scan_ms", 5000))),
            ]
        if bool(getattr(args, "scan_include_bad_fcs", False)):
            cmd_argv.append("--scan-include-bad-fcs")
        if bool(getattr(args, "pcap", "")):
            cmd_argv += ["--pcap", str(getattr(args, "pcap"))]
        if bool(getattr(args, "pcap_include_bad_fcs", False)):
            cmd_argv.append("--pcap-include-bad-fcs")
        if bool(getattr(args, "pcap_with_fcs", False)):
            cmd_argv.append("--pcap-with-fcs")
        igi = int(getattr(args, "igi", -1))
        if igi >= 0:
            cmd_argv += ["--igi", str(igi)]
    elif args.cmd == "rx":
        if use_8188eu_bin:
            cmd_argv += [
                "--rx",
                "--channel",
                str(int(getattr(args, "channel", 1))),
                "--bw",
                str(int(getattr(args, "bw", 20))),
                "--timeout-ms",
                str(int(getattr(args, "timeout_ms", 1000))),
                "--read-size",
                str(int(getattr(args, "read_size", 32768))),
            ]
        else:
            cmd_argv += [
                "rx",
                "--channel",
                str(int(getattr(args, "channel", 1))),
                "--bw",
                str(int(getattr(args, "bw", 20))),
                "--timeout-ms",
                str(int(getattr(args, "timeout_ms", 1000))),
                "--size",
                str(int(getattr(args, "read_size", 32768))),
            ]
        if bool(getattr(args, "pcap", "")):
            cmd_argv += ["--pcap", str(getattr(args, "pcap"))]
        if bool(getattr(args, "pcap_include_bad_fcs", False)):
            cmd_argv.append("--pcap-include-bad-fcs")
        if bool(getattr(args, "pcap_with_fcs", False)):
            cmd_argv.append("--pcap-with-fcs")
        igi = int(getattr(args, "igi", -1))
        if igi >= 0:
            cmd_argv += ["--igi", str(igi)]
    elif args.cmd == "deauth":
        cmd_argv += [
            "deauth",
            "--channel",
            str(int(getattr(args, "channel", 1))),
            "--bw",
            str(int(getattr(args, "bw", 20))),
            "--target-mac",
            str(getattr(args, "target_mac")),
            "--bssid",
            str(getattr(args, "bssid")),
            "--reason",
            str(int(getattr(args, "reason", 7))),
            "--count",
            str(int(getattr(args, "count", 1))),
            "--delay-ms",
            str(int(getattr(args, "delay_ms", 100))),
        ]
        if getattr(args, "source_mac", None):
            cmd_argv += ["--source-mac", str(getattr(args, "source_mac"))]
    elif args.cmd == "deauth-burst":
        if use_8188eu_bin:
            cmd_argv += [
                "--deauth-burst",
                "--channel",
                str(int(getattr(args, "channel", 1))),
                "--bw",
                str(int(getattr(args, "bw", 20))),
                "--target-mac",
                str(getattr(args, "target_mac")),
                "--bssid",
                str(getattr(args, "bssid")),
                "--reason",
                str(int(getattr(args, "reason", 7))),
                "--pcap",
                str(getattr(args, "pcap")),
                "--burst-size",
                str(int(getattr(args, "burst_size", 20))),
                "--burst-interval-ms",
                str(int(getattr(args, "burst_interval_ms", 2000))),
                "--burst-duration-s",
                str(int(float(getattr(args, "burst_duration_s", 0.0)))),
                "--burst-read-timeout-ms",
                str(int(getattr(args, "burst_read_timeout_ms", 50))),
                "--read-size",
                str(int(getattr(args, "read_size", 32768))),
            ]
        else:
            cmd_argv += [
                "deauth-burst",
                "--channel",
                str(int(getattr(args, "channel", 1))),
                "--bw",
                str(int(getattr(args, "bw", 20))),
                "--target-mac",
                str(getattr(args, "target_mac")),
                "--bssid",
                str(getattr(args, "bssid")),
                "--reason",
                str(int(getattr(args, "reason", 7))),
                "--pcap",
                str(getattr(args, "pcap")),
                "--burst-size",
                str(int(getattr(args, "burst_size", 20))),
                "--burst-interval-ms",
                str(int(getattr(args, "burst_interval_ms", 2000))),
                "--burst-duration-s",
                str(float(getattr(args, "burst_duration_s", 0.0))),
                "--burst-read-timeout-ms",
                str(int(getattr(args, "burst_read_timeout_ms", 50))),
                "--read-size",
                str(int(getattr(args, "read_size", 32768))),
            ]
        if getattr(args, "source_mac", None):
            cmd_argv += ["--source-mac", str(getattr(args, "source_mac"))]
        if bool(getattr(args, "pcap_include_bad_fcs", False)):
            cmd_argv.append("--pcap-include-bad-fcs")
        if bool(getattr(args, "pcap_with_fcs", False)):
            cmd_argv.append("--pcap-with-fcs")

    if extra:
        cmd_argv += list(extra)

    return _exec_backend(prog_abs, [*fwd, *cmd_argv])


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
