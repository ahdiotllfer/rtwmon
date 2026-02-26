import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional, Tuple


SUPPORTED_IDS = {
    (0x2357, 0x010C): "8188eu",
    (0x2357, 0x0120): "8821au",
    (0x0BDA, 0xB812): "8822bu",
}


def _termux_api_bin() -> str:
    p = "/data/data/com.termux/files/usr/libexec/termux-api"
    if os.path.isfile(p) and os.access(p, os.X_OK):
        return p
    raise RuntimeError("termux-api binary not found (install Termux:API)")


def _termux_usb_list() -> list[str]:
    out = subprocess.check_output([_termux_api_bin(), "Usb", "-a", "list"], text=True)
    s = out.strip()
    if not s:
        return []
    v = json.loads(s)
    if isinstance(v, list):
        return [str(x) for x in v if isinstance(x, str)]
    return []


def _termux_usb_permission_device(device_path: str) -> bool:
    try:
        out = subprocess.check_output(
            [_termux_api_bin(), "Usb", "-a", "permission", "--es", "device", str(device_path), "--ez", "request", "true"],
            stderr=subprocess.STDOUT,
            text=True,
        ).strip()
        return out == "yes" or "Permission granted" in out
    except Exception:
        return False


def _termux_usb_permission_vidpid(vid: int, pid: int) -> bool:
    try:
        out = subprocess.check_output(
            [
                _termux_api_bin(),
                "Usb",
                "-a",
                "permission",
                "--es",
                "vendorId",
                str(int(vid)),
                "--es",
                "productId",
                str(int(pid)),
                "--ez",
                "request",
                "true",
            ],
            stderr=subprocess.STDOUT,
            text=True,
        ).strip()
        return out == "yes" or "Permission granted" in out
    except Exception:
        return False


def _callback_cmd() -> str:
    cb = str((Path(__file__).resolve().parent / "termux_usb_callback.py").resolve())
    py = os.environ.get("PYTHON", "python3")
    return f"{py} {cb}"


def _termux_open_capture(*, device_path: Optional[str] = None, vid: Optional[int] = None, pid: Optional[int] = None, env: dict) -> str:
    extra: list[str] = []
    if device_path is not None:
        extra = ["--es", "device", str(device_path)]
    elif vid is not None and pid is not None:
        extra = ["--es", "vendorId", str(int(vid)), "--es", "productId", str(int(pid))]
    else:
        raise RuntimeError("missing selector")
    return subprocess.check_output([_termux_api_bin(), "Usb", "-a", "open", *extra], stderr=subprocess.STDOUT, text=True, env=env)


def _termux_open_run(*, device_path: Optional[str] = None, vid: Optional[int] = None, pid: Optional[int] = None, env: dict) -> int:
    extra: list[str] = []
    if device_path is not None:
        extra = ["--es", "device", str(device_path)]
    elif vid is not None and pid is not None:
        extra = ["--es", "vendorId", str(int(vid)), "--es", "productId", str(int(pid))]
    else:
        raise RuntimeError("missing selector")
    return int(subprocess.run([_termux_api_bin(), "Usb", "-a", "open", *extra], env=env).returncode)


def _parse_vidpid(out: str) -> Optional[Tuple[int, int]]:
    for line in reversed(out.splitlines()):
        m = re.search(r"\b([0-9a-fA-F]{4}):([0-9a-fA-F]{4})\b", line.strip())
        if not m:
            continue
        return int(m.group(1), 16), int(m.group(2), 16)
    return None


def _read_device_vidpid(device_path: str) -> Optional[Tuple[int, int]]:
    if not _termux_usb_permission_device(device_path):
        return None
    env = dict(os.environ)
    env["TERMUX_CALLBACK"] = _callback_cmd()
    env["TERMUX_EXPORT_FD"] = "true"
    env["RTWMON_MODE"] = "vidpid"
    env.pop("RTWMON_EXEC_JSON", None)
    try:
        out = _termux_open_capture(device_path=device_path, env=env)
        return _parse_vidpid(out)
    except Exception:
        return None


def _auto_pick_supported_device() -> Tuple[str, int, int, str]:
    paths = _termux_usb_list()
    matches: list[tuple[str, int, int, str]] = []
    for p in paths:
        vpid = _read_device_vidpid(p)
        if vpid is None:
            continue
        v, d = vpid
        drv = SUPPORTED_IDS.get((int(v), int(d)))
        if drv is None:
            continue
        matches.append((drv, int(v), int(d), str(p)))
    uniq = {(a, b, c, d) for (a, b, c, d) in matches}
    if len(uniq) == 1:
        return next(iter(uniq))
    if len(uniq) > 1:
        parts = [f"{drv}:{vid:04x}:{pid:04x} ({path})" for (drv, vid, pid, path) in sorted(list(uniq))]
        raise RuntimeError("multiple supported devices: " + ", ".join(parts))
    raise RuntimeError("no supported device found")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="termux_usb_run")
    ap.add_argument("--device", default="")
    ap.add_argument("--vid", type=lambda s: int(s, 0), default=-1)
    ap.add_argument("--pid", type=lambda s: int(s, 0), default=-1)
    ap.add_argument("--auto", action="store_true")
    ap.add_argument("--print-fd", action="store_true")
    ap.add_argument("cmd", nargs=argparse.REMAINDER)
    args = ap.parse_args(argv)

    cmd = list(args.cmd)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        raise SystemExit("missing command (use -- <command...>)")

    device = str(args.device or "").strip()
    vid = int(getattr(args, "vid", -1))
    pid = int(getattr(args, "pid", -1))

    chosen_device: Optional[str] = None
    chosen_vidpid: Optional[Tuple[int, int]] = None

    if args.auto:
        _drv, v, p, path = _auto_pick_supported_device()
        chosen_device = path
        chosen_vidpid = (int(v), int(p))
    elif device:
        chosen_device = device
    elif vid >= 0 and pid >= 0:
        chosen_vidpid = (vid, pid)
    else:
        _drv, v, p, path = _auto_pick_supported_device()
        chosen_device = path
        chosen_vidpid = (int(v), int(p))

    if chosen_device is not None:
        if not _termux_usb_permission_device(chosen_device):
            raise SystemExit("permission denied")
    elif chosen_vidpid is not None:
        if not _termux_usb_permission_vidpid(chosen_vidpid[0], chosen_vidpid[1]):
            raise SystemExit("permission denied")
    else:
        raise SystemExit("no selector")

    env = dict(os.environ)
    env["TERMUX_CALLBACK"] = _callback_cmd()
    env["TERMUX_EXPORT_FD"] = "true"
    env["RTWMON_MODE"] = ""
    env["RTWMON_EXEC_JSON"] = json.dumps([str(x) for x in cmd])

    if args.print_fd:
        out = _termux_open_capture(device_path=chosen_device, vid=(chosen_vidpid[0] if chosen_vidpid else None), pid=(chosen_vidpid[1] if chosen_vidpid else None), env=env)
        sys.stdout.write(out)
        return 0

    return _termux_open_run(device_path=chosen_device, vid=(chosen_vidpid[0] if chosen_vidpid else None), pid=(chosen_vidpid[1] if chosen_vidpid else None), env=env)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

