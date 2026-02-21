# rtwmon

`rtl8188eu_pyusb.py` is a Python userspace tool that talks to an RTL8188EU USB Wi‑Fi device via PyUSB. It can:

- Initialize the device and load firmware
- Passively scan channels and optionally list stations for a target SSID
- Capture frames to a PCAP file
- Stream RX frames to stdout (optionally dumping bytes)
- Send disassociation / deauthentication frames
- Send deauth bursts while capturing to PCAP

## Requirements

- Python 3
- PyUSB (`pip install pyusb`)
- Firmware file `rtl8188eufw.bin` (auto-searched in common locations, or pass `--firmware`)

## Usage

```bash
python3 rtl8188eu_pyusb.py [options]
```

If you run without a “mode” option (`--scan`, `--pcap`, `--rx`, `--disassoc`, `--deauth`, `--deauth-burst`), the script initializes the device and exits (or use `--init-only` explicitly).

## Options

### Device / initialization

| Option | Default | Notes |
|---|---:|---|
| `--vid` | `0x2357` | USB vendor id, accepts hex (`0x...`) or decimal |
| `--pid` | `0x010C` | USB product id, accepts hex (`0x...`) or decimal |
| `--firmware` | auto | Path to `rtl8188eufw.bin` (if not set, tries local `firmware/` and common system paths) |
| `--tables-from` | `rtl8xxxu_8188e.c` | Path to a kernel driver source file used to extract tables |
| `--channel` | `1` | Channel used for init / RX / TX modes |
| `--bw` | `20` | Channel bandwidth (`20` or `40`) |
| `--init-only` | off | Initialize device then exit |
| `--tx-debug` | off | Enable TX debug output |
| `--tx-dump-bytes` | `0` | Dump this many TX bytes (0 disables) |

### Capture / reading

| Option | Default | Notes |
|---|---:|---|
| `--reads` | `0` | Max number of USB reads (0 = unlimited) |
| `--read-size` | `16384` | Bytes per USB read |
| `--timeout-ms` | `1000` | USB read timeout for `--rx`, `--scan`, and `--pcap` |
| `--good-fcs-only` | off | Filter to frames with good FCS (when supported by mode) |
| `--dump-bytes` | `0` | Dump this many bytes per RX frame (0 disables) |

### RX mode

| Option | Default | Notes |
|---|---:|---|
| `--rx` | off | Run RX loop (prints frames, optional `--dump-bytes`) |

### Passive scan mode

| Option | Default | Notes |
|---|---:|---|
| `--scan` | off | Passive scan across channels |
| `--scan-channels` | `1-11` | Channel spec like `1-11` or `1,6,11` |
| `--dwell-ms` | `200` | Time to dwell on each channel |
| `--scan-include-bad-fcs` | off | Include frames with bad FCS when scanning |
| `--target-ssid` | `""` | If set, filter results to this SSID |
| `--station-scan-time` | `5000` | Time in ms to scan for stations when targeting a network |

### PCAP capture mode

| Option | Default | Notes |
|---|---:|---|
| `--pcap` | `""` | Output PCAP path; use `-` to write to stdout |
| `--pcap-include-bad-fcs` | off | Include frames with bad FCS in PCAP |
| `--pcap-with-fcs` | off | Keep/emit FCS when possible |

### Disassoc / deauth mode

| Option | Default | Notes |
|---|---:|---|
| `--disassoc` | off | Send Disassociate frame(s) |
| `--deauth` | off | Send Deauthentication frame(s) |
| `--target-mac` | `""` | Target MAC address (DA). Required for `--disassoc` / `--deauth` |
| `--bssid` | `""` | BSSID (and Source MAC by default). Required for `--disassoc` / `--deauth` |
| `--source-mac` | `None` | Source MAC (SA) if different from BSSID |
| `--reason` | `8` | Reason code |
| `--count` | `1` | Number of frames to send |
| `--delay-ms` | `100` | Delay between frames |

### Deauth burst + capture

| Option | Default | Notes |
|---|---:|---|
| `--deauth-burst` | off | Send deauth bursts and capture to PCAP |
| `--pcap` | `""` | Required for `--deauth-burst` |
| `--target-mac` | `""` | Required for `--deauth-burst` |
| `--bssid` | `""` | Required for `--deauth-burst` |
| `--burst-size` | `10` | Frames per burst |
| `--burst-interval-ms` | `1000` | Delay between bursts |
| `--burst-duration-s` | `0` | Total run time (0 = until Ctrl-C) |
| `--burst-read-timeout-ms` | `50` | USB read timeout used during burst loop |

## Examples

Initialize only:

```bash
python3 rtl8188eu_pyusb.py --init-only
```

Passive scan channels 1–11:

```bash
python3 rtl8188eu_pyusb.py --scan --scan-channels 1-11
```

Filter scan results to one SSID and list stations (uses `--station-scan-time`):

```bash
python3 rtl8188eu_pyusb.py --scan --target-ssid "MyWiFi"
```

Capture to a PCAP file (Ctrl‑C to stop):

```bash
python3 rtl8188eu_pyusb.py --pcap capture.pcap
```

Write PCAP to stdout:

```bash
python3 rtl8188eu_pyusb.py --pcap - > capture.pcap
```

Send 10 deauth frames:

```bash
python3 rtl8188eu_pyusb.py --deauth --bssid aa:bb:cc:dd:ee:ff --target-mac 11:22:33:44:55:66 --count 10
```

Deauth burst + PCAP capture (runs until Ctrl‑C when `--burst-duration-s 0`):

```bash
python3 rtl8188eu_pyusb.py --deauth-burst --bssid aa:bb:cc:dd:ee:ff --target-mac 11:22:33:44:55:66 --pcap burst.pcap
```
