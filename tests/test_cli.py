from hdd_toolkit.cli.handlers import build_parser


def test_parser_created():
    parser = build_parser()
    assert parser is not None
    assert parser.prog == "hdd-toolkit"


def test_parser_has_all_commands():
    parser = build_parser()
    seen = set(parser._subparsers._group_actions[0].choices.keys())
    expected = {
        "parse-firmware", "decode-samsung", "scan-strings", "scan-fptables",
        "diff", "list-vscs", "read-ram", "write-ram",
        "hot-patch", "benchmark", "dump-overlay", "dump-all-overlays",
        "jtag-shell", "jtag-dump", "jtag-bp", "jtag-regs",
        "samsung-memory-map", "samsung-fw-history",
        "samsung-gpio", "samsung-ncq", "samsung-aes-info",
        "samsung-dma-dump", "samsung-ftl-preload",
        "samsung-flash-read", "samsung-flash-write",
        "samsung-flash-erase", "samsung-flash-integrity",
        "samsung-safe-shell", "samsung-safe-read", "samsung-safe-write",
        "parse-seagate",
        "sa-probe", "sa-dump", "sa-hide", "sa-extract",
        "sa-scan-spare",
        "seagate-sa-info", "seagate-sa-read", "seagate-sa-write", "seagate-sa-dump",
        "wd-sa-info",
        "fwexploit-send", "fwexploit-activate",
        "nvme-bridge-sanitize", "patch-template",
        "toshiba-parse", "toshiba-nand",
        "sat-cdb", "patcher-apply", "patcher-fix",
        "ata-sec-status",
        "nvme-identify", "nvme-smart", "nvme-fw-download",
        "nvme-fw-activate", "nvme-vendor",
        "nvme-live-identify", "nvme-live-smart", "nvme-live-get-log",
        "nvme-live-fw-log", "nvme-live-send",
        "usb-identify", "usb-list",
        "dr-smart", "dr-identify", "dr-native-max", "dr-pattern",
        "hpa-detect", "hpa-build-cmd", "hpa-parse-dco",
        "nvme-timing-baseline", "nvme-timing-detect", "nvme-timing-gc",
        "envme-dma", "envme-scan", "envme-compat",
        "nvmeof-check-kernel", "nvmeof-build-icreq", "nvmeof-poc",
        "fwdetect-current", "fwdetect-timing",
        "fwdetect-verify", "fwdetect-report",
        "fw-readback-probe",
        "sandisk-id", "sandisk-sniff-logs", "sandisk-build-log",
        "sandisk-build-vu", "sandisk-build-purge", "sandisk-build-resize",
        "sandisk-parse-c0", "sandisk-parse-ca", "sandisk-parse-d0",
        "sandisk-live-sniff",
        "spi-decode-csv",
        "psoc-sync", "psoc-read-sec", "psoc-read-srom", "psoc-write-reg",
        "psoc-locate-pin", "psoc-dump-block",
        "i2c-diff",
        "fw-identity-check",
        "hddss-info", "hddss-patch",
        "opal-discovery", "opal-start-session",
        "ata-security-check", "ata-security-build",
        "scsi-inquiry", "scsi-read-capacity", "scsi-ses", "scsi-inquiry-cdb",
        "nvme-hmb-caps", "nvme-hmb-attack", "nvme-hmb-enable-cmd",
        "rtl9210-info", "rtl9210-read-reg", "rtl9210-write-reg",
        "rtl9210-read-spi", "rtl9210-inject-sanitize",
        "ata-master-pw-oracle", "ata-master-pw-detect",
        "vwc-analyse", "vwc-disable-cmd", "vwc-fault-plan",
        "hitachi-sa-info", "hitachi-sa-read", "hitachi-sa-write",
        "seagate-f3-cmd", "seagate-f3-sa-read", "seagate-f3-head-select",
        "wd-passport-probe", "wd-passport-keyrec", "wd-passport-status-cdb",
        "wd-idle3-get", "wd-idle3-set", "wd-idle3-disable",
    }
    missing = expected - seen
    extra = seen - expected
    assert not missing, f"Missing commands: {missing}"
    assert not extra, f"Extra commands: {extra}"


def test_parse_firmware_args():
    parser = build_parser()
    args = parser.parse_args(["parse-firmware", "firmware.bin"])
    assert args.file == "firmware.bin"
    assert args.format == "wd"
    assert args.func is not None


def test_read_ram_args():
    parser = build_parser()
    args = parser.parse_args(["read-ram", "--drive", "/dev/sdb", "--addr", "0x41414141"])
    assert args.drive == "/dev/sdb"
    assert args.addr == "0x41414141"
    assert args.size == 256
