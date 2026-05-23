# HDD Firmware Toolkit

A comprehensive Python toolkit for dumping, analyzing, patching, and
hot-deploying HDD/SSD firmware via ATA passthrough and JTAG (OpenOCD).

Covers WD, Seagate, Samsung (840 EVO MEX), Toshiba, NVMe, SAS, and USB
bridge platforms.

## Features

- **Firmware Parsers:** WD LZHUF, Samsung nibble-swap, Seagate .lod,
  Toshiba firmware images
- **Firmware Deobfuscation:** Samsung bytewise + AES/shuffle transforms,
  WD 513-byte XOR key decode, WDOSX packed executable extraction
- **ATA Passthrough:** Linux sg_io and Windows DeviceIoControl for
  direct drive communication
- **WD VSC Protocol:** Read/write RAM, dump overlay modules,
  deploy hot-patches via SMART LOG 0xBE
- **JTAG (OpenOCD):** Memory dumps, breakpoints, register inspection,
  GPIO/MCU interaction
- **Samsung MEX (840 EVO):** Full MEX memory map, GPIO, NCQ, AES key
  slots, DMA exfiltration, SAFE-mode UART, flash channel access
- **NVMe Admin:** Identify, SMART, firmware download/activate, sanitize,
  vendor-specific commands
- **USB Bridge Detection:** Identify USB-SATA bridge chips from INQUIRY
  strings and VID/PID
- **Data Recovery:** Read retry escalation, bad sector handling,
  defective sector pattern generation
- **HPA/DCO:** Host Protected Area and Device Configuration Overlay
  detection and command building
- **NVMe Side-Channel:** Timing analysis, contention detection, covert
  channel modelling
- **eNVMe:** DMA attack descriptor building, platform compatibility,
  kernel module injection modelling
- **NVMe-oF:** CVE-2023-5178 double-free PoC, PDU parsing, kernel
  vulnerability checking
- **Firmware Identity Spoof Detection:** Xbox 360 / HDDHackr-style firmware-level
  identity manipulation (Read et al., 2013) — security sector detection, IDENTIFY
  string analysis, SMART serial cross-check, capacity plausibility
- **Firmware Exploitation:** DOWNLOAD-MICROCODE offset overflow,
  ASM2362 XRAM injection, Service Area hide/extract
- **Patch Templates:** NOP sleds, data traps, exfiltration hooks,
  SMART log redirect
- **32 CLI Commands:** All features accessible from the command line

## Installation

```bash
# Basic install (no optional deps)
pip install hdd-firmware-toolkit

# With all optional dependencies
pip install "hdd-firmware-toolkit[all]"

# Optional dependency groups
pip install "hdd-firmware-toolkit[serial]"   # pyserial (SAFE mode UART)
pip install "hdd-firmware-toolkit[asm]"      # keystone-engine (Thumb-2 assembly)
pip install "hdd-firmware-toolkit[disasm]"   # capstone (disassembly)
pip install "hdd-firmware-toolkit[yaml]"     # PyYAML (hot-patch config)
```

## Quick Start

```bash
# Parse a WD firmware image
hdd-firmware-toolkit parse-firmware firmware.bin --format wd

# Decode Samsung nibble-swap obfuscation
hdd-firmware-toolkit decode-samsung firmware.bin -o decoded.bin

# Scan for ASCII strings
hdd-firmware-toolkit scan-strings firmware.bin

# Check NVMe-oF kernel vulnerability
hdd-firmware-toolkit nvmeof-check-kernel --kernel 6.7
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `parse-firmware` | Parse & extract firmware sections |
| `decode-samsung` | Remove Samsung nibble-swap obfuscation |
| `scan-strings` | Find ASCII strings in firmware |
| `scan-fptables` | Heuristic ARM function-pointer table scan |
| `diff` | Byte-level diff two firmware images |
| `list-vscs` | Request VSC list from WD drive |
| `read-ram` | Read drive RAM via WD VSC |
| `write-ram` | Write file to drive RAM via WD VSC |
| `hot-patch` | Deploy delay hook to live drive RAM |
| `benchmark` | Timed read benchmark |
| `dump-overlay` | Dump a WD service-area overlay module |
| `dump-all-overlays` | Dump all overlay modules to directory |
| `jtag-shell` | Interactive OpenOCD shell |
| `jtag-dump` | Dump memory via JTAG |
| `jtag-bp` | Set hardware breakpoint via JTAG |
| `jtag-regs` | Read CPU registers via JTAG |
| `samsung-memory-map` | Print MEX memory map |
| `samsung-fw-history` | Print FW version history |
| `samsung-gpio` | Read GPIO status via JTAG |
| `samsung-ncq` | Dump NCQ buffers via JTAG |
| `samsung-aes-info` | Read AES-XTS key slots via JTAG |
| `samsung-dma-dump` | RAM to SATA via DMA |
| `samsung-ftl-preload` | Pre-load FTL map |
| `samsung-safe-shell` | Interactive SAFE-mode UART shell |
| `samsung-safe-read` | Read via SAFE-mode UART |
| `samsung-safe-write` | Write via SAFE-mode UART |
| `parse-seagate` | Parse Seagate .lod firmware |
| `sa-probe` | Probe Service Area size |
| `sa-dump` | Full Service Area dump |
| `sa-hide` | Hide data in SA module |
| `sa-extract` | Extract hidden data from SA module |
| `fwexploit-send` | Inject firmware via offset overflow |
| `fwexploit-activate` | Activate injected firmware |
| `nvme-bridge-sanitize` | Inject Sanitize via ASM2362 XRAM |
| `patch-template` | Generate pre-built patch shellcode |
| `toshiba-parse` | Parse Toshiba firmware image |
| `toshiba-nand` | Show Toshiba NAND configuration |
| `sat-cdb` | Build SCSI-ATA Translation CDB |
| `patcher-apply` | Apply patches and fix checksums |
| `patcher-fix` | Auto-fix firmware checksums |
| `ata-sec-status` | Check ATA security status |
| `nvme-identify` | NVMe Identify Controller |
| `nvme-smart` | NVMe SMART / Health log |
| `nvme-fw-download` | NVMe firmware download |
| `nvme-fw-activate` | NVMe firmware activate |
| `nvme-vendor` | NVMe vendor-specific command |
| `usb-identify` | Identify USB-SATA bridge chip |
| `usb-list` | List known USB-SATA bridge chips |
| `dr-smart` | SMART quick test (data recovery) |
| `dr-identify` | Identify device parameters |
| `dr-native-max` | Read Native Max Address |
| `dr-pattern` | Generate defective sector pattern |
| `hpa-detect` | Detect HPA from IDENTIFY data |
| `hpa-build-cmd` | Build HPA/DCO ATA command |
| `hpa-parse-dco` | Parse DCO feature set descriptor |
| `nvme-timing-baseline` | NVMe read latency baseline |
| `nvme-timing-detect` | Detect NVMe timing contention |
| `nvme-timing-gc` | Analyze NVMe GC events |
| `envme-dma` | Build eNVMe DMA attack descriptor |
| `envme-scan` | Model host memory scan |
| `envme-compat` | Check eNVMe compatibility |
| `nvmeof-check-kernel` | Check CVE-2023-5178 vulnerability |
| `nvmeof-build-icreq` | Build NVMe-oF TCP ICReq PDU |
| `nvmeof-poc` | Generate double-free PoC PDU |
| `fw-identity-check` | Detect Xbox 360 / HDDHackr firmware identity spoofing |
| `fwdetect-timing` | Detect FW via timing analysis |
| `fwdetect-verify` | Verify firmware checksums |
| `fwdetect-report` | Comprehensive integrity report |

## Requirements

- **Python** >= 3.11
- **Optional:** pyserial, keystone-engine, capstone, PyYAML

### Platform-Specific

- **Linux:** ATA passthrough via sg_io requires root + `/dev/sdX` or `/dev/sgX`
- **Windows:** ATA passthrough requires Administrator privileges

## Development

```bash
pip install -e ".[all]"
pre-commit install
pytest
ruff check src/
```

## License

MIT
