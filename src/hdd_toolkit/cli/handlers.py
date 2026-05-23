import argparse
import json
import struct
import sys
from pathlib import Path

from hdd_toolkit.ata.commands import (
    SAMSUNG_840_EVO_FW_HISTORY,
    ATADevice,
    ATAError,
    ATASecurityCommands,
)
from hdd_toolkit.ata.hitachi_vsc import HitachiVSCClient
from hdd_toolkit.ata.idle3 import IDLE3_DISABLED, WDIdle3Client
from hdd_toolkit.ata.sat import SATLayer
from hdd_toolkit.ata.seagate_f3_terminal import SeagateF3ROMMap, SeagateF3Terminal
from hdd_toolkit.ata.seagate_vsc import SeagateF3SCTClient, SeagateSAModule
from hdd_toolkit.ata.security import ATAFrozenBypass, ATASecurityStatus
from hdd_toolkit.ata.tcg_opal import TCGDiscovery0Parser
from hdd_toolkit.ata.wd_vsc import WD_SA_ROM_MAP, WDVSCClient
from hdd_toolkit.core.utils import (
    _hex_dump,
    diff_firmware,
    err,
    find_arm_function_tables,
    hdr,
    hexdump,
    info,
    ok,
    scan_strings,
    warn,
)
from hdd_toolkit.exploit.ata_password_oracle import ATAMasterPasswordOracle
from hdd_toolkit.exploit.bridge_attack import ASM2362NVMeBridge
from hdd_toolkit.exploit.fw_update import FirmwareUpdateExploit
from hdd_toolkit.exploit.hotpatch import (
    HotPatchConfig,
    PatchTemplates,
    benchmark_reads,
    deploy_hot_patch,
)
from hdd_toolkit.exploit.psoc_coldboot import PSoCColdBoot
from hdd_toolkit.exploit.rtl9210_bridge import RTL9210Bridge
from hdd_toolkit.exploit.service_area import ServiceArea, dump_all_overlays
from hdd_toolkit.exploit.spare_sector_forensics import SpareSectorForensics
from hdd_toolkit.exploit.wd_passport import (
    WDPassportBridgeCmd,
    WDPassportKeyRecovery,
)
from hdd_toolkit.exploit.write_cache_fault import (
    WriteCacheFaultModel,
    plan_power_loss_fault,
)
from hdd_toolkit.exploit.xbox360_firmware_spoof import (
    FirmwareIdentitySpoofDetector,
    HddhackrFirmwarePatcher,
    HddhackrSectorFile,
)
from hdd_toolkit.firmware.detection import FirmwareDetection
from hdd_toolkit.firmware.patcher import FirmwarePatch, FirmwarePatcher
from hdd_toolkit.firmware.samsung import SamsungFirmwareParser, samsung_decode
from hdd_toolkit.firmware.seagate import SeagateFWLoader
from hdd_toolkit.firmware.toshiba import ToshibaFirmwareParser
from hdd_toolkit.firmware.wd import WDFirmwareParser
from hdd_toolkit.firmware.wd100x import parse_wd100x_rom
from hdd_toolkit.hw.data_recovery import SATADataRecoveryOps
from hdd_toolkit.hw.hpa_dco import HPADCOAccess
from hdd_toolkit.hw.issp import ISSPEngine
from hdd_toolkit.hw.jtag import OpenOCDBridge
from hdd_toolkit.hw.sas import (
    SCSICapacity,
    SCSIDevice,
    SCSIInquiryData,
    build_inquiry_cdb,
    parse_ses_enclosure_status,
)
from hdd_toolkit.hw.spi_flash import SPIFlashCapture
from hdd_toolkit.hw.usb_bridge import USBToSATABridge
from hdd_toolkit.nvme.admin import NVMeAdminPassthrough
from hdd_toolkit.nvme.envme import eNVMeIntegration
from hdd_toolkit.nvme.hmb import (
    HMBAllocation,
    HMBAttackModel,
    HMBDescriptor,
    parse_hmb_caps_from_identify,
)
from hdd_toolkit.nvme.ofabrics import NVMeOverFabrics
from hdd_toolkit.nvme.sandisk import SanDiskNVMeVSC
from hdd_toolkit.nvme.timing import NVMeTimingSideChannel
from hdd_toolkit.samsung_mex.aes import SamsungAESInfo
from hdd_toolkit.samsung_mex.dma import SamsungDMAHelper
from hdd_toolkit.samsung_mex.flash import SamsungFlashChannel
from hdd_toolkit.samsung_mex.gpio import SamsungGPIO
from hdd_toolkit.samsung_mex.memory_map import SamsungMEXMap
from hdd_toolkit.samsung_mex.ncq import SamsungNCQParser
from hdd_toolkit.samsung_mex.safe_uart import SamsungSafeUARTClient


def cmd_toshiba_parse(args):
    hdr(f"Parse Toshiba firmware: {args.file}")
    data = Path(args.file).read_bytes()
    parser = ToshibaFirmwareParser(data)
    if not parser.valid:
        err(f"Not a Toshiba image (magic={parser.magic!r})")
        return


def cmd_toshiba_nand(args):
    hdr(f"Toshiba NAND config: {args.file}")
    data = Path(args.file).read_bytes()
    parser = ToshibaFirmwareParser(data)
    if not parser.nand_config:
        warn("No NAND config found")
        return
    for k, v in parser.nand_config.items():
        pass


# == SAT layer helpers ========================================================


def cmd_sat_build_cdb(args):
    hdr(f"SAT CDB: ATA CMD=0x{args.ata_cmd:02X} LBA=0x{args.lba:X} count={args.count}")
    if args.cdb_size == "16":
        SATLayer.build_ata_pass_through_16(
            args.ata_cmd, args.lba, args.count, protocol=args.protocol
        )
    elif args.cdb_size == "12":
        SATLayer.build_ata_pass_through_12(
            args.ata_cmd, args.lba, args.count, protocol=args.protocol
        )
    else:
        SATLayer.build_ata_pass_through_32(
            args.ata_cmd, args.lba, args.count, protocol=args.protocol
        )


# == Firmware patcher helpers =================================================


def cmd_patcher_apply(args):
    hdr(f"Patch firmware: {args.file}")
    data = Path(args.file).read_bytes()
    patcher = FirmwarePatcher(data)
    ok(f"Detected vendor: {patcher.vendor}")
    for patch_file in args.patches:
        patch = json.loads(Path(patch_file).read_text())
        fp = FirmwarePatch(
            offset=patch["offset"],
            original=b"",  # filled by apply_patch
            replacement=bytes.fromhex(patch["replacement"]),
            description=patch.get("description", ""),
        )
        patcher.apply_patch(fp)
    fixes = patcher.fix_all()
    for f in fixes:
        ok(f"Fix: {f}")
    patcher.write(args.output)
    ok(f"Patched firmware written to {args.output}")


def cmd_patcher_fix(args):
    hdr(f"Fix checksums: {args.file}")
    data = Path(args.file).read_bytes()
    patcher = FirmwarePatcher(data)
    ok(f"Detected vendor: {patcher.vendor}")
    fixes = patcher.fix_all()
    if fixes:
        for f in fixes:
            ok(f"Fix: {f}")
        patcher.write(args.output or f"fixed_{Path(args.file).name}")
    else:
        warn("No fixes applied")


# == ATA security helpers =====================================================


def cmd_ata_sec_status(args):
    hdr("ATA Security Status (from IDENTIFY DEVICE)")
    sec = ATASecurityCommands.parse_security_status(bytes(512))
    if sec.get("frozen"):
        ok("Drive is frozen (normal for OS-attached drives)")
    if sec.get("locked"):
        warn("Drive is locked -- supply password to unlock")


# == NVMe helpers =============================================================


def cmd_nvme_identify(args):
    hdr("NVMe Identify Controller")
    cmd = NVMeAdminPassthrough.identify_ctrlr()
    info(f"Send via: nvme admin-passthrough /dev/nvme{args.device} --opcode={cmd.opcode} ...")


def cmd_nvme_smart(args):
    hdr("NVMe SMART Log")
    NVMeAdminPassthrough.get_smart_log()
    info(f"Parsed SMART fields: {list(NVMeAdminPassthrough.parse_smart_log(bytes(512)).keys())}")
    info(f"Send via: nvme get-log /dev/nvme{args.device} --log-id=2 -l 512")


def cmd_nvme_fw_dl(args):
    hdr(f"NVMe Firmware Download: {args.file}")
    fw_data = Path(args.file).read_bytes()
    cmd = NVMeAdminPassthrough.firmware_download(args.offset or 0, fw_data)
    info(f"Offset: {cmd.cdw11} dwords,  Size: {len(cmd.data)} bytes ({len(cmd.data) // 4} dwords)")
    info(
        f"Send via: nvme fw-download /dev/nvme{args.device} --fw={args.file} --offset={args.offset}"
    )


def cmd_nvme_fw_activate(args):
    hdr(f"NVMe Firmware Activate: slot {args.slot}")
    NVMeAdminPassthrough.firmware_activate(args.slot, args.action)
    actions = {1: "replace", 2: "replace+enable", 3: "replace+enable+reset"}
    info(f"Action: {actions.get(args.action, '=')}  Slot: {args.slot}")
    info(
        f"Send via: nvme fw-activate /dev/nvme{args.device} --slot={args.slot} --action={args.action}"
    )
    warn("Drive will reset if action=3")


def cmd_nvme_vendor(args):
    hdr(f"NVMe Vendor Cmd: opcode=0x{args.opcode:02X}")
    info(f"cdw10=0x{args.cdw10:08X} cdw11=0x{args.cdw11:08X} data_len={args.data_len}")
    cmd = NVMeAdminPassthrough.vendor_specific(
        args.opcode, args.cdw10, args.cdw11, data_len=args.data_len
    )
    info(f"Send via: nvme admin-passthrough /dev/nvme{args.device} --opcode=0x{cmd.opcode:02X}")


def cmd_nvme_live_identify(args):
    """
    Read and parse Identify Controller data from a live NVMe device.
    Opens /dev/nvme{device}, sends IDENTIFY controller, and dumps key fields.
    """
    try:
        device = int(args.device)
    except ValueError:
        device = args.device
    hdr(f"NVMe Live Identify Controller: /dev/nvme{device}")
    cmd = NVMeAdminPassthrough.identify_ctrlr()
    try:
        data = NVMeAdminPassthrough.execute_admin_cmd(device, cmd)
    except OSError as e:
        err(f"ioctl failed: {e}")
        if e.errno == 1:
            info("Try: sudo hdd-firmware-toolkit nvme-live-identify 0")
        return
    parsed = NVMeAdminPassthrough.parse_identify_ctrlr(data)
    for k, v in parsed.items():
        info(f"  {k}: {v}")
    if args.hex:
        for line in _hex_dump(data[:256]).split("\n"):
            info(line)


def cmd_nvme_live_smart(args):
    """
    Read and parse SMART/Health log from a live NVMe device.
    """
    hdr(f"NVMe Live SMART Log: /dev/nvme{args.device}")
    cmd = NVMeAdminPassthrough.get_smart_log()
    try:
        data = NVMeAdminPassthrough.execute_admin_cmd(args.device, cmd)
    except OSError as e:
        err(f"ioctl failed: {e}")
        if e.errno == 1:
            info("Try: sudo hdd-firmware-toolkit nvme-live-smart 0")
        return
    parsed = NVMeAdminPassthrough.parse_smart_log(data)
    for k, v in parsed.items():
        unit = "K" if k in ("data_units_read", "data_units_written") else ""
        info(f"  {k}: {v}{unit}")
    if args.hex:
        for line in _hex_dump(data).split("\n"):
            info(line)


def cmd_nvme_live_get_log(args):
    """
    Read a raw log page from a live NVMe device and optionally parse it.
    Supports standard (0x00-0x7F) and vendor-specific (0xC0-0xFF) log pages.
    """
    hdr(f"NVMe Live Get Log Page 0x{args.log_id:02X}: /dev/nvme{args.device}")
    size = int(args.size, 0) if args.size else 512
    cmd = NVMeAdminPassthrough.get_log_page(args.log_id, size=size)
    try:
        data = NVMeAdminPassthrough.execute_admin_cmd(args.device, cmd)
    except OSError as e:
        err(f"ioctl failed: {e}")
        if e.errno == 1:
            info(
                f"Try: sudo hdd-firmware-toolkit nvme-live-get-log 0x{args.log_id:02X} --device 0"
            )
        return
    ok(f"Read {len(data)} bytes from log 0x{args.log_id:02X}")
    if args.log_id in (0xC0,) and len(data) >= 512:
        parsed = SanDiskNVMeVSC.parse_c0_eol_log(data)
        for k, v in parsed.items():
            info(f"  {k}: {v}")
    elif args.log_id in (0xCA,) and len(data) >= 160:
        parsed = SanDiskNVMeVSC.parse_ca_device_info_log(data)
        for k, v in parsed.items():
            info(f"  {k}: {v}")
    elif args.log_id in (0xD0,) and len(data) >= 512:
        parsed = SanDiskNVMeVSC.parse_d0_vu_smart_log(data)
        for k, v in parsed.items():
            info(f"  {k}: {v}")
    for line in _hex_dump(data).split("\n"):
        info(line)


def cmd_nvme_live_fw_log(args):
    """Read and parse Firmware Slot Information log from a live NVMe device."""
    hdr(f"NVMe Live Firmware Slots: /dev/nvme{args.device}")
    cmd = NVMeAdminPassthrough.get_firmware_slot_log()
    try:
        data = NVMeAdminPassthrough.execute_admin_cmd(args.device, cmd)
    except OSError as e:
        err(f"ioctl failed: {e}")
        return
    parsed = NVMeAdminPassthrough.parse_firmware_slot_log(data)
    info(f"Active slot: {parsed['active_slot']}")
    info(f"Next reset slot: {parsed['next_reset_slot']}")
    for s in parsed["slots"]:
        info(f"  Slot {s['slot']}: {s['revision']}")


def cmd_nvme_live_send(args):
    """
    Send a raw NVMe admin command to a live device and display result.
    Specify opcode, cdw10-15, and data_len.  For write commands, provide a file.
    """
    hdr(f"NVMe Live Send: opcode=0x{args.opcode:02X} on /dev/nvme{args.device}")
    payload = Path(args.file).read_bytes() if args.file else b""
    is_write = bool(payload)
    cmd = NVMeAdminPassthrough.vendor_specific(
        args.opcode,
        cdw10=args.cdw10,
        cdw11=args.cdw11,
        cdw12=args.cdw12,
        cdw13=args.cdw13,
        data_len=len(payload) if not is_write else 0,
        data=payload,
        is_write=is_write,
        nsid=args.nsid,
    )
    try:
        data = NVMeAdminPassthrough.execute_admin_cmd(args.device, cmd)
    except OSError as e:
        err(f"ioctl failed: {e}")
        if e.errno == 1:
            info(f"Try: sudo hdd-firmware-toolkit nvme-live-send 0x{args.opcode:02X} --device 0")
        return
    if is_write:
        result = struct.unpack("<I", data)[0]
        ok(f"Command completed, result=0x{result:08X}")
    else:
        ok(f"Read {len(data)} bytes")
        for line in _hex_dump(data[: min(len(data), 512)]).split("\n"):
            info(line)


def cmd_sandisk_live_sniff(args):
    """
    Detect SanDisk/WD NVMe drive on a live device by reading Identify Controller
    data and checking VID/DID against the known device database.
    """
    hdr(f"SanDisk/WD Live Detection: /dev/nvme{args.device}")
    try:
        id_data = NVMeAdminPassthrough.execute_admin_cmd(
            args.device, NVMeAdminPassthrough.identify_ctrlr()
        )
    except OSError as e:
        err(f"ioctl failed: {e}")
        return
    result = SanDiskNVMeVSC.sniff_vendor_log_pages(id_data)
    if not result:
        vid = struct.unpack_from("<H", id_data, 0)[0]
        err(f"VID 0x{vid:04X} is not a known SanDisk/WD vendor ID")
        return
    info(f"Vendor: {result['vendor']}  Family: {result['family']}")
    info(f"VID:DID = 0x{result['vid']:04X}:0x{result['did']:04X}")
    for p in result["log_pages"]:
        info(f"  Log 0x{p['log_id']:02X}: {p['name']} ({p['size']} bytes)")
    # Try to read the first few vendor log pages
    for lp in result["log_pages"][:3]:
        try:
            lcmd = SanDiskNVMeVSC.build_get_log_page(lp["log_id"], lp["size"])
            ldata = NVMeAdminPassthrough.execute_admin_cmd(args.device, lcmd)
            ok(f"Read log 0x{lp['log_id']:02X}: {len(ldata)} bytes")
        except OSError:
            warn(f"Log 0x{lp['log_id']:02X} not accessible")


# == SanDisk/WD NVMe VSC helpers ==============================================


def cmd_sandisk_id(args):
    hdr("SanDisk/WD NVMe Identify")
    info(f"VID: 0x{SanDiskNVMeVSC.VID_SANDISK:04X} (SanDisk)")
    info(f"VID: 0x{SanDiskNVMeVSC.VID_WDC:04X}, 0x{SanDiskNVMeVSC.VID_WDC_2:04X} (WDC)")
    info(f"SN740 device IDs: {[hex(d) for d in SanDiskNVMeVSC.DID_SN740]}")
    info(f"SN560 device IDs: {[hex(d) for d in SanDiskNVMeVSC.DID_SN560]}")


def cmd_sandisk_sniff_logs(args):
    hdr("SanDisk/WD Vendor Log Page Detection")
    data = bytes(4096)
    struct.pack_into("<H", data, 0, SanDiskNVMeVSC.VID_SANDISK)
    struct.pack_into("<H", data, 2, 0x5015)
    result = SanDiskNVMeVSC.sniff_vendor_log_pages(data)
    if not result:
        err("Not a SanDisk/WD NVMe drive")
        return
    info(f"Vendor: {result['vendor']}  Family: {result['family']}")
    info(f"VID:DID = {result['vid']}:{result['did']}")
    for p in result["log_pages"]:
        info(f"  Log 0x{p['log_id']:02X}: {p['name']} ({p['size']} bytes)")


def cmd_sandisk_build_log(args):
    hdr("SanDisk/WD Build Vendor Log Command")
    log_id = int(args.log_id, 0)
    size = int(args.size, 0) if args.size else 512
    cmd = SanDiskNVMeVSC.build_get_log_page(log_id, size)
    info(f"GET LOG PAGE 0x{log_id:02X} size={size}")
    info(f"Send via: nvme get-log /dev/nvme{args.device} --log-id=0x{log_id:02X} -l {size}")
    if hasattr(args, "dump") and args.dump:
        info(f"Parsed log data: {cmd}")


def cmd_sandisk_build_vu(args):
    hdr("SanDisk/WD Build Vendor Admin Command")
    opcode = int(args.opcode, 0)
    cdw10 = int(args.cdw10, 0) if args.cdw10 else 0
    cdw11 = int(args.cdw11, 0) if args.cdw11 else 0
    SanDiskNVMeVSC.build_vu_admin_cmd(opcode, cdw10=cdw10, cdw11=cdw11)
    info(f"VU CMD: opcode=0x{opcode:02X} cdw10=0x{cdw10:08X} cdw11=0x{cdw11:08X}")
    info(f"Send via: nvme admin-passthrough /dev/nvme{args.device} --opcode=0x{opcode:02X}")


def cmd_sandisk_build_purge(args):
    hdr("SanDisk/WD Build Purge Command")
    cmd = SanDiskNVMeVSC.build_purge_cmd()
    info(f"opcode=0x{cmd.opcode:02X} cdw10=0x{cmd.cdw10:08X}")
    info("WARNING: Purge is destructive and may take minutes")
    info("Send via: nvme admin-passthrough /dev/nvme0 --opcode=0xDD --cdw10=0x0000000C")


def cmd_sandisk_build_resize(args):
    hdr("SanDisk/WD Build Drive Resize Command")
    new_size = int(args.size, 0)
    cmd = SanDiskNVMeVSC.build_drive_resize_cmd(new_size)
    info(f"Drive Resize: {new_size} sectors ({new_size * 512 / 1e9:.1f} GB)")
    info(f"opcode=0x{cmd.opcode:02X} cdw10=0x{cmd.cdw10:08X}")
    info(f"cdw11=0x{cmd.cdw11:08X} cdw12=0x{cmd.cdw12:08X}")


def cmd_sandisk_parse_c0(args):
    hdr("SanDisk/WD Parse 0xC0 EOL Status Log")
    data = Path(args.file).read_bytes()
    parsed = SanDiskNVMeVSC.parse_c0_eol_log(data)
    for k, v in parsed.items():
        info(f"  {k}: {v}")


def cmd_sandisk_parse_ca(args):
    hdr("SanDisk/WD Parse 0xCA Device Info Log")
    data = Path(args.file).read_bytes()
    parsed = SanDiskNVMeVSC.parse_ca_device_info_log(data)
    for k, v in parsed.items():
        info(f"  {k}: {v}")


def cmd_sandisk_parse_d0(args):
    hdr("SanDisk/WD Parse 0xD0 VU SMART Log")
    data = Path(args.file).read_bytes()
    parsed = SanDiskNVMeVSC.parse_d0_vu_smart_log(data)
    for k, v in parsed.items():
        info(f"  {k}: {v}")


# == USB bridge helpers =======================================================


def cmd_usb_identify(args):
    hdr("USB Bridge Identification")
    if args.vid and args.pid:
        bi = USBToSATABridge.identify_from_vid_pid(args.vid, args.pid)
        if bi:
            pass
        else:
            err(f"No bridge found for VID=0x{args.vid:04X} PID=0x{args.pid:04X}")
    elif args.inquiry:
        bi = USBToSATABridge.identify_from_inquiry(args.inquiry)


def cmd_usb_list(args):
    hdr("Known USB-to-SATA Bridge Chips")
    for bi in USBToSATABridge.BRIDGE_DB:
        ", ".join(bi.quirks) if bi.quirks else "--"


# == Data recovery helpers ====================================================


def cmd_dr_smart(args):
    hdr(f"SMART Quick Test: {args.drive}")
    SATADataRecoveryOps.smart_quick_test(args.drive)
    info("Real execution requires physical drive access")


def cmd_dr_identify(args):
    hdr(f"Identify Device: {args.drive}")
    parsed = SATADataRecoveryOps.identify_device(args.drive)
    for k, v in parsed.items():
        pass
    info("Real execution requires physical drive access")


def cmd_dr_native_max(args):
    hdr(f"Read Native Max: {args.drive}")
    SATADataRecoveryOps.read_native_max(args.drive)
    info("Simulated -- requires physical drive access for real result")


def cmd_dr_pattern(args):
    hdr(f"Defective Sector Pattern: LBA=0x{args.lba:X}")
    data = SATADataRecoveryOps.defective_sector_pattern_offset(args.lba, args.size)
    Path(args.output).write_bytes(data)
    ok(f"Wrote {len(data)} bytes -- {args.output}")


# == HPA/DCO helpers ===========================================================


def cmd_hpa_detect(args):
    hdr("HPA Detection (from IDENTIFY DEVICE data)")
    data = Path(args.file).read_bytes() if args.file else bytes(512)
    result = HPADCOAccess.detect_hpa_from_identify(data)
    active = result.get("hpa_active")
    if active is True:
        warn("HPA is active -- sectors hidden past current max")
    elif active is None:
        info("Cannot determine HPA from IDENTIFY alone; use READ NATIVE MAX command")


def cmd_hpa_build_cmd(args):
    hdr("Build HPA/DCO Command")
    if args.type == "read-native":
        HPADCOAccess.build_read_native_max_cmd(args.lba48)
    elif args.type == "set-max":
        HPADCOAccess.build_set_max_cmd(args.lba, args.persistent, args.lba48)
    elif args.type == "dco-identify":
        HPADCOAccess.build_dco_identify_cmd()
    elif args.type == "dco-set":
        info("DCO SET requires DCO data file (--dco-file)")
        return
    elif args.type == "dco-restore":
        HPADCOAccess.build_dco_restore_cmd()
    else:
        err(f"Unknown command type: {args.type}")
        return


def cmd_hpa_parse_dco(args):
    hdr("Parse DCO Feature Set Descriptor")
    data = Path(args.file).read_bytes()
    result = HPADCOAccess.parse_dco_data(data)
    for name, f_info in result.get("features", {}).items():
        status = "enabled" if f_info["enabled"] else "DISABLED"
        if not f_info["enabled"]:
            warn(f"  {name:<20} {status}")
        else:
            pass


# == NVMe timing side-channel helpers =========================================


def cmd_nvme_timing_baseline(args):
    hdr("NVMe Timing Baseline Estimation")
    import random

    random.seed(42)
    baseline_us = [random.gauss(50, 10) for _ in range(100)]
    NVMeTimingSideChannel.estimate_read_latency(baseline_us)


def cmd_nvme_timing_detect(args):
    hdr("NVMe Timing Contention Detection (simulated)")
    import random

    random.seed(42)
    baseline_us = [random.gauss(50, 10) for _ in range(100)]
    contested_us = [random.gauss(300, 80) for _ in range(100)]
    baseline = NVMeTimingSideChannel.estimate_read_latency(baseline_us)
    sample = NVMeTimingSideChannel.estimate_read_latency(contested_us)
    NVMeTimingSideChannel.detect_content_contention(baseline, sample)


def cmd_nvme_timing_gc(args):
    hdr("NVMe GC/Controller Timing Analysis (simulated)")
    import random

    random.seed(42)
    times = [random.gauss(50, 10) for _ in range(90)]
    times += [random.gauss(500, 100) for _ in range(10)]
    random.shuffle(times)
    NVMeTimingSideChannel.ctrl_timing_analysis(times)


# == eNVMe platform helpers ==================================================


def cmd_envme_dma(args):
    hdr("eNVMe DMA Attack Descriptor")
    eNVMeIntegration.build_dma_attack_cmd(int(args.host_addr, 0), args.size, args.direction)
    info("Real execution requires eNVMe platform on RK3588")


def cmd_envme_scan(args):
    hdr("eNVMe Host Memory Scan (modelled)")
    result = eNVMeIntegration.scan_host_memory(chunk_size=args.chunk, max_pages=args.pages)
    for region in result["host_regions"]:
        region["size"] // 1024
    info("Simulated -- requires physical DMA-capable NVMe device")


def cmd_envme_compat(args):
    hdr("eNVMe Platform Compatibility Check")
    data = Path(args.file).read_bytes() if args.file else bytes(4096)
    eNVMeIntegration.detect_platform_compatibility(data)


# == NVMe-oF helpers =========================================================


def cmd_nvmeof_check_kernel(args):
    hdr("NVMe-oF Kernel Vulnerability Check")
    result = NVMeOverFabrics.check_vulnerable_kernel(args.kernel)
    if result.get("vulnerable"):
        warn("Kernel vulnerable to CVE-2023-5178 NVMe-oF TCP double-free")


def cmd_nvmeof_build_icreq(args):
    hdr("NVMe-oF TCP ICReq Builder")
    NVMeOverFabrics.build_icreq(hdgst=args.hdgst, ddgst=args.ddgst, maxh2cdata=args.maxh2cdata)
    info("Send via TCP to NVMe-oF target port (usually 4420)")


def cmd_nvmeof_poc(args):
    hdr("CVE-2023-5178 Double-Free PoC Packet")
    NVMeOverFabrics.build_corrupt_icreq_poc()
    warn("This generates a malformed ICReq that triggers kmalloc-96 double-free")
    info("Requires Linux kernel < 6.8 with NVMe-oF TCP target enabled")


# == Firmware detection helpers ==============================================


def cmd_fwdetect_current(args):
    hdr("Firmware Detection via Current Draw Analysis")
    baseline = args.baseline if args.baseline else FirmwareDetection.CURRENT_BASELINE_MA
    current = args.current if args.current else FirmwareDetection.CURRENT_BASELINE_MA + 50
    result = FirmwareDetection.current_draw_anomaly(current, baseline)
    if result["likely_modified"]:
        warn("HIGH CONFIDENCE firmware modification detected via current draw")
    elif result["suspicious"]:
        warn("SUSPICIOUS current draw anomaly")


def cmd_fwdetect_timing(args):
    hdr("Firmware Detection via Timing Analysis")
    baseline = args.baseline if args.baseline else FirmwareDetection.TIMING_BASELINE_US
    import random

    random.seed(42)
    if args.modified:
        times = [random.gauss(25000, 5000) for _ in range(50)]
    else:
        times = [random.gauss(5000, 500) for _ in range(50)]
    result = FirmwareDetection.timing_anomaly(times, baseline)
    if result["likely_modified"]:
        warn("LIKELY MODIFIED firmware detected via timing analysis")


def cmd_fwdetect_verify(args):
    hdr("Firmware Checksum Verification")
    data = Path(args.file).read_bytes()
    vendor = args.vendor
    results = FirmwareDetection.verify_all_checksums(data, vendor)
    all_valid = True
    for result in results:
        if "error" in result:
            all_valid = False
        else:
            "OK" if result["checksum_valid"] else "INVALID"
            if not result["checksum_valid"]:
                all_valid = False
    if all_valid:
        ok("All checksums valid")
    else:
        warn("Some checksums are invalid -- firmware may be modified")


def cmd_fwdetect_report(args):
    hdr("Comprehensive Firmware Integrity Report")
    data = Path(args.file).read_bytes()
    vendor = args.vendor
    FirmwareDetection.integrity_report(data, vendor)


# == Samsung helpers ==========================================================


def cmd_samsung_memory_map(args):
    hdr("Samsung MEX Memory Map  (TheMissingManual)")
    M = SamsungMEXMap  # noqa: N806
    rows = [
        ("ATCM", f"0x{M.ATCM_BASE:08X}", "96-128 KB per core; mex1 sees SAFE ROM here"),
        ("BTCM", f"0x{M.BTCM_BASE:08X}", "8 MB shared by all three cores"),
        ("NCQ buffers", f"0x{M.NCQ_BASE:08X}", f"{M.NCQ_SLOTS} = 16 B (off-by-one vs spec's 32)"),
        ("SATA status", f"0x{M.SATA_STATUS_REG:08X}", "poll for COMINIT"),
        ("GPIO dir", f"0x{M.GPIO_DIR_REG:08X}", "bit=1 -- output"),
        ("GPIO val", f"0x{M.GPIO_VAL_REG:08X}", "read/write"),
        (
            "Flash pwr",
            f"0x{M.FLASH_PWR_REG:08X}",
            f"0x{M.FLASH_PWR_ON:X}=on  0x{M.FLASH_PWR_OFF:X}=off",
        ),
        (
            "DMA status/trigger",
            f"0x{M.DMA_BASE:08X}",
            f"trigger=0x{M.DMA_TRIGGER:X}; fire then sleep 1s",
        ),
        ("DMA SATA window", f"0x{M.DMA_SATA_WINDOW:08X}", "copy here -- exfiltrate via dd"),
        ("AES ctrl", f"0x{M.AES_BASE:08X}", "OR 0x10000 to encrypt; XTS-256 only"),
        ("AES key slot", f"0x{M.AES_KEY_SLOT:08X}", "64 bytes: key1||key2"),
        ("AES IV", f"0x{M.AES_IV:08X}", "16 bytes"),
        ("RNG", f"0x{M.RNG_BASE:08X}", "=32 random bytes at a time"),
        ("UART TX", f"0x{M.UART_TX:08X}", f"SAFE mode {M.UART_BAUD} 8N1 3.3V"),
        ("UART RX", f"0x{M.UART_RX:08X}", ""),
        ("Flash CH0 (MEX2)", f"0x{M.FLASH_CH_MEX2[0]:08X}", ""),
        ("Flash CH3 (MEX2)", f"0x{M.FLASH_CH_MEX2[3]:08X}", ""),
        ("Flash CH4 (MEX3)", f"0x{M.FLASH_CH_MEX3[0]:08X}", ""),
        ("Flash CH7 (MEX3)", f"0x{M.FLASH_CH_MEX3[3]:08X}", ""),
        ("Flash dispatch", f"0x{M.FLASH_DISPATCH:08X}", "dest selector"),
        ("Flash zone sel", f"0x{M.FLASH_ZONE_SEL:08X}", "zone + cmd (6=write, 7=read)"),
        ("Flash trigger", f"0x{M.FLASH_TRIGGER:08X}", "write 1 to start; auto-clears"),
        ("Enc ranges", f"0x{M.ENC_RANGES_ADDR:08X}", "ZEROED shortly after boot!"),
        ("Enc key material", f"0x{M.ENC_KEY_MAT_ADDR:08X}", "ZEROED shortly after boot!"),
        ("FTL loaded (MEX2)", f"0x{M.FTL_LOADED_MEX2:08X}", "bitarray: which FTL chunks in RAM"),
        ("JTAG IDCODE", f"0x{M.JTAG_KNOWN_IDCODE:08X}", "instruction 0x0E"),
    ]
    for name, addr, notes in rows:
        pass


def cmd_samsung_fw_history(args):
    hdr("Samsung 840 EVO Firmware Version History")
    for ver, date, notes in SAMSUNG_840_EVO_FW_HISTORY:
        pass
    info("Packaging: ISO -- isolinux/btdsk.img -- samsung/DSRD/FW/<ver>/<VER>.enc")
    info("Decrypt .enc with samsung_decode() (nibble-swap on high nibble)")
    info("Updater EXE packed with WDOSX; unpack with WDOSXUnpacker.py (Python 2.7)")


def _ocd_args(args):
    return OpenOCDBridge(args.host, args.port)


def cmd_samsung_gpio(args):
    with _ocd_args(args) as ocd:
        SamsungGPIO(ocd).print_status()


def cmd_samsung_ncq(args):
    with _ocd_args(args) as ocd:
        SamsungNCQParser(ocd).print_slots()
        if args.output:
            slots = SamsungNCQParser(ocd).dump()
            Path(args.output).write_text(
                "\n".join(
                    f"slot={s['slot']} cmd={s['cmd']:#04x} lba={s['lba']:#018x} raw={s['raw']}"
                    for s in slots
                )
            )
            ok(f"Saved to {args.output}")


def cmd_samsung_aes_info(args):
    with _ocd_args(args) as ocd:
        SamsungAESInfo(ocd).print_aes_info()


def cmd_samsung_dma_dump(args):
    hdr(f"Samsung DMA Dump: 0x{int(args.addr, 0):08X}  size={args.size}")
    with _ocd_args(args) as ocd:
        helper = SamsungDMAHelper(ocd)
        helper.copy_to_sata_window(int(args.addr, 0), args.size)
        if args.sata_dev:
            out = args.output or f"dma_dump_{int(args.addr, 0):08X}.bin"
            sectors = (args.size + 511) // 512
            import subprocess

            subprocess.run(
                ["dd", f"if={args.sata_dev}", f"of={out}", "bs=512", f"count={sectors}"],
                check=True,
            )
            ok(f"Saved {sectors * 512} bytes -- {out}")


def cmd_samsung_ftl_preload(args):
    with _ocd_args(args) as ocd:
        SamsungDMAHelper(ocd).preload_ftl_map(args.sata_dev, args.size_gb)


def cmd_samsung_flash_read(args):
    hdr(
        f"Samsung Flash Read: ch{args.channel} "
        f"block=0x{int(args.block, 0):X} page=0x{int(args.page, 0):X}"
    )
    mem_addr = int(args.mem_addr, 0) if args.mem_addr else SamsungMEXMap.DMA_SATA_WINDOW
    with _ocd_args(args) as ocd:
        ch = SamsungFlashChannel(ocd, args.channel)
        ch.read_page(int(args.block, 0), int(args.page, 0), mem_addr=mem_addr)
        if args.sata_dev:
            out = args.output or f"flash_ch{args.channel}_b{int(args.block,0):X}_p{int(args.page,0):X}.bin"
            sectors = 16
            import subprocess
            subprocess.run(
                ["dd", f"if={args.sata_dev}", f"of={out}", "bs=512", f"count={sectors}"],
                check=True,
            )
            ok(f"Saved {sectors * 512} bytes -- {out}")


def cmd_samsung_flash_write(args):
    hdr(
        f"Samsung Flash Write: ch{args.channel} "
        f"block=0x{int(args.block, 0):X} page=0x{int(args.page, 0):X}"
    )
    mem_addr = int(args.mem_addr, 0)
    with _ocd_args(args) as ocd:
        ch = SamsungFlashChannel(ocd, args.channel)
        ch.write_page(int(args.block, 0), int(args.page, 0), mem_addr=mem_addr)


def cmd_samsung_flash_erase(args):
    hdr(f"Samsung Flash Erase: ch{args.channel} block=0x{int(args.block, 0):X}")
    with _ocd_args(args) as ocd:
        ch = SamsungFlashChannel(ocd, args.channel)
        ch.erase_block(int(args.block, 0))


def cmd_samsung_flash_integrity(args):
    hdr(f"Samsung Flash Integrity Check: ch{args.channel}")
    with _ocd_args(args) as ocd:
        ch = SamsungFlashChannel(ocd, args.channel)
        ch.check_integrity()


def cmd_samsung_safe_shell(args):
    with SamsungSafeUARTClient(args.port) as uart:
        uart.interactive_shell()


def cmd_samsung_safe_read(args):
    addr = int(args.addr, 0)
    with SamsungSafeUARTClient(args.port) as uart:
        if args.size and args.size > 4:
            data = uart.read_range(addr, args.size)
            if args.output:
                Path(args.output).write_bytes(data)
                ok(f"Saved {len(data)} bytes -- {args.output}")
        else:
            uart.read_word(addr)


def cmd_samsung_safe_write(args):
    addr = int(args.addr, 0)
    value = int(args.value, 0)
    with SamsungSafeUARTClient(args.port) as uart:
        uart.write_word(addr, value)
        ok(f"Wrote 0x{value:08X} -- 0x{addr:08X}")
        if args.verify:
            rb = uart.read_word(addr)
            if rb == value:
                ok(f"Verified: 0x{addr:08X} = 0x{rb:08X} =")
            else:
                err(f"Mismatch: expected 0x{value:08X} got 0x{rb:08X}")


def cmd_parse_firmware(args):
    hdr(f"Parse firmware: {args.file}")
    data = Path(args.file).read_bytes()
    if args.format == "wd":
        parser = WDFirmwareParser(data)
        ok(
            f"Magic: {parser.magic.hex()}, Version: {parser.version}, Sections: {len(parser.sections)}"
        )
        for sec in parser.sections:
            pass
    elif args.format == "samsung":
        parser = SamsungFirmwareParser()
        info = parser.parse(data)
        ok(f"Entries: {info.get('entry_count', 0)}, FTL blobs: {info.get('ftl_count', 0)}")
        for k, v in info.items():
            if isinstance(v, (bytes, list)):
                pass
            else:
                pass
        nibble_swapped = info.get("nibble_swapped", False)
        if nibble_swapped:
            warn("Nibble-swapped -- use decode-samsung first")
    if args.extract:
        out = Path(args.extract)
        out.mkdir(exist_ok=True)
        if args.format == "wd":
            for i, sec in enumerate(parser.sections):
                fname = out / f"wd_sec{i:02X}_{sec.load_addr:08X}.bin"
                fname.write_bytes(parser.section_data(sec))
                ok(f"Wrote {fname}")
        else:
            for i, (k, v) in enumerate(info.items()):
                if isinstance(v, bytes):
                    fname = out / f"samsung_{k.replace(' ', '_')}.bin"
                    fname.write_bytes(v)
                    ok(f"Wrote {fname}")


def cmd_decode_samsung(args):
    hdr(f"Samsung Deobfuscate: {args.file}")
    data = Path(args.file).read_bytes()
    decoded = samsung_decode(data)
    out = args.output or (args.file + ".decoded")
    Path(out).write_bytes(decoded)
    ok(f"Decoded {len(decoded)} bytes -- {out}")


def cmd_wd100x_parse(args):
    hdr(f"Parse WD100x ROM: {args.file}")
    data = Path(args.file).read_bytes()
    image = parse_wd100x_rom(
        data,
        segment_size=args.segment_size,
        require_aligned=args.require_aligned,
    )
    ok(
        f"Image size: {image.total_size} bytes, "
        f"segment_size: 0x{image.segment_size:X}, "
        f"segments: {len(image.segments)}"
    )
    info(f"Image SHA256: {image.image_sha256}")

    if args.extract:
        out = Path(args.extract)
        out.mkdir(parents=True, exist_ok=True)
        for seg in image.segments:
            name = f"wd100x_seg{seg.index:02d}_offset{seg.offset:06X}.bin"
            out_file = out / name
            out_file.write_bytes(seg.data)
            ok(f"Wrote {out_file}")


def cmd_scan_strings(args):
    hdr(f"String Scan: {args.file}")
    data = Path(args.file).read_bytes()
    strings = scan_strings(data, min_len=args.min_len)
    for offset, s in strings:
        pass
    ok(f"Found {len(strings)} strings")


def cmd_scan_fptables(args):
    hdr(f"Function-Pointer Table Scan: {args.file}")
    data = Path(args.file).read_bytes()
    base = int(args.base, 0) if args.base else 0
    tables = find_arm_function_tables(data, base, args.min_entries)
    for t in tables:
        pass
    ok(f"Found {len(tables)} candidate tables")


def cmd_diff(args):
    hdr(f"Firmware Diff: {args.file_a}  vs  {args.file_b}")
    a = Path(args.file_a).read_bytes()
    b = Path(args.file_b).read_bytes()
    diffs = diff_firmware(a, b)
    if not diffs:
        ok("Files are identical")
        return
    for offset, old, new in diffs:
        if old:
            pass
        if new:
            pass
    ok(
        f"{len(diffs)} differing region(s), "
        f"total {sum(max(len(o), len(n)) for o, n in [(d[1], d[2]) for d in diffs])} bytes"
    )


def cmd_list_vscs(args):
    hdr(f"List VSCs: {args.drive}")
    with ATADevice(args.drive) as dev:
        vsc = WDVSCClient(dev)
        vsc.list_vscs()


def cmd_read_ram(args):
    hdr(f"Read RAM: {args.drive}  addr=0x{int(args.addr, 0):08X}  size={args.size}")
    with ATADevice(args.drive) as dev:
        vsc = WDVSCClient(dev)
        data = vsc.read_ram(int(args.addr, 0), args.size)
    if args.output:
        Path(args.output).write_bytes(data)
        ok(f"Saved to {args.output}")


def cmd_write_ram(args):
    hdr(f"Write RAM: {args.drive}  addr=0x{int(args.addr, 0):08X}")
    data = Path(args.file).read_bytes()
    info(f"Writing {len(data)} bytes=")
    with ATADevice(args.drive) as dev:
        vsc = WDVSCClient(dev)
        vsc.write_ram(int(args.addr, 0), data)
    ok("Write complete")


def cmd_hot_patch(args):
    config = HotPatchConfig(args.config)
    drive = args.drive or config.drive
    if not drive:
        err("No drive specified (pass --drive or set 'drive:' in config)")
        sys.exit(1)
    success = deploy_hot_patch(drive, config)
    sys.exit(0 if success else 1)


def cmd_benchmark(args):
    before_avg = benchmark_reads(args.drive, int(args.sector, 0), args.iterations)
    if args.patch_config:
        config = HotPatchConfig(args.patch_config)
        deploy_hot_patch(args.drive, config)
        info("\nRe-running benchmark with patch active=")
        after_avg = benchmark_reads(args.drive, int(args.sector, 0), args.iterations)
        after_avg - before_avg
        hdr("Summary")


def cmd_dump_overlay(args):
    hdr(f"Dump Overlay: drive={args.drive}  module=0x{int(args.module, 0):02X}")
    with ATADevice(args.drive) as dev:
        vsc = WDVSCClient(dev)
        data = vsc.read_overlay(int(args.module, 0))
    if not data:
        warn("Empty response")
        return
    out = args.output or f"overlay_{int(args.module, 0):03X}.bin"
    Path(out).write_bytes(data)
    ok(f"Wrote {len(data)} bytes -- {out}")


def cmd_dump_all_overlays(args):
    dump_all_overlays(args.drive, args.out_dir, args.max_module)


def cmd_jtag_shell(args):
    with OpenOCDBridge(args.host, args.port) as ocd:
        ocd.interactive_shell()


def cmd_jtag_dump(args):
    hdr(f"JTAG Memory Dump: 0x{int(args.addr, 0):08X}  size={args.size}")
    with OpenOCDBridge(args.host, args.port) as ocd:
        ocd.halt()
        data = ocd.dump_memory(int(args.addr, 0), args.size)
        ocd.resume()
    if data:
        out = args.output or f"memdump_{int(args.addr, 0):08X}.bin"
        Path(out).write_bytes(data)
        ok(f"Wrote {len(data)} bytes -- {out}")
    else:
        warn("No data returned - check OpenOCD host for the dump file")


def cmd_jtag_bp(args):
    hdr(f"Set Breakpoint: 0x{int(args.addr, 0):08X}")
    with OpenOCDBridge(args.host, args.port) as ocd:
        ocd.set_bp(int(args.addr, 0))


def cmd_jtag_regs(args):
    hdr("Read CPU Registers")
    with OpenOCDBridge(args.host, args.port) as ocd:
        ocd.halt()
        regs = ocd.read_regs()
        ocd.resume()
    for name, val in regs.items():
        pass


# == Seagate F3 Service Area commands =========================================


def cmd_seagate_sa_read(args):
    hdr(f"Seagate SA Read: drive={args.drive}  module=0x{int(args.module, 0):02X}")
    with ATADevice(args.drive) as dev:
        client = SeagateF3SCTClient(dev)
        data = client.read_module(int(args.module, 0))
    if not data or all(b == 0xFF for b in data):
        warn("Empty response -- module may not exist on this drive")
        return
    out = args.output or f"seagate_sa_{int(args.module, 0):02X}.bin"
    Path(out).write_bytes(data)
    ok(f"Wrote {len(data)} bytes -- {out}")
    hexdump(data[:256])


def cmd_seagate_sa_write(args):
    hdr(f"Seagate SA Write: drive={args.drive}  module=0x{int(args.module, 0):02X}")
    data = Path(args.file).read_bytes()
    info(f"Writing {len(data)} bytes to module 0x{int(args.module, 0):02X}")
    with ATADevice(args.drive) as dev:
        client = SeagateF3SCTClient(dev)
        client.write_module(int(args.module, 0), data)
    ok("Write complete")


def cmd_seagate_sa_dump(args):
    hdr(f"Seagate SA Dump: drive={args.drive}  max_module=0x{args.max_module:02X}")
    out_path = Path(args.out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    with ATADevice(args.drive) as dev:
        client = SeagateF3SCTClient(dev)
        modules = client.list_modules(args.max_module)
    for mod_id, data in modules.items():
        fname = out_path / f"seagate_sa_{mod_id:02X}.bin"
        fname.write_bytes(data)
        ok(f"Mod 0x{mod_id:02X}: {len(data)} B -- {fname.name}")
    ok(f"Dumped {len(modules)} modules -- {out_path}/")


def cmd_seagate_sa_info(args):
    hdr("Seagate F3 Service Area Module Reference")
    rows = [
        (SeagateSAModule.ROM_RESIDENT_0, "ROM-resident module 0 (always loaded at power-on)"),
        (SeagateSAModule.ROM_RESIDENT_1, "ROM-resident module 1 (always loaded)"),
        (SeagateSAModule.PHYSICAL_OVERLAY_0, "Physical Overlay File 0"),
        (SeagateSAModule.PHYSICAL_OVERLAY_1, "Physical Overlay File 1"),
        (SeagateSAModule.PHYSICAL_OVERLAY_2, "Physical Overlay File 2"),
        (SeagateSAModule.CONGEN_XML, "Packed CONGEN XML drive personality definition"),
    ]
    for mod, desc in rows:
        info(f"  MOD 0x{mod:02X}  {desc}")


def cmd_wd_sa_info(args):
    hdr("WD ROYL SA-to-ROM Module Map")
    info("SA Module  ROM Module  Description")
    descs = {
        0x102: "head map",
        0x103: "(no standard name)",
        0x104: "identity",
        0x105: "(no standard name)",
        0x106: "(no standard name)",
        0x107: "module directory",
        0x109: "header + ROM code + MOD templates",
    }
    for sa_mod, rom_mod in WD_SA_ROM_MAP.items():
        rom_str = f"ROM 0x{rom_mod:02X}" if rom_mod is not None else "no single ROM counterpart"
        info(f"  SA 0x{sa_mod:03X}  {rom_str:<18}  {descs.get(sa_mod, '')}")


# == Seagate .lod commands ====================================================


def cmd_parse_seagate(args):
    hdr(f"Parse Seagate .lod: {args.file}")
    data = Path(args.file).read_bytes()
    parser = SeagateFWLoader()
    sections = parser.parse(data)
    for s in sections:
        pass
    if args.extract:
        out = Path(args.extract)
        out.mkdir(exist_ok=True)
        for s in sections:
            fname = out / f"seagate_sec_{s.id:02X}_{s.load_addr:08X}.bin"
            fname.write_bytes(s.data)
            ok(f"Wrote {fname}")


# == Service Area commands ====================================================


def cmd_sa_probe(args):
    with ATADevice(args.drive) as dev:
        vsc = WDVSCClient(dev)
        ServiceArea.probe_sa_size(dev, vsc)


def cmd_sa_dump(args):
    ServiceArea.dump_sa(args.drive, args.out_dir, args.max_module)


def cmd_sa_hide(args):
    data = Path(args.file).read_bytes()
    with ATADevice(args.drive) as dev:
        vsc = WDVSCClient(dev)
        ServiceArea.hide_data_in_glist(dev, vsc, data, args.module)
        ok(f"Hidden {len(data)} bytes in SA module 0x{args.module:02X}")


def cmd_sa_extract(args):
    with ATADevice(args.drive) as dev:
        vsc = WDVSCClient(dev)
        data = ServiceArea.extract_hidden_data(dev, vsc, args.module)
    if data:
        out = args.output or f"sa_extract_{args.module:02X}.bin"
        Path(out).write_bytes(data)
        ok(f"Extracted {len(data)} bytes -- {out}")
        hexdump(data[:256])


# == Spare-sector forensics commands =========================================


def cmd_sa_scan_spare(args):
    hdr("Spare-Sector Forensic Scanner")
    identify_data = Path(args.identify).read_bytes() if args.identify else bytes(512)
    native_max = args.native_max if args.native_max is not None else 0
    glist_entries = []
    if args.glist:
        import json as _json

        glist_entries = _json.loads(Path(args.glist).read_text())
    vsc_max = args.vsc_max if args.vsc_max is not None else None

    report = SpareSectorForensics.forensic_report(
        identify_data=identify_data,
        native_max_lba=native_max,
        glist_entries=glist_entries,
        vsc_max_lba=vsc_max,
    )
    verdict = report["verdict"]
    if verdict == "suspicious":
        warn(f"SUSPICIOUS: flags={report['flags']}")
    else:
        ok("No spare-sector anomalies detected")

    hc = report["hidden_capacity"]
    if hc.get("hidden_sectors", 0) > 0:
        warn(
            f"Hidden capacity: {hc['hidden_sectors']} sectors "
            f"({hc['hidden_bytes'] / 1024:.1f} KB)"
        )
    gl = report["glist"]
    info(f"G-list entries: {gl['entry_count']}  verdict: {gl['verdict']}")
    for rng in report["hidden_ranges"].get("hidden_ranges", []):
        info(
            f"  Hidden range [{rng['type']}]: "
            f"LBA 0x{rng['start_lba']:X}-0x{rng['end_lba']:X} "
            f"({rng['sector_count']} sectors)"
        )


# == Firmware read-back capability probe =====================================


def cmd_fw_readback_probe(args):
    hdr("Firmware Read-Back Capability Probe")
    result = FirmwareDetection.fw_readback_capability(
        has_jtag=args.jtag,
        has_spi_clip=args.spi_clip,
        has_vsc_readback=args.vsc,
        drive_type=args.drive_type,
    )
    cap = result["capability"]
    if cap == "full":
        ok(f"Read-back capability: FULL  paths={result['paths']}")
    elif cap == "partial":
        warn(f"Read-back capability: PARTIAL  paths={result['paths']}")
    else:
        warn(f"Read-back capability: BLIND  reason: {result['blind_reason']}")
    info(f"Applicable detection methods: {result['detection_methods']}")


# == SPI flash CSV decode commands ============================================


def cmd_spi_decode_csv(args):
    hdr(f"SPI Flash CSV Decode: {args.csv_file}")
    csv_text = Path(args.csv_file).read_text()
    info_obj = SPIFlashCapture.decode_csv(csv_text)

    if info_obj.jedec_id:
        jedec = SPIFlashCapture.parse_jedec_id(info_obj.jedec_id)
        ok(
            f"JEDEC ID: {info_obj.jedec_id.hex().upper()}  "
            f"Mfr: {jedec['manufacturer']}  "
            f"Capacity: {jedec['capacity_kb']} KB"
        )
    else:
        warn("No JEDEC ID found in capture")

    if info_obj.firmware_blob:
        out = args.output or "dump.bin"
        Path(out).write_bytes(info_obj.firmware_blob)
        ok(f"Firmware blob: {len(info_obj.firmware_blob)} bytes  SHA-1: {info_obj.sha1}")
        ok(f"Written to {out}")
    else:
        warn("No firmware data found in capture")

    info(f"Transactions decoded: {len(info_obj.transactions)}")


# == ISSP PSoC commands =======================================================


def cmd_psoc_sync(args):
    hdr("ISSP Synchronisation Sequence")
    engine = ISSPEngine()
    vectors = engine.sync_sequence()
    info(f"Entry sequence: {len(vectors)} vectors")
    for i, v in enumerate(vectors[:8]):
        info(f"  [{i}] 0x{v.bits:06X}  bits={v.length}")
    if len(vectors) > 8:
        info(f"  ... ({len(vectors) - 8} more vectors)")
    ok("Sync sequence built (send after XRES release + magic on SDATA)")


def cmd_psoc_read_sec(args):
    hdr("ISSP Read Security Byte Table")
    engine = ISSPEngine()
    vectors = engine.read_security_data()
    info(f"Security read sequence: {len(vectors)} vectors")
    for i, v in enumerate(vectors[:4]):
        info(f"  [{i}] opcode=0x{(v.bits >> 18) & 0xF:X}  addr=0x{(v.bits >> 10) & 0xFF:02X}")
    ok("Security table read vectors built")


def cmd_psoc_read_srom(args):
    hdr(f"ISSP SROM Call: fn=0x{args.fn:02X}")
    engine = ISSPEngine()
    vectors = engine.srom_call(args.fn)
    for i, v in enumerate(vectors):
        info(f"  [{i}] 0x{v.bits:06X}")
    ok(f"SROM call vectors built for fn=0x{args.fn:02X}")


def cmd_psoc_write_reg(args):
    hdr(f"ISSP Write Register: addr=0x{args.addr:02X}  data=0x{args.data:02X}")
    engine = ISSPEngine()
    vec = engine.write_reg(args.addr, args.data)
    info(f"Vector: 0x{vec.bits:06X}")
    ok("Write-register vector built")


# == PSoC cold-boot attack commands ===========================================


def cmd_psoc_locate_pin(args):
    hdr(f"Locate PIN in PSoC Flash Dump: {args.dump}")
    flash_bytes = Path(args.dump).read_bytes()
    attack = PSoCColdBoot()
    result = attack.locate_pin(flash_bytes, pin_length=args.pin_length)
    if result["found"]:
        ok(f"Found {len(result['candidates'])} PIN candidate(s):")
        for c in result["candidates"][:10]:
            ok(f"  offset=0x{c['offset']:04X}  PIN={c['pin']}")
    else:
        warn("No ASCII digit runs of expected length found in dump")


def cmd_psoc_dump_block(args):
    hdr(f"PSoC Flash Block Dump: {args.dump}  block={args.block}")
    flash_bytes = Path(args.dump).read_bytes()
    attack = PSoCColdBoot()
    result = attack.dump_block(flash_bytes, args.block, block_size=args.block_size)
    info(f"Block {result['block_index']}  offset=0x{result['start_offset']:04X}")
    info(f"  all_ff={result['all_ff']}  all_zero={result['all_zero']}")
    info(f"  hex: {result['hex'][:64]}{'...' if len(result['hex']) > 64 else ''}")


def cmd_i2c_diff(args):
    hdr("I2C Bus Capture Diff")
    import json as _json

    before = _json.loads(Path(args.before).read_text())
    after = _json.loads(Path(args.after).read_text())
    diffs = PSoCColdBoot.i2c_diff(before, after)
    if not diffs:
        ok("No I2C register differences detected")
        return
    ok(f"{len(diffs)} register change(s):")
    for d in diffs:
        info(
            f"  addr=0x{d.address:02X}  reg=0x{d.register:02X}  "
            f"0x{d.before:02X} -> 0x{d.after:02X}"
        )


# == Firmware update exploit commands =========================================


def cmd_fwexploit_send(args):
    payload = Path(args.payload).read_bytes()
    with ATADevice(args.drive) as dev:
        FirmwareUpdateExploit.send_offset_overflow(dev, payload, args.offset, args.subcmd)


def cmd_fwexploit_activate(args):
    with ATADevice(args.drive) as dev:
        FirmwareUpdateExploit.activate_firmware(dev)
    ok("Activate sent -- drive may reset or become unresponsive")


# == ASM2362 NVMe bridge command ==============================================


def cmd_nvme_bridge_sanitize(args):
    ASM2362NVMeBridge.inject_sanitize(None)
    ok("Sanitize command structure built (platform-specific TLP injection required)")


# == Patch template command ===================================================


def cmd_patch_template(args):
    hdr(f"Patch Template: {args.type}")
    if args.type == "nop-sled":
        code = PatchTemplates.build_nop_sled(args.size)
    elif args.type == "data-trap":
        if not args.addr:
            err("--addr required for data-trap")
            sys.exit(1)
        repl = Path(args.replacement).read_bytes() if args.replacement else b"\x00" * 4
        code = PatchTemplates.data_modification_trap(int(args.addr, 0), repl)
    elif args.type == "exfil-hook":
        if not args.addr:
            err("--addr required for exfil-hook")
            sys.exit(1)
        signal = args.fake_addr or "0xFFE00000"
        code = PatchTemplates.exfiltration_hook(int(args.addr, 0), int(signal, 0))
    elif args.type == "smart-redirect":
        addr = int(args.addr, 0) if args.addr else 0xBE
        fake = int(args.fake_addr, 0) if args.fake_addr else None
        code = PatchTemplates.smart_log_redirect(addr, fake)
    else:
        err(f"Unknown template: {args.type}")
        sys.exit(1)

    Path(args.output).write_bytes(code)
    ok(f"Wrote {len(code)} bytes -- {args.output}")


def cmd_fw_identity_check(args):
    hdr("Xbox 360 / HDDHackr Firmware Identity Spoof Check")
    identify_data = Path(args.identify).read_bytes() if args.identify else bytes(512)
    security_sector = Path(args.security_sector).read_bytes() if args.security_sector else None
    smart_data = Path(args.smart).read_bytes() if args.smart else None

    report = FirmwareIdentitySpoofDetector.forensic_report(
        identify_data=identify_data,
        security_sector=security_sector,
        smart_data=smart_data,
    )

    strings = report["strings"]
    info(f"Model    : {strings.get('model', '')}")
    info(f"Serial   : {strings.get('serial', '')}")
    info(f"FW Rev   : {strings.get('firmware_rev', '')}")

    if security_sector is not None:
        sec = report["security_sector"]
        if sec.get("detected"):
            warn(
                f"Xbox 360 security sector detected  magic={sec['magic_name']}  "
                f"serial={sec['serial']}  model={sec['model']}"
            )
            if sec.get("secret_initialized"):
                warn("  Xbox 360 HMAC secret is initialized (drive was used in a console)")
        else:
            ok("No Xbox 360 security sector magic found in provided sector data")

    spoof = report["spoof_check"]
    for indicator in spoof.get("indicators", []):
        warn(f"Spoof indicator: {indicator}")

    if report["smart_check"].get("mismatch"):
        sc = report["smart_check"]
        warn(
            f"SMART serial mismatch: IDENTIFY={sc['identify_serial']}  "
            f"SMART={sc['smart_serial']}"
        )

    verdict = report["verdict"]
    if verdict == "suspicious":
        warn(f"SUSPICIOUS: flags={report['flags']}")
    else:
        ok("No firmware identity spoofing indicators detected")


def cmd_hddss_info(args):
    hdr(f"HDDHackr hddss.bin: {args.file}")
    data = Path(args.file).read_bytes()
    result = HddhackrSectorFile.parse(data)
    if "error" in result:
        err(result["error"])
        return
    info(f"Valid    : {result['valid']}")
    info(f"Serial   : {result['serial']}")
    info(f"FW Rev   : {result['fw_rev']}")
    info(f"Model    : {result['model']}")
    info(f"Sectors  : {result['sector_count']}")
    info(f"Checksum : 0x{result['checksum']:04X} (expected 0x{HddhackrSectorFile.CHECKSUM_MAGIC:04X})")
    if result["valid"]:
        ok("Integrity check passed")
    else:
        warn("Integrity check FAILED (bad checksum or zero first word)")


def cmd_hddss_patch(args):
    hdr("HDDHackr firmware module 2 identity patch")
    hddss_data = Path(args.hddss).read_bytes()
    module2_data = Path(args.module2).read_bytes()
    parsed = HddhackrSectorFile.parse(hddss_data)
    if "error" in parsed:
        err(parsed["error"])
        return
    if not parsed["valid"]:
        warn("hddss.bin integrity check failed; proceeding anyway")
    result = HddhackrFirmwarePatcher.patch_all(
        module2=module2_data,
        current_serial=args.current_serial,
        current_model=args.current_model,
        current_count=args.current_count,
        new_serial=parsed["serial"],
        new_model=parsed["model"],
        new_count=parsed["sector_count"],
    )
    Path(args.output).write_bytes(result)
    info(f"New serial : {parsed['serial']}")
    info(f"New model  : {parsed['model']}")
    info(f"New sectors: {parsed['sector_count']}")
    ok(f"Patched module 2 written to {args.output}")


# =============================================================================
# TCG Opal / SED commands
# =============================================================================


def cmd_opal_discovery(args):
    hdr(f"TCG Opal Level 0 Discovery: {args.file}")
    data = Path(args.file).read_bytes()[:512]
    if len(data) < 48:
        data = data.ljust(512, b"\x00")
    result = TCGDiscovery0Parser.parse(data)
    info(f"SSC       : {result.ssc_name}")
    info(f"BaseComID : 0x{result.base_com_id:04X}")
    if result.tper:
        t = result.tper
        info(
            f"TPer      : sync={t.sync} async={t.async_} bufmgmt={t.buffer_mgmt} "
            f"comidmgmt={t.com_id_mgmt}"
        )
    if result.locking:
        lk = result.locking
        info(
            f"Locking   : supported={lk.locking_supported} enabled={lk.locking_enabled} "
            f"locked={lk.locked} mbr={lk.mbr_enabled} media_enc={lk.media_encryption}"
        )
    if result.geometry:
        g = result.geometry
        info(
            f"Geometry  : align={g.align} lbs={g.logical_block_size} "
            f"ag={g.alignment_granularity} lal={g.lowest_aligned_lba}"
        )
    if result.opal_v200:
        o = result.opal_v200
        info(
            f"Opal 2.0  : base_comid=0x{o.base_com_id:04X} "
            f"admins={o.num_locking_admin_auth} users={o.num_locking_user_auth}"
        )
    flags = []
    for attr in (
        "has_enterprise", "has_opal_v100", "has_single_user", "has_datastore",
        "has_block_sid", "has_opalite", "has_pyrite_v100", "has_pyrite_v200",
        "has_ruby", "has_data_removal",
    ):
        if getattr(result, attr):
            flags.append(attr.replace("has_", ""))
    if flags:
        info(f"Features  : {', '.join(flags)}")
    ok(f"Parsed {len(result.raw_features)} feature descriptor(s)")


def cmd_opal_start_session(args):
    from hdd_toolkit.ata.tcg_opal import TCGSession
    hdr(f"TCG Opal Build StartSession packet: com_id=0x{args.com_id:04X}")
    sp_uid = bytes.fromhex(args.sp_uid.replace(":", "").replace(" ", ""))
    packet = TCGSession.build_start_session(
        com_id=args.com_id,
        hsn=args.hsn,
        sp_uid=sp_uid,
        read_write=not args.read_only,
    )
    out = args.output or "start_session.bin"
    Path(out).write_bytes(packet)
    ok(f"Wrote {len(packet)} bytes -- {out}")
    hexdump(packet[:64])


# =============================================================================
# ATA Security Feature Set commands
# =============================================================================


def cmd_ata_security_check(args):
    hdr(f"ATA Security Feature Set Status: {args.file}")
    data = Path(args.file).read_bytes()
    status = ATASecurityStatus.from_identify(data)
    info(f"Status    : {status.describe()}")
    info(f"Raw word  : 0x{status.raw_word:04X}")
    bypass = ATAFrozenBypass.analyse(status)
    if bypass["bypass_options"]:
        warn(f"Bypass options: {', '.join(bypass['bypass_options'])}")
        for rec in bypass["recommendations"]:
            info(f"  {rec}")
    else:
        ok("No bypass options applicable")


def cmd_ata_security_build(args):
    from hdd_toolkit.ata.security import ATASecurityCmd, _build_password_sector
    cmd_map = {
        "freeze": ATASecurityCmd.SECURITY_FREEZE_LOCK,
        "unlock": ATASecurityCmd.SECURITY_UNLOCK,
        "set-password": ATASecurityCmd.SECURITY_SET_PASSWORD,
        "erase-prepare": ATASecurityCmd.SECURITY_ERASE_PREPARE,
        "erase-unit": ATASecurityCmd.SECURITY_ERASE_UNIT,
        "disable-password": ATASecurityCmd.SECURITY_DISABLE_PASSWORD,
    }
    cmd_code = cmd_map[args.operation]
    info(f"ATA Security command: {args.operation} (opcode 0x{cmd_code:02X})")

    if args.operation in ("unlock", "set-password", "erase-unit", "disable-password"):
        pw = args.password.encode() if args.password else b"\x00" * 32
        sector = _build_password_sector(master=args.master, password=pw)
        if args.output:
            Path(args.output).write_bytes(sector)
            ok(f"Password sector written to {args.output}")
        hexdump(sector[:64])
    else:
        ok(f"Command 0x{cmd_code:02X} takes no data payload")


# =============================================================================
# SCSI/SAS commands
# =============================================================================


def cmd_scsi_inquiry(args):
    hdr(f"SCSI INQUIRY: {args.device}")
    with SCSIDevice(args.device) as dev:
        data = dev.inquiry(evpd=args.evpd, page_code=args.page_code or 0)
    if args.output:
        Path(args.output).write_bytes(data)
        ok(f"Raw data saved to {args.output}")
    if not args.evpd:
        inq = SCSIInquiryData.parse(data)
        info(f"Device type : {inq.device_type_name}")
        info(f"Vendor      : {inq.vendor_id}")
        info(f"Product     : {inq.product_id}")
        info(f"Revision    : {inq.product_rev}")
        info(f"SPC version : {inq.spc_version}")
    else:
        hexdump(data[:128])


def cmd_scsi_read_capacity(args):
    hdr(f"SCSI READ CAPACITY: {args.device}")
    with SCSIDevice(args.device) as dev:
        if args.use_16:
            data = dev.read_capacity_16()
            cap = SCSICapacity.parse_16(data)
        else:
            data = dev.read_capacity_10()
            cap = SCSICapacity.parse_10(data)
    info(f"Last LBA    : {cap.last_lba} (0x{cap.last_lba:X})")
    info(f"Block size  : {cap.block_length} bytes")
    info(f"Capacity    : {cap.total_gb:.2f} GB ({cap.total_bytes} bytes)")


def cmd_scsi_ses(args):
    hdr(f"SCSI SES Enclosure Status: {args.device}")
    with SCSIDevice(args.device) as dev:
        data = dev.receive_diagnostic(page_code=0x02, alloc_len=4096)
    if args.output:
        Path(args.output).write_bytes(data)
        ok(f"Raw SES page saved to {args.output}")
    elements = parse_ses_enclosure_status(data)
    if not elements:
        warn("No SES element status descriptors found")
        return
    for e in elements:
        line = (
            f"  slot={e.slot_number:2d}  status={e.status_name:<16}  "
            f"disabled={e.disabled}  swap={e.swap}"
        )
        if e.status_code == 0x02:
            warn(line)
        elif e.status_code == 0x01:
            ok(line)
        else:
            info(line)
    ok(f"Parsed {len(elements)} element(s)")


def cmd_scsi_inquiry_cdb(args):
    hdr("Build SCSI INQUIRY CDB")
    cdb = build_inquiry_cdb(
        evpd=args.evpd, page_code=args.page_code or 0, alloc_len=args.alloc_len
    )
    info(f"CDB ({len(cdb)} bytes): {cdb.hex(' ')}")
    if args.output:
        Path(args.output).write_bytes(cdb)
        ok(f"Saved to {args.output}")


# =============================================================================
# NVMe HMB commands
# =============================================================================


def cmd_nvme_hmb_caps(args):
    hdr(f"NVMe HMB Capabilities: {args.file}")
    data = Path(args.file).read_bytes()
    caps = parse_hmb_caps_from_identify(data)
    if not caps["hmb_supported"]:
        warn("Host Memory Buffer NOT supported by this controller")
        return
    ok("Host Memory Buffer supported")
    info(f"HMMIN (minimum): {caps['hmmin_bytes']:,} bytes ({caps['hmmin_4k']} x 4 KiB)")
    info(f"HMPRE (preferred): {caps['hmpre_bytes']:,} bytes ({caps['hmpre_4k']} x 4 KiB)")


def cmd_nvme_hmb_attack(args):
    hdr("NVMe HMB Attack Surface Model")
    descriptors = []
    for spec in args.descriptors:
        parts = spec.split(":")
        if len(parts) != 2:
            err(f"Invalid descriptor spec '{spec}' (expected base:size_4k)")
            sys.exit(1)
        descriptors.append(
            HMBDescriptor(
                base_address=int(parts[0], 16),
                size_4k=int(parts[1], 0),
            )
        )
    alloc = HMBAllocation(descriptors=descriptors)
    model = HMBAttackModel(alloc)
    report = model.attack_report()

    info(
        f"Total HMB size  : {report['total_size_mb']:.2f} MB "
        f"({report['total_size_bytes']} bytes)"
    )
    info(f"Descriptor count: {report['region_count']}")
    for r in report["regions"]:
        info(
            f"  0x{r['base_address']:016X} -- 0x{r['end_address']:016X}"
            f"  ({r['size_bytes']:,} bytes)"
        )
    if report["risk_flags"]:
        warn(f"Risk flags: {', '.join(report['risk_flags'])}")
    risk = report["risk_level"]
    if risk == "high":
        warn(f"Overall risk: {risk.upper()}")
    else:
        info(f"Overall risk: {risk}")


def cmd_nvme_hmb_enable_cmd(args):
    hdr("Build NVMe SET FEATURES (HMB enable) command")
    from hdd_toolkit.nvme.hmb import build_hmb_enable_cmd as _build
    descriptors = [HMBDescriptor(base_address=args.base_addr, size_4k=args.size_4k)]
    alloc = HMBAllocation(descriptors=descriptors)
    cmd = _build(alloc, descriptor_list_addr=args.base_addr, mr=args.mr)
    info(f"Opcode  : 0x{cmd.opcode:02X} (SET FEATURES)")
    info(f"CDW10   : 0x{cmd.cdw10:08X} (FID=0x{cmd.cdw10:02X})")
    info(f"CDW11   : 0x{cmd.cdw11:08X} (EHM={cmd.cdw11 & 1} MR={(cmd.cdw11 >> 1) & 1})")
    info(f"CDW12   : 0x{cmd.cdw12:08X} (HSIZE={cmd.cdw12} x 4 KiB)")
    info(f"CDW13   : 0x{cmd.cdw13:08X} (HMDLAL low 32 bits)")
    info(f"CDW14   : 0x{cmd.cdw14:08X} (HMDLAU high 32 bits)")
    info(f"CDW15   : 0x{cmd.cdw15:08X} (HMDLEC={cmd.cdw15} descriptors)")
    ok("SET FEATURES HMB command built")


# =============================================================================
# RTL9210 bridge commands
# =============================================================================


def cmd_rtl9210_info(args):
    hdr("RTL9210B Bridge Capability Summary")
    report = RTL9210Bridge.probe_info()
    info(f"VID     : 0x{report['vid']:04X}")
    info(f"PID(s)  : {' '.join(f'0x{p:04X}' for p in report['pid_variants'])}")
    info(f"Opcodes : {list(report['vendor_opcodes'].keys())}")
    info(f"NVMe ASQ base : 0x{report['nvme_asq_xram_base']:04X}  depth={report['nvme_asq_depth']}")
    if not report["sig_check"]:
        warn("No firmware signature verification on SPI write (0xE3)")


def cmd_rtl9210_read_reg(args):
    hdr(f"RTL9210B XRAM read: addr=0x{int(args.addr, 0):04X} len={args.length}")
    cdb = RTL9210Bridge.build_read_register_cdb(int(args.addr, 0), args.length)
    info(f"CDB ({len(cdb)} bytes): {cdb.hex(' ')}")
    if args.output:
        Path(args.output).write_bytes(cdb)
        ok(f"Saved to {args.output}")


def cmd_rtl9210_write_reg(args):
    hdr(f"RTL9210B XRAM write: addr=0x{int(args.addr, 0):04X} value=0x{int(args.value, 0):02X}")
    cdb = RTL9210Bridge.build_write_register_cdb(int(args.addr, 0), int(args.value, 0))
    info(f"CDB ({len(cdb)} bytes): {cdb.hex(' ')}")
    if args.output:
        Path(args.output).write_bytes(cdb)
        ok(f"Saved to {args.output}")


def cmd_rtl9210_read_spi(args):
    hdr(f"RTL9210B SPI flash read: offset=0x{int(args.offset, 0):X} len={args.length}")
    cdb = RTL9210Bridge.build_read_spi_cdb(int(args.offset, 0), args.length)
    info(f"CDB ({len(cdb)} bytes): {cdb.hex(' ')}")
    if args.output:
        Path(args.output).write_bytes(cdb)
        ok(f"Saved to {args.output}")


def cmd_rtl9210_inject_sanitize(args):
    hdr(f"RTL9210B inject Sanitize Block Erase (XRAM slot {args.slot})")
    cmd = RTL9210Bridge.inject_sanitize(slot=args.slot)
    info(f"NVMe SQ entry ({len(cmd)} bytes): {cmd[:16].hex(' ')} ...")
    if args.output:
        Path(args.output).write_bytes(cmd)
        ok(f"Saved to {args.output}")


# =============================================================================
# ATA master password oracle commands
# =============================================================================


def cmd_ata_master_pw_oracle(args):
    hdr(f"ATA Master Password Oracle: {args.file}")
    data = Path(args.file).read_bytes()
    model = args.model or ""
    plan = ATAMasterPasswordOracle.oracle_plan(
        model_string=model,
        identify_data=data,
        erase_mode=args.erase_mode,
    )
    if "error" in plan:
        err(plan["error"])
        return
    info(f"Model          : {plan['model']}")
    info(f"Security level : {plan['security_level']}")
    info(f"Attempt count  : {plan['attempt_count']}")
    info(f"Safe to proceed: {plan['safe_to_proceed']}")
    for w in plan["warnings"]:
        warn(w)
    if not plan["trial_list"]:
        warn("No trial passwords available")
        return
    ok(f"Trial passwords ({len(plan['trial_list'])}):")
    for t in plan["trial_list"]:
        info(f"  [{t['label']}]  {t['notes']}")
        info(f"    password hex: {t['password_hex']}")


def cmd_ata_master_pw_detect(args):
    hdr(f"ATA Master Password Detection: model={args.model}")
    result = ATAMasterPasswordOracle.detect_default_master_pw(
        identify_data=bytes(512),
        model_string=args.model,
    )
    if result["likely_default"]:
        warn("Drive model matches known default master password pattern")
        top = result["top_candidate"]
        if top:
            info(f"Top candidate: [{top['label']}]")
            info(f"  Password hex: {top['password_hex']}")
            info(f"  Notes: {top['notes']}")
    else:
        ok("No default master password match found for this model")
    info(f"Total candidates: {len(result['all_candidates'])}")


# =============================================================================
# Volatile write cache fault analysis commands
# =============================================================================


def cmd_vwc_analyse(args):
    hdr(f"Volatile Write Cache Analysis: {args.file}")
    data = Path(args.file).read_bytes()
    result = WriteCacheFaultModel.analyse(data)
    info(f"Status: {result['description']}")
    info(f"Risk  : {result['risk_level'].upper()}")
    if result["attack_scenarios"]:
        warn(f"Attack scenarios: {', '.join(result['attack_scenarios'])}")
    for rec in result["recommendations"]:
        info(f"  {rec}")


def cmd_vwc_disable_cmd(args):
    hdr("ATA SET FEATURES 0x82 (disable volatile write cache)")
    regs = WriteCacheFaultModel.build_ata_disable_vwc_regs()
    info(f"ATA cmd=0x{regs['cmd']:02X} features=0x{regs['features']:02X}")
    ok("Issue this via ATA passthrough to disable the drive VWC")


def cmd_vwc_fault_plan(args):
    hdr(f"Power-Loss Fault Injection Plan: LBA=0x{int(args.lba, 0):X}")
    plan = plan_power_loss_fault(
        target_lba=int(args.lba, 0),
        write_count=args.count,
        power_cut_delay_ms=args.delay_ms,
        flush_before_cut=args.flush,
    )
    info(f"Target LBA         : 0x{plan.target_lba:X}")
    info(f"Write count        : {plan.write_count} sectors")
    info(f"Power cut delay    : {plan.power_cut_delay_ms:.1f} ms")
    info(f"Flush before cut   : {plan.flush_before_cut}")
    info(f"Expected outcome   : {plan.expected_outcome}")
    cache_mb = args.cache_mb if hasattr(args, "cache_mb") and args.cache_mb else 4
    rate_mb_s = args.rate_mb_s if hasattr(args, "rate_mb_s") and args.rate_mb_s else 100.0
    window = WriteCacheFaultModel.estimate_fault_window_ms(cache_mb, rate_mb_s)
    info(f"Estimated fault window ({cache_mb} MiB cache @ {rate_mb_s} MiB/s): {window:.1f} ms")


# =============================================================================
# Hitachi/HGST SA commands
# =============================================================================


def cmd_hitachi_sa_info(args):
    hdr("Hitachi/HGST Service Area interface summary")
    dev = object.__new__(type("_Stub", (), {"passthrough": lambda *a, **kw: b""}))
    client = HitachiVSCClient.__new__(HitachiVSCClient)
    client.dev = dev
    caps = client.probe_capabilities()
    info(f"Vendor           : {caps['vendor']}")
    info(f"SA cmd log       : {caps['sa_cmd_log']}")
    info(f"SA data log      : {caps['sa_data_log']}")
    info(f"Feat SA read     : {caps['feat_sa_read']}")
    info(f"Feat SA write    : {caps['feat_sa_write']}")
    info(f"Feat diag mode   : {caps['feat_diag_mode']}")
    info(f"Feat fw mode     : {caps['feat_fw_mode']}")
    info("Known SA modules:")
    for mod_id, mod_name in caps["known_modules"].items():
        info(f"  0x{mod_id:02X}  {mod_name}")
    info(caps["notes"])


def cmd_hitachi_sa_read(args):
    hdr(f"Hitachi SA read: drive={args.device}  module=0x{args.module:02X}")
    with ATADevice(args.device) as dev:
        client = HitachiVSCClient(dev)
        data = client.read_module(args.module)
    ok(f"Read {len(data)} bytes from module 0x{args.module:02X}")
    if args.output:
        Path(args.output).write_bytes(data)
        ok(f"Saved to {args.output}")
    else:
        hexdump(data[:256])


def cmd_hitachi_sa_write(args):
    hdr(f"Hitachi SA write: drive={args.device}  module=0x{args.module:02X}")
    data = Path(args.file).read_bytes()
    warn(f"About to write {len(data)} bytes to SA module 0x{args.module:02X}")
    with ATADevice(args.device) as dev:
        client = HitachiVSCClient(dev)
        client.write_module(args.module, data)
    ok(f"Wrote {len(data)} bytes to module 0x{args.module:02X}")


# =============================================================================
# Seagate F3 terminal commands
# =============================================================================


def cmd_seagate_f3_cmd(args):
    hdr("Seagate F3 terminal command builder")
    cmd_map = {
        "spin-up": SeagateF3Terminal.spin_up(),
        "spin-down": SeagateF3Terminal.spin_down(),
        "reset": SeagateF3Terminal.soft_reset(),
        "identity": SeagateF3Terminal.print_identity(),
        "p-list": SeagateF3Terminal.print_p_list(),
        "g-list": SeagateF3Terminal.print_g_list(),
        "clear-glist": SeagateF3Terminal.clear_g_list(),
        "toggle-sata": SeagateF3Terminal.build_toggle_sata(),
        "enter-terminal": SeagateF3Terminal.build_enter_terminal_mode(),
    }
    if args.cmd in cmd_map:
        cmd_str = cmd_map[args.cmd]
        ok(f"F3 terminal command: {cmd_str!r}")
        if args.output:
            Path(args.output).write_bytes(cmd_str.encode() + b"\r\n")
            ok(f"Saved to {args.output}")
    else:
        err(f"Unknown command alias: {args.cmd}")


def cmd_seagate_f3_sa_read(args):
    hdr(f"Seagate F3 SA read command: module=0x{args.module:02X} track={args.track}")
    cmd = SeagateF3Terminal.build_sa_read(module_id=args.module, track=args.track)
    encoded = cmd.encode()
    ok(f"F3 terminal command: {encoded!r}")
    module_name = SeagateF3ROMMap.describe(args.module)
    info(f"Module description: {module_name}")
    if args.output:
        Path(args.output).write_bytes(encoded.encode() + b"\r\n")
        ok(f"Saved to {args.output}")


def cmd_seagate_f3_head_select(args):
    hdr(f"Seagate F3 head select: count={args.count} mask=0x{args.mask:02X}")
    cmd = SeagateF3Terminal.set_active_heads(args.count, args.mask)
    ok(f"F3 terminal command: {cmd!r}")


# =============================================================================
# WD My Passport commands
# =============================================================================


def cmd_wd_passport_probe(args):
    hdr(f"WD My Passport probe: serial={args.serial}")
    result = WDPassportKeyRecovery.probe(args.serial)
    info(f"Serial             : {result['serial']}")
    info(f"Wrapping key (hex) : {result['wrapping_key_hex']}")
    if result["vulnerable"]:
        warn(f"VULNERABLE: {result['affected_model_hint']}")
    else:
        ok(f"Not in known-vulnerable range: {result['affected_model_hint']}")
    info(result["notes"])


def cmd_wd_passport_keyrec(args):
    hdr(f"WD My Passport offline DEK recovery: serial={args.serial}")
    warn("This operation decrypts the drive encryption key.")
    encrypted_dek = Path(args.dek_file).read_bytes()
    if len(encrypted_dek) < 16:
        err(f"DEK file too short ({len(encrypted_dek)} bytes, need >= 16)")
        return
    dek = WDPassportKeyRecovery.recover_dek(encrypted_dek, args.serial)
    ok(f"Recovered DEK: {dek.hex()}")
    if args.output:
        Path(args.output).write_bytes(dek)
        ok(f"DEK saved to {args.output}")


def cmd_wd_passport_status_cdb(args):
    hdr("WD My Passport: build GET_SEC_STATUS CDB (0xD8/0x00)")
    cdb = WDPassportBridgeCmd.build_get_security_status_cdb()
    ok(f"CDB (hex): {cdb.hex()}")
    if args.output:
        Path(args.output).write_bytes(cdb)
        ok(f"Saved to {args.output}")


# == WD IntelliPark idle3 timer ===============================================


def cmd_wd_idle3_get(args):
    hdr(f"WD idle3 timer: {args.drive}")
    with ATADevice(args.drive) as dev:
        client = WDIdle3Client(dev)
        raw = client.read_timer()
        scale = args.scale or "raw"
        ok(f"Idle3 timer: {WDIdle3Client.decode_timer(raw, scale)}")


def cmd_wd_idle3_set(args):
    hdr(f"WD idle3 timer set: {args.drive}")
    value = int(args.value, 0) if isinstance(args.value, str) else int(args.value)
    if not (1 <= value <= 255):
        err("Timer value must be 1-255 (use wd-idle3-disable to disable)")
        return
    with ATADevice(args.drive) as dev:
        client = WDIdle3Client(dev)
        client.write_timer(value)
    ok(f"Idle3 timer set to {value} (0x{value:02X})")
    warn("Power cycle (not reboot) required for the new setting to take effect")


def cmd_wd_idle3_disable(args):
    hdr(f"WD idle3 timer disable: {args.drive}")
    with ATADevice(args.drive) as dev:
        client = WDIdle3Client(dev)
        client.write_timer(IDLE3_DISABLED)
    ok("Idle3 timer disabled")
    warn("Power cycle (not reboot) required for the new setting to take effect")


# =============================================================================
# Argument parser
# =============================================================================


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hdd-toolkit",
        description="HDD Firmware Hacking Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = p.add_subparsers(dest="command", required=True)

    # == Firmware analysis ====================================================
    sp = sub.add_parser("parse-firmware", help="Parse & extract firmware sections")
    sp.add_argument("file")
    sp.add_argument("--format", choices=["wd", "samsung"], default="wd")
    sp.add_argument("--extract", metavar="DIR", help="Extract sections to directory")
    sp.set_defaults(func=cmd_parse_firmware)

    sp = sub.add_parser("wd100x-parse", help="Parse and optionally extract WD100x ROM segments")
    sp.add_argument("file")
    sp.add_argument("--segment-size", type=lambda x: int(x, 0), default=0x800)
    sp.add_argument(
        "--require-aligned",
        action="store_true",
        help="Require ROM size to be an even multiple of segment size",
    )
    sp.add_argument("--extract", metavar="DIR", help="Extract segmented ROM chunks to directory")
    sp.set_defaults(func=cmd_wd100x_parse)

    sp = sub.add_parser("decode-samsung", help="Remove Samsung nibble-swap obfuscation")
    sp.add_argument("file")
    sp.add_argument("-o", "--output")
    sp.set_defaults(func=cmd_decode_samsung)

    sp = sub.add_parser("scan-strings", help="Find ASCII strings in firmware")
    sp.add_argument("file")
    sp.add_argument("--min-len", type=int, default=5)
    sp.set_defaults(func=cmd_scan_strings)

    sp = sub.add_parser("scan-fptables", help="Heuristic ARM function-pointer table scan")
    sp.add_argument("file")
    sp.add_argument("--base", default="0", help="Base load address (hex)")
    sp.add_argument("--min-entries", type=int, default=4)
    sp.set_defaults(func=cmd_scan_fptables)

    sp = sub.add_parser("diff", help="Diff two firmware files")
    sp.add_argument("file_a")
    sp.add_argument("file_b")
    sp.set_defaults(func=cmd_diff)

    # == Live drive (ATA) =====================================================
    def add_drive(p):
        p.add_argument(
            "--drive", required=True, help=r"Drive path e.g. \\.\PhysicalDrive1 or /dev/sdb"
        )

    sp = sub.add_parser("list-vscs", help="Request VSC list from WD drive")
    add_drive(sp)
    sp.set_defaults(func=cmd_list_vscs)

    sp = sub.add_parser("read-ram", help="Read drive RAM via WD VSC")
    add_drive(sp)
    sp.add_argument("--addr", required=True, help="Address (hex)")
    sp.add_argument("--size", type=int, default=256)
    sp.add_argument("-o", "--output")
    sp.set_defaults(func=cmd_read_ram)

    sp = sub.add_parser("write-ram", help="Write file to drive RAM via WD VSC")
    add_drive(sp)
    sp.add_argument("--addr", required=True, help="Address (hex)")
    sp.add_argument("--file", required=True)
    sp.set_defaults(func=cmd_write_ram)

    sp = sub.add_parser("hot-patch", help="Assemble + deploy a delay hook to live drive RAM")
    sp.add_argument("--drive", help="Override drive from config")
    sp.add_argument("--config", required=True, help="YAML patch config file")
    sp.set_defaults(func=cmd_hot_patch)

    sp = sub.add_parser("benchmark", help="Timed read benchmark (optional: pre/post patch)")
    add_drive(sp)
    sp.add_argument("--sector", default="0x100", help="LBA sector (hex)")
    sp.add_argument("--iterations", type=int, default=10)
    sp.add_argument(
        "--patch-config", metavar="YAML", help="Apply patch between the two benchmark runs"
    )
    sp.set_defaults(func=cmd_benchmark)

    sp = sub.add_parser("dump-overlay", help="Dump a single WD service-area overlay module")
    add_drive(sp)
    sp.add_argument("--module", required=True, help="Module ID (hex)")
    sp.add_argument("-o", "--output")
    sp.set_defaults(func=cmd_dump_overlay)

    sp = sub.add_parser("dump-all-overlays", help="Dump all overlay modules to a directory")
    add_drive(sp)
    sp.add_argument("--out-dir", default="overlays")
    sp.add_argument("--max-module", type=int, default=0x80)
    sp.set_defaults(func=cmd_dump_all_overlays)

    # == JTAG (OpenOCD) =======================================================
    def add_ocd(p):
        p.add_argument("--host", default="localhost")
        p.add_argument("--port", type=int, default=4444)

    sp = sub.add_parser("jtag-shell", help="Interactive OpenOCD shell")
    add_ocd(sp)
    sp.set_defaults(func=cmd_jtag_shell)

    sp = sub.add_parser("jtag-dump", help="Dump memory via JTAG")
    add_ocd(sp)
    sp.add_argument("--addr", required=True, help="Address (hex)")
    sp.add_argument("--size", type=int, default=1024)
    sp.add_argument("-o", "--output")
    sp.set_defaults(func=cmd_jtag_dump)

    sp = sub.add_parser("jtag-bp", help="Set a hardware breakpoint via JTAG")
    add_ocd(sp)
    sp.add_argument("--addr", required=True, help="Address (hex)")
    sp.set_defaults(func=cmd_jtag_bp)

    sp = sub.add_parser("jtag-regs", help="Read CPU registers via JTAG")
    add_ocd(sp)
    sp.set_defaults(func=cmd_jtag_regs)

    # == Samsung MEX (840 EVO) - reference / static ===========================
    sp = sub.add_parser(
        "samsung-memory-map", help="Print Samsung MEX memory map (TheMissingManual)"
    )
    sp.set_defaults(func=cmd_samsung_memory_map)

    sp = sub.add_parser(
        "samsung-fw-history", help="Print Samsung 840 EVO firmware version history"
    )
    sp.set_defaults(func=cmd_samsung_fw_history)

    # == Samsung MEX (840 EVO) - JTAG-based commands ==========================
    sp = sub.add_parser("samsung-gpio", help="Read Samsung MEX GPIO status via JTAG")
    add_ocd(sp)
    sp.set_defaults(func=cmd_samsung_gpio)

    sp = sub.add_parser("samsung-ncq", help="Dump Samsung MEX NCQ buffers (0x00800C00) via JTAG")
    add_ocd(sp)
    sp.add_argument("-o", "--output", help="Save slot dump to text file")
    sp.set_defaults(func=cmd_samsung_ncq)

    sp = sub.add_parser(
        "samsung-aes-info",
        help="Read AES-XTS key slots / range table via JTAG "
        "(!! must halt before firmware zeroes them at boot !!)",
    )
    add_ocd(sp)
    sp.set_defaults(func=cmd_samsung_aes_info)

    sp = sub.add_parser(
        "samsung-dma-dump", help="Copy RAM to SATA window via DMA, then dd-exfiltrate"
    )
    add_ocd(sp)
    sp.add_argument("--addr", required=True, help="Source address (hex)")
    sp.add_argument(
        "--size", type=lambda x: int(x, 0), default=0x200, help="Byte count (default 512)"
    )
    sp.add_argument("--sata-dev", metavar="DEV", help="Block device for dd, e.g. /dev/sda")
    sp.add_argument(
        "--sleep", type=float, default=1.0, help="Seconds to sleep after DMA fire (default 1.0)"
    )
    sp.add_argument("-o", "--output", help="Output filename for dd (default auto)")
    sp.set_defaults(func=cmd_samsung_dma_dump)

    sp = sub.add_parser(
        "samsung-ftl-preload",
        help="Pre-load full FTL map by reading one sector per 117.5 MB chunk",
    )
    sp.add_argument("--sata-dev", required=True, metavar="DEV", help="Block device, e.g. /dev/sda")
    sp.add_argument("--size-gb", type=int, default=250, help="SSD capacity in GB (default 250)")
    sp.add_argument("--host", default="localhost")
    sp.add_argument("--port", type=int, default=4444)
    sp.set_defaults(func=cmd_samsung_ftl_preload)

    # == Samsung MEX (840 EVO) - NAND flash channel commands ===================
    sp = sub.add_parser(
        "samsung-flash-read",
        help="Read one NAND page via JTAG flash channel (TheMissingManual)",
    )
    add_ocd(sp)
    sp.add_argument("--channel", type=int, required=True, help="Flash channel 0-7")
    sp.add_argument("--block", required=True, help="Physical block number (hex)")
    sp.add_argument("--page", required=True, help="Page within block (hex, 0-255)")
    sp.add_argument(
        "--mem-addr",
        metavar="ADDR",
        help="Destination RAM address (hex; default DMA_SATA_WINDOW 0x85833000)",
    )
    sp.add_argument("--sata-dev", metavar="DEV", help="Block device for dd exfiltration")
    sp.add_argument("-o", "--output", help="Output filename for dd (default auto)")
    sp.set_defaults(func=cmd_samsung_flash_read)

    sp = sub.add_parser(
        "samsung-flash-write",
        help="Write one NAND page via JTAG flash channel (block must be erased first)",
    )
    add_ocd(sp)
    sp.add_argument("--channel", type=int, required=True, help="Flash channel 0-7")
    sp.add_argument("--block", required=True, help="Physical block number (hex)")
    sp.add_argument("--page", required=True, help="Page within block (hex, 0-255)")
    sp.add_argument(
        "--mem-addr", required=True, metavar="ADDR", help="Source RAM address (hex)"
    )
    sp.set_defaults(func=cmd_samsung_flash_write)

    sp = sub.add_parser(
        "samsung-flash-erase",
        help="Erase a NAND block via JTAG flash channel",
    )
    add_ocd(sp)
    sp.add_argument("--channel", type=int, required=True, help="Flash channel 0-7")
    sp.add_argument("--block", required=True, help="Physical block number (hex)")
    sp.set_defaults(func=cmd_samsung_flash_erase)

    sp = sub.add_parser(
        "samsung-flash-integrity",
        help="Run channel integrity check via JTAG (result at 0x20300050+ch, 0xEC=OK)",
    )
    add_ocd(sp)
    sp.add_argument("--channel", type=int, required=True, help="Flash channel 0-7")
    sp.set_defaults(func=cmd_samsung_flash_integrity)


    sp = sub.add_parser("parse-seagate", help="Parse Seagate .lod firmware file")
    sp.add_argument("file")
    sp.add_argument("--extract", metavar="DIR", help="Extract sections to directory")
    sp.set_defaults(func=cmd_parse_seagate)

    # == Service Area commands =================================================
    def add_drive_wrapped(p):
        p.add_argument(
            "--drive", required=True, help=r"Drive path e.g. \\.\PhysicalDrive1 or /dev/sdb"
        )

    sp = sub.add_parser("sa-probe", help="Probe Service Area size")
    add_drive_wrapped(sp)
    sp.set_defaults(func=cmd_sa_probe)

    sp = sub.add_parser("sa-dump", help="Full Service Area dump to directory")
    add_drive_wrapped(sp)
    sp.add_argument("--out-dir", default="sa_dump")
    sp.add_argument("--max-module", type=int, default=0x80)
    sp.set_defaults(func=cmd_sa_dump)

    sp = sub.add_parser("sa-hide", help="Hide data in SA module (covert storage)")
    add_drive_wrapped(sp)
    sp.add_argument("--file", required=True, help="Data file to hide")
    sp.add_argument(
        "--module", type=lambda x: int(x, 0), default=0x37, help="Module ID (hex, default 0x37)"
    )
    sp.set_defaults(func=cmd_sa_hide)

    sp = sub.add_parser("sa-extract", help="Extract hidden data from SA module")
    add_drive_wrapped(sp)
    sp.add_argument(
        "--module", type=lambda x: int(x, 0), default=0x37, help="Module ID (hex, default 0x37)"
    )
    sp.add_argument("-o", "--output", help="Output file")
    sp.set_defaults(func=cmd_sa_extract)

    # == Seagate F3 Service Area (SCT) commands ================================
    sp = sub.add_parser("seagate-sa-info", help="Print Seagate F3 SA module ID reference")
    sp.set_defaults(func=cmd_seagate_sa_info)

    sp = sub.add_parser("seagate-sa-read", help="Read one Seagate F3 SA module via SCT")
    add_drive_wrapped(sp)
    sp.add_argument("--module", required=True, help="Module ID (hex, e.g. 0x1D)")
    sp.add_argument("-o", "--output", help="Output file (default: seagate_sa_<id>.bin)")
    sp.set_defaults(func=cmd_seagate_sa_read)

    sp = sub.add_parser("seagate-sa-write", help="Write one Seagate F3 SA module via SCT")
    add_drive_wrapped(sp)
    sp.add_argument("--module", required=True, help="Module ID (hex)")
    sp.add_argument("--file", required=True, help="Data file to write")
    sp.set_defaults(func=cmd_seagate_sa_write)

    sp = sub.add_parser("seagate-sa-dump", help="Dump all Seagate F3 SA modules to directory")
    add_drive_wrapped(sp)
    sp.add_argument("--out-dir", default="seagate_sa_dump")
    sp.add_argument("--max-module", type=lambda x: int(x, 0), default=0x40)
    sp.set_defaults(func=cmd_seagate_sa_dump)

    sp = sub.add_parser("wd-sa-info", help="Print WD ROYL SA-to-ROM module map")
    sp.set_defaults(func=cmd_wd_sa_info)

    # == Firmware update exploit (DOWNLOAD-MICROCODE) ==========================
    sp = sub.add_parser(
        "fwexploit-send", help="Inject firmware via DOWNLOAD-MICROCODE offset overflow"
    )
    add_drive_wrapped(sp)
    sp.add_argument("--payload", required=True, help="Shellcode/firmware file")
    sp.add_argument(
        "--offset",
        type=lambda x: int(x, 0),
        default=0,
        help="Sector offset (high = buffer overflow)",
    )
    sp.add_argument(
        "--subcmd", type=lambda x: int(x, 0), default=0x03, help="Subcommand: 0x03=DMA, 0x0E=PIO"
    )
    sp.set_defaults(func=cmd_fwexploit_send)

    sp = sub.add_parser("fwexploit-activate", help="Activate injected firmware")
    add_drive_wrapped(sp)
    sp.set_defaults(func=cmd_fwexploit_activate)

    # == ASM2362 NVMe bridge ==================================================
    sp = sub.add_parser(
        "nvme-bridge-sanitize", help="Inject Sanitize Block Erase via ASM2362 XRAM"
    )
    sp.set_defaults(func=cmd_nvme_bridge_sanitize)

    # == Patch templates =======================================================
    sp = sub.add_parser("patch-template", help="Generate pre-built patch shellcode")
    sp.add_argument(
        "type",
        choices=["nop-sled", "data-trap", "exfil-hook", "smart-redirect"],
        help="Patch template type",
    )
    sp.add_argument("--addr", help="Target address (hex)")
    sp.add_argument("--fake-addr", help="Fake data address for smart-redirect")
    sp.add_argument("--replacement", help="Replacement data file for data-trap")
    sp.add_argument("--size", type=int, default=64, help="Size for nop-sled")
    sp.add_argument("-o", "--output", default="patch.bin", help="Output file")
    sp.set_defaults(func=cmd_patch_template)

    # == Toshiba firmware commands ==============================================
    sp = sub.add_parser("toshiba-parse", help="Parse Toshiba firmware image")
    sp.add_argument("file")
    sp.set_defaults(func=cmd_toshiba_parse)

    sp = sub.add_parser("toshiba-nand", help="Show Toshiba NAND configuration")
    sp.add_argument("file")
    sp.set_defaults(func=cmd_toshiba_nand)

    # == SAT layer commands ====================================================
    sp = sub.add_parser("sat-cdb", help="Build SCSI-ATA Translation CDB")
    sp.add_argument("ata_cmd", type=lambda x: int(x, 0), help="ATA command (hex)")
    sp.add_argument("--lba", type=lambda x: int(x, 0), default=0)
    sp.add_argument("--count", type=int, default=1)
    sp.add_argument(
        "--protocol",
        type=int,
        default=4,
        help="4=PIO_IN, 5=PIO_OUT, 6=DMA, 10=UDMA_IN, 13=NO_DATA",
    )
    sp.add_argument("--cdb-size", choices=["12", "16", "32"], default="16")
    sp.set_defaults(func=cmd_sat_build_cdb)

    # == Firmware patcher commands =============================================
    sp = sub.add_parser("patcher-apply", help="Apply patches and fix checksums")
    sp.add_argument("file", help="Original firmware image")
    sp.add_argument("patches", nargs="+", help="Patch JSON file(s)")
    sp.add_argument("-o", "--output", default="patched.bin")
    sp.set_defaults(func=cmd_patcher_apply)

    sp = sub.add_parser("patcher-fix", help="Auto-fix firmware checksums")
    sp.add_argument("file")
    sp.add_argument("-o", "--output")
    sp.set_defaults(func=cmd_patcher_fix)

    # == ATA security commands =================================================
    sp = sub.add_parser("ata-sec-status", help="Check ATA security status")
    sp.set_defaults(func=cmd_ata_sec_status)

    # == NVMe admin commands ==================================================
    sp = sub.add_parser("nvme-identify", help="NVMe Identify Controller")
    sp.add_argument("--device", default="0", help="NVMe device number")
    sp.set_defaults(func=cmd_nvme_identify)

    sp = sub.add_parser("nvme-smart", help="NVMe SMART / Health log")
    sp.add_argument("--device", default="0", help="NVMe device number")
    sp.set_defaults(func=cmd_nvme_smart)

    sp = sub.add_parser("nvme-fw-download", help="NVMe firmware download")
    sp.add_argument("file")
    sp.add_argument(
        "--offset", type=lambda x: int(x, 0), default=0, help="Download offset (dwords)"
    )
    sp.add_argument("--device", default="0", help="NVMe device number")
    sp.set_defaults(func=cmd_nvme_fw_dl)

    sp = sub.add_parser("nvme-fw-activate", help="NVMe firmware activate")
    sp.add_argument("--slot", type=int, default=1, help="Firmware slot (1-7)")
    sp.add_argument(
        "--action", type=int, default=3, help="1=replace, 2=replace+enable, 3=replace+enable+reset"
    )
    sp.add_argument("--device", default="0", help="NVMe device number")
    sp.set_defaults(func=cmd_nvme_fw_activate)

    sp = sub.add_parser("nvme-vendor", help="NVMe vendor-specific admin command")
    sp.add_argument("opcode", type=lambda x: int(x, 0), help="Admin opcode (hex)")
    sp.add_argument("--cdw10", type=lambda x: int(x, 0), default=0)
    sp.add_argument("--cdw11", type=lambda x: int(x, 0), default=0)
    sp.add_argument("--data-len", type=int, default=0)
    sp.add_argument("--device", default="0", help="NVMe device number")
    sp.set_defaults(func=cmd_nvme_vendor)

    # == NVMe live device commands =============================================
    sp = sub.add_parser(
        "nvme-live-identify", help="Read Identify Controller data from live NVMe device"
    )
    sp.add_argument("device", type=str, help="NVMe device number (e.g. 0) or path")
    sp.add_argument("--hex", action="store_true", help="Show hex dump of data")
    sp.set_defaults(func=cmd_nvme_live_identify)

    sp = sub.add_parser("nvme-live-smart", help="Read SMART/Health log from live NVMe device")
    sp.add_argument("device", type=str, help="NVMe device number (e.g. 0) or path")
    sp.add_argument("--hex", action="store_true", help="Show hex dump of data")
    sp.set_defaults(func=cmd_nvme_live_smart)

    sp = sub.add_parser("nvme-live-get-log", help="Read arbitrary log page from live NVMe device")
    sp.add_argument("log_id", type=lambda x: int(x, 0), help="Log page ID (hex, e.g. 0xC0)")
    sp.add_argument("--device", type=str, default="0", help="NVMe device number or path")
    sp.add_argument("--size", help="Log page size (hex, default 512)")
    sp.set_defaults(func=cmd_nvme_live_get_log)

    sp = sub.add_parser(
        "nvme-live-fw-log", help="Read Firmware Slot Information log from live NVMe device"
    )
    sp.add_argument("device", type=str, help="NVMe device number (e.g. 0) or path")
    sp.set_defaults(func=cmd_nvme_live_fw_log)

    sp = sub.add_parser("nvme-live-send", help="Send arbitrary NVMe admin command to live device")
    sp.add_argument("opcode", type=lambda x: int(x, 0), help="Admin opcode (hex)")
    sp.add_argument("--device", type=str, default="0", help="NVMe device number or path")
    sp.add_argument("--cdw10", type=lambda x: int(x, 0), default=0)
    sp.add_argument("--cdw11", type=lambda x: int(x, 0), default=0)
    sp.add_argument("--cdw12", type=lambda x: int(x, 0), default=0)
    sp.add_argument("--cdw13", type=lambda x: int(x, 0), default=0)
    sp.add_argument("--nsid", type=lambda x: int(x, 0), default=0)
    sp.add_argument("--file", help="File to write (for write commands)")
    sp.set_defaults(func=cmd_nvme_live_send)

    sp = sub.add_parser(
        "sandisk-live-sniff",
        help="Detect SanDisk/WD NVMe drive and probe vendor log pages on live device",
    )
    sp.add_argument("device", type=str, help="NVMe device number (e.g. 0) or path")
    sp.set_defaults(func=cmd_sandisk_live_sniff)

    # == SanDisk/WD NVMe vendor-specific commands ==============================
    sp = sub.add_parser("sandisk-id", help="SanDisk/WD NVMe vendor info (VID/DID/family)")
    sp.set_defaults(func=cmd_sandisk_id)

    sp = sub.add_parser(
        "sandisk-sniff-logs",
        help="Detect which vendor log pages a SanDisk/WD drive likely supports",
    )
    sp.set_defaults(func=cmd_sandisk_sniff_logs)

    sp = sub.add_parser(
        "sandisk-build-log", help="Build GET LOG PAGE command for a SanDisk/WD vendor log"
    )
    sp.add_argument("--log-id", required=True, help="Log page ID (hex, e.g. 0xC0)")
    sp.add_argument("--size", help="Log page size (hex, default 512)")
    sp.add_argument("--device", default="0", help="NVMe device number")
    sp.add_argument("--dump", action="store_true", help="Dump parsed log data")
    sp.set_defaults(func=cmd_sandisk_build_log)

    sp = sub.add_parser("sandisk-build-vu", help="Build SanDisk/WD vendor-specific admin command")
    sp.add_argument("opcode", type=lambda x: int(x, 0), help="Admin opcode (hex)")
    sp.add_argument("--cdw10", help="CDW10 value (hex)")
    sp.add_argument("--cdw11", help="CDW11 value (hex)")
    sp.add_argument("--device", default="0", help="NVMe device number")
    sp.set_defaults(func=cmd_sandisk_build_vu)

    sp = sub.add_parser("sandisk-build-purge", help="Build SanDisk/WD Purge command (opcode 0xDD)")
    sp.set_defaults(func=cmd_sandisk_build_purge)

    sp = sub.add_parser(
        "sandisk-build-resize", help="Build SanDisk/WD Drive Resize command (opcode 0xCC)"
    )
    sp.add_argument("--size", required=True, help="New size in sectors")
    sp.set_defaults(func=cmd_sandisk_build_resize)

    sp = sub.add_parser("sandisk-parse-c0", help="Parse SanDisk/WD 0xC0 EOL Status log page")
    sp.add_argument("file", help="Raw log page dump (512 bytes)")
    sp.set_defaults(func=cmd_sandisk_parse_c0)

    sp = sub.add_parser(
        "sandisk-parse-ca", help="Parse SanDisk/WD 0xCA Device Info / Performance log page"
    )
    sp.add_argument("file", help="Raw log page dump (160+ bytes)")
    sp.set_defaults(func=cmd_sandisk_parse_ca)

    sp = sub.add_parser("sandisk-parse-d0", help="Parse SanDisk/WD 0xD0 VU SMART log page")
    sp.add_argument("file", help="Raw log page dump (512 bytes)")
    sp.set_defaults(func=cmd_sandisk_parse_d0)

    # == USB bridge commands ==================================================
    sp = sub.add_parser("usb-identify", help="Identify USB-SATA bridge chip")
    sp.add_argument("--vid", type=lambda x: int(x, 0), help="USB vendor ID (hex)")
    sp.add_argument("--pid", type=lambda x: int(x, 0), help="USB product ID (hex)")
    sp.add_argument("--inquiry", help="SCSI INQUIRY vendor string")
    sp.set_defaults(func=cmd_usb_identify)

    sp = sub.add_parser("usb-list", help="List known USB-SATA bridge chips")
    sp.set_defaults(func=cmd_usb_list)

    # == Data recovery commands ================================================
    sp = sub.add_parser("dr-smart", help="SMART quick test (data recovery)")
    sp.add_argument("--drive", required=True, help="Drive path")
    sp.set_defaults(func=cmd_dr_smart)

    sp = sub.add_parser("dr-identify", help="Identify device parameters for recovery")
    sp.add_argument("--drive", required=True, help="Drive path")
    sp.set_defaults(func=cmd_dr_identify)

    sp = sub.add_parser("dr-native-max", help="Read Native Max Address")
    sp.add_argument("--drive", required=True, help="Drive path")
    sp.set_defaults(func=cmd_dr_native_max)

    sp = sub.add_parser("dr-pattern", help="Generate defective sector test pattern")
    sp.add_argument("--lba", type=lambda x: int(x, 0), default=0x1000)
    sp.add_argument("--size", type=int, default=512, help="Sector size")
    sp.add_argument("-o", "--output", default="defective_sector.bin")
    sp.set_defaults(func=cmd_dr_pattern)

    # == HPA/DCO commands =====================================================
    sp = sub.add_parser("hpa-detect", help="Detect HPA from IDENTIFY DEVICE data")
    sp.add_argument("--file", help="IDENTIFY DEVICE dump binary")
    sp.set_defaults(func=cmd_hpa_detect)

    sp = sub.add_parser("hpa-build-cmd", help="Build HPA/DCO ATA command CDB")
    sp.add_argument(
        "type", choices=["read-native", "set-max", "dco-identify", "dco-set", "dco-restore"]
    )
    sp.add_argument("--lba", type=lambda x: int(x, 0), default=0, help="LBA for SET MAX")
    sp.add_argument("--lba48", action="store_true", default=True, help="Use 48-bit LBA")
    sp.add_argument("--persistent", action="store_true", default=False, help="Persistent SET MAX")
    sp.add_argument("--dco-file", help="DCO data file for SET")
    sp.set_defaults(func=cmd_hpa_build_cmd)

    sp = sub.add_parser("hpa-parse-dco", help="Parse DCO feature set descriptor")
    sp.add_argument("file", help="DCO IDENTIFY data binary (512 bytes)")
    sp.set_defaults(func=cmd_hpa_parse_dco)

    # == NVMe timing side-channel commands =====================================
    sp = sub.add_parser("nvme-timing-baseline", help="NVMe read latency baseline estimation")
    sp.set_defaults(func=cmd_nvme_timing_baseline)

    sp = sub.add_parser("nvme-timing-detect", help="Detect NVMe timing contention (simulated)")
    sp.set_defaults(func=cmd_nvme_timing_detect)

    sp = sub.add_parser("nvme-timing-gc", help="Analyze NVMe completion timing for GC events")
    sp.set_defaults(func=cmd_nvme_timing_gc)

    # == eNVMe platform commands =================================================
    sp = sub.add_parser("envme-dma", help="Build eNVMe DMA attack descriptor")
    sp.add_argument("--host-addr", required=True, help="Host physical address (hex)")
    sp.add_argument("--size", type=int, default=4096, help="Transfer size (bytes)")
    sp.add_argument("--direction", choices=["read", "write"], default="read")
    sp.set_defaults(func=cmd_envme_dma)

    sp = sub.add_parser("envme-scan", help="Model host memory scan via eNVMe")
    sp.add_argument("--chunk", type=int, default=4096, help="Scan chunk size")
    sp.add_argument("--pages", type=int, default=256, help="Max pages to scan")
    sp.set_defaults(func=cmd_envme_scan)

    sp = sub.add_parser("envme-compat", help="Check eNVMe platform compatibility")
    sp.add_argument("--file", help="NVMe Identify Controller data (4096 bytes)")
    sp.set_defaults(func=cmd_envme_compat)

    # == NVMe-oF commands ========================================================
    sp = sub.add_parser("nvmeof-check-kernel", help="Check kernel for CVE-2023-5178 vulnerability")
    sp.add_argument("--kernel", default="6.7", help="Kernel version string")
    sp.set_defaults(func=cmd_nvmeof_check_kernel)

    sp = sub.add_parser("nvmeof-build-icreq", help="Build NVMe-oF TCP ICReq PDU")
    sp.add_argument("--hdgst", action="store_true", help="Enable header digest")
    sp.add_argument("--ddgst", action="store_true", help="Enable data digest")
    sp.add_argument(
        "--maxh2cdata",
        type=lambda x: int(x, 0),
        default=0x100000,
        help="Max host-to-controller data",
    )
    sp.set_defaults(func=cmd_nvmeof_build_icreq)

    sp = sub.add_parser("nvmeof-poc", help="Generate CVE-2023-5178 double-free PoC PDU")
    sp.set_defaults(func=cmd_nvmeof_poc)

    # == Firmware detection commands ===========================================
    sp = sub.add_parser(
        "fwdetect-current", help="Detect FW modification via current draw analysis"
    )
    sp.add_argument("--current", type=float, help="Measured current (mA)")
    sp.add_argument("--baseline", type=float, help="Baseline current (mA)")
    sp.set_defaults(func=cmd_fwdetect_current)

    sp = sub.add_parser("fwdetect-timing", help="Detect FW modification via timing analysis")
    sp.add_argument("--baseline", type=float, help="Baseline time (us)")
    sp.add_argument("--modified", action="store_true", help="Simulate modified firmware timing")
    sp.set_defaults(func=cmd_fwdetect_timing)

    sp = sub.add_parser("fwdetect-verify", help="Verify firmware checksums")
    sp.add_argument("file", help="Firmware image")
    sp.add_argument(
        "--vendor", default="auto", help="Firmware vendor (wd/seagate/samsung/toshiba)"
    )
    sp.set_defaults(func=cmd_fwdetect_verify)

    sp = sub.add_parser("fwdetect-report", help="Comprehensive firmware integrity report")
    sp.add_argument("file", help="Firmware image")
    sp.add_argument(
        "--vendor", default="auto", help="Firmware vendor (wd/seagate/samsung/toshiba)"
    )
    sp.set_defaults(func=cmd_fwdetect_report)

    # == Samsung MEX (840 EVO) - SAFE-mode UART commands =====================
    def add_uart(p):
        p.add_argument("--port", required=True, help="Serial port, e.g. /dev/ttyUSB0 or COM3")
        p.add_argument("--timeout", type=float, default=2.0)

    sp = sub.add_parser("samsung-safe-shell", help="Interactive SAFE-mode UART shell (rr/rw)")
    add_uart(sp)
    sp.set_defaults(func=cmd_samsung_safe_shell)

    sp = sub.add_parser("samsung-safe-read", help="Read word(s) via SAFE-mode UART (rr command)")
    add_uart(sp)
    sp.add_argument("--addr", required=True, help="Address (hex)")
    sp.add_argument(
        "--size",
        type=lambda x: int(x, 0),
        default=4,
        help="Bytes to read (default 4; multiples of 4)",
    )
    sp.add_argument("-o", "--output", help="Save raw bytes to file")
    sp.set_defaults(func=cmd_samsung_safe_read)

    sp = sub.add_parser("samsung-safe-write", help="Write word via SAFE-mode UART (rw command)")
    add_uart(sp)
    sp.add_argument("--addr", required=True, help="Address (hex)")
    sp.add_argument("--value", required=True, help="32-bit value (hex)")
    sp.add_argument("--verify", action="store_true", help="Read back and confirm write")
    sp.set_defaults(func=cmd_samsung_safe_write)

    # == Spare-sector forensic scanner ========================================
    sp = sub.add_parser(
        "sa-scan-spare",
        help="Dump and analyse defect tables for Equation Group-style covert storage",
    )
    sp.add_argument("--identify", metavar="FILE", help="512-byte IDENTIFY DEVICE dump")
    sp.add_argument(
        "--native-max",
        type=lambda x: int(x, 0),
        default=0,
        metavar="LBA",
        help="Native max LBA from READ NATIVE MAX ADDRESS",
    )
    sp.add_argument("--glist", metavar="FILE", help="G-list entries JSON file")
    sp.add_argument(
        "--vsc-max",
        type=lambda x: int(x, 0),
        default=None,
        metavar="LBA",
        help="Max LBA accessible via VSC overlay (optional)",
    )
    sp.set_defaults(func=cmd_sa_scan_spare)

    # == Firmware read-back capability probe ==================================
    sp = sub.add_parser(
        "fw-readback-probe",
        help="Probe firmware read-back capability (blind/partial/full)",
    )
    sp.add_argument("--jtag", action="store_true", help="JTAG/OpenOCD is available")
    sp.add_argument("--spi-clip", action="store_true", help="SPI flash clip is attached (SSD)")
    sp.add_argument("--vsc", action="store_true", help="Drive responds to VSC readback")
    sp.add_argument(
        "--drive-type",
        choices=["hdd", "ssd"],
        default="hdd",
        help="Drive type (default: hdd)",
    )
    sp.set_defaults(func=cmd_fw_readback_probe)

    # == SPI flash CSV decode =================================================
    sp = sub.add_parser(
        "spi-decode-csv",
        help="Decode Saleae SPI analyser CSV capture of JMS539 firmware boot",
    )
    sp.add_argument("csv_file", help="Saleae SPI CSV export file")
    sp.add_argument("-o", "--output", default="dump.bin", help="Output firmware binary")
    sp.set_defaults(func=cmd_spi_decode_csv)

    # == ISSP PSoC programming ================================================
    sp = sub.add_parser("psoc-sync", help="Build ISSP synchronisation vector sequence")
    sp.set_defaults(func=cmd_psoc_sync)

    sp = sub.add_parser("psoc-read-sec", help="Build ISSP vectors to read PSoC security table")
    sp.set_defaults(func=cmd_psoc_read_sec)

    sp = sub.add_parser("psoc-read-srom", help="Build ISSP SROM syscall vectors")
    sp.add_argument(
        "--fn",
        type=lambda x: int(x, 0),
        default=ISSPEngine.SROM_FN_CHECKSUM_SETUP,
        help="SROM function number (hex, default 0x07=CHECKSUM_SETUP)",
    )
    sp.set_defaults(func=cmd_psoc_read_srom)

    sp = sub.add_parser("psoc-write-reg", help="Build ISSP write-register vector")
    sp.add_argument("--addr", type=lambda x: int(x, 0), required=True, help="Register address")
    sp.add_argument("--data", type=lambda x: int(x, 0), required=True, help="Data byte")
    sp.set_defaults(func=cmd_psoc_write_reg)

    # == PSoC cold-boot attack ================================================
    sp = sub.add_parser(
        "psoc-locate-pin",
        help="Search PSoC flash dump for PIN digit sequences",
    )
    sp.add_argument("dump", help="PSoC flash dump binary")
    sp.add_argument("--pin-length", type=int, default=6, help="Expected PIN length (default 6)")
    sp.set_defaults(func=cmd_psoc_locate_pin)

    sp = sub.add_parser(
        "psoc-dump-block",
        help="Extract and display one 64-byte block from PSoC flash dump",
    )
    sp.add_argument("dump", help="PSoC flash dump binary")
    sp.add_argument("--block", type=int, default=0, help="Block index (0-based)")
    sp.add_argument("--block-size", type=int, default=64, help="Bytes per block (default 64)")
    sp.set_defaults(func=cmd_psoc_dump_block)

    sp = sub.add_parser(
        "i2c-diff",
        help="Diff two I2C bus captures to identify PIN-related register writes",
    )
    sp.add_argument("before", help="JSON file: I2C capture before PIN entry")
    sp.add_argument("after", help="JSON file: I2C capture after PIN entry")
    sp.set_defaults(func=cmd_i2c_diff)

    # == Xbox 360 / HDDHackr firmware identity spoof check ====================
    sp = sub.add_parser(
        "fw-identity-check",
        help="Detect Xbox 360 / HDDHackr firmware-level identity spoofing (Read et al., 2013)",
    )
    sp.add_argument("--identify", metavar="FILE", help="512-byte IDENTIFY DEVICE dump")
    sp.add_argument(
        "--security-sector",
        metavar="FILE",
        help="512-byte raw sector from LBA 0 or drive security-sector LBA",
    )
    sp.add_argument(
        "--smart",
        metavar="FILE",
        help="512-byte SMART READ DATA response for serial cross-check",
    )
    sp.set_defaults(func=cmd_fw_identity_check)

    sp = sub.add_parser(
        "hddss-info",
        help="Parse and display identity fields from an HDDHackr hddss.bin sector dump",
    )
    sp.add_argument("file", help="3584-byte hddss.bin sector dump file")
    sp.set_defaults(func=cmd_hddss_info)

    sp = sub.add_parser(
        "hddss-patch",
        help="Patch a WD firmware module 2 dump with identity from hddss.bin",
    )
    sp.add_argument("hddss", help="3584-byte hddss.bin identity source file")
    sp.add_argument("module2", help="1024-byte firmware module 2 dump to patch")
    sp.add_argument("output", help="Output file for patched module 2")
    sp.add_argument("--current-serial", required=True, help="Current drive serial (from IDENTIFY)")
    sp.add_argument("--current-model", required=True, help="Current drive model (from IDENTIFY)")
    sp.add_argument(
        "--current-count",
        required=True,
        type=int,
        help="Current drive LBA28 sector count (from IDENTIFY word 60-61)",
    )
    sp.set_defaults(func=cmd_hddss_patch)

    # == TCG Opal / SED commands ==============================================
    sp = sub.add_parser(
        "opal-discovery",
        help="Parse TCG Opal Level 0 Discovery response from a 512-byte dump",
    )
    sp.add_argument("file", help="512-byte IF_RECV Level 0 Discovery dump")
    sp.set_defaults(func=cmd_opal_discovery)

    sp = sub.add_parser(
        "opal-start-session",
        help="Build a TCG Opal StartSession ComPacket for ATA IF_SEND",
    )
    sp.add_argument(
        "--com-id",
        type=lambda x: int(x, 0),
        required=True,
        help="BaseComID from Level 0 Discovery (e.g. 0x0204)",
    )
    sp.add_argument(
        "--sp-uid",
        default="00000205 00000001",
        help="8-byte SP UID hex string (default: Admin SP)",
    )
    sp.add_argument("--hsn", type=lambda x: int(x, 0), default=0x41, help="Host session number")
    sp.add_argument("--read-only", action="store_true", help="Request read-only session")
    sp.add_argument("-o", "--output", help="Output file (default: start_session.bin)")
    sp.set_defaults(func=cmd_opal_start_session)

    # == ATA Security Feature Set commands =====================================
    sp = sub.add_parser(
        "ata-security-check",
        help="Parse ATA Security Feature Set status from an IDENTIFY DEVICE dump",
    )
    sp.add_argument("file", help="512-byte IDENTIFY DEVICE dump")
    sp.set_defaults(func=cmd_ata_security_check)

    sp = sub.add_parser(
        "ata-security-build",
        help="Build ATA Security Feature Set command payload (for passthrough scripting)",
    )
    sp.add_argument(
        "operation",
        choices=[
            "freeze", "unlock", "set-password",
            "erase-prepare", "erase-unit", "disable-password",
        ],
        help="Security operation",
    )
    sp.add_argument(
        "--password",
        help="Password string (max 32 bytes; for unlock/set/erase/disable)",
    )
    sp.add_argument("--master", action="store_true", help="Use master password slot")
    sp.add_argument("-o", "--output", help="Save password sector payload to file")
    sp.set_defaults(func=cmd_ata_security_build)

    # == SCSI / SAS commands ==================================================
    sp = sub.add_parser("scsi-inquiry", help="Issue SCSI INQUIRY to a SCSI/SAS device")
    sp.add_argument("device", help="Device path, e.g. /dev/sg1 or /dev/sdb")
    sp.add_argument("--evpd", action="store_true", help="Enable Vital Product Data")
    sp.add_argument("--page-code", type=lambda x: int(x, 0), default=0, help="VPD page code (hex)")
    sp.add_argument("-o", "--output", help="Save raw response to file")
    sp.set_defaults(func=cmd_scsi_inquiry)

    sp = sub.add_parser(
        "scsi-read-capacity",
        help="Issue SCSI READ CAPACITY to a SCSI/SAS device",
    )
    sp.add_argument("device", help="Device path, e.g. /dev/sg1 or /dev/sdb")
    sp.add_argument("--use-16", action="store_true", help="Use READ CAPACITY (16) instead of (10)")
    sp.set_defaults(func=cmd_scsi_read_capacity)

    sp = sub.add_parser(
        "scsi-ses",
        help="Read and parse SES Enclosure Status page from a SCSI/SAS enclosure or drive",
    )
    sp.add_argument("device", help="SES device path, e.g. /dev/sg2")
    sp.add_argument("-o", "--output", help="Save raw SES page to file")
    sp.set_defaults(func=cmd_scsi_ses)

    sp = sub.add_parser(
        "scsi-inquiry-cdb",
        help="Build a SCSI INQUIRY CDB without sending it (for use with other passthrough tools)",
    )
    sp.add_argument("--evpd", action="store_true", help="Enable Vital Product Data")
    sp.add_argument("--page-code", type=lambda x: int(x, 0), default=0, help="VPD page code (hex)")
    sp.add_argument("--alloc-len", type=int, default=96, help="Allocation length (default 96)")
    sp.add_argument("-o", "--output", help="Save CDB bytes to file")
    sp.set_defaults(func=cmd_scsi_inquiry_cdb)

    # == NVMe HMB commands ====================================================
    sp = sub.add_parser(
        "nvme-hmb-caps",
        help="Parse Host Memory Buffer capabilities from Identify Controller dump",
    )
    sp.add_argument("file", help="4096-byte Identify Controller data dump")
    sp.set_defaults(func=cmd_nvme_hmb_caps)

    sp = sub.add_parser(
        "nvme-hmb-attack",
        help="Model HMB attack surface for a given descriptor list",
    )
    sp.add_argument(
        "descriptors",
        nargs="+",
        metavar="BASE:SIZE_4K",
        help="HMB descriptor as base_address_hex:size_in_4k_pages (e.g. 0x80000000:16)",
    )
    sp.set_defaults(func=cmd_nvme_hmb_attack)

    sp = sub.add_parser(
        "nvme-hmb-enable-cmd",
        help="Build NVMe SET FEATURES (HMB enable) command register dump",
    )
    sp.add_argument(
        "--base-addr",
        type=lambda x: int(x, 0),
        required=True,
        help="HMB base address (hex)",
    )
    sp.add_argument("--size-4k", type=int, required=True, help="HMB size in 4-KiB pages")
    sp.add_argument("--mr", action="store_true", help="Set Memory Return bit")
    sp.set_defaults(func=cmd_nvme_hmb_enable_cmd)

    # == RTL9210 bridge commands ==============================================
    sp = sub.add_parser("rtl9210-info", help="Print RTL9210B bridge capability summary")
    sp.set_defaults(func=cmd_rtl9210_info)

    sp = sub.add_parser("rtl9210-read-reg", help="Build RTL9210B XRAM/MMIO read CDB (0xF8)")
    sp.add_argument("--addr", required=True, help="Register address (hex)")
    sp.add_argument("--length", type=int, default=4, help="Bytes to read (1-255, default 4)")
    sp.add_argument("-o", "--output", help="Save CDB to file")
    sp.set_defaults(func=cmd_rtl9210_read_reg)

    sp = sub.add_parser("rtl9210-write-reg", help="Build RTL9210B XRAM/MMIO write CDB (0xF9)")
    sp.add_argument("--addr", required=True, help="Register address (hex)")
    sp.add_argument("--value", required=True, help="Byte value (hex)")
    sp.add_argument("-o", "--output", help="Save CDB to file")
    sp.set_defaults(func=cmd_rtl9210_write_reg)

    sp = sub.add_parser("rtl9210-read-spi", help="Build RTL9210B SPI flash read CDB (0xE2)")
    sp.add_argument("--offset", default="0", help="Flash byte offset (hex)")
    sp.add_argument("--length", type=int, default=512, help="Bytes to read (default 512)")
    sp.add_argument("-o", "--output", help="Save CDB to file")
    sp.set_defaults(func=cmd_rtl9210_read_spi)

    sp = sub.add_parser(
        "rtl9210-inject-sanitize",
        help="Build RTL9210B XRAM-injected NVMe Sanitize Block Erase command",
    )
    sp.add_argument("--slot", type=int, default=0, help="Admin SQ slot (0-3, default 0)")
    sp.add_argument("-o", "--output", help="Save 64-byte NVMe SQ entry to file")
    sp.set_defaults(func=cmd_rtl9210_inject_sanitize)

    # == ATA master password oracle commands ==================================
    sp = sub.add_parser(
        "ata-master-pw-oracle",
        help="Plan ATA master password oracle attack from IDENTIFY DEVICE dump",
    )
    sp.add_argument("file", help="512-byte IDENTIFY DEVICE dump")
    sp.add_argument("--model", default="", help="Drive model string (override)")
    sp.add_argument(
        "--erase-mode",
        action="store_true",
        help="Plan SECURITY ERASE UNIT instead of SECURITY UNLOCK",
    )
    sp.set_defaults(func=cmd_ata_master_pw_oracle)

    sp = sub.add_parser(
        "ata-master-pw-detect",
        help="Detect if a drive model has a known default master password",
    )
    sp.add_argument("model", help="Drive model string (from IDENTIFY DEVICE words 27-46)")
    sp.set_defaults(func=cmd_ata_master_pw_detect)

    # == Volatile write cache fault commands ==================================
    sp = sub.add_parser(
        "vwc-analyse",
        help="Analyse drive IDENTIFY DEVICE dump for volatile write cache fault risk",
    )
    sp.add_argument("file", help="512-byte IDENTIFY DEVICE dump")
    sp.set_defaults(func=cmd_vwc_analyse)

    sp = sub.add_parser(
        "vwc-disable-cmd",
        help="Print ATA SET FEATURES 0x82 (disable volatile write cache) register values",
    )
    sp.set_defaults(func=cmd_vwc_disable_cmd)

    sp = sub.add_parser(
        "vwc-fault-plan",
        help="Generate a power-loss fault injection plan for volatile write cache",
    )
    sp.add_argument("--lba", required=True, help="Target starting LBA (hex)")
    sp.add_argument("--count", type=int, default=64, help="Number of sectors to write (default 64)")
    sp.add_argument(
        "--delay-ms",
        type=float,
        default=50.0,
        help="Milliseconds after first write to cut power (default 50)",
    )
    sp.add_argument("--flush", action="store_true", help="Flush cache before cut (baseline mode)")
    sp.add_argument(
        "--cache-mb",
        type=int,
        default=4,
        help="Estimated drive cache size in MiB for window estimation (default 4)",
    )
    sp.add_argument(
        "--rate-mb-s",
        type=float,
        default=100.0,
        help="Drive sustained write rate in MiB/s (default 100)",
    )
    sp.set_defaults(func=cmd_vwc_fault_plan)

    # == Hitachi/HGST SA commands ==============================================
    sp = sub.add_parser(
        "hitachi-sa-info",
        help="Print Hitachi/HGST Service Area VSC interface capability summary",
    )
    sp.set_defaults(func=cmd_hitachi_sa_info)

    sp = sub.add_parser(
        "hitachi-sa-read",
        help="Read a Hitachi/HGST SA module via ATA SMART vendor commands",
    )
    sp.add_argument("device", help="Drive path, e.g. /dev/sdb")
    sp.add_argument(
        "--module",
        type=lambda x: int(x, 0),
        required=True,
        help="SA module ID (hex), e.g. 0x00 for BOOT_CODE",
    )
    sp.add_argument("-o", "--output", help="Save module data to file")
    sp.set_defaults(func=cmd_hitachi_sa_read)

    sp = sub.add_parser(
        "hitachi-sa-write",
        help="Write a Hitachi/HGST SA module via ATA SMART vendor commands",
    )
    sp.add_argument("device", help="Drive path, e.g. /dev/sdb")
    sp.add_argument(
        "--module",
        type=lambda x: int(x, 0),
        required=True,
        help="SA module ID (hex), e.g. 0x03 for G_LIST",
    )
    sp.add_argument("file", help="Binary file to write into the module")
    sp.set_defaults(func=cmd_hitachi_sa_write)

    # == Seagate F3 terminal commands =========================================
    sp = sub.add_parser(
        "seagate-f3-cmd",
        help="Build a Seagate F3 UART terminal command string",
    )
    sp.add_argument(
        "cmd",
        choices=[
            "spin-up", "spin-down", "reset", "identity",
            "p-list", "g-list", "clear-glist", "toggle-sata", "enter-terminal",
        ],
        help="F3 command alias",
    )
    sp.add_argument("-o", "--output", help="Write command bytes (+ CRLF) to file")
    sp.set_defaults(func=cmd_seagate_f3_cmd)

    sp = sub.add_parser(
        "seagate-f3-sa-read",
        help="Build a Seagate F3 SA read command string (i4 family)",
    )
    sp.add_argument(
        "--module",
        type=lambda x: int(x, 0),
        required=True,
        help="SA module ID (hex), e.g. 0x34 for CONGEN_XML",
    )
    sp.add_argument("--track", type=int, default=1, help="SA track number (default 1)")
    sp.add_argument("-o", "--output", help="Write command bytes to file")
    sp.set_defaults(func=cmd_seagate_f3_sa_read)

    sp = sub.add_parser(
        "seagate-f3-head-select",
        help="Build a Seagate F3 head-select command (N command, for data recovery)",
    )
    sp.add_argument("--count", type=int, required=True, help="Number of heads to activate")
    sp.add_argument(
        "--mask",
        type=lambda x: int(x, 0),
        default=0xFF,
        help="Head enable bitmask (hex, default 0xFF = all)",
    )
    sp.set_defaults(func=cmd_seagate_f3_head_select)

    # == WD My Passport commands ==============================================
    sp = sub.add_parser(
        "wd-passport-probe",
        help="Offline risk assessment for WD My Passport drives (key derivation weakness)",
    )
    sp.add_argument(
        "serial",
        help="Drive serial number from SCSI INQUIRY (e.g. WX21A12B3456C7)",
    )
    sp.set_defaults(func=cmd_wd_passport_probe)

    sp = sub.add_parser(
        "wd-passport-keyrec",
        help="Recover WD My Passport DEK offline using SMART serial + static salt",
    )
    sp.add_argument("serial", help="Drive serial number")
    sp.add_argument("dek_file", help="32-byte encrypted DEK read from SMART log 0xA0")
    sp.add_argument("-o", "--output", help="Save recovered DEK bytes to file")
    sp.set_defaults(func=cmd_wd_passport_keyrec)

    sp = sub.add_parser(
        "wd-passport-status-cdb",
        help="Build WD My Passport GET_SEC_STATUS CDB (opcode 0xD8/0x00)",
    )
    sp.add_argument("-o", "--output", help="Save 10-byte CDB to file")
    sp.set_defaults(func=cmd_wd_passport_status_cdb)

    # == WD IntelliPark idle3 timer ============================================
    sp = sub.add_parser(
        "wd-idle3-get",
        help="Read WD IntelliPark idle3 head-parking timer (idle3ctl -g)",
    )
    sp.add_argument("--drive", required=True, help=r"Drive path e.g. /dev/sdb")
    sp.add_argument(
        "--scale",
        choices=["raw", "v100", "v103"],
        default="raw",
        help="Timer decode scale: raw (default), v100 (0.1s/unit), v103 (mixed)",
    )
    sp.set_defaults(func=cmd_wd_idle3_get)

    sp = sub.add_parser(
        "wd-idle3-set",
        help="Set WD IntelliPark idle3 timer raw value 1-255 (idle3ctl -s)",
    )
    sp.add_argument("--drive", required=True, help=r"Drive path e.g. /dev/sdb")
    sp.add_argument("value", help="Raw timer byte 1-255 (decimal or 0x hex)")
    sp.set_defaults(func=cmd_wd_idle3_set)

    sp = sub.add_parser(
        "wd-idle3-disable",
        help="Disable WD IntelliPark idle3 head-parking timer (idle3ctl -d)",
    )
    sp.add_argument("--drive", required=True, help=r"Drive path e.g. /dev/sdb")
    sp.set_defaults(func=cmd_wd_idle3_disable)

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        warn("Interrupted")
    except ATAError as e:
        err(f"ATA error: {e}")
        sys.exit(1)
    except Exception as e:
        err(f"Unexpected error: {e}")
        raise
