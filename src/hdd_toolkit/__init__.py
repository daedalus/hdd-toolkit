"""HDD Firmware Hacking Toolkit."""

from hdd_toolkit._version import __version__, __version_info__
from hdd_toolkit.ata.commands import (
    ATA_PASS_THROUGH_EX,
    SAMSUNG_840_EVO_FW_HISTORY,
    ATACmd,
    ATADevice,
    ATAError,
    ATASecurityCommands,
)
from hdd_toolkit.ata.hitachi_vsc import HitachiSAModule, HitachiVSCClient
from hdd_toolkit.ata.idle3 import (
    IDLE3_DISABLED,
    WDIdle3Client,
    decode_timer_v100,
    decode_timer_v103,
)
from hdd_toolkit.ata.sat import SATCmd, SATLayer
from hdd_toolkit.ata.seagate_f3_terminal import (
    F3Level,
    F3SAReadCmd,
    SeagateF3ROMMap,
    SeagateF3Terminal,
    build_sa_sector_descriptor,
)
from hdd_toolkit.ata.seagate_vsc import SeagateF3SCTClient, SeagateSAModule
from hdd_toolkit.ata.security import ATAFrozenBypass, ATASecurityAccess, ATASecurityStatus
from hdd_toolkit.ata.tcg_opal import (
    TCGDiscovery0,
    TCGDiscovery0Parser,
    TCGFeatureCode,
    TCGOpalClient,
    TCGSession,
    build_if_recv,
    build_if_send,
)
from hdd_toolkit.ata.wd_vsc import WD_SA_ROM_MAP, WD_VSC, WDVSCClient
from hdd_toolkit.cli.handlers import build_parser, main
from hdd_toolkit.core.utils import (
    _c,
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
from hdd_toolkit.exploit.ata_password_oracle import ATAMasterPasswordOracle, MasterPasswordTable
from hdd_toolkit.exploit.bridge_attack import ASM2362NVMeBridge
from hdd_toolkit.exploit.fw_update import FirmwareUpdateExploit
from hdd_toolkit.exploit.hotpatch import (
    HotPatchConfig,
    PatchTemplates,
    _bytes_to_asm,
    assemble_thumb,
    benchmark_reads,
    build_delay_hook,
    deploy_hot_patch,
)
from hdd_toolkit.exploit.psoc_coldboot import ColdBootResult, I2CDiff, PSoCColdBoot
from hdd_toolkit.exploit.rtl9210_bridge import RTL9210Bridge, RTL9210FirmwareInfo
from hdd_toolkit.exploit.service_area import ServiceArea, dump_all_overlays
from hdd_toolkit.exploit.spare_sector_forensics import SpareSectorForensics
from hdd_toolkit.exploit.wd_passport import (
    WDPassportBridgeCmd,
    WDPassportKeyRecovery,
    WDPassportSecStatus,
    analyse_passport,
)
from hdd_toolkit.exploit.write_cache_fault import (
    PowerLossFaultPlan,
    VWCState,
    VWCStatus,
    WriteCacheFaultModel,
    plan_power_loss_fault,
)
from hdd_toolkit.exploit.xbox360_firmware_spoof import (
    FirmwareIdentitySpoofDetector,
    Xbox360SecuritySector,
)
from hdd_toolkit.firmware.detection import FirmwareDetection
from hdd_toolkit.firmware.emulator import SamsungHDDEmulator
from hdd_toolkit.firmware.patcher import FirmwarePatch, FirmwarePatcher
from hdd_toolkit.firmware.samsung import (
    SamsungFirmwareParser,
    SamsungSection,
    samsung_decode,
)
from hdd_toolkit.firmware.seagate import (
    ARTIFACT_8051_FW,
    ARTIFACT_BOOT_FW,
    ARTIFACT_FLASH_LOADER,
    ARTIFACT_MAIN_FW,
    ARTIFACT_MAYBE_BSS,
    ARTIFACT_NAMES,
    ARTIFACT_OVERLAY,
    ARTIFACT_PADDING,
    SeagateArtifact,
    SeagateArtifactParser,
    SeagateChunkSection,
    SeagateCRC16,
    SeagateFWLoader,
    SeagateLODSection,
    SeagateOverlayInfo,
    SeagateSectionRun,
    SeagateSectionsHeader,
    SeagateSegmentHeader,
)
from hdd_toolkit.firmware.toshiba import ToshibaFirmwareImage, ToshibaFirmwareParser
from hdd_toolkit.firmware.wd import LZHUFDecoder, WDFirmwareParser, WDSection
from hdd_toolkit.firmware.wd100x import (
    WD100xFormatError,
    WD100xImage,
    WD100xSegment,
    extract_wd100x_segments,
    parse_wd100x_rom,
)
from hdd_toolkit.hw.data_recovery import ReadRetryResult, SATADataRecoveryOps
from hdd_toolkit.hw.hpa_dco import HPADCOAccess
from hdd_toolkit.hw.issp import ISSPEngine, ISSPVector
from hdd_toolkit.hw.jtag import OpenOCDBridge
from hdd_toolkit.hw.sas import (
    SCSICapacity,
    SCSIDevice,
    SCSIInquiryData,
    SCSIOpcode,
    SESElementStatus,
    VPDPage,
    build_inquiry_cdb,
    build_read_capacity_10_cdb,
    build_read_capacity_16_cdb,
    build_receive_diagnostic_cdb,
    parse_ses_enclosure_status,
)
from hdd_toolkit.hw.spi_flash import SPIFlashCapture, SPIFlashInfo, SPITransaction
from hdd_toolkit.hw.usb_bridge import USBBridgeInfo, USBToSATABridge
from hdd_toolkit.nvme.admin import (
    NVMeAdminCmd,
    NVMeAdminPassthrough,
    NVMeDevice,
    NvmePassthruCmd,
)
from hdd_toolkit.nvme.envme import eNVMeIntegration
from hdd_toolkit.nvme.hmb import (
    HMBAllocation,
    HMBAttackModel,
    HMBDescriptor,
    build_hmb_disable_cmd,
    build_hmb_enable_cmd,
    build_hmb_get_cmd,
    parse_hmb_caps_from_identify,
)
from hdd_toolkit.nvme.ofabrics import NVMeOverFabrics
from hdd_toolkit.nvme.sandisk import SanDiskNVMeVSC
from hdd_toolkit.nvme.timing import NVMeTimingSideChannel
from hdd_toolkit.samsung_mex.aes import SamsungAESInfo
from hdd_toolkit.samsung_mex.dma import SamsungDMAHelper
from hdd_toolkit.samsung_mex.flash import SamsungFlashChannel
from hdd_toolkit.samsung_mex.gpio import SamsungGPIO
from hdd_toolkit.samsung_mex.memory_map import SamsungFlashCmd, SamsungMEXMap
from hdd_toolkit.samsung_mex.ncq import SamsungNCQParser
from hdd_toolkit.samsung_mex.safe_uart import SamsungSafeUARTClient

__all__ = [
    "ARTIFACT_8051_FW",
    "ARTIFACT_BOOT_FW",
    "ARTIFACT_FLASH_LOADER",
    "ARTIFACT_MAIN_FW",
    "ARTIFACT_MAYBE_BSS",
    "ARTIFACT_NAMES",
    "ARTIFACT_OVERLAY",
    "ARTIFACT_PADDING",
    "ATA_PASS_THROUGH_EX",
    "IDLE3_DISABLED",
    "SAMSUNG_840_EVO_FW_HISTORY",
    "WD_SA_ROM_MAP",
    "WD_VSC",
    "ASM2362NVMeBridge",
    "ATACmd",
    "ATADevice",
    "ATAError",
    "ATAFrozenBypass",
    "ATAMasterPasswordOracle",
    "ATASecurityAccess",
    "ATASecurityCommands",
    "ATASecurityStatus",
    "ColdBootResult",
    "F3Level",
    "F3SAReadCmd",
    "FirmwareDetection",
    "FirmwareIdentitySpoofDetector",
    "FirmwarePatch",
    "FirmwarePatcher",
    "FirmwareUpdateExploit",
    "HMBAllocation",
    "HMBAttackModel",
    "HMBDescriptor",
    "HPADCOAccess",
    "HitachiSAModule",
    "HitachiVSCClient",
    "HotPatchConfig",
    "I2CDiff",
    "ISSPEngine",
    "ISSPVector",
    "LZHUFDecoder",
    "MasterPasswordTable",
    "NVMeAdminCmd",
    "NVMeAdminPassthrough",
    "NVMeDevice",
    "NVMeOverFabrics",
    "NVMeTimingSideChannel",
    "NvmePassthruCmd",
    "OpenOCDBridge",
    "PSoCColdBoot",
    "PatchTemplates",
    "PowerLossFaultPlan",
    "RTL9210Bridge",
    "RTL9210FirmwareInfo",
    "ReadRetryResult",
    "SATADataRecoveryOps",
    "SATCmd",
    "SATLayer",
    "SCSICapacity",
    "SCSIDevice",
    "SCSIInquiryData",
    "SCSIOpcode",
    "SESElementStatus",
    "SPIFlashCapture",
    "SPIFlashInfo",
    "SPITransaction",
    "SamsungAESInfo",
    "SamsungDMAHelper",
    "SamsungFirmwareParser",
    "SamsungFlashChannel",
    "SamsungFlashCmd",
    "SamsungGPIO",
    "SamsungHDDEmulator",
    "SamsungMEXMap",
    "SamsungNCQParser",
    "SamsungSafeUARTClient",
    "SamsungSection",
    "SanDiskNVMeVSC",
    "SeagateArtifact",
    "SeagateArtifactParser",
    "SeagateCRC16",
    "SeagateChunkSection",
    "SeagateF3ROMMap",
    "SeagateF3SCTClient",
    "SeagateF3Terminal",
    "SeagateFWLoader",
    "SeagateLODSection",
    "SeagateOverlayInfo",
    "SeagateSAModule",
    "SeagateSectionRun",
    "SeagateSectionsHeader",
    "SeagateSegmentHeader",
    "ServiceArea",
    "SpareSectorForensics",
    "TCGDiscovery0",
    "TCGDiscovery0Parser",
    "TCGFeatureCode",
    "TCGOpalClient",
    "TCGSession",
    "ToshibaFirmwareImage",
    "ToshibaFirmwareParser",
    "USBBridgeInfo",
    "USBToSATABridge",
    "VPDPage",
    "VWCState",
    "VWCStatus",
    "WD100xFormatError",
    "WD100xImage",
    "WD100xSegment",
    "WDFirmwareParser",
    "WDIdle3Client",
    "WDPassportBridgeCmd",
    "WDPassportKeyRecovery",
    "WDPassportSecStatus",
    "WDSection",
    "WDVSCClient",
    "WriteCacheFaultModel",
    "Xbox360SecuritySector",
    "__version__",
    "__version_info__",
    "_bytes_to_asm",
    "_c",
    "_hex_dump",
    "analyse_passport",
    "assemble_thumb",
    "benchmark_reads",
    "build_delay_hook",
    "build_hmb_disable_cmd",
    "build_hmb_enable_cmd",
    "build_hmb_get_cmd",
    "build_if_recv",
    "build_if_send",
    "build_inquiry_cdb",
    "build_parser",
    "build_read_capacity_10_cdb",
    "build_read_capacity_16_cdb",
    "build_receive_diagnostic_cdb",
    "build_sa_sector_descriptor",
    "decode_timer_v100",
    "decode_timer_v103",
    "deploy_hot_patch",
    "diff_firmware",
    "dump_all_overlays",
    "eNVMeIntegration",
    "err",
    "extract_wd100x_segments",
    "find_arm_function_tables",
    "hdr",
    "hexdump",
    "info",
    "main",
    "ok",
    "parse_hmb_caps_from_identify",
    "parse_ses_enclosure_status",
    "parse_wd100x_rom",
    "plan_power_loss_fault",
    "samsung_decode",
    "scan_strings",
    "warn",
]
