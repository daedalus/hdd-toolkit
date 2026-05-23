"""Tests for hdd_toolkit.ata.idle3 (WD IntelliPark idle3 timer control)."""

import pytest

from hdd_toolkit.ata.idle3 import (
    ATA_OP_SMART,
    ATA_OP_VENDOR_SPECIFIC,
    IDLE3_CYL_HI,
    IDLE3_CYL_LO,
    IDLE3_DATA_LOG,
    IDLE3_DISABLED,
    IDLE3_KEY_LOG,
    SMART_READ_LOG,
    SMART_WRITE_LOG,
    VSC_KEY_READ,
    VSC_KEY_WRITE,
    WDIdle3Client,
    decode_timer_v100,
    decode_timer_v103,
)


class _MockDevice:
    def __init__(self, read_data: bytes = b""):
        self.calls: list[dict] = []
        self._read_data = read_data

    def passthrough(self, regs: dict, data_out: bytes | None = None, data_in_size: int = 0):
        self.calls.append({"regs": regs, "data_out": data_out, "data_in_size": data_in_size})
        if data_in_size:
            return (self._read_data + b"\x00" * data_in_size)[:data_in_size]
        return b""


# =============================================================================
# Constants
# =============================================================================


def test_ata_op_smart():
    assert ATA_OP_SMART == 0xB0


def test_ata_op_vendor_specific():
    assert ATA_OP_VENDOR_SPECIFIC == 0x80


def test_smart_log_subcommands():
    assert SMART_READ_LOG == 0xD5
    assert SMART_WRITE_LOG == 0xD6


def test_cyl_registers():
    assert IDLE3_CYL_LO == 0x4F
    assert IDLE3_CYL_HI == 0xC2


def test_log_addresses():
    assert IDLE3_KEY_LOG == 0xBE
    assert IDLE3_DATA_LOG == 0xBF


def test_vsc_key_values():
    assert VSC_KEY_READ == 0x01
    assert VSC_KEY_WRITE == 0x02


def test_idle3_disabled_value():
    assert IDLE3_DISABLED == 0x00


# =============================================================================
# Timer decode helpers
# =============================================================================


def test_decode_v100_8s():
    assert decode_timer_v100(80) == pytest.approx(8.0)


def test_decode_v100_0_1s():
    assert decode_timer_v100(1) == pytest.approx(0.1)


def test_decode_v100_255():
    assert decode_timer_v100(255) == pytest.approx(25.5)


def test_decode_v103_low_range():
    assert decode_timer_v103(80) == pytest.approx(8.0)


def test_decode_v103_boundary():
    assert decode_timer_v103(128) == pytest.approx(12.8)


def test_decode_v103_high_range():
    assert decode_timer_v103(129) == pytest.approx(30.0)


def test_decode_v103_255():
    assert decode_timer_v103(255) == pytest.approx((255 - 128) * 30.0)


# =============================================================================
# WDIdle3Client.decode_timer
# =============================================================================


def test_decode_timer_disabled():
    assert WDIdle3Client.decode_timer(0) == "disabled"


def test_decode_timer_raw():
    result = WDIdle3Client.decode_timer(80, "raw")
    assert "80" in result
    assert "0x50" in result


def test_decode_timer_v100():
    result = WDIdle3Client.decode_timer(80, "v100")
    assert "8.0s" in result
    assert "0x50" in result


def test_decode_timer_v103_low():
    result = WDIdle3Client.decode_timer(80, "v103")
    assert "8.0s" in result


def test_decode_timer_v103_high():
    result = WDIdle3Client.decode_timer(129, "v103")
    assert "30.0s" in result


def test_decode_timer_disabled_all_scales():
    for scale in ("raw", "v100", "v103"):
        assert WDIdle3Client.decode_timer(0, scale) == "disabled"


# =============================================================================
# WDIdle3Client.is_wdc_drive
# =============================================================================


def _make_identify(model: str) -> bytes:
    buf = bytearray(512)
    for i, ch in enumerate(model[:40]):
        word = 27 + i // 2
        if i % 2 == 0:
            buf[word * 2 + 1] = ord(ch)
        else:
            buf[word * 2] = ord(ch)
    return bytes(buf)


def test_is_wdc_drive_positive():
    ident = _make_identify("WDC WD20EARS-00MVWB0")
    assert WDIdle3Client.is_wdc_drive(ident) is True


def test_is_wdc_drive_negative_seagate():
    ident = _make_identify("ST1000DM003-1CH162")
    assert WDIdle3Client.is_wdc_drive(ident) is False


def test_is_wdc_drive_short_buffer():
    assert WDIdle3Client.is_wdc_drive(b"\x00" * 10) is False


def test_is_wdc_drive_empty():
    assert WDIdle3Client.is_wdc_drive(b"") is False


# =============================================================================
# vsc_enable / vsc_disable
# =============================================================================


def test_vsc_enable_sends_correct_regs():
    dev = _MockDevice()
    client = WDIdle3Client(dev)
    client.vsc_enable()
    assert len(dev.calls) == 1
    regs = dev.calls[0]["regs"]
    assert regs["cmd"] == ATA_OP_VENDOR_SPECIFIC
    assert regs["features"] == 0x45
    assert regs["cyl_lo"] == 0x44
    assert regs["cyl_hi"] == 0x57
    assert dev.calls[0]["data_out"] is None


def test_vsc_disable_sends_correct_regs():
    dev = _MockDevice()
    client = WDIdle3Client(dev)
    client.vsc_disable()
    regs = dev.calls[0]["regs"]
    assert regs["cmd"] == ATA_OP_VENDOR_SPECIFIC
    assert regs["features"] == 0x44
    assert regs["cyl_lo"] == 0x44
    assert regs["cyl_hi"] == 0x57


# =============================================================================
# _send_key / send_read_key / send_write_key
# =============================================================================


def test_send_read_key_uses_smart_write_log_to_key_log():
    dev = _MockDevice()
    client = WDIdle3Client(dev)
    client.send_read_key()
    assert len(dev.calls) == 1
    regs = dev.calls[0]["regs"]
    assert regs["cmd"] == ATA_OP_SMART
    assert regs["features"] == SMART_WRITE_LOG
    assert regs["lba_lo"] == IDLE3_KEY_LOG
    assert regs["cyl_lo"] == IDLE3_CYL_LO
    assert regs["cyl_hi"] == IDLE3_CYL_HI


def test_send_read_key_buffer_layout():
    dev = _MockDevice()
    WDIdle3Client(dev).send_read_key()
    buf = dev.calls[0]["data_out"]
    assert len(buf) == 512
    assert buf[0] == 0x2A
    assert buf[2] == VSC_KEY_READ
    assert buf[4] == 0x02
    assert buf[6] == 0x0D
    assert buf[8] == 0x16
    assert buf[10] == 0x01


def test_send_write_key_buffer_layout():
    dev = _MockDevice()
    WDIdle3Client(dev).send_write_key()
    buf = dev.calls[0]["data_out"]
    assert buf[2] == VSC_KEY_WRITE


# =============================================================================
# get_timer
# =============================================================================


def test_get_timer_reads_data_log():
    dev = _MockDevice(read_data=bytes([0x50]) + b"\x00" * 511)
    client = WDIdle3Client(dev)
    value = client.get_timer()
    assert value == 0x50
    regs = dev.calls[0]["regs"]
    assert regs["cmd"] == ATA_OP_SMART
    assert regs["features"] == SMART_READ_LOG
    assert regs["lba_lo"] == IDLE3_DATA_LOG
    assert regs["count"] == 1
    assert regs["cyl_lo"] == IDLE3_CYL_LO
    assert regs["cyl_hi"] == IDLE3_CYL_HI


def test_get_timer_returns_first_byte():
    dev = _MockDevice(read_data=bytes([0x1F]) + b"\xFF" * 511)
    assert WDIdle3Client(dev).get_timer() == 0x1F


def test_get_timer_disabled():
    dev = _MockDevice(read_data=b"\x00" * 512)
    assert WDIdle3Client(dev).get_timer() == 0


# =============================================================================
# set_timer
# =============================================================================


def test_set_timer_writes_data_log():
    dev = _MockDevice()
    WDIdle3Client(dev).set_timer(0x42)
    regs = dev.calls[0]["regs"]
    assert regs["cmd"] == ATA_OP_SMART
    assert regs["features"] == SMART_WRITE_LOG
    assert regs["lba_lo"] == IDLE3_DATA_LOG
    assert regs["count"] == 1


def test_set_timer_buffer_first_byte():
    dev = _MockDevice()
    WDIdle3Client(dev).set_timer(0x42)
    buf = dev.calls[0]["data_out"]
    assert len(buf) == 512
    assert buf[0] == 0x42
    assert all(b == 0 for b in buf[1:])


def test_set_timer_masks_to_byte():
    dev = _MockDevice()
    WDIdle3Client(dev).set_timer(0x1FF)
    buf = dev.calls[0]["data_out"]
    assert buf[0] == 0xFF


def test_disable_timer_sets_zero():
    dev = _MockDevice()
    WDIdle3Client(dev).disable_timer()
    buf = dev.calls[0]["data_out"]
    assert buf[0] == IDLE3_DISABLED


# =============================================================================
# read_timer / write_timer (high-level wrappers)
# =============================================================================


def test_read_timer_sequence():
    dev = _MockDevice(read_data=bytes([0x80]) + b"\x00" * 511)
    value = WDIdle3Client(dev).read_timer()
    assert value == 0x80
    # expect: vsc_enable, send_read_key, get_timer, vsc_disable
    cmds = [c["regs"]["cmd"] for c in dev.calls]
    assert cmds == [
        ATA_OP_VENDOR_SPECIFIC,
        ATA_OP_SMART,
        ATA_OP_SMART,
        ATA_OP_VENDOR_SPECIFIC,
    ]
    assert dev.calls[0]["regs"]["features"] == 0x45
    assert dev.calls[1]["regs"]["features"] == SMART_WRITE_LOG
    assert dev.calls[2]["regs"]["features"] == SMART_READ_LOG
    assert dev.calls[3]["regs"]["features"] == 0x44


def test_write_timer_sequence():
    dev = _MockDevice()
    WDIdle3Client(dev).write_timer(0x64)
    cmds = [c["regs"]["cmd"] for c in dev.calls]
    assert cmds == [
        ATA_OP_VENDOR_SPECIFIC,
        ATA_OP_SMART,
        ATA_OP_SMART,
        ATA_OP_VENDOR_SPECIFIC,
    ]
    set_call = dev.calls[2]
    assert set_call["data_out"][0] == 0x64


def test_write_timer_disable_sequence():
    dev = _MockDevice()
    WDIdle3Client(dev).write_timer(IDLE3_DISABLED)
    set_call = dev.calls[2]
    assert set_call["data_out"][0] == 0


# =============================================================================
# Error propagation
# =============================================================================


def test_vsc_enable_propagates_ata_error():
    from hdd_toolkit.ata.commands import ATAError

    class _ErrorDevice:
        def passthrough(self, regs, data_out=None, data_in_size=0):
            raise ATAError("mock error")

    with pytest.raises(ATAError):
        WDIdle3Client(_ErrorDevice()).vsc_enable()
