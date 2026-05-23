"""Tests for SamsungHDDEmulator (Unicorn-based ARM firmware emulator)."""

from unittest.mock import patch

import pytest

from hdd_toolkit.firmware.emulator import (
    SamsungHDDEmulator,
    _CAPSTONE_AVAILABLE,
    _UNICORN_AVAILABLE,
)


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------


def test_rom_address():
    assert SamsungHDDEmulator.ROM_ADDRESS == 0xFFF00000


def test_stack_address():
    assert SamsungHDDEmulator.STACK_ADDRESS == 0x80000000


def test_stack_size():
    assert SamsungHDDEmulator.STACK_SIZE == 0x10000


def test_memory_regions_non_empty():
    assert len(SamsungHDDEmulator.MEMORY_REGIONS) > 0


def test_memory_regions_all_tuples():
    for region in SamsungHDDEmulator.MEMORY_REGIONS:
        assert len(region) == 2
        base, size = region
        assert isinstance(base, int)
        assert isinstance(size, int)
        assert size > 0


def test_hardware_stubs_non_empty():
    assert len(SamsungHDDEmulator.HARDWARE_STUBS) > 0


def test_hardware_stubs_value_types():
    for addr, value in SamsungHDDEmulator.HARDWARE_STUBS.items():
        assert isinstance(addr, int)
        assert isinstance(value, bytes)
        assert len(value) > 0


def test_hardware_stubs_contains_status_register():
    assert 0xFFFE005C in SamsungHDDEmulator.HARDWARE_STUBS


def test_hardware_stubs_contains_io_fix():
    assert 0x1C00A000 + 0xA0 in SamsungHDDEmulator.HARDWARE_STUBS


def test_status_interval():
    assert SamsungHDDEmulator.STATUS_INTERVAL_SECS > 0


# ---------------------------------------------------------------------------
# Instantiation guards
# ---------------------------------------------------------------------------


def test_init_raises_without_unicorn():
    with patch("hdd_toolkit.firmware.emulator._UNICORN_AVAILABLE", False):
        with pytest.raises(ImportError, match="unicorn"):
            SamsungHDDEmulator()


def test_init_raises_without_capstone():
    with (
        patch("hdd_toolkit.firmware.emulator._UNICORN_AVAILABLE", True),
        patch("hdd_toolkit.firmware.emulator._CAPSTONE_AVAILABLE", False),
    ):
        with pytest.raises(ImportError, match="capstone"):
            SamsungHDDEmulator()


def test_run_raises_without_load_firmware():
    if not (_UNICORN_AVAILABLE and _CAPSTONE_AVAILABLE):
        pytest.skip("unicorn/capstone not installed")
    emu = SamsungHDDEmulator()
    with pytest.raises(RuntimeError, match="load_firmware"):
        emu.run()


# ---------------------------------------------------------------------------
# _unpack_address static helper
# ---------------------------------------------------------------------------


def test_unpack_address_little_endian():
    result = SamsungHDDEmulator._unpack_address(b"\x01\x00\x00\x00")
    assert result == 1


def test_unpack_address_all_bytes():
    result = SamsungHDDEmulator._unpack_address(b"\x78\x56\x34\x12")
    assert result == 0x12345678


def test_unpack_address_big_endian():
    result = SamsungHDDEmulator._unpack_address(b"\x12\x34\x56\x78", little_endian=False)
    assert result == 0x12345678


def test_unpack_address_zeros():
    assert SamsungHDDEmulator._unpack_address(b"\x00\x00\x00\x00") == 0


def test_unpack_address_ff():
    assert SamsungHDDEmulator._unpack_address(b"\xff\xff\xff\xff") == 0xFFFFFFFF


# ---------------------------------------------------------------------------
# Memory region layout sanity checks
# ---------------------------------------------------------------------------


def test_io_region_in_memory_map():
    bases = [base for base, _ in SamsungHDDEmulator.MEMORY_REGIONS]
    assert 0x1C000000 in bases


def test_fffe0000_region_in_memory_map():
    bases = [base for base, _ in SamsungHDDEmulator.MEMORY_REGIONS]
    assert 0xFFFE0000 in bases
