import struct

import pytest

from hdd_toolkit.firmware.wdosx import (
    WDOSXFormatError,
    parse_wdx_metadata,
    parse_wfse_entries,
    parse_wfse_entry,
    unpack_wdosx_executable,
    validate_wdosx_executable,
    wfse_ui_header_size,
)


def _build_wfse_entry(filename: str, virtual_size: int, packed_content: bytes) -> bytes:
    name_bytes = filename.encode("ascii")
    ui_header_size = wfse_ui_header_size(virtual_size)
    body = bytearray()
    body.extend(struct.pack("<4sIII", b"WFSE", 0, virtual_size, 0))
    body.extend(name_bytes)
    body.append(0)
    body.extend(b"\x00" * ui_header_size)
    body.extend(packed_content)
    struct.pack_into("<I", body, 4, len(body))
    return bytes(body)


def _build_wdosx_executable(entries: list[bytes]) -> bytes:
    data = bytearray(b"\x00" * 0x40)
    data[:2] = b"MZ"
    data[0x19:0x20] = b"TIPPACH"
    struct.pack_into("<4sHBBIII", data, 0x20, b"$WdX", 1, 2, 3, 0x1000, 0x2000, 0x40)
    for entry in entries:
        data.extend(entry)
    return bytes(data)


def test_wdosx_parse_and_unpack_minimal_entries():
    exe = _build_wdosx_executable(
        [
            _build_wfse_entry("a.bin", virtual_size=1, packed_content=b"A"),
            _build_wfse_entry("b.bin", virtual_size=1, packed_content=b"B"),
        ]
    )

    validate_wdosx_executable(exe)
    metadata = parse_wdx_metadata(exe)
    entries = parse_wfse_entries(exe, metadata)
    assert metadata.wfse_start == 0x40
    assert [entry.filename for entry in entries] == ["a.bin", "b.bin"]

    _, unpacked = unpack_wdosx_executable(exe, strict=True)
    assert unpacked[0].unpacked_content == b"A"
    assert unpacked[1].unpacked_content == b"B"


def test_wdosx_validate_executable_rejects_invalid_headers():
    with pytest.raises(WDOSXFormatError, match="MZ"):
        validate_wdosx_executable(b"\x00\x00")

    bad = bytearray(b"MZ" + b"\x00" * 0x30)
    with pytest.raises(WDOSXFormatError, match="TIPPACH"):
        validate_wdosx_executable(bad)


def test_wdosx_parse_wfse_entry_rejects_invalid_signature():
    bad = bytearray(_build_wfse_entry("bad.bin", virtual_size=1, packed_content=b"A"))
    bad[:4] = b"NOPE"
    with pytest.raises(WDOSXFormatError, match="WFSE"):
        parse_wfse_entry(bad, 0)
