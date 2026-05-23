"""Tests for SeagateCRC16 and SeagateArtifactParser (Eurecom reimplementation)."""

import struct

import pytest

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
    SeagateOverlayInfo,
    SeagateSectionRun,
    SeagateSegmentHeader,
    SeagateSectionsHeader,
    _SEAGATE_CRC16_TABLE,
)


# ---------------------------------------------------------------------------
# CRC16 table
# ---------------------------------------------------------------------------


def test_crc16_table_length():
    assert len(_SEAGATE_CRC16_TABLE) == 256


def test_crc16_table_first_entry_is_zero():
    assert _SEAGATE_CRC16_TABLE[0] == 0


def test_crc16_table_second_entry():
    assert _SEAGATE_CRC16_TABLE[1] == 0xC0C1


def test_crc16_table_all_uint16():
    for entry in _SEAGATE_CRC16_TABLE:
        assert 0 <= entry <= 0xFFFF


# ---------------------------------------------------------------------------
# SeagateCRC16.update_byte
# ---------------------------------------------------------------------------


def test_update_byte_zero_inputs():
    assert SeagateCRC16.update_byte(0, 0) == 0


def test_update_byte_one_zero_crc():
    result = SeagateCRC16.update_byte(1, 0)
    assert result == _SEAGATE_CRC16_TABLE[1]


# ---------------------------------------------------------------------------
# SeagateCRC16.compute
# ---------------------------------------------------------------------------


def test_compute_empty_data():
    assert SeagateCRC16.compute(b"") == 0


def test_compute_raises_on_non_multiple_of_4():
    with pytest.raises(ValueError, match="multiple of 4"):
        SeagateCRC16.compute(b"\x00\x00\x00")


def test_compute_all_zeros_4_bytes():
    assert SeagateCRC16.compute(b"\x00" * 4) == 0


def test_compute_known_value():
    result = SeagateCRC16.compute(b"\x01\x00\x00\x00")
    assert result == 0xC0C1


def test_compute_reversed_byte_order():
    v1 = SeagateCRC16.compute(b"\x01\x00\x00\x00")
    v2 = SeagateCRC16.compute(b"\x00\x00\x00\x01")
    assert v1 != v2


def test_compute_8_bytes():
    result = SeagateCRC16.compute(b"\x01\x02\x03\x04\x05\x06\x07\x08")
    assert isinstance(result, int)
    assert 0 <= result <= 0xFFFF


# ---------------------------------------------------------------------------
# SeagateCRC16.finalize_buffer
# ---------------------------------------------------------------------------


def test_finalize_buffer_raises_on_short():
    with pytest.raises(ValueError):
        SeagateCRC16.finalize_buffer(b"\x00\x00\x00")


def test_finalize_buffer_raises_on_non_multiple():
    with pytest.raises(ValueError):
        SeagateCRC16.finalize_buffer(b"\x00\x00\x00\x00\x00")


def test_finalize_buffer_length_preserved():
    buf = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    result = SeagateCRC16.finalize_buffer(buf)
    assert len(result) == len(buf)


def test_finalize_buffer_last_two_bytes_zero():
    buf = b"\x00" * 8
    result = SeagateCRC16.finalize_buffer(buf)
    assert result[-2] == 0
    assert result[-1] == 0


# ---------------------------------------------------------------------------
# Artifact type constants
# ---------------------------------------------------------------------------


def test_artifact_type_constants():
    assert ARTIFACT_OVERLAY == 0x4A
    assert ARTIFACT_FLASH_LOADER == 0x457
    assert ARTIFACT_BOOT_FW == 0x422
    assert ARTIFACT_MAIN_FW == 0x426
    assert ARTIFACT_MAYBE_BSS == 0x24
    assert ARTIFACT_PADDING == 0x07
    assert ARTIFACT_8051_FW == 0x9603


def test_artifact_names_covers_defined_constants():
    for const in (
        ARTIFACT_OVERLAY,
        ARTIFACT_FLASH_LOADER,
        ARTIFACT_BOOT_FW,
        ARTIFACT_MAIN_FW,
        ARTIFACT_MAYBE_BSS,
        ARTIFACT_PADDING,
        ARTIFACT_8051_FW,
    ):
        assert const in ARTIFACT_NAMES
        assert isinstance(ARTIFACT_NAMES[const], str)
        assert len(ARTIFACT_NAMES[const]) > 0


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


def test_seagate_segment_header_dataclass():
    seg = SeagateSegmentHeader(
        size_in_words=0x100,
        flash_address=0x08000000,
        load_address=0x20000000,
        field_c=0,
    )
    assert seg.size_in_words == 0x100
    assert seg.flash_address == 0x08000000
    assert seg.load_address == 0x20000000
    assert seg.file_offset == 0


def test_seagate_sections_header_dataclass():
    hdr = SeagateSectionsHeader(
        magic=0x44697363,
        field_14=0,
        checksum=0xABCD,
        field_18=0,
        field_1c=0,
    )
    assert hdr.magic == 0x44697363
    assert hdr.checksum == 0xABCD


def test_seagate_overlay_info_dataclass():
    ov = SeagateOverlayInfo(
        number=1,
        overlay_id=0xDEAD,
        size=0x1000,
        field_c=0,
        function_string_table=0x400,
        field_14=0,
        field_18=0,
        load_address=0x20001000,
        information=0,
    )
    assert ov.number == 1
    assert ov.overlay_id == 0xDEAD
    assert ov.load_address == 0x20001000


def test_seagate_chunk_section_dataclass():
    cs = SeagateChunkSection(
        size_flags=0x1000_0002,
        load_address=0x20002000,
        valid=True,
        size=0x10,
    )
    assert cs.valid is True
    assert cs.load_address == 0x20002000


def test_seagate_section_run_dataclass():
    run = SeagateSectionRun(file_offset=0x1234)
    assert run.file_offset == 0x1234
    assert run.sections == []


def test_seagate_artifact_dataclass():
    art = SeagateArtifact(
        index=0,
        file_offset=0,
        artifact_type=ARTIFACT_OVERLAY,
        subtype=1,
        content_size=0x40,
        compilation_time=0,
        compilation_date=0,
        header_checksum_ok=True,
        content_crc_ok=False,
    )
    assert art.artifact_type == ARTIFACT_OVERLAY
    assert art.artifact_name() == "Overlay"
    assert art.content == b""
    assert art.overlay_info is None
    assert art.section_runs == []


def test_seagate_artifact_name_unknown():
    art = SeagateArtifact(
        index=0,
        file_offset=0,
        artifact_type=0xFFFF,
        subtype=0,
        content_size=0x40,
        compilation_time=0,
        compilation_date=0,
        header_checksum_ok=False,
        content_crc_ok=False,
    )
    name = art.artifact_name()
    assert "0xFFFF" in name or "Unknown" in name


# ---------------------------------------------------------------------------
# SeagateArtifactParser
# ---------------------------------------------------------------------------


def test_parser_empty_data_returns_empty_list():
    parser = SeagateArtifactParser()
    result = parser.parse(b"")
    assert result == []


def test_parser_short_data_returns_empty_list():
    parser = SeagateArtifactParser()
    result = parser.parse(b"\x00" * 32)
    assert result == []


def test_parser_header_size_is_64():
    assert SeagateArtifactParser._HEADER_SIZE == 64


def test_parser_segment_size_is_16():
    assert SeagateArtifactParser._SEGMENT_SIZE == 16


def test_parser_sections_size_is_16():
    assert SeagateArtifactParser._SECTIONS_SIZE == 16


def test_parser_overlay_size_is_36():
    assert SeagateArtifactParser._OVERLAY_SIZE == 36


def test_parser_chunk_size_is_8():
    assert SeagateArtifactParser._CHUNK_SIZE == 8


def test_parser_sections_magic():
    assert SeagateArtifactParser._SECTIONS_MAGIC == 0x44697363


def _build_artifact_header(
    artifact_type: int = ARTIFACT_PADDING,
    subtype: int = 0,
    content_size: int = 8,
    compilation_time: int = 0,
    compilation_date: int = 0,
) -> bytes:
    fmt = "<LLLHHLLLLLLLLLLLHH"
    raw = bytearray(struct.pack(
        fmt,
        0, 0, 0,
        subtype, artifact_type,
        content_size,
        0, compilation_time, compilation_date,
        0, 0,
        0, 0, 0, 0, 0,
        0, 0,
    ))
    total = sum(
        ((raw[i + 1] << 8) | raw[i]) for i in range(0, len(raw) - 1, 2)
    ) & 0xFFFF
    correction = (0x10000 - total) & 0xFFFF
    struct.pack_into("<H", raw, 62, correction)
    return bytes(raw)


def test_parser_header_checksum_ok_all_zeros():
    header = bytes(64)
    assert SeagateArtifactParser._header_checksum_ok(header) is True


def test_parser_header_checksum_crafted():
    header = _build_artifact_header()
    assert SeagateArtifactParser._header_checksum_ok(header) is True


def test_parser_content_crc_ok_all_zeros():
    content = b"\x00" * 4
    crc_raw = b"\x00" * 4
    result = SeagateArtifactParser._content_crc_ok(content, crc_raw)
    assert isinstance(result, bool)


def test_parser_minimal_artifact():
    content_size = 8
    header = _build_artifact_header(
        artifact_type=ARTIFACT_PADDING, content_size=content_size
    )
    content_body = b"\x00" * (content_size - 4)
    crc_raw = b"\x00" * 4
    data = header + content_body + crc_raw

    parser = SeagateArtifactParser()
    artifacts = parser.parse(data)
    assert len(artifacts) == 1
    art = artifacts[0]
    assert art.index == 0
    assert art.file_offset == 0
    assert art.artifact_type == ARTIFACT_PADDING
    assert art.content_size == content_size
    assert art.header_checksum_ok is True


def test_parser_two_artifacts():
    content_size = 8
    header = _build_artifact_header(content_size=content_size)
    payload = b"\x00" * (content_size - 4) + b"\x00" * 4
    block = header + payload
    data = block + block

    parser = SeagateArtifactParser()
    artifacts = parser.parse(data)
    assert len(artifacts) == 2
    assert artifacts[0].index == 0
    assert artifacts[1].index == 1
    assert artifacts[1].file_offset == len(header) + content_size


def test_decode_compilation_date_zero():
    art = SeagateArtifact(
        index=0,
        file_offset=0,
        artifact_type=ARTIFACT_PADDING,
        subtype=0,
        content_size=8,
        compilation_time=0,
        compilation_date=0,
        header_checksum_ok=True,
        content_crc_ok=True,
    )
    result = art.decode_compilation_date()
    assert result is None
