import pytest

from hdd_toolkit.firmware.wd100x import (
    WD100xFormatError,
    extract_wd100x_segments,
    parse_wd100x_rom,
)


def test_parse_wd100x_rom_default_segmentation():
    data = bytes(range(256)) * 16
    image = parse_wd100x_rom(data)
    assert image.total_size == len(data)
    assert image.segment_size == 0x800
    assert len(image.segments) == 2
    assert image.segments[0].offset == 0
    assert image.segments[1].offset == 0x800


def test_parse_wd100x_rom_require_aligned_rejects_partial_segment():
    with pytest.raises(WD100xFormatError, match="aligned"):
        parse_wd100x_rom(b"\x00" * 10, segment_size=8, require_aligned=True)


def test_extract_wd100x_segments_uses_requested_segment_size():
    segs = extract_wd100x_segments(b"ABCDEFGH", segment_size=3)
    assert [s.size for s in segs] == [3, 3, 2]
