"""WD100x ROM parsing helpers (clean-room implementation)."""

from dataclasses import dataclass, field
from hashlib import sha256


class WD100xFormatError(ValueError):
    """Raised when WD100x ROM metadata is malformed.

    Sources:
      - Clean-room design based on generic ROM image handling patterns.
    """


@dataclass(frozen=True)
class WD100xSegment:
    """A fixed-size segment in a WD100x ROM image.

    Sources:
      - Clean-room design based on generic ROM image handling patterns.
    """

    index: int
    offset: int
    size: int
    digest_sha256: str
    data: bytes = field(repr=False)


@dataclass(frozen=True)
class WD100xImage:
    """Parsed WD100x ROM image summary.

    Sources:
      - Clean-room design based on generic ROM image handling patterns.
    """

    segment_size: int
    total_size: int
    image_sha256: str
    segments: list[WD100xSegment]


def parse_wd100x_rom(
    rom_data: bytes | bytearray | memoryview,
    *,
    segment_size: int = 0x800,
    require_aligned: bool = False,
) -> WD100xImage:
    """Parse a flat WD100x ROM blob into fixed-size segments.

    Sources:
      - Clean-room design based on generic ROM image handling patterns.
    """
    data = bytes(rom_data)
    if segment_size <= 0:
        raise WD100xFormatError("segment_size must be > 0")
    if require_aligned and (len(data) % segment_size != 0):
        raise WD100xFormatError("ROM size is not aligned to segment_size")

    segments: list[WD100xSegment] = []
    for index, offset in enumerate(range(0, len(data), segment_size)):
        chunk = data[offset : offset + segment_size]
        segments.append(
            WD100xSegment(
                index=index,
                offset=offset,
                size=len(chunk),
                digest_sha256=sha256(chunk).hexdigest(),
                data=chunk,
            )
        )

    return WD100xImage(
        segment_size=segment_size,
        total_size=len(data),
        image_sha256=sha256(data).hexdigest(),
        segments=segments,
    )


def extract_wd100x_segments(
    rom_data: bytes | bytearray | memoryview,
    *,
    segment_size: int = 0x800,
    require_aligned: bool = False,
) -> list[WD100xSegment]:
    """Return the parsed WD100x ROM segments.

    Sources:
      - Clean-room design based on generic ROM image handling patterns.
    """
    return parse_wd100x_rom(
        rom_data, segment_size=segment_size, require_aligned=require_aligned
    ).segments
