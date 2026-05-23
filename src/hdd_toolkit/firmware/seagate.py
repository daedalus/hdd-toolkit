import struct
from dataclasses import dataclass, field
from datetime import datetime

from hdd_toolkit.core.utils import info, warn

# ---------------------------------------------------------------------------
# Seagate CRC16 — reverse-engineered by Eurecom (Jonas Zaddach, 2014)
# ---------------------------------------------------------------------------

_SEAGATE_CRC16_TABLE: list[int] = [
    0, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
    0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
    0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
    0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
    0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
    0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
    0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
    0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
    0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
    0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
    0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
    0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
    0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
    0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
    0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
    0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
    0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
    0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
    0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
    0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
    0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
    0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
    0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
    0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
    0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
    0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
    0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
    0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
    0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
    0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
    0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
    0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040,
]


class SeagateCRC16:
    """CRC16 checksum used in Seagate HDD firmware artifact containers.

    The algorithm processes data in 4-byte little-endian word chunks,
    feeding bytes in reversed order (3, 2, 1, 0) through a 256-entry table.

    Sources:
      - eurecom-s3/hdd_firmware_tools hdd_crc.py (clean-room Python 3 reimplementation)
      - Zaddach, J. "Looking into the Eye of the Needle", Recon 2014.
    """

    @staticmethod
    def update_byte(data: int, crc: int) -> int:
        return _SEAGATE_CRC16_TABLE[(data ^ crc) & 0xFF] ^ ((crc >> 8) & 0xFF)

    @staticmethod
    def compute(data: bytes) -> int:
        if len(data) % 4 != 0:
            raise ValueError("Data length must be a multiple of 4")
        crc = 0
        for i in range(0, len(data), 4):
            crc = SeagateCRC16.update_byte(data[i + 3], crc)
            crc = SeagateCRC16.update_byte(data[i + 2], crc)
            crc = SeagateCRC16.update_byte(data[i + 1], crc)
            crc = SeagateCRC16.update_byte(data[i + 0], crc)
        return crc

    @staticmethod
    def finalize_buffer(data: bytes) -> bytes:
        """Return data with last 4 bytes replaced by a valid CRC trailer.

        The resulting buffer passes: SeagateCRC16.compute(buf) == 0.
        """
        if len(data) < 4 or len(data) % 4 != 0:
            raise ValueError("Buffer length must be >= 4 and a multiple of 4")
        crc = SeagateCRC16.compute(data[:-4])
        crc = (crc >> 8) ^ _SEAGATE_CRC16_TABLE[crc & 0xFF]
        crc = (crc >> 8) ^ _SEAGATE_CRC16_TABLE[crc & 0xFF]
        return data[:-4] + bytes([(crc >> 8) & 0xFF, crc & 0xFF, 0, 0])


# ---------------------------------------------------------------------------
# Seagate firmware artifact type codes (reverse-engineered, Eurecom 2014)
# ---------------------------------------------------------------------------

ARTIFACT_OVERLAY: int = 0x4A
ARTIFACT_FLASH_LOADER: int = 0x457
ARTIFACT_BOOT_FW: int = 0x422
ARTIFACT_MAIN_FW: int = 0x426
ARTIFACT_MAYBE_BSS: int = 0x24
ARTIFACT_PADDING: int = 0x07
ARTIFACT_8051_FW: int = 0x9603

ARTIFACT_NAMES: dict[int, str] = {
    ARTIFACT_OVERLAY: "Overlay",
    ARTIFACT_BOOT_FW: "BootFW",
    ARTIFACT_MAYBE_BSS: "MaybeBSS",
    ARTIFACT_PADDING: "Padding",
    ARTIFACT_FLASH_LOADER: "FlashLoaderStub",
    ARTIFACT_8051_FW: "ServoController8051FW",
    ARTIFACT_MAIN_FW: "MainFWCore",
    0x41: "Unknown_0x41",
    0x53: "Unknown_0x53",
    0x4B: "Unknown_0x4B",
    0x0D: "Unknown_0x0D",
    0x43: "Unknown_0x43",
    0x442: "Unknown_0x442",
}


# ---------------------------------------------------------------------------
# Sub-structure dataclasses
# ---------------------------------------------------------------------------


@dataclass
class SeagateSegmentHeader:
    """Flash-loader stub header embedded in BOOT_FW / MAIN_FW artifacts.

    Sources:
      - eurecom-s3/hdd_firmware_tools seagate_fw_extract.py SEGMENT_HEADER_DEFINITION
    """

    size_in_words: int
    flash_address: int
    load_address: int
    field_c: int
    file_offset: int = 0


@dataclass
class SeagateSectionsHeader:
    """Section-container header following a segment header.

    magic must equal 0x44697363 (ASCII "Disc").

    Sources:
      - eurecom-s3/hdd_firmware_tools seagate_fw_extract.py SECTIONS_HEADER_DEFINITION
    """

    magic: int
    field_14: int
    checksum: int
    field_18: int
    field_1c: int
    file_offset: int = 0


@dataclass
class SeagateOverlayInfo:
    """Header of an overlay artifact.

    Sources:
      - eurecom-s3/hdd_firmware_tools seagate_fw_extract.py OVERLAY_HEADER_DEFINITION
    """

    number: int
    overlay_id: int
    size: int
    field_c: int
    function_string_table: int
    field_14: int
    field_18: int
    load_address: int
    information: int
    file_offset: int = 0


@dataclass
class SeagateChunkSection:
    """One loadable sub-chunk within a MainFW section run.

    Sources:
      - eurecom-s3/hdd_firmware_tools seagate_fw_extract.py MAIN_FW_CHUNK_HEADER_DEFINITION
    """

    size_flags: int
    load_address: int
    valid: bool
    size: int
    data: bytes = field(repr=False, default=b"")
    file_offset: int = 0


@dataclass
class SeagateSectionRun:
    """A linked list of SeagateChunkSection objects sharing a list-head pointer.

    Sources:
      - eurecom-s3/hdd_firmware_tools seagate_fw_extract.py parse_sections()
    """

    file_offset: int
    sections: list[SeagateChunkSection] = field(default_factory=list)


@dataclass
class SeagateArtifact:
    """One top-level artifact parsed from a Seagate .lod firmware file.

    Sources:
      - eurecom-s3/hdd_firmware_tools seagate_fw_extract.py load_file()
    """

    index: int
    file_offset: int
    artifact_type: int
    subtype: int
    content_size: int
    compilation_time: int
    compilation_date: int
    header_checksum_ok: bool
    content_crc_ok: bool
    raw_header: bytes = field(repr=False, default=b"")
    content: bytes = field(repr=False, default=b"")
    segment_header: SeagateSegmentHeader | None = field(default=None)
    sections_header: SeagateSectionsHeader | None = field(default=None)
    section_runs: list[SeagateSectionRun] = field(default_factory=list)
    overlay_info: SeagateOverlayInfo | None = field(default=None)

    def artifact_name(self) -> str:
        return ARTIFACT_NAMES.get(self.artifact_type, f"Unknown_0x{self.artifact_type:X}")

    def decode_compilation_date(self) -> datetime | None:
        """Decode the packed ASCII-hex compilation_date field as a datetime.

        The 32-bit value encodes YYYYDDMM where each pair of digits is BCD.
        """
        try:
            raw = self.compilation_date
            year = int("%04x" % (raw >> 16))
            month = int("%02x" % (raw & 0xFF))
            day = int("%02x" % ((raw >> 8) & 0xFF))
            hour = int("%02x" % ((self.compilation_time >> 24) & 0xFF))
            minute = int("%02x" % ((self.compilation_time >> 16) & 0xFF))
            return datetime(year, month, day, hour, minute)
        except (ValueError, OverflowError):
            return None


# ---------------------------------------------------------------------------
# SeagateArtifactParser
# ---------------------------------------------------------------------------


class SeagateArtifactParser:
    """Parse Seagate .lod firmware files using the artifact container format.

    Each artifact occupies:
      - 64-byte header (type, content_size, compilation date/time, checksum)
      - N-4 bytes of content  (N = content_size)
      - 4-byte CRC16 trailer

    Type-specific sub-structures (segment header, sections header, overlays)
    are nested inside the content.

    Sources:
      - eurecom-s3/hdd_firmware_tools seagate_fw_extract.py (clean-room Python 3 reimplementation)
      - Zaddach, J. "Looking into the Eye of the Needle", Recon 2014.
    """

    _HEADER_FMT = "<LLLHHLLLLLLLLLLLHH"
    _HEADER_SIZE: int = struct.calcsize(_HEADER_FMT)  # 64 bytes

    _SEGMENT_FMT = "<LLLL"
    _SEGMENT_SIZE: int = struct.calcsize(_SEGMENT_FMT)  # 16 bytes

    _SECTIONS_FMT = "<LHHLL"
    _SECTIONS_SIZE: int = struct.calcsize(_SECTIONS_FMT)  # 16 bytes

    _OVERLAY_FMT = "<LLLLLLLLL"
    _OVERLAY_SIZE: int = struct.calcsize(_OVERLAY_FMT)  # 36 bytes

    _CHUNK_FMT = "<LL"
    _CHUNK_SIZE: int = struct.calcsize(_CHUNK_FMT)  # 8 bytes

    _SECTIONS_MAGIC: int = 0x44697363  # ASCII "Disc"

    def parse(self, data: bytes) -> list[SeagateArtifact]:
        artifacts: list[SeagateArtifact] = []
        offset = 0
        index = 0

        while offset < len(data):
            if offset + self._HEADER_SIZE > len(data):
                break

            header_raw = data[offset : offset + self._HEADER_SIZE]
            (
                _f0, _f4, _f8, subtype, artifact_type,
                content_size, _f14, compilation_time, compilation_date,
                _f20, _size, _f28, _f2c, _f30, _f34, _f38,
                _f3c, _checksum_16bit,
            ) = struct.unpack_from(self._HEADER_FMT, header_raw)

            if content_size == 0 or offset + self._HEADER_SIZE + content_size > len(data):
                warn(
                    f"Artifact {index}: content_size={content_size} out of range "
                    f"at file offset 0x{offset:X}"
                )
                break

            content_end = offset + self._HEADER_SIZE + content_size
            content_raw = data[offset + self._HEADER_SIZE : content_end - 4]
            crc_raw = data[content_end - 4 : content_end]

            header_ok = self._header_checksum_ok(header_raw)
            crc_ok = self._content_crc_ok(content_raw, crc_raw)

            artifact = SeagateArtifact(
                index=index,
                file_offset=offset,
                artifact_type=artifact_type,
                subtype=subtype,
                content_size=content_size,
                compilation_time=compilation_time,
                compilation_date=compilation_date,
                header_checksum_ok=header_ok,
                content_crc_ok=crc_ok,
                raw_header=header_raw,
                content=content_raw,
            )

            self._parse_content(artifact, content_raw, offset + self._HEADER_SIZE)
            artifacts.append(artifact)

            offset = content_end
            index += 1

        return artifacts

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _header_checksum_ok(header_raw: bytes) -> bool:
        total = 0
        for i in range(0, len(header_raw) - 1, 2):
            total = (total + ((header_raw[i + 1] << 8) | header_raw[i])) & 0xFFFF
        return total == 0

    @staticmethod
    def _content_crc_ok(content_raw: bytes, crc_raw: bytes) -> bool:
        combined = content_raw + crc_raw
        if len(combined) % 4 != 0:
            return False
        try:
            return SeagateCRC16.compute(combined) == 0
        except ValueError:
            return False

    def _parse_content(
        self, artifact: SeagateArtifact, content: bytes, base_file_offset: int
    ) -> None:
        atype = artifact.artifact_type
        if atype in (
            ARTIFACT_FLASH_LOADER,
            ARTIFACT_BOOT_FW,
            ARTIFACT_MAIN_FW,
            ARTIFACT_MAYBE_BSS,
        ):
            self._parse_fw_artifact(artifact, content, base_file_offset)
        elif atype == ARTIFACT_OVERLAY:
            self._parse_overlay_artifact(artifact, content, base_file_offset)

    def _parse_fw_artifact(
        self, artifact: SeagateArtifact, content: bytes, base_file_offset: int
    ) -> None:
        if len(content) < self._SEGMENT_SIZE:
            return
        (size_in_words, flash_address, load_address, field_c) = struct.unpack_from(
            self._SEGMENT_FMT, content
        )
        seg = SeagateSegmentHeader(
            size_in_words=size_in_words,
            flash_address=flash_address,
            load_address=load_address,
            field_c=field_c,
            file_offset=base_file_offset,
        )
        artifact.segment_header = seg

        sec_start = self._SEGMENT_SIZE
        if len(content) < sec_start + self._SECTIONS_SIZE:
            return
        (magic, field_14, checksum, field_18, field_1c) = struct.unpack_from(
            self._SECTIONS_FMT, content, sec_start
        )
        if magic != self._SECTIONS_MAGIC:
            return
        sechdr = SeagateSectionsHeader(
            magic=magic,
            field_14=field_14,
            checksum=checksum,
            field_18=field_18,
            field_1c=field_1c,
            file_offset=base_file_offset + sec_start,
        )
        artifact.sections_header = sechdr

        runs_start = self._SEGMENT_SIZE + self._SECTIONS_SIZE
        artifact.section_runs = self._parse_section_runs(
            content, runs_start, base_file_offset
        )

    def _parse_section_runs(
        self, content: bytes, runs_start: int, base_file_offset: int
    ) -> list[SeagateSectionRun]:
        runs: list[SeagateSectionRun] = []
        ptr = runs_start
        while ptr + 4 <= len(content):
            head = struct.unpack_from("<L", content, ptr)[0]
            list_id = head & 0x3F
            list_offset = head >> 8
            if list_id == 0:
                break
            run = SeagateSectionRun(file_offset=base_file_offset + ptr)
            chunk_ptr = list_offset
            while chunk_ptr + self._CHUNK_SIZE <= len(content):
                (size_flags, load_address) = struct.unpack_from(
                    self._CHUNK_FMT, content, chunk_ptr
                )
                valid = (size_flags & 0x1E) != 0
                chunk_size = ((size_flags >> 0xC) & 0xFFFFF) * 4
                chunk_data = content[
                    chunk_ptr + self._CHUNK_SIZE : chunk_ptr + self._CHUNK_SIZE + chunk_size
                ]
                run.sections.append(
                    SeagateChunkSection(
                        size_flags=size_flags,
                        load_address=load_address,
                        valid=valid,
                        size=chunk_size,
                        data=chunk_data,
                        file_offset=base_file_offset + chunk_ptr + self._CHUNK_SIZE,
                    )
                )
                if not valid:
                    break
                chunk_ptr += self._CHUNK_SIZE + chunk_size
            runs.append(run)
            ptr += 4
        return runs

    def _parse_overlay_artifact(
        self, artifact: SeagateArtifact, content: bytes, base_file_offset: int
    ) -> None:
        if len(content) < self._OVERLAY_SIZE:
            return
        (number, overlay_id, size, field_c, func_str_table, f14, f18, load_address, information) = (
            struct.unpack_from(self._OVERLAY_FMT, content)
        )
        artifact.overlay_info = SeagateOverlayInfo(
            number=number,
            overlay_id=overlay_id,
            size=size,
            field_c=field_c,
            function_string_table=func_str_table,
            field_14=f14,
            field_18=f18,
            load_address=load_address,
            information=information,
            file_offset=base_file_offset,
        )


@dataclass
class SeagateLODSection:
    id: int
    offset: int
    size: int
    load_addr: int
    flags: int
    checksum: int
    data: bytes = field(repr=False, default=b"")


class SeagateFWLoader:
    """
    Seagate .lod firmware file parser/repacker.
    .lod files are the standard Seagate firmware update container format,
    used by the F3 architecture (Barracuda, IronWolf, Exos families).

    Format structure (confirmed by Eurecom tools and MalwareTech RE):
      Offset  Size  Field
      ==============================================
      0x000   4     Magic: 0x014C444C  (little-endian, ASCII: 'LD' + '\\x01\\x00')
      0x004   4     Header size (typically 0x30)
      0x008   4     Section count
      0x00C  20     Vendor string (20 bytes, null-padded)
      0x020   N*16  Section descriptors

    Each section descriptor:
      0x00  2     Section ID
      0x02  2     Data offset in file (short form; 0=inline after descriptor)
      0x04  4     Data size (bytes)
      0x08  4     Load address  (ARM Thumb destination in DRAM)
      0x0C  2     Flags
      0x0E  2     Checksum (sum of payload bytes & 0xFFFF)

    Sources:
      - INVESTIGATION.md  -- "seagate_fw_extract.py":
          Eurecom's hdd_firmware_tools confirms MAGIC/structure
      - INVESTIGATION.md  -- "MalwareTech -- Hard Disk Firmware Hacking":
          Multi-core architecture (core 1=debug, core 2=SATA+bootloader)
      - INVESTIGATION.md  -- "HDD Serial Commander":
          Seagate F3 diagnostic UART for low-level firmware ops
    """

    HEADER_SIZE = 32
    DESC_SIZE = 16
    MAGIC = 0x014C444C  # 'LOD\x01' little-endian

    def parse(self, data: bytes) -> list[SeagateLODSection]:
        if len(data) < self.HEADER_SIZE:
            raise ValueError(f"File too small for .lod header ({len(data)} bytes)")

        magic = struct.unpack_from("<I", data, 0)[0]
        if magic != self.MAGIC:
            raise ValueError(f"Bad .lod magic: 0x{magic:08X} (expected 0x{self.MAGIC:08X})")

        header_size = struct.unpack_from("<I", data, 4)[0]
        total_sections = struct.unpack_from("<I", data, 8)[0]
        data[12:32].rstrip(b"\x00").decode("ascii", errors="replace")

        sections = []
        desc_off = header_size if header_size >= self.HEADER_SIZE else self.HEADER_SIZE

        for i in range(total_sections):
            if desc_off + self.DESC_SIZE > len(data):
                warn(f"Section {i}: truncated descriptor at offset 0x{desc_off:X}")
                break

            sec_id, sec_off, sec_size, load_addr, flags, csum = struct.unpack_from(
                "<HHIIHH", data, desc_off
            )

            if sec_size == 0xFFFF or sec_size == 0:
                info(f"Section {sec_id}: skip (size=0/0xFFFF)")
                desc_off += self.DESC_SIZE
                continue

            raw_start = sec_off if sec_off else desc_off + self.DESC_SIZE
            raw_end = raw_start + sec_size

            sec_data = data[raw_start:raw_end] if raw_end <= len(data) else data[raw_start:]
            calc_cs = sum(sec_data) & 0xFFFF
            cs_ok = calc_cs == csum or csum == 0

            sections.append(
                SeagateLODSection(
                    id=i,
                    offset=raw_start,
                    size=sec_size,
                    load_addr=load_addr,
                    flags=flags,
                    checksum=csum,
                    data=sec_data,
                )
            )

            if not cs_ok:
                warn(
                    f"Section {sec_id}: checksum mismatch (file=0x{csum:04X} calc=0x{calc_cs:04X})"
                )

            desc_off += self.DESC_SIZE

        return sections

    @staticmethod
    def repack(sections: list[SeagateLODSection], vendor_str: str = "") -> bytes:
        """Re-pack sections back into a .lod file."""
        header = bytearray(32)
        struct.pack_into("<I", header, 0, SeagateFWLoader.MAGIC)
        struct.pack_into("<I", header, 4, 32)
        struct.pack_into("<I", header, 8, len(sections))
        vendor_bytes = vendor_str.encode()[:20]
        header[12 : 12 + len(vendor_bytes)] = vendor_bytes

        descs = bytearray()
        body = bytearray()
        offset = 32 + len(sections) * SeagateFWLoader.DESC_SIZE

        for sec in sections:
            aligned = (offset + 3) & ~3
            body.extend(b"\x00" * (aligned - offset))
            offset = aligned + len(sec.data)
            descs += struct.pack(
                "<HHIIHH",
                sec.id,
                offset,
                len(sec.data),
                sec.load_addr,
                sec.flags,
                sum(sec.data) & 0xFFFF,
            )
            body += sec.data

        return bytes(header + descs + body)
