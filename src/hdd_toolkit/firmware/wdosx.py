import struct
from dataclasses import dataclass, replace


class WDOSXFormatError(ValueError):
    """Raised when WDOSX metadata or packed content is malformed."""


@dataclass(frozen=True)
class WdXMetadata:
    signature: bytes
    revision: int
    flags: int
    stub_class: int
    xmem_reserve: int
    xmem_alloc: int
    wfse_start: int


@dataclass(frozen=True)
class WFSEEntry:
    offset: int
    signature: bytes
    size: int
    virtual_size: int
    flags: int
    filename: str
    ui_header_size: int
    packed_content: bytes
    unpacked_content: bytes | None = None


class _WfsePageDecoder:
    def __init__(self, packed_content: bytes, output_size: int):
        self.src = packed_content
        self.src_index = 0
        self.dst = bytearray(output_size)
        self.dst_index = 0
        self.tag_bits = 0x80
        self.dh = 0x80
        self.wbp = 0

    @staticmethod
    def _shift_left(value: int, shift_in_bit: int = 0) -> tuple[int, int]:
        shifted = (value << 1) + shift_in_bit
        return shifted & 0xFF, shifted >> 8

    @classmethod
    def _shift_left_word(cls, value: int, shift_in_bit: int = 0) -> tuple[int, int]:
        lower = value & 0xFF
        upper = value >> 8
        lower, carry = cls._shift_left(lower, shift_in_bit)
        upper, carry = cls._shift_left(upper, carry)
        return (upper << 8) + lower, carry

    def _get_bit(self) -> int:
        self.tag_bits, next_bit = self._shift_left(self.tag_bits)
        if self.tag_bits == 0:
            self.tag_bits = self.src[self.src_index]
            self.src_index += 1
            self.tag_bits, next_bit = self._shift_left(self.tag_bits, next_bit)
        return next_bit

    def _read_number(self, start_value: int) -> int:
        value = start_value * 2 + self._get_bit()
        if self._get_bit() == 1:
            return self._read_number(value)
        return value

    def _copy_literal(self) -> None:
        self.dst[self.dst_index] = self.src[self.src_index]
        self.dst_index += 1
        self.src_index += 1
        self.dh = 0x80

    def _inflate(self) -> None:
        num_bytes_to_copy = self._read_number(1)
        dst_index_offset = self._read_number(1)

        self.dh, carry_flag = self._shift_left(self.dh)
        dst_index_offset = dst_index_offset - 2 - carry_flag

        if dst_index_offset >= 0:
            dst_index_offset = dst_index_offset | 0x400
            while True:
                dst_index_offset, carry_flag = self._shift_left_word(
                    dst_index_offset, self._get_bit()
                )
                if carry_flag == 1:
                    break

            dst_index_offset += 1
            if dst_index_offset >= 0x781:
                num_bytes_to_copy += 1
            self.wbp = dst_index_offset

        copy_from_index = self.dst_index - self.wbp
        for _ in range(num_bytes_to_copy):
            self.dst[self.dst_index] = self.dst[copy_from_index]
            self.dst_index += 1
            copy_from_index += 1

    def _main_loop(self) -> None:
        start_of_page = self.dst_index
        do_copy_literal = True
        while True:
            if do_copy_literal:
                self._copy_literal()

            if (self.dst_index - start_of_page) >= 0x1000:
                return
            if self.src_index >= len(self.src):
                return

            do_copy_literal = self._get_bit() == 0
            if not do_copy_literal:
                self._inflate()

    def decompress(self) -> bytes:
        if not self.dst:
            return b""
        page_count = (len(self.dst) + 0xFFF) // 0x1000
        for _ in range(page_count):
            self.tag_bits = 0x80
            self._main_loop()
        return bytes(self.dst)


def validate_wdosx_executable(executable_data: bytes | bytearray | memoryview) -> None:
    data = bytes(executable_data)
    if len(data) < 2 or data[:2] != b"MZ":
        raise WDOSXFormatError("Not an MZ executable")
    if len(data) < 0x20 or data[0x19:0x20] != b"TIPPACH":
        raise WDOSXFormatError("TIPPACH signature not found")


def parse_wdx_metadata(
    executable_data: bytes | bytearray | memoryview, offset: int = 0x20
) -> WdXMetadata:
    data = bytes(executable_data)
    if len(data) - offset < 20:
        raise WDOSXFormatError("WDX metadata is truncated")

    signature, revision, flags, stub_class, xmem_reserve, xmem_alloc, wfse_start = (
        struct.unpack_from("<4sHBBIII", data, offset)
    )
    if signature != b"$WdX":
        raise WDOSXFormatError("Invalid $WdX signature")

    return WdXMetadata(
        signature=signature,
        revision=revision,
        flags=flags,
        stub_class=stub_class,
        xmem_reserve=xmem_reserve,
        xmem_alloc=xmem_alloc,
        wfse_start=wfse_start,
    )


def parse_wfse_entry(executable_data: bytes | bytearray | memoryview, offset: int) -> WFSEEntry:
    data = bytes(executable_data)
    if len(data) - offset < 17:
        raise WDOSXFormatError("WFSE entry is too short")

    signature, size, virtual_size, flags = struct.unpack_from("<4sIII", data, offset)
    if signature != b"WFSE":
        raise WDOSXFormatError("Invalid WFSE signature")
    if size <= 0:
        raise WDOSXFormatError("WFSE entry has invalid size")

    end_of_entry = offset + size
    if end_of_entry > len(data):
        raise WDOSXFormatError("WFSE entry extends past end of input")

    name_start = offset + 16
    name_end = data.find(b"\x00", name_start, end_of_entry)
    if name_end == -1:
        raise WDOSXFormatError("WFSE filename is not null-terminated")
    filename = data[name_start:name_end].decode("latin-1")

    ui_header_size = ((virtual_size + 0xFFF) // 0x1000 * 4) + 6
    packed_start = name_end + 1 + ui_header_size
    if packed_start > end_of_entry:
        raise WDOSXFormatError("WFSE packed content offset is invalid")
    packed_content = data[packed_start:end_of_entry]

    return WFSEEntry(
        offset=offset,
        signature=signature,
        size=size,
        virtual_size=virtual_size,
        flags=flags,
        filename=filename,
        ui_header_size=ui_header_size,
        packed_content=packed_content,
    )


def parse_wfse_entries(
    executable_data: bytes | bytearray | memoryview, metadata: WdXMetadata
) -> list[WFSEEntry]:
    data = bytes(executable_data)
    entries: list[WFSEEntry] = []
    offset = metadata.wfse_start
    while offset < len(data):
        entry = parse_wfse_entry(data, offset)
        entries.append(entry)
        offset += entry.size
    return entries


def unpack_wfse_entry(entry: WFSEEntry, *, strict: bool = False) -> bytes:
    decoder = _WfsePageDecoder(entry.packed_content, entry.virtual_size)
    try:
        return decoder.decompress()
    except Exception as exc:
        if strict:
            raise WDOSXFormatError(f"WFSE decompression failed for {entry.filename}") from exc
        return bytes(decoder.dst)


def unpack_wdosx_executable(
    executable_data: bytes | bytearray | memoryview, *, strict: bool = False
) -> tuple[WdXMetadata, list[WFSEEntry]]:
    data = bytes(executable_data)
    validate_wdosx_executable(data)
    metadata = parse_wdx_metadata(data)
    entries = parse_wfse_entries(data, metadata)
    unpacked_entries = [
        replace(entry, unpacked_content=unpack_wfse_entry(entry, strict=strict)) for entry in entries
    ]
    return metadata, unpacked_entries
