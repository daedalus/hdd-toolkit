import struct
from dataclasses import dataclass, field

from hdd_toolkit.core.utils import warn

WD_DEOBFUSCATION_KEY = bytes.fromhex(
    "6f6f6e76796a6a723466656a6a30776c6f6f6c753161717170327679796f326d"
    "336f6f37356776766434786c61616d713862626b393735343472647370703764"
    "366874746164796161676e6c6c63636766766e6e73736a656767756537686863"
    "79327a6a6a386f36616164683776616135726e3535696b67387a7a3466327777"
    "39687032767665656832326d687162777730353839393762336f383839797175"
    "753066656769693868687676317a3665787873746a3434776833723535376774"
    "7171323164796969686e697a7a6b786230303062357a73737769683679793237"
    "6b6f6f77777833727274397631316f6e7a70747469676963636f74367a626278"
    "6e6365656b6a646f32327475666e6e7570726a656538736f7777667835386d6d"
    "7869363434336c3133757576626b6b6b797169786a6a6d793977773137626136"
    "363478676d6d707775316c6c61746134347265796866666339646d6d70353773"
    "646465783839396d616c6264646f353867677864766830307936377272336279"
    "746c6c6e673563636b7a6b306868356431363662753738696936797a6a6a316f"
    "68376464333638626279707a797a7a35733838387162707036366e7077616165"
    "6e667376767862657474666b703939397a79787777766471727070666e786969"
    "32327437646473626d3535393475677171386c7274746167316574747362766b"
    "00"
)


def wd_xor_deobfuscate(data: bytes | bytearray | memoryview, offset: int = 0) -> bytes:
    """Decode WD-obfuscated bytes using the repeating 513-byte XOR key."""
    src = bytes(data)
    key_len = len(WD_DEOBFUSCATION_KEY)
    return bytes(
        value ^ WD_DEOBFUSCATION_KEY[(offset + index) % key_len] for index, value in enumerate(src)
    )


class LZHUFDecoder:
    """
    LZHUF decompressor with Western Digital variant constants:
      N         = 4096   (standard = 2048)
      F         = 60     (max match length)
      THRESHOLD = 2
      run_len   = match_len - THRESHOLD   (standard adds THRESHOLD)
    """

    N = 4096
    F = 60
    THRESHOLD = 2
    NIL = N

    def __init__(self):
        self._init_tree()

    def _init_tree(self):
        self.lson = [0] * (self.N + 1)
        self.rson = [0] * (self.N + 257)
        self.dad = [0] * (self.N + 1)

    def decompress(self, data: bytes) -> bytes:
        src = bytearray(data)
        out = bytearray()
        ring = bytearray(b" " * self.N)
        r = self.N - self.F
        si = 0

        flags = 0
        flag_count = 0

        while si < len(src):
            if flag_count == 0:
                if si >= len(src):
                    break
                flags = src[si]
                si += 1
                flag_count = 8

            if flags & 1:
                # Literal byte
                if si >= len(src):
                    break
                c = src[si]
                si += 1
                out.append(c)
                ring[r] = c
                r = (r + 1) & (self.N - 1)
            else:
                # Back reference
                if si + 1 >= len(src):
                    break
                pos = src[si] | ((src[si + 1] & 0xF0) << 4)
                si += 2
                length = (src[si - 1] & 0x0F) + self.THRESHOLD
                for _ in range(length):
                    c = ring[pos & (self.N - 1)]
                    out.append(c)
                    ring[r] = c
                    r = (r + 1) & (self.N - 1)
                    pos = (pos + 1) & (self.N - 1)

            flags >>= 1
            flag_count -= 1

        return bytes(out)


# =============================================================================
# WD firmware image parser
# =============================================================================


@dataclass
class WDSection:
    index: int
    base_addr: int
    file_offset: int
    compressed_size: int
    decompressed_size: int
    checksum: int
    is_loader: bool
    data: bytes = field(repr=False, default=b"")
    decompressed_data: bytes = field(repr=False, default=b"")


class WDFirmwareParser:
    SECTION_HEADER_SIZE = 0x10

    def parse(self, data: bytes) -> list[WDSection]:
        sections = []
        offset = 0
        index = 0

        while offset + self.SECTION_HEADER_SIZE <= len(data):
            base_addr, comp_size, decomp_size, checksum = struct.unpack_from("<IIHH", data, offset)

            if base_addr == 0xFFFFFFFF:
                break  # sentinel

            sec_data = data[
                offset + self.SECTION_HEADER_SIZE : offset + self.SECTION_HEADER_SIZE + comp_size
            ]

            calc_cs = sum(sec_data) & 0xFF
            cs_ok = calc_cs == (checksum & 0xFF)

            sec = WDSection(
                index=index,
                base_addr=base_addr,
                file_offset=offset,
                compressed_size=comp_size,
                decompressed_size=decomp_size,
                checksum=checksum,
                is_loader=(index == 0),
                data=sec_data,
            )

            if index == 0:
                sec.decompressed_data = sec_data  # loader is not compressed
            else:
                try:
                    sec.decompressed_data = LZHUFDecoder().decompress(sec_data)
                except Exception as e:
                    warn(f"Section {index}: decompression failed - {e}")
                    sec.decompressed_data = sec_data

            if not cs_ok:
                warn(
                    f"Section {index}: checksum mismatch "
                    f"(file={checksum:#04x} calc={calc_cs:#04x})"
                )

            sections.append(sec)
            offset += self.SECTION_HEADER_SIZE + comp_size
            index += 1

        return sections

    @staticmethod
    def repack(sections: list[WDSection]) -> bytes:
        """Re-pack sections back into a flat firmware image with updated checksums."""
        out = bytearray()
        for sec in sections:
            cs = sum(sec.data) & 0xFF
            hdr_bytes = struct.pack(
                "<IIHH", sec.base_addr, len(sec.data), sec.decompressed_size, cs
            )
            out += hdr_bytes + sec.data
        out += struct.pack("<I", 0xFFFFFFFF)  # sentinel
        return bytes(out)
