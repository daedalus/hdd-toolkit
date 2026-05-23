import struct
from dataclasses import dataclass, field

from Crypto.Cipher import AES

SAMSUNG_MAGIC_SHUFFLE = bytes.fromhex(
    "101112131415161718191a1b1c1d1e1f303132333435363738393a3b3c3d3e3f"
    "505152535455565758595a5b5c5d5e5f707172737475767778797a7b7c7d7e7f"
    "909192939495969798999a9b9c9d9e9fb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
    "d0d1d2d3d4d5d6d7d8d9dadbdcdddedff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    "e0e1e2e3e4e5e6e7e8e9eaebecedeeefc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf808182838485868788898a8b8c8d8e8f"
    "606162636465666768696a6b6c6d6e6f404142434445464748494a4b4c4d4e4f"
    "202122232425262728292a2b2c2d2e2f000102030405060708090a0b0c0d0e0f"
)
SAMSUNG_MAGIC_KEY = bytes.fromhex("56e47a38c5598974bc46903dba290349")
SAMSUNG_MAGIC_IV_PREFIX = bytes.fromhex("8ce82eefbea0da3c44699ed7")
SAMSUNG_MAGIC_COUNTER_WINDOW = 32


def _as_bytes(data: bytes | bytearray | memoryview) -> bytes:
    try:
        return bytes(data)
    except TypeError as exc:
        raise TypeError("Expected bytes-like input") from exc


def _invert_table(table: bytes) -> bytes:
    if len(table) != 256:
        raise ValueError("Shuffle table must be exactly 256 bytes")
    inverse = bytearray(256)
    seen = bytearray(256)
    for index, value in enumerate(table):
        if seen[value]:
            raise ValueError("Shuffle table must contain each byte exactly once")
        seen[value] = 1
        inverse[value] = index
    return bytes(inverse)


SAMSUNG_MAGIC_UNSHUFFLE = _invert_table(SAMSUNG_MAGIC_SHUFFLE)


def samsung_encode_byte(value: int) -> int:
    """Encode one byte with Samsung's PM871/840 obfuscation primitive.

    Sources:
      - ddcc/drive_firmware samsung utility behavior (clean-room reimplementation)
    """
    if value & 0x80:
        return ((~(value << 1)) & 0xE0) | (value & 0x0F)
    return ((value << 1) & 0xE0) | 0x10 | (value & 0x0F)


def samsung_decode_byte(value: int) -> int:
    """Decode one byte with Samsung's PM871/840 obfuscation primitive.

    Sources:
      - ddcc/drive_firmware samsung utility behavior (clean-room reimplementation)
    """
    if value & 0x10:
        return ((value >> 1) & 0x70) | (value & 0x0F)
    return ((~(value >> 1)) & 0x70) | 0x80 | (value & 0x0F)


def samsung_encode(data: bytes | bytearray | memoryview) -> bytes:
    """Encode bytes using Samsung's bytewise obfuscation transform.

    Sources:
      - ddcc/drive_firmware samsung utility behavior (clean-room reimplementation)
    """
    src = _as_bytes(data)
    return bytes(samsung_encode_byte(value) for value in src)


def samsung_decode_bytewise(data: bytes | bytearray | memoryview) -> bytes:
    """Decode bytes using Samsung's bytewise obfuscation transform.

    Sources:
      - ddcc/drive_firmware samsung utility behavior (clean-room reimplementation)
    """
    src = _as_bytes(data)
    return bytes(samsung_decode_byte(value) for value in src)


def samsung_decode(data: bytes | bytearray | memoryview) -> bytes:
    """Backward-compatible alias for Samsung bytewise decode.

    Sources:
      - ddcc/drive_firmware samsung utility behavior (clean-room reimplementation)
    """
    return samsung_decode_bytewise(data)


def samsung_magic_deobfuscate(
    data: bytes | bytearray | memoryview,
    *,
    key: bytes = SAMSUNG_MAGIC_KEY,
    iv_prefix: bytes = SAMSUNG_MAGIC_IV_PREFIX,
    shuffle_table: bytes = SAMSUNG_MAGIC_SHUFFLE,
) -> bytes:
    """
    Deobfuscate Samsung firmware blocks using AES-generated keystream and unshuffle.

    The transform uses AES-ECB to generate 16-byte keystream blocks from:
    ``iv_prefix (12 bytes) + counter_be (4 bytes)``.
    The 32-bit counter starts at 1 and wraps every 32 blocks.

    Sources:
      - chrivers/samsung-firmware-magic behavior (clean-room reimplementation)
    """
    src = _as_bytes(data)
    if len(key) != 16:
        raise ValueError("AES key must be 16 bytes")
    if len(iv_prefix) != 12:
        raise ValueError("IV prefix must be 12 bytes")
    unshuffle = (
        SAMSUNG_MAGIC_UNSHUFFLE
        if shuffle_table == SAMSUNG_MAGIC_SHUFFLE
        else _invert_table(shuffle_table)
    )

    cipher = AES.new(key, AES.MODE_ECB)
    out = bytearray()
    for block_index, start in enumerate(range(0, len(src), 16)):
        counter = (block_index % SAMSUNG_MAGIC_COUNTER_WINDOW) + 1
        keystream = cipher.encrypt(iv_prefix + counter.to_bytes(4, "big"))
        block = src[start : start + 16]
        xored = bytes(a ^ b for a, b in zip(block, keystream))
        out.extend(unshuffle[value] for value in xored)
    return bytes(out)


@dataclass
class SamsungSection:
    index: int
    base_addr: int
    offset: int
    size: int
    data: bytes = field(repr=False, default=b"")


class SamsungFirmwareParser:
    """
    Parse Samsung PM871a firmware images.
    Section descriptors appear after an 8KB metadata block.
    Offset and size are in units of 16KB blocks.
    """

    BLOCK_SIZE = 0x4000  # 16 KB
    META_SIZE = 0x2000  # 8  KB
    DESC_STRIDE = 0x10

    def parse(self, data: bytes) -> list[SamsungSection]:
        sections = []
        offset = self.META_SIZE
        index = 0

        while offset + self.DESC_STRIDE <= len(data):
            base_addr, blk_offset, blk_size, _flags = struct.unpack_from("<IIII", data, offset)

            if base_addr == 0 and blk_offset == 0:
                offset += self.DESC_STRIDE
                continue
            if base_addr == 0xFFFFFFFF:
                break

            byte_offset = blk_offset * self.BLOCK_SIZE
            byte_size = blk_size * self.BLOCK_SIZE

            sec_data = data[byte_offset : byte_offset + byte_size]

            sections.append(
                SamsungSection(
                    index=index,
                    base_addr=base_addr,
                    offset=byte_offset,
                    size=byte_size,
                    data=sec_data,
                )
            )

            offset += self.DESC_STRIDE
            index += 1

        return sections
