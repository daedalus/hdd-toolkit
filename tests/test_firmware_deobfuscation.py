from Crypto.Cipher import AES

from hdd_toolkit.firmware.samsung import (
    SAMSUNG_MAGIC_IV_PREFIX,
    SAMSUNG_MAGIC_KEY,
    SAMSUNG_MAGIC_SHUFFLE,
    samsung_decode,
    samsung_decode_bytewise,
    samsung_encode,
    samsung_magic_deobfuscate,
)
from hdd_toolkit.firmware.wd import WD_DEOBFUSCATION_KEY, wd_xor_deobfuscate


def _samsung_magic_obfuscate(plain: bytes) -> bytes:
    cipher = AES.new(SAMSUNG_MAGIC_KEY, AES.MODE_ECB)
    out = bytearray()
    for block_index, start in enumerate(range(0, len(plain), 16)):
        counter = (block_index % 32) + 1
        keystream = cipher.encrypt(SAMSUNG_MAGIC_IV_PREFIX + counter.to_bytes(4, "big"))
        block = plain[start : start + 16]
        shuffled = bytes(SAMSUNG_MAGIC_SHUFFLE[value] for value in block)
        out.extend(a ^ b for a, b in zip(keystream, shuffled))
    return bytes(out)


def test_samsung_bytewise_roundtrip_full_table():
    plain = bytes(range(256))
    encoded = samsung_encode(plain)
    assert samsung_decode_bytewise(encoded) == plain
    assert samsung_decode(encoded) == plain


def test_samsung_magic_deobfuscate_roundtrip():
    plain = bytes((index * 7) & 0xFF for index in range(53))
    obfuscated = _samsung_magic_obfuscate(plain)
    assert samsung_magic_deobfuscate(obfuscated) == plain


def test_wd_xor_deobfuscation_reversible():
    plain = bytes((index * 3) & 0xFF for index in range(1025))
    obfuscated = wd_xor_deobfuscate(plain)
    assert wd_xor_deobfuscate(obfuscated) == plain
    assert wd_xor_deobfuscate(b"\x00" * 513) == WD_DEOBFUSCATION_KEY
