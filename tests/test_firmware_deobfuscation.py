from hdd_toolkit.firmware.samsung import (
    samsung_decode,
    samsung_decode_bytewise,
    samsung_encode,
    samsung_magic_deobfuscate,
)
from hdd_toolkit.firmware.wd import WD_DEOBFUSCATION_KEY, wd_xor_deobfuscate


def test_samsung_bytewise_roundtrip_full_table():
    plain = bytes(range(256))
    encoded = samsung_encode(plain)
    assert samsung_decode_bytewise(encoded) == plain
    assert samsung_decode(encoded) == plain


def test_samsung_magic_deobfuscate_roundtrip():
    plain = bytes.fromhex(
        "00070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9"
        "e0e7eef5fc030a11181f262d343b424950575e656c"
    )
    obfuscated = bytes.fromhex(
        "65ca348c729d5fad8f43ead365fc605931af2382c52243d79affa9014e1417f0"
        "7b3f2412501d25cae48b474fdc21bf6ef47a1345dc"
    )
    assert samsung_magic_deobfuscate(obfuscated) == plain


def test_wd_xor_deobfuscation_reversible():
    plain = bytes((index * 3) & 0xFF for index in range(1025))
    obfuscated = wd_xor_deobfuscate(plain)
    assert wd_xor_deobfuscate(obfuscated) == plain
    assert wd_xor_deobfuscate(b"\x00" * 513) == WD_DEOBFUSCATION_KEY
