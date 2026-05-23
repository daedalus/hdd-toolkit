"""Samsung HM641JI HDD firmware emulator (Unicorn-based).

Clean-room Python 3 reimplementation of egueler/HDD-Firmware-Emulation.

Sources:
  - egueler/HDD-Firmware-Emulation unicorn-gdb.py (clean-room reimplementation)
"""

import datetime
import json
import os
import sys
import time
from typing import Any, ClassVar

try:
    from unicorn import (  # type: ignore[import-not-found]
        UC_ARCH_ARM,
        UC_HOOK_CODE,
        UC_HOOK_MEM_FETCH_INVALID,
        UC_HOOK_MEM_FETCH_PROT,
        UC_HOOK_MEM_FETCH_UNMAPPED,
        UC_HOOK_MEM_READ,
        UC_HOOK_MEM_READ_UNMAPPED,
        UC_HOOK_MEM_WRITE,
        UC_HOOK_MEM_WRITE_UNMAPPED,
        UC_MODE_LITTLE_ENDIAN,
        UC_MODE_THUMB,
        UC_QUERY_MODE,
        Uc,
    )
    from unicorn.arm_const import (  # type: ignore[import-not-found]
        UC_ARM_REG_LR,
        UC_ARM_REG_PC,
        UC_ARM_REG_R0,
        UC_ARM_REG_R1,
        UC_ARM_REG_R2,
        UC_ARM_REG_R3,
        UC_ARM_REG_R4,
        UC_ARM_REG_R5,
        UC_ARM_REG_R6,
        UC_ARM_REG_R7,
        UC_ARM_REG_R8,
        UC_ARM_REG_R9,
        UC_ARM_REG_R10,
        UC_ARM_REG_R11,
        UC_ARM_REG_R12,
        UC_ARM_REG_SP,
    )

    _UNICORN_ARM_REGS: list[int] = [
        UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
        UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
        UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
        UC_ARM_REG_R12,
    ]
    _UNICORN_AVAILABLE = True
except ImportError:
    _UNICORN_AVAILABLE = False

try:
    from capstone import (  # type: ignore[import-not-found]
        CS_ARCH_ARM,
        CS_MODE_LITTLE_ENDIAN,
        CS_MODE_THUMB,
        Cs,
    )

    _CAPSTONE_AVAILABLE = True
except ImportError:
    _CAPSTONE_AVAILABLE = False


class SamsungHDDEmulator:
    """Emulate the Samsung HM641JI 640 GB SATA HDD ARM firmware up to its main loop.

    Requires the ``unicorn`` and ``capstone`` packages.  Both are available as
    optional dependencies: ``pip install unicorn capstone``.

    The emulator performs hardware stubbing (pre-writing synthesised values to
    MMIO-mapped addresses) and applies a set of address-specific patches that
    unblock the firmware boot path without real hardware.

    Usage::

        emu = SamsungHDDEmulator()
        emu.load_firmware("rom.bin")
        emu.run()

    Sources:
      - egueler/HDD-Firmware-Emulation unicorn-gdb.py (clean-room reimplementation)
    """

    ROM_ADDRESS: int = 0xFFF00000
    STACK_ADDRESS: int = 0x80000000
    STACK_SIZE: int = 0x10000

    MEMORY_REGIONS: ClassVar[list[tuple[int, int]]] = [
        (0x1C000000, 0x1000000),
        (0x14000, 0x100000),
        (0x0, 0x14000),
        (0x4000000, 0x8000),
        (0x18000000, 0x1000000),
        (0xFFFE0000, 0x10000),
        (0x10000000, 0x1000000),
        (0x43080000, 0x1000000),
    ]

    HARDWARE_STUBS: ClassVar[dict[int, bytes]] = {
        0x1C00A000 + 0xA0: b"\x1E",
        0x1C00A000 + 0x62C: b"\xFF",
        0x7FFFFFB8: b"\x01\x00\x00\x00",
        0x4005B60: b"\x3A\x7C\x37\x54",
        0x1C004A0C: b"\x01\x00\x00\x00",
        0x4005B64: b"\x00\xF6\xEF\xFF",
        0x1C002E14: b"\xFF\xFF\xFF\xFF",
        0xFFFE005C: b"\x02\x40\x00\x00",
    }

    STATUS_INTERVAL_SECS: float = 3.0

    def __init__(self) -> None:
        if not _UNICORN_AVAILABLE:
            raise ImportError(
                "unicorn is required for SamsungHDDEmulator: pip install unicorn"
            )
        if not _CAPSTONE_AVAILABLE:
            raise ImportError(
                "capstone is required for SamsungHDDEmulator: pip install capstone"
            )
        self._mu: Any = None
        self._md: Any = None
        self._last_time: float = time.time()
        self._last_lr: int = 0
        self._src_addr: int = 0
        self._src_len: int = 0
        self._dst_addr: int = 0
        self._found_functions: list[tuple[int, int]] = []
        self._rom_size: int = 0
        self.verbose: bool = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_firmware(self, firmware_path: str) -> None:
        """Read firmware binary and map all memory regions.

        Must be called before :meth:`run`.
        """
        with open(firmware_path, "rb") as fh:
            content = fh.read()
        self._rom_size = len(content)

        self._md = Cs(CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN)
        self._md.detail = True

        self._mu = Uc(UC_ARCH_ARM, UC_MODE_LITTLE_ENDIAN)

        self._mu.mem_map(self.ROM_ADDRESS, len(content))
        self._mu.mem_map(self.STACK_ADDRESS - self.STACK_SIZE, self.STACK_SIZE)
        for base, size in self.MEMORY_REGIONS:
            self._mu.mem_map(base, size)

        for address, value in self.HARDWARE_STUBS.items():
            self._mu.mem_write(address, value)

        self._mu.mem_write(self.ROM_ADDRESS, content)
        self._mu.reg_write(UC_ARM_REG_SP, self.STACK_ADDRESS)

        self._mu.hook_add(UC_HOOK_MEM_READ, self._hook_read_memory)
        self._mu.hook_add(UC_HOOK_MEM_WRITE, self._hook_write_memory)
        self._mu.hook_add(
            UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED,
            self._hook_invalid_memory,
        )
        self._mu.hook_add(
            UC_HOOK_MEM_FETCH_UNMAPPED | UC_HOOK_MEM_FETCH_PROT | UC_HOOK_MEM_FETCH_INVALID,
            self._hook_invalid_fetch,
        )
        self._mu.hook_add(UC_HOOK_CODE, self._hook_code)

    def run(self, start_offset: int = 0x10) -> None:
        """Start emulation from ROM_ADDRESS + start_offset."""
        if self._mu is None:
            raise RuntimeError("Call load_firmware() before run()")
        self._mu.emu_start(self.ROM_ADDRESS + start_offset, 0xFFFFFFFF)
        print("Emulation done.")
        self.dump_found_functions()

    def dump_memory(self, output_dir: str = "dumps") -> None:
        """Write each mapped memory region to a separate .bin file."""
        if self._mu is None:
            return
        ts = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
        dest = os.path.join(output_dir, ts)
        os.makedirs(dest, exist_ok=True)
        for map_start, map_end, _perms in self._mu.mem_regions():
            path = os.path.join(dest, f"rom-{map_start:x}.bin")
            with open(path, "wb") as fh:
                fh.write(bytes(self._mu.mem_read(map_start, map_end - map_start)))

    def dump_found_functions(self) -> None:
        unique = list(set(self._found_functions))
        print([f"{addr:08x} (thumb={thumb})" for addr, thumb in unique])
        with open("foundFuncs.json", "w") as fh:
            json.dump(unique, fh)

    # ------------------------------------------------------------------
    # Hooks
    # ------------------------------------------------------------------

    def _hook_read_memory(
        self, mu: Any, access: int, address: int, size: int, value: int, user_data: Any
    ) -> bool:
        if self.verbose:
            actual = self._unpack_address(bytes(mu.mem_read(address, size)))
            print(
                f"hookReadMemory(-, {access:08x}, {address:08x}, {size:x}, {actual:x}, -)"
            )
        return True

    def _hook_write_memory(
        self, mu: Any, access: int, address: int, size: int, value: int, user_data: Any
    ) -> bool:
        if self.verbose:
            print(
                f"hookWriteMemory(-, {access:08x}, {address:08x}, {size:x}, {value:x}, -)"
            )
        return True

    def _hook_invalid_memory(
        self, mu: Any, access: int, address: int, size: int, value: int, user_data: Any
    ) -> bool:
        self.dump_memory()
        self.dump_found_functions()
        print(
            f"hookInvalidMemory(-, {access:08x}, {address:08x}, {size:x}, {value:x}, -)"
        )
        return True

    def _hook_invalid_fetch(
        self, mu: Any, access: int, address: int, size: int, value: int, user_data: Any
    ) -> bool:
        print(
            f"hookInvalidFetchMemory(-, {access:08x}, {address:08x}, {size:x}, {value:x}, -)"
        )
        return True

    def _hook_code(
        self, mu: Any, address: int, size: int, user_data: Any
    ) -> None:
        now = time.time()
        if now - self._last_time > self.STATUS_INTERVAL_SECS:
            self._last_time = now
            print(f"Status update, PC: {address:08x}")
            for i, reg_id in enumerate(_UNICORN_ARM_REGS):
                sys.stdout.write(f"R{i}: {mu.reg_read(reg_id):x}, ")
            sys.stdout.write(f"SP: {mu.reg_read(UC_ARM_REG_SP):x}\n")

        if self.verbose:
            disasm = self._disassemble(bytes(mu.mem_read(address, size)), address)
            print(f"{address:08x}: {disasm}")

        current_lr = mu.reg_read(UC_ARM_REG_LR)
        if current_lr != self._last_lr:
            is_thumb = int(mu.query(UC_QUERY_MODE) == UC_MODE_THUMB)
            fn_addr = address - self.ROM_ADDRESS if address > self.ROM_ADDRESS else address
            self._found_functions.append((fn_addr, is_thumb))
            self._last_lr = current_lr

        self._apply_patches(mu, address)

    def _apply_patches(self, mu: Any, address: int) -> None:
        rom = self.ROM_ADDRESS

        if address == rom + 0x194:
            print("loading unpack loader ERROR")
            mu.emu_stop()

        elif address == rom + 0x1A0:
            print("loading unpack loader successful")
            self._print_hex_dump(0x159F0, 0x100)

        elif address == rom + 0x1A4:
            mu.reg_write(UC_ARM_REG_PC, 0x159F0)

        elif address in (rom + 0x664, 0x10664):
            self._src_addr = mu.reg_read(UC_ARM_REG_R0)
            self._dst_addr = mu.reg_read(UC_ARM_REG_R1)
            self._src_len = mu.reg_read(UC_ARM_REG_R2)
            print(
                f"{address:08x} calling __copy("
                f"dst={self._dst_addr:x}, src={self._src_addr:x}, "
                f"len={self._src_len:x}, a4={mu.reg_read(UC_ARM_REG_R3):x})"
            )
            mu.reg_write(UC_ARM_REG_R3, 0x1)

        elif address in (rom + 0x704, 0x10704):
            print("__copy finished")
            self._print_hex_dump(self._dst_addr, self._src_len)

        elif address == 0x15C8C:
            print("chksum err")

        elif address == 0x15CBC:
            print("decomp err")

        elif address == 0x1068C:
            raw = (mu.reg_read(UC_ARM_REG_R1) - mu.reg_read(UC_ARM_REG_R2) - 1) & 0xFFFFFFFF
            value_bytes = raw.to_bytes(4, "little")
            mu.mem_write(0x1C00A204, value_bytes)

        elif address == 0xEDC6:
            mu.reg_write(UC_ARM_REG_R0, mu.reg_read(UC_ARM_REG_R4))

        elif address == 0x15D34:
            mu.mem_write(0xFFFE005C, b"\x01\x40\x00\x00")

        elif address == 0x15DDC:
            mu.mem_write(0xFFFE005C, b"\x02\x40\x00\x00")

        elif address == 0x73C0:
            mu.mem_write(0x400385C, b"\x02\x00\x00\x00")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _disassemble(self, code: bytes, addr: int = 0) -> str:
        if self._md is None:
            return ""
        is_thumb = bool(self._mu.query(UC_QUERY_MODE) & UC_MODE_THUMB)
        self._md.mode = CS_MODE_THUMB if is_thumb else CS_MODE_LITTLE_ENDIAN
        lines = [f"{ins.mnemonic} {ins.op_str}" for ins in self._md.disasm(code, addr)]
        return lines[0] if lines else ""

    def _print_hex_dump(self, start: int, length: int) -> None:
        if self._mu is None:
            return
        for i in range(length):
            if i % 16 == 0:
                sys.stdout.write(f"\n{start + i:08x}: ")
            byte = bytes(self._mu.mem_read(start + i, 1))[0]
            sys.stdout.write(f"{byte:02x} ")
        sys.stdout.write("\n")

    @staticmethod
    def _unpack_address(address: bytes, little_endian: bool = True) -> int:
        return int.from_bytes(address, "little" if little_endian else "big")
