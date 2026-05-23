"""WD IntelliPark idle3 timer control via Vendor Specific ATA Commands.

Reimplementation of idle3-tools (idle3ctl) by Christophe Bothamy, originally
published at https://sourceforge.net/p/idle3-tools/ under GPLv3.

The idle3 (IntelliPark) timer controls automatic head-parking on Western
Digital Green/Blue drives.  Aggressive default values (8 s) cause excessive
Load_Cycle_Count wear.  This module allows reading, setting, and disabling
the timer over a live ATA passthrough interface.

Sources:
  - idle3ctl.c v0.9.3 by Christophe Bothamy (idle3-tools, SourceForge)
  - ATA/ATAPI Command Set (ACS-3), T13 Project 2161-D
"""

from hdd_toolkit.ata.commands import ATADevice

ATA_OP_SMART = 0xB0
ATA_OP_VENDOR_SPECIFIC = 0x80

SMART_READ_LOG = 0xD5
SMART_WRITE_LOG = 0xD6

IDLE3_CYL_LO = 0x4F
IDLE3_CYL_HI = 0xC2

IDLE3_KEY_LOG = 0xBE
IDLE3_DATA_LOG = 0xBF

VSC_KEY_READ = 0x01
VSC_KEY_WRITE = 0x02

IDLE3_DISABLED = 0x00


def decode_timer_v100(raw: int) -> float:
    """Decode raw idle3 value using wdidle3 v1.00 scale (0.1 s per unit).

    Sources:
      - idle3ctl.c, action==2 branch
    """
    return raw / 10.0


def decode_timer_v103(raw: int) -> float:
    """Decode raw idle3 value using wdidle3 v1.03/v1.05 scale.

    Values 1-128 use 0.1 s per unit; values 129-255 use 30 s per unit
    relative to 128 (i.e. value - 128 * 30 s).

    Sources:
      - idle3ctl.c, action==3 branch
    """
    if raw < 129:
        return raw / 10.0
    return (raw - 128) * 30.0


class WDIdle3Client:
    """Control the Western Digital IntelliPark idle3 head-parking timer.

    Uses WD Vendor Specific ATA Commands (VSC) via SMART LOG to read and
    write the single-byte idle3 timer register stored at log page 0xBF.
    The caller is responsible for opening and closing the ATADevice.

    Sources:
      - idle3ctl.c v0.9.3 by Christophe Bothamy
      - forum.hddguru.com -- "WD IntelliPark / idle3 timer"
    """

    def __init__(self, device: ATADevice):
        self.dev = device

    def _passthrough_nodata(self, regs: dict) -> None:
        self.dev.passthrough(regs)

    def _passthrough_write(self, regs: dict, buf: bytes) -> None:
        self.dev.passthrough(regs, data_out=buf)

    def _passthrough_read(self, regs: dict) -> bytes:
        return self.dev.passthrough(regs, data_in_size=512)

    def vsc_enable(self) -> None:
        """Send the WD VSC enable sequence (ATA command 0x80, feat=0x45).

        Activates vendor-specific command mode on WD drives.  Must be called
        before any VSC key or timer operation.

        Sources:
          - idle3ctl.c VSC_enable()
        """
        regs = {
            "features": 0x45,
            "cyl_lo": 0x44,
            "cyl_hi": 0x57,
            "cmd": ATA_OP_VENDOR_SPECIFIC,
        }
        self._passthrough_nodata(regs)

    def vsc_disable(self) -> None:
        """Send the WD VSC disable sequence (ATA command 0x80, feat=0x44).

        Deactivates vendor-specific command mode.  Should be called after
        all VSC operations are complete.

        Sources:
          - idle3ctl.c VSC_disable()
        """
        regs = {
            "features": 0x44,
            "cyl_lo": 0x44,
            "cyl_hi": 0x57,
            "cmd": ATA_OP_VENDOR_SPECIFIC,
        }
        self._passthrough_nodata(regs)

    def _send_key(self, rw: int) -> None:
        """Send the VSC session key (SMART WRITE LOG 0xBE).

        Authenticates the forthcoming VSC read or write operation.  Must be
        called immediately before get_timer() or set_timer().

        Sources:
          - idle3ctl.c VSC_send_key()
        """
        regs = {
            "features": SMART_WRITE_LOG,
            "count": 1,
            "lba_lo": IDLE3_KEY_LOG,
            "cyl_lo": IDLE3_CYL_LO,
            "cyl_hi": IDLE3_CYL_HI,
            "cmd": ATA_OP_SMART,
        }
        buf = bytearray(512)
        buf[0] = 0x2A
        buf[2] = rw
        buf[4] = 0x02
        buf[6] = 0x0D
        buf[8] = 0x16
        buf[10] = 0x01
        self._passthrough_write(regs, bytes(buf))

    def send_read_key(self) -> None:
        """Send the VSC session key for a subsequent read operation."""
        self._send_key(VSC_KEY_READ)

    def send_write_key(self) -> None:
        """Send the VSC session key for a subsequent write operation."""
        self._send_key(VSC_KEY_WRITE)

    def get_timer(self) -> int:
        """Read the raw idle3 timer byte from SMART data log 0xBF.

        Returns the single raw byte value (0x00 = disabled, 1-255 active).
        Caller must call vsc_enable() and send_read_key() first.

        Sources:
          - idle3ctl.c VSC_get_timer()
        """
        regs = {
            "features": SMART_READ_LOG,
            "count": 1,
            "lba_lo": IDLE3_DATA_LOG,
            "cyl_lo": IDLE3_CYL_LO,
            "cyl_hi": IDLE3_CYL_HI,
            "cmd": ATA_OP_SMART,
        }
        buf = self._passthrough_read(regs)
        return buf[0]

    def set_timer(self, value: int) -> None:
        """Write the raw idle3 timer byte to SMART data log 0xBF.

        value=0 disables the timer.  Caller must call vsc_enable() and
        send_write_key() first.  A power cycle (not reboot) is required
        for the new setting to take effect.

        Sources:
          - idle3ctl.c VSC_set_timer()
        """
        regs = {
            "features": SMART_WRITE_LOG,
            "count": 1,
            "lba_lo": IDLE3_DATA_LOG,
            "cyl_lo": IDLE3_CYL_LO,
            "cyl_hi": IDLE3_CYL_HI,
            "cmd": ATA_OP_SMART,
        }
        buf = bytearray(512)
        buf[0] = value & 0xFF
        self._passthrough_write(regs, bytes(buf))

    def disable_timer(self) -> None:
        """Disable the idle3 timer by writing value 0x00.

        Equivalent to idle3ctl -d.  Requires vsc_enable() and
        send_write_key() to have been called first.
        """
        self.set_timer(IDLE3_DISABLED)

    def read_timer(self) -> int:
        """Enable VSC, send read key, read and return the raw timer byte.

        High-level convenience wrapper that performs the full sequence:
        vsc_enable -> send_read_key -> get_timer -> vsc_disable.
        """
        self.vsc_enable()
        self.send_read_key()
        value = self.get_timer()
        self.vsc_disable()
        return value

    def write_timer(self, value: int) -> None:
        """Enable VSC, send write key, write the given raw timer byte.

        High-level convenience wrapper that performs the full sequence:
        vsc_enable -> send_write_key -> set_timer -> vsc_disable.
        value=0 disables the timer.
        """
        self.vsc_enable()
        self.send_write_key()
        self.set_timer(value)
        self.vsc_disable()

    @staticmethod
    def is_wdc_drive(identify_data: bytes) -> bool:
        """Return True if the 512-byte IDENTIFY DEVICE data is from a WD drive.

        Checks that the model string (words 27-46) begins with the three
        characters "WDC".  In ATA IDENTIFY data, character strings are stored
        as 16-bit words with bytes swapped, so word 27 byte-pair order is
        [low=char2, high=char1].

        Sources:
          - idle3ctl.c check_WDC_drive()
          - ACS-3 Table 12 -- IDENTIFY DEVICE word 27
        """
        if len(identify_data) < 58:
            return False
        return (
            identify_data[27 * 2 + 1] == ord("W")
            and identify_data[27 * 2] == ord("D")
            and identify_data[28 * 2 + 1] == ord("C")
        )

    @staticmethod
    def decode_timer(raw: int, scale: str = "raw") -> str:
        """Return a human-readable string for a raw idle3 timer byte.

        scale options:
          "raw"   -- show raw hex/decimal value (idle3ctl -g)
          "v100"  -- wdidle3 v1.00 scale: 0.1 s per unit (idle3ctl -g100)
          "v103"  -- wdidle3 v1.03/v1.05 scale (idle3ctl -g103 / -g105)

        Sources:
          - idle3ctl.c main(), action 1/2/3 output branches
        """
        if raw == IDLE3_DISABLED:
            return "disabled"
        if scale == "v100":
            return f"{decode_timer_v100(raw):.1f}s (0x{raw:02X})"
        if scale == "v103":
            return f"{decode_timer_v103(raw):.1f}s (0x{raw:02X})"
        return f"{raw} (0x{raw:02X})"
