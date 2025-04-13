import zigpy
import zigpy.device
from zigpy.zcl import foundation
import zigpy.types as t


class ManufacturerPayload:

    @classmethod
    def item_bits(cls, items: list) -> list[int]:
        all_bits = []
        for item in items:
            all_bits.append(item.get_bit())
        return all_bits

    @classmethod
    def item_signed(cls, items: list) -> list[bool]:
        all_signed = []
        for item in items:
            all_signed.append(item.get_signed())
        return all_signed


class TuyaMode(ManufacturerPayload):
    _mode: t.uint8_t = t.uint8_t(0)
    _byte_order: list[str] = ["little"]
    function = {0: "white",
                1: "color",
                2: "scene",
                3: "music"}

    @classmethod
    def byte_order(cls) -> list[str]:
        return cls._byte_order

    @classmethod
    def get_items(cls):
        return [cls._mode]


class ColorBrightness(ManufacturerPayload):
    _brightness: t.uint8_t = t.uint8_t(0x00)
    _byte_order: list[str] = ["little"]

    @classmethod
    def byte_order(cls) -> list[str]:
        return cls._byte_order

    @classmethod
    def get_items(cls):
        return [cls._brightness]


class GlobalData(ManufacturerPayload):
    _

class GradientSwitch(ManufacturerPayload):
    _vision: t.uint8_t = t.uint8_t(0x00)
    _open_time: t.uint24_t = t.uint24_t(0x0003e8)
    _close_time: t.uint24_t = t.uint24_t(0x0003e8)
    _byte_order: list[str] = ["little", "big", "big"]

    @classmethod
    def byte_order(cls) -> list[str]:
        return cls._byte_order

    @classmethod
    def get_items(cls):
        return [cls._vision, cls._open_time, cls._close_time]


class Disturb(ManufacturerPayload):
    _not_disturb: t.Bool = t.Bool(False)
    _byte_order: list[str] = ["little"]

    @classmethod
    def byte_order(cls) -> list[str]:
        return cls._byte_order

    @classmethod
    def get_items(cls):
        return [cls._not_disturb]


class CycleTimer(ManufacturerPayload):
    _vision: t.uint8_t = t.uint8_t(0x00)


class PowerMemory(ManufacturerPayload):
    pass


ATTR_CLASS_MAP = {
    0xF000: TuyaMode,
    0xF00B: CycleTimer,
    0xF00C: PowerMemory,
    0xF00D: Disturb,
    0xF00E: GradientSwitch
}

if __name__ == "__main__":
    types = TuyaMode
    print(types.byte_order())