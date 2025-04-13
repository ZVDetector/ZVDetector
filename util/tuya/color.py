import zigpy
import zigpy.device
from zigpy.zcl import foundation
import zigpy.types as t
from typing import List


class ManufacturerPayload:

    @classmethod
    def item_bits(cls, items: List) -> List[int]:
        all_bits = []
        for item in items:
            all_bits.append(item.get_bit())
        return all_bits

    @classmethod
    def item_signed(cls, items: List) -> List[bool]:
        all_signed = []
        for item in items:
            all_signed.append(item.get_signed())
        return all_signed


class WhiteColorTemp(ManufacturerPayload):
    _temp: t.uint16_t = t.uint16_t(100)
    _byte_order: List[str] = ["little"]

    @classmethod
    def byte_order(cls) -> List[str]:
        return cls._byte_order

    @classmethod
    def get_items(cls):
        return [cls._temp]


class ColorTemp(ManufacturerPayload):
    _tempH: t.uint16_t = t.uint16_t(100)
    _tempS: t.uint16_t = t.uint16_t(100)
    _tempV: t.uint16_t = t.uint16_t(100)

    _byte_order: List[str] = ["little", "little", "little"]

    @classmethod
    def byte_order(cls) -> List[str]:
        return cls._byte_order

    @classmethod
    def get_items(cls):
        return [cls._tempH, cls._tempS, cls._tempV]


class TuyaMode(ManufacturerPayload):
    _mode: t.uint8_t = t.uint8_t(0)
    _byte_order: List[str] = ["little"]
    function = {0: "white",
                1: "color",
                2: "scene",
                3: "music"}

    @classmethod
    def byte_order(cls) -> List[str]:
        return cls._byte_order

    @classmethod
    def get_items(cls):
        return [cls._mode]


class ColorBrightness(ManufacturerPayload):
    _tempB: t.uint8_t = t.uint8_t(0x00)
    _byte_order: List[str] = ["little"]

    @classmethod
    def byte_order(cls) -> List[str]:
        return cls._byte_order

    @classmethod
    def get_items(cls):
        return [cls._tempB]


class GlobalData(ManufacturerPayload):
    _switch: t.uint8_t = t.uint8_t(0x00)
    _mode: t.uint8_t = t.uint8_t(0x00)
    _tempH: t.uint16_t = t.uint16_t(0x0000)
    _tempS: t.uint16_t = t.uint16_t(0x0000)
    _tempV: t.uint16_t = t.uint16_t(0x0000)
    _tempB: t.uint16_t = t.uint16_t(0x0000)
    _tempT: t.uint16_t = t.uint16_t(0x0000)
    _byte_order: List[str] = ["little", "little", "big", "big", "big", "big", "big"]

    @classmethod
    def byte_order(cls) -> List[str]:
        return cls._byte_order

    @classmethod
    def get_items(cls):
        return [cls._switch, cls._mode, cls._tempH, cls._tempS, cls._tempV, cls._tempB, cls._tempT]


class GradientSwitch(ManufacturerPayload):
    _vision: t.uint8_t = t.uint8_t(0x00)
    _open_time: t.uint24_t = t.uint24_t(0x0003e8)
    _close_time: t.uint24_t = t.uint24_t(0x0003e8)
    _byte_order: List[str] = ["little", "big", "big"]

    @classmethod
    def byte_order(cls) -> List[str]:
        return cls._byte_order

    @classmethod
    def get_items(cls):
        return [cls._vision, cls._open_time, cls._close_time]


class Disturb(ManufacturerPayload):
    _not_disturb: t.Bool = t.Bool(False)
    _byte_order: List[str] = ["little"]

    @classmethod
    def byte_order(cls) -> List[str]:
        return cls._byte_order

    @classmethod
    def get_items(cls):
        return [cls._not_disturb]


class Timer(ManufacturerPayload):
    _vision: t.uint8_t = t.uint8_t(0x00)
    _node_length: t.uint8_t = t.uint8_t(0x00)
    _switch: t.uint8_t = t.uint8_t(0x00)
    _date: t.uint8_t = t.uint8_t(0x00)  # hex(int('0x01000000', 2)) 表示设置周六
    _start_time: t.uint16_t = t.uint16_t(0x0000)
    _end_time: t.uint16_t = t.uint16_t(0x0000)
    _open_time: t.uint16_t = t.uint16_t(0x0000)
    _close_time: t.uint16_t = t.uint16_t(0x0000)
    _tempH: t.uint16_t = t.uint16_t(0x0000)
    _tempS: t.uint8_t = t.uint8_t(0x00)
    _tempV: t.uint8_t = t.uint8_t(0x00)
    _tempB: t.uint8_t = t.uint8_t(0x00)
    _tempT: t.uint8_t = t.uint8_t(0x00)
    _byte_order: List[str] = ["little"]

    @classmethod
    def byte_order(cls) -> List[str]:
        return cls._byte_order

    @classmethod
    def get_fixed_items(cls):
        return [cls._vision, cls._node_length]

    @classmethod
    def get_varied_items(cls):
        return [cls._switch, cls._date, cls._start_time, cls._end_time, cls._open_time, cls._close_time, cls._tempH,
                cls._tempS, cls._tempV, cls._tempB, cls._tempT]


class LightGradient(ManufacturerPayload):
    _vision: t.uint8_t = t.uint8_t(0x00)
    _gradient_time: t.uint16_t = t.uint16_t(0x0000)
    _byte_order: List[str] = ["little", "big"]

    @classmethod
    def byte_order(cls) -> List[str]:
        return cls._byte_order

    @classmethod
    def get_items(cls):
        return [cls._vision, cls._gradient_time]


class PowerMemory(ManufacturerPayload):
    _vision: t.uint8_t = t.uint8_t(0x00)
    _mode: t.uint8_t = t.uint8_t(0x01)  # 0x00: Default Color  0x01: Recovery Memory  0x02: Customized Color
    _tempH: t.uint16_t = t.uint16_t(100)
    _tempS: t.uint16_t = t.uint16_t(100)
    _tempV: t.uint16_t = t.uint16_t(100)
    _tempB: t.uint16_t = t.uint16_t(100)
    _tempT: t.uint16_t = t.uint16_t(100)
    _byte_order: List[str] = ["little", "little", "big", "big", "big", "big", "big"]

    @classmethod
    def byte_order(cls) -> List[str]:
        return cls._byte_order

    @classmethod
    def get_items(cls):
        return [cls._vision, cls._mode, cls._tempH, cls._tempS, cls._tempV, cls._tempB, cls._tempT]


class ClusterRevision(ManufacturerPayload):
    _revision: t.uint16_t = t.uint16_t(0x0000)
    _byte_order: List[str] = ["little"]

    @classmethod
    def byte_order(cls) -> List[str]:
        return cls._byte_order

    @classmethod
    def get_items(cls):
        return [cls._revision]


class Scene(ManufacturerPayload):
    _scene_number: t.uint8_t = t.uint8_t(0x00)
    _mode: t.uint8_t = t.uint8_t(0x00)
    _switch_time: t.uint8_t = t.uint8_t(0x00)
    _change_time: t.uint8_t = t.uint8_t(0x00)
    _tempH_percent: t.uint8_t = t.uint8_t(0x00)
    _tempS_percent: t.uint8_t = t.uint8_t(0x00)
    _tempV_percent: t.uint8_t = t.uint8_t(0x00)
    _tempB_percent: t.uint8_t = t.uint8_t(0x00)
    _tempT_percent: t.uint8_t = t.uint8_t(0x00)
    _byte_order: List[str] = ["little", "little", "little", "little",
                              "little", "little", "little", "little", "little"]

    @classmethod
    def byte_order(cls) -> List[str]:
        return cls._byte_order

    @classmethod
    def get_fixed_items(cls):
        return [cls._scene_number, cls._mode]

    @classmethod
    def get_varied_items(cls):
        return [cls._switch_time, cls._change_time, cls._tempH_percent, cls._tempS_percent, cls._tempV_percent,
                cls._tempB_percent, cls._tempT_percent]


class Awake(ManufacturerPayload):
    _vision: t.uint8_t = t.uint8_t(0x00)
    _node_number: t.uint8_t = t.uint8_t(0x00)  # Max 4 nodes
    _node_switch: t.uint8_t = t.uint8_t(0x00)  # 0x00: off  0x01: open
    _date: t.uint8_t = t.uint8_t(0x00)  # hex(int('0x01000000', 2)) 表示设置周六
    _step: t.uint8_t = t.uint8_t(0x01)  # 1-72
    _start_hour: t.uint8_t = t.uint8_t(0x00)  # 0x10: 16点
    _start_min: t.uint8_t = t.uint8_t(0x00)  # 0X10: 16分
    _tempH: t.uint16_t = t.uint16_t(0x0000)  # 0x0310: 0x03(百位) + 0x10(十位和个位) 316
    _tempS_percent: t.uint8_t = t.uint8_t(0x00)
    _tempV_percent: t.uint8_t = t.uint8_t(0x00)
    _tempB_percent: t.uint8_t = t.uint8_t(0x00)
    _tempT_percent: t.uint8_t = t.uint8_t(0x00)
    _duration: t.uint8_t = t.uint8_t(0x00)  # 0: No Light Off 24: Off Light After 120min
    _byte_order: List[str] = ["little", "little", "little", "little", "little", "little", "little",
                              "big", "little", "little", "little", "little", "little"]

    @classmethod
    def byte_order(cls) -> List[str]:
        return cls._byte_order

    @classmethod
    def get_fixed_items(cls):
        return [cls._vision, cls._node_number]

    @classmethod
    def get_varied_items(cls):
        return [cls._node_switch, cls._date, cls._step, cls._start_hour, cls._start_min, cls._tempH,
                cls._tempS_percent, cls._tempV_percent, cls._tempB_percent, cls._tempT_percent, cls._duration]


class Sleep(ManufacturerPayload):
    _vision: t.uint8_t = t.uint8_t(0x00)
    _node_number: t.uint8_t = t.uint8_t(0x00)  # Max 4 nodes
    _node_switch: t.uint8_t = t.uint8_t(0x00)  # 0x00: off  0x01: open
    _date: t.uint8_t = t.uint8_t(0x00)  # hex(int('01000000', 2)) 表示设置周六
    _step: t.uint8_t = t.uint8_t(0x01)  # 1-72
    _start_hour: t.uint8_t = t.uint8_t(0x00)  # 0x10: 16点
    _start_min: t.uint8_t = t.uint8_t(0x00)  # 0X10: 16分
    _tempH: t.uint16_t = t.uint16_t(0x0000)  # 0x0310: 0x03(百位) + 0x10(十位和个位) 316
    _tempS_percent: t.uint8_t = t.uint8_t(0x00)
    _tempV_percent: t.uint8_t = t.uint8_t(0x00)
    _tempB_percent: t.uint8_t = t.uint8_t(0x00)
    _tempT_percent: t.uint8_t = t.uint8_t(0x00)
    _byte_order: List[str] = ["little", "little", "little", "little", "little", "little", "little",
                              "big", "little", "little", "little", "little"]

    @classmethod
    def byte_order(cls) -> List[str]:
        return cls._byte_order

    @classmethod
    def get_fixed_items(cls):
        return [cls._vision, cls._node_number]

    @classmethod
    def get_varied_items(cls):
        return [cls._node_switch, cls._date, cls._step, cls._start_hour, cls._start_min, cls._tempH,
                cls._tempS_percent, cls._tempV_percent, cls._tempB_percent, cls._tempT_percent]


class Biorhythm(ManufacturerPayload):
    _vision: t.uint8_t = t.uint8_t(0x00)
    _task_switch: t.uint8_t = t.uint8_t(0x00)  # 0x00: Task Close  0x01: Task Open
    _mode: t.uint8_t = t.uint8_t(0x00)  # 0x00: Full Gradient
    _date: t.uint8_t = t.uint8_t(0x00)  # hex(int('0x01000000', 2)) 表示设置周六
    _node_number: t.uint8_t = t.uint8_t(0x00)  # Max: 6 nodes
    _node_switch: t.uint8_t = t.uint8_t(0x01)  # 0x00: 节点不生效  0x01: 节点生效
    _start_hour: t.uint8_t = t.uint8_t(0x00)
    _start_min: t.uint8_t = t.uint8_t(0x00)
    _tempH: t.uint16_t = t.uint16_t(0x0310)
    _tempS_percent: t.uint8_t = t.uint8_t(0x00)
    _tempV_percent: t.uint8_t = t.uint8_t(0x00)
    _tempB_percent: t.uint8_t = t.uint8_t(0x00)
    _tempT_percent: t.uint8_t = t.uint8_t(0x00)

    _byte_order: List[str] = ["little", "little", "little", "little", "little", "little",
                              "little", "little", "big", "little", "little", "little", "little"]

    @classmethod
    def byte_order(cls) -> List[str]:
        return cls._byte_order

    @classmethod
    def get_fixed_items(cls):
        return [cls._vision, cls._task_switch, cls._mode, cls._date, cls._node_number]

    @classmethod
    def get_varied_items(cls):
        return [cls._node_switch, cls._start_hour, cls._start_min, cls._tempH,
                cls._tempS_percent, cls._tempV_percent, cls._tempB_percent, cls._tempT_percent]


class Music(ManufacturerPayload):
    _mode: t.uint8_t = t.uint8_t(0x00)  # 0:direct  1:gradient
    _tempH: t.uint16_t = t.uint16_t(0x0000)
    _tempS: t.uint16_t = t.uint16_t(0x0000)
    _tempV: t.uint16_t = t.uint16_t(0x0000)
    _tempB: t.uint16_t = t.uint16_t(0x0000)
    _tempT: t.uint16_t = t.uint16_t(0x0000)

    _byte_order: List[str] = ["little", "big", "big", "big", "big", "big"]

    @classmethod
    def byte_order(cls) -> List[str]:
        return cls._byte_order

    @classmethod
    def get_items(cls):
        return [cls._mode, cls._tempH, cls._tempS, cls._tempV, cls._tempB, cls._tempT]


ATTR_CLASS_MAP = {
    0xE000: WhiteColorTemp,
    0xE100: ColorTemp,
    0xF000: TuyaMode,  # 模式
    0xF001: ColorBrightness,  # 彩光亮度
    0xF002: GlobalData,  # 全量数据
    0xF003: Scene,  # 场景数据
    0xF007: Sleep,  # 入睡
    0xF008: Awake,  # 唤醒
    0xF009: Biorhythm,  # 生物节律
    0xF00A: Timer,  # DP210随机定时
    0xF00B: Timer,  # DP209循环定时
    0xF00C: PowerMemory,  # 断电记忆
    0xF00D: Disturb,  # 勿扰模式
    0xF00E: GradientSwitch,  # 开关渐变
    0xF013: LightGradient,  # 白光渐变
    0xF014: LightGradient,  # 彩光渐变
    0xFFFD: ClusterRevision  # 保留位
}


COMMAND_CLASS_MAP = {
    0xE0: WhiteColorTemp,
    0xE1: ColorTemp,
    0xF0: TuyaMode,
    0xF1: Scene,
    0xF2: Music,
    0xF4: Sleep,
    0xF5: Awake,
    0xF6: Biorhythm,
    0xF7: Timer,
    0xF8: Timer,
    0xF9: PowerMemory,
    0xFA: Disturb,
    0xFB: GradientSwitch,
    0xFD: LightGradient,
    0xFE: LightGradient
}

if __name__ == "__main__":
    for value in ATTR_CLASS_MAP.values():
        print("————————{}——————————".format(value))
        try:
            items = value.get_items()
            for item in items:
                print(type(item))
        except AttributeError:
            fixed_items = value.get_fixed_items()
            varied_items = value.get_varied_items()
            for item in fixed_items:
                print(type(item))
            for item in varied_items:
                print(type(item))