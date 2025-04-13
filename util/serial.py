import os
import sys

sys.path.append(os.path.dirname(__file__))

import zigpy.types as t
from tuya import color

MANUFACTURER_PRIVATE_TYPE = []

MANUFACTURER_PRIVATE_TYPE.extend(color.ATTR_CLASS_MAP.values())

ZIGBEE_STR_TYPE = [t.LVBytes, t.CharacterString, t.LongCharacterString, t.LongOctetString]

ZIGBEE_SIGNED_INT_TYPE = [t.int8s, t.int16s, t.int16s_be, t.int24s, t.int24s_be, t.int32s, t.int32s_be,
                          t.int40s, t.int40s_be, t.int48s, t.int48s_be, t.int56s, t.int56s_be, t.int64s, t.int64s_be]

ZIGBEE_UNSIGNED_INT_TYPE = [t.uint1_t, t.uint2_t, t.uint3_t, t.uint4_t, t.uint5_t, t.uint6_t, t.uint7_t,
                            t.uint8_t, t.uint16_t, t.uint16_t_be, t.uint24_t, t.uint24_t_be,
                            t.uint32_t, t.uint32_t_be, t.uint40_t, t.uint40_t_be, t.uint48_t, t.uint48_t_be,
                            t.uint56_t, t.uint56_t_be, t.uint64_t, t.uint64_t_be, t.Bool]

ZIGBEE_ENUM_TYPE = [t.enum1, t.enum2, t.enum3, t.enum4, t.enum5, t.enum6, t.enum7, t.enum8,
                    t.enum16, t.enum16_be, t.enum32, t.enum32_be]

ZIGBEE_BITMAP_TYPE = [t.bitmap2, t.bitmap3, t.bitmap3, t.bitmap4, t.bitmap5, t.bitmap6, t.bitmap7, t.bitmap8,
                      t.bitmap16, t.bitmap16_be, t.bitmap32, t.bitmap32_be, t.bitmap56, t.bitmap56_be,
                      t.bitmap64, t.bitmap64_be]

ZIGBEE_INTEGER_TYPE = []

ZIGBEE_INTEGER_TYPE.extend(ZIGBEE_SIGNED_INT_TYPE)
ZIGBEE_INTEGER_TYPE.extend(ZIGBEE_UNSIGNED_INT_TYPE)
ZIGBEE_INTEGER_TYPE.extend(ZIGBEE_BITMAP_TYPE)
ZIGBEE_INTEGER_TYPE.extend(ZIGBEE_ENUM_TYPE)

ZIGBEE_DATA_TYPE = [t.data8, t.data16, t.data24, t.data32, t.data40, t.data48, t.data56, t.data64]


def father_class(specific_type, type_list):
    for type_father in type_list:
        if issubclass(specific_type, type_father):
            return True
    return False


def serialize(value, types):
    if types in ZIGBEE_STR_TYPE or father_class(types, ZIGBEE_STR_TYPE):
        try:
            string_bytes = len(value).to_bytes(types.prefix(), "little", signed=False) + value.encode("utf-8")
        except OverflowError:
            string_bytes = len(value).to_bytes(types.prefix() * 2, "little", signed=False) + value.encode("utf-8")
        return string_bytes

    elif types in ZIGBEE_SIGNED_INT_TYPE or types in ZIGBEE_UNSIGNED_INT_TYPE or types in ZIGBEE_ENUM_TYPE \
            or types in ZIGBEE_BITMAP_TYPE:
        try:
            if value < 0:
                integer_bytes = value.to_bytes(types.get_bit() // 8, "little", signed=True)
            else:
                integer_bytes = value.to_bytes(types.get_bit() // 8, "little", signed=types.get_signed())
        except OverflowError:
            bits = types.get_bit()
            while True:
                bits = bits * 2
                integer_bytes = b''
                try:
                    if value < 0:
                        integer_bytes = value.to_bytes(bits // 8, "little", signed=True)
                    else:
                        integer_bytes = value.to_bytes(bits // 8, "little", signed=types.get_signed())
                except OverflowError:
                    continue
                return integer_bytes
        return integer_bytes

    elif types in ZIGBEE_DATA_TYPE:
        item_types = types.get_item()
        data_bytes = b""
        for item_value in value:
            item_bytes = b""
            try:
                item_bytes = item_value.to_bytes(item_types.get_bit() // 8, 'little', signed=item_types.get_signed())
            except OverflowError:
                item_bytes = item_value.to_bytes(item_types.get_bit() * 2 // 8, 'little',
                                                 signed=item_types.get_signed())
            finally:
                data_bytes += item_bytes

    elif types in MANUFACTURER_PRIVATE_TYPE:
        item_orders = types.byte_order()

        # 如果是固定类型，则认为后续array队列是固定长度的，此时value = [element1, element2, ..., element n]
        try:
            all_items = types.get_items()
            bits_list = types.item_bits(all_items)
            signed_list = types.item_signed(all_items)

            data_bytes = b""
            for index in range(len(value)):
                item_bytes = b""
                try:
                    item_bytes = value[index].to_bytes(bits_list[index] // 8, item_orders[index],
                                                       signed=signed_list[index])
                except OverflowError:
                    item_bytes = value[index].to_bytes(bits_list[index] * 2 // 8, item_orders[index],
                                                       signed=signed_list[index])
                finally:
                    data_bytes += item_bytes

            return data_bytes

        # 如果是变化长度的，则认为后续array队列是变化长度的，此时value = [element1, element2, [], []...)
        except AttributeError:
            fixed_items = types.get_fixed_items()
            varied_items = types.get_varied_items()

            bits_fixed_list = types.item_bits(fixed_items)
            signed_fixed_list = types.item_signed(fixed_items)

            bits_varied_list = types.item_bits(varied_items)
            signed_varied_list = types.item_signed(varied_items)

            data_bytes = b""

            fixed_length = len(fixed_items)

            for index in range(fixed_length):
                item_bytes = b""
                try:
                    item_bytes = value[index].to_bytes(bits_fixed_list[index] // 8, item_orders[index],
                                                       signed=signed_fixed_list[index])
                except OverflowError:
                    item_bytes = value[index].to_bytes(bits_fixed_list[index] * 2 // 8, item_orders[index],
                                                       signed=signed_fixed_list[index])
                finally:
                    data_bytes += item_bytes

            print(data_bytes)

            for index in range(fixed_length, len(value)):
                for i in range(len(value[index])):
                    item_bytes = b""
                    print(value[index][i])
                    try:
                        item_bytes = value[index][i].to_bytes(bits_varied_list[i] // 8, item_orders[index],
                                                              signed=signed_varied_list[i])
                    except OverflowError:
                        item_bytes = value[index][i].to_bytes(bits_varied_list[i] * 2 // 8, item_orders[index],
                                                              signed=signed_varied_list[i])
                    finally:
                        data_bytes += item_bytes

            return data_bytes


if __name__ == "__main__":
    values = [0x00, 0x01, [0x01, int('01000000', 2), 0x01, 0x10, 0x10, 0x0310, 0x64, 0x64, 0x64, 0x64]]
    types = color.Sleep
    data_bytes= serialize(values, types)
    print(type(data_bytes) == bytes)