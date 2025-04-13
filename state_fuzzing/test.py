import dataclasses
import typing
import json
import binascii
import zigpy.types as t
from zigpy.zcl import foundation
from zigpy.zcl.foundation import GENERAL_COMMANDS, ZCLCommandDef, Direction, GeneralCommand

a = range(t.uint16_t.min_value, t.uint16_t.max_value)
print(t.bitmap64.max_value)

b = t.uint16_t(65535)
type_id = foundation.DATA_TYPES.pytype_to_datatype_id(type(b))
types = foundation.DATA_TYPES[66][2]

if types == foundation.Discrete:
    print(True)

print(t.Single)
print(t.enum8.max_value)
print(t.bitmap64.max_value)
print(t.Bool.min_value)
print(t.data8([1]).serialize())

print("————————STRING————————")
# print(t.LVBytes("f"*256, encoding="utf-8"))
# print(t.CharacterString("f"*254))
# print(t.CharacterString("f"*254).serialize())

string = "f"*254
types = t.CharacterString
try:
    string_hex = len(string).to_bytes(types.prefix(), "little", signed=False) + string.encode("utf-8")
except OverflowError:
    print("overflow")
    string_hex = len(string).to_bytes(types.prefix()*2, "little", signed=False) + string.encode("utf-8")
print(string_hex)


print("————————INT————————")
# integer = -257
types = t.int64s
integer = types.max_value + 2
print(integer)
try:
    integer_bytes = integer.to_bytes(types.get_bit() // 8, "little", signed=types.get_signed())
except OverflowError:
    print("overflow")
    integer_bytes = integer.to_bytes(types.get_bit()*2 // 8, "little", signed=types.get_signed())

print(integer_bytes)


print("————————ENUM————————")

value = t.enum16.max_value
types = t.enum8
try:
    integer_bytes = value.to_bytes(types.get_bit() // 8, "little", signed=types.get_signed())
except OverflowError:
    print("overflow")
    integer_bytes = value.to_bytes(types.get_bit()*2 // 8, "little", signed=types.get_signed())

print(integer_bytes)

print("————————BOOL————————")
value = t.Bool.max_value
types = t.Bool
print(t.Bool(True).serialize())
try:
    integer_bytes = value.to_bytes(types.get_bit() // 8, "little", signed=types.get_signed())
except OverflowError:
    print("overflow")
    integer_bytes = value.to_bytes(types.get_bit()*2 // 8, "little", signed=types.get_signed())
print(integer_bytes)
print(types.get_signed())

print("————————BITMAP————————")
value = 256
types = t.bitmap8
try:
    integer_bytes = value.to_bytes(types.get_bit() // 8, "little", signed=types.get_signed())
except OverflowError:
    print("overflow")
    integer_bytes = value.to_bytes(types.get_bit()*2 // 8, "little", signed=types.get_signed())

print(integer_bytes)

print("————————DATA————————")
value = [1, 2]
types = t.data8
item_types = types.get_item()

data_bytes = b""
for item_value in value:
    item_bytes = b""
    try:
        item_bytes = item_value.to_bytes(item_types.get_bit() // 8, 'little', signed=item_types.get_signed())
    except OverflowError:
        item_bytes = item_value.to_bytes(item_types.get_bit() * 2 // 8, 'little', signed=item_types.get_signed())
    finally:
        data_bytes += item_bytes

# data_bytes = data_bytes.join(all_item_bytes)
print(data_bytes)

print("————————Array————————")

ins = 1000
# attribute: 0xf00e
time_open = ins.to_bytes(3, "big", signed=False)
print(time_open)

bit_stream = '01000000'

# 将比特流转换为十六进制数
decimal_value = int(bit_stream, 2)
hex_value = hex(decimal_value)
print(hex_value)

# 整数 cluster id转换成 t.ClusterID
# print(t.ClusterId(cluster_id))


a = int('01000000', 2)
print(a)

cluster_id = 0x0300
print(t.ClusterId(cluster_id))

cluster_id = [0, 1, 6]
print(0x0006 in cluster_id)

bytes_string = "\x00\x00\xff\xff"
bytes_stream = b'\x00\x00\xff\xff'
payload2 = bytes(bytes_string, "latin1")
print(payload2)
print(''.join(f'\\x{byte:02x}' for byte in bytes_stream))

status_dict = {status.value: status.name for status in foundation.Status}
print(status_dict)

print(list())
if not list():
    print(False)

sup = {}
print(sup.keys())

name = "Manufacturer-Specific-Cluster_57344"
ints = 1794
print(''.join(f'\\x{ints:02x}'))
