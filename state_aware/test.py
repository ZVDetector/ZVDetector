import inspect
import importlib.util
import re
import os
import json
import zigpy.types as t
from const import *

def get_all_classes_in_file(file_path):
    # 从文件路径导入模块
    module_name = file_path.split('/')[-1].replace('.py', '')
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    # 获取模块中定义的所有类
    classes = [obj for name, obj in inspect.getmembers(module, inspect.isclass) if obj.__module__ == module_name]

    # 获取类名并添加到模块的 __all__
    class_names = [cls.__name__ for cls in classes]
    module.__all__ = class_names

    return module, class_names


def dynamic_import_class(module_name, class_name):
    try:
        # 动态导入模块
        module = importlib.import_module(module_name)
        # 从模块中获取类
        cls = getattr(module, class_name)
        return cls
    except (ModuleNotFoundError, AttributeError) as e:
        # print(f"无法导入 {class_name} 从 {module_name}: {e}")
        return None


# file_path = "/Users/linhai/opt/anaconda3/envs/fuzzing/lib/python3.9/site-packages/zigpy/zcl/clusters/general.py"
# module, class_names = get_all_classes_in_file(file_path)
# print(class_names)

# cls = dynamic_import_class("zigpy.zcl.clusters.hvac", "SeqDayOfWeek")
#
# if cls is None:
#     print("yes")
# else:
#     print(cls.__bases__)

zcl_command_pattern = r'(.*?): Final = ZCLCommandDef\(.*?id=(.*?),.*?schema={(.*?)},.*?direction=(.*?)\)'
command_content = """class NeighborInfo(t.Struct):
    neighbor: t.EUI64
    x: t.int16s
    y: t.int16s
    z: t.int16s
    rssi: t.int8s
    num_measurements: t.uint8_t
        """

# cls = dynamic_import_class("zigpy.zcl.clusters.general", "")

# print(message_content.split("\n")[1].replace(" ", ""))

from zigpy.zcl.clusters.general import ImageNotifyCommand, QueryNextImageCommand, ImageBlockCommand, ImagePageCommand, ImageBlockResponseCommand

# print(ImageNotifyCommand.__dict__['__annotations__'])
# print(QueryNextImageCommand.__dict__['__annotations__'])
# print(ImageBlockCommand.__dict__['__annotations__'])
# print(ImagePageCommand.__dict__['__annotations__'])
# print(ImageBlockCommand.FieldControl.__dict__.items())
cls = dynamic_import_class("zigpy.zcl.clusters.general", "ImageBlockCommand")
cls2 = dynamic_import_class("zigpy.zcl.clusters.general", "TimeStatus")
cls3 = dynamic_import_class("zigpy.zcl.clusters.general", "NeighborInfo")
# print(getattr(cls, "FieldControl").__dict__['_member_names_'])
# print(getattr(getattr(cls, "FieldControl"), "MinimumBlockPeriod").value)
# print(cls2.__dict__['_member_names_'])
# print(getattr(cls2, "Master").value)
fields = cls.__dict__['__annotations__']
# for fieldname in fields:
#     print(fields[fieldname])

# cls4 = dynamic_import_class("zigpy.zcl.clusters.general", "FieldControl")
# print(getattr(cls.__dict__['field_control'], "type"))
# print(cls.__dict__['__annotations__'])
field_type_text = str(getattr(cls.__dict__['field_control'], "type"))
field_type = re.match(r".*?'(.*)'", field_type_text)
field_type = field_type.group(1)
# cls4 = getattr(cls, field_type)
# print(cls4.__dict__['_member_names_'])
# cl5 = getattr(cls.__dict__['field_control'], "type")
# print(field_type_text)


# print(getattr(cls, "FieldControl"))

cls0 = dynamic_import_class("zigpy.zcl.clusters.hvac", "SetpointMode")
# print(cls0)

# pattern = r'(?:async\s+)?def'
# print(re.match(pattern, "def _handle_query_next_image(self, hdr, cmd):"))

cls_warn = dynamic_import_class("zigpy.zcl.clusters.security", "Squawk")
# print(cls_warn.__dict__)

found_pattern = r'foundation\.(.*)'

found_str = 'foundation.ZCL_CLUSTER_REVISION_ATTR'

if __name__ == "__main__":

    with open(os.path.join(os.getcwd(), "result/format/all_formats(Zigbee).json"), "r") as f:
        results = json.load(f)

    total_count = []
    for layer, msgs in results.items():
        total_count.append(len(msgs))
    print(total_count)

    rounds = 11 * 5 + 13 * 4 + 12 * 3 + 85 * 2 + 299*1
    print(rounds)
