# from util.serial import serialize, ZIGBEE_STR_TYPE
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import re
import json
import inspect
import importlib.util
import logging
import copy

from state_aware.type import *
import zhaquirks.thirdreality.switch
import zhaquirks.thirdreality.night_light
import zhaquirks.sengled.e1e_g7f
import zhaquirks.thirdreality.switch

from util.utils import list_files_in_folder, is_prefix
from zhaquirks.tuya import TuyaZBE000Cluster, TuyaZB1888Cluster, TuyaZBElectricalMeasurement, \
    TuyaZBMeteringClusterWithUnit, TuyaZBOnOffAttributeCluster

# 2. 导入所有schema类
from zigpy.zcl.clusters.general import PowerSource, PhysicalEnvironment, AlarmMask, ImageBlockCommand

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

ZHA_FILE_ORIGIN_PATH = os.path.join(os.path.dirname(__file__), "zha_zcl_library", "origin")
ZHA_FILE_PATH = os.path.join(os.path.dirname(__file__), "zha_zcl_library", "process")
FORMAT_SAVE_DIR = os.path.join(os.path.dirname(__file__), "result/format/ZCL")
ATTR_SAVE_DIR = os.path.join(os.path.dirname(__file__), "result/attribute")
BASE_MODULE = "zigpy.zcl.clusters"
ATTR_CLASS = ('AttributeDefs', 'BaseAttributeDefs')
COMMAND_CLASS = [('ServerCommandDefs', 'BaseCommandDefs'), ('ClientCommandDefs', 'BaseCommandDefs')]
STRUCT_BASE_CLASS = ["t.Struct", "foundation.CommandSchema"]
LIST_TYPE = ["t.List", "t.LVList"]
COMPLEX_TYPE = ["t.List", "t.LVList", "t.FixedList", "t.LVBytes", "t.data8", "t.data16", "t.data24", "t.data32",
                "t.data48", "t.data56", "t.data64"]

COMPLEX_TIME_TYPE = ["t.LocalTime", "t.UTCTime", "t.TimeOfDay", "t.Date"]
ATTRIBUTE_MAP = {}
COMMAND_MAP = {}
FILENAME_MAP = {}
CLASSNAME_MAP = {}


def clear_comment(file_path: str):
    """
    对文件进行预处理，清除注释和comment
    :param file_path: 文件路径(绝对路径)
    :return:
    """
    filename = re.match(r'.*/(.*)', file_path).group(1)
    content = ""
    with open(file_path, 'r', encoding='utf-8') as file:
        for line in file:
            if not line.strip().startswith("#"):
                content += line
        content_pattern = r'"""(.*?)"""'
        content_clear = re.sub(content_pattern, '', content, flags=re.DOTALL)

    with open(os.path.join(ZHA_FILE_PATH, filename), 'w', encoding='utf-8') as f:
        f.write(content_clear)


def extract_classes_and_types(file_path: str) -> list:
    """
    提取文件下所有的class和base class
    :param file_path:
    :return:
    """
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()

        # 匹配所有形如 "class ColorMode(t.enum8)" 的字符串
        class_pattern = r"class (.*?)\((.*?)\)"
        class_matches = re.findall(class_pattern, content)

        return class_matches


def dynamic_import_class(module_name, class_name):
    try:
        module = importlib.import_module(module_name)
        cls = getattr(module, class_name)
        return cls
    except (ModuleNotFoundError, AttributeError) as e:
        # print(f"Cannot import {class_name} from {module_name}: {e}")
        return None


def search_cluster_class():
    """
    找到所有具有 ServerCommandDefs 或 ClientCommandDefs 的类
    找到所有具有 AttributeDefs的类
    :return: 更新COMMAND MAP, FILENAME MAP, CLASSNAME MAP
    COMMAND MAP: Cluster类对应的cluster名缩写 -> Cluster类实体[Dynamic Instance]
    FILENAME MAP: Cluster类对应的cluster名缩写 -> Cluster类在ZHA Library中的文件名[general/hvac/...]
    CLASSNAME MAP: Cluster类对应的cluster名缩写 -> Cluster类名字[First Letter Uppercase]
    """
    filename_pattern = r"(.*)/(.*).txt"
    CLASS_CMD_RESULT = []
    CLASS_ATTR_RESULT = []

    all_files = list_files_in_folder(ZHA_FILE_PATH)
    for filepath in all_files:
        filename = re.match(filename_pattern, filepath).group(2)
        classes = extract_classes_and_types(filepath)
        for index, cls in enumerate(classes):
            if cls[1] != 'Cluster':
                continue
            if index + 1 >= len(classes):
                continue
            if classes[index + 1] in COMMAND_CLASS:
                CLASS_CMD_RESULT.append((filename, cls[0]))
                continue
            if classes[index + 1] == ATTR_CLASS:
                CLASS_ATTR_RESULT.append((filename, cls[0]))

            if index + 2 >= len(classes):
                continue
            if classes[index + 1] == ATTR_CLASS and classes[index + 2] in COMMAND_CLASS:
                CLASS_CMD_RESULT.append((filename, cls[0]))

    for result in CLASS_CMD_RESULT:
        module_name = BASE_MODULE + "." + result[0]
        dynamic_module = dynamic_import_class(module_name, result[1])
        COMMAND_MAP[dynamic_module.ep_attribute] = dynamic_module
        FILENAME_MAP[dynamic_module.ep_attribute] = result[0]
        CLASSNAME_MAP[dynamic_module.ep_attribute] = result[1]

    for result in CLASS_ATTR_RESULT:
        module_name = BASE_MODULE + "." + result[0]
        dynamic_module = dynamic_import_class(module_name, result[1])
        ATTRIBUTE_MAP[dynamic_module.ep_attribute] = dynamic_module
        if dynamic_module.ep_attribute not in FILENAME_MAP.keys():
            FILENAME_MAP[dynamic_module.ep_attribute] = result[0]
            CLASSNAME_MAP[dynamic_module.ep_attribute] = result[1]


def get_cluster_command(cluster_name: str) -> list:
    """
    返回cluster下所支持的所有command id列表
    :param cluster_name: cluster name
    :return:
    """
    if not CLASSNAME_MAP:
        search_cluster_class()
    print(CLASSNAME_MAP)
    result = []
    if cluster_name not in CLASSNAME_MAP.keys():
        print(cluster_name)
        log.info("[ERROR] This cluster is not recorded!")
        return result

    if not os.path.exists(os.path.join(FORMAT_SAVE_DIR, "format(ZCL_Command).json")):
        log.info("[ERROR] Please extract specification first!")
        return result

    with open(os.path.join(FORMAT_SAVE_DIR, "format(ZCL_Command).json"), 'r', encoding='utf-8') as file:
        all_messages = json.load(file)

    cluster_commands = all_messages[cluster_name]
    for category, category_commands in cluster_commands.items():
        for command_name, command_schema in category_commands.items():
            result.append(command_schema["id"])

    return result


def judge_command_type(cluster_content: str):
    """
    判断cluster中是否包含了Server Command或者Client Command
    :param cluster_content:
    :return:
    """
    HAS_Server_Command = False
    HAS_Client_Command = False
    for index, element in enumerate(COMMAND_CLASS):
        match_content_pattern = r'class {}\({}\):'.format(element[0], element[1])
        result = re.search(match_content_pattern, cluster_content, re.DOTALL)
        if result is not None:
            if index == 0:
                HAS_Server_Command = True
            else:
                HAS_Client_Command = True
    return HAS_Server_Command, HAS_Client_Command


def extract_cluster_content(filename: str, cluster_name: str):
    """
    获取文件中定义的关于cluster的文本内容
    :param filename: 在ZHA Library中包含cluster定义的文件名
    :param cluster_name: cluster名字，需要是缩写[ep_attribute]
    :return: 文件中定义的文本内容 result
    """

    file_path = os.path.join(ZHA_FILE_PATH, "{}.txt".format(filename))
    classes_and_types = extract_classes_and_types(file_path)
    if cluster_name not in CLASSNAME_MAP:
        log.info("Cluster {} has no defined command in ZHA Library!".format(cluster_name))
        return None
    cluster_classname = CLASSNAME_MAP[cluster_name]
    begin_element = None
    end_element = None

    # 0. 找到匹配的cluster的tuple和 下一个cluster的tuple(如果没有则说明cluster在末尾)
    for index, ct in enumerate(classes_and_types):
        if ct[0] == cluster_classname and ct[1] == "Cluster":
            begin_element = ct
            if index == len(classes_and_types) - 1:
                break

            no_class_left = False
            while classes_and_types[index + 1] == ATTR_CLASS or classes_and_types[index + 1] in COMMAND_CLASS:
                index += 1
                if index == len(classes_and_types) - 1:
                    no_class_left = True
                    break

            if not no_class_left:
                end_element = classes_and_types[index + 1]

            break

    if begin_element is None:
        return None

    # 1. 如果Class在文件中间
    elif end_element is not None:
        match_content_pattern = r'class {}\({}\):(.*)class {}\({}\):'. \
            format(begin_element[0], begin_element[1], end_element[0], end_element[1])
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
            result = re.search(match_content_pattern, content, re.DOTALL)

        return result.group(1)

    # 2. 如果Class在文件末尾
    else:
        match_content_pattern = r'class {}\({}\):(.*)'.format(begin_element[0], begin_element[1])
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
            result = re.search(match_content_pattern, content, re.DOTALL)
        return result.group(1)


def extract_message_schema(message_content: str) -> dict:
    """
    通过提取到的message的文本内容，获取message的schema
    :param message_content: message的文本内容
    :return: 返回保存了message schema的字典
    """
    message_schema = {}
    zcl_command_pattern = r'(.*?): Final = ZCLCommandDef\(.*?id=(.*?),.*?schema=(.*?),.*?direction=(.*?)\)'
    commands_list_content = re.findall(zcl_command_pattern, message_content, re.DOTALL)
    for matched_command in commands_list_content:
        command_params = {}

        command_name = matched_command[0].replace("\n", "").replace(" ", "")
        command_id = int(matched_command[1].strip(), 16)
        command_schema = matched_command[2].replace("\n", " ").replace(" ", "").strip(",")
        command_direction = (0 if matched_command[3].replace("\n", " ").replace(",", "").strip() == "False" else 1)

        # if command_name == "move_to_level":
        #     print(matched_command[3].replace("\n", " ").replace(",", "").strip() == "False")
        whether_schema_dict = False

        # 如果command schema是字典结构
        if "{" in command_schema:
            command_schema = None
            zcl_schema_pattern = r'{command_name}: Final = ZCLCommandDef\(.*?id={command_id},.*?schema=\{{(.*?)\}},.*?direction=.*?\)'
            zcl_schema_pattern = zcl_schema_pattern.format(command_name=command_name, command_id=matched_command[1])
            command_schema_content = re.search(zcl_schema_pattern, message_content, re.DOTALL)
            if command_schema_content is not None:
                command_schema = command_schema_content.group(1).replace("\n", " ").replace(" ", "").strip(",")
            whether_schema_dict = True

        command_params["id"] = command_id
        command_params["direction_header"] = command_direction

        # 1. 如果command schema是字典结构，则按照键值对进行划分
        if command_schema is not None and whether_schema_dict:
            all_params = command_schema.split(",")
            schema_pattern = r'"(.*)":(.*)'
            for param in all_params:
                result = re.match(schema_pattern, param)
                if result is None:
                    continue
                command_params[result.group(1).strip("?")] = result.group(2)

        # 2. 如果command schema是其他数据结构类，则直接保存该数据结构类的名字
        else:
            command_params["schema"] = command_schema

        message_schema[command_name] = command_params

    return message_schema


def extract_attribute_params(attribute_content: str) -> dict:
    """
    通过提取到的attribute的文本内容，获取attribute的params
    :param attribute_content: message的文本内容
    :return: 返回保存了attribute params的字典
    """
    attribute_result = {}
    attribute_pattern = r'(.*?): Final = ZCLAttributeDef\(.*?id=(.*?),.*?type=(.*?),.*?access="(.*?)".*?\)'
    attribute_matched_results = re.findall(attribute_pattern, attribute_content, re.DOTALL)
    attribute_foundation_pattern = r'(\w+): Final = foundation\.(\w+)'
    attribute_foundation_results = re.findall(attribute_foundation_pattern, attribute_content, re.DOTALL)

    for matched_result in attribute_matched_results:
        attribute_params = {}

        attribute_name = matched_result[0].replace("\n", "").replace(" ", "")
        attribute_id = int(matched_result[1].strip(), 16)
        attribute_type = matched_result[2].replace("\n", "").replace(" ", "")
        attribute_access = matched_result[3].replace('"', '')
        # print(attribute_name, attribute_id, attribute_type, attribute_access)

        attribute_params["id"] = attribute_id
        attribute_params["access"] = attribute_access
        attribute_params["type"] = attribute_type

        attribute_result[attribute_name] = attribute_params

    for found_result in attribute_foundation_results:
        attribute_params = {}
        attribute_name = found_result[0].replace("\n", "").replace(" ", "")
        attribute_class = "foundation." + found_result[1].replace("\n", "").replace(" ", "")

        # print(attribute_name, attribute_class)

        attribute_params["class"] = attribute_class
        attribute_result[attribute_name] = attribute_params

    return attribute_result


def acquire_command_schema(cluster_content: str) -> dict:
    """
    获取指定cluster下 所有的 server commands 和 client commands的schema
    :param cluster_content: ZHA Library中定义的cluster类包含的文本内容
    :return: cluster下所有支持的命令的schema字典
    """

    HAS_Server_Command, HAS_Client_Command = judge_command_type(cluster_content)

    server_command_content = None
    client_command_content = None
    def_pattern = r'class {}\({}\):(.*?) (?:async\s+)?def'

    if HAS_Client_Command:
        client_def_match = re.search(def_pattern.format(COMMAND_CLASS[1][0],
                                                        COMMAND_CLASS[1][1]), cluster_content, re.DOTALL)

        if client_def_match is not None:
            client_command_content = client_def_match.group(1)
            if "class" in client_command_content:
                client_result = re.search(r'class {}\({}\):(.*)class {}\({}\):'.format(COMMAND_CLASS[1][0],
                                                                                       COMMAND_CLASS[1][1],
                                                                                       COMMAND_CLASS[0][0],
                                                                                       COMMAND_CLASS[0][1]),
                                          cluster_content, re.DOTALL)
                if client_result is not None:
                    client_command_content = client_result.group(1)
        else:
            client_result = re.search(r'class {}\({}\):(.*)'.format(COMMAND_CLASS[1][0],
                                                                    COMMAND_CLASS[1][1]),
                                      cluster_content, re.DOTALL)
            if client_result is not None:
                client_command_content = client_result.group(1)
                if "class" in client_command_content:
                    client_result = re.search(r'class {}\({}\):(.*)class {}\({}\):'.format(COMMAND_CLASS[1][0],
                                                                                           COMMAND_CLASS[1][1],
                                                                                           COMMAND_CLASS[0][0],
                                                                                           COMMAND_CLASS[0][1]),
                                              cluster_content, re.DOTALL)
                    if client_result is not None:
                        client_command_content = client_result.group(1)

    if HAS_Server_Command:
        server_def_match = re.search(def_pattern.format(COMMAND_CLASS[0][0],
                                                        COMMAND_CLASS[0][1]), cluster_content, re.DOTALL)

        if server_def_match is not None:
            server_command_content = server_def_match.group(1)
            if "class" in server_command_content:
                server_result = re.search(r'class {}\({}\):(.*)class {}\({}\):'.format(COMMAND_CLASS[0][0],
                                                                                       COMMAND_CLASS[0][1],
                                                                                       COMMAND_CLASS[1][0],
                                                                                       COMMAND_CLASS[1][1]),
                                          cluster_content, re.DOTALL)
                if server_result is not None:
                    server_command_content = server_result.group(1)
        else:
            server_result = re.search(r'class {}\({}\):(.*)'.format(COMMAND_CLASS[0][0],
                                                                    COMMAND_CLASS[0][1]),
                                      cluster_content, re.DOTALL)
            if server_result is not None:
                server_command_content = server_result.group(1)
                if "class" in server_command_content:
                    server_result = re.search(r'class {}\({}\):(.*)class {}\({}\):'.format(COMMAND_CLASS[0][0],
                                                                                           COMMAND_CLASS[0][1],
                                                                                           COMMAND_CLASS[1][0],
                                                                                           COMMAND_CLASS[1][1]),
                                              cluster_content, re.DOTALL)
                    if server_result is not None:
                        server_command_content = server_result.group(1)

    result = {}
    if server_command_content is not None:
        server_command_content = server_command_content.strip("\n")
        result["Server"] = extract_message_schema(server_command_content)

    if client_command_content is not None:
        client_command_content = client_command_content.strip("\n")
        result["Client"] = extract_message_schema(client_command_content)

    return result


def acquire_attribute_definition(cluster_content: str):
    """
    获取cluster下的所有attribute
    :param cluster_content:
    :return:
    """
    HAS_Server_Command, HAS_Client_Command = judge_command_type(cluster_content)
    attr_content = None

    # Step 1: 获取attribute定义部分的内容

    # 1. 如果cluster 有Server命令类, 匹配AttributeDefs和Server命令类之间的部分
    if HAS_Server_Command:
        attr_result = re.search(r'class {}\({}\):(.*?)class {}\({}\):'.format(ATTR_CLASS[0],
                                                                              ATTR_CLASS[1],
                                                                              COMMAND_CLASS[0][0],
                                                                              COMMAND_CLASS[0][1]),
                                cluster_content, re.DOTALL)

        if attr_result is not None:
            attr_content = attr_result.group(1)

    # 2. 如果cluster 没有Server命令类，有Client命令类，匹配AttributeDefs和Client命令类之间的部分
    elif not HAS_Server_Command and HAS_Client_Command:
        attr_result = re.search(r'class {}\({}\):(.*?)class {}\({}\):'.format(ATTR_CLASS[0],
                                                                              ATTR_CLASS[1],
                                                                              COMMAND_CLASS[1][0],
                                                                              COMMAND_CLASS[1][1]),
                                cluster_content, re.DOTALL)

        if attr_result is not None:
            attr_content = attr_result.group(1)

    def_pattern = r'class {}\({}\):(.*?)(?:async\s+)?def '
    def_match = re.search(def_pattern.format(ATTR_CLASS[0],
                                             ATTR_CLASS[1]), cluster_content, re.DOTALL)

    if def_match is not None:
        # 3. 如果cluster有函数定义def，但是AttributeDefs和函数定义def之间有命令类，则不改变上述匹配的结果
        if "class" not in def_match.group(1):
            attr_content = def_match.group(1)
    else:
        # 4. 如果cluster 没有command 且没有定义的函数，则匹配AttributeDefs之后的所有内容作为Attribute Content
        if attr_content is None:
            attr_result = re.search(r'class {}\({}\):(.*)'.format(ATTR_CLASS[0],
                                                                   ATTR_CLASS[1]), cluster_content, re.DOTALL)
            if attr_result is not None:
                attr_content = attr_result.group(1)

    # Step 2: 解析attribute定义部分的内容，获取ZCLAttributeDef中定义的内容
    result = {}
    if attr_content is not None:
        result["Attribute"] = extract_attribute_params(attr_content)

    return result


def parse_field_type(type_name: str, filename: str, out_class: str = None):
    """
    对指定数据类型 type_name 进行分析，得到细粒度的type类型
    :param type_name: 数据类型名字
    :param filename: 所属的ZHA Library文件名
    :param out_class: 该数据类型类是否有外部类
    :return: None or 包含细粒度的type类型的dict + 是否为STRUCT CLASS
    """
    fine_grained_type = {}

    file_path = os.path.join(ZHA_FILE_PATH, "{}.txt".format(filename))
    current_module = BASE_MODULE + ".{}".format(filename)

    classes_and_types = extract_classes_and_types(file_path)

    OUT_CLASS_OCCUR = False

    IF_STRUCT_CLASS = False
    for index, ct in enumerate(classes_and_types):
        if out_class is not None and ct[0] == out_class:
            OUT_CLASS_OCCUR = True

        if ct[0] != type_name:
            continue

        # 如果是内部类，必须判断外部类是否已出现。如果外部类还没出现，则判定为匹配的内部类不正确
        if out_class is not None and not OUT_CLASS_OCCUR:
            continue

        basic_type_pattern = r't\.(.*)'
        basic_match = re.match(basic_type_pattern, ct[1])

        # 1. 判断是否为结构型字段类，t.Struct 或者 foundation.CommandSchema
        if ct[1] in STRUCT_BASE_CLASS:
            type_class_cls = dynamic_import_class(current_module, ct[0])
            field_info = type_class_cls.__dict__['__annotations__']
            IF_STRUCT_CLASS = True

            for field_name, field_type in field_info.items():

                # 1.1 如果字段类型是明确的
                if field_type != "None":
                    whether_basic_field_type = re.match(basic_type_pattern, field_type)
                    if whether_basic_field_type is not None:
                        fine_grained_type[field_name] = field_type
                    else:
                        deeper_field_type, _ = parse_field_type(field_type, filename)
                        if deeper_field_type is not None:
                            fine_grained_type[field_name] = deeper_field_type

                # 1.2 如果字段类型是更复杂的结构
                else:
                    try:
                        field_type_cls = getattr(type_class_cls.__dict__[field_name], "type")
                    except AttributeError:
                        log.error("No more specific type is defined!")
                        fine_grained_type[field_name] = type_class_cls.__dict__[field_name]
                        continue

                    # 匹配结果形如<enum 'FieldControl'>, 得到更细粒度的类型类 FieldControl
                    none_field_type = re.match(r".*?'(.*)'", str(field_type_cls))
                    if none_field_type is None:
                        # 获取更细粒度的类型类的所有属性成员
                        specific_fields = field_type_cls.__dict__['_member_names_']
                        fine_grained_type[field_name] = []
                        for specific_field in specific_fields:
                            fine_grained_type[field_name].append(getattr(field_type_cls, specific_field).value)
                        continue

                    none_field_type_name = none_field_type.group(1)
                    complex_result, _ = parse_field_type(none_field_type_name, filename, out_class=ct[0])
                    if complex_result is None:
                        fine_grained_type[field_name] = none_field_type_name
                    else:
                        fine_grained_type[field_name] = complex_result

            return fine_grained_type, IF_STRUCT_CLASS

        # 2.  判断class type是否为基本类型, 如果是则穷举所有基本类型的取值
        elif basic_match is not None:
            class_type = ct[1]

            # 可能是工厂制造类，确定对应的基本类型
            enum_factory_matched = re.match(r't\.enum_factory\((.*)', ct[1])
            bitmap_factory_matched = re.match(r't\.bitmap_factory\((.*)', ct[1])

            if enum_factory_matched is not None:
                type_enum_t_matched = re.match(r't\.uint(.*?)_t, .*?', enum_factory_matched.group(1))
                type_enum_t_matched2 = re.match(r't\.uint(.*?)_t', enum_factory_matched.group(1))
                if type_enum_t_matched is not None:
                    class_type = "t.enum{}".format(type_enum_t_matched.group(1))
                elif type_enum_t_matched2 is not None:
                    class_type = "t.enum{}".format(type_enum_t_matched2.group(1))
                else:
                    class_type = "ENUM_FACTORY"
            elif bitmap_factory_matched is not None:
                type_bitmap_t_matched = re.match(r't\.uint(.*?)_t, .*?', bitmap_factory_matched.group(1))
                type_bitmap_t_matched2 = re.match(r't\.uint(.*?)_t', bitmap_factory_matched.group(1))
                if type_bitmap_t_matched is not None:
                    class_type = "t.bitmap{}".format(type_bitmap_t_matched.group(1))
                elif type_bitmap_t_matched2 is not None:
                    class_type = "t.bitmap{}".format(type_bitmap_t_matched2.group(1))
                else:
                    class_type = "BITMAP_FACTORY"

            fine_grained_type[class_type] = []

            # 如果有外部类，则先导入外部类，在通过属性导入内部类；否则，直接导入
            if out_class is not None:
                type_father_class_cls = dynamic_import_class(current_module, out_class)
                type_class_cls = getattr(type_father_class_cls, ct[0])
            else:
                type_class_cls = dynamic_import_class(current_module, ct[0])

            all_enum_fields = type_class_cls.__dict__['_member_names_']
            for enum_field in all_enum_fields:
                fine_grained_type[class_type].append(getattr(type_class_cls, enum_field).value)

            return fine_grained_type, IF_STRUCT_CLASS

        # 3. 判断是否为其他类的继承类
        else:
            type_class = dynamic_import_class(current_module, type_name)
            if type_class is None:
                continue
            for field_name, field_value in type_class.__dict__.items():
                value_result = re.match(r"<enum '(.*)'>", str(field_value))
                if value_result is None:
                    continue
                field_class = dynamic_import_class(current_module, value_result.group(1))
                if field_class is not None:
                    fine_grained_type[field_name], is_struct = parse_field_type(value_result.group(1), filename)
                else:
                    fine_grained_type[field_name], is_struct = parse_field_type(value_result.group(1), filename,
                                                                                out_class=type_name)

                if is_struct:
                    IF_STRUCT_CLASS = True

            return fine_grained_type, IF_STRUCT_CLASS
    return None, IF_STRUCT_CLASS


def count_all_messages():
    def add_count(type_name: str, type_category: dict):
        if type_name not in type_category.keys():
            type_category[type_name] = 1
        else:
            type_category[type_name] += 1
        return type_category

    def check_type_count(command_set: dict, type_category: dict):
        for command_schema in command_set.values():
            for field_name, field_value in command_schema.items():
                if type(field_value) not in [str, dict]:
                    continue
                # 1. 如果是现成的基本类型
                if type(field_value) == str:
                    type_category = add_count(field_value, type_category)
                # 2. 如果是基本自定义数据类型，或者是结构型自定义数据类型
                else:
                    # FIXME 对于Struct结构的提取不精确
                    foundation_pattern = r'foundation\.(.*)'
                    zigpy_type_pattern = r't\.(.*)'
                    for name, value in field_value.items():
                        if re.match(foundation_pattern, name) is None and re.match(zigpy_type_pattern, name) is None:

                            # 如果是结构型自定义数据类型，且字段为基本数据类型
                            if type(value) == str:
                                if re.match(foundation_pattern, value) is not None \
                                        or re.match(zigpy_type_pattern, value) is not None:
                                    type_category = add_count(value, type_category)

                            # 如果是结构型自定义数据类型，且字段为自定义数据类型
                            else:
                                for final_type_name in value.keys():
                                    if type(final_type_name) != str:
                                        continue
                                    if re.match(foundation_pattern, final_type_name) is not None \
                                            or re.match(zigpy_type_pattern, final_type_name) is not None:
                                        type_category = add_count(final_type_name, type_category)
                        # 如果是基本类型类
                        else:
                            type_category = add_count(name, type_category)

        return type_category

    count = 0
    category = {}
    cluster_count = {}
    cluster_command_name = {}

    with open(os.path.join(FORMAT_SAVE_DIR, "format(ZCL_Command).json"), 'r', encoding='utf-8') as file:
        all_messages = json.load(file)

    for cluster_name, i in all_messages.items():
        cluster_count[cluster_name] = 0
        cluster_command_name[cluster_name] = []

        if "Server" in i.keys():
            count += len(i["Server"].keys())
            cluster_count[cluster_name] += len(i["Server"].keys())
            category = check_type_count(i["Server"], category)
            cluster_command_name[cluster_name].extend(i["Server"].keys())

        if "Client" in i.keys():
            count += len(i["Client"].keys())
            cluster_count[cluster_name] += len(i["Client"].keys())
            category = check_type_count(i["Client"], category)
            cluster_command_name[cluster_name].extend(i["Client"].keys())

    log.info("[OUTPUT] Extracted Message Formats: {}".format(count))
    log.info("[OUTPUT] Extracted Message Distributions: {}".format(cluster_count))
    # log.info("[OUTPUT] Message Name: {}".format(cluster_command_name))

    with open(os.path.join(FORMAT_SAVE_DIR, "message_distribution.json"), "w") as f:
        json.dump(cluster_count, f, indent=4)

    with open(os.path.join(FORMAT_SAVE_DIR, "type_category.json"), "w") as f:
        json.dump(category, f, indent=4)

    return count


def count_attributes():
    cluster_attribute_count = {}
    cluster_attribute_count_unique = {}
    total_attribute_count = 0
    have_attribute_cluster = []

    index = 1

    with open(os.path.join(ATTR_SAVE_DIR, "attribute_raw.json"), 'r', encoding='utf-8') as file:
        all_attributes = json.load(file)

    for cluster_name, cluster_value in all_attributes.items():
        if not cluster_value["Attribute"]:
            cluster_attribute_count[cluster_name] = 0
        else:
            attr_count = len(cluster_value["Attribute"].keys())
            total_attribute_count += attr_count
            cluster_attribute_count[cluster_name] = attr_count
            cluster_attribute_count_unique[cluster_name] = attr_count
            have_attribute_cluster.append(str(cluster_name))

        index += 1

    save_path1 = os.path.join(ATTR_SAVE_DIR, "cluster_attribute_count.json")
    if not os.path.exists(save_path1):
        with open(save_path1, 'w') as file:
            json.dump(cluster_attribute_count, file, indent=4)

    save_path2 = os.path.join(ATTR_SAVE_DIR, "cluster_attribute_count_unique.json")
    if not os.path.exists(save_path2):
        with open(save_path2, 'w') as file:
            json.dump(cluster_attribute_count_unique, file, indent=4)
    else:
        with open(save_path2, 'r') as f:
            cac = json.load(f)

    log.info(f"[OUTPUT] ZCL Cluster Attribute Count: {total_attribute_count}")
    log.info(f"[OUTPUT] ZCL Attributes Distribution : {cac}")


async def attribute_specification():
    """
    获取所有attribute的规范
    :return:
    """
    attr_raw_specification = {}
    attr_fine_specification = {}
    complex_datatype_count = {}
    complex_attribute_datatype = {"StructClass": 0}

    for cluster_name, cluster_ins in ATTRIBUTE_MAP.items():

        complex_datatype_count[cluster_name] = 0

        filename = FILENAME_MAP[cluster_name]

        # 1. 获取cluster对应的文件内容
        cluster_content = extract_cluster_content(filename, cluster_name)
        if cluster_content is None:
            continue

        # 2. 获取cluster内容中的属性定义，如果没有则返回{"Attribute": {}}
        cluster_attribute = acquire_attribute_definition(cluster_content)

        # 3. 保存粗粒度的cluster属性，即其中部分属性类型并未明确解析
        attr_raw_specification[str(cluster_name)] = cluster_attribute

        basic_pattern = r't\.(.*)'
        found_pattern = r'foundation\.(.*)'

        copy_attribute = copy.deepcopy(cluster_attribute)

        # 4. 解析其中部分复杂属性类型，并且进行复杂数据类型数量的统计
        for attributes in copy_attribute.values():
            for attribute, params in list(attributes.items()):
                # 如果是"type"为键的
                if "type" in params.keys():
                    basic_matched = re.match(basic_pattern, params["type"])
                    found_matched = re.match(found_pattern, params["type"])
                    if basic_matched is not None:

                        # 如果是COMPLEX_TYPE or COMPLEX_TIME_TYPE, 则认定该属性为具有复杂数据类型
                        if params["type"] in COMPLEX_TYPE:
                            if params["type"] in complex_attribute_datatype.keys():
                                complex_attribute_datatype[params["type"]] += 1
                            else:
                                complex_attribute_datatype[params["type"]] = 1

                            complex_datatype_count[cluster_name] += 1

                        elif is_prefix(COMPLEX_TYPE, params["type"])[0]:
                            match_type = is_prefix(COMPLEX_TYPE, params["type"])[1][0]
                            if match_type in complex_attribute_datatype.keys():
                                complex_attribute_datatype[match_type] += 1
                            else:
                                complex_attribute_datatype[match_type] = 1

                            complex_datatype_count[cluster_name] += 1

                        elif params["type"] in COMPLEX_TIME_TYPE:
                            if "t.Time" in complex_attribute_datatype.keys():
                                complex_attribute_datatype["t.Time"] += 1
                            else:
                                complex_attribute_datatype["t.Time"] = 1

                            complex_datatype_count[cluster_name] += 1

                        continue

                    if found_matched is not None:
                        continue

                    # print(params["type"])
                    fine_grained_type, is_struct = parse_field_type(params["type"], filename)
                    if fine_grained_type is not None:
                        copy_attribute["Attribute"][attribute]["type"] = fine_grained_type

                    # 如果为Struct Class, 则认定该属性为具有复杂数据类型
                    if is_struct:
                        complex_datatype_count[cluster_name] += 1
                        complex_attribute_datatype["StructClass"] += 1

                # 如果是"class"为键的，这认定为是foundation
                elif "class" in params.keys():
                    found_matched = re.match(found_pattern, params["class"])
                    if found_matched is not None:
                        if found_matched.group(1) in FOUNDATION_ATTR_MAP.keys():
                            copy_attribute["Attribute"][attribute]["type"] = FOUNDATION_ATTR_MAP[found_matched.group(1)]
                            copy_attribute["Attribute"][attribute].pop("class", None)
                        else:
                            continue

        attr_fine_specification[cluster_name] = copy_attribute

    if not os.path.exists(os.path.join(ATTR_SAVE_DIR, "attribute_raw.json")):
        with open(os.path.join(ATTR_SAVE_DIR, "attribute_raw.json"), "w") as f1:
            json.dump(attr_raw_specification, f1, indent=4)

    if not os.path.exists(os.path.join(ATTR_SAVE_DIR, "attribute_fine.json")):
        with open(os.path.join(ATTR_SAVE_DIR, "attribute_fine.json"), "w") as f2:
            json.dump(attr_fine_specification, f2, indent=4)

    if not os.path.exists(os.path.join(ATTR_SAVE_DIR, "complex_type_cluster(attr).json")):
        with open(os.path.join(ATTR_SAVE_DIR, "complex_type_cluster(attr).json"), "w") as f3:
            json.dump(complex_datatype_count, f3, indent=4)

    else:
        with open(os.path.join(ATTR_SAVE_DIR, "complex_type_cluster(attr).json"), "r") as f3:
            complex_datatype_count = json.load(f3)

    if not os.path.exists(os.path.join(ATTR_SAVE_DIR, "complex_type_each(attr).json")):
        with open(os.path.join(ATTR_SAVE_DIR, "complex_type_each(attr).json"), "w") as f4:
            json.dump(complex_attribute_datatype, f4, indent=4)
    else:
        with open(os.path.join(ATTR_SAVE_DIR, "complex_type_each(attr).json"), "r") as f4:
            complex_attribute_datatype = json.load(f4)

    total_complex_datatype = 0
    for count in complex_datatype_count.values():
        total_complex_datatype += count

    log.info("[Device State Awareness (Stage 2)] Parsed Complex Data Types Distribution(Attributes): {}".format(complex_attribute_datatype))
    log.info("[Device State Awareness (Stage 2)] Parsed Complex Data Types Number(Attributes): {}".format(total_complex_datatype))

    # 5.统计每个cluster的属性数量分布，以及有属性的cluster的属性数量分布
    count_attributes()


async def message_specification():
    """
    获取所有message的规范
    :return:
    """
    all_command_schema = {}
    complex_data_type = {}
    complex_message_datatype = {"StructClass": 0}
    complex_type_field = []

    for cluster_name in COMMAND_MAP.keys():
        complex_data_type[cluster_name] = 0

        filename = FILENAME_MAP[cluster_name]
        # Step1: 获取每个cluster在ZHA Library中定义的文件内容
        class_content = extract_cluster_content(filename, cluster_name)
        if class_content is None:
            continue

        # Step2: 从文件内容中获取包含的Server Command和Client Command Schema
        cluster_command_schema = acquire_command_schema(class_content)
        schema_copy = copy.deepcopy(cluster_command_schema)

        # Step3: 对Command Schema中的field type进行细粒度的分析
        for category, all_command in schema_copy.items():
            for command_name, command_schema in all_command.items():
                has_complex_datatype = False
                for field_name, field_type in list(command_schema.items()):
                    if type(field_type) != str:
                        continue

                    if field_name == "schema":
                        fine_grained_type, is_struct = parse_field_type(field_type, filename)

                        if is_struct:
                            has_complex_datatype = True
                            complex_message_datatype["StructClass"] += 1
                            complex_type_field.append((cluster_name, command_name, field_name, "StructClass"))

                        if fine_grained_type is not None:
                            cluster_command_schema[category][command_name].pop(field_name, None)
                            cluster_command_schema[category][command_name].update(fine_grained_type)
                        continue

                    result = re.match(r't\.(.*)', field_type)
                    if result is not None:
                        if field_type in COMPLEX_TYPE:
                            has_complex_datatype = True
                            complex_type_field.append((cluster_name, command_name, field_name, field_type))

                            if field_type not in complex_message_datatype.keys():
                                complex_message_datatype[field_type] = 1
                            else:
                                complex_message_datatype[field_type] += 1

                            continue

                        for lt in LIST_TYPE:
                            list_type_pattern = r'{}\[(.*)\]'.format(lt)
                            list_type_matched = re.match(list_type_pattern, field_type)
                            if list_type_matched is not None:
                                has_complex_datatype = True
                                complex_type_field.append((cluster_name, command_name, field_name, lt))

                                if lt not in complex_message_datatype.keys():
                                    complex_message_datatype[lt] = 1
                                else:
                                    complex_message_datatype[lt] += 1

                                basic_type_matched = re.match(r't\.(.*)', list_type_matched.group(1))
                                if basic_type_matched is not None:
                                    cluster_command_schema[category][command_name][field_name] = \
                                        {lt: basic_type_matched.group(1)}
                                else:
                                    fine_grained_type, is_struct = parse_field_type(list_type_matched.group(1),
                                                                                    filename)
                                    if is_struct:
                                        complex_message_datatype["StructClass"] += 1
                                        complex_type_field.append((cluster_name, command_name, field_name, "StructClass"))

                                    cluster_command_schema[category][command_name][field_name] = {lt: fine_grained_type}
                                break
                        continue

                    fine_grained_type, is_struct = parse_field_type(field_type, filename)

                    if is_struct:
                        complex_message_datatype["StructClass"] += 1
                        has_complex_datatype = True
                        complex_type_field.append((cluster_name, command_name, field_name, "StructClass"))

                    if fine_grained_type is not None:
                        cluster_command_schema[category][command_name][field_name] = fine_grained_type

                if has_complex_datatype:
                    complex_data_type[cluster_name] += 1

        all_command_schema[cluster_name] = cluster_command_schema

    with open(os.path.join(FORMAT_SAVE_DIR, "format(ZCL_Command).json"), "w") as f1:
        json.dump(all_command_schema, f1, indent=4)

    with open(os.path.join(FORMAT_SAVE_DIR, "complex_type_cluster(message).json"), "w") as f2:
        json.dump(complex_data_type, f2, indent=4)

    with open(os.path.join(FORMAT_SAVE_DIR, "complex_type_each(message).json"), "w") as f3:
        json.dump(complex_message_datatype, f3, indent=4)

    has_complex_type_message = 0
    for count in complex_data_type.values():
        has_complex_type_message += count

    complex_field = {}
    for field in complex_type_field:
        if field[0] not in complex_field.keys():
            complex_field[field[0]] = {}
        if field[1] not in complex_field[field[0]].keys():
            complex_field[field[0]][field[1]] = []

        is_combine = False
        for index, element in enumerate(complex_field[field[0]][field[1]]):
            if list(element.keys())[0] == field[2]:
                origin_value = complex_field[field[0]][field[1]][index][field[2]]
                complex_field[field[0]][field[1]][index][field[2]] = origin_value + "+ {}".format(field[3])
                is_combine = True
                break

        if not is_combine:
            complex_field[field[0]][field[1]].append({field[2]: field[3]})

    with open(os.path.join(FORMAT_SAVE_DIR, "complex_type_field(message).json"), "w") as f4:
        json.dump(complex_field, f4, indent=4)

    log.info("[OUTPUT] Parsed Complex Data Types Distribution(Messages): {}".format(complex_message_datatype))
    log.info("[OUTPUT] Parsed Objects That Contain Complex Data Types(Messages): {}".format(has_complex_type_message))
    log.info("[OUTPUT] Complex Data Types Fields(Messages): {}".format(len(complex_type_field)))

    count_all_messages()


def main():
    # Step 0: 预处理文件，清理文件中的注释
    all_files = list_files_in_folder(ZHA_FILE_ORIGIN_PATH)
    for file_path in all_files:
        clear_comment(file_path)

    # Step 1: 搜索cluster class, 找到所有属性类和命令类
    search_cluster_class()

    # Step 2: 获取所有属性类下定义的attribute的ID, 数据类型和访问权限
    attribute_specification()

    # Step 3: 获取所有命令类下定义的message格式
    message_specification()


if __name__ == "__main__":
    main()
